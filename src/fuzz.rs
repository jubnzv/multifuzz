use crate::ui::{Dashboard, EngineInfo, EngineKind};
use crate::{Build, Fuzz};
use anyhow::{anyhow, Context, Result};
use glob::glob;
use std::{
    collections::HashSet,
    env, fs,
    fs::File,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{self, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Recursively collect all directories under `dir`.
fn collect_dirs_recursively(dir: &Path, dir_list: &mut HashSet<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && dir_list.insert(path.clone()) {
                collect_dirs_recursively(&path, dir_list);
            }
        }
    }
}

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigint(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}
use twox_hash::XxHash64;

/// Merge multiple dictionary files into one, deduplicating token lines.
fn merge_dicts(dicts: &[PathBuf], output_dir: &str) -> Result<PathBuf> {
    let merged_path = PathBuf::from(format!("{output_dir}/merged.dict"));
    let mut out = File::create(&merged_path)
        .with_context(|| format!("Failed to create merged dict at {}", merged_path.display()))?;
    let mut seen: HashSet<String> = HashSet::new();

    for dict_path in dicts {
        writeln!(out, "# --- merged from: {} ---", dict_path.display())?;
        let file = File::open(dict_path)
            .with_context(|| format!("Failed to open dictionary: {}", dict_path.display()))?;
        for line in BufReader::new(file).lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                writeln!(out, "{line}")?;
                continue;
            }
            if seen.insert(trimmed.to_string()) {
                writeln!(out, "{line}")?;
            }
        }
        writeln!(out)?;
    }

    Ok(merged_path)
}

impl Fuzz {
    /// Resolved corpus directory path.
    fn corpus_dir(&self) -> String {
        match &self.corpus {
            Some(p) => p.display().to_string(),
            None => format!("{}/{}/corpus", self.output.display(), self.target),
        }
    }

    /// `{output}/{target}` — the per-target output root.
    fn output_target(&self) -> String {
        format!("{}/{}", self.output.display(), self.target)
    }

    fn afl_enabled(&self) -> bool {
        !self.no_afl
    }

    /// Honggfuzz is enabled when not explicitly disabled and there are >1 jobs
    /// (with a single job, AFL++ alone is more effective).
    fn honggfuzz_enabled(&self) -> bool {
        if self.no_honggfuzz {
            return false;
        }
        if self.no_afl {
            return true;
        }
        self.jobs > 1
    }

    fn libfuzzer_enabled(&self) -> bool {
        !self.no_libfuzzer
    }

    // ── public entry point ──────────────────────────────────────────────

    pub fn fuzz(&mut self) -> Result<()> {
        // Resolve output to an absolute path so all printed paths are absolute.
        fs::create_dir_all(&self.output)?;
        self.output = self.output.canonicalize()?;

        // Build first
        let build = Build {
            no_afl: !self.afl_enabled(),
            no_honggfuzz: !self.honggfuzz_enabled(),
            no_libfuzzer: !self.libfuzzer_enabled(),
        };
        build.build().context("Failed to build the fuzzers")?;

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        let crash_dir = format!("{}/crashes/{}/", self.output_target(), timestamp);
        fs::create_dir_all(&crash_dir)?;
        fs::create_dir_all(format!("{}/logs/", self.output_target()))?;
        fs::create_dir_all(format!("{}/queue/", self.output_target()))?;
        if self.libfuzzer_enabled() {
            fs::create_dir_all(format!("{}/libfuzzer/corpus/", self.output_target()))?;
            fs::create_dir_all(format!("{}/libfuzzer/crashes/", self.output_target()))?;
        }

        // Ensure corpus directory exists with at least one seed
        let corpus = self.corpus_dir();
        fs::create_dir_all(&corpus)?;
        if fs::read_dir(&corpus)?.next().is_none() {
            let init = File::create(format!("{corpus}/init"))?;
            writeln!(&init, "00000000")?;
            drop(init);
        }

        // Pre-merge dictionaries if more than one is provided
        if self.dictionaries.len() > 1 {
            self.merged_dict = Some(merge_dicts(&self.dictionaries, &self.output_target())?);
        }

        let (mut processes, engines) = self.spawn_fuzzers()?;

        eprintln!("    Crashes: {crash_dir}");
        if !self.external_corpus.is_empty() {
            for dir in &self.external_corpus {
                eprintln!("    External corpus: {}", dir.display());
            }
        }
        eprintln!();
        eprint!("    Press Enter to start the dashboard...");
        let _ = std::io::stdin().read_line(&mut String::new());

        let mut dashboard = Dashboard::new(&self.target, &self.output_target(), engines);
        dashboard.record_baseline();

        let crash_path = Path::new(&crash_dir);
        let mut last_synced_created_time: Option<SystemTime> = None;
        let mut last_sync_time = Instant::now();
        let loop_start = Instant::now();

        unsafe {
            libc::signal(libc::SIGINT, handle_sigint as libc::sighandler_t);
        }

        loop {
            thread::sleep(Duration::from_secs(1));

            if STOP.load(Ordering::Relaxed) {
                break;
            }

            // ── crash collection ────────────────────────────────────────
            self.collect_crashes(crash_path)?;

            // ── corpus sync (every 10 minutes) ─────────────────────────
            if last_sync_time.elapsed().as_secs() > self.sync_interval * 60 {
                dashboard.set_syncing(true);
                dashboard.refresh(&mut processes);
                last_synced_created_time = self.sync_corpus(last_synced_created_time)?;
                last_sync_time = Instant::now();
                dashboard.set_syncing(false);
            }

            // ── dashboard refresh + liveness check ──────────────────────
            if dashboard.refresh(&mut processes) {
                break;
            }
        }

        // ── cleanup + summary ───────────────────────────────────────────
        self.collect_crashes(crash_path)?;
        stop_fuzzers(&mut processes)?;

        let elapsed = loop_start.elapsed().as_secs();
        let days = elapsed / 86400;
        let hrs = (elapsed % 86400) / 3600;
        let mins = (elapsed % 3600) / 60;
        let secs = elapsed % 60;
        let runtime = if days > 0 {
            format!("{days} days {hrs:02} hrs {mins:02} mins {secs:02} secs")
        } else if hrs > 0 {
            format!("{hrs} hrs {mins:02} mins {secs:02} secs")
        } else if mins > 0 {
            format!("{mins} mins {secs:02} secs")
        } else {
            format!("{secs} secs")
        };

        let crash_count = fs::read_dir(crash_path)
            .map(|entries| entries.flatten().count())
            .unwrap_or(0);
        let corpus_count = fs::read_dir(format!("{}/corpus", self.output_target()))
            .map(|entries| entries.flatten().count())
            .unwrap_or(0);

        eprintln!();
        eprintln!("── Session complete ──────────────────────────────");
        eprintln!(" Runtime  : {runtime}");
        eprintln!(" Crashes  : {crash_count}");
        eprintln!(" Corpus   : {corpus_count} files");
        eprintln!();
        eprintln!(" Results:");
        eprintln!("   Crashes : {crash_dir}");
        eprintln!("   Corpus  : {}/corpus/", self.output_target());
        eprintln!("   Logs    : {}/logs/", self.output_target());

        Ok(())
    }

    // ── crash collection ────────────────────────────────────────────────

    fn collect_crashes(&self, crash_path: &Path) -> Result<()> {
        let mut extra_dirs: Vec<std::path::PathBuf> =
            vec![format!("{}/honggfuzz/{}", self.output_target(), self.target).into()];
        if self.libfuzzer_enabled() {
            extra_dirs.push(format!("{}/libfuzzer/crashes", self.output_target()).into());
        }

        let crash_dirs = glob(&format!("{}/afl/*/crashes", self.output_target()))
            .map_err(|_| anyhow!("Failed to read crashes glob pattern"))?
            .flatten()
            .chain(extra_dirs);

        for dir in crash_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let dest = crash_path.join(&name);
                    if dest.exists()
                        || ["", "README.txt", "HONGGFUZZ.REPORT.TXT", "input"]
                            .contains(&name.to_str().unwrap_or_default())
                    {
                        continue;
                    }
                    fs::copy(entry.path(), dest)?;
                }
            }
        }
        Ok(())
    }

    // ── corpus sync ─────────────────────────────────────────────────────

    fn sync_corpus(&self, last_synced: Option<SystemTime>) -> Result<Option<SystemTime>> {
        let mut files = vec![];
        if self.afl_enabled() {
            files.extend(
                glob(&format!(
                    "{}/afl/mainaflfuzzer/queue/*",
                    self.output_target()
                ))?
                .flatten(),
            );
        }
        if self.honggfuzz_enabled() {
            files.extend(glob(&format!("{}/honggfuzz/corpus/*", self.output_target()))?.flatten());
        }
        if self.libfuzzer_enabled() {
            files.extend(glob(&format!("{}/libfuzzer/corpus/*", self.output_target()))?.flatten());
        }

        // Collect files from external corpus directories
        let external_files = self.collect_external_corpus_files();

        let mut newest_time = last_synced;
        let valid_files: Vec<_> = files
            .iter()
            .filter(|file| {
                if let Ok(metadata) = file.metadata() {
                    if let Ok(created) = metadata.created() {
                        if last_synced.is_none_or(|time| created > time) {
                            if newest_time.is_none_or(|time| created > time) {
                                newest_time = Some(created);
                            }
                            return true;
                        }
                    }
                }
                false
            })
            .collect();

        let max_len = self.max_input_size as u64;

        // Merge engine files + external files into the same dedup pipeline
        let all_files: Vec<&PathBuf> = valid_files
            .into_iter()
            .chain(external_files.iter())
            .collect();

        for file in all_files {
            if file.file_name().is_some() {
                let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
                if file_len > max_len {
                    continue;
                }

                // Hash-dedup into shared corpus
                let bytes = fs::read(file).unwrap_or_default();
                let hash = XxHash64::oneshot(0, &bytes);
                let corpus_path = format!("{}/corpus/{hash:x}", self.output_target());
                if Path::new(&corpus_path).exists() {
                    continue;
                }
                let _ = fs::copy(file, &corpus_path);

                // Copy to honggfuzz bridge queue
                if self.honggfuzz_enabled() {
                    let queue_path = format!(
                        "{}/queue/{:?}",
                        self.output_target(),
                        file.file_name().unwrap()
                    );
                    if !Path::new(&queue_path).exists() {
                        let _ = fs::copy(file, &queue_path);
                    }
                }
            }
        }

        Ok(newest_time)
    }

    /// Collect files from `--external-corpus` directories.
    fn collect_external_corpus_files(&self) -> Vec<PathBuf> {
        if self.external_corpus.is_empty() {
            return vec![];
        }

        let mut dirs: Vec<PathBuf> = self.external_corpus.clone();

        if self.external_corpus_recursive {
            let mut all_dirs = HashSet::new();
            for dir in &self.external_corpus {
                all_dirs.insert(dir.clone());
                collect_dirs_recursively(dir, &mut all_dirs);
            }
            for dir in all_dirs {
                if !dirs.contains(&dir) {
                    dirs.push(dir);
                }
            }
        }

        dirs.iter()
            .flat_map(|path| {
                if path.is_dir() {
                    fs::read_dir(path)
                        .into_iter()
                        .flatten()
                        .filter_map(|e| e.ok())
                        .map(|e| e.path())
                        .filter(|p| p.is_file())
                        .collect::<Vec<_>>()
                } else {
                    vec![path.clone()]
                }
            })
            .collect()
    }

    // ── spawning ────────────────────────────────────────────────────────

    fn spawn_fuzzers(&self) -> Result<(Vec<process::Child>, Vec<EngineInfo>)> {
        if self.no_afl && self.no_honggfuzz && !self.libfuzzer_enabled() {
            return Err(anyhow!("Pick at least one fuzzer"));
        }

        let mut handles = vec![];
        let mut engines = vec![];
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        let (afl_jobs, honggfuzz_jobs, libfuzzer_jobs) = self.allocate_jobs();

        if afl_jobs > 0 {
            fs::create_dir_all(format!("{}/afl", self.output_target()))?;
            let start = handles.len();
            let afl_cmds = self.spawn_afl(&cargo, afl_jobs, &mut handles)?;
            engines.push(EngineInfo {
                name: format!("AFL++ ({afl_jobs}P)"),
                kind: EngineKind::Afl,
                process_indices: (start..handles.len()).collect(),
            });
            eprintln!("    Launched AFL++ ({afl_jobs} instances)");
            for cmd in &afl_cmds {
                eprintln!("      $ {cmd}");
            }
        }

        if honggfuzz_jobs > 0 {
            let start = handles.len();
            let hfuzz_cmd = self.spawn_honggfuzz(&cargo, honggfuzz_jobs, &mut handles)?;
            engines.push(EngineInfo {
                name: format!("honggfuzz ({honggfuzz_jobs}T)"),
                kind: EngineKind::Honggfuzz,
                process_indices: (start..handles.len()).collect(),
            });
            eprintln!("    Launched honggfuzz ({honggfuzz_jobs} threads)");
            eprintln!("      $ {hfuzz_cmd}");
        }

        if libfuzzer_jobs > 0 {
            let start = handles.len();
            let lf_cmd = self.spawn_libfuzzer(libfuzzer_jobs, &mut handles)?;
            engines.push(EngineInfo {
                name: format!("libfuzzer ({libfuzzer_jobs}F)"),
                kind: EngineKind::Libfuzzer,
                process_indices: (start..handles.len()).collect(),
            });
            eprintln!("    Launched libfuzzer ({libfuzzer_jobs} workers)");
            eprintln!("      $ {lf_cmd}");
        }

        // Print log paths so the user can tail them in another terminal.
        let logs_dir = format!("{}/logs", self.output_target());
        eprintln!();
        eprintln!("    Log files:");
        if afl_jobs > 0 {
            for i in 0..afl_jobs {
                let name = if i == 0 {
                    "afl.log".to_string()
                } else {
                    format!("afl_{i}.log")
                };
                eprintln!("      tail -f {logs_dir}/{name}");
            }
        }
        if honggfuzz_jobs > 0 {
            eprintln!("      tail -f {logs_dir}/honggfuzz.log");
        }
        if libfuzzer_jobs > 0 {
            eprintln!("      tail -f {logs_dir}/libfuzzer.log");
        }

        Ok((handles, engines))
    }

    /// Allocate jobs between AFL++, honggfuzz and libfuzzer.
    /// Returns (afl_jobs, honggfuzz_jobs, libfuzzer_jobs).
    fn allocate_jobs(&self) -> (u32, u32, u32) {
        let afl = self.afl_enabled();
        let hfuzz = self.honggfuzz_enabled();
        let libf = self.libfuzzer_enabled();

        // With a single job and multiple engines, give it all to AFL (most effective solo).
        if self.jobs == 1 {
            if afl {
                return (1, 0, 0);
            } else if hfuzz {
                return (0, 1, 0);
            } else {
                return (0, 0, 1);
            }
        }

        // Carve out libfuzzer jobs first.
        let lf_jobs = if libf {
            if !afl && !hfuzz {
                self.jobs
            } else {
                std::cmp::min(self.jobs.div_ceil(4), 4)
            }
        } else {
            0
        };
        let remaining = self.jobs - lf_jobs;

        // Split remaining between AFL++ and honggfuzz.
        let (a, h) = if !afl {
            (0, remaining)
        } else if !hfuzz {
            (remaining, 0)
        } else {
            let hf = std::cmp::min(remaining.div_ceil(3), 4);
            (remaining - hf, hf)
        };

        (a, h, lf_jobs)
    }

    fn spawn_afl(
        &self,
        cargo: &str,
        afl_jobs: u32,
        handles: &mut Vec<process::Child>,
    ) -> Result<Vec<String>> {
        // Power schedule diversity following AFL++ best practices
        let afl_modes = [
            "explore", "fast", "coe", "lin", "quad", "exploit", "rare", "explore", "fast", "mmopt",
        ];

        let corpus = self.corpus_dir();

        // AFL++ supports up to 4 -x flags natively; merge if more.
        let dict_flags: Vec<String> = if self.dictionaries.is_empty() {
            vec![]
        } else if self.dictionaries.len() <= 4 {
            self.dictionaries
                .iter()
                .map(|d| format!("-x{}", d.display()))
                .collect()
        } else {
            let merged = self.merged_dict.as_ref().unwrap();
            vec![format!("-x{}", merged.display())]
        };

        // When AFL++ already has a queue from a previous run, use a minimal
        // seed directory instead of the (potentially huge) shared corpus.
        // AFL_AUTORESUME makes AFL++ reuse its existing queue, so `-i` only
        // matters for the very first import — a single dummy seed is enough.
        let afl_queue_dir = format!("{}/afl/mainaflfuzzer/queue", self.output_target());
        let afl_can_resume = Path::new(&afl_queue_dir)
            .read_dir()
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);

        let afl_input_dir = if afl_can_resume {
            let minimal = format!("{}/afl/_seed", self.output_target());
            fs::create_dir_all(&minimal)?;
            let marker = format!("{minimal}/init");
            if !Path::new(&marker).exists() {
                File::create(&marker)?.write_all(b"00000000\n")?;
            }
            minimal
        } else {
            corpus.clone()
        };

        let mut cmds = Vec::new();

        for job_num in 0..afl_jobs {
            let is_main = job_num == 0;

            let fuzzer_name = if is_main {
                String::from("-Mmainaflfuzzer")
            } else {
                format!("-Ssecondaryfuzzer{job_num}")
            };

            // Only the main instance syncs from honggfuzz's output corpus
            let honggfuzz_sync_flag = if self.honggfuzz_enabled() && job_num == 0 {
                format!("-F{}/honggfuzz/corpus", self.output_target())
            } else {
                String::new()
            };

            let libfuzzer_sync_flag = if self.libfuzzer_enabled() && job_num == 0 {
                format!("-F{}/libfuzzer/corpus", self.output_target())
            } else {
                String::new()
            };

            // 10% MOpt mutator
            let mopt = if job_num % 10 == 9 { "-L0" } else { "" };

            let power_schedule = afl_modes
                .get(job_num as usize % afl_modes.len())
                .unwrap_or(&"fast");

            // 10% old queue cycling
            let old_queue = if job_num % 10 == 8 { "-Z" } else { "" };

            // Cmplog diversity
            let cmplog = match job_num {
                1 => "-l2a",
                3 => "-l1",
                14 => "-l2a",
                22 => "-l3at",
                _ => "-c-",
            };

            let timeout_flag = match self.timeout {
                Some(t) => format!("-t{}", t * 1000),
                None => String::new(),
            };

            let max_len_flag = format!("-G{}", self.max_input_size);

            let log_destination = || -> Stdio {
                let name = if job_num == 0 {
                    "afl.log".to_string()
                } else {
                    format!("afl_{job_num}.log")
                };
                File::create(format!("{}/logs/{name}", self.output_target()))
                    .unwrap()
                    .into()
            };

            let final_sync = if job_num == 0 {
                "AFL_FINAL_SYNC"
            } else {
                "_DUMMY_VAR"
            };

            let target_path = format!("./target/afl/debug/{}", self.target);

            let afl_args: Vec<String> = [
                "afl".to_string(),
                "fuzz".to_string(),
                fuzzer_name.clone(),
                format!("-i{afl_input_dir}"),
                format!("-p{power_schedule}"),
                format!("-o{}/afl", self.output_target()),
                honggfuzz_sync_flag.clone(),
                libfuzzer_sync_flag.clone(),
                old_queue.to_string(),
                cmplog.to_string(),
                mopt.to_string(),
                timeout_flag.clone(),
                max_len_flag.clone(),
            ]
            .into_iter()
            .filter(|a| !a.is_empty())
            .collect();

            let mut cmd_parts: Vec<String> = Vec::new();
            cmd_parts.push(format!("AFL_AUTORESUME=1 AFL_TESTCACHE_SIZE=100 AFL_FAST_CAL=1 {final_sync}=1"));
            cmd_parts.push(cargo.to_string());
            cmd_parts.extend(afl_args.iter().cloned());
            cmd_parts.extend(dict_flags.iter().cloned());
            cmd_parts.push(target_path.clone());
            cmds.push(cmd_parts.join(" "));

            handles.push(
                process::Command::new(cargo)
                    .args(&afl_args)
                    .args(&dict_flags)
                    .arg(&target_path)
                    .env("AFL_AUTORESUME", "1")
                    .env("AFL_TESTCACHE_SIZE", "100")
                    .env("AFL_FAST_CAL", "1")
                    .env("AFL_FORCE_UI", "1")
                    .env("AFL_IGNORE_UNKNOWN_ENVS", "1")
                    .env("AFL_CMPLOG_ONLY_NEW", "1")
                    .env("AFL_DISABLE_TRIM", "1")
                    .env("AFL_NO_WARN_INSTABILITY", "1")
                    .env("AFL_FUZZER_STATS_UPDATE_INTERVAL", "10")
                    .env(final_sync, "1")
                    .env("AFL_IGNORE_SEED_PROBLEMS", "1")
                    .stdout(log_destination())
                    .stderr(log_destination())
                    .spawn()?,
            );
        }

        Ok(cmds)
    }

    fn spawn_honggfuzz(
        &self,
        cargo: &str,
        honggfuzz_jobs: u32,
        handles: &mut Vec<process::Child>,
    ) -> Result<String> {
        let corpus = self.corpus_dir();

        let timeout_flag = match self.timeout {
            Some(t) => format!("-t{t}"),
            None => String::new(),
        };

        let dict_flag = if self.dictionaries.is_empty() {
            String::new()
        } else if self.dictionaries.len() == 1 {
            format!("-w{}", self.dictionaries[0].display())
        } else {
            format!("-w{}", self.merged_dict.as_ref().unwrap().display())
        };

        // Purge any corpus/queue files exceeding max_input_size so honggfuzz
        // doesn't abort on oversized inputs left by other engines.
        let max_len = self.max_input_size as u64;
        let mut oversized: Vec<PathBuf> = Vec::new();
        for dir in [
            format!("{}/queue", self.output_target()),
            format!("{}/honggfuzz/corpus", self.output_target()),
        ] {
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    if entry.metadata().map(|m| m.len()).unwrap_or(0) > max_len {
                        oversized.push(entry.path());
                    }
                }
            }
        }
        if !oversized.is_empty() {
            eprintln!(
                "    Warning: {} file(s) exceed max_input_size ({} bytes) and will crash honggfuzz.",
                oversized.len(),
                self.max_input_size,
            );
            // Group by parent directory for a concise summary.
            let mut by_dir: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            for path in &oversized {
                let dir = path
                    .parent()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                *by_dir.entry(dir).or_default() += 1;
            }
            for (dir, count) in &by_dir {
                eprintln!("      {count} file(s) in {dir}");
            }
            eprint!("    Remove them? [Y/n] ");
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            let answer = answer.trim().to_lowercase();
            if answer.is_empty() || answer == "y" || answer == "yes" {
                for path in &oversized {
                    let _ = fs::remove_file(path);
                }
                eprintln!("    Removed {} oversized file(s).", oversized.len());
            } else {
                eprintln!("    Skipped removal. Honggfuzz may abort on oversized inputs.");
            }
        }

        // The `script` invocation is a trick to get the correct TTY output for
        // honggfuzz (it requires a valid terminal).
        let hfuzz_run_args = format!(
            "--input={corpus} \
             -o{}/honggfuzz/corpus \
             -n{honggfuzz_jobs} \
             --dynamic_input={}/queue \
             -F{} \
             {timeout_flag} {dict_flag}",
            self.output_target(),
            self.output_target(),
            self.max_input_size,
        );

        let cmd_str = format!(
            "HFUZZ_BUILD_ARGS='--features=multifuzz/honggfuzz' \
             CARGO_TARGET_DIR=./target/honggfuzz \
             HFUZZ_WORKSPACE={}/honggfuzz \
             HFUZZ_RUN_ARGS='{hfuzz_run_args}' \
             {cargo} hfuzz run {}",
            self.output_target(),
            self.target,
        );

        let hfuzz_log = File::create(format!("{}/logs/honggfuzz.log", self.output_target()))?;
        let hfuzz_log_clone = hfuzz_log.try_clone()?;
        handles.push(
            process::Command::new("script")
                .args([
                    "--flush",
                    "--quiet",
                    "-c",
                    &format!("{cargo} hfuzz run {}", &self.target),
                    "/dev/null",
                ])
                .env("HFUZZ_BUILD_ARGS", "--features=multifuzz/honggfuzz")
                .env("CARGO_TARGET_DIR", "./target/honggfuzz")
                .env(
                    "HFUZZ_WORKSPACE",
                    format!("{}/honggfuzz", self.output_target()),
                )
                .env("HFUZZ_RUN_ARGS", &hfuzz_run_args)
                .stdin(Stdio::null())
                .stderr(hfuzz_log)
                .stdout(hfuzz_log_clone)
                .spawn()?,
        );

        Ok(cmd_str)
    }

    fn spawn_libfuzzer(
        &self,
        libfuzzer_jobs: u32,
        handles: &mut Vec<process::Child>,
    ) -> Result<String> {
        // The libfuzzer binary is built with --target=<triple> to isolate
        // SanitizerCoverage flags from build scripts.
        let host = std::env::consts::ARCH.to_string() + "-unknown-" + std::env::consts::OS + "-gnu";
        let binary = format!("./target/libfuzzer/{host}/release/{}", self.target);
        let corpus = self.corpus_dir();

        let mut args = vec![
            format!("{}/libfuzzer/corpus/", self.output_target()),
            corpus,
            format!(
                "-artifact_prefix={}/libfuzzer/crashes/",
                self.output_target()
            ),
            format!("-fork={libfuzzer_jobs}"),
            "-reload=1".to_string(),
            "-print_final_stats=1".to_string(),
            "-ignore_crashes=1".to_string(),
            "-ignore_ooms=1".to_string(),
            "-ignore_timeouts=1".to_string(),
            format!("-max_len={}", self.max_input_size),
        ];

        if let Some(t) = self.timeout {
            args.push(format!("-timeout={t}"));
        }
        if !self.dictionaries.is_empty() {
            let dict_path = if self.dictionaries.len() == 1 {
                self.dictionaries[0].clone()
            } else {
                self.merged_dict.as_ref().unwrap().clone()
            };
            args.push(format!("-dict={}", dict_path.display()));
        }

        let cmd_str = format!("{binary} {}", args.join(" "));

        let lf_log = File::create(format!("{}/logs/libfuzzer.log", self.output_target()))?;
        let lf_log_clone = lf_log.try_clone()?;

        handles.push(
            process::Command::new(&binary)
                .args(&args)
                .stdout(lf_log)
                .stderr(lf_log_clone)
                .spawn()
                .with_context(|| format!("Failed to spawn libfuzzer binary: {binary}"))?,
        );

        Ok(cmd_str)
    }
}

// ── process management ──────────────────────────────────────────────────

/// Recursively send SIGTERM to a process tree rooted at `pid`.
fn kill_subprocesses_recursively(pid: &str) -> Result<()> {
    let subprocesses = process::Command::new("pgrep")
        .arg(format!("-P{pid}"))
        .output()?;
    for subprocess in std::str::from_utf8(&subprocesses.stdout)?.split('\n') {
        if subprocess.is_empty() {
            continue;
        }
        kill_subprocesses_recursively(subprocess)
            .context("Error in kill_subprocesses_recursively")?;
    }
    unsafe {
        libc::kill(pid.parse::<i32>().unwrap(), libc::SIGTERM);
    }
    Ok(())
}

fn stop_fuzzers(processes: &mut Vec<process::Child>) -> Result<()> {
    for process in processes {
        kill_subprocesses_recursively(&process.id().to_string())?;
    }
    Ok(())
}

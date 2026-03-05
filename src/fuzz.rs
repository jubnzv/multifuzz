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
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
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

        let mut processes = self.spawn_fuzzers()?;

        let crash_path = Path::new(&crash_dir);
        let mut last_synced_created_time: Option<SystemTime> = None;
        let mut last_sync_time = Instant::now();

        eprintln!("\nFuzzing {}...", self.target);
        eprintln!("See live information:");
        if self.afl_enabled() {
            let (afl_jobs, _, _) = self.allocate_jobs();
            for i in 0..afl_jobs {
                let name = if i == 0 { "afl.log".to_string() } else { format!("afl_{i}.log") };
                eprintln!("  tail -f {}/logs/{name}", self.output_target());
            }
        }
        if self.honggfuzz_enabled() {
            eprintln!("  tail -f {}/logs/honggfuzz.log", self.output_target());
        }
        if self.libfuzzer_enabled() {
            eprintln!("  tail -f {}/logs/libfuzzer.log", self.output_target());
        }

        loop {
            thread::sleep(Duration::from_secs(1));

            // ── crash collection ────────────────────────────────────────
            self.collect_crashes(crash_path)?;

            // ── corpus sync (every 10 minutes) ─────────────────────────
            if last_sync_time.elapsed().as_secs() > 10 * 60 {
                last_synced_created_time = self.sync_corpus(last_synced_created_time)?;
                last_sync_time = Instant::now();
            }

            // ── liveness check ──────────────────────────────────────────
            if processes
                .iter_mut()
                .all(|p| p.try_wait().unwrap_or(None).is_some())
            {
                stop_fuzzers(&mut processes)?;
                return Ok(());
            }
        }
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

        for file in valid_files {
            if file.file_name().is_some() {
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
                // Hash-dedup into shared corpus
                let bytes = fs::read(file).unwrap_or_default();
                let hash = XxHash64::oneshot(0, &bytes);
                let corpus_path = format!("{}/corpus/{hash:x}", self.output_target());
                if !Path::new(&corpus_path).exists() {
                    let _ = fs::copy(file, corpus_path);
                }
            }
        }

        Ok(newest_time)
    }

    // ── spawning ────────────────────────────────────────────────────────

    fn spawn_fuzzers(&self) -> Result<Vec<process::Child>> {
        if self.no_afl && self.no_honggfuzz && !self.libfuzzer_enabled() {
            return Err(anyhow!("Pick at least one fuzzer"));
        }

        let mut handles = vec![];
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        let (afl_jobs, honggfuzz_jobs, libfuzzer_jobs) = self.allocate_jobs();

        if afl_jobs > 0 {
            fs::create_dir_all(format!("{}/afl", self.output_target()))?;
            self.spawn_afl(&cargo, afl_jobs, &mut handles)?;
            eprintln!("    Launched afl ({afl_jobs} instances)");
        }

        if honggfuzz_jobs > 0 {
            self.spawn_honggfuzz(&cargo, honggfuzz_jobs, &mut handles)?;
            eprintln!("    Launched honggfuzz ({honggfuzz_jobs} threads)");
        }

        if libfuzzer_jobs > 0 {
            self.spawn_libfuzzer(libfuzzer_jobs, &mut handles)?;
            eprintln!("    Launched libfuzzer ({libfuzzer_jobs} workers)");
        }

        Ok(handles)
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
    ) -> Result<()> {
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

        for job_num in 0..afl_jobs {
            let is_main = job_num == 0;

            let fuzzer_name = if is_main {
                String::from("-Mmainaflfuzzer")
            } else {
                format!("-Ssecondaryfuzzer{job_num}")
            };

            // Only the main instance syncs from the shared corpus (honggfuzz bridge)
            let shared_corpus_flag = if !self.no_honggfuzz && job_num == 0 {
                format!("-F{corpus}")
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

            handles.push(
                process::Command::new(cargo)
                    .args(
                        [
                            "afl",
                            "fuzz",
                            &fuzzer_name,
                            &format!("-i{corpus}"),
                            &format!("-p{power_schedule}"),
                            &format!("-o{}/afl", self.output_target()),
                            &shared_corpus_flag,
                            &libfuzzer_sync_flag,
                            old_queue,
                            cmplog,
                            mopt,
                            &timeout_flag,
                        ]
                        .iter()
                        .filter(|a| !a.is_empty()),
                    )
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
                    .env("AFL_IMPORT_FIRST", "1")
                    .env(final_sync, "1")
                    .env("AFL_IGNORE_SEED_PROBLEMS", "1")
                    .stdout(log_destination())
                    .stderr(log_destination())
                    .spawn()?,
            );
        }

        Ok(())
    }

    fn spawn_honggfuzz(
        &self,
        cargo: &str,
        honggfuzz_jobs: u32,
        handles: &mut Vec<process::Child>,
    ) -> Result<()> {
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

        // The `script` invocation is a trick to get the correct TTY output for
        // honggfuzz (it requires a valid terminal).
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
                .env(
                    "HFUZZ_RUN_ARGS",
                    format!(
                        "--input={corpus} \
                         -o{}/honggfuzz/corpus \
                         -n{honggfuzz_jobs} \
                         --dynamic_input={}/queue \
                         {timeout_flag} {dict_flag}",
                        self.output_target(),
                        self.output_target(),
                    ),
                )
                .stdin(Stdio::null())
                .stderr(hfuzz_log)
                .stdout(hfuzz_log_clone)
                .spawn()?,
        );

        Ok(())
    }

    fn spawn_libfuzzer(
        &self,
        libfuzzer_jobs: u32,
        handles: &mut Vec<process::Child>,
    ) -> Result<()> {
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

        Ok(())
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

use crate::ui::ProcessSlot;
use crate::{config, Build, Fuzz};
use anyhow::{anyhow, Context, Result};
use glob::glob;
use std::{
    collections::{BTreeMap, HashSet},
    env, fs,
    fs::File,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{self, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Print per-worker configuration to stderr.
fn log_afl_worker(job_num: u32, label: &str, env_vars: &BTreeMap<String, String>, cmd: &str) {
    eprintln!("    -- AFL worker {job_num} ({label}) --");
    if env_vars.is_empty() {
        eprintln!("    (no env vars configured)");
    } else {
        for (k, v) in env_vars {
            eprintln!("    env {k}={v}");
        }
    }
    eprintln!("    $ {cmd}");
    eprintln!();
}

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigint(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

use std::os::unix::process::CommandExt;

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
            None => format!("{}/{}/corpus", self.output().display(), self.target()),
        }
    }

    /// `{output}/{target}` — the per-target output root.
    fn output_target(&self) -> String {
        format!("{}/{}", self.output().display(), self.target())
    }

    fn afl_enabled(&self) -> bool {
        !self.no_afl
    }

    fn honggfuzz_enabled(&self) -> bool {
        self.honggfuzz_config.is_some()
    }

    fn libfuzzer_enabled(&self) -> bool {
        self.libfuzzer_config.is_some()
    }

    // ── public entry point ──────────────────────────────────────────────

    pub fn fuzz(&mut self) -> Result<()> {
        // Load TOML config and merge with CLI args.
        self.resolve_config()?;

        // target is required
        if self.target.is_none() {
            return Err(anyhow!(
                "target is required (positional arg or [fuzz] target in config)"
            ));
        }

        // Resolve output to an absolute path so all printed paths are absolute.
        fs::create_dir_all(self.output())?;
        self.output = Some(self.output().canonicalize()?);

        // Build all enabled engines.
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
        fs::create_dir_all(format!("{}/honggfuzz/dynamic_input/", self.output_target()))?;
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

        let crash_path = Path::new(&crash_dir);

        if self.honggfuzz_enabled() {
            self.check_honggfuzz_oversized_files()?;
        }

        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = handle_sigint as libc::sighandler_t;
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = 0;
            libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        }

        let loop_start = Instant::now();

        let mut processes = self.spawn_fuzzers_afl_first()?;
        self.print_launch_info(&crash_dir);

        self.run_loop(&mut processes, crash_path)?;

        stop_fuzzers(&mut processes)?;
        let _ = self.collect_crashes(crash_path);

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

    fn print_launch_info(&self, crash_dir: &str) {
        eprintln!("    Crashes: {crash_dir}");
        for dir in &self.external_corpus {
            let count = fs::read_dir(dir)
                .map(|entries| entries.flatten().filter(|e| e.path().is_file()).count())
                .unwrap_or(0);
            if count > 0 {
                eprintln!(
                    "    External corpus: {} (contains {count} files — move them to input corpus?)",
                    dir.display()
                );
            } else {
                eprintln!("    External corpus: {}", dir.display());
            }
        }
    }

    /// Main loop: crash collection, corpus sync, liveness check.
    fn run_loop(
        &mut self,
        processes: &mut [Option<ProcessSlot>],
        crash_path: &Path,
    ) -> Result<()> {
        let mut last_synced_created_time: Option<SystemTime> = None;
        let mut last_sync_time = Instant::now();

        loop {
            if STOP.load(Ordering::Relaxed) {
                break;
            }

            thread::sleep(Duration::from_secs(1));

            if STOP.load(Ordering::Relaxed) {
                break;
            }

            // ── crash collection (non-fatal during shutdown) ────────────
            if let Err(e) = self.collect_crashes(crash_path) {
                if STOP.load(Ordering::Relaxed) {
                    break;
                }
                return Err(e);
            }

            // ── corpus sync (every N minutes) ───────────────────────────
            if last_sync_time.elapsed().as_secs() > self.sync_interval() * 60 {
                let sync_result = self.sync_corpus(last_synced_created_time);
                match sync_result {
                    Ok(t) => last_synced_created_time = t,
                    Err(e) => {
                        if STOP.load(Ordering::Relaxed) {
                            break;
                        }
                        return Err(e);
                    }
                }
                last_sync_time = Instant::now();
            }

            // ── liveness check ──────────────────────────────────────────
            let all_dead = processes.iter_mut().all(|slot| {
                slot.as_mut()
                    .is_none_or(|ps| ps.child.try_wait().unwrap_or(None).is_some())
            });
            if all_dead {
                break;
            }
        }

        Ok(())
    }



    // ── crash collection ────────────────────────────────────────────────

    fn collect_crashes(&self, crash_path: &Path) -> Result<()> {
        let afl_pattern = format!("{}/afl/*/crashes", self.output_target());
        let afl_dirs: Vec<_> = glob(&afl_pattern)
            .map_err(|_| anyhow!("Failed to read crashes glob pattern"))?
            .flatten()
            .map(|d| ("afl", d))
            .collect();

        let mut dirs: Vec<(&str, PathBuf)> = afl_dirs;
        dirs.push((
            "honggfuzz",
            format!("{}/honggfuzz/{}", self.output_target(), self.target()).into(),
        ));
        if self.libfuzzer_enabled() {
            dirs.push((
                "libfuzzer",
                format!("{}/libfuzzer/crashes", self.output_target()).into(),
            ));
        }

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (engine, dir) in dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_str().unwrap_or_default();
                    if name_str.is_empty()
                        || ["README.txt", "HONGGFUZZ.REPORT.TXT", "input"].contains(&name_str)
                    {
                        continue;
                    }
                    let dest_name = format!("{engine}_{ts}_{name_str}");
                    let dest = crash_path.join(&dest_name);
                    if dest.exists() {
                        continue;
                    }
                    // Also skip if we already collected this crash under a
                    // different timestamp (same engine + original name).
                    let already_collected = fs::read_dir(crash_path)
                        .into_iter()
                        .flatten()
                        .flatten()
                        .any(|e| {
                            let n = e.file_name();
                            let s = n.to_str().unwrap_or_default();
                            s.starts_with(&format!("{engine}_")) && s.ends_with(name_str)
                        });
                    if already_collected {
                        continue;
                    }
                    fs::copy(entry.path(), dest)?;
                }
            }
        }
        Ok(())
    }

    // ── corpus sync ─────────────────────────────────────────────────────

    fn sync_corpus(&mut self, last_synced: Option<SystemTime>) -> Result<Option<SystemTime>> {
        let max_len = self.max_input_size() as u64;
        let mut newest = last_synced;

        // Build source lists per engine.
        let afl_queue: PathBuf = format!("{}/afl/mainaflfuzzer/queue", self.output_target()).into();
        let hongg_corpus: PathBuf = format!("{}/honggfuzz/corpus", self.output_target()).into();
        let hongg_input: PathBuf = format!("{}/honggfuzz/dynamic_input", self.output_target()).into();
        let lf_corpus: PathBuf = format!("{}/libfuzzer/corpus", self.output_target()).into();

        let external: Vec<PathBuf> = crate::sync::collect_external_files(
            &self.external_corpus,
            self.external_corpus_recursive,
            last_synced,
        )
        .iter()
        .map(|p| p.parent().unwrap_or(Path::new(".")).to_path_buf())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

        // 1. External → AFL queue (hongg/libfuzzer→AFL is handled by -F).
        if self.afl_enabled() && !self.external_corpus.is_empty() {
            let mut sources = external.clone();
            // Deduplicate source dirs.
            sources.sort();
            sources.dedup();
            if let Ok(t) = crate::sync::sync_files(
                &sources,
                &afl_queue,
                last_synced,
                max_len,
                &mut self.sync_hashes,
            ) {
                if t.is_some() {
                    newest = t;
                }
            }
        }

        // 2. AFL + libfuzzer + external → honggfuzz dynamic_input.
        if self.honggfuzz_enabled() {
            let mut sources = vec![afl_queue.clone()];
            if self.libfuzzer_enabled() {
                sources.push(lf_corpus.clone());
            }
            sources.extend(external.iter().cloned());
            if let Ok(t) = crate::sync::sync_files(
                &sources,
                &hongg_input,
                last_synced,
                max_len,
                &mut self.sync_hashes,
            ) {
                if t.is_some() {
                    newest = t;
                }
            }
        }

        // 3. AFL + honggfuzz + external → libfuzzer corpus.
        if self.libfuzzer_enabled() {
            let mut sources = vec![afl_queue.clone()];
            if self.honggfuzz_enabled() {
                sources.push(hongg_corpus.clone());
            }
            sources.extend(external.iter().cloned());
            if let Ok(t) = crate::sync::sync_files(
                &sources,
                &lf_corpus,
                last_synced,
                max_len,
                &mut self.sync_hashes,
            ) {
                if t.is_some() {
                    newest = t;
                }
            }
        }

        Ok(newest)
    }

    // ── spawning ────────────────────────────────────────────────────────

    fn spawn_fuzzers_afl_first(&mut self) -> Result<Vec<Option<ProcessSlot>>> {
        let (a, h, l) = self.allocate_jobs();
        self.spawn_fuzzers_with_allocation(a, h, l)
    }

    fn spawn_fuzzers_with_allocation(
        &mut self,
        afl_jobs: u32,
        honggfuzz_jobs: u32,
        libfuzzer_jobs: u32,
    ) -> Result<Vec<Option<ProcessSlot>>> {
        if afl_jobs == 0 && honggfuzz_jobs == 0 && libfuzzer_jobs == 0 {
            return Err(anyhow!("Pick at least one fuzzer"));
        }

        let mut handles: Vec<Option<ProcessSlot>> = vec![];
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        if afl_jobs > 0 {
            fs::create_dir_all(format!("{}/afl", self.output_target()))?;
            self.spawn_afl(&cargo, afl_jobs, &mut handles)?;
            eprintln!("    Launched AFL++ ({afl_jobs} instances)");
        }

        if honggfuzz_jobs > 0 {
            self.spawn_honggfuzz(&cargo, &mut handles)?;
            eprintln!("    Launched honggfuzz");
        }

        if libfuzzer_jobs > 0 {
            self.spawn_libfuzzer(&mut handles)?;
            eprintln!("    Launched libfuzzer");
        }

        // Print log paths.
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

        Ok(handles)
    }

    /// Allocate jobs between AFL++, honggfuzz and libfuzzer.
    /// Returns (afl_jobs, honggfuzz_slots, libfuzzer_slots).
    /// Each configured satellite takes 1 slot from the total. AFL gets the rest.
    /// Internal parallelism (hongg -n, libfuzzer -fork) is in user args.
    fn allocate_jobs(&self) -> (u32, u32, u32) {
        let satellites = self.honggfuzz_enabled() as u32 + self.libfuzzer_enabled() as u32;
        let afl_jobs = if self.afl_enabled() {
            self.jobs().saturating_sub(satellites)
        } else {
            0
        };
        let h = self.honggfuzz_enabled() as u32;
        let l = self.libfuzzer_enabled() as u32;
        (afl_jobs, h, l)
    }

    /// Compute the AFL++ input directory (resume-aware).
    fn afl_input_dir(&self) -> Result<String> {
        let corpus = self.corpus_dir();
        let afl_queue_dir = format!("{}/afl/mainaflfuzzer/queue", self.output_target());
        let afl_can_resume = Path::new(&afl_queue_dir)
            .read_dir()
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);

        if afl_can_resume {
            let minimal = format!("{}/afl/_seed", self.output_target());
            fs::create_dir_all(&minimal)?;
            let marker = format!("{minimal}/init");
            if !Path::new(&marker).exists() {
                File::create(&marker)?.write_all(b"00000000\n")?;
            }
            Ok(minimal)
        } else {
            Ok(corpus)
        }
    }

    /// AFL++ dictionary flags (shared by main and secondaries).
    fn afl_dict_flags(&self) -> Vec<String> {
        if self.dictionaries.is_empty() {
            vec![]
        } else if self.dictionaries.len() <= 4 {
            self.dictionaries
                .iter()
                .map(|d| format!("-x{}", d.display()))
                .collect()
        } else {
            let merged = self.merged_dict.as_ref().unwrap();
            vec![format!("-x{}", merged.display())]
        }
    }

    /// Spawn a single AFL++ secondary instance.  Returns (child, command_string).
    fn spawn_afl_secondary(&self, cargo: &str, job_num: u32) -> Result<(process::Child, String)> {
        let worker_cfg = self.afl_worker_configs.get(&job_num);

        // Custom command: delegate to sh -c.
        if let Some(command) = worker_cfg.and_then(|c| c.command.as_deref()) {
            return self.spawn_afl_custom(job_num, command);
        }

        let afl_input_dir = self.afl_input_dir()?;
        let dict_flags = self.afl_dict_flags();

        let fuzzer_name = format!("-Ssecondaryfuzzer{job_num}");
        let target_path = format!("./target/afl/debug/{}", self.target());

        let timeout_flag = match self.timeout {
            Some(t) => format!("-t{}", t * 1000),
            None => String::new(),
        };
        let max_len_flag = format!("-G{}", self.max_input_size());

        let log_name = format!("afl_{job_num}.log");
        let log_destination = || -> Stdio {
            File::create(format!("{}/logs/{log_name}", self.output_target()))
                .unwrap()
                .into()
        };

        // Minimal auto-generated args. Everything else (power schedule, cmplog,
        // old queue, etc.) comes from user's `args` in the config.
        let mut afl_args: Vec<String> = [
            "afl".to_string(),
            "fuzz".to_string(),
            fuzzer_name,
            format!("-i{afl_input_dir}"),
            format!("-o{}/afl", self.output_target()),
            timeout_flag,
            max_len_flag,
        ]
        .into_iter()
        .filter(|a| !a.is_empty())
        .collect();

        // Append user args from config.
        if let Some(extra) = worker_cfg.and_then(|c| c.args.as_deref()) {
            afl_args.extend(extra.split_whitespace().map(|s| s.to_string()));
        }

        // Resolve env: all config + worker config merged, no hardcoded defaults.
        let env_vars = config::resolve_afl_env(&self.afl_all_config, worker_cfg);
        for (k, v) in &env_vars {
            if k == "AFL_TMPDIR" {
                let _ = std::fs::create_dir_all(v);
            }
        }

        let mut cmd = process::Command::new(cargo);
        cmd.args(&afl_args)
            .args(&dict_flags)
            .arg(&target_path)
            .stdout(log_destination())
            .stderr(log_destination())
            .process_group(0);
        for (k, v) in &env_vars {
            cmd.env(k, v);
        }

        // Build display strings.
        let mut cmd_parts: Vec<&str> = vec![cargo];
        cmd_parts.extend(afl_args.iter().map(|s| s.as_str()));
        cmd_parts.extend(dict_flags.iter().map(|s| s.as_str()));
        cmd_parts.push(&target_path);
        let cmd_str = cmd_parts.join(" ");
        log_afl_worker(job_num, "secondary", &env_vars, &cmd_str);

        Ok((cmd.spawn()?, cmd_str))
    }

    /// Spawn an AFL++ worker with a custom command (sh -c).
    fn spawn_afl_custom(&self, job_num: u32, command: &str) -> Result<(process::Child, String)> {
        let log_name = if job_num == 0 {
            "afl.log".to_string()
        } else {
            format!("afl_{job_num}.log")
        };
        let log_destination = || -> Stdio {
            File::create(format!("{}/logs/{log_name}", self.output_target()))
                .unwrap()
                .into()
        };

        let worker_cfg = self.afl_worker_configs.get(&job_num);
        let env_vars = config::resolve_afl_env(&self.afl_all_config, worker_cfg);
        for (k, v) in &env_vars {
            if k == "AFL_TMPDIR" {
                let _ = std::fs::create_dir_all(v);
            }
        }

        let mut cmd = process::Command::new("sh");
        cmd.arg("-c")
            .arg(command)
            .stdout(log_destination())
            .stderr(log_destination())
            .process_group(0);
        for (k, v) in &env_vars {
            cmd.env(k, v);
        }

        log_afl_worker(job_num, "custom", &env_vars, command);

        Ok((cmd.spawn()?, command.to_string()))
    }

    fn spawn_afl(
        &mut self,
        cargo: &str,
        afl_jobs: u32,
        handles: &mut Vec<Option<ProcessSlot>>,
    ) -> Result<Vec<String>> {
        let afl_input_dir = self.afl_input_dir()?;
        let dict_flags = self.afl_dict_flags();

        let mut cmds = Vec::new();

        // Set next_afl_job_num early so spawn_afl_secondary sees total count.
        self.next_afl_job_num = afl_jobs;

        // Spawn main instance (job_num=0) — unique -M flag, -F sync flags.
        {
            let job_num: u32 = 0;
            let worker_cfg = self.afl_worker_configs.get(&job_num);

            // Custom command: delegate to sh -c.
            if let Some(command) = worker_cfg.and_then(|c| c.command.as_deref()) {
                let (child, cmd_str) = self.spawn_afl_custom(job_num, command)?;
                cmds.push(cmd_str.clone());
                handles.push(Some(ProcessSlot {
                    child,
                    paused: false,
                }));
            } else {
                let fuzzer_name = String::from("-Mmainaflfuzzer");

                let honggfuzz_sync_flag = if self.honggfuzz_enabled() {
                    format!("-F{}/honggfuzz/corpus", self.output_target())
                } else {
                    String::new()
                };
                let libfuzzer_sync_flag = if self.libfuzzer_enabled() {
                    format!("-F{}/libfuzzer/corpus", self.output_target())
                } else {
                    String::new()
                };

                let timeout_flag = match self.timeout {
                    Some(t) => format!("-t{}", t * 1000),
                    None => String::new(),
                };
                let max_len_flag = format!("-G{}", self.max_input_size());

                let log_destination = || -> Stdio {
                    File::create(format!("{}/logs/afl.log", self.output_target()))
                        .unwrap()
                        .into()
                };

                let target_path = format!("./target/afl/debug/{}", self.target());

                // Minimal auto-generated args. User adds power schedule etc. via `args`.
                let mut afl_args: Vec<String> = [
                    "afl".to_string(),
                    "fuzz".to_string(),
                    fuzzer_name.clone(),
                    format!("-i{afl_input_dir}"),
                    format!("-o{}/afl", self.output_target()),
                    honggfuzz_sync_flag.clone(),
                    libfuzzer_sync_flag.clone(),
                    timeout_flag.clone(),
                    max_len_flag.clone(),
                ]
                .into_iter()
                .filter(|a| !a.is_empty())
                .collect();

                // Append user args from config.
                if let Some(extra) = worker_cfg.and_then(|c| c.args.as_deref()) {
                    afl_args.extend(extra.split_whitespace().map(|s| s.to_string()));
                }

                // Resolve env: all config + worker config merged, no hardcoded defaults.
                let env_vars = config::resolve_afl_env(&self.afl_all_config, worker_cfg);
                for (k, v) in &env_vars {
                    if k == "AFL_TMPDIR" {
                        let _ = std::fs::create_dir_all(v);
                    }
                }

                let mut cmd_parts: Vec<&str> = vec![cargo];
                cmd_parts.extend(afl_args.iter().map(|s| s.as_str()));
                cmd_parts.extend(dict_flags.iter().map(|s| s.as_str()));
                cmd_parts.push(&target_path);
                let main_cmd_str = cmd_parts.join(" ");
                cmds.push(main_cmd_str.clone());
                log_afl_worker(job_num, "main", &env_vars, &main_cmd_str);

                let mut cmd = process::Command::new(cargo);
                cmd.args(&afl_args)
                    .args(&dict_flags)
                    .arg(&target_path)
                    .stdout(log_destination())
                    .stderr(log_destination())
                    .process_group(0);
                for (k, v) in &env_vars {
                    cmd.env(k, v);
                }

                handles.push(Some(ProcessSlot {
                    child: cmd.spawn()?,
                    paused: false,
                }));
            }
        }

        // Spawn secondaries (job_num 1..afl_jobs)
        for job_num in 1..afl_jobs {
            let (child, sec_cmd_str) = self.spawn_afl_secondary(cargo, job_num)?;
            cmds.push(sec_cmd_str.clone());

            handles.push(Some(ProcessSlot {
                child,
                paused: false,
            }));
        }

        Ok(cmds)
    }

    fn spawn_honggfuzz(
        &self,
        cargo: &str,
        handles: &mut Vec<Option<ProcessSlot>>,
    ) -> Result<String> {
        let corpus = self.corpus_dir();
        let worker_cfg = self.honggfuzz_config.as_ref();

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

        let extra_args = worker_cfg
            .and_then(|c| c.args.as_deref())
            .unwrap_or("");

        // The `script` invocation is a trick to get the correct TTY output for
        // honggfuzz (it requires a valid terminal).
        let hfuzz_run_args = format!(
            "--input={corpus} \
             -o{}/honggfuzz/corpus \
             --dynamic_input={}/honggfuzz/dynamic_input \
             -F{} \
             {timeout_flag} {dict_flag} {extra_args}",
            self.output_target(),
            self.output_target(),
            self.max_input_size(),
        );

        let hfuzz_workspace = format!("{}/honggfuzz", self.output_target());

        // Collect all env vars for logging.
        let mut env_vars = BTreeMap::new();
        env_vars.insert(
            "HFUZZ_BUILD_ARGS".to_string(),
            "--features=multifuzz/honggfuzz".to_string(),
        );
        env_vars.insert("CARGO_TARGET_DIR".to_string(), "./target/honggfuzz".to_string());
        env_vars.insert("HFUZZ_WORKSPACE".to_string(), hfuzz_workspace.clone());
        env_vars.insert("HFUZZ_RUN_ARGS".to_string(), hfuzz_run_args.clone());
        if let Some(user_env) = worker_cfg.and_then(|c| c.env.as_ref()) {
            for (k, v) in user_env {
                env_vars.insert(k.clone(), v.clone());
            }
        }

        let cmd_str = format!(
            "script --flush --quiet -c \"{cargo} hfuzz run {}\" /dev/null",
            self.target(),
        );
        log_afl_worker(0, "honggfuzz", &env_vars, &cmd_str);

        let hfuzz_log = File::create(format!("{}/logs/honggfuzz.log", self.output_target()))?;
        let hfuzz_log_clone = hfuzz_log.try_clone()?;

        let mut cmd = process::Command::new("script");
        cmd.args([
            "--flush",
            "--quiet",
            "-c",
            &format!("{cargo} hfuzz run {}", self.target()),
            "/dev/null",
        ]);
        for (k, v) in &env_vars {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::null())
            .stderr(hfuzz_log)
            .stdout(hfuzz_log_clone)
            .process_group(0);

        handles.push(Some(ProcessSlot {
            child: cmd.spawn()?,
            paused: false,
        }));

        Ok(cmd_str)
    }

    fn spawn_libfuzzer(
        &self,
        handles: &mut Vec<Option<ProcessSlot>>,
    ) -> Result<String> {
        let worker_cfg = self.libfuzzer_config.as_ref();

        // The libfuzzer binary is built with --target=<triple> to isolate
        // SanitizerCoverage flags from build scripts.
        let host = std::env::consts::ARCH.to_string() + "-unknown-" + std::env::consts::OS + "-gnu";
        let binary = format!("./target/libfuzzer/{host}/release/{}", self.target());
        let corpus = self.corpus_dir();

        let mut args = vec![
            format!("{}/libfuzzer/corpus/", self.output_target()),
            corpus,
            format!(
                "-artifact_prefix={}/libfuzzer/crashes/",
                self.output_target()
            ),
            "-reload=1".to_string(),
            "-print_final_stats=1".to_string(),
            "-ignore_crashes=1".to_string(),
            "-ignore_ooms=1".to_string(),
            "-ignore_timeouts=1".to_string(),
            format!("-max_len={}", self.max_input_size()),
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

        // Append user args from config.
        if let Some(extra) = worker_cfg.and_then(|c| c.args.as_deref()) {
            args.extend(extra.split_whitespace().map(String::from));
        }

        // Collect env for logging.
        let env_vars: BTreeMap<String, String> = worker_cfg
            .and_then(|c| c.env.as_ref())
            .map(|e| e.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();

        let cmd_str = format!("{binary} {}", args.join(" "));
        log_afl_worker(0, "libfuzzer", &env_vars, &cmd_str);

        let lf_log = File::create(format!("{}/logs/libfuzzer.log", self.output_target()))?;
        let lf_log_clone = lf_log.try_clone()?;

        let mut cmd = process::Command::new(&binary);
        cmd.args(&args)
            .stdout(lf_log)
            .stderr(lf_log_clone)
            .process_group(0);
        for (k, v) in &env_vars {
            cmd.env(k, v);
        }

        handles.push(Some(ProcessSlot {
            child: cmd.spawn()
                .with_context(|| format!("Failed to spawn libfuzzer binary: {binary}"))?,
            paused: false,
        }));

        Ok(cmd_str)
    }

    /// Check for oversized files that would crash honggfuzz and prompt for removal.
    /// Must be called BEFORE the stdin command thread is spawned.
    fn check_honggfuzz_oversized_files(&self) -> Result<()> {
        let max_len = self.max_input_size() as u64;
        let mut oversized: Vec<PathBuf> = Vec::new();
        for dir in [
            format!("{}/honggfuzz/dynamic_input", self.output_target()),
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
                self.max_input_size(),
            );
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
        Ok(())
    }
}

// ── process management ──────────────────────────────────────────────────

/// Kill a process and all its descendants.
///
/// First tries SIGTERM to the process group (negative PID), which catches
/// libfuzzer fork-mode workers spawned via `system()`. Falls back to
/// recursive pgrep-based tree walk for processes that escaped the group.
fn kill_process_tree(pid: u32) -> Result<()> {
    let pid_i32 = pid as i32;

    // SIGTERM the entire process group rooted at this PID.
    // Negative PID → signal the process group whose PGID equals |pid|.
    unsafe {
        libc::kill(-pid_i32, libc::SIGTERM);
    }

    // Also walk the tree via pgrep in case any children have a different PGID
    // (e.g. `script` wrapper creates a new session).
    kill_subprocesses_recursively(&pid.to_string())?;

    Ok(())
}

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

/// Send a signal to an entire process group.
fn send_signal_to_process_group(pid: u32, signal: libc::c_int) {
    unsafe {
        libc::kill(-(pid as i32), signal);
    }
}


fn stop_fuzzers(processes: &mut [Option<ProcessSlot>]) -> Result<()> {
    // Send SIGTERM to all workers first.
    for slot in processes.iter_mut() {
        if let Some(ps) = slot.as_mut() {
            if ps.paused {
                send_signal_to_process_group(ps.child.id(), libc::SIGCONT);
            }
            kill_process_tree(ps.child.id())?;
        }
    }
    // Wait for all workers to actually terminate.
    for slot in processes.iter_mut() {
        if let Some(ps) = slot.as_mut() {
            let _ = ps.child.wait();
        }
    }
    // Now drop the slots.
    for slot in processes.iter_mut() {
        *slot = None;
    }
    Ok(())
}

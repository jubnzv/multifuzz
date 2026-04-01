use crate::{config, Build, Fuzz};
use anyhow::{anyhow, Context, Result};
use std::{
    collections::{BTreeMap, HashSet},
    env, fs,
    fs::File,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{self, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant, SystemTime},
};

/// Extract `--target-dir` value from a build command string.
fn extract_target_dir(cmd: &str) -> Option<String> {
    // --target-dir=path
    if let Some(pos) = cmd.find("--target-dir=") {
        let rest = &cmd[pos + 13..];
        let end = rest.find(' ').unwrap_or(rest.len());
        return Some(rest[..end].to_string());
    }
    // --target-dir path
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    for (i, part) in parts.iter().enumerate() {
        if *part == "--target-dir" {
            if let Some(next) = parts.get(i + 1) {
                return Some(next.to_string());
            }
        }
    }
    None
}

/// (process handles, worker names + log paths)
type SpawnResult = (Vec<Option<process::Child>>, Vec<(String, String)>);

/// RAII guard that deletes the lockfile on drop (normal exit, Ctrl-C, all fuzzers dead).
struct LockGuard {
    _file: File,
    path: String,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

static NO_COLORS: AtomicBool = AtomicBool::new(false);

// ANSI escape codes.
fn c_reset() -> &'static str {
    if NO_COLORS.load(Ordering::Relaxed) {
        ""
    } else {
        "\x1b[0m"
    }
}
fn c_bold_red() -> &'static str {
    if NO_COLORS.load(Ordering::Relaxed) {
        ""
    } else {
        "\x1b[1;31m"
    }
}
fn c_bold_orange() -> &'static str {
    if NO_COLORS.load(Ordering::Relaxed) {
        ""
    } else {
        "\x1b[1;33m"
    }
}
fn c_bold_green() -> &'static str {
    if NO_COLORS.load(Ordering::Relaxed) {
        ""
    } else {
        "\x1b[1;32m"
    }
}

/// Timestamped log to stderr: `[HH:MM:SS] message`.
macro_rules! log {
    ($($arg:tt)*) => {{
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let t = unsafe {
            let t = secs as libc::time_t;
            *libc::localtime(&t)
        };
        eprint!("[{:02}:{:02}:{:02}] ", t.tm_hour, t.tm_min, t.tm_sec);
        eprintln!($($arg)*);
    }};
}

/// Timestamped eprint (no newline) for inline sync messages.
macro_rules! log_inline {
    ($($arg:tt)*) => {{
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let t = unsafe {
            let t = secs as libc::time_t;
            *libc::localtime(&t)
        };
        eprint!("[{:02}:{:02}:{:02}] ", t.tm_hour, t.tm_min, t.tm_sec);
        eprint!($($arg)*);
    }};
}

/// Print per-worker configuration to stderr.
fn log_worker(name: &str, env_vars: &BTreeMap<String, String>, cmd: &str) {
    eprintln!("-- {name} --");
    if env_vars.is_empty() {
        eprintln!("(no env vars configured)");
    } else {
        for (k, v) in env_vars {
            eprintln!("env {k}={v}");
        }
    }
    eprintln!("$ {cmd}");
    eprintln!();
}

static STOP: AtomicBool = AtomicBool::new(false);
static RELOAD: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigint(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
    // write() is async-signal-safe; eprintln!/log! are not.
    let _ = unsafe {
        libc::write(
            2,
            b"\nGracefully terminating...\n".as_ptr() as *const libc::c_void,
            26,
        )
    };
}

extern "C" fn handle_sigusr1(_: libc::c_int) {
    RELOAD.store(true, Ordering::Relaxed);
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
        self.afl_all_config.is_some() || !self.afl_worker_configs.is_empty()
    }

    fn honggfuzz_enabled(&self) -> bool {
        self.honggfuzz_config.is_some()
    }

    fn libfuzzer_enabled(&self) -> bool {
        self.libfuzzer_config.is_some()
    }

    /// Check if any AFL worker config has cmplog level args (-l followed by a digit).
    fn needs_cmplog(&self) -> bool {
        self.afl_worker_configs.values().any(|cfg| {
            cfg.args.as_deref().is_some_and(|args| {
                args.split_whitespace()
                    .any(|a| a.starts_with("-l") && a.len() > 2 && a.as_bytes()[2].is_ascii_digit())
            })
        })
    }

    fn afl_binary_path(&self) -> String {
        let cfg = config::load_config(self.config.as_deref()).ok();
        let cmd = cfg
            .as_ref()
            .and_then(|c| c.build.as_ref())
            .and_then(|b| b.afl.as_deref())
            .unwrap_or("--release");
        let profile = if cmd.contains("--release") {
            "release"
        } else {
            "debug"
        };
        let target_dir = extract_target_dir(cmd).unwrap_or_else(|| "./target/afl".into());
        format!("{target_dir}/{profile}/{}", self.target())
    }

    fn afl_cmplog_binary_path(&self) -> String {
        let cfg = config::load_config(self.config.as_deref()).ok();
        let cmd = cfg
            .as_ref()
            .and_then(|c| c.build.as_ref())
            .and_then(|b| b.afl_cmplog.as_deref())
            .unwrap_or("--release");
        let profile = if cmd.contains("--release") {
            "release"
        } else {
            "debug"
        };
        let target_dir = extract_target_dir(cmd).unwrap_or_else(|| "./target/afl-cmplog".into());
        format!("{target_dir}/{profile}/{}", self.target())
    }

    fn libfuzzer_binary_path(&self) -> String {
        let host = std::env::consts::ARCH.to_string() + "-unknown-" + std::env::consts::OS + "-gnu";
        let cfg = config::load_config(self.config.as_deref()).ok();
        let cmd = cfg
            .as_ref()
            .and_then(|c| c.build.as_ref())
            .and_then(|b| b.libfuzzer.as_deref())
            .unwrap_or("--release");
        let profile = if cmd.contains("--release") {
            "release"
        } else {
            "debug"
        };
        let target_dir =
            extract_target_dir(cmd).unwrap_or_else(|| format!("./target/libfuzzer/{host}"));
        format!("{target_dir}/{profile}/{}", self.target())
    }

    // ── public entry point ──────────────────────────────────────────────

    pub fn fuzz(&mut self) -> Result<()> {
        let config_path = self
            .config
            .as_deref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "./multifuzz.toml".to_string());
        self.resolve_config()?;
        NO_COLORS.store(self.no_colors, Ordering::Relaxed);
        log!("Loading config from {config_path}");

        // target is required
        if self.target.is_none() {
            return Err(anyhow!(
                "target is required (positional arg or [fuzz] target in config)"
            ));
        }

        // Resolve output to an absolute path so all printed paths are absolute.
        fs::create_dir_all(self.output())?;
        self.output = Some(self.output().canonicalize()?);

        // Lockfile: ensure only one multifuzz instance per output dir.
        let lock_path = format!("{}/.multifuzz.lock", self.output_target());
        fs::create_dir_all(self.output_target())?;
        let lock_file = File::create(&lock_path)
            .with_context(|| format!("Failed to create lockfile: {lock_path}"))?;
        use std::os::unix::io::AsRawFd;
        if unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(anyhow!(
                "Another multifuzz instance is already running (lockfile: {lock_path})"
            ));
        }
        let _lock_guard = LockGuard {
            _file: lock_file,
            path: lock_path,
        };

        let build = Build {
            config: self.config.clone(),
            afl_cmplog: self.needs_cmplog(),
            force: false,
        };
        build.build().context("Failed to build the fuzzers")?;

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

        if self.honggfuzz_enabled() {
            self.check_honggfuzz_oversized_files()?;

            // Copy corpus files into hongg's --input dir so it starts with
            // the full seed set. This is {HFUZZ_WORKSPACE}/{target}/input/ —
            // the dir hongg actually reads at startup for corpus minimization.
            // dynamic_input/ is for runtime sync only (consumed and deleted).
            let hongg_input = format!("{}/honggfuzz/{}/input", self.output_target(), self.target());
            fs::create_dir_all(&hongg_input)?;
            let mut seeded = 0usize;
            if let Ok(entries) = fs::read_dir(&corpus) {
                for entry in entries.flatten() {
                    let src = entry.path();
                    if src.is_file() {
                        let dest =
                            format!("{}/{}", hongg_input, entry.file_name().to_string_lossy());
                        if !Path::new(&dest).exists() {
                            let _ = fs::copy(&src, &dest);
                            seeded += 1;
                        }
                    }
                }
            }
            if seeded > 0 {
                log!("Seeded honggfuzz input with {seeded} corpus files");
            }
        }

        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = handle_sigint as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = 0;
            libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());

            let mut sa_usr1: libc::sigaction = std::mem::zeroed();
            sa_usr1.sa_sigaction = handle_sigusr1 as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut sa_usr1.sa_mask);
            sa_usr1.sa_flags = libc::SA_RESTART;
            libc::sigaction(libc::SIGUSR1, &sa_usr1, std::ptr::null_mut());
        }

        let loop_start = Instant::now();

        let (mut processes, worker_info) = self.spawn_fuzzers()?;

        // Write state file for `multifuzz worker ps/kill`.
        let state_entries: Vec<(String, u32, String)> = processes
            .iter()
            .zip(worker_info.iter())
            .filter_map(|(proc, (name, log))| {
                proc.as_ref().map(|ch| (name.clone(), ch.id(), log.clone()))
            })
            .collect();
        crate::worker::write_state(&self.output_target(), &state_entries);
        crate::worker::write_pid(&self.output_target());

        self.print_launch_info();
        log!("Fuzzing campaign started");

        self.run_loop(&mut processes, &worker_info)?;

        stop_fuzzers(&mut processes)?;
        crate::worker::remove_pid(&self.output_target());

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

        eprintln!();
        log!("Session complete ({runtime})");

        Ok(())
    }

    fn print_launch_info(&self) {
        eprintln!();
        eprintln!("Crashes:");
        if self.afl_enabled() {
            eprintln!("  AFL:       {}/afl/*/crashes/", self.output_target());
        }
        if self.honggfuzz_enabled() {
            eprintln!(
                "  honggfuzz: {}/honggfuzz/{}/",
                self.output_target(),
                self.target()
            );
        }
        if self.libfuzzer_enabled() {
            eprintln!("  libfuzzer: {}/libfuzzer/crashes/", self.output_target());
        }
        for dir in &self.external_corpus {
            eprintln!("External corpus: {}", dir.display());
        }

        // Sync status.
        let has_external = !self.external_corpus.is_empty();
        let has_hongg = self.honggfuzz_enabled();
        let has_libfuzzer = self.libfuzzer_enabled();
        let needs_sync = has_external || has_hongg || has_libfuzzer;

        if !self.sync_enabled() {
            if needs_sync {
                let cfg_path = self
                    .config
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "./multifuzz.toml".to_string());
                if has_external {
                    log!("{}WARNING{}: external corpus configured but sync is disabled. Set sync_interval in {cfg_path}", c_bold_orange(), c_reset());
                }
                if has_hongg || has_libfuzzer {
                    log!("{}WARNING{}: satellite engines configured but sync is disabled — no cross-engine corpus sharing. Set sync_interval in {cfg_path}", c_bold_orange(), c_reset());
                }
            }
            log!("Synchronization: {}disabled{}", c_bold_red(), c_reset());
        } else if !needs_sync {
            log!(
                "Synchronization: {}disabled{} (nothing to sync)",
                c_bold_red(),
                c_reset()
            );
        } else {
            let mins = self.sync_interval();
            log!(
                "Synchronization: {}every {mins}min{}",
                c_bold_green(),
                c_reset()
            );
            if has_external && self.afl_enabled() {
                eprintln!("  external → AFL");
            }
            if has_hongg {
                eprintln!("  AFL → honggfuzz");
            }
            if has_libfuzzer {
                eprintln!("  AFL → libfuzzer");
            }
        }
    }

    /// Main loop: corpus sync, liveness check.
    fn run_loop(
        &mut self,
        processes: &mut [Option<process::Child>],
        worker_info: &[(String, String)],
    ) -> Result<()> {
        let mut last_synced_created_time: Option<SystemTime> = None;
        let mut last_sync_time = Instant::now();
        let mut reported_dead: Vec<bool> = vec![false; processes.len()];
        let mut known_pids: HashSet<u32> = processes
            .iter()
            .filter_map(|p| p.as_ref().map(|ch| ch.id()))
            .collect();

        loop {
            if STOP.load(Ordering::Relaxed) {
                break;
            }

            thread::sleep(Duration::from_secs(1));

            if STOP.load(Ordering::Relaxed) {
                break;
            }

            // ── new worker detection (SIGUSR1) ─────────────────────────
            if RELOAD.load(Ordering::Relaxed) {
                RELOAD.store(false, Ordering::Relaxed);
                let current = crate::worker::read_state(&self.output_target());
                for entry in &current {
                    if entry.pid != 0 && known_pids.insert(entry.pid) {
                        log!(
                            "{}Worker attached: {}{}",
                            c_bold_green(),
                            entry.name,
                            c_reset()
                        );
                        eprintln!("  pid: {}", entry.pid);
                        eprintln!("  log: {}", entry.log);
                    }
                }
            }

            // ── corpus sync (every N minutes) ───────────────────────────
            if self.sync_enabled() && last_sync_time.elapsed().as_secs() > self.sync_interval() * 60
            {
                let hongg_alive = worker_info
                    .iter()
                    .zip(reported_dead.iter())
                    .any(|((name, _), &dead)| name == "honggfuzz" && !dead);
                let libfuzzer_alive = worker_info
                    .iter()
                    .zip(reported_dead.iter())
                    .any(|((name, _), &dead)| name == "libfuzzer" && !dead);
                let sync_result =
                    self.sync_corpus(last_synced_created_time, hongg_alive, libfuzzer_alive);
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
            let mut all_dead = true;
            let mut state_changed = false;
            for (i, slot) in processes.iter_mut().enumerate() {
                if let Some(child) = slot.as_mut() {
                    match child.try_wait() {
                        Ok(Some(status)) if !reported_dead[i] => {
                            reported_dead[i] = true;
                            state_changed = true;
                            let (name, log) = &worker_info[i];
                            let code = status
                                .code()
                                .map(|c| c.to_string())
                                .unwrap_or_else(|| "signal".to_string());
                            log!("{}{name} exited (code={code}){}", c_bold_red(), c_reset());
                            eprintln!("  log: {log}");
                            eprintln!("  restart: multifuzz worker start {name}");
                        }
                        Ok(None) => {
                            all_dead = false;
                        }
                        _ => {}
                    }
                }
            }
            if state_changed {
                let alive: Vec<(String, u32, String)> = processes
                    .iter()
                    .zip(worker_info.iter())
                    .zip(reported_dead.iter())
                    .filter_map(|((proc, (name, log)), &dead)| {
                        if dead {
                            return None;
                        }
                        proc.as_ref().map(|ch| (name.clone(), ch.id(), log.clone()))
                    })
                    .collect();
                crate::worker::write_state(&self.output_target(), &alive);
            }
            if all_dead {
                break;
            }
        }

        Ok(())
    }

    // ── corpus sync ─────────────────────────────────────────────────────

    fn sync_corpus(
        &mut self,
        last_synced: Option<SystemTime>,
        hongg_alive: bool,
        libfuzzer_alive: bool,
    ) -> Result<Option<SystemTime>> {
        let max_len = self.max_input_size() as u64;
        let mut newest = last_synced;

        // Build source lists per engine.
        let afl_queue: PathBuf = format!("{}/afl/master/queue", self.output_target()).into();
        let hongg_corpus: PathBuf = format!("{}/honggfuzz/corpus", self.output_target()).into();
        let hongg_input: PathBuf =
            format!("{}/honggfuzz/dynamic_input", self.output_target()).into();
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
            sources.sort();
            sources.dedup();
            log_inline!("Syncing external → AFL ... ");
            match crate::sync::sync_files(
                &sources,
                &afl_queue,
                last_synced,
                max_len,
                &mut self.sync_hashes,
            ) {
                Ok((t, n)) => {
                    if n > 0 {
                        eprintln!("{n} files");
                    } else {
                        eprintln!("nothing to sync");
                    }
                    if t.is_some() {
                        newest = t;
                    }
                }
                Err(e) => eprintln!("error: {e}"),
            }
        }

        // 2. AFL + libfuzzer + external → honggfuzz dynamic_input.
        if self.honggfuzz_enabled() && hongg_alive {
            let mut sources = vec![afl_queue.clone()];
            if self.libfuzzer_enabled() {
                sources.push(lf_corpus.clone());
            }
            sources.extend(external.iter().cloned());
            log_inline!("Syncing AFL → honggfuzz ... ");
            match crate::sync::sync_files(
                &sources,
                &hongg_input,
                last_synced,
                max_len,
                &mut self.sync_hashes,
            ) {
                Ok((t, n)) => {
                    if n > 0 {
                        eprintln!("{n} files");
                    } else {
                        eprintln!("nothing to sync");
                    }
                    if t.is_some() {
                        newest = t;
                    }
                }
                Err(e) => eprintln!("error: {e}"),
            }
        }

        // 3. AFL + honggfuzz + external → libfuzzer corpus.
        if self.libfuzzer_enabled() && libfuzzer_alive {
            let mut sources = vec![afl_queue.clone()];
            if self.honggfuzz_enabled() {
                sources.push(hongg_corpus.clone());
            }
            sources.extend(external.iter().cloned());
            log_inline!("Syncing AFL → libfuzzer ... ");
            match crate::sync::sync_files(
                &sources,
                &lf_corpus,
                last_synced,
                max_len,
                &mut self.sync_hashes,
            ) {
                Ok((t, n)) => {
                    if n > 0 {
                        eprintln!("{n} files");
                    } else {
                        eprintln!("nothing to sync");
                    }
                    if t.is_some() {
                        newest = t;
                    }
                }
                Err(e) => eprintln!("error: {e}"),
            }
        }

        Ok(newest)
    }

    // ── spawning ────────────────────────────────────────────────────────

    /// AFL worker count: derived from config sections.
    /// If explicit workerN keys exist, count = max key + 1 (so worker0..workerN are spawned).
    /// If only [fuzz.afl.all] exists (no workerN), spawn 1 worker (master only).
    fn afl_worker_count(&self) -> u32 {
        if !self.afl_enabled() {
            return 0;
        }
        if self.afl_worker_configs.is_empty() {
            1 // just master
        } else {
            self.afl_worker_configs.keys().max().unwrap() + 1
        }
    }

    /// Spawn all configured fuzzers. Returns (handles, worker_info) where
    /// worker_info[i] = (name, log_path) for handles[i].
    fn spawn_fuzzers(&mut self) -> Result<SpawnResult> {
        let afl_count = self.afl_worker_count();
        let has_hongg = self.honggfuzz_enabled();
        let has_libfuzzer = self.libfuzzer_enabled();

        if afl_count == 0 && !has_hongg && !has_libfuzzer {
            return Err(anyhow!("Pick at least one fuzzer"));
        }

        let mut handles: Vec<Option<process::Child>> = vec![];
        let mut worker_info: Vec<(String, String)> = vec![];
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
        let logs_dir = format!("{}/logs", self.output_target());

        if afl_count > 0 {
            fs::create_dir_all(format!("{}/afl", self.output_target()))?;
            self.spawn_afl(&cargo, afl_count, &mut handles)?;
            for i in 0..afl_count {
                let name = if i == 0 {
                    "AFL master".to_string()
                } else {
                    format!("AFL slave{i}")
                };
                let log = if i == 0 {
                    format!("{logs_dir}/afl.log")
                } else {
                    format!("{logs_dir}/afl_{i}.log")
                };
                worker_info.push((name, log));
            }
            log!("Launched AFL++ ({afl_count} instances)");
        }

        if has_hongg {
            self.spawn_honggfuzz(&mut handles)?;
            worker_info.push(("honggfuzz".to_string(), format!("{logs_dir}/honggfuzz.log")));
            log!("Launched honggfuzz");
        }

        if has_libfuzzer {
            self.spawn_libfuzzer(&mut handles)?;
            worker_info.push(("libfuzzer".to_string(), format!("{logs_dir}/libfuzzer.log")));
            log!("Launched libfuzzer");
        }

        eprintln!();
        eprintln!();
        eprintln!("Log files:");
        for (name, log) in &worker_info {
            eprintln!("  [{name}] tail -f {log}");
        }

        Ok((handles, worker_info))
    }

    /// Compute the AFL++ input directory (resume-aware).
    fn afl_input_dir(&self) -> Result<String> {
        let corpus = self.corpus_dir();
        let afl_queue_dir = format!("{}/afl/master/queue", self.output_target());
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

        let fuzzer_name = format!("-Sslave{job_num}");
        let target_path = self.afl_binary_path();

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

        // Auto-inject cmplog binary path if worker uses -l (cmplog level).
        if let Some(extra) = worker_cfg.and_then(|c| c.args.as_deref()) {
            let has_cmplog = extra
                .split_whitespace()
                .any(|a| a.starts_with("-l") && a.len() > 2 && a.as_bytes()[2].is_ascii_digit());
            if has_cmplog {
                afl_args.push(format!("-c{}", self.afl_cmplog_binary_path()));
            }
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
        log_worker(&format!("AFL slave{job_num}"), &env_vars, &cmd_str);

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

        let label = if job_num == 0 {
            "AFL master".to_string()
        } else {
            format!("AFL slave{job_num}")
        };
        log_worker(&format!("{label} (custom)"), &env_vars, command);

        Ok((cmd.spawn()?, command.to_string()))
    }

    fn spawn_afl(
        &mut self,
        cargo: &str,
        afl_jobs: u32,
        handles: &mut Vec<Option<process::Child>>,
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
                handles.push(Some(child));
            } else {
                let fuzzer_name = String::from("-Mmaster");

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

                let target_path = self.afl_binary_path();

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

                // Auto-inject cmplog binary path if worker uses -l (cmplog level).
                if let Some(extra) = worker_cfg.and_then(|c| c.args.as_deref()) {
                    let has_cmplog = extra.split_whitespace().any(|a| {
                        a.starts_with("-l") && a.len() > 2 && a.as_bytes()[2].is_ascii_digit()
                    });
                    if has_cmplog {
                        afl_args.push(format!("-c{}", self.afl_cmplog_binary_path()));
                    }
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
                log_worker("AFL master", &env_vars, &main_cmd_str);

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

                handles.push(Some(cmd.spawn()?));
            }
        }

        // Spawn secondaries (job_num 1..afl_jobs)
        for job_num in 1..afl_jobs {
            let (child, sec_cmd_str) = self.spawn_afl_secondary(cargo, job_num)?;
            cmds.push(sec_cmd_str.clone());

            handles.push(Some(child));
        }

        Ok(cmds)
    }

    fn spawn_honggfuzz(&self, handles: &mut Vec<Option<process::Child>>) -> Result<String> {
        let cfg = self.honggfuzz_config.as_ref().unwrap();

        let command = cfg.command.as_deref().ok_or_else(|| {
            anyhow!(
                "[fuzz.honggfuzz.worker] requires 'command'. Example:\n\
                 command = \"CARGO_TARGET_DIR=./target/honggfuzz HFUZZ_BUILD_ARGS='--features=multifuzz/honggfuzz' \
                 script --flush --quiet -c 'cargo hfuzz run {}' /dev/null\"",
                self.target()
            )
        })?;

        // Validate: user must not override structural paths.
        if let Some(env) = &cfg.env {
            for key in ["HFUZZ_WORKSPACE", "HFUZZ_RUN_ARGS", "CARGO_TARGET_DIR"] {
                if env.contains_key(key) {
                    return Err(anyhow!(
                        "honggfuzz worker env must not set {key} — managed by multifuzz"
                    ));
                }
            }
        }
        if let Some(args) = &cfg.args {
            for flag in ["--input", "--dynamic_input"] {
                if args.contains(flag) {
                    return Err(anyhow!(
                        "honggfuzz args must not contain {flag} — managed by multifuzz"
                    ));
                }
            }
            if args.split_whitespace().any(|a| a.starts_with("-o")) {
                return Err(anyhow!(
                    "honggfuzz args must not contain -o — managed by multifuzz"
                ));
            }
        }

        let corpus = self.corpus_dir();
        let user_args = cfg.args.as_deref().unwrap_or("");

        // Structural paths only — everything else from user args.
        let hfuzz_run_args = format!(
            "--input={corpus} \
             -o{output}/honggfuzz/corpus \
             --dynamic_input={output}/honggfuzz/dynamic_input \
             {user_args}",
            output = self.output_target(),
        );

        let mut env_vars = BTreeMap::new();
        env_vars.insert(
            "CARGO_TARGET_DIR".to_string(),
            "./target/honggfuzz".to_string(),
        );
        env_vars.insert(
            "HFUZZ_WORKSPACE".to_string(),
            format!("{}/honggfuzz", self.output_target()),
        );
        env_vars.insert("HFUZZ_RUN_ARGS".to_string(), hfuzz_run_args);
        if let Some(user_env) = &cfg.env {
            for (k, v) in user_env {
                env_vars.insert(k.clone(), v.clone());
            }
        }

        log_worker("honggfuzz", &env_vars, command);

        let hfuzz_log = File::create(format!("{}/logs/honggfuzz.log", self.output_target()))?;
        let hfuzz_log_clone = hfuzz_log.try_clone()?;

        let mut cmd = process::Command::new("sh");
        cmd.arg("-c").arg(command);
        for (k, v) in &env_vars {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::null())
            .stderr(hfuzz_log)
            .stdout(hfuzz_log_clone)
            .process_group(0);

        handles.push(Some(cmd.spawn()?));

        Ok(command.to_string())
    }

    fn spawn_libfuzzer(&self, handles: &mut Vec<Option<process::Child>>) -> Result<String> {
        let cfg = self.libfuzzer_config.as_ref().unwrap();

        // Validate: user must not override structural paths.
        if let Some(args) = &cfg.args {
            if args.contains("-artifact_prefix") {
                return Err(anyhow!(
                    "libfuzzer args must not contain -artifact_prefix — managed by multifuzz"
                ));
            }
        }

        let binary = self.libfuzzer_binary_path();
        let corpus = self.corpus_dir();

        // Structural args only — corpus dirs and crash prefix.
        let mut args = vec![
            format!("{}/libfuzzer/corpus/", self.output_target()),
            corpus,
            format!(
                "-artifact_prefix={}/libfuzzer/crashes/",
                self.output_target()
            ),
        ];

        // Append ALL user args (fork, reload, max_len, timeout, dict, etc.).
        if let Some(extra) = cfg.args.as_deref() {
            args.extend(extra.split_whitespace().map(String::from));
        }

        let env_vars: BTreeMap<String, String> = cfg
            .env
            .as_ref()
            .map(|e| e.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();

        let cmd_str = format!("{binary} {}", args.join(" "));
        log_worker("libfuzzer", &env_vars, &cmd_str);

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

        handles.push(Some(cmd.spawn().with_context(|| {
            format!("Failed to spawn libfuzzer binary: {binary}")
        })?));

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
                "Warning: {} file(s) exceed max_input_size ({} bytes) and will crash honggfuzz.",
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
                eprintln!("{count} file(s) in {dir}");
            }
            eprint!("Remove these copies? (originals are not affected) [Y/n] ");
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            let answer = answer.trim().to_lowercase();
            if answer.is_empty() || answer == "y" || answer == "yes" {
                for path in &oversized {
                    let _ = fs::remove_file(path);
                }
                eprintln!("Removed {} oversized file(s).", oversized.len());
            } else {
                eprintln!("Skipped removal. Honggfuzz may abort on oversized inputs.");
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

fn stop_fuzzers(processes: &mut [Option<process::Child>]) -> Result<()> {
    for slot in processes.iter_mut() {
        if let Some(child) = slot.as_mut() {
            kill_process_tree(child.id())?;
        }
    }
    for slot in processes.iter_mut() {
        if let Some(child) = slot.as_mut() {
            let _ = child.wait();
        }
    }
    for slot in processes.iter_mut() {
        *slot = None;
    }
    Ok(())
}

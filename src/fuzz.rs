use crate::ui::{Dashboard, EngineInfo, EngineKind, ProcessSlot};
use crate::{config, web, Build, Fuzz};
use anyhow::{anyhow, Context, Result};
use glob::glob;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env, fs,
    fs::File,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{self, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Per-worker AFL++ configuration computed by the distribution algorithm.
struct AflWorkerConfig {
    power_schedule: &'static str,
    cmplog_level: Option<&'static str>,
    old_queue: bool,
}

/// Compute AFL++ flags for a secondary worker based on total worker count.
///
/// Distributes power schedules, cmplog, and old-queue evenly:
/// - Power schedules rotate through all available modes.
/// - Cmplog on ~20% of workers (min 1 if workers >= 3), varying `-l` levels.
/// - Old queue (`-Z`) on ~10% of workers (min 1 if workers >= 5).
fn afl_worker_config(job_num: u32, total_secondaries: u32) -> AflWorkerConfig {
    const SCHEDULES: &[&str] = &[
        "explore", "fast", "coe", "exploit", "rare", "mmopt", "seek", "lin", "quad",
    ];
    const CMPLOG_LEVELS: &[&str] = &["-l2a", "-l1", "-l3at"];

    let n = total_secondaries as usize;
    let idx = (job_num - 1) as usize; // 0-based index among secondaries

    let power_schedule = SCHEDULES[idx % SCHEDULES.len()];

    // Cmplog: ~20% of workers, at least 1 when >= 3 secondaries.
    let cmplog_count = if n >= 3 { (n / 5).max(1) } else { 0 };
    let cmplog_level = if idx < cmplog_count {
        Some(CMPLOG_LEVELS[idx % CMPLOG_LEVELS.len()])
    } else {
        None
    };

    // Old queue: ~10% of workers, at least 1 when >= 5 secondaries.
    let old_queue_count = if n >= 5 { (n / 10).max(1) } else { 0 };
    let old_queue_start = cmplog_count;
    let old_queue = idx >= old_queue_start && idx < old_queue_start + old_queue_count;

    AflWorkerConfig {
        power_schedule,
        cmplog_level,
        old_queue,
    }
}

/// Print per-worker AFL configuration to stderr.
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

pub enum WebCommand {
    ScaleAfl(i32),
    PauseSlot(usize),
    ResumeSlot(usize),
    RemoveSlot(usize),
}
use std::os::unix::process::CommandExt;
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

    /// Honggfuzz is enabled when not explicitly disabled and there are >1 jobs
    /// (with a single job, AFL++ alone is more effective).
    fn honggfuzz_enabled(&self) -> bool {
        if self.no_honggfuzz {
            return false;
        }
        if self.no_afl {
            return true;
        }
        self.jobs() > 1
    }

    fn libfuzzer_enabled(&self) -> bool {
        !self.no_libfuzzer
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
            no_honggfuzz: self.no_honggfuzz,
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

        let crash_path = Path::new(&crash_dir);

        if !self.no_honggfuzz {
            self.check_honggfuzz_oversized_files()?;
        }

        // Web dashboard setup (optional)
        let (cmd_rx, web_html, _web_handle) = if self.web {
            let loading_html = concat!(
                "<!DOCTYPE html><html><head><meta charset=\"utf-8\">",
                "<meta http-equiv=\"refresh\" content=\"2\">",
                "<title>multifuzz</title>",
                "<style>body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:20px}</style>",
                "</head><body><h1>multifuzz</h1><p>Starting fuzzers...</p></body></html>",
            );
            let mut init_map = HashMap::new();
            for tab in &["exec", "corpus", "cpu", "mem"] {
                init_map.insert(tab.to_string(), loading_html.to_string());
            }
            let html: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(init_map));
            let (tx, rx) = mpsc::channel::<WebCommand>();
            let logs_dir = format!("{}/logs", self.output_target());
            let (handle, port) =
                web::start_server(self.web_port(), html.clone(), tx, &STOP, logs_dir)?;
            let url = format!("http://127.0.0.1:{port}");
            eprintln!("    Dashboard: {url}");
            let _ = process::Command::new("xdg-open")
                .arg(&url)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
            (Some(rx), Some(html), Some(handle))
        } else {
            (None, None, None)
        };

        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = handle_sigint as libc::sighandler_t;
            libc::sigemptyset(&mut sa.sa_mask);
            // No SA_RESTART: interrupted syscalls return EINTR immediately.
            sa.sa_flags = 0;
            libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        }

        let loop_start = Instant::now();

        let (mut processes, engines) = self.spawn_fuzzers_afl_first()?;
        self.print_launch_info(&crash_dir);

        let abs_corpus = fs::canonicalize(self.corpus_dir())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| self.corpus_dir());
        let abs_external: Vec<String> = self
            .external_corpus
            .iter()
            .map(|p| {
                fs::canonicalize(p)
                    .map(|c| c.display().to_string())
                    .unwrap_or_else(|_| p.display().to_string())
            })
            .collect();
        let abs_crash = fs::canonicalize(&crash_dir)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| crash_dir.clone());
        let mut dashboard = Dashboard::new(
            self.target(),
            &self.output_target(),
            engines,
            self.sync_interval(),
            &abs_corpus,
            abs_external,
            &abs_crash,
        );
        dashboard.record_baseline();

        self.run_phase(
            &mut processes,
            &mut dashboard,
            crash_path,
            cmd_rx.as_ref(),
            web_html.as_ref(),
        )?;

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

    /// Run the main tick loop: crash collection, corpus sync, optional web
    /// dashboard update, liveness check.
    fn run_phase(
        &mut self,
        processes: &mut Vec<Option<ProcessSlot>>,
        dashboard: &mut Dashboard,
        crash_path: &Path,
        cmd_rx: Option<&mpsc::Receiver<WebCommand>>,
        web_html: Option<&Arc<Mutex<HashMap<String, String>>>>,
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

            // Drain web commands, batching rapid-fire scale clicks
            if let Some(rx) = cmd_rx {
                let mut afl_delta: i32 = 0;
                while let Ok(cmd) = rx.try_recv() {
                    match cmd {
                        WebCommand::ScaleAfl(d) => {
                            afl_delta += d;
                        }
                        WebCommand::PauseSlot(slot) => {
                            handle_pause_slot(processes, slot);
                        }
                        WebCommand::ResumeSlot(slot) => {
                            handle_resume_slot(processes, slot);
                        }
                        WebCommand::RemoveSlot(slot) => {
                            self.handle_remove_slot(slot, processes, dashboard)?;
                        }
                    }
                }
                if afl_delta != 0 {
                    self.handle_scale_afl(afl_delta, processes, dashboard)?;
                }
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
                dashboard.set_syncing(true);
                if let Some(wh) = web_html {
                    let (stats, corpus, _) = dashboard.collect_stats(processes);
                    dashboard.record_tick(corpus, processes);
                    let mut map = HashMap::new();
                    let tabs: &[&str] = if dashboard.has_external_corpus() {
                        &["exec", "corpus", "cpu", "mem", "ext-corpus"]
                    } else {
                        &["exec", "corpus", "cpu", "mem"]
                    };
                    for tab in tabs {
                        map.insert(
                            tab.to_string(),
                            dashboard.render_html(&stats, corpus, processes, tab),
                        );
                    }
                    *wh.lock().unwrap() = map;
                }
                let sync_result = self.sync_corpus_afl_first(last_synced_created_time);
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
                dashboard.set_syncing(false);
            }

            // ── collect stats + update web + liveness check ─────────────
            let (stats, corpus, all_dead) = dashboard.collect_stats(processes);
            dashboard.record_tick(corpus, processes);

            if let Some(wh) = web_html {
                let mut map = HashMap::new();
                let tabs: &[&str] = if dashboard.has_external_corpus() {
                    &["exec", "corpus", "cpu", "mem", "ext-corpus"]
                } else {
                    &["exec", "corpus", "cpu", "mem"]
                };
                for tab in tabs {
                    map.insert(
                        tab.to_string(),
                        dashboard.render_html(&stats, corpus, processes, tab),
                    );
                }
                *wh.lock().unwrap() = map;
            }

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

    /// Sync: push seeds from libfuzzer/honggfuzz into AFL++ main queue.
    /// Uses an in-memory hash set for O(1) dedup that scales to 200k+ files.
    fn sync_corpus_afl_first(
        &mut self,
        last_synced: Option<SystemTime>,
    ) -> Result<Option<SystemTime>> {
        let afl_queue = format!("{}/afl/mainaflfuzzer/queue", self.output_target());
        if !Path::new(&afl_queue).exists() {
            return Ok(last_synced);
        }

        // First call: build the hash set from existing AFL queue contents.
        if self.sync_hashes.is_empty() {
            if let Ok(entries) = fs::read_dir(&afl_queue) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Ok(bytes) = fs::read(&path) {
                            let hash = XxHash64::oneshot(0, &bytes);
                            self.sync_hashes.insert(hash);
                        }
                    }
                }
            }
        }

        // Collect new files from satellites only (no AFL, no cross-satellite sync).
        let mut source_files: Vec<PathBuf> = vec![];
        if self.honggfuzz_enabled() {
            source_files
                .extend(glob(&format!("{}/honggfuzz/corpus/*", self.output_target()))?.flatten());
        }
        if self.libfuzzer_enabled() {
            source_files
                .extend(glob(&format!("{}/libfuzzer/corpus/*", self.output_target()))?.flatten());
        }

        let external_files = self.collect_external_corpus_files(last_synced);

        let mut newest_time = last_synced;
        let max_len = self.max_input_size() as u64;

        // Time-filter source files.
        let mut is_new_file = |file: &PathBuf| -> bool {
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
        };

        let valid_files: Vec<_> = source_files.iter().filter(|f| is_new_file(f)).collect();
        for f in &external_files {
            is_new_file(f);
        }

        let all_files: Vec<&PathBuf> = valid_files
            .into_iter()
            .chain(external_files.iter())
            .collect();

        for file in all_files {
            if !file.is_file() {
                continue;
            }
            let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
            if file_len > max_len || file_len == 0 {
                continue;
            }

            let bytes = match fs::read(file) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let hash = XxHash64::oneshot(0, &bytes);

            if self.sync_hashes.contains(&hash) {
                continue;
            }

            // Atomic write: temp file then rename.
            let tmp_path = format!("{afl_queue}/.sync_tmp_{hash:x}");
            let dest_path = format!("{afl_queue}/sync_ext_{hash:x}");
            if Path::new(&dest_path).exists() {
                self.sync_hashes.insert(hash);
                continue;
            }
            if fs::write(&tmp_path, &bytes).is_ok() {
                let _ = fs::rename(&tmp_path, &dest_path);
            }
            self.sync_hashes.insert(hash);
        }

        Ok(newest_time)
    }

    /// Collect files from `--external-corpus` directories.
    ///
    /// Only files modified after `since` are returned, so we avoid re-scanning
    /// and re-hashing the entire external directory on every sync cycle.
    /// On the first sync (`since` is `None`), all files are returned.
    fn collect_external_corpus_files(&self, since: Option<SystemTime>) -> Vec<PathBuf> {
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
            .filter(|p| {
                since.is_none_or(|t| {
                    p.metadata()
                        .and_then(|m| m.modified())
                        .is_ok_and(|mt| mt > t)
                })
            })
            .collect()
    }

    // ── spawning ────────────────────────────────────────────────────────

    fn spawn_fuzzers_afl_first(&mut self) -> Result<(Vec<Option<ProcessSlot>>, Vec<EngineInfo>)> {
        let (a, h, l) = self.allocate_jobs_afl_first();
        self.spawn_fuzzers_with_allocation(a, h, l)
    }

    fn spawn_fuzzers_with_allocation(
        &mut self,
        afl_jobs: u32,
        honggfuzz_jobs: u32,
        libfuzzer_jobs: u32,
    ) -> Result<(Vec<Option<ProcessSlot>>, Vec<EngineInfo>)> {
        if afl_jobs == 0 && honggfuzz_jobs == 0 && libfuzzer_jobs == 0 {
            return Err(anyhow!("Pick at least one fuzzer"));
        }

        let mut handles: Vec<Option<ProcessSlot>> = vec![];
        let mut engines = vec![];
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        if afl_jobs > 0 {
            fs::create_dir_all(format!("{}/afl", self.output_target()))?;
            let start = handles.len();
            let _afl_cmds = self.spawn_afl(&cargo, afl_jobs, &mut handles)?;
            engines.push(EngineInfo {
                name: format!("AFL++ ({afl_jobs}P)"),
                kind: EngineKind::Afl,
                process_indices: (start..handles.len()).collect(),
                worker_count: afl_jobs,
            });
            eprintln!("    Launched AFL++ ({afl_jobs} instances)");
        }

        if honggfuzz_jobs > 0 {
            let start = handles.len();
            let hfuzz_cmd = self.spawn_honggfuzz(&cargo, honggfuzz_jobs, &mut handles)?;
            engines.push(EngineInfo {
                name: format!("honggfuzz ({honggfuzz_jobs}T)"),
                kind: EngineKind::Honggfuzz,
                process_indices: (start..handles.len()).collect(),
                worker_count: honggfuzz_jobs,
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
                worker_count: libfuzzer_jobs,
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
    /// Job allocation: 1 libfuzzer fork, 1 honggfuzz thread, rest AFL.
    /// With fewer than 3 jobs, satellites are silently disabled.
    fn allocate_jobs_afl_first(&self) -> (u32, u32, u32) {
        let afl = self.afl_enabled();
        let hfuzz = self.honggfuzz_enabled();
        let libf = self.libfuzzer_enabled();

        // Fewer than 3 jobs: give everything to the primary engine.
        if self.jobs() <= 2 {
            if afl {
                return (self.jobs(), 0, 0);
            } else if hfuzz {
                return (0, self.jobs(), 0);
            } else {
                return (0, 0, self.jobs());
            }
        }

        // 3+ jobs: satellites get 1 each, AFL gets the rest.
        let mut reserved = 0u32;
        let h_jobs = if hfuzz {
            reserved += 1;
            1
        } else {
            0
        };
        let lf_jobs = if libf {
            reserved += 1;
            1
        } else {
            0
        };
        let a_jobs = if afl { self.jobs() - reserved } else { 0 };

        (a_jobs, h_jobs, lf_jobs)
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

        let total_secondaries = self.next_afl_job_num.max(job_num + 1) - 1;
        let wc = afl_worker_config(job_num, total_secondaries);

        let afl_input_dir = self.afl_input_dir()?;
        let dict_flags = self.afl_dict_flags();

        let fuzzer_name = format!("-Ssecondaryfuzzer{job_num}");
        let old_queue_flag = if wc.old_queue { "-Z" } else { "" };

        let target_path = format!("./target/afl/debug/{}", self.target());
        let cmplog_flags: Vec<String> = match wc.cmplog_level {
            Some(level) => vec![format!("-c{target_path}"), level.to_string()],
            None => vec![],
        };

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

        let afl_args: Vec<String> = [
            "afl".to_string(),
            "fuzz".to_string(),
            fuzzer_name,
            format!("-i{afl_input_dir}"),
            format!("-p{}", wc.power_schedule),
            format!("-o{}/afl", self.output_target()),
            old_queue_flag.to_string(),
            timeout_flag,
            max_len_flag,
        ]
        .into_iter()
        .filter(|a| !a.is_empty())
        .chain(cmplog_flags.iter().cloned())
        .collect();

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
                    job_num: Some(0),
                    command: Some(cmd_str),
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

                let power_schedule = "explore";
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

                let afl_args: Vec<String> = [
                    "afl".to_string(),
                    "fuzz".to_string(),
                    fuzzer_name.clone(),
                    format!("-i{afl_input_dir}"),
                    format!("-p{power_schedule}"),
                    format!("-o{}/afl", self.output_target()),
                    honggfuzz_sync_flag.clone(),
                    libfuzzer_sync_flag.clone(),
                    timeout_flag.clone(),
                    max_len_flag.clone(),
                ]
                .into_iter()
                .filter(|a| !a.is_empty())
                .collect();

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
                    job_num: Some(0),
                    command: Some(main_cmd_str),
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
                job_num: Some(job_num),
                command: Some(sec_cmd_str),
            }));
        }

        Ok(cmds)
    }

    fn spawn_honggfuzz(
        &self,
        cargo: &str,
        honggfuzz_jobs: u32,
        handles: &mut Vec<Option<ProcessSlot>>,
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
            self.max_input_size(),
        );

        let cmd_str = format!(
            "HFUZZ_BUILD_ARGS='--features=multifuzz/honggfuzz' \
             CARGO_TARGET_DIR=./target/honggfuzz \
             HFUZZ_WORKSPACE={}/honggfuzz \
             HFUZZ_RUN_ARGS='{hfuzz_run_args}' \
             {cargo} hfuzz run {}",
            self.output_target(),
            self.target(),
        );

        let hfuzz_log = File::create(format!("{}/logs/honggfuzz.log", self.output_target()))?;
        let hfuzz_log_clone = hfuzz_log.try_clone()?;
        handles.push(Some(ProcessSlot {
            child: process::Command::new("script")
                .args([
                    "--flush",
                    "--quiet",
                    "-c",
                    &format!("{cargo} hfuzz run {}", self.target()),
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
                .process_group(0)
                .spawn()?,
            paused: false,
            job_num: None,
            command: Some(cmd_str.clone()),
        }));

        Ok(cmd_str)
    }

    fn spawn_libfuzzer(
        &self,
        libfuzzer_jobs: u32,
        handles: &mut Vec<Option<ProcessSlot>>,
    ) -> Result<String> {
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
            format!("-fork={libfuzzer_jobs}"),
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

        let cmd_str = format!("{binary} {}", args.join(" "));

        let lf_log = File::create(format!("{}/logs/libfuzzer.log", self.output_target()))?;
        let lf_log_clone = lf_log.try_clone()?;

        handles.push(Some(ProcessSlot {
            child: process::Command::new(&binary)
                .args(&args)
                .stdout(lf_log)
                .stderr(lf_log_clone)
                .process_group(0)
                .spawn()
                .with_context(|| format!("Failed to spawn libfuzzer binary: {binary}"))?,
            paused: false,
            job_num: None,
            command: Some(cmd_str.clone()),
        }));

        Ok(cmd_str)
    }

    /// Dynamically add or remove AFL++ secondary workers.
    fn handle_scale_afl(
        &mut self,
        delta: i32,
        processes: &mut Vec<Option<ProcessSlot>>,
        dashboard: &mut Dashboard,
    ) -> Result<()> {
        // Find the AFL engine in the dashboard
        let afl_idx = dashboard
            .engines
            .iter()
            .position(|e| matches!(e.kind, EngineKind::Afl));
        let Some(afl_idx) = afl_idx else {
            return Ok(()); // AFL not active
        };

        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        if delta > 0 {
            // Scale up
            for _ in 0..delta {
                let job_num = self.next_afl_job_num;
                let (child, cmd_str) = self.spawn_afl_secondary(&cargo, job_num)?;
                let slot_idx = processes.len();
                processes.push(Some(ProcessSlot {
                    child,
                    paused: false,
                    job_num: Some(job_num),
                    command: Some(cmd_str),
                }));
                dashboard.engines[afl_idx].process_indices.push(slot_idx);
                dashboard.engines[afl_idx].worker_count += 1;
                self.next_afl_job_num += 1;
            }
        } else {
            // Scale down
            let remove_count = (-delta) as usize;
            for _ in 0..remove_count {
                let engine = &mut dashboard.engines[afl_idx];
                // Never kill the main instance (always at index 0 in process_indices)
                if engine.process_indices.len() <= 1 {
                    break;
                }
                let slot_idx = engine.process_indices.pop().unwrap();
                if let Some(ps) = processes[slot_idx].as_ref() {
                    if ps.paused {
                        send_signal_to_process_group(ps.child.id(), libc::SIGCONT);
                    }
                    let _ = kill_process_tree(ps.child.id());
                }
                processes[slot_idx] = None;
                engine.worker_count -= 1;
            }
        }

        // Update the engine display name
        let wc = dashboard.engines[afl_idx].worker_count;
        dashboard.engines[afl_idx].name = format!("AFL++ ({wc}P)");

        Ok(())
    }

    /// Remove a specific process slot (used by the web UI remove button).
    fn handle_remove_slot(
        &mut self,
        slot: usize,
        processes: &mut [Option<ProcessSlot>],
        dashboard: &mut Dashboard,
    ) -> Result<()> {
        for engine in &mut dashboard.engines {
            if let Some(pos) = engine.process_indices.iter().position(|&idx| idx == slot) {
                // For AFL, don't allow removing the main instance (position 0)
                if matches!(engine.kind, EngineKind::Afl) && pos == 0 {
                    return Ok(());
                }
                if let Some(ps) = processes[slot].take() {
                    if ps.paused {
                        send_signal_to_process_group(ps.child.id(), libc::SIGCONT);
                    }
                    let _ = kill_process_tree(ps.child.id());
                }
                engine.process_indices.remove(pos);
                engine.worker_count -= 1;
                if matches!(engine.kind, EngineKind::Afl) {
                    let wc = engine.worker_count;
                    engine.name = format!("AFL++ ({wc}P)");
                }
                break;
            }
        }
        Ok(())
    }

    /// Check for oversized files that would crash honggfuzz and prompt for removal.
    /// Must be called BEFORE the stdin command thread is spawned.
    fn check_honggfuzz_oversized_files(&self) -> Result<()> {
        let max_len = self.max_input_size() as u64;
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

fn handle_pause_slot(processes: &mut [Option<ProcessSlot>], slot: usize) {
    if let Some(ps) = processes.get_mut(slot).and_then(|o| o.as_mut()) {
        if !ps.paused && ps.child.try_wait().unwrap_or(None).is_none() {
            send_signal_to_process_group(ps.child.id(), libc::SIGSTOP);
            ps.paused = true;
        }
    }
}

fn handle_resume_slot(processes: &mut [Option<ProcessSlot>], slot: usize) {
    if let Some(ps) = processes.get_mut(slot).and_then(|o| o.as_mut()) {
        if ps.paused && ps.child.try_wait().unwrap_or(None).is_none() {
            send_signal_to_process_group(ps.child.id(), libc::SIGCONT);
            ps.paused = false;
        }
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

use std::{
    fmt::Write as FmtWrite,
    fs,
    io::{self, Read, Seek, SeekFrom, Write},
    process,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// ── types ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub enum EngineKind {
    Afl,
    Honggfuzz,
    Libfuzzer,
}

pub struct EngineInfo {
    pub name: String,
    pub kind: EngineKind,
    /// Indices into the process handles vec that belong to this engine group.
    pub process_indices: Vec<usize>,
}

struct EngineStats {
    execs_per_sec: f64,
    corpus_count: u64,
    crashes: u64,
    alive: bool,
    /// Engine is loading/importing corpus files.
    loading: bool,
    /// Optional status hint shown instead of "alive" during startup phases.
    status_hint: Option<String>,
}

pub struct Dashboard {
    start_time: Instant,
    target: String,
    output_target: String,
    engines: Vec<EngineInfo>,
    /// Crash counts at startup, subtracted from displayed values.
    baseline_crashes: Vec<u64>,
    syncing: bool,
    last_sync: Option<String>,
    /// Sync interval in minutes, for display.
    sync_interval: u64,
    /// When an engine entered the loading state (for elapsed timer).
    loading_since: Option<Instant>,
}

// ── dashboard ────────────────────────────────────────────────────────────

impl Dashboard {
    pub fn new(
        target: &str,
        output_target: &str,
        engines: Vec<EngineInfo>,
        sync_interval: u64,
    ) -> Self {
        let baseline_crashes = vec![0; engines.len()];
        Self {
            start_time: Instant::now(),
            target: target.to_string(),
            output_target: output_target.to_string(),
            engines,
            baseline_crashes,
            syncing: false,
            last_sync: None,
            sync_interval,
            loading_since: None,
        }
    }

    /// Snapshot current crash counts as the baseline so the dashboard only
    /// shows crashes from this session.
    pub fn set_syncing(&mut self, syncing: bool) {
        if !syncing && self.syncing {
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let h = (secs % 86400) / 3600;
            let m = (secs % 3600) / 60;
            let s = secs % 60;
            self.last_sync = Some(format!("{h:02}:{m:02}:{s:02}"));
        }
        self.syncing = syncing;
    }

    pub fn record_baseline(&mut self) {
        for (i, engine) in self.engines.iter().enumerate() {
            let es = match engine.kind {
                EngineKind::Afl => self.read_afl_stats(engine),
                EngineKind::Honggfuzz => self.read_honggfuzz_stats(),
                EngineKind::Libfuzzer => self.read_libfuzzer_stats(),
            };
            self.baseline_crashes[i] = es.crashes;
        }
    }

    /// Read stats, redraw the dashboard. Returns `true` when every process has
    /// exited (i.e. the caller should stop the loop).
    pub fn refresh(&mut self, processes: &mut [process::Child]) -> bool {
        let mut all_dead = true;
        let mut stats: Vec<EngineStats> = Vec::with_capacity(self.engines.len());
        let mut any_loading = false;

        for (i, engine) in self.engines.iter().enumerate() {
            let alive = engine
                .process_indices
                .iter()
                .any(|&i| processes[i].try_wait().unwrap_or(None).is_none());
            if alive {
                all_dead = false;
            }

            let mut es = match engine.kind {
                EngineKind::Afl => self.read_afl_stats(engine),
                EngineKind::Honggfuzz => self.read_honggfuzz_stats(),
                EngineKind::Libfuzzer => self.read_libfuzzer_stats(),
            };
            es.alive = alive;
            es.crashes = es.crashes.saturating_sub(self.baseline_crashes[i]);
            if es.loading {
                any_loading = true;
            }
            stats.push(es);
        }

        // Track when loading started for the elapsed timer.
        if any_loading && self.loading_since.is_none() {
            self.loading_since = Some(Instant::now());
        } else if !any_loading {
            self.loading_since = None;
        }

        let engines_with_corpus = stats.iter().filter(|s| s.corpus_count > 0).count() as u64;
        let corpus_count = if engines_with_corpus > 0 {
            stats.iter().map(|s| s.corpus_count).sum::<u64>() / engines_with_corpus
        } else {
            0
        };
        self.draw(&stats, corpus_count);

        all_dead
    }

    // ── stat readers ─────────────────────────────────────────────────────

    /// Parse AFL++ `fuzzer_stats` key-value files.
    fn read_afl_stats(&self, engine: &EngineInfo) -> EngineStats {
        let mut total = EngineStats {
            execs_per_sec: 0.0,
            corpus_count: 0,
            crashes: 0,
            alive: false,
            loading: false,
            status_hint: None,
        };

        // The engine name encodes the instance dir; for the aggregate view we
        // glob all instances under the afl output dir.
        let pattern = format!("{}/afl/*/fuzzer_stats", self.output_target);
        let mut found_stats = false;
        for path in glob::glob(&pattern).into_iter().flatten().flatten() {
            if let Ok(contents) = fs::read_to_string(&path) {
                found_stats = true;
                for line in contents.lines() {
                    if let Some((key, val)) = line.split_once(':') {
                        let key = key.trim();
                        let val = val.trim();
                        match key {
                            "execs_per_sec" => {
                                total.execs_per_sec += val.parse::<f64>().unwrap_or(0.0);
                            }
                            "corpus_count" => {
                                total.corpus_count += val.parse::<u64>().unwrap_or(0);
                            }
                            "saved_crashes" => {
                                total.crashes += val.parse::<u64>().unwrap_or(0);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // No fuzzer_stats yet → AFL++ is still doing dry runs / importing seeds.
        if !found_stats {
            let log_path = format!("{}/logs/afl.log", self.output_target);
            let tail = tail_file(&log_path, 4096);
            if tail.contains("Attempting dry run") {
                // Count how many dry runs we've seen
                let done = tail.matches("Attempting dry run").count();
                total.status_hint = Some(format!("importing seeds ({done})"));
                total.loading = true;
            } else if !tail.is_empty() {
                total.status_hint = Some("starting".to_string());
                total.loading = true;
            }
        }

        let _ = engine;
        total
    }

    /// Parse honggfuzz TUI log. Labels like "Speed : " are clean ASCII; values
    /// are wrapped in ANSI bold/reset sequences which we strip before parsing.
    fn read_honggfuzz_stats(&self) -> EngineStats {
        let mut stats = EngineStats {
            execs_per_sec: 0.0,
            corpus_count: 0,
            crashes: 0,
            alive: false,
            loading: false,
            status_hint: None,
        };

        let log_path = format!("{}/logs/honggfuzz.log", self.output_target);
        let tail = tail_file(&log_path, 8192);

        // Search for the last occurrence of each label in the raw output.
        if let Some(v) = rfind_after(&tail, "Speed : ") {
            // "\x1b[1m64/sec\x1b[0m ..." → "64"
            let clean = strip_ansi_inline(v);
            if let Some(num) = clean.split('/').next() {
                stats.execs_per_sec = parse_num(num);
            }
        }
        if let Some(v) = rfind_after(&tail, "Crashes : ") {
            let clean = strip_ansi_inline(v);
            if let Some(num) = clean.split_whitespace().next() {
                stats.crashes = parse_num(num) as u64;
            }
        }
        if let Some(v) = rfind_after(&tail, "Corpus Size : ") {
            // "2,666, max: ..." — grab everything up to first non-digit/non-comma
            let clean = strip_ansi_inline(v);
            let num: String = clean
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == ',')
                .collect();
            stats.corpus_count = parse_num(&num) as u64;
        }

        // Detect startup phases when we have no real stats yet.
        if stats.execs_per_sec == 0.0 {
            if tail.contains("Loading dynamic input file") {
                stats.loading = true;
            } else if tail.contains("Compiling") && !tail.contains("Speed : ") {
                stats.status_hint = Some("compiling".to_string());
                stats.loading = true;
            } else if !tail.contains("Speed : ") && !tail.is_empty() {
                stats.status_hint = Some("starting".to_string());
                stats.loading = true;
            }
        }

        stats
    }

    /// Parse libfuzzer log output for stats.
    fn read_libfuzzer_stats(&self) -> EngineStats {
        let mut stats = EngineStats {
            execs_per_sec: 0.0,
            corpus_count: 0,
            crashes: 0,
            alive: false,
            loading: false,
            status_hint: None,
        };

        let log_path = format!("{}/logs/libfuzzer.log", self.output_target);
        let tail = tail_file(&log_path, 8192);

        // Lines look like: #12345\tNEW    cov: 123 ft: 456 corp: 789/1234b exec/s: 5678
        for line in tail.lines().rev() {
            if stats.execs_per_sec == 0.0 {
                if let Some(v) = extract_after(line, "exec/s: ") {
                    if let Some(num) = v.split_whitespace().next() {
                        stats.execs_per_sec = parse_num(num);
                    }
                }
            }
            if stats.corpus_count == 0 {
                if let Some(v) = extract_after(line, "corp: ") {
                    // Fork mode: "19725 exec/s: ..."
                    // Normal mode: "789/1234b exec/s: ..."
                    if let Some(num) = v.split(|c: char| !c.is_ascii_digit()).next() {
                        stats.corpus_count = parse_num(num) as u64;
                    }
                }
            }
        }

        // Count crash files for libfuzzer.
        stats.crashes = count_files(&format!("{}/libfuzzer/crashes", self.output_target));

        stats
    }

    // ── drawing ──────────────────────────────────────────────────────────

    fn draw(&self, stats: &[EngineStats], corpus_count: u64) {
        let elapsed = self.start_time.elapsed();
        let total_crashes: u64 = stats.iter().map(|s| s.crashes).sum();

        let mut buf = String::with_capacity(1024);

        // Clear screen + move cursor home.
        let _ = write!(buf, "\x1b[2J\x1b[H");

        let header = format!("── multifuzz ── {} ", self.target);
        let _ = writeln!(
            buf,
            "\x1b[1m{header}{}\x1b[0m",
            "─".repeat(60usize.saturating_sub(header.len()))
        );
        let _ = writeln!(buf, " Runtime : {}", fmt_duration(elapsed));
        let last_sync_str = self.last_sync.as_deref().unwrap_or("—");
        let _ = writeln!(
            buf,
            " Last sync: {last_sync_str} (every {} min)",
            self.sync_interval
        );
        let _ = writeln!(buf, " Corpus  : {} files (shared)", corpus_count);
        let _ = writeln!(buf, " Crashes : {total_crashes}");
        if self.syncing {
            let _ = writeln!(buf, " \x1b[1;33m⟳ syncing corpus...\x1b[0m");
        }
        let _ = writeln!(buf);

        // Table header.
        let _ = writeln!(
            buf,
            " {:<20} {:>8} {:>10} {:>8} {:>8}",
            "Engine", "Status", "Exec/s", "Corpus", "Crashes"
        );
        let _ = writeln!(buf, " {}", "─".repeat(58));

        let spinner_frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        let spinner_idx = elapsed.as_secs() as usize % spinner_frames.len();
        let spinner = spinner_frames[spinner_idx];

        for (engine, es) in self.engines.iter().zip(stats.iter()) {
            if es.loading && es.alive {
                let loading_elapsed = self.loading_since.map(|t| t.elapsed()).unwrap_or_default();
                let ls = loading_elapsed.as_secs();
                let hint = es.status_hint.as_deref().unwrap_or("syncing corpus");
                let _ = writeln!(
                    buf,
                    " {:<20} \x1b[1;33m{spinner} {hint} ({:02}:{:02})\x1b[0m",
                    engine.name,
                    ls / 60,
                    ls % 60,
                );
                continue;
            }
            let status = if !es.alive {
                "\x1b[31mdead\x1b[0m "
            } else if let Some(ref hint) = es.status_hint {
                // Alive but with a status hint (e.g. "starting")
                let _ = writeln!(buf, " {:<20} \x1b[33m{hint}\x1b[0m", engine.name,);
                continue;
            } else {
                "\x1b[32malive\x1b[0m"
            };
            // exec/s: show "-" when dead or no data yet
            let exec_s = if !es.alive || es.execs_per_sec <= 0.0 {
                "-".to_string()
            } else {
                format!("{:.0}", es.execs_per_sec)
            };
            let _ = writeln!(
                buf,
                " {:<20} {:>13} {:>10} {:>8} {:>8}",
                engine.name, status, exec_s, es.corpus_count, es.crashes
            );
        }

        let _ = writeln!(buf, " {}", "─".repeat(58));

        let stderr = io::stderr();
        let mut handle = stderr.lock();
        let _ = handle.write_all(buf.as_bytes());
        let _ = handle.flush();
    }
}

// ── helpers ──────────────────────────────────────────────────────────────

/// Read the last `n` bytes of a file as a string.
fn tail_file(path: &str, n: u64) -> String {
    let Ok(mut file) = fs::File::open(path) else {
        return String::new();
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if len > n {
        let _ = file.seek(SeekFrom::End(-(n as i64)));
    }
    let mut buf = String::new();
    let _ = file.read_to_string(&mut buf);
    buf
}

/// Find the substring after the *last* occurrence of `prefix` in `haystack`.
/// Works on raw TUI output where lines may be overwritten by cursor movements.
fn rfind_after<'a>(haystack: &'a str, prefix: &str) -> Option<&'a str> {
    let idx = haystack.rfind(prefix)?;
    Some(&haystack[idx + prefix.len()..])
}

/// Strip ANSI escape sequences from a short value string (e.g. "\x1b[1m64/sec\x1b[0m").
fn strip_ansi_inline(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Find the substring after `prefix` in `line`, if present.
fn extract_after<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let idx = line.find(prefix)?;
    Some(&line[idx + prefix.len()..])
}

/// Parse a number string that may contain commas (e.g. "96,542").
fn parse_num(s: &str) -> f64 {
    let clean: String = s.chars().filter(|c| *c != ',').collect();
    clean.parse().unwrap_or(0.0)
}

/// Count files in a directory (non-recursive).
fn count_files(dir: &str) -> u64 {
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_file())
                .count() as u64
        })
        .unwrap_or(0)
}

fn fmt_duration(d: Duration) -> String {
    let total_secs = d.as_secs();
    let days = total_secs / 86400;
    let hrs = (total_secs % 86400) / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    format!("{days} days {hrs:02} hrs {mins:02} mins {secs:02} secs")
}

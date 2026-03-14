use crate::Strategy;
use std::{
    collections::{HashMap, VecDeque},
    fmt::Write as FmtWrite,
    fs,
    io::{Read, Seek, SeekFrom},
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

pub struct ProcessSlot {
    pub child: process::Child,
    pub paused: bool,
    /// AFL job_num (for display label), None for honggfuzz/libfuzzer.
    pub job_num: Option<u32>,
    /// Command string used to spawn this process (shown as tooltip).
    pub command: Option<String>,
}

pub struct EngineInfo {
    pub name: String,
    pub kind: EngineKind,
    /// Indices into the process handles vec that belong to this engine group.
    pub process_indices: Vec<usize>,
    /// Number of workers: AFL processes, honggfuzz threads, libfuzzer forks.
    pub worker_count: u32,
}

pub struct EngineStatsSnapshot {
    pub name: String,
    pub alive: bool,
    pub loading: bool,
    pub status_hint: Option<String>,
    pub execs_per_sec: f64,
    pub corpus_count: u64,
    pub crashes: u64,
    pub execs_done: u64,
    pub last_crash: u64,
}

struct EngineStats {
    execs_per_sec: f64,
    corpus_count: u64,
    crashes: u64,
    execs_done: u64,
    /// Unix timestamp (seconds) of last saved crash, 0 = none.
    last_crash: u64,
    alive: bool,
    /// Engine is loading/importing corpus files.
    loading: bool,
    /// Optional status hint shown instead of "alive" during startup phases.
    status_hint: Option<String>,
}

const GRAPH_MAX_SAMPLES: usize = 1800; // 30 min at 1 sample/sec

struct TimeSeriesSample {
    elapsed_secs: f64,
    per_engine: Vec<f64>,
}

struct SyncPeriod {
    start_secs: f64,
    end_secs: Option<f64>,
}

pub struct Dashboard {
    start_time: Instant,
    target: String,
    output_target: String,
    pub engines: Vec<EngineInfo>,
    /// Crash counts at startup, subtracted from displayed values.
    baseline_crashes: Vec<u64>,
    syncing: bool,
    last_sync: Option<String>,
    /// Sync interval in minutes, for display.
    sync_interval: u64,
    /// Show strategy switching controls in web UI.
    show_switch_hints: bool,
    /// Current strategy, for selecting the default in the dropdown.
    current_strategy: Option<Strategy>,
    /// Path to the shared corpus directory.
    corpus_dir: String,
    /// External corpus directories (display only).
    external_corpus: Vec<String>,
    /// Path to the crashes directory.
    crash_dir: String,

    // Time-series ring buffers
    exec_history: VecDeque<TimeSeriesSample>,
    corpus_history: VecDeque<TimeSeriesSample>,
    cpu_history: VecDeque<TimeSeriesSample>,
    mem_history: VecDeque<TimeSeriesSample>,
    /// External corpus file counts over time (one series per directory).
    ext_corpus_history: VecDeque<TimeSeriesSample>,

    /// CPU jiffies at previous tick, keyed by PID.
    prev_cpu_jiffies: HashMap<u32, u64>,
    /// Elapsed seconds at previous tick (for accurate CPU% delta).
    prev_tick_secs: f64,

    /// Labels for graph lines (rebuilt each tick to track AFL workers individually).
    graph_labels: Vec<String>,
    /// Colors matching graph_labels.
    graph_colors: Vec<String>,

    /// Per-AFL-worker baseline crash counts (keyed by job_num).
    baseline_worker_crashes: HashMap<u32, u64>,

    clock_ticks_per_sec: f64,
    page_size: usize,

    /// Sync period annotations rendered as shaded bands on graphs.
    sync_periods: Vec<SyncPeriod>,

    /// Unix epoch when this session started, used to detect stale fuzzer_stats.
    session_start_epoch: u64,
}

// ── dashboard ────────────────────────────────────────────────────────────

impl Dashboard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target: &str,
        output_target: &str,
        engines: Vec<EngineInfo>,
        sync_interval: u64,
        show_switch_hints: bool,
        current_strategy: Option<Strategy>,
        corpus_dir: &str,
        external_corpus: Vec<String>,
        crash_dir: &str,
    ) -> Self {
        let baseline_crashes = vec![0; engines.len()];
        let clock_ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) as f64 };
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        Self {
            start_time: Instant::now(),
            target: target.to_string(),
            output_target: output_target.to_string(),
            engines,
            baseline_crashes,
            syncing: false,
            last_sync: None,
            sync_interval,
            show_switch_hints,
            current_strategy,
            corpus_dir: corpus_dir.to_string(),
            external_corpus,
            crash_dir: crash_dir.to_string(),
            exec_history: VecDeque::with_capacity(GRAPH_MAX_SAMPLES),
            corpus_history: VecDeque::with_capacity(GRAPH_MAX_SAMPLES),
            cpu_history: VecDeque::with_capacity(GRAPH_MAX_SAMPLES),
            mem_history: VecDeque::with_capacity(GRAPH_MAX_SAMPLES),
            ext_corpus_history: VecDeque::with_capacity(GRAPH_MAX_SAMPLES),
            prev_cpu_jiffies: HashMap::new(),
            prev_tick_secs: 0.0,
            graph_labels: Vec::new(),
            graph_colors: Vec::new(),
            baseline_worker_crashes: HashMap::new(),
            clock_ticks_per_sec,
            page_size,
            sync_periods: Vec::new(),
            session_start_epoch: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Snapshot current crash counts as the baseline so the dashboard only
    /// shows crashes from this session.
    pub fn has_external_corpus(&self) -> bool {
        !self.external_corpus.is_empty()
    }

    pub fn set_syncing(&mut self, syncing: bool) {
        if syncing && !self.syncing {
            let elapsed = self.start_time.elapsed().as_secs_f64();
            self.sync_periods.push(SyncPeriod {
                start_secs: elapsed,
                end_secs: None,
            });
        }
        if !syncing && self.syncing {
            if let Some(last) = self.sync_periods.last_mut() {
                last.end_secs = Some(self.start_time.elapsed().as_secs_f64());
            }
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
                EngineKind::Afl => {
                    let (total, per_worker) = self.read_afl_all_stats();
                    for (jn, ws) in &per_worker {
                        self.baseline_worker_crashes.insert(*jn, ws.crashes);
                    }
                    total
                }
                EngineKind::Honggfuzz => self.read_honggfuzz_stats(),
                EngineKind::Libfuzzer => self.read_libfuzzer_stats(),
            };
            self.baseline_crashes[i] = es.crashes;
        }
    }

    /// Record one tick of time-series data for graphs.
    /// AFL++ workers are expanded into individual graph lines.
    pub fn record_tick(&mut self, _corpus_count: u64, processes: &[Option<ProcessSlot>]) {
        let elapsed_secs = self.start_time.elapsed().as_secs_f64();
        let dt = elapsed_secs - self.prev_tick_secs;
        let first_tick = self.prev_tick_secs == 0.0;
        self.prev_tick_secs = elapsed_secs;

        // Build per-graph-line values: expand AFL workers individually.
        let mut exec_values = Vec::new();
        let mut corpus_values = Vec::new();
        let mut cpu_values = Vec::new();
        let mut mem_values = Vec::new();
        let mut labels = Vec::new();
        let mut colors = Vec::new();

        // AFL per-worker exec/s from fuzzer_stats
        let afl_worker_stats: HashMap<u32, EngineStats> = {
            let has_afl = self
                .engines
                .iter()
                .any(|e| matches!(e.kind, EngineKind::Afl));
            if has_afl {
                self.read_afl_all_stats().1
            } else {
                HashMap::new()
            }
        };

        // AFL worker color palette — distinct hues so lines are easy to tell apart
        const AFL_COLORS: &[&str] = &[
            "#ff4444", "#4dabf7", "#ff922b", "#51cf66", "#cc5de8", "#20c997", "#f06595", "#94d82d",
            "#fcc419", "#339af0",
        ];

        for engine in &self.engines {
            match engine.kind {
                EngineKind::Afl => {
                    // One graph line per AFL worker process
                    for (wi, &idx) in engine.process_indices.iter().enumerate() {
                        let ps = processes.get(idx).and_then(|o| o.as_ref());
                        let job_num = ps.and_then(|p| p.job_num);
                        let label = if let Some(jn) = job_num {
                            if jn == 0 {
                                "AFL++ main".to_string()
                            } else {
                                format!("AFL++ #{jn}")
                            }
                        } else {
                            format!("AFL++ w{wi}")
                        };

                        // Exec/s and corpus from fuzzer_stats
                        let ws = job_num.and_then(|jn| afl_worker_stats.get(&jn));
                        exec_values.push(ws.map(|w| w.execs_per_sec).unwrap_or(0.0));
                        corpus_values.push(ws.map(|w| w.corpus_count as f64).unwrap_or(0.0));

                        // CPU & memory from /proc
                        if let Some(ps) = ps {
                            let pid = ps.child.id();
                            let jiffies = read_proc_cpu_jiffies(pid);
                            let rss = read_proc_rss_bytes(pid, self.page_size);

                            let cpu_pct = if first_tick || dt <= 0.0 {
                                0.0
                            } else {
                                let prev =
                                    self.prev_cpu_jiffies.get(&pid).copied().unwrap_or(jiffies);
                                let delta = jiffies.saturating_sub(prev);
                                delta as f64 / self.clock_ticks_per_sec / dt * 100.0
                            };
                            self.prev_cpu_jiffies.insert(pid, jiffies);
                            cpu_values.push(cpu_pct);
                            mem_values.push(rss as f64 / (1024.0 * 1024.0));
                        } else {
                            cpu_values.push(0.0);
                            mem_values.push(0.0);
                        }

                        labels.push(label);
                        colors.push(AFL_COLORS[wi % AFL_COLORS.len()].to_string());
                    }
                }
                _ => {
                    // Non-AFL: one graph line per engine, aggregate all processes
                    let mut total_jiffies: u64 = 0;
                    let mut total_rss: u64 = 0;
                    // Use a synthetic PID key for the engine aggregate (won't collide with real PIDs)
                    let synth_key = u32::MAX - labels.len() as u32;
                    for &idx in &engine.process_indices {
                        if let Some(ps) = processes.get(idx).and_then(|o| o.as_ref()) {
                            let pid = ps.child.id();
                            total_jiffies += read_proc_cpu_jiffies(pid);
                            total_rss += read_proc_rss_bytes(pid, self.page_size);
                        }
                    }
                    let cpu_pct = if first_tick || dt <= 0.0 {
                        0.0
                    } else {
                        let prev = self
                            .prev_cpu_jiffies
                            .get(&synth_key)
                            .copied()
                            .unwrap_or(total_jiffies);
                        let delta = total_jiffies.saturating_sub(prev);
                        delta as f64 / self.clock_ticks_per_sec / dt * 100.0
                    };
                    self.prev_cpu_jiffies.insert(synth_key, total_jiffies);

                    let engine_stats = match engine.kind {
                        EngineKind::Honggfuzz => self.read_honggfuzz_stats(),
                        EngineKind::Libfuzzer => self.read_libfuzzer_stats(),
                        _ => EngineStats {
                            execs_per_sec: 0.0,
                            corpus_count: 0,
                            crashes: 0,
                            execs_done: 0,
                            last_crash: 0,
                            alive: false,
                            loading: false,
                            status_hint: None,
                        },
                    };
                    exec_values.push(engine_stats.execs_per_sec);
                    corpus_values.push(engine_stats.corpus_count as f64);
                    cpu_values.push(cpu_pct);
                    mem_values.push(total_rss as f64 / (1024.0 * 1024.0));

                    labels.push(engine.name.clone());
                    colors.push(match engine.kind {
                        EngineKind::Honggfuzz => "#ffd93d".to_string(),
                        EngineKind::Libfuzzer => "#6bcb77".to_string(),
                        _ => "#ffffff".to_string(),
                    });
                }
            }
        }

        self.graph_labels = labels;
        self.graph_colors = colors;

        self.exec_history.push_back(TimeSeriesSample {
            elapsed_secs,
            per_engine: exec_values,
        });
        self.corpus_history.push_back(TimeSeriesSample {
            elapsed_secs,
            per_engine: corpus_values,
        });
        self.cpu_history.push_back(TimeSeriesSample {
            elapsed_secs,
            per_engine: cpu_values,
        });
        self.mem_history.push_back(TimeSeriesSample {
            elapsed_secs,
            per_engine: mem_values,
        });

        // External corpus file counts
        if !self.external_corpus.is_empty() {
            let ext_values: Vec<f64> = self
                .external_corpus
                .iter()
                .map(|dir| count_files(dir) as f64)
                .collect();
            self.ext_corpus_history.push_back(TimeSeriesSample {
                elapsed_secs,
                per_engine: ext_values,
            });
        }

        // Evict old samples
        for buf in [
            &mut self.exec_history,
            &mut self.corpus_history,
            &mut self.cpu_history,
            &mut self.mem_history,
            &mut self.ext_corpus_history,
        ] {
            while buf.len() > GRAPH_MAX_SAMPLES {
                buf.pop_front();
            }
        }
    }

    /// Collect stats from all engines. Returns (per-engine snapshots, corpus count, all_dead).
    pub fn collect_stats(
        &self,
        processes: &mut [Option<ProcessSlot>],
    ) -> (Vec<EngineStatsSnapshot>, u64, bool) {
        let mut all_dead = true;
        let mut snapshots = Vec::with_capacity(self.engines.len());

        for (i, engine) in self.engines.iter().enumerate() {
            let alive = engine.process_indices.iter().any(|&idx| {
                processes
                    .get_mut(idx)
                    .and_then(|o| o.as_mut())
                    .is_some_and(|ps| ps.child.try_wait().unwrap_or(None).is_none())
            });
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

            snapshots.push(EngineStatsSnapshot {
                name: engine.name.clone(),
                alive: es.alive,
                loading: es.loading,
                status_hint: es.status_hint,
                execs_per_sec: es.execs_per_sec,
                corpus_count: es.corpus_count,
                crashes: es.crashes,
                execs_done: es.execs_done,
                last_crash: es.last_crash,
            });
        }

        let engines_with_corpus = snapshots.iter().filter(|s| s.corpus_count > 0).count() as u64;
        let corpus_count = if engines_with_corpus > 0 {
            snapshots.iter().map(|s| s.corpus_count).sum::<u64>() / engines_with_corpus
        } else {
            0
        };

        (snapshots, corpus_count, all_dead)
    }

    /// Render an auto-refreshing HTML dashboard page from collected stats.
    pub fn render_html(
        &self,
        stats: &[EngineStatsSnapshot],
        corpus_count: u64,
        processes: &[Option<ProcessSlot>],
        active_tab: &str,
    ) -> String {
        let elapsed = self.start_time.elapsed();
        let total_crashes: u64 = stats.iter().map(|s| s.crashes).sum();

        // HTML-escape target name
        let target_escaped = self
            .target
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;");

        // Collect per-worker AFL stats for sub-row display
        let afl_worker_stats: HashMap<u32, EngineStats> = {
            let has_afl = self
                .engines
                .iter()
                .any(|e| matches!(e.kind, EngineKind::Afl));
            if has_afl {
                self.read_afl_all_stats().1
            } else {
                HashMap::new()
            }
        };

        let mut buf = String::with_capacity(2048);
        let _ = write!(
            buf,
            r#"<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>multifuzz — {target_escaped}</title>
<style>
body {{ font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
h1 {{ color: #00d4ff; }}
table {{ border-collapse: collapse; margin: 10px 0; }}
th, td {{ padding: 4px 12px; text-align: right; border-bottom: 1px solid #333; }}
th {{ color: #888; text-align: right; }}
td:first-child, th:first-child {{ text-align: left; }}
.alive {{ color: #4caf50; }}
.dead {{ color: #f44336; }}
.loading {{ color: #ff9800; }}
a {{ color: #00d4ff; text-decoration: none; margin-right: 12px; }}
a:hover {{ text-decoration: underline; }}
.actions {{ margin-top: 16px; }}
.syncing {{ color: #ff9800; font-weight: bold; }}
select, button {{ font-family: monospace; background: #16213e; color: #e0e0e0; border: 1px solid #555; padding: 4px 8px; cursor: pointer; }}
button:hover {{ background: #1a3a5c; }}
svg text {{ font-family: monospace; font-size: 11px; fill: #888; }}
.worker-row td:first-child {{ padding-left: 28px; font-size: 0.9em; color: #aaa; }}
.paused {{ color: #ff9800; }}
.action-btn {{ font-family: monospace; background: #16213e; color: #e0e0e0; border: 1px solid #555; padding: 2px 8px; cursor: pointer; font-size: 0.85em; text-decoration: none; margin-right: 4px; }}
.action-btn:hover {{ background: #1a3a5c; }}
.action-btn.danger {{ border-color: #f44336; }}
.action-btn.danger:hover {{ background: #5c1a1a; }}
td[title] {{ cursor: pointer; border-bottom: 1px dotted #555; }}
.path-copy {{ cursor: pointer; border-bottom: 1px dotted #888; }}
.path-copy:hover {{ color: #00d4ff; }}
.tab-bar {{ margin: 10px 0; }}
.tab {{ padding: 4px 12px; color: #888; text-decoration: none; margin-right: 4px; border-bottom: 2px solid transparent; }}
.tab:hover {{ color: #e0e0e0; }}
.tab.active {{ background: #16213e; color: #00d4ff; border-bottom: 2px solid #00d4ff; }}
</style>
</head><body>
"#
        );

        let header = format!("multifuzz &mdash; {target_escaped}");
        let _ = writeln!(buf, "<h1>{header}</h1>");
        let _ = writeln!(
            buf,
            "<p id=\"runtime\">Runtime: {}</p>",
            fmt_duration(elapsed)
        );

        let last_sync_str = self.last_sync.as_deref().unwrap_or("&mdash;");
        let _ = writeln!(
            buf,
            "<p id=\"last-sync\">Last sync: {last_sync_str} (every {} min)</p>",
            self.sync_interval
        );
        let corpus_dir = &self.corpus_dir;
        let _ = writeln!(
            buf,
            "<p id=\"corpus-count\"><span class=\"path-copy\" title=\"{corpus_dir}\" \
             onclick=\"navigator.clipboard.writeText('{corpus_dir}')\">Corpus:</span> {corpus_count} files (shared)</p>"
        );
        let _ = write!(buf, "<div id=\"external-corpus\">");
        for ext_dir in &self.external_corpus {
            let ext_count = count_files(ext_dir);
            let _ = writeln!(
                buf,
                "<p><span class=\"path-copy\" title=\"{ext_dir}\" \
                 onclick=\"navigator.clipboard.writeText('{ext_dir}')\">External:</span> {ext_dir} ({ext_count} files)</p>"
            );
        }
        let _ = write!(buf, "</div>");
        let crash_dir = &self.crash_dir;
        let _ = writeln!(
            buf,
            "<p id=\"crash-count\"><span class=\"path-copy\" title=\"{crash_dir}\" \
             onclick=\"navigator.clipboard.writeText('{crash_dir}')\">Crashes:</span> {total_crashes}</p>"
        );
        if self.syncing {
            let _ = writeln!(
                buf,
                "<p id=\"syncing\" class=\"syncing\">syncing corpus...</p>"
            );
        } else {
            let _ = writeln!(buf, "<p id=\"syncing\"></p>");
        }

        let _ = writeln!(
            buf,
            "<table id=\"stats-table\"><tr><th>Engine</th><th>Status</th><th>Exec/s</th><th>Execs</th><th>Corpus</th><th>Crashes</th><th>Last Crash</th><th>Actions</th></tr>"
        );
        for (ei, es) in stats.iter().enumerate() {
            let engine = &self.engines[ei];
            let status = if es.loading && es.alive {
                let hint = es.status_hint.as_deref().unwrap_or("syncing corpus");
                format!("<span class=\"loading\">{hint}</span>")
            } else if !es.alive {
                "<span class=\"dead\">dead</span>".to_string()
            } else if let Some(ref hint) = es.status_hint {
                format!("<span class=\"loading\">{hint}</span>")
            } else {
                "<span class=\"alive\">alive</span>".to_string()
            };
            let exec_s = if !es.alive || es.execs_per_sec <= 0.0 {
                "-".to_string()
            } else {
                format!("{:.0}", es.execs_per_sec)
            };

            if matches!(engine.kind, EngineKind::Afl) {
                // AFL header row — per-worker statuses shown in sub-rows
                let afl_header_actions = if self.show_switch_hints {
                    &format!("<a class=\"action-btn\" href=\"/scale?e=afl&amp;d=1&amp;tab={active_tab}\" title=\"add AFL++ worker\">+</a>")
                } else {
                    ""
                };
                let _ = writeln!(
                    buf,
                    "<tr><td><b>AFL++</b></td><td></td><td></td><td></td><td></td><td></td><td></td><td>{afl_header_actions}</td></tr>",
                );

                // Per-worker sub-rows (only in switchable mode)
                if self.show_switch_hints {
                    for (pos, &slot_idx) in engine.process_indices.iter().enumerate() {
                        let is_main = pos == 0;
                        let (label, job_num) = if is_main {
                            ("main".to_string(), Some(0u32))
                        } else if let Some(Some(ps)) = processes.get(slot_idx) {
                            match ps.job_num {
                                Some(n) => (format!("secondary #{n}"), Some(n)),
                                None => (format!("worker #{pos}"), None),
                            }
                        } else {
                            (format!("worker #{pos}"), None)
                        };

                        let worker_stats = job_num.and_then(|jn| afl_worker_stats.get(&jn));
                        let worker_loading = worker_stats.map(|ws| ws.loading).unwrap_or(true); // no stats yet → loading
                        let worker_hint = worker_stats.and_then(|ws| ws.status_hint.as_deref());
                        let worker_dead = worker_stats.is_some_and(|ws| !ws.alive && !ws.loading);
                        let (worker_status, is_paused) = match processes.get(slot_idx) {
                            Some(Some(ps)) if ps.paused => {
                                ("<span class=\"paused\">paused</span>".to_string(), true)
                            }
                            Some(Some(_)) if worker_dead => {
                                ("<span class=\"dead\">dead</span>".to_string(), false)
                            }
                            Some(Some(_)) if worker_loading => {
                                let hint = worker_hint.unwrap_or("loading\u{2026}");
                                (format!("<span class=\"loading\">{hint}</span>"), false)
                            }
                            Some(Some(_)) => {
                                ("<span class=\"alive\">alive</span>".to_string(), false)
                            }
                            _ => ("<span class=\"dead\">dead</span>".to_string(), false),
                        };

                        // Per-worker stats from fuzzer_stats files
                        let (w_exec, w_execs_done, w_corpus, w_crashes, w_last_crash) =
                            if let Some(jn) = job_num {
                                if let Some(ws) = afl_worker_stats.get(&jn) {
                                    let baseline =
                                        self.baseline_worker_crashes.get(&jn).copied().unwrap_or(0);
                                    let crashes = ws.crashes.saturating_sub(baseline);
                                    (
                                        if ws.execs_per_sec > 0.0 {
                                            format!("{:.0}", ws.execs_per_sec)
                                        } else {
                                            "-".to_string()
                                        },
                                        fmt_execs(ws.execs_done),
                                        format!("{}", ws.corpus_count),
                                        format!("{crashes}"),
                                        fmt_time_ago(ws.last_crash),
                                    )
                                } else {
                                    ("-".into(), "-".into(), "-".into(), "-".into(), "-".into())
                                }
                            } else {
                                ("-".into(), "-".into(), "-".into(), "-".into(), "-".into())
                            };

                        let mut actions = String::new();
                        if let Some(Some(_)) = processes.get(slot_idx) {
                            if is_paused {
                                let _ = write!(actions, "<a class=\"action-btn\" href=\"/resume?slot={slot_idx}&amp;tab={active_tab}\" title=\"resume\">\u{25b6}</a>");
                            } else {
                                let _ = write!(actions, "<a class=\"action-btn\" href=\"/pause?slot={slot_idx}&amp;tab={active_tab}\" title=\"pause\">\u{23f8}</a>");
                            }
                            if !is_main {
                                let _ = write!(actions, "<a class=\"action-btn danger\" href=\"/remove?slot={slot_idx}&amp;tab={active_tab}\" title=\"remove\">\u{2716}</a>");
                            }
                        }

                        let cmd_title = processes
                            .get(slot_idx)
                            .and_then(|o| o.as_ref())
                            .and_then(|ps| ps.command.as_deref())
                            .unwrap_or("");
                        let cmd_escaped = html_escape_attr(cmd_title);
                        let td_attr = if cmd_escaped.is_empty() {
                            String::new()
                        } else {
                            let js_escaped = cmd_title.replace('\\', "\\\\").replace('\'', "\\'");
                            format!(" class=\"path-copy\" title=\"{cmd_escaped}\" onclick=\"navigator.clipboard.writeText('{js_escaped}')\"")
                        };
                        let _ = writeln!(
                            buf,
                            "<tr class=\"worker-row\"><td{td_attr}>{label}</td><td>{worker_status}</td><td>{w_exec}</td><td>{w_execs_done}</td><td>{w_corpus}</td><td>{w_crashes}</td><td>{w_last_crash}</td><td>{actions}</td></tr>"
                        );
                    }
                }
            } else {
                // honggfuzz / libfuzzer: single row with pause/resume
                let mut actions = String::new();
                if self.show_switch_hints {
                    if let Some(&slot_idx) = engine.process_indices.first() {
                        if let Some(Some(ps)) = processes.get(slot_idx) {
                            if ps.paused {
                                let _ = write!(actions, "<a class=\"action-btn\" href=\"/resume?slot={slot_idx}&amp;tab={active_tab}\" title=\"resume\">\u{25b6}</a>");
                            } else {
                                let _ = write!(actions, "<a class=\"action-btn\" href=\"/pause?slot={slot_idx}&amp;tab={active_tab}\" title=\"pause\">\u{23f8}</a>");
                            }
                        }
                    }
                }
                let cmd_title = engine
                    .process_indices
                    .first()
                    .and_then(|&idx| processes.get(idx))
                    .and_then(|o| o.as_ref())
                    .and_then(|ps| ps.command.as_deref())
                    .unwrap_or("");
                let cmd_escaped = html_escape_attr(cmd_title);
                let td_attr = if cmd_escaped.is_empty() {
                    String::new()
                } else {
                    let js_escaped = cmd_title.replace('\\', "\\\\").replace('\'', "\\'");
                    format!(" class=\"path-copy\" title=\"{cmd_escaped}\" onclick=\"navigator.clipboard.writeText('{js_escaped}')\"")
                };
                let e_execs_done = fmt_execs(es.execs_done);
                let e_last_crash = fmt_time_ago(es.last_crash);
                let _ = writeln!(
                    buf,
                    "<tr><td{td_attr}>{}</td><td>{status}</td><td>{exec_s}</td><td>{e_execs_done}</td><td>{}</td><td>{}</td><td>{e_last_crash}</td><td>{actions}</td></tr>",
                    es.name, es.corpus_count, es.crashes
                );
            }
        }
        let _ = writeln!(buf, "</table>");

        // Graphs section — tabbed
        let has_ext_corpus = !self.external_corpus.is_empty();
        let mut tabs: Vec<(&str, &str)> = vec![
            ("exec", "Exec/s"),
            ("corpus", "Corpus"),
            ("cpu", "CPU"),
            ("mem", "Memory"),
        ];
        if has_ext_corpus {
            tabs.push(("ext-corpus", "Ext Corpus"));
        }
        let _ = write!(buf, "<div id=\"graph-area\">");
        let _ = write!(buf, "<div class=\"tab-bar\">");
        for (id, label) in &tabs {
            let cls = if *id == active_tab {
                "tab active"
            } else {
                "tab"
            };
            let _ = write!(buf, "<a href=\"/?tab={id}\" class=\"{cls}\">{label}</a>");
        }
        let _ = writeln!(buf, "</div>");

        let graph_names: Vec<&str> = self.graph_labels.iter().map(|s| s.as_str()).collect();
        let graph_colors: Vec<&str> = self.graph_colors.iter().map(|s| s.as_str()).collect();
        match active_tab {
            "exec" => self.render_line_chart(
                &mut buf,
                "Exec/s",
                "exec/s",
                &self.exec_history,
                &graph_names,
                &graph_colors,
            ),
            "corpus" => self.render_line_chart(
                &mut buf,
                "Corpus Size",
                "files",
                &self.corpus_history,
                &graph_names,
                &graph_colors,
            ),
            "cpu" => self.render_line_chart(
                &mut buf,
                "CPU Usage",
                "%",
                &self.cpu_history,
                &graph_names,
                &graph_colors,
            ),
            "ext-corpus" if has_ext_corpus => {
                let ext_names: Vec<&str> =
                    self.external_corpus.iter().map(|s| s.as_str()).collect();
                const EXT_COLORS: &[&str] = &[
                    "#7ec8e3", "#a3d977", "#c49bdb", "#e8c170", "#70d6d6", "#d4a0a0",
                ];
                let ext_colors: Vec<&str> = (0..self.external_corpus.len())
                    .map(|i| EXT_COLORS[i % EXT_COLORS.len()])
                    .collect();
                self.render_line_chart(
                    &mut buf,
                    "External Corpus Files",
                    "files",
                    &self.ext_corpus_history,
                    &ext_names,
                    &ext_colors,
                );
            }
            _ => self.render_line_chart(
                &mut buf,
                "Memory (RSS)",
                "MiB",
                &self.mem_history,
                &graph_names,
                &graph_colors,
            ),
        }

        let _ = writeln!(buf, "</div>"); // close graph-area

        // Strategy + Stop
        let _ = writeln!(buf, "<div class=\"actions\">");
        if self.show_switch_hints {
            let _ = writeln!(buf, "<h2>Strategy</h2>");
            let cur = self.current_strategy.unwrap_or(Strategy::AflFirst);
            let options = [
                (Strategy::AflFirst, "afl-first", "AFL++ first"),
                (Strategy::Parallel, "parallel", "Parallel"),
                (Strategy::AflOnly, "afl-only", "AFL++ only"),
                (Strategy::HonggOnly, "hongg-only", "honggfuzz only"),
                (Strategy::LibfuzzerOnly, "libfuzzer-only", "libfuzzer only"),
            ];
            let _ = write!(
                buf,
                "<form method=\"get\" action=\"/switch\" style=\"display:inline\">"
            );
            let _ = write!(
                buf,
                "<input type=\"hidden\" name=\"tab\" value=\"{active_tab}\">"
            );
            let _ = write!(buf, "<select name=\"s\">");
            for (strat, value, label) in &options {
                let selected = if *strat == cur { " selected" } else { "" };
                let _ = write!(buf, "<option value=\"{value}\"{selected}>{label}</option>");
            }
            let _ = write!(buf, "</select> ");
            let _ = write!(buf, "<button type=\"submit\">Switch</button>");
            let _ = write!(buf, "</form> ");
        }
        let _ = writeln!(
            buf,
            "<form method=\"get\" action=\"/stop\" style=\"display:inline\"><input type=\"hidden\" name=\"tab\" value=\"{active_tab}\"><button type=\"submit\" style=\"border-color:#f44336;color:#f44336\">Stop</button></form>"
        );
        let _ = writeln!(buf, "</div>");

        // Logs section
        let _ = writeln!(
            buf,
            "<div class=\"logs-section\" style=\"margin-top:16px\">"
        );
        let _ = writeln!(buf, "<h2>Logs</h2>");
        let _ = write!(
            buf,
            "<form method=\"get\" action=\"/logs\" target=\"_blank\"><select name=\"f\">"
        );
        for engine in &self.engines {
            match engine.kind {
                EngineKind::Afl => {
                    for &idx in &engine.process_indices {
                        if let Some(Some(ps)) = processes.get(idx) {
                            let jn = ps.job_num.unwrap_or(0);
                            if jn == 0 {
                                let _ = write!(buf, "<option value=\"afl\">AFL++ main</option>");
                            } else {
                                let _ = write!(
                                    buf,
                                    "<option value=\"afl_{jn}\">AFL++ secondary #{jn}</option>"
                                );
                            }
                        }
                    }
                }
                EngineKind::Honggfuzz => {
                    let _ = write!(buf, "<option value=\"honggfuzz\">honggfuzz</option>");
                }
                EngineKind::Libfuzzer => {
                    let _ = write!(buf, "<option value=\"libfuzzer\">libfuzzer</option>");
                }
            }
        }
        let abs_logs_dir = std::fs::canonicalize(format!("{}/logs", self.output_target))
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| format!("{}/logs", self.output_target));
        let _ = write!(
            buf,
            "</select> <button type=\"submit\">Show Logs</button>\
             <button type=\"button\" class=\"action-btn\" \
             onclick=\"var s=this.previousElementSibling.previousElementSibling;\
             var f=s.options[s.selectedIndex].value;\
             navigator.clipboard.writeText('{abs_logs_dir}/'+f+'.log');\
             this.textContent='\\u2713';setTimeout(()=>this.textContent='\\u2398',800)\" \
             title=\"Copy log path\">&#9112;</button>\
             </form>"
        );
        let _ = writeln!(buf, "</div>");

        let _ = writeln!(
            buf,
            "<script>\
document.addEventListener('click',function(e){{\
var el=e.target.closest('.path-copy');\
if(!el)return;\
var r=el.getBoundingClientRect();\
var t=document.createElement('span');\
t.textContent='Copied!';\
t.style.cssText='position:fixed;top:'+(r.top-24)+'px;left:'+(r.left+r.width/2)+'px;\
transform:translateX(-50%);background:#00d4ff;color:#0a0e27;padding:2px 8px;border-radius:4px;\
font-size:11px;pointer-events:none;z-index:9999;opacity:1;transition:opacity 0.4s';\
document.body.appendChild(t);\
setTimeout(function(){{t.style.opacity='0'}},600);\
setTimeout(function(){{t.remove()}},1000);\
}});\
setInterval(function(){{\
fetch(window.location.href)\
.then(function(r){{return r.text()}})\
.then(function(html){{\
var doc=new DOMParser().parseFromString(html,'text/html');\
var ids=['runtime','last-sync','corpus-count','external-corpus',\
'crash-count','syncing','stats-table','graph-area'];\
ids.forEach(function(id){{\
var fresh=doc.getElementById(id);\
var live=document.getElementById(id);\
if(fresh&&live)live.innerHTML=fresh.innerHTML;\
}});\
}})\
.catch(function(){{}});\
}},2000);\
</script>"
        );
        let _ = writeln!(buf, "</body></html>");
        buf
    }

    // ── chart rendering ─────────────────────────────────────────────────

    fn render_line_chart(
        &self,
        buf: &mut String,
        title: &str,
        y_label: &str,
        data: &VecDeque<TimeSeriesSample>,
        engine_names: &[&str],
        colors: &[&str],
    ) {
        if data.is_empty() {
            return;
        }

        let (left, right, top, bottom) = (60.0_f64, 780.0, 10.0, 180.0);
        let min_t = data.front().unwrap().elapsed_secs;
        let max_t = data.back().unwrap().elapsed_secs;
        let t_range = (max_t - min_t).max(1.0);

        // Find y_max across all series
        let y_max = {
            let raw = data
                .iter()
                .flat_map(|s| s.per_engine.iter().copied())
                .fold(0.0_f64, f64::max);
            round_up_nice(raw.max(1.0))
        };

        let _ = writeln!(
            buf,
            "<svg viewBox=\"0 0 800 200\" width=\"100%\" style=\"max-width:820px;margin:8px 0\">"
        );
        let _ = writeln!(
            buf,
            "<rect width=\"800\" height=\"200\" fill=\"#16213e\" rx=\"4\"/>"
        );

        // Title
        let _ = writeln!(
            buf,
            "<text x=\"{left}\" y=\"{top}\" dy=\"10\" fill=\"#e0e0e0\" font-size=\"12\">{title}</text>"
        );

        // Grid lines + Y labels
        for i in 0..=3 {
            let frac = i as f64 / 3.0;
            let y = bottom - frac * (bottom - top - 14.0);
            let val = y_max * frac;
            let _ = writeln!(
                buf,
                "<line x1=\"{left}\" y1=\"{y}\" x2=\"{right}\" y2=\"{y}\" stroke=\"#333\" stroke-dasharray=\"4\"/>"
            );
            let label = format_compact(val);
            let _ = writeln!(
                buf,
                "<text x=\"{lx}\" y=\"{y}\" dy=\"3\" text-anchor=\"end\">{label}</text>",
                lx = left - 4.0
            );
        }

        // Y-axis label
        let _ = writeln!(
            buf,
            "<text x=\"14\" y=\"100\" transform=\"rotate(-90,14,100)\" text-anchor=\"middle\" font-size=\"10\">{y_label}</text>"
        );

        // X-axis time labels
        render_x_labels(buf, min_t, max_t, left, right, bottom);

        // Sync bands
        self.render_sync_bands(buf, min_t, t_range, left, right, top, bottom);

        // Downsample
        let step = if data.len() > 600 {
            data.len() / 300
        } else {
            1
        };

        // Polylines per engine
        for (ei, color) in colors.iter().enumerate().take(engine_names.len()) {
            let mut points = String::new();
            for (j, sample) in data.iter().enumerate() {
                if j % step != 0 && j != data.len() - 1 {
                    continue;
                }
                let val = sample.per_engine.get(ei).copied().unwrap_or(0.0);
                let x = left + (sample.elapsed_secs - min_t) / t_range * (right - left);
                let y = bottom - (val / y_max) * (bottom - top - 14.0);
                let _ = write!(points, "{x:.1},{y:.1} ");
            }
            let _ = writeln!(
                buf,
                "<polyline points=\"{points}\" fill=\"none\" stroke=\"{color}\" stroke-width=\"1.5\"/>"
            );
        }

        // Legend (top-right)
        let n_engines = engine_names.len().min(colors.len());
        for (ei, (name, color)) in engine_names
            .iter()
            .zip(colors.iter())
            .enumerate()
            .take(n_engines)
        {
            let lx = right - 10.0;
            let ly = top + 14.0 + ei as f64 * 14.0;
            let _ = writeln!(
                buf,
                "<rect x=\"{rx}\" y=\"{ry}\" width=\"8\" height=\"8\" fill=\"{color}\"/>",
                rx = lx - 10.0,
                ry = ly - 7.0
            );
            let _ = writeln!(
                buf,
                "<text x=\"{lx}\" y=\"{ly}\" text-anchor=\"end\" font-size=\"9\" dx=\"-14\">{name}</text>"
            );
        }

        let _ = writeln!(buf, "</svg>");
    }

    #[allow(clippy::too_many_arguments)]
    fn render_sync_bands(
        &self,
        buf: &mut String,
        min_t: f64,
        t_range: f64,
        left: f64,
        right: f64,
        top: f64,
        bottom: f64,
    ) {
        for sp in &self.sync_periods {
            let x1 = left + (sp.start_secs - min_t) / t_range * (right - left);
            let x2 = if let Some(end) = sp.end_secs {
                left + (end - min_t) / t_range * (right - left)
            } else {
                right
            };
            let x1 = x1.max(left);
            let x2 = x2.min(right);
            if x2 > x1 {
                let _ = writeln!(
                    buf,
                    "<rect x=\"{x1:.1}\" y=\"{top}\" width=\"{w:.1}\" height=\"{h}\" fill=\"rgba(255,152,0,0.15)\"/>",
                    w = x2 - x1,
                    h = bottom - top
                );
            }
        }
    }

    // ── stat readers ─────────────────────────────────────────────────────

    /// Parse AFL++ `fuzzer_stats` key-value files.
    fn read_afl_stats(&self, engine: &EngineInfo) -> EngineStats {
        let mut total = EngineStats {
            execs_per_sec: 0.0,
            corpus_count: 0,
            crashes: 0,
            execs_done: 0,
            last_crash: 0,
            alive: false,
            loading: false,
            status_hint: None,
        };

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
                            "execs_done" => {
                                total.execs_done += val.parse::<u64>().unwrap_or(0);
                            }
                            "last_crash" => {
                                let v = val.parse::<u64>().unwrap_or(0);
                                if v > total.last_crash {
                                    total.last_crash = v;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        if !found_stats {
            let log_path = format!("{}/logs/afl.log", self.output_target);
            if let Some((done, total_seeds)) = parse_afl_import_progress(&log_path) {
                total.status_hint = Some(format!("importing seeds ({done}/{total_seeds})"));
                total.loading = true;
            } else {
                let tail = tail_file(&log_path, 4096);
                if !tail.is_empty() {
                    total.status_hint = Some("starting".to_string());
                    total.loading = true;
                }
            }
        }

        let _ = engine;
        total
    }

    /// Parse AFL++ `fuzzer_stats` for all workers individually, returning
    /// aggregate stats and a per-worker map keyed by job_num.
    fn read_afl_all_stats(&self) -> (EngineStats, HashMap<u32, EngineStats>) {
        let mut total = EngineStats {
            execs_per_sec: 0.0,
            corpus_count: 0,
            crashes: 0,
            execs_done: 0,
            last_crash: 0,
            alive: false,
            loading: false,
            status_hint: None,
        };
        let mut per_worker: HashMap<u32, EngineStats> = HashMap::new();

        let pattern = format!("{}/afl/*/fuzzer_stats", self.output_target);
        let mut found_stats = false;
        for path in glob::glob(&pattern).into_iter().flatten().flatten() {
            let dir_name = path
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .unwrap_or("");
            let job_num = if dir_name == "mainaflfuzzer" {
                0u32
            } else if let Some(suffix) = dir_name.strip_prefix("secondaryfuzzer") {
                suffix.parse::<u32>().unwrap_or(u32::MAX)
            } else {
                continue;
            };

            if let Ok(contents) = fs::read_to_string(&path) {
                found_stats = true;
                let mut ws = EngineStats {
                    execs_per_sec: 0.0,
                    corpus_count: 0,
                    crashes: 0,
                    execs_done: 0,
                    last_crash: 0,
                    alive: false,
                    loading: false,
                    status_hint: None,
                };
                let mut stats_start_time: u64 = 0;
                let mut fuzzer_pid: u32 = 0;
                for line in contents.lines() {
                    if let Some((key, val)) = line.split_once(':') {
                        let key = key.trim();
                        let val = val.trim();
                        match key {
                            "execs_per_sec" => {
                                ws.execs_per_sec = val.parse::<f64>().unwrap_or(0.0);
                            }
                            "corpus_count" => {
                                ws.corpus_count = val.parse::<u64>().unwrap_or(0);
                            }
                            "saved_crashes" => {
                                ws.crashes = val.parse::<u64>().unwrap_or(0);
                            }
                            "start_time" => {
                                stats_start_time = val.parse::<u64>().unwrap_or(0);
                            }
                            "fuzzer_pid" => {
                                fuzzer_pid = val.parse::<u32>().unwrap_or(0);
                            }
                            "execs_done" => {
                                ws.execs_done = val.parse::<u64>().unwrap_or(0);
                            }
                            "last_crash" => {
                                ws.last_crash = val.parse::<u64>().unwrap_or(0);
                            }
                            _ => {}
                        }
                    }
                }
                // Check if the fuzzer process is actually alive.
                if fuzzer_pid > 0 {
                    ws.alive = std::path::Path::new(&format!("/proc/{fuzzer_pid}")).exists();
                }
                // Stale stats from a previous AFL_AUTORESUME session
                let stale = stats_start_time > 0
                    && stats_start_time < self.session_start_epoch.saturating_sub(5);
                if stale {
                    // Stats file is from a previous run; ignore its values
                    ws.loading = true;
                    ws.status_hint = Some("starting".to_string());
                }
                if ws.alive {
                    total.execs_per_sec += ws.execs_per_sec;
                    total.corpus_count += ws.corpus_count;
                    total.crashes += ws.crashes;
                    total.execs_done += ws.execs_done;
                    if ws.last_crash > total.last_crash {
                        total.last_crash = ws.last_crash;
                    }
                }
                per_worker.insert(job_num, ws);
            }
        }

        if !found_stats {
            // Check per-worker logs for import progress
            let worker_logs: Vec<(u32, String)> = {
                let mut logs = vec![(0u32, format!("{}/logs/afl.log", self.output_target))];
                for i in 1..32u32 {
                    let p = format!("{}/logs/afl_{i}.log", self.output_target);
                    if std::path::Path::new(&p).exists() {
                        logs.push((i, p));
                    } else {
                        break;
                    }
                }
                logs
            };
            let mut agg_done: u64 = 0;
            let mut agg_total: u64 = 0;
            let mut any_importing = false;
            for (job_num, log_path) in &worker_logs {
                if let Some((done, total_seeds)) = parse_afl_import_progress(log_path) {
                    any_importing = true;
                    agg_done += done;
                    agg_total += total_seeds;
                    per_worker.insert(
                        *job_num,
                        EngineStats {
                            execs_per_sec: 0.0,
                            corpus_count: 0,
                            crashes: 0,
                            execs_done: 0,
                            last_crash: 0,
                            alive: false,
                            loading: true,
                            status_hint: Some(format!("importing seeds ({done}/{total_seeds})")),
                        },
                    );
                } else {
                    let tail = tail_file(log_path, 4096);
                    if !tail.is_empty() {
                        per_worker.insert(
                            *job_num,
                            EngineStats {
                                execs_per_sec: 0.0,
                                corpus_count: 0,
                                crashes: 0,
                                execs_done: 0,
                                last_crash: 0,
                                alive: false,
                                loading: true,
                                status_hint: Some("starting".to_string()),
                            },
                        );
                    }
                }
            }
            if any_importing {
                total.status_hint = Some(format!("importing seeds ({agg_done}/{agg_total})"));
            } else {
                let main_log = format!("{}/logs/afl.log", self.output_target);
                let tail = tail_file(&main_log, 4096);
                if !tail.is_empty() {
                    total.status_hint = Some("starting".to_string());
                }
            }
            total.loading = true;
        } else if per_worker.values().all(|ws| ws.loading) {
            total.loading = true;
            total.status_hint = Some("starting".to_string());
        }

        (total, per_worker)
    }

    /// Parse honggfuzz TUI log.
    fn read_honggfuzz_stats(&self) -> EngineStats {
        let mut stats = EngineStats {
            execs_per_sec: 0.0,
            corpus_count: 0,
            crashes: 0,
            execs_done: 0,
            last_crash: 0,
            alive: false,
            loading: false,
            status_hint: None,
        };

        let log_path = format!("{}/logs/honggfuzz.log", self.output_target);
        let tail = tail_file(&log_path, 32768);

        if let Some(v) = rfind_after(&tail, "Speed : ") {
            let clean = strip_ansi_inline(v);
            // Parse instantaneous speed: "N/sec [avg: M]"
            if let Some(num) = clean.split('/').next() {
                stats.execs_per_sec = parse_num(num);
            }
            // Fallback to average speed if instantaneous is 0
            if stats.execs_per_sec == 0.0 {
                if let Some(avg) = clean.find("avg: ").map(|i| &clean[i + 5..]) {
                    let avg_num: String = avg
                        .chars()
                        .take_while(|c| c.is_ascii_digit() || *c == ',')
                        .collect();
                    if !avg_num.is_empty() {
                        stats.execs_per_sec = parse_num(&avg_num);
                    }
                }
            }
        }
        if let Some(v) = rfind_after(&tail, "Crashes : ") {
            let clean = strip_ansi_inline(v);
            if let Some(num) = clean.split_whitespace().next() {
                stats.crashes = parse_num(num) as u64;
            }
        }
        if let Some(v) = rfind_after(&tail, "Corpus Size : ") {
            let clean = strip_ansi_inline(v);
            let num: String = clean
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == ',')
                .collect();
            stats.corpus_count = parse_num(&num) as u64;
        }
        if let Some(v) = rfind_after(&tail, "Iterations : ") {
            let clean = strip_ansi_inline(v);
            let num: String = clean
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == ',')
                .collect();
            stats.execs_done = parse_num(&num) as u64;
        }
        // Last crash: newest file mtime in honggfuzz crash dir.
        stats.last_crash =
            newest_file_mtime(&format!("{}/honggfuzz/{}", self.output_target, self.target));

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
            execs_done: 0,
            last_crash: 0,
            alive: false,
            loading: false,
            status_hint: None,
        };

        let log_path = format!("{}/logs/libfuzzer.log", self.output_target);
        let tail = tail_file(&log_path, 8192);

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
                    if let Some(num) = v.split(|c: char| !c.is_ascii_digit()).next() {
                        stats.corpus_count = parse_num(num) as u64;
                    }
                }
            }
        }

        stats.crashes = count_files(&format!("{}/libfuzzer/crashes", self.output_target));
        // Total execs from libfuzzer log.
        for line in tail.lines().rev() {
            if stats.execs_done == 0 {
                if let Some(v) = extract_after(line, "stat::number_of_executed_units: ") {
                    if let Some(num) = v.split_whitespace().next() {
                        stats.execs_done = parse_num(num) as u64;
                    }
                }
            }
        }
        // Last crash: newest file mtime in libfuzzer crash dir.
        stats.last_crash = newest_file_mtime(&format!("{}/libfuzzer/crashes", self.output_target));

        if stats.execs_per_sec == 0.0 && !tail.is_empty() && !tail.contains("exec/s:") {
            stats.status_hint = Some("starting".to_string());
            stats.loading = true;
        }

        stats
    }
}

// ── /proc readers ───────────────────────────────────────────────────────

/// Sum utime + stime from /proc/{pid}/stat.
/// Excludes cutime/cstime to avoid huge spikes when forkserver children exit.
fn read_proc_cpu_jiffies(pid: u32) -> u64 {
    let path = format!("/proc/{pid}/stat");
    let Ok(contents) = fs::read_to_string(path) else {
        return 0;
    };
    // Fields after the comm "(name)" to avoid spaces in process name
    let Some(rest) = contents.rfind(')').map(|i| &contents[i + 2..]) else {
        return 0;
    };
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // After closing paren: field 11 = utime, 12 = stime
    let utime = fields
        .get(11)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let stime = fields
        .get(12)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    utime + stime
}

/// RSS in bytes from /proc/{pid}/statm field 1, multiplied by page_size.
fn read_proc_rss_bytes(pid: u32, page_size: usize) -> u64 {
    let path = format!("/proc/{pid}/statm");
    let Ok(contents) = fs::read_to_string(path) else {
        return 0;
    };
    let rss_pages = contents
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    rss_pages * page_size as u64
}

// ── chart helpers ───────────────────────────────────────────────────────

/// Round a value up to a "nice" number for Y-axis max.
fn round_up_nice(v: f64) -> f64 {
    if v <= 0.0 {
        return 1.0;
    }
    let mag = 10.0_f64.powf(v.log10().floor());
    let norm = v / mag;
    let nice = if norm <= 1.0 {
        1.0
    } else if norm <= 2.0 {
        2.0
    } else if norm <= 5.0 {
        5.0
    } else {
        10.0
    };
    nice * mag
}

/// Format a number compactly for axis labels.
fn format_compact(v: f64) -> String {
    if v >= 1_000_000.0 {
        format!("{:.1}M", v / 1_000_000.0)
    } else if v >= 1_000.0 {
        format!("{:.1}K", v / 1_000.0)
    } else if v == v.floor() {
        format!("{:.0}", v)
    } else {
        format!("{:.1}", v)
    }
}

/// Format elapsed seconds as `Xm` or `XhYm`.
fn fmt_elapsed_short(secs: f64) -> String {
    let total = secs as u64;
    let h = total / 3600;
    let m = (total % 3600) / 60;
    if h > 0 {
        format!("{h}h{m:02}m")
    } else {
        format!("{m}m")
    }
}

fn render_x_labels(buf: &mut String, min_t: f64, max_t: f64, left: f64, right: f64, bottom: f64) {
    let t_range = (max_t - min_t).max(1.0);
    // Aim for ~5 labels
    let step_secs = (t_range / 5.0).max(30.0);
    // Round step to a nice interval
    let step_secs = if step_secs < 60.0 {
        60.0
    } else if step_secs < 300.0 {
        300.0
    } else {
        600.0
    };
    let mut t = (min_t / step_secs).ceil() * step_secs;
    while t <= max_t {
        let x = left + (t - min_t) / t_range * (right - left);
        let label = fmt_elapsed_short(t);
        let _ = writeln!(
            buf,
            "<text x=\"{x:.1}\" y=\"{y}\" text-anchor=\"middle\">{label}</text>",
            y = bottom + 14.0
        );
        t += step_secs;
    }
}

// ── helpers ──────────────────────────────────────────────────────────────

/// Read the last `n` bytes of a file as a string.
pub fn tail_file(path: &str, n: u64) -> String {
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

/// Read the first `n` bytes of a file.
fn head_file(path: &str, n: u64) -> String {
    let Ok(file) = fs::File::open(path) else {
        return String::new();
    };
    let mut buf = String::new();
    let _ = file.take(n).read_to_string(&mut buf);
    buf
}

/// Parse AFL++ seed import progress from a log file.
/// Returns `Some((done, total))` when the log shows a dry run in progress.
fn parse_afl_import_progress(log_path: &str) -> Option<(u64, u64)> {
    // Read head to find total seed count ("Loaded a total of N seeds.")
    let head = head_file(log_path, 8192);
    let total = head
        .find("Loaded a total of ")
        .map(|i| &head[i + "Loaded a total of ".len()..])
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse::<u64>().ok())?;

    // Read tail to find the last dry-run id
    let tail = tail_file(log_path, 4096);
    if !tail.contains("Attempting dry run") {
        return None;
    }
    // Extract the last "id:NNNNNN" — the id is 0-indexed, so done = id + 1
    let done = tail
        .rmatch_indices("Attempting dry run with 'id:")
        .next()
        .and_then(|(i, _)| {
            let after = &tail[i + "Attempting dry run with 'id:".len()..];
            let num: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            num.parse::<u64>().ok().map(|id| id + 1)
        })
        .unwrap_or(0);

    Some((done, total))
}

/// Find the substring after the *last* occurrence of `prefix` in `haystack`.
fn rfind_after<'a>(haystack: &'a str, prefix: &str) -> Option<&'a str> {
    let idx = haystack.rfind(prefix)?;
    Some(&haystack[idx + prefix.len()..])
}

/// Strip ANSI escape sequences from a short value string.
pub fn strip_ansi_inline(s: &str) -> String {
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
fn html_escape_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

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

/// Format a unix timestamp as relative time ago, e.g. "2m", "1h", "3d".
fn fmt_time_ago(unix_ts: u64) -> String {
    if unix_ts == 0 {
        return "-".to_string();
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if unix_ts > now {
        return "now".to_string();
    }
    let ago = now - unix_ts;
    if ago < 60 {
        format!("{ago}s")
    } else if ago < 3600 {
        format!("{}m", ago / 60)
    } else if ago < 86400 {
        format!("{}h", ago / 3600)
    } else {
        format!("{}d", ago / 86400)
    }
}

/// Format a large number compactly: 1234 → "1234", 12345 → "12.3K", 1234567 → "1.2M".
fn fmt_execs(n: u64) -> String {
    if n == 0 {
        return "-".to_string();
    }
    if n < 10_000 {
        format!("{n}")
    } else if n < 1_000_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else if n < 1_000_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else {
        format!("{:.1}B", n as f64 / 1_000_000_000.0)
    }
}

/// Get the mtime (as unix seconds) of the newest file in a directory.
fn newest_file_mtime(dir: &str) -> u64 {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter_map(|e| e.metadata().ok()?.modified().ok())
        .map(|t| t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs())
        .max()
        .unwrap_or(0)
}

pub fn fmt_duration(d: Duration) -> String {
    let total_secs = d.as_secs();
    let days = total_secs / 86400;
    let hrs = (total_secs % 86400) / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    format!("{days} days {hrs:02} hrs {mins:02} mins {secs:02} secs")
}

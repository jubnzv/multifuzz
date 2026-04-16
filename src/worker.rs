use crate::{config, Worker, WorkerCommand, DEFAULT_OUTPUT_DIR};
use anyhow::{anyhow, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

/// One entry in the state file.
pub struct WorkerEntry {
    pub name: String,
    pub pid: u32,
    pub log: String,
}

const STATE_FILE: &str = ".multifuzz.state";
const PID_FILE: &str = ".multifuzz.pid";

fn state_path(output_target: &str) -> PathBuf {
    PathBuf::from(format!("{output_target}/{STATE_FILE}"))
}

fn pid_path(output_target: &str) -> PathBuf {
    PathBuf::from(format!("{output_target}/{PID_FILE}"))
}

/// Write orchestrator PID so `worker start` can signal it.
pub fn write_pid(output_target: &str) {
    let _ = fs::write(pid_path(output_target), std::process::id().to_string());
}

/// Remove orchestrator PID file.
pub fn remove_pid(output_target: &str) {
    let _ = fs::remove_file(pid_path(output_target));
}

/// Read orchestrator PID.
pub fn read_pid(output_target: &str) -> Option<u32> {
    fs::read_to_string(pid_path(output_target))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn resolve_output_target(config_path: Option<&Path>) -> Result<String> {
    let cfg = config::load_config(config_path)?;
    let fuzz_cfg = cfg
        .fuzz
        .ok_or_else(|| anyhow!("No [fuzz] section in config"))?;
    let target = fuzz_cfg
        .target
        .ok_or_else(|| anyhow!("No target in config"))?;
    let output = fuzz_cfg
        .output
        .unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT_DIR));
    Ok(format!("{}/{}", output.display(), target))
}

/// Read state file. Returns empty vec if missing.
pub fn read_state(output_target: &str) -> Vec<WorkerEntry> {
    let path = state_path(output_target);
    let contents = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    contents
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.splitn(3, '\t').collect();
            if parts.len() == 3 {
                Some(WorkerEntry {
                    name: parts[0].to_string(),
                    pid: parts[1].parse().unwrap_or(0),
                    log: parts[2].to_string(),
                })
            } else {
                None
            }
        })
        .collect()
}

/// Write state file (overwrite).
pub fn write_state(output_target: &str, entries: &[(String, u32, String)]) {
    let path = state_path(output_target);
    let content: String = entries
        .iter()
        .map(|(name, pid, log)| format!("{name}\t{pid}\t{log}"))
        .collect::<Vec<_>>()
        .join("\n");
    let _ = fs::write(path, content + "\n");
}

/// Send SIGUSR1 to the orchestrator so it picks up new state.
#[allow(dead_code)]
pub fn notify_orchestrator(output_target: &str) {
    if let Some(pid) = read_pid(output_target) {
        unsafe {
            libc::kill(pid as i32, libc::SIGUSR1);
        }
    }
}

fn pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

/// True while any process remains in the group with PGID = `pid`.
/// Workers are spawned with process_group(0), so PGID == leader PID.
fn pgroup_alive(pid: u32) -> bool {
    unsafe { libc::kill(-(pid as i32), 0) == 0 }
}

/// Stop a worker process group: SIGTERM, wait up to ~5s for the entire
/// group (forkservers, fork-mode children, grandchildren) to exit, then
/// SIGKILL and wait up to another ~5s. Only returns once the group is
/// truly empty, so callers can safely respawn without flock conflicts.
fn stop_worker(pid: u32, name: &str) {
    if !pgroup_alive(pid) {
        return;
    }
    eprintln!("Stopping {name} (pid={pid})");
    unsafe {
        libc::kill(-(pid as i32), libc::SIGTERM);
    }
    for _ in 0..100 {
        if !pgroup_alive(pid) {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    eprintln!("{name} (pid={pid}) did not exit; sending SIGKILL");
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
    for _ in 0..100 {
        if !pgroup_alive(pid) {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    eprintln!("{name} (pid={pid}) still has live processes after SIGKILL");
}

fn find_worker<'a>(entries: &'a [WorkerEntry], query: &str) -> Option<&'a WorkerEntry> {
    let q = query.to_lowercase();
    entries
        .iter()
        .find(|e| e.name.to_lowercase() == q || e.name.to_lowercase().contains(&q))
}

impl Worker {
    pub fn run(&self) -> Result<()> {
        let output_target = resolve_output_target(self.config.as_deref())?;

        match &self.command {
            WorkerCommand::Ps => {
                let entries = read_state(&output_target);
                if entries.is_empty() {
                    eprintln!("No state file found. Is a fuzzing campaign running?");
                    return Ok(());
                }
                eprintln!("{:<20} {:<10} {:<10} LOG", "NAME", "PID", "STATUS");
                for e in &entries {
                    let status = if pid_alive(e.pid) { "running" } else { "dead" };
                    eprintln!("{:<20} {:<10} {:<10} {}", e.name, e.pid, status, e.log);
                }
            }
            WorkerCommand::Kill { name } => {
                let entries = read_state(&output_target);
                let entry = find_worker(&entries, name)
                    .ok_or_else(|| anyhow!("Worker '{}' not found in state file", name))?;

                if !pid_alive(entry.pid) {
                    eprintln!("{} (pid={}) is already dead", entry.name, entry.pid);
                    return Ok(());
                }

                eprintln!("Sending SIGTERM to {} (pid={})", entry.name, entry.pid);
                unsafe {
                    libc::kill(-(entry.pid as i32), libc::SIGTERM);
                }

                // Update state: remove the killed entry.
                let remaining: Vec<(String, u32, String)> = entries
                    .iter()
                    .filter(|e| e.pid != entry.pid)
                    .map(|e| (e.name.clone(), e.pid, e.log.clone()))
                    .collect();
                write_state(&output_target, &remaining);
                eprintln!("Done.");
            }
            WorkerCommand::Start { name } => {
                let entries = read_state(&output_target);
                if let Some(entry) = find_worker(&entries, name) {
                    if pid_alive(entry.pid) {
                        return Err(anyhow!(
                            "{} is already running (pid={})",
                            entry.name,
                            entry.pid
                        ));
                    }
                }
                self.do_start(name, &output_target, entries)?;
            }
            WorkerCommand::Restart { name } => {
                let entries = read_state(&output_target);
                if let Some(entry) = find_worker(&entries, name) {
                    stop_worker(entry.pid, &entry.name);
                } else {
                    eprintln!("No running instance of '{name}'; starting fresh.");
                }
                self.do_start(name, &output_target, entries)?;
            }
        }

        Ok(())
    }

    fn do_start(&self, name: &str, output_target: &str, entries: Vec<WorkerEntry>) -> Result<()> {
        let mut fuzz = crate::Fuzz::from_config(self.config.as_deref())?;
        let (child, canonical_name, log_path) = fuzz.spawn_single_worker(name)?;
        let pid = child.id();
        // Let Child drop — Rust does not kill child on drop, and
        // process_group(0) ensures it survives after we exit.
        drop(child);

        // Update state: keep live entries, add the new one.
        let mut new_entries: Vec<(String, u32, String)> = entries
            .iter()
            .filter(|e| e.name != canonical_name && pid_alive(e.pid))
            .map(|e| (e.name.clone(), e.pid, e.log.clone()))
            .collect();
        new_entries.push((canonical_name.clone(), pid, log_path.clone()));
        write_state(output_target, &new_entries);

        notify_orchestrator(output_target);

        eprintln!("Started {} (pid={})", canonical_name, pid);
        eprintln!("  log: {log_path}");
        Ok(())
    }
}

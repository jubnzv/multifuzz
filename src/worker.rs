use crate::{config, Worker, WorkerCommand, DEFAULT_OUTPUT_DIR};
use anyhow::{anyhow, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// One entry in the state file.
pub struct WorkerEntry {
    pub name: String,
    pub pid: u32,
    pub log: String,
}

const STATE_FILE: &str = ".multifuzz.state";

fn state_path(output_target: &str) -> PathBuf {
    PathBuf::from(format!("{output_target}/{STATE_FILE}"))
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

fn pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
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

                // TODO: spawn worker from config.
                // This requires refactoring spawn logic out of Fuzz methods
                // into standalone functions that can be called from here.
                // For now, error with instructions.
                return Err(anyhow!(
                    "`worker start` is not yet implemented. Use `multifuzz fuzz` to start all workers."
                ));
            }
        }

        Ok(())
    }
}

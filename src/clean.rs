use crate::{config, Clean, DEFAULT_OUTPUT_DIR};
use anyhow::{anyhow, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::{fs, io};

fn prompt(msg: &str) -> bool {
    eprint!("{msg} [Y/n] ");
    io::stderr().flush().ok();
    let mut answer = String::new();
    io::stdin().read_line(&mut answer).unwrap_or(0);
    let answer = answer.trim().to_lowercase();
    answer.is_empty() || answer == "y" || answer == "yes"
}

impl Clean {
    pub fn clean(&self) -> Result<()> {
        let cfg = config::load_config(self.config.as_deref())?;
        let fuzz_cfg = cfg
            .fuzz
            .ok_or_else(|| anyhow!("No [fuzz] section in config"))?;

        let target = fuzz_cfg
            .target
            .ok_or_else(|| anyhow!("No target in config"))?;
        let output = fuzz_cfg
            .output
            .unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT_DIR));
        let output_target = format!("{}/{}", output.display(), target);

        let mut cleaned = false;

        // Step 1: Lockfile + state file.
        let lock_path = format!("{output_target}/.multifuzz.lock");
        let state_path = format!("{output_target}/.multifuzz.state");
        let has_lock = Path::new(&lock_path).exists();
        let has_state = Path::new(&state_path).exists();
        if has_lock || has_state {
            if has_lock {
                eprintln!("Found lockfile: {lock_path}");
            }
            if has_state {
                eprintln!("Found state file: {state_path}");
            }
            eprintln!("Ensure no multifuzz instance is running!");
            if prompt("Remove?") {
                if has_lock {
                    let _ = fs::remove_file(&lock_path);
                }
                if has_state {
                    let _ = fs::remove_file(&state_path);
                }
                eprintln!("Removed.");
                cleaned = true;
            }
        }

        // Step 2: AFL_TMPDIR .cur_input files.
        let mut cur_inputs: Vec<PathBuf> = Vec::new();
        if let Some(afl) = &fuzz_cfg.afl {
            if let Ok((all_cfg, worker_cfgs)) = config::parse_afl_worker_configs(afl) {
                // Collect AFL_TMPDIR from all config.
                if let Some(all) = &all_cfg {
                    if let Some(env) = &all.env {
                        if let Some(dir) = env.get("AFL_TMPDIR") {
                            let p = PathBuf::from(dir).join(".cur_input");
                            if p.exists() {
                                cur_inputs.push(p);
                            }
                        }
                    }
                }
                // Collect from each worker.
                for cfg in worker_cfgs.values() {
                    if let Some(env) = &cfg.env {
                        if let Some(dir) = env.get("AFL_TMPDIR") {
                            let p = PathBuf::from(dir).join(".cur_input");
                            if p.exists() {
                                cur_inputs.push(p);
                            }
                        }
                    }
                }
            }
        }
        if !cur_inputs.is_empty() {
            eprintln!();
            eprintln!("Found .cur_input in AFL temp dirs:");
            for p in &cur_inputs {
                eprintln!("  {}", p.display());
            }
            if prompt("Remove all .cur_input files?") {
                for p in &cur_inputs {
                    let _ = fs::remove_file(p);
                }
                eprintln!("Removed.");
                cleaned = true;
            }
        }

        // Step 3: Output directory.
        if Path::new(&output_target).exists() {
            eprintln!();
            eprintln!("WARNING: removing output directory will destroy all fuzzing results!");
            eprintln!("Unsynced corpus and crashes will be lost.");
            eprintln!("Consider running `afl-cmin` on the corpus before cleaning.");
            eprintln!("Output directory: {output_target}");
            if prompt("Remove?") {
                fs::remove_dir_all(&output_target)?;
                eprintln!("Removed.");
                cleaned = true;
            }
        }

        if !cleaned {
            eprintln!("Nothing to clean.");
        }

        Ok(())
    }
}

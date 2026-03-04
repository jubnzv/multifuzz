use crate::Run;
use anyhow::{anyhow, Context, Result};
use std::{
    collections::HashSet,
    env, fs,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process,
};

impl Run {
    pub fn run(&self) -> Result<()> {
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        eprintln!("    Building runner");

        let status = process::Command::new(cargo)
            .args(["rustc", "--target-dir=target/runner"])
            .spawn()
            .context("couldn't spawn runner compilation")?
            .wait()
            .context("couldn't wait for the runner compilation process")?;

        if !status.success() {
            return Err(anyhow!(
                "Error building runner: exited with {:?}",
                status.code()
            ));
        }

        eprintln!("    Finished runner");

        let mut input_dirs = self.inputs.clone();

        if self.recursive {
            let mut all_dirs = HashSet::new();
            for input in &self.inputs {
                all_dirs.insert(input.clone());
                collect_dirs_recursively(input, &mut all_dirs)?;
            }
            for dir in all_dirs {
                if !input_dirs.contains(&dir) {
                    input_dirs.push(dir);
                }
            }
        }

        let input_files: Vec<PathBuf> = input_dirs
            .iter()
            .flat_map(|path| {
                if path.is_dir() {
                    fs::read_dir(path)
                        .expect("could not read directory")
                        .filter_map(|entry| entry.ok())
                        .map(|entry| entry.path())
                        .filter(|p| p.is_file())
                        .collect::<Vec<_>>()
                } else {
                    vec![path.clone()]
                }
            })
            .collect();

        let runner_path = format!("./target/runner/debug/{}", self.target);

        for file in &input_files {
            let res = process::Command::new(&runner_path)
                .arg(file)
                .env("RUST_BACKTRACE", "full")
                .spawn()
                .context("couldn't spawn the runner process")?
                .wait()
                .context("couldn't wait for the runner process")?;

            if !res.success() {
                if let Some(signal) = res.signal() {
                    println!("input terminated with signal {signal:?}!");
                } else if let Some(exit_code) = res.code() {
                    println!("input terminated with code {exit_code:?}!");
                } else {
                    println!("input terminated for unknown reason!");
                }
            }
        }

        Ok(())
    }
}

fn collect_dirs_recursively(dir: &Path, dir_list: &mut HashSet<PathBuf>) -> Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && !dir_list.contains(&path) {
                dir_list.insert(path.clone());
                collect_dirs_recursively(&path, dir_list)?;
            }
        }
    }
    Ok(())
}

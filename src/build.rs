use crate::{config, Build};
use anyhow::{anyhow, Context, Result};
use std::process;

fn default_afl_cmd() -> String {
    "AFL_QUIET=1 cargo afl build --features=multifuzz/afl --target-dir=target/afl".to_string()
}

fn default_afl_cmplog_cmd() -> String {
    "AFL_QUIET=1 AFL_LLVM_CMPLOG=1 cargo afl build --features=multifuzz/afl --target-dir=target/afl-cmplog".to_string()
}

fn default_honggfuzz_cmd() -> String {
    "CARGO_TARGET_DIR=./target/honggfuzz HFUZZ_BUILD_ARGS='--features=multifuzz/honggfuzz' cargo hfuzz build-debug".to_string()
}

fn default_libfuzzer_cmd() -> String {
    let host = detect_host_triple();
    let target_key = format!(
        "CARGO_TARGET_{}_RUSTFLAGS",
        host.to_uppercase().replace('-', "_")
    );
    let sancov = "-Cpasses=sancov-module \
        -Cllvm-args=-sanitizer-coverage-level=4 \
        -Cllvm-args=-sanitizer-coverage-trace-compares \
        -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
        -Cllvm-args=-sanitizer-coverage-pc-table";
    format!(
        "{target_key}='{sancov}' cargo build --release --target={host} --features=multifuzz/libfuzzer --target-dir=target/libfuzzer"
    )
}

fn detect_host_triple() -> String {
    process::Command::new("rustc")
        .args(["-vV"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("host:"))
                .map(|l| l["host:".len()..].trim().to_string())
        })
        .unwrap_or_else(|| String::from("x86_64-unknown-linux-gnu"))
}

fn run_build_step(name: &str, cmd: &str) -> Result<()> {
    eprintln!("    Building {name}");
    eprintln!("    $ {cmd}");
    let status = process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .spawn()
        .with_context(|| format!("Failed to spawn build command for {name}"))?
        .wait()
        .with_context(|| format!("Failed to wait for build command for {name}"))?;
    if !status.success() {
        return Err(anyhow!(
            "Error building {name}: exited with {:?}",
            status.code()
        ));
    }
    eprintln!("    Finished {name}");
    Ok(())
}

impl Build {
    pub fn build(&self) -> Result<()> {
        let cfg = config::load_config(self.config.as_deref())?;
        let build_cfg = cfg.build.unwrap_or_default();

        if build_cfg.no_build.unwrap_or(false) {
            eprintln!("    Skipping build (no_build = true)");
            return Ok(());
        }

        let afl_cmd = build_cfg.afl.unwrap_or_else(default_afl_cmd);
        run_build_step("afl", &afl_cmd)?;

        if self.afl_cmplog {
            let cmplog_cmd = build_cfg.afl_cmplog.unwrap_or_else(default_afl_cmplog_cmd);
            run_build_step("afl (cmplog)", &cmplog_cmd)?;
        }

        let hongg_cmd = build_cfg.honggfuzz.unwrap_or_else(default_honggfuzz_cmd);
        run_build_step("honggfuzz", &hongg_cmd)?;

        let lf_cmd = build_cfg.libfuzzer.unwrap_or_else(default_libfuzzer_cmd);
        run_build_step("libfuzzer", &lf_cmd)?;

        Ok(())
    }
}

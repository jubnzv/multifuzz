use crate::Build;
use anyhow::{anyhow, Context, Result};
use std::{env, process};

impl Build {
    pub fn build(&self) -> Result<()> {
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        eprintln!("    Building afl");
        eprintln!(
            "    $ AFL_QUIET=1 {cargo} afl build --features=multifuzz/afl --target-dir=target/afl"
        );
        let status = process::Command::new(&cargo)
            .args([
                "afl",
                "build",
                "--features=multifuzz/afl",
                "--target-dir=target/afl",
            ])
            .env("AFL_QUIET", "1")
            .env("RUSTFLAGS", env::var("RUSTFLAGS").unwrap_or_default())
            .env("RUSTDOCFLAGS", env::var("RUSTDOCFLAGS").unwrap_or_default())
            .spawn()?
            .wait()
            .context("Error spawning afl build command")?;
        if !status.success() {
            return Err(anyhow!(
                "Error building afl fuzzer: exited with {:?}",
                status.code()
            ));
        }
        eprintln!("    Finished afl");

        if self.afl_cmplog {
            eprintln!("    Building afl (cmplog)");
            eprintln!("    $ AFL_QUIET=1 AFL_LLVM_CMPLOG=1 {cargo} afl build --features=multifuzz/afl --target-dir=target/afl-cmplog");
            let status = process::Command::new(&cargo)
                .args([
                    "afl",
                    "build",
                    "--features=multifuzz/afl",
                    "--target-dir=target/afl-cmplog",
                ])
                .env("AFL_QUIET", "1")
                .env("AFL_LLVM_CMPLOG", "1")
                .env("RUSTFLAGS", env::var("RUSTFLAGS").unwrap_or_default())
                .env("RUSTDOCFLAGS", env::var("RUSTDOCFLAGS").unwrap_or_default())
                .spawn()?
                .wait()
                .context("Error spawning afl cmplog build command")?;
            if !status.success() {
                return Err(anyhow!(
                    "Error building afl cmplog fuzzer: exited with {:?}",
                    status.code()
                ));
            }
            eprintln!("    Finished afl (cmplog)");
        }

        eprintln!("    Building honggfuzz");
        eprintln!("    $ CARGO_TARGET_DIR=./target/honggfuzz HFUZZ_BUILD_ARGS='--features=multifuzz/honggfuzz' {cargo} hfuzz build-debug");
        let status = process::Command::new(&cargo)
            .args(["hfuzz", "build-debug"])
            .env("CARGO_TARGET_DIR", "./target/honggfuzz")
            .env("HFUZZ_BUILD_ARGS", "--features=multifuzz/honggfuzz")
            .env("RUSTFLAGS", env::var("RUSTFLAGS").unwrap_or_default())
            .stdout(process::Stdio::piped())
            .spawn()?
            .wait()
            .context("Error spawning hfuzz build command")?;
        if !status.success() {
            return Err(anyhow!(
                "Error building honggfuzz fuzzer: exited with {:?}",
                status.code()
            ));
        }
        eprintln!("    Finished honggfuzz");

        let sancov_flags = [
            "-Cpasses=sancov-module",
            "-Cllvm-args=-sanitizer-coverage-level=4",
            "-Cllvm-args=-sanitizer-coverage-trace-compares",
            "-Cllvm-args=-sanitizer-coverage-inline-8bit-counters",
            "-Cllvm-args=-sanitizer-coverage-pc-table",
        ]
        .join(" ");

        let host = process::Command::new("rustc")
            .args(["-vV"])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("host:"))
                    .map(|l| l["host:".len()..].trim().to_string())
            })
            .unwrap_or_else(|| String::from("x86_64-unknown-linux-gnu"));

        let target_rustflags_key = format!(
            "CARGO_TARGET_{}_RUSTFLAGS",
            host.to_uppercase().replace('-', "_")
        );

        eprintln!("    Building libfuzzer");
        eprintln!("    $ {target_rustflags_key}='{sancov_flags}' {cargo} build --release --target={host} --features=multifuzz/libfuzzer --target-dir=target/libfuzzer");
        let status = process::Command::new(&cargo)
            .args([
                "build",
                "--release",
                &format!("--target={host}"),
                "--features=multifuzz/libfuzzer",
                "--target-dir=target/libfuzzer",
            ])
            .env(&target_rustflags_key, &sancov_flags)
            .spawn()?
            .wait()
            .context("Error spawning libfuzzer build command")?;
        if !status.success() {
            return Err(anyhow!(
                "Error building libfuzzer target: exited with {:?}",
                status.code()
            ));
        }
        eprintln!("    Finished libfuzzer");

        Ok(())
    }
}

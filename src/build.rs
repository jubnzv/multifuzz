use crate::Build;
use anyhow::{anyhow, Context, Result};
use std::{env, process};

impl Build {
    fn libfuzzer_active(&self) -> bool {
        !self.no_libfuzzer
    }

    pub fn build(&self) -> Result<()> {
        if self.no_afl && self.no_honggfuzz && !self.libfuzzer_active() {
            return Err(anyhow!("Pick at least one fuzzer"));
        }

        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        if !self.no_afl {
            eprintln!("    Building afl");

            let status = process::Command::new(&cargo)
                .args([
                    "afl",
                    "build",
                    "--features=multifuzz/afl",
                    "--target-dir=target/afl",
                ])
                .env("AFL_QUIET", "1")
                .env("AFL_LLVM_CMPLOG", "1")
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
        }

        if !self.no_honggfuzz {
            eprintln!("    Building honggfuzz");

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
        }

        if self.libfuzzer_active() {
            eprintln!("    Building libfuzzer (with SanitizerCoverage)");

            // SanitizerCoverage flags for coverage-guided fuzzing.
            // Use the target-specific env var so build scripts are not
            // instrumented (they can't link against sanitizer symbols).
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

            // CARGO_TARGET_<TRIPLE>_RUSTFLAGS only applies to target
            // crates, not build scripts or proc-macros.
            let target_rustflags_key = format!(
                "CARGO_TARGET_{}_RUSTFLAGS",
                host.to_uppercase().replace('-', "_")
            );

            // Pass --target explicitly so Cargo distinguishes host
            // (build scripts, proc-macros) from target crates. The
            // target-specific RUSTFLAGS then only apply to the target.
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
        }

        Ok(())
    }
}

# multifuzz example

A buggy calculator that takes 3 bytes `[a, b, op]` and crashes with a division
by zero when `op == '/'` and `b == 0`.

## Prerequisites

```sh
rustup default nightly
cargo install cargo-afl && cargo afl config --build
cargo install honggfuzz
```

## Seed corpus

```sh
cd example/
mkdir -p corpus && echo -n "AB+" > corpus/seed
```

## AFL++

```sh
cargo afl build --features multifuzz/afl --target-dir target/afl
cargo afl fuzz -i corpus -o output/afl target/afl/debug/example_crash
```

Crashes appear in `output/afl/default/crashes/`.

## honggfuzz

```sh
HFUZZ_BUILD_ARGS="--features multifuzz/honggfuzz" \
CARGO_TARGET_DIR=target/honggfuzz \
HFUZZ_WORKSPACE=output/honggfuzz \
HFUZZ_RUN_ARGS="--input corpus --exit_upon_crash" \
  cargo hfuzz run example_crash
```

Crashes appear in `output/honggfuzz/example_crash/`.

## libfuzzer

The orchestrator builds libfuzzer targets with SanitizerCoverage and `--release`
automatically. To build standalone:

```sh
TRIPLE=$(rustc -vV | awk '/^host:/{print $2}')
TARGET_KEY="CARGO_TARGET_$(echo $TRIPLE | tr '[:lower:]-' '[:upper:]_')_RUSTFLAGS"
export "$TARGET_KEY"="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 \
  -Cllvm-args=-sanitizer-coverage-trace-compares \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
  -Cllvm-args=-sanitizer-coverage-pc-table"
cargo build --release --target="$TRIPLE" --features multifuzz/libfuzzer --target-dir target/libfuzzer
./target/libfuzzer/$TRIPLE/release/example_crash corpus/
```

Crashes appear in the current directory (prefixed with `crash-`).

Using the orchestrator is easier — see below.

## multifuzz (orchestrated)

Build and run all three engines in parallel via the multifuzz CLI:

```sh
# Build all engines
cargo run --manifest-path ../Cargo.toml -- build

# Fuzz with 3 parallel jobs (AFL++ + honggfuzz + libfuzzer)
cargo run --manifest-path ../Cargo.toml -- fuzz example_crash -j 3 -i corpus -o output/multi
```

Crashes from all engines are collected in `output/multi/example_crash/crashes/`.

## Replay crashes

```sh
cargo run --manifest-path ../Cargo.toml -- run example_crash -i output/multi/example_crash/crashes/ -r
```

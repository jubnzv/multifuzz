# multifuzz

Multi-engine fuzzing orchestrator for Rust. Runs AFL++, honggfuzz, and libfuzzer in parallel with automatic corpus synchronization and crash collection.

![screenshot](./docs/img/screenshot.png)

## Usage

Write a fuzz harness using the `fuzz!` macro:

```rust
use multifuzz::fuzz;

fn main() {
    fuzz!(|data: &[u8]| {
        // test your code here
    });
}
```

Structured input via `Arbitrary` is also supported:

```rust
fuzz!(|data: MyStruct| {
    // data is deserialized automatically
});
```

## Prerequisites

Install the fuzzing toolchains:

```sh
cargo install cargo-afl
cargo install honggfuzz
```

## Installation

```sh
cargo install --path path/to/multifuzz
```

## Configuration

Campaigns are configured via a TOML file (`multifuzz.toml` by default, or `--config <path>`). See `multifuzz.toml.example` for a full reference.

```toml
[fuzz]
target = "my_target"
jobs = 4
corpus = "./corpus"
output = "./output"
timeout = 10
strategy = "parallel"       # "parallel", "afl-only", "hongg-only", "libfuzzer-only"
sync_interval = 60
dictionaries = ["./dict.dict"]

[fuzz.web]
enabled = true

# Per-worker AFL++ env overrides.
# Keys: "all", "even", "odd", "workerN".
[fuzz.afl.all.env]
AFL_SKIP_CPUFREQ = "1"

[fuzz.afl.worker2.env]
AFL_CUSTOM_MUTATOR_LIBRARY = "/path/to/mutator.so"
```

## CLI

```sh
# Build all fuzzer binaries (AFL++, honggfuzz, libfuzzer)
multifuzz build

# Run campaign (reads multifuzz.toml from cwd, or pass --config <path>)
multifuzz fuzz

# Replay a crash or directory of inputs
multifuzz run my_target -i output/my_target/crashes/ -r

# Add external inputs to a running fuzzing session
multifuzz add-corpus my_target -i interesting_inputs/ -r
```

## Web dashboard

An optional lightweight web UI (`[fuzz.web] enabled = true`) provides real-time monitoring, pause/resume controls, and worker scaling for running campaigns.

## How it works

Jobs are distributed across engines automatically. Corpus files are synchronized between engines periodically using hash-based deduplication. Crashes from all engines are collected into a unified `crashes/` directory.

## License

Apache-2.0

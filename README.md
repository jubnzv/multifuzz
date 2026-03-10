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

## CLI

From your harness crate directory:

```sh
# Build all fuzzer binaries (AFL++, honggfuzz, libfuzzer)
multifuzz build

# Run fuzzing with 3 parallel jobs across all engines
multifuzz fuzz my_target -j 3 -i corpus/ -o output/

# Replay a crash or directory of inputs
multifuzz run my_target -i output/my_target/crashes/ -r

# Add external inputs to a running fuzzing session
multifuzz add-corpus my_target -i interesting_inputs/ -r
```

### Options

| Flag | Description |
|---|---|
| `-j NUM` | Number of concurrent jobs (default: 1) |
| `-i DIR` | Corpus directory |
| `-o DIR` | Output directory (default: `./output`) |
| `-x FILE` | Dictionary file (repeatable) |
| `-t SECS` | Timeout per run |
| `--no-afl` | Disable AFL++ |
| `--no-honggfuzz` | Disable honggfuzz |
| `--no-libfuzzer` | Disable libfuzzer |
| `--max-input-size BYTES` | Maximum input size in bytes (default: 8192) |
| `--sync-interval MINS` | Corpus sync interval in minutes (default: 60) |

## How it works

Jobs are distributed across engines automatically. Corpus files are synchronized between engines periodically (default: every 60 minutes, configurable via `--sync-interval`) using hash-based deduplication. Crashes from all engines are collected into a unified `crashes/` directory.

## License

Apache-2.0

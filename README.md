# multifuzz

Multi-engine fuzzing orchestrator for Rust. Runs AFL++, honggfuzz, and libfuzzer in parallel with automatic corpus synchronization and crash collection.

**Features:**
1. **Unified Rust API** to set up a harness for all three fuzzers (see below)
2. **Corpus synchronization** between engines with dynamic input handling. Leverages built-in fuzzer features for synchronization.
3. **Single configuration file** for all fuzzer instances – everything is 100% explicit; the orchestrator does not introduce any implicit configuration options or environment variables
4. **No overhead**: no UI, no fancy extra tools, etc.

Overall, it simplifies Rust harness implementation and replaces Makefiles/custom scripts for running complex fuzzing campaigns.

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
sync_interval = 60  # min
dictionaries = ["./dict.dict"]

# Per-worker AFL++ configuration. No hidden defaults — everything explicit.
# [fuzz.afl.all.env] sets base env vars for every AFL worker.
# [fuzz.afl.workerN]  overrides for specific worker N (0=main, 1+=secondary).
# Worker env = all.env + workerN.env merged (worker wins on conflict).
[fuzz.afl.all.env]
AFL_AUTORESUME = "1"
AFL_FAST_CAL = "1"
AFL_FORCE_UI = "1"
AFL_IGNORE_UNKNOWN_ENVS = "1"
AFL_CMPLOG_ONLY_NEW = "1"
AFL_DISABLE_TRIM = "1"
AFL_NO_WARN_INSTABILITY = "1"
AFL_FUZZER_STATS_UPDATE_INTERVAL = "10"
AFL_IGNORE_SEED_PROBLEMS = "1"

[fuzz.afl.worker0.env]
AFL_FINAL_SYNC = "1"

[fuzz.afl.worker2.env]
AFL_CUSTOM_MUTATOR_LIBRARY = "/path/to/mutator.so"
```

## CLI

```sh
# Build all the required fuzzer binaries
multifuzz build

# Run campaign
multifuzz fuzz

# Replay a crash or directory of inputs
multifuzz run my_target -i output/my_target/afl/master/crashes/ -r
```

Crashes are written by each engine to its own directory. Locations are printed at startup:
- AFL: `{output}/{target}/afl/*/crashes/`
- honggfuzz: `{output}/{target}/honggfuzz/{target}/`
- libfuzzer: `{output}/{target}/libfuzzer/crashes/`

## License

Apache-2.0

# multifuzz

Multi-engine fuzzing orchestrator for Rust. Runs AFL++, honggfuzz, and libfuzzer in parallel with automatic corpus synchronization.

**Features:**
1. **Unified Rust API** to set up a harness for all three fuzzers (see below)
2. **Corpus synchronization** between engines with dynamic input handling. Leverages built-in fuzzer features for synchronization.
3. **Single configuration file** for all fuzzer instances — everything is 100% explicit; the orchestrator does not introduce any implicit configuration options or environment variables
4. **No overhead**: no UI, no extra tools

Simplifies Rust harness implementation and replaces Makefiles/custom scripts for running complex fuzzing campaigns.

## Installation

Install the fuzzing toolchains you are going to use:

```sh
cargo install cargo-afl
cargo install honggfuzz
```

Then clone the repository and install the `multifuzz` binary:

```sh
git clone https://github.com/jubnzv/multifuzz
cd multifuzz
cargo install --path .
```

## Usage

### 1. Create the fuzzing harness

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

### 2. Write a configuration file

Campaigns are configured via a TOML file (`multifuzz.toml` by default, or `--config <path>`). See `multifuzz.toml.example` for a full reference.

```toml
[fuzz]
target = "my_target"
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

### 3. Use CLI to start and manage the campaign

```sh
# Build all fuzzer binaries
multifuzz build

# Run the campaign
multifuzz fuzz

# List running workers
multifuzz worker ps

# Kill a specific worker
multifuzz worker kill slave1

# Start a stopped worker
multifuzz worker start slave1

# Clean up artifacts (lockfile, temp files, output)
multifuzz clean

# Replay a crash or directory of inputs
multifuzz run my_target -i output/my_target/afl/master/crashes/ -r
```

## License

Apache-2.0

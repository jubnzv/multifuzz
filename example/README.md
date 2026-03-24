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

## Running with multifuzz

Build all engines and fuzz using the config in `multifuzz.toml`:

```sh
cd example/

# Build
cargo run --manifest-path ../Cargo.toml -- build

# Fuzz (reads multifuzz.toml from cwd)
cargo run --manifest-path ../Cargo.toml -- fuzz
```

Crashes from all engines are collected in `output/multi/example_crash/crashes/`.

## Replay crashes

```sh
cargo run --manifest-path ../Cargo.toml -- run example_crash -i output/multi/example_crash/crashes/ -r
```

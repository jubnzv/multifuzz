#!/bin/bash
set -euo pipefail

echo "=== rustfmt ==="
cargo fmt --all -- --check

echo "=== clippy (all targets) ==="
cargo clippy --all-targets -- -D warnings

echo "=== clippy (libfuzzer only) ==="
cargo clippy --no-default-features --features libfuzzer -- -D warnings

echo "=== all checks passed ==="

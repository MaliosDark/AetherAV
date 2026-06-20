#!/usr/bin/env bash
# Best-effort REPRODUCIBLE release build: anyone can rebuild from source and get
# the same binary hash, proving the published binary matches the public code
# (defends against a backdoored/tampered official build).
#
# For bit-for-bit reproducibility, build in the SAME environment (pin the Rust
# toolchain via rustup, same target). The flags below remove the main sources of
# nondeterminism: absolute paths, build timestamps, and incremental artifacts.
set -euo pipefail
cd "$(dirname "$0")/.."

# Deterministic timestamp from the last git commit (fallback: fixed epoch).
export SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct 2>/dev/null || echo 1700000000)"
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-C remap-path-prefix=$PWD=/build -C debuginfo=0 ${RUSTFLAGS:-}"
export LC_ALL=C TZ=UTC

echo ">> toolchain: $(rustc --version)"
echo ">> SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
cargo build --release --locked -p aether-cli

echo ">> reproducible build hash:"
sha256sum target/release/aether
echo ">> rebuild on a matching toolchain and compare this hash to the published SHA256SUMS."

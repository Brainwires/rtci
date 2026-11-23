#!/usr/bin/env bash
# Builds str0m-peer from its own Cargo.lock (--locked): str0m 0.26.0 with the rust-crypto
# backend. The crate is a workspace of its own, outside the engine's.
set -euo pipefail
OUT=$1
HERE=$(cd "$(dirname "$0")" && pwd)
T=${CARGO_TARGET_DIR:-/target}/peers
cargo build --release --locked --manifest-path "$HERE/Cargo.toml" --target-dir "$T"
cp "$T/release/str0m-peer" "$OUT/str0m-peer"

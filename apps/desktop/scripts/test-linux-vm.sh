#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

(cd desktop-shell && npm ci && npm run build)
cargo fmt --manifest-path desktop-shell/src-tauri/Cargo.toml --all --check
cargo clippy --manifest-path desktop-shell/src-tauri/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path desktop-shell/src-tauri/Cargo.toml --locked
scripts/build-linux.sh

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cargo >/dev/null || { echo 'Rust/Cargo is required (add ~/.cargo/bin to PATH).' >&2; exit 1; }
pkg-config --exists gtk+-3.0 webkit2gtk-4.1 || { echo 'Install GTK 3 and WebKitGTK 4.1 development packages first.' >&2; exit 1; }
cargo build --release --locked -p raiun-agent -p raiun-cli
(cd desktop-shell && npm ci && npm run build)
cargo build --manifest-path desktop-shell/src-tauri/Cargo.toml --release --locked
bundle=target/raiun-desktop-linux
mkdir -p "$bundle"
install -m755 target/release/raiun-agent target/release/raiun "$bundle/"
install -m755 desktop-shell/src-tauri/target/release/raiun-desktop-shell "$bundle/raiun-desktop"
install -m644 desktop-shell/src-tauri/icons/icon.png "$bundle/raiun-desktop.png"
install -m755 packaging/linux/install.sh "$bundle/install.sh"
cp README.md "$bundle/README.md"
archive="target/raiun-desktop-linux-$(uname -m).tar.gz"
tar -czf "$archive" -C target raiun-desktop-linux
printf 'Built %s\n' "$archive"

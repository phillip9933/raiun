#!/usr/bin/env bash
# No Node, Tauri, GTK, WebKit, display, keyring, or service registration.
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
[[ "$(uname -s)" == Linux ]] || { echo 'This candidate currently targets Linux.' >&2; exit 1; }
cargo build --release --locked -p raiun-agent -p raiun-cli
target_dir="${CARGO_TARGET_DIR:-target}"
bundle_parent="${RAIUN_HEADLESS_OUTPUT_DIR:-$target_dir}"
mkdir -p -- "$bundle_parent"
bundle="$bundle_parent/raiun-headless-linux"
[[ ! -e "$bundle" ]] || { echo 'Bundle directory already exists; preserve it or choose a fresh CARGO_TARGET_DIR.' >&2; exit 1; }
mkdir -p -- "$bundle"
install -m755 "$target_dir/release/raiun" "$target_dir/release/raiun-agent" "$bundle/"
install -m755 packaging/headless-linux/install.sh "$bundle/install.sh"
install -m644 docs/HEADLESS.md "$bundle/README.md"
for document in HEADLESS.md HEADLESS-WINDOWS.md HEADLESS-STARTUP.md HEADLESS-ACCEPTANCE.md HEADLESS-FUSE-TEST.md; do
  install -m644 "docs/$document" "$bundle/"
done
install -m755 scripts/test-headless-fuse-linux.py "$bundle/"
for document in LICENSE NOTICE THIRD-PARTY-NOTICES.md PRIVACY.md; do
  install -m644 "$document" "$bundle/"
done
cp -R legal "$bundle/legal"
(cd -- "$bundle" && sha256sum raiun raiun-agent > SHA256SUMS)
archive="$bundle_parent/raiun-headless-linux-$(uname -m).tar.gz"
[[ ! -e "$archive" ]] || { echo 'Archive already exists; preserved without replacement.' >&2; exit 1; }
tar -czf "$archive" -C "$bundle_parent" raiun-headless-linux
printf 'Built local headless candidate: %s\n' "$archive"

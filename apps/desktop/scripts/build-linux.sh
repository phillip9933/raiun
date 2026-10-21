#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cargo >/dev/null || { echo 'Rust/Cargo is required (add ~/.cargo/bin to PATH).' >&2; exit 1; }
command -v sha256sum >/dev/null || { echo 'sha256sum is required to verify the Linux bundle.' >&2; exit 1; }
pkg-config --exists gtk+-3.0 webkit2gtk-4.1 || { echo 'Install GTK 3 and WebKitGTK 4.1 development packages first.' >&2; exit 1; }
cargo build --release --locked -p raiun-agent -p raiun-cli
(cd desktop-shell && npm ci && npm run build)
cargo build --manifest-path desktop-shell/src-tauri/Cargo.toml --release --locked --features custom-protocol
bundle=target/raiun-desktop-linux
mkdir -p "$bundle"
install -m755 target/release/raiun-agent target/release/raiun "$bundle/"
install -m755 desktop-shell/src-tauri/target/release/raiun-desktop-shell "$bundle/raiun-desktop"
install -m644 desktop-shell/src-tauri/icons/icon.png "$bundle/raiun-desktop.png"
install -m755 packaging/linux/install.sh "$bundle/install.sh"
cp README.md "$bundle/README.md"
for document in LICENSE NOTICE THIRD-PARTY-NOTICES.md PRIVACY.md CHANGELOG.md; do
  install -m644 "$document" "$bundle/$document"
done
test -f legal/dependency-inventory.json || { echo 'Generate the reviewed runtime dependency notices before packaging.' >&2; exit 1; }
cp -R legal "$bundle/legal"
mkdir -p "$bundle/docs"
for document in OFFLINE-CACHE.md ENCRYPTED-SYNC.md ENCRYPTION-INTEROP.md VAULT-SESSIONS.md VAULT-DIRECTORIES.md VAULT-WRITE-CONTRACT.md; do
  install -m644 "docs/$document" "$bundle/docs/$document"
done

build_timestamp_utc="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
git_commit=unknown
dirty=true
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  candidate_commit="$(git rev-parse HEAD 2>/dev/null || true)"
  if [[ "$candidate_commit" =~ ^[0-9a-f]{40,64}$ ]]; then
    git_commit="$candidate_commit"
  fi
  if git_status="$(git status --porcelain --untracked-files=normal 2>/dev/null)"; then
    if [[ -n "$git_status" ]]; then
      dirty=true
    else
      dirty=false
    fi
  else
    dirty=true
  fi
fi

# Unsigned hashes detect payload corruption; they do not authenticate a build.
manifest="$bundle/manifest.txt"
{
  printf 'format=raiun-linux-bundle-v1\n'
  printf 'build_timestamp_utc=%s\n' "$build_timestamp_utc"
  printf 'git_commit=%s\n' "$git_commit"
  printf 'dirty=%s\n' "$dirty"
  for file in raiun-agent raiun raiun-desktop raiun-desktop.png; do
    read -r digest _ < <(sha256sum -- "$bundle/$file")
    printf 'sha256.%s=%s\n' "$file" "$digest"
  done
} > "$manifest"
chmod 644 "$manifest"
archive="target/raiun-desktop-linux-$(uname -m).tar.gz"
tar -czf "$archive" -C target raiun-desktop-linux
printf 'Built %s\n' "$archive"

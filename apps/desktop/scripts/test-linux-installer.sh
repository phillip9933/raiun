#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

command -v sha256sum >/dev/null || { echo 'sha256sum is required.' >&2; exit 1; }
test_root="$(mktemp -d)"
cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT

# Presence is checked, but this synthetic installer test must never open a dialog.
mkdir "$test_root/test-bin"
printf '#!/bin/sh\nexit 99\n' > "$test_root/test-bin/zenity"
chmod 755 "$test_root/test-bin/zenity"
export PATH="$test_root/test-bin:$PATH"

bundle="$test_root/bundle"
data_home="$test_root/xdg-data"
config_home="$test_root/xdg-config"
mkdir -p "$bundle" "$config_home"
for file in raiun-agent raiun raiun-desktop; do
  printf 'synthetic executable %s\n' "$file" > "$bundle/$file"
done
printf 'synthetic icon\n' > "$bundle/raiun-desktop.png"
cp packaging/linux/install.sh "$bundle/install.sh"
chmod 755 "$bundle/install.sh"

write_manifest() {
  {
    printf 'format=raiun-linux-bundle-v1\n'
    printf 'build_timestamp_utc=2026-10-10T01:23:45Z\n'
    printf 'git_commit=unknown\n'
    printf 'dirty=true\n'
    for file in raiun-agent raiun raiun-desktop raiun-desktop.png; do
      read -r digest _ < <(sha256sum -- "$bundle/$file")
      printf 'sha256.%s=%s\n' "$file" "$digest"
    done
  } > "$bundle/manifest.txt"
}

write_manifest
(cd "$bundle" && XDG_DATA_HOME="$data_home" XDG_CONFIG_HOME="$config_home" ./install.sh)
install_root="$data_home/raiun-desktop"
desktop_file="$data_home/applications/raiun-desktop.desktop"
for file in raiun-agent raiun raiun-desktop raiun-desktop.png manifest.txt; do
  cmp "$bundle/$file" "$install_root/$file"
done
test -f "$desktop_file"
grep -Fq 'Exec="'"$install_root"'/raiun-desktop" %u' "$desktop_file"
grep -Fq 'MimeType=x-scheme-handler/raiun;' "$desktop_file"

assert_previous_install_unchanged() {
  for file in raiun-agent raiun raiun-desktop raiun-desktop.png manifest.txt; do
    cmp "$test_root/previous/$file" "$install_root/$file"
  done
  cmp "$test_root/previous/raiun-desktop.desktop" "$desktop_file"
}
mkdir -p "$test_root/previous"
for file in raiun-agent raiun raiun-desktop raiun-desktop.png manifest.txt; do
  cp "$install_root/$file" "$test_root/previous/$file"
done
cp "$desktop_file" "$test_root/previous/raiun-desktop.desktop"

expect_rejected_without_replacement() {
  local reason="$1"
  if (cd "$bundle" && XDG_DATA_HOME="$data_home" XDG_CONFIG_HOME="$config_home" ./install.sh >"$test_root/stdout" 2>"$test_root/stderr"); then
    echo "Installer accepted $reason." >&2
    exit 1
  fi
  assert_previous_install_unchanged
}

# A missing dialog helper must preserve the previous installation and avoid
# creating destination directories, even when all bundle hashes are valid.
mkdir "$test_root/no-dialog-bin"
ln -s "$(command -v sha256sum)" "$test_root/no-dialog-bin/sha256sum"
ln -s "$(command -v dirname)" "$test_root/no-dialog-bin/dirname"
if (cd "$bundle" && PATH="$test_root/no-dialog-bin" XDG_DATA_HOME="$data_home" /bin/bash ./install.sh >"$test_root/stdout" 2>"$test_root/stderr"); then
  echo 'Installer accepted a missing confirmation-dialog helper.' >&2
  exit 1
fi
grep -Fq 'Zenity is required for confirmation dialogs.' "$test_root/stderr"
assert_previous_install_unchanged
if (cd "$bundle" && PATH="$test_root/no-dialog-bin" XDG_DATA_HOME="$test_root/no-dialog-destination" /bin/bash ./install.sh >"$test_root/stdout" 2>"$test_root/stderr"); then
  echo 'Fresh installer accepted a missing confirmation-dialog helper.' >&2
  exit 1
fi
test ! -e "$test_root/no-dialog-destination"

printf 'tampered executable\n' >> "$bundle/raiun-agent"
expect_rejected_without_replacement 'a payload with a mismatched digest'
write_manifest

printf 'format=raiun-linux-bundle-v1\n' >> "$bundle/manifest.txt"
expect_rejected_without_replacement 'a manifest with a duplicate key'
write_manifest

printf 'sha256.../outside=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' >> "$bundle/manifest.txt"
expect_rejected_without_replacement 'a manifest with an unexpected path-like field'

write_manifest
grep -v '^sha256.raiun=' "$bundle/manifest.txt" > "$test_root/manifest-missing-hash.txt"
mv "$test_root/manifest-missing-hash.txt" "$bundle/manifest.txt"
expect_rejected_without_replacement 'a manifest missing a required payload digest'

head -c 4097 /dev/zero > "$bundle/manifest.txt"
expect_rejected_without_replacement 'an oversized manifest'

mv "$bundle/raiun" "$bundle/raiun.regular"
printf 'outside synthetic file\n' > "$test_root/outside"
ln -s "$test_root/outside" "$bundle/raiun"
write_manifest
expect_rejected_without_replacement 'a symlink payload'
rm "$bundle/raiun"
mv "$bundle/raiun.regular" "$bundle/raiun"

write_manifest
mv "$bundle/raiun-desktop.png" "$bundle/raiun-desktop.png.missing"
expect_rejected_without_replacement 'a missing payload'
mv "$bundle/raiun-desktop.png.missing" "$bundle/raiun-desktop.png"

write_manifest
mv "$bundle/manifest.txt" "$test_root/saved-manifest.txt"
expect_rejected_without_replacement 'a missing manifest'
cp "$test_root/saved-manifest.txt" "$bundle/manifest.txt"

mv "$bundle/manifest.txt" "$test_root/saved-manifest-symlink.txt"
ln -s "$test_root/saved-manifest-symlink.txt" "$bundle/manifest.txt"
expect_rejected_without_replacement 'a symlink manifest'
rm "$bundle/manifest.txt"
cp "$test_root/saved-manifest-symlink.txt" "$bundle/manifest.txt"

printf 'Installer tests passed (synthetic bundle only).\n'

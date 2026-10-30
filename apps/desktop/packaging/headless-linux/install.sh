#!/usr/bin/env bash
# Installs a headless candidate into a NEW directory; never starts the agent.
set -euo pipefail
source_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
prefix="${HOME:?HOME must be set}/.local/lib/raiun-headless"
if [[ "$#" -eq 2 && "$1" == --prefix ]]; then
  prefix="$2"
elif [[ "$#" -ne 0 ]]; then
  echo 'Usage: install.sh [--prefix /absolute/new/directory]' >&2
  exit 2
fi
[[ "$prefix" == /* ]] || { echo 'The install prefix must be absolute.' >&2; exit 2; }
[[ ! -e "$prefix" && ! -L "$prefix" ]] || { echo 'Choose a new install directory; existing installations are preserved.' >&2; exit 1; }
# Require exactly these two payload entries, without interpreting arbitrary paths.
mapfile -t hashes < "$source_dir/SHA256SUMS"
[[ "${#hashes[@]}" -eq 2 ]] || { echo 'Invalid headless bundle manifest.' >&2; exit 1; }
for index in 0 1; do
  name=raiun
  [[ "$index" -eq 0 ]] || name=raiun-agent
  [[ "${hashes[$index]}" =~ ^[0-9a-f]{64}\ \ $name$ ]] || { echo 'Invalid headless bundle hash entry.' >&2; exit 1; }
  [[ -f "$source_dir/$name" && ! -L "$source_dir/$name" ]] || { echo 'Invalid headless payload.' >&2; exit 1; }
  actual="$(sha256sum -- "$source_dir/$name")"
  [[ "${actual:0:64}" == "${hashes[$index]:0:64}" ]] || { echo 'Headless payload checksum mismatch.' >&2; exit 1; }
done
umask 077
mkdir -p -- "$(dirname -- "$prefix")"
mkdir -- "$prefix"
install -m755 -- "$source_dir/raiun" "$source_dir/raiun-agent" "$prefix/"
for name in README.md LICENSE NOTICE THIRD-PARTY-NOTICES.md PRIVACY.md SHA256SUMS; do
  install -m644 -- "$source_dir/$name" "$prefix/"
done
for document in HEADLESS.md HEADLESS-WINDOWS.md HEADLESS-STARTUP.md; do
  if [[ -f "$source_dir/$document" && ! -L "$source_dir/$document" ]]; then
    install -m644 -- "$source_dir/$document" "$prefix/"
  fi
done
if [[ -d "$source_dir/legal" ]]; then cp -R -- "$source_dir/legal" "$prefix/"; fi
printf 'Installed headless candidate to %s\nRun: %q drive --help\n' "$prefix" "$prefix/raiun"
printf 'After configuring remembered login and auto_mount, preview boot startup:\n  %q --config /ABS/config.json drive --state-dir /ABS/state startup enable --dry-run\n' "$prefix/raiun"
printf 'Run the same command without --dry-run only when ready to enable/start the user service. Installation itself changed no startup settings.\n'

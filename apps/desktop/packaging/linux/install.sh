#!/usr/bin/env bash
# User-scoped installation; running the app and enabling autostart remain explicit.
set -euo pipefail
cd "$(dirname "$0")"
command -v sha256sum >/dev/null || { echo 'sha256sum is required to verify this bundle.' >&2; exit 1; }
# The xdg-portal dialog backend uses Zenity for confirmation messages.
# Refuse before replacing an installation if those dialogs cannot be opened.
command -v zenity >/dev/null || { echo 'Zenity is required for confirmation dialogs. Install the zenity system package, then run this installer again.' >&2; exit 1; }

# This unsigned manifest detects accidental bundle corruption; it does not
# authenticate the publisher or establish artifact provenance.
manifest=manifest.txt
if [[ -L "$manifest" || ! -f "$manifest" ]]; then
  echo 'Bundle manifest is missing or is not a regular file.' >&2
  exit 1
fi
manifest_bytes="$(wc -c < "$manifest")"
manifest_bytes="${manifest_bytes//[[:space:]]/}"
if [[ ! "$manifest_bytes" =~ ^[0-9]+$ || "$manifest_bytes" -gt 4096 ]]; then
  echo 'Bundle manifest exceeds its 4 KiB limit.' >&2
  exit 1
fi

declare -A manifest_fields=()
while IFS= read -r line || [[ -n "$line" ]]; do
  if [[ "$line" != *=* ]]; then
    echo 'Bundle manifest has an invalid line.' >&2
    exit 1
  fi
  key="${line%%=*}"
  value="${line#*=}"
  case "$key" in
    format|build_timestamp_utc|git_commit|dirty|sha256.raiun-agent|sha256.raiun|sha256.raiun-desktop|sha256.raiun-desktop.png) ;;
    *) echo 'Bundle manifest contains an unexpected field.' >&2; exit 1;;
  esac
  if [[ -n "${manifest_fields[$key]+present}" ]]; then
    echo 'Bundle manifest contains a duplicate field.' >&2
    exit 1
  fi
  manifest_fields["$key"]="$value"
done < "$manifest"

if [[ "${#manifest_fields[@]}" -ne 8
  || "${manifest_fields[format]-}" != 'raiun-linux-bundle-v1'
  || ! "${manifest_fields[build_timestamp_utc]-}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$
  || ! "${manifest_fields[git_commit]-}" =~ ^(unknown|[0-9a-f]{40,64})$
  || ! "${manifest_fields[dirty]-}" =~ ^(true|false)$ ]]; then
  echo 'Bundle manifest is incomplete or invalid.' >&2
  exit 1
fi

payload=(raiun-agent raiun raiun-desktop raiun-desktop.png)
for file in "${payload[@]}"; do
  if [[ -L "$file" || ! -f "$file" ]]; then
    echo "Bundle payload is missing or is not a regular file: $file" >&2
    exit 1
  fi
  expected="${manifest_fields[sha256.$file]-}"
  if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
    echo 'Bundle manifest contains an invalid payload digest.' >&2
    exit 1
  fi
  read -r actual _ < <(sha256sum -- "$file")
  if [[ "$actual" != "$expected" ]]; then
    echo "Bundle payload hash mismatch: $file" >&2
    exit 1
  fi
done

install_root="${XDG_DATA_HOME:-$HOME/.local/share}/raiun-desktop"
applications="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
case "$install_root" in *$'\n'*|*'"'*|*'%'*|*'`'*|*'$'*|*'\'*) echo 'Unsupported special character in installation path' >&2; exit 1;; esac
mkdir -p "$install_root" "$applications"
stage_dir="$(mktemp -d "$install_root/.install.XXXXXXXX")"
cleanup() {
  rm -rf -- "$stage_dir"
}
trap cleanup EXIT
for executable in raiun-agent raiun raiun-desktop; do
  install -m755 "$executable" "$stage_dir/$executable"
done
install -m644 raiun-desktop.png "$stage_dir/raiun-desktop.png"
{
  printf 'format=%s\n' "${manifest_fields[format]}"
  printf 'build_timestamp_utc=%s\n' "${manifest_fields[build_timestamp_utc]}"
  printf 'git_commit=%s\n' "${manifest_fields[git_commit]}"
  printf 'dirty=%s\n' "${manifest_fields[dirty]}"
  for file in "${payload[@]}"; do
    printf 'sha256.%s=%s\n' "$file" "${manifest_fields[sha256.$file]}"
  done
} > "$stage_dir/manifest.txt"
for file in "${payload[@]}"; do
  expected="${manifest_fields[sha256.$file]}"
  read -r staged_digest _ < <(sha256sum -- "$stage_dir/$file")
  if [[ "$staged_digest" != "$expected" ]]; then
    echo "Staged payload hash mismatch: $file" >&2
    exit 1
  fi
done
for executable in raiun-agent raiun raiun-desktop; do
  mv -f "$stage_dir/$executable" "$install_root/$executable"
done
mv -f "$stage_dir/raiun-desktop.png" "$install_root/raiun-desktop.png"
mv -f "$stage_dir/manifest.txt" "$install_root/manifest.txt"
cat > "$applications/raiun-desktop.desktop" <<ENTRY
[Desktop Entry]
Type=Application
Name=Raiun Desktop
Comment=OpenCloud folder sync and cloud drive
Exec="$install_root/raiun-desktop" %u
Icon=$install_root/raiun-desktop.png
Terminal=false
Categories=Network;FileTransfer;
MimeType=x-scheme-handler/raiun;
ENTRY
if command -v xdg-mime >/dev/null 2>&1; then
  xdg-mime default raiun-desktop.desktop x-scheme-handler/raiun >/dev/null 2>&1 \
    || printf 'Could not set the raiun:// link handler automatically; choose Raiun Desktop in your desktop settings.\n' >&2
fi
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$applications" >/dev/null 2>&1 || true
fi
printf 'Installed to %s. Open Raiun Desktop from your application launcher.\n' "$install_root"

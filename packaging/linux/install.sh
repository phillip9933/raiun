#!/usr/bin/env bash
# User-scoped installation; running the app and enabling autostart remain explicit.
set -euo pipefail
cd "$(dirname "$0")"
install_root="${XDG_DATA_HOME:-$HOME/.local/share}/raiun-desktop"
applications="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
case "$install_root" in *$'\n'*|*'"'*|*'%'*|*'`'*|*'$'*|*'\'*) echo 'Unsupported special character in installation path' >&2; exit 1;; esac
mkdir -p "$install_root" "$applications"
for executable in raiun-agent raiun raiun-desktop; do
  install -m755 "$executable" "$install_root/$executable.new"
  mv -f "$install_root/$executable.new" "$install_root/$executable"
done
install -m644 raiun-desktop.png "$install_root/raiun-desktop.png"
cat > "$applications/raiun-desktop.desktop" <<ENTRY
[Desktop Entry]
Type=Application
Name=Raiun Desktop
Comment=OpenCloud folder sync and cloud drive
Exec="$install_root/raiun-desktop"
Icon=$install_root/raiun-desktop.png
Terminal=false
Categories=Network;FileTransfer;
ENTRY
printf 'Installed to %s. Open Raiun Desktop from your application launcher.\n' "$install_root"

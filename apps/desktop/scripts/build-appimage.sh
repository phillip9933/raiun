#!/usr/bin/env bash
# Ubuntu 24.04 x86_64 companion build; does not replace the tarball installer.
set -euo pipefail
trap 'echo "AppImage packaging failed at line $LINENO: $BASH_COMMAND" >&2' ERR
cd "$(dirname "$0")/.."
[[ $# == 0 && $(uname -m) == x86_64 ]]
. /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]] || { echo 'Build on Ubuntu 24.04.' >&2; exit 1; }
root=$PWD
out="$root/target/appimage"
work="$root/target/appimage-work"
mkdir -p "$out" "$work"
for tool in cargo npm python3 curl sha256sum desktop-file-edit readelf; do command -v "$tool" >/dev/null; done
cargo build --release --locked -p raiun-agent -p raiun-cli
python3 - "$root" "$work/tauri-appimage.json" <<'PY'
import json,sys
from pathlib import Path
r=Path(sys.argv[1]); files={}
for n in ('raiun-agent','raiun'): files['/usr/bin/'+n]=str(r/'target/release'/n)
for n in ('secret-tool','zenity'): files['/usr/bin/'+n]='/usr/bin/'+n
for n in ('LICENSE','NOTICE','THIRD-PARTY-NOTICES.md','PRIVACY.md','CHANGELOG.md','README.md','legal'):
 files['/usr/share/doc/raiun-desktop/'+n]=str(r/n)
Path(sys.argv[2]).write_text(json.dumps({'mainBinaryName':'raiun-desktop','bundle':{'targets':['appimage'],'linux':{'appimage':{'files':files}}}}))
PY
(cd desktop-shell && npm ci && npm run tauri -- build --bundles appimage --features custom-protocol --config "$work/tauri-appimage.json")
appdir=$(find desktop-shell/src-tauri/target/release/bundle/appimage -maxdepth 1 -type d -name '*.AppDir' -print)
[[ -n "$appdir" && "$appdir" != *$'\n'* ]]
appdir=$(realpath "$appdir")
# Explicitly deploy both helper dependency closures (Zenity uses GTK4).
linuxdeploy=$(find "${XDG_CACHE_HOME:-$HOME/.cache}/tauri" -type f -name 'linuxdeploy-07333c6-x86_64.AppImage' -print -quit)
[[ -n "$linuxdeploy" ]]
APPIMAGE_EXTRACT_AND_RUN=1 "$linuxdeploy" --appimage-extract-and-run --appdir "$appdir" --executable "$appdir/usr/bin/zenity" --executable "$appdir/usr/bin/secret-tool"
mv "$appdir/AppRun" "$appdir/AppRun.tauri"
install -m755 packaging/linux/AppRun "$appdir/AppRun"
for n in xdg-open fusermount3; do install -m755 packaging/linux/appimage-host-helper "$appdir/usr/bin/$n"; done
for desktop in "$appdir"/*.desktop; do desktop-file-edit --set-key=Exec --set-value='raiun-desktop %u' --set-key=MimeType --set-value='x-scheme-handler/raiun;' "$desktop"; done
fetch() { local url=$1 dest=$2 hash=$3; curl --fail --location --retry 0 "$url" -o "$dest"; echo "$hash  $dest" | sha256sum -c -; }
fetch https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage "$work/appimagetool" ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0
fetch https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64 "$work/runtime-x86_64" 2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d
chmod 755 "$work/appimagetool"
# These inputs are generated before repacking, so notices are inside the image.
python3 - "$appdir" "$work" <<'PY'
import hashlib,json,sys
from pathlib import Path
r,w=map(Path,sys.argv[1:]); rows=[]
for n in ('raiun-desktop','raiun-agent','raiun'):
 p=r/'usr/bin'/n; b=p.read_bytes(); rows.append({'path':str(p.relative_to(r)),'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b)})
(w/'first-party.json').write_text(json.dumps({'files':rows},indent=2)+'\n')
PY
python3 - "$root" "$appdir" "$work" <<'PYMETA'
import hashlib,json,shutil,sys
from pathlib import Path
root,app,work=map(Path,sys.argv[1:]); src=root/'packaging/linux/appimage-licenses'
dest=app/'usr/share/doc/raiun-desktop/appimage-tools'; shutil.copytree(src,dest)
def descriptor(p,logical,origin,url,licenses):
 b=p.read_bytes()
 return {'path':logical,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'origin':origin,'source_url':url,'license_files':[{'path':str(dest/n),'bytes':(dest/n).stat().st_size,'sha256':hashlib.sha256((dest/n).read_bytes()).hexdigest()} for n in licenses]}
alllicenses=[p.name for p in src.iterdir() if p.name!='sources.json']
meta={'files':[descriptor(app/'AppRun.tauri','AppRun.tauri','linuxdeploy 07333c6 generated hook wrapper','https://github.com/linuxdeploy/linuxdeploy/tree/07333c6',['linuxdeploy-LICENSE']),descriptor(app/'AppRun.wrapped','AppRun.wrapped','Tauri upstream AppRun (AppImageKit)','https://github.com/tauri-apps/binary-releases/releases/tag/apprun-old',['AppImageKit-LICENSE'])],
'artifacts':[descriptor(work/'runtime-x86_64',str(work/'runtime-x86_64'),'AppImage type2-runtime 20251108','https://github.com/AppImage/type2-runtime/releases/tag/20251108',alllicenses),descriptor(work/'appimagetool',str(work/'appimagetool'),'appimagetool 1.9.1 build tool','https://github.com/AppImage/appimagetool/releases/tag/1.9.1',['appimagetool-LICENSE'])]}
(work/'runtime-metadata.json').write_text(json.dumps(meta,indent=2)+'\n')
PYMETA
# Runtime/tool metadata includes upstream redistribution licenses. Keep this
# separate from native dpkg origins; the collector refuses unaccounted ELF files.
python3 scripts/collect-appimage-notices.py --appdir "$appdir" --output "$appdir/usr/share/doc/raiun-desktop/native" --first-party-manifest "$work/first-party.json" --runtime-metadata "$work/runtime-metadata.json"
version=$(python3 -c 'import json; print(json.load(open("desktop-shell/package.json"))["version"])')
artifact="$out/raiun-desktop-${version}-linux-x86_64.AppImage"
ARCH=x86_64 VERSION="$version" "$work/appimagetool" --appimage-extract-and-run --runtime-file "$work/runtime-x86_64" "$appdir" "$artifact"
python3 - "$appdir" "$artifact" "$out" <<'PYAUDIT'
import hashlib,json,re,subprocess,sys
from pathlib import Path
app,artifact,out=map(Path,sys.argv[1:]); rows=[]
for p in sorted(app.rglob('*')):
 if not p.is_file() or p.is_symlink(): continue
 b=p.read_bytes()
 if b[:4]!=b'\x7fELF': continue
 text=subprocess.check_output(['readelf','--version-info',str(p)],text=True,stderr=subprocess.STDOUT)
 versions=sorted(set(re.findall(r'GLIBC_(\d+\.\d+)',text)),key=lambda s:tuple(map(int,s.split('.'))))
 if versions and tuple(map(int,versions[-1].split('.')))>(2,39): raise SystemExit('ELF exceeds Ubuntu24 baseline: '+str(p))
 if p.name=='libc.so.6' or p.name.startswith('ld-linux'): raise SystemExit('Bundled glibc/loader refused')
 rows.append({'path':str(p.relative_to(app)),'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'max_glibc':versions[-1] if versions else None})
# Filtered source exports deliberately omit Git metadata. External archive
# receipts identify their exact input; never describe such exports as clean.
source='unknown'; dirty=True
try:
 source=subprocess.check_output(['git','rev-parse','HEAD'],text=True,stderr=subprocess.DEVNULL).strip()
 dirty=bool(subprocess.check_output(['git','status','--porcelain'],text=True,stderr=subprocess.DEVNULL))
except subprocess.CalledProcessError:
 source='unknown'; dirty=True
(out/'source-commit.txt').write_text(source+'\n')
(out/'build-provenance.json').write_text(json.dumps({'source_commit':source,'dirty':dirty,'baseline':'Ubuntu 24.04 x86_64 / glibc 2.39','artifact_sha256':hashlib.sha256(artifact.read_bytes()).hexdigest(),'elf_files':rows,'url_handler':'Optional AppImageLauncher integration required; no automatic host installation','host_services':['Secret Service','D-Bus','fusermount3','system TLS trust']},indent=2)+'\n')
PYAUDIT
sha256sum "$artifact" > "$artifact.sha256"
cp "$work/first-party.json" "$out/first-party.json"
cp "$work/runtime-metadata.json" "$out/runtime-metadata.json"
printf 'Built %s\n' "$artifact"

#!/usr/bin/env python3
"""Package the existing native MSVC installer payload as an unsigned CLI ZIP.

No compilation, tests, executable launch, signing or registration is performed.
The installer build must already have validated and staged its exact payloads.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

APP = Path(__file__).resolve().parents[1]
REPO = APP.parents[1]
TARGET = 'x86_64-pc-windows-msvc'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True,
                        help='Fresh output directory; existing outputs are preserved')
    args = parser.parse_args()
    stage = APP / 'target/windows-package-resources'
    payload_path = stage / 'payload-manifest.json'
    payload = json.loads(payload_path.read_text(encoding='utf-8-sig'))
    if payload['target'] != TARGET or payload['signed'] is not False:
        raise RuntimeError('Expected the unsigned native MSVC installer payload')
    records = payload['payloads']
    if len(records) != 2 or {r['name'] for r in records} != {'raiun.exe', 'raiun-agent.exe'}:
        raise RuntimeError('Expected exactly the CLI and agent release payloads')
    # Recheck the exact MSVC legal inventory validated by installer packaging.
    for record in payload['noticeInventory']['files']:
        path = APP / record['path']
        if APP not in path.resolve().parents or path.stat().st_size != record['length'] or digest(path) != record['sha256']:
            raise RuntimeError('Installer redistribution notice changed after staging')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    bundle = output / 'raiun-headless-windows-x86_64'
    bundle.mkdir()
    for record in records:
        source = stage / record['name']
        if source.stat().st_size != record['length'] or digest(source) != record['sha256']:
            raise RuntimeError('Installer payload changed after compilation')
        destination = bundle / record['name']
        shutil.copyfile(source, destination)
        if digest(destination) != record['sha256']:
            raise RuntimeError('Headless payload copy failed hash verification')
    shutil.copyfile(payload_path, bundle / 'payload-manifest.json')
    shutil.copyfile(APP / 'docs/HEADLESS-WINDOWS.md', bundle / 'README.md')
    for name in ('HEADLESS.md', 'HEADLESS-WINDOWS.md', 'HEADLESS-STARTUP.md'):
        shutil.copyfile(APP / 'docs' / name, bundle / name)
    for name in ('install.ps1', 'startup.ps1'):
        shutil.copyfile(APP / 'packaging/headless-windows' / name, bundle / name)
    for name in ('LICENSE', 'NOTICE', 'PRIVACY.md'):
        shutil.copyfile(APP / name, bundle / name)
    shutil.copyfile(APP / 'legal/windows/THIRD-PARTY-NOTICES.md', bundle / 'THIRD-PARTY-NOTICES.md')
    shutil.copytree(APP / 'legal/windows', bundle / 'legal/windows')
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    dirty = bool(subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=REPO))
    if dirty:
        raise RuntimeError('Review bundle must identify a clean committed source')
    files = {p.relative_to(bundle).as_posix(): digest(p)
             for p in sorted(bundle.rglob('*')) if p.is_file()}
    manifest = {
        'format': 'raiun-headless-windows-candidate-v1',
        'candidate': 'github-build-only-review', 'target': TARGET,
        'source': {'base_commit': source, 'uncommitted': dirty},
        'signed': False, 'published': False, 'native_acceptance': False,
        'files': files,
    }
    manifest_path = bundle / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    sums = dict(files, **{'manifest.json': digest(manifest_path)})
    (bundle / 'SHA256SUMS').write_text(
        ''.join(f'{value}  {name}\n' for name, value in sorted(sums.items())), encoding='utf-8')
    archive = output / 'raiun-headless-windows-x86_64.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED, compresslevel=9) as zipped:
        for path in sorted(bundle.rglob('*')):
            if path.is_file():
                zipped.write(path, path.relative_to(output).as_posix())
    (output / 'SHA256SUMS').write_text(f'{digest(archive)}  {archive.name}\n', encoding='utf-8')
    print(json.dumps({'archive': str(archive), 'sha256': digest(archive), 'bytes': archive.stat().st_size}))


if __name__ == '__main__':
    main()

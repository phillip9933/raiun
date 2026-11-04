#!/usr/bin/env python3
"""Build a local Windows test candidate with an explicitly supplied LLVM-MinGW.

No downloads, installation, account use, signing, Git writes or publication.
The Rust x86_64-pc-windows-gnullvm standard library must already be installed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

APP = Path(__file__).resolve().parents[1]
REPO = APP.parents[1]
TARGET = 'x86_64-pc-windows-gnullvm'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--llvm-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='New task output directory')
    parser.add_argument('--include-tests', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    llvm = args.llvm_root.resolve()
    tools = llvm / 'bin'
    imports = output / 'import-libs'
    imports.mkdir()
    subprocess.run([str(tools / 'llvm-dlltool'), '-m', 'i386:x86-64', '-d',
                    str(APP / 'packaging/headless-windows/CldApi.def'), '-l',
                    str(imports / 'libCldApi.a')], check=True)
    environment = dict(os.environ)
    environment['PATH'] = str(tools) + os.pathsep + environment.get('PATH', '')
    environment['CC_x86_64_pc_windows_gnullvm'] = str(tools / 'x86_64-w64-mingw32-clang')
    environment['AR_x86_64_pc_windows_gnullvm'] = str(tools / 'x86_64-w64-mingw32-ar')
    environment['CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER'] = str(tools / 'x86_64-w64-mingw32-clang')
    # Encoded arguments keep paths containing spaces as a single linker argument.
    environment['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join([
        '-C', 'target-feature=+crt-static', '-C', 'link-arg=-static', '-L', 'native=' + str(imports)])
    environment.pop('RUSTFLAGS', None)

    def cargo(arguments, name):
        with (output / (name + '.jsonl')).open('wb') as stdout, (output / (name + '.log')).open('wb') as stderr:
            subprocess.run(['cargo', *arguments, '--target', TARGET, '--locked', '--message-format=json'],
                           cwd=APP, env=environment, stdout=stdout, stderr=stderr, check=True)
        return [json.loads(line) for line in (output / (name + '.jsonl')).read_text().splitlines() if line]

    artifacts = cargo(['build', '--release', '-p', 'raiun-agent', '-p', 'raiun-cli'], 'build')
    bundle = output / 'raiun-headless-windows-x86_64'
    bundle.mkdir()
    for artifact in artifacts:
        if artifact.get('reason') == 'compiler-artifact' and artifact.get('executable') and artifact['target']['name'] in ('raiun', 'raiun-agent'):
            shutil.copyfile(artifact['executable'], bundle / Path(artifact['executable']).name)
    for name in ('raiun.exe', 'raiun-agent.exe'):
        if not (bundle / name).is_file():
            raise RuntimeError('Missing executable: ' + name)
    if args.include_tests:
        # The connected-root fixtures are compiled only into the diagnostic
        # test executables. The release binaries above retain default features.
        tests = cargo(['test', '--no-run', '--lib', '-p', 'raiun-control-windows',
                       '-p', 'raiun-cloudfiles-windows', '--features',
                       'raiun-cloudfiles-windows/synthetic-agent-integration'], 'test-libraries')
        tests += cargo(['test', '--no-run', '--bin', 'raiun-agent', '-p', 'raiun-agent'], 'test-agent')
        (bundle / 'tests').mkdir()
        names = {'raiun_control_windows': 'control-tests.exe', 'raiun_cloudfiles_windows': 'provider-tests.exe', 'raiun-agent': 'agent-tests.exe'}
        for artifact in tests:
            if artifact.get('reason') == 'compiler-artifact' and artifact.get('executable') and artifact.get('profile', {}).get('test'):
                name = names.get(artifact['target']['name'])
                if name:
                    destination = bundle / 'tests' / name
                    shutil.copyfile(artifact['executable'], destination)
                    # Keep original symbols in Cargo output; ship only the test
                    # code/data and named fixtures in the diagnostic bundle.
                    subprocess.run([str(tools / 'llvm-strip'), '--strip-debug', str(destination)], check=True)
        for name in names.values():
            if not (bundle / 'tests' / name).is_file():
                raise RuntimeError('Missing test executable: ' + name)
    shutil.copyfile(APP / 'docs/HEADLESS-WINDOWS.md', bundle / 'README.md')
    for name in ('HEADLESS.md', 'HEADLESS-WINDOWS.md', 'HEADLESS-STARTUP.md'):
        shutil.copyfile(APP / 'docs' / name, bundle / name)
    for name in ('HEADLESS-MOUNT-TEST.md', 'HEADLESS-CLI-TEST.md', 'HEADLESS-WRITE-TEST.md',
                 'HEADLESS-EDITS-TEST.md', 'HEADLESS-PERSONAL-BUSY-TEST.md', 'HEADLESS-STREAMED-TEST.md',
                 'HEADLESS-ACCEPTANCE.md', 'HEADLESS-WINDOWS-AUTOMATIC-DIRECTORY-TEST.md'):
        if (APP / 'docs' / name).is_file():
            shutil.copyfile(APP / 'docs' / name, bundle / name)
    for name in ('test-headless-mount-windows.ps1', 'test-headless-mount-runner.ps1',
                 'test-headless-cli-windows.ps1', 'test-headless-write-windows.ps1',
                 'test-headless-edits-windows.ps1', 'test-headless-personal-busy-windows.ps1',
                 'test-headless-streamed-windows.ps1', 'test-headless-directory-windows.ps1'):
        if (APP / 'scripts' / name).is_file():
            shutil.copyfile(APP / 'scripts' / name, bundle / name)
    shutil.copyfile(APP / 'packaging/headless-windows/install.ps1', bundle / 'install.ps1')
    shutil.copyfile(APP / 'scripts/test-headless-windows.ps1', bundle / 'test-headless-windows.ps1')
    for name in ('LICENSE', 'NOTICE', 'THIRD-PARTY-NOTICES.md', 'PRIVACY.md'):
        shutil.copyfile(APP / name, bundle / name)
    shutil.copytree(APP / 'legal', bundle / 'legal')
    (bundle / 'legal' / 'llvm-mingw').mkdir()
    shutil.copyfile(llvm / 'LICENSE.TXT', bundle / 'legal/llvm-mingw/LICENSE.TXT')
    imports_by_file = {}
    for name in ('raiun.exe', 'raiun-agent.exe'):
        result = subprocess.check_output([str(tools / 'llvm-objdump'), '-p', str(bundle / name)], text=True)
        imports_by_file[name] = [line.split('DLL Name:', 1)[1].strip() for line in result.splitlines() if 'DLL Name:' in line]
    source_files = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', 'apps/desktop'], cwd=REPO).decode().split('\0')
    source_hashes = {name: digest(REPO / name) for name in sorted(set(source_files)) if name and (REPO / name).is_file()}
    source = {'base_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip(),
              'uncommitted': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=REPO)),
              'files': source_hashes}
    (output / 'source-manifest.json').write_text(json.dumps(source, indent=2) + '\n')
    files = {str(path.relative_to(bundle)).replace(os.sep, '/'): digest(path) for path in sorted(bundle.rglob('*')) if path.is_file()}
    manifest = {'format': 'raiun-headless-windows-candidate-v1', 'candidate': 'local-test', 'target': TARGET,
                'source': {'base_commit': source['base_commit'], 'uncommitted': source['uncommitted'], 'manifest_sha256': digest(output / 'source-manifest.json')},
                'signed': False, 'published': False, 'files': files, 'system_dll_imports': imports_by_file,
                'compiler': subprocess.check_output([str(tools / 'x86_64-w64-mingw32-clang'), '--version'], text=True),
                'rust': subprocess.check_output(['rustc', '--version'], text=True).strip()}
    (bundle / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (bundle / 'SHA256SUMS').write_text(''.join(f'{value}  {name}\n' for name, value in files.items()))
    archive = output / 'raiun-headless-windows-x86_64-test.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zipped:
        for path in sorted(bundle.rglob('*')):
            if path.is_file():
                zipped.write(path, str(path.relative_to(output)))
    (output / 'SHA256SUMS').write_text(f'{digest(archive)}  {archive.name}\n')
    print(json.dumps({'archive': str(archive), 'sha256': digest(archive), 'bytes': archive.stat().st_size}))


if __name__ == '__main__':
    main()

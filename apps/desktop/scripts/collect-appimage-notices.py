#!/usr/bin/env python3
"""Collect Ubuntu 24.04 native AppDir notice provenance; never installs/downloads.
Exact hashes are preferred. Recorded transformed ELF origins require both the
same GNU build-id and identical executable-section fingerprints. This is notice
provenance, not executable authentication or a binary security certification.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote

MAX_FILE = 512 * 1024 * 1024
FIRST_PARTY = {'raiun', 'raiun-agent', 'raiun-desktop', 'raiun-desktop-shell'}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def read(path, limit=MAX_FILE):
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('file exceeds collector bound: ' + str(path))
    return data

def elf_identity(data):
    if not data.startswith(b'\x7fELF'):
        return None
    if len(data) < 64 or data[4:6] != b'\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 62:
        raise ValueError('unsupported ELF; expected little-endian x86_64 ELF64')
    offset = struct.unpack_from('<Q', data, 40)[0]
    size, count, names = struct.unpack_from('<HHH', data, 58)
    if size != 64 or not 0 < count <= 8192 or names >= count or offset + size * count > len(data):
        raise ValueError('ELF section table unavailable or malformed')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * size) for i in range(count)]
    table = sections[names]
    if table[4] + table[5] > len(data):
        raise ValueError('ELF name table bounds')
    strings = data[table[4]:table[4] + table[5]]
    code, build_ids = [], []
    for section in sections:
        name_offset, kind, flags, _, start, length, *_ = section
        if name_offset >= len(strings):
            raise ValueError('ELF section name offset')
        end = strings.find(b'\0', name_offset)
        if end < 0:
            raise ValueError('ELF section name terminator')
        name = strings[name_offset:end].decode('ascii', 'strict')
        if kind != 8 and start + length > len(data):
            raise ValueError('ELF section bytes bounds')
        if flags & 4:
            if kind == 8 or not length:
                raise ValueError('ELF executable section missing bytes')
            code.append({'name': name, 'bytes': length, 'sha256': sha(data[start:start + length])})
        if name == '.note.gnu.build-id':
            note = data[start:start + length]
            cursor = 0
            while cursor + 12 <= len(note):
                n, d, typ = struct.unpack_from('<III', note, cursor)
                cursor += 12
                if cursor + ((n + 3) & ~3) + ((d + 3) & ~3) > len(note):
                    raise ValueError('ELF build-id note bounds')
                owner = note[cursor:cursor + n]
                cursor += (n + 3) & ~3
                value = note[cursor:cursor + d]
                cursor += (d + 3) & ~3
                if owner == b'GNU\0' and typ == 3:
                    build_ids.append(value.hex())
    if not code or len({r['name'] for r in code}) != len(code):
        raise ValueError('ELF executable sections unavailable or ambiguous')
    code.sort(key=lambda r: r['name'])
    build_id = build_ids[0] if len(build_ids) == 1 and build_ids[0] else None
    return {'build_id': build_id, 'code_sha256': sha(json.dumps(code, sort_keys=True, separators=(',', ':')).encode()), 'executable_sections': code}

def match_mode(bundle_hash, bundle_elf, source_hash, source_elf):
    if bundle_hash == source_hash:
        return 'exact-file-sha256'
    if bundle_elf and source_elf and bundle_elf['build_id'] and bundle_elf['build_id'] == source_elf['build_id'] and bundle_elf['code_sha256'] == source_elf['code_sha256']:
        return 'same-build-id-and-executable-code-sections'
    return None

def checked_descriptor(row, base):
    path = Path(row['path'])
    if not path.is_absolute():
        path = base / path
    body = read(path)
    if type(row.get('bytes')) is not int or len(body) != row['bytes'] or sha(body) != row.get('sha256'):
        raise ValueError('input descriptor differs: ' + str(path))
    return path, body

class UbuntuBaseline:
    def __init__(self, basenames):
        release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
        if release.get('ID', '').strip('"') != 'ubuntu' or release.get('VERSION_ID', '').strip('"') != '24.04':
            raise ValueError('collector must run on the Ubuntu 24.04 dpkg baseline')
        self.index, self.cache, self.packages = {}, {}, {}
        for listing in sorted(Path('/var/lib/dpkg/info').glob('*.list')):
            package = listing.name[:-5]
            for text in listing.read_text(errors='strict').splitlines():
                path = Path(text)
                if path.is_absolute() and path.name in basenames and str(path).startswith(('/usr/', '/lib/', '/lib64/', '/bin/', '/sbin/')):
                    self.index.setdefault(path.name, set()).add((str(path), package))
    def package(self, name):
        if name not in self.packages:
            fmt = '${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n'
            result = subprocess.check_output(['dpkg-query', '-W', '-f=' + fmt, name], text=True).strip().split('\t')
            if len(result) != 5:
                raise ValueError('dpkg metadata schema: ' + name)
            package, version, arch, source, source_version = result
            self.packages[name] = {'package': package, 'version': version, 'architecture': arch, 'source_package': source, 'source_version': source_version, 'source_url': 'https://launchpad.net/ubuntu/+source/' + quote(source, safe='') + '/' + quote(source_version, safe='')}
        return dict(self.packages[name])
    def origin(self, name, digest, identity):
        candidates = self.index.get(name, set())
        if len(candidates) > 512:
            # Resource provenance is best-effort; ubiquitous copyright names
            # must not bypass the strict origin requirement for native ELFs.
            if identity is None:
                return []
            raise ValueError('too many dpkg candidates for basename: ' + name)
        matches = []
        for text, package in sorted(candidates):
            path = Path(text)
            try:
                resolved = path.resolve(strict=True)
                if not resolved.is_file():
                    continue
                key = str(resolved)
                if key not in self.cache:
                    body = read(resolved)
                    self.cache[key] = (sha(body), elf_identity(body))
                source_hash, source_elf = self.cache[key]
                mode = match_mode(digest, identity, source_hash, source_elf)
                if mode:
                    row = self.package(package)
                    row.update(dpkg_listed_path=text, installed_source_path=key, source_sha256=source_hash, bundled_sha256=digest, match=mode, transformed=mode != 'exact-file-sha256')
                    if mode != 'exact-file-sha256':
                        row['ELF_identity'] = identity
                        row['transformation_limit'] = 'Whole files differ; no assertion that only RPATH or stripping changed.'
                    matches.append(row)
            except (FileNotFoundError, IsADirectoryError):
                continue
        return matches

def self_check():
    original = read(Path('/usr/bin/true'))
    identity = elf_identity(original)
    if identity is None or not identity['build_id']:
        raise ValueError('self-check needs the installed x86_64 true ELF with build-id')
    changed = original + b'collector fixture non-executable trailer\n'
    assert match_mode(sha(changed), elf_identity(changed), sha(original), identity) == 'same-build-id-and-executable-code-sections'
    offset = struct.unpack_from('<Q', original, 40)[0]
    count = struct.unpack_from('<H', original, 60)[0]
    section = next(struct.unpack_from('<IIQQQQIIQQ', original, offset + i * 64) for i in range(count) if struct.unpack_from('<Q', original, offset + i * 64 + 8)[0] & 4)
    mutated = bytearray(original)
    mutated[section[4]] ^= 1
    assert match_mode(sha(mutated), elf_identity(mutated), sha(original), identity) is None
    assert match_mode(sha(original), identity, sha(original), identity) == 'exact-file-sha256'
    with tempfile.TemporaryDirectory() as temporary:
        p = Path(temporary) / 'actual-fixture'; p.write_bytes(original)
        row = {'path': str(p), 'sha256': sha(original), 'bytes': len(original)}
        assert checked_descriptor(row, Path(temporary))[1] == original
        row['sha256'] = '0' * 64
        try:
            checked_descriptor(row, Path(temporary))
            raise AssertionError('changed fixture accepted')
        except ValueError:
            pass
    print(json.dumps({'state': 'actual_ELF_and_temp_descriptor_selfcheck_passed', 'exact_hash': True, 'same_build_id_code_transformed': True, 'changed_code_refused': True, 'changed_descriptor_refused': True}))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--appdir', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--first-party-manifest', type=Path)
    parser.add_argument('--runtime-metadata', type=Path)
    parser.add_argument('--self-check', action='store_true')
    args = parser.parse_args()
    if args.self_check:
        self_check(); return 0
    if not args.appdir or not args.output or not args.first_party_manifest:
        parser.error('--appdir, --output and --first-party-manifest required')
    appdir = args.appdir.resolve(strict=True); output = args.output.resolve()
    if not appdir.is_dir() or output == appdir or not output.is_relative_to(appdir):
        raise ValueError('notice output must be inside the final AppDir')
    first = json.loads(read(args.first_party_manifest).decode())
    first_rows = {row['path']: row for row in first['files']}
    for rel, row in first_rows.items():
        path = Path(rel)
        if path.is_absolute() or '..' in path.parts or path.name not in FIRST_PARTY:
            raise ValueError('only exact Raiun payload names may be first-party exceptions')
        checked_descriptor(row, appdir)
    tool_files, tool_artifacts, tool_licenses = {}, [], []
    output.mkdir(parents=True, exist_ok=True)
    def retain(source, relative):
        body = read(source, 2 * 1024 * 1024); destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True); destination.write_bytes(body)
        return {'path': str(destination.relative_to(appdir)), 'bytes': len(body), 'sha256': sha(body), 'source_path': str(source.resolve())}
    if args.runtime_metadata:
        metadata = json.loads(read(args.runtime_metadata).decode())
        for section in ('files', 'artifacts'):
            for index, row in enumerate(metadata.get(section, [])):
                source, _ = checked_descriptor(row, appdir if section == 'files' else args.runtime_metadata.parent)
                if not row.get('source_url') or not row.get('origin') or not row.get('license_files'):
                    raise ValueError('tool/runtime origin and license descriptors required')
                notices = []
                for license_row in row['license_files']:
                    license_path, _ = checked_descriptor(license_row, args.runtime_metadata.parent)
                    notices.append(retain(license_path, Path('tool-licenses') / (section + '-' + str(index)) / license_path.name))
                item = {k: row[k] for k in ('path', 'sha256', 'bytes', 'origin', 'source_url')}; item['license_files'] = notices
                if section == 'files':
                    rel = str(source.relative_to(appdir)); tool_files[rel] = item
                else:
                    tool_artifacts.append(item)
                tool_licenses.extend(notices)
    paths = [p for p in sorted(appdir.rglob('*')) if (p.is_file() or p.is_symlink()) and not p.is_relative_to(output)]
    if len(paths) > 20000:
        raise ValueError('AppDir file-count bound')
    baseline = UbuntuBaseline({p.name for p in paths})
    files, gaps, warnings, packages = [], [], [], {}
    for path in paths:
        rel = str(path.relative_to(appdir))
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError):
            gaps.append({'path': rel, 'reason': 'bundle symlink target unavailable'}); continue
        if not resolved.is_relative_to(appdir):
            gaps.append({'path': rel, 'reason': 'bundle symlink escapes AppDir'}); continue
        body = read(path); digest = sha(body)
        row = {'path': rel, 'bytes': len(body), 'sha256': digest}
        if path.is_symlink(): row['symlink_target'] = os.readlink(path)
        identity = elf_identity(body)
        if rel in first_rows:
            if digest != first_rows[rel]['sha256'] or len(body) != first_rows[rel]['bytes']:
                raise ValueError('first-party payload changed during inventory: ' + rel)
            row['origin'] = 'exact-first-party-manifest'
        elif rel in tool_files:
            if digest != tool_files[rel]['sha256'] or len(body) != tool_files[rel]['bytes']:
                raise ValueError('tool payload changed during inventory: ' + rel)
            row['origin'] = 'pinned-tool-metadata'; row['tool'] = tool_files[rel]
        else:
            # Preserve the existing Rust legal tree unchanged; it has its own
            # locked inventory, not Ubuntu binary package origins.
            legal_resource = '/legal/' in '/' + rel or rel.startswith('legal/')
            origins = [] if legal_resource else baseline.origin(path.name, digest, identity)
            if origins:
                row['origins'] = origins
                for origin in origins:
                    packages[origin['package']] = {key: origin[key] for key in ('package', 'version', 'architecture', 'source_package', 'source_version', 'source_url')}
            elif identity:
                gaps.append({'path': rel, 'sha256': digest, 'reason': 'no exact dpkg source or matching build-id/executable-code origin'})
            elif not legal_resource:
                warnings.append({'path': rel, 'reason': 'non-ELF resource inventoried without asserted dpkg origin'})
        row['ELF'] = identity
        files.append(row)
    notices = []
    for package, metadata in sorted(packages.items()):
        name = package.split(':', 1)[0]
        source = Path('/usr/share/doc') / name / 'copyright'
        try:
            copied = retain(source, Path('packages') / package / 'copyright'); text = read(source, 2 * 1024 * 1024).decode('utf-8', 'replace')
            metadata['copyright'] = copied; notices.append(copied)
            common = sorted(set(re.findall(r'/usr/share/common-licenses/([A-Za-z0-9_.+\-]+)', text)))
            metadata['common_licenses'] = []
            for name in common:
                name = name.rstrip('.')
                item = retain(Path('/usr/share/common-licenses') / name, Path('common-licenses') / name)
                metadata['common_licenses'].append(item); notices.append(item)
        except (OSError, ValueError) as error:
            gaps.append({'package': package, 'reason': 'copyright/common-license unavailable: ' + type(error).__name__ + ': ' + str(error)})
    report = {'schema': 'raiun-AppImage-Ubuntu24-native-notices-v1', 'baseline': 'Ubuntu 24.04 installed dpkg database', 'files': files, 'packages': packages, 'tool_artifacts': tool_artifacts, 'retained_notice_files': notices + tool_licenses, 'gaps': gaps, 'resource_warnings': warnings, 'scope': 'Notice provenance only; transformed=true never claims whole-file equality or only-RPATH changes. External tool/runtime metadata does not itself prove which runtime bytes are embedded in the repacked AppImage. Existing Rust notices are preserved, not reclassified.'}
    (output / 'inventory.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'files': len(files), 'packages': len(packages), 'gaps': gaps, 'resource_warnings': len(warnings), 'inventory': str(output / 'inventory.json')}, sort_keys=True))
    return 1 if gaps else 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print('native notice collection refused: ' + str(error), file=sys.stderr)
        sys.exit(1)

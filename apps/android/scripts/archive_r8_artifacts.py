#!/usr/bin/env python3
"""Archive exact R8 reports for an APK without accessing signing tools or keys."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import zipfile
from pathlib import Path


REPORTS = ("mapping.txt", "configuration.txt", "seeds.txt", "usage.txt", "resources.txt")
MAP_ID_RE = re.compile(r"(?m)^# pg_map_id: ([0-9a-f]{64})\s*$")
DEX_RE = re.compile(r"classes(?:\d+)?\.dex")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def expected_archive(apk: Path, mapping_dir: Path, version: str) -> tuple[dict[str, bytes], dict]:
    if not VERSION_RE.fullmatch(version):
        raise ValueError(f"Unsafe version value: {version!r}")
    if not apk.is_file():
        raise FileNotFoundError(f"APK is missing: {apk}")
    if not mapping_dir.is_dir():
        raise FileNotFoundError(f"Mapping directory is missing: {mapping_dir}")
    files = {}
    for name in REPORTS:
        path = mapping_dir / name
        if not path.is_file():
            raise FileNotFoundError(f"Required R8 report is missing: {path}")
        files[name] = path.read_bytes()
    match = MAP_ID_RE.search(files["mapping.txt"].decode("utf-8"))
    if not match:
        raise ValueError("mapping.txt has no valid # pg_map_id header")
    map_id = match.group(1)
    marker = f"r8-map-id-{map_id}".encode("ascii")
    with zipfile.ZipFile(apk) as archive:
        dex_names = sorted(name for name in archive.namelist() if DEX_RE.fullmatch(name))
        if not dex_names:
            raise ValueError("APK has no root classes*.dex entries")
        if not any(marker in archive.read(name) for name in dex_names):
            raise ValueError("R8 mapping ID marker is absent from APK root classes*.dex; mapping may be stale")
    apk_hash = hashlib.sha256()
    with apk.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            apk_hash.update(chunk)
    manifest = {
        "schema": 1,
        "version": version,
        "apk": {"sha256": apk_hash.hexdigest(), "bytes": apk.stat().st_size},
        "mapping_id": map_id,
        "reports": {name: {"sha256": sha256(content), "bytes": len(content)}
                    for name, content in sorted(files.items())},
    }
    return files, manifest


def archive(apk: Path, mapping_dir: Path, output: Path, version: str) -> Path:
    files, manifest = expected_archive(apk, mapping_dir, version)
    output = output.resolve()
    version_dir = output / version
    if version_dir.is_symlink():
        raise ValueError(f"Refusing symlink archive version directory: {version_dir}")
    version_dir.mkdir(parents=True, exist_ok=True)
    destination = version_dir / manifest["apk"]["sha256"]
    expected = {**files, "MANIFEST.json": (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()}
    if destination.exists():
        if destination.is_symlink() or not destination.is_dir():
            raise ValueError(f"Archive destination is not a regular directory: {destination}")
        actual_names = {path.name for path in destination.iterdir()}
        if actual_names != set(expected):
            raise FileExistsError(f"Existing archive contents differ; refusing overwrite: {destination}")
        for name, content in expected.items():
            path = destination / name
            if path.is_symlink() or not path.is_file() or path.read_bytes() != content:
                raise FileExistsError(f"Existing archive file differs; refusing overwrite: {path}")
        return destination
    with tempfile.TemporaryDirectory(prefix=".r8-archive-", dir=version_dir) as temporary:
        staged = Path(temporary)
        for name, content in expected.items():
            (staged / name).write_bytes(content)
        try:
            os.replace(staged, destination)
        except OSError:
            if destination.exists():
                # A concurrent identical archive is safe; differing bytes remain a hard failure.
                actual_names = {path.name for path in destination.iterdir()} if destination.is_dir() else set()
                if actual_names != set(expected) or any((destination / name).read_bytes() != content
                                                         for name, content in expected.items()):
                    raise FileExistsError(f"Concurrent archive differs; refusing overwrite: {destination}")
            else:
                raise
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", required=True, type=Path, help="Unsigned release APK")
    parser.add_argument("--mapping-dir", required=True, type=Path, help="AGP release mapping output directory")
    parser.add_argument("--output", required=True, type=Path, help="Private/internal artifact archive root")
    parser.add_argument("--version", required=True, help="Release version name")
    args = parser.parse_args()
    destination = archive(args.apk, args.mapping_dir, args.output, args.version)
    print(destination)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"archive_r8_artifacts: {error}", file=sys.stderr)
        raise SystemExit(1)

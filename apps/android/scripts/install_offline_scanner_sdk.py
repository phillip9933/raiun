#!/usr/bin/env python3
"""Install the checksum-pinned offline scanner Maven repository into .gradle."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath


def fail(message: str) -> "NoReturn":
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_archive_path(name: str) -> PurePosixPath:
    if "\\" in name:
        fail(f"Archive member uses an unsafe path separator: {name!r}")
    raw_parts = name.split("/")
    if name.endswith("/"):
        raw_parts.pop()
    if any(part in ("", ".", "..") or ":" in part for part in raw_parts):
        fail(f"Archive member has an unsafe path: {name!r}")
    member = PurePosixPath(name)
    if member.is_absolute() or not member.parts:
        fail(f"Archive member has an unsafe path: {name!r}")
    return member


def main() -> None:
    project = Path(__file__).resolve().parent.parent
    lock_path = Path(__file__).with_name("offline-scanner-sdk.lock.json")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    version = lock["version"]
    archive_name = lock["archive"]
    expected_digest = lock["sha256"].lower()
    if len(expected_digest) != 64 or any(char not in "0123456789abcdef" for char in expected_digest):
        fail(f"Invalid SHA-256 in {lock_path}")

    cache = project / ".gradle" / f"open-android-doc-scanner-{version}"
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / archive_name
    if archive.exists():
        actual_digest = sha256(archive)
        if actual_digest != expected_digest:
            fail(f"Cached archive SHA-256 mismatch: expected {expected_digest}, got {actual_digest}; remove {archive} and retry")
    else:
        download = cache / f"{archive_name}.download"
        try:
            request = urllib.request.Request(lock["url"], headers={"User-Agent": "OpenCloud-Android-Next-SDK-Installer"})
            with urllib.request.urlopen(request, timeout=60) as response, download.open("wb") as output:
                shutil.copyfileobj(response, output)
            actual_digest = sha256(download)
            if actual_digest != expected_digest:
                fail(f"Downloaded archive SHA-256 mismatch: expected {expected_digest}, got {actual_digest}")
            os.replace(download, archive)
        finally:
            download.unlink(missing_ok=True)

    maven_repository = cache / "maven"
    expected_coordinate = PurePosixPath(
        f"dev/offlinescan/scanner-ui-compose/{version}/scanner-ui-compose-{version}"
    )
    expected_files = {f"maven/{expected_coordinate}{suffix}" for suffix in (".pom", ".aar")}
    with zipfile.ZipFile(archive) as bundle:
        members: dict[str, zipfile.ZipInfo] = {}
        for info in bundle.infolist():
            member = safe_archive_path(info.filename)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                fail(f"Archive contains a symbolic link: {info.filename!r}")
            if member.parts[0] == "maven" and not info.is_dir():
                if info.filename in members:
                    fail(f"Archive contains a duplicate Maven member: {info.filename!r}")
                members[info.filename] = info
        if not expected_files.issubset(members):
            fail("Verified release archive is missing the scanner UI POM or AAR")

        existing = maven_repository.exists()
        if existing:
            installed_members = {
                path.relative_to(maven_repository).as_posix()
                for path in maven_repository.rglob("*")
                if path.is_file()
            }
            expected_members = {name.removeprefix("maven/") for name in members}
            if installed_members != expected_members:
                fail(f"Installed Maven repository does not match the pinned archive at {maven_repository}; remove it and rerun")
            for archive_name_in_zip, info in members.items():
                relative = safe_archive_path(archive_name_in_zip).relative_to("maven")
                installed = maven_repository.joinpath(*relative.parts)
                if not installed.is_file():
                    fail(f"Installed Maven repository is incomplete: {installed}; remove {maven_repository} and rerun")
                with bundle.open(info) as source, installed.open("rb") as current:
                    if hashlib.sha256(source.read()).digest() != hashlib.sha256(current.read()).digest():
                        fail(f"Installed Maven artifact differs from the pinned archive: {installed}; remove {maven_repository} and rerun")
        else:
            with tempfile.TemporaryDirectory(prefix="scanner-sdk-", dir=cache) as temporary:
                staging = Path(temporary) / "maven"
                for archive_name_in_zip, info in members.items():
                    relative = safe_archive_path(archive_name_in_zip).relative_to("maven")
                    destination = staging.joinpath(*relative.parts)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with bundle.open(info) as source, destination.open("xb") as output:
                        shutil.copyfileobj(source, output)
                staging.replace(maven_repository)

    print(f"Installed dev.offlinescan:scanner-ui-compose:{version} in {maven_repository}")
    print(f"Verified archive SHA-256: {expected_digest}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Create deterministic Desktop updater metadata from final signed package files.

This tool inventories and embeds signature text; it does NOT cryptographically
verify Tauri signatures. Verification remains the updater's responsibility.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

REPOSITORY = "phillip9933/raiun"
RELEASE_BASE = f"https://github.com/{REPOSITORY}/releases/download"
MAX_PACKAGE_BYTES = 512 * 1024 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024
MAX_NOTES_BYTES = 32 * 1024
CHUNK_BYTES = 1024 * 1024

# SemVer 2.0.0, including the no-leading-zero rule for numeric identifiers.
_NUM = r"(?:0|[1-9][0-9]*)"
_PRE_ID = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
_BUILD_ID = r"[0-9A-Za-z-]+"
_SEMVER_RE = re.compile(
    rf"^{_NUM}\.{_NUM}\.{_NUM}"
    rf"(?:-{_PRE_ID}(?:\.{_PRE_ID})*)?"
    rf"(?:\+{_BUILD_ID}(?:\.{_BUILD_ID})*)?$"
)
_ASSET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")


class InputError(ValueError):
    pass


def parse_tag(tag: str) -> str:
    prefix = "desktop-v"
    if not tag.startswith(prefix):
        raise InputError("tag must use the exact desktop-v<SemVer> form")
    version = tag[len(prefix) :]
    if len(version.encode("utf-8")) > 96:
        raise InputError("tag version exceeds the 96-byte runtime limit")
    if not version or not _SEMVER_RE.fullmatch(version):
        raise InputError("tag does not contain a strict SemVer 2.0.0 version")
    return version


def absolute_without_symlink(path_text: str, *, must_exist: bool) -> Path:
    if not path_text or "\x00" in path_text:
        raise InputError("path is empty or contains a NUL byte")
    path = Path(os.path.abspath(os.path.expanduser(path_text)))
    current = Path(path.anchor)
    parts = path.parts[1:] if path.anchor else path.parts
    for index, part in enumerate(parts):
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if must_exist or index < len(parts) - 1:
                raise InputError(f"path component does not exist: {current}") from None
            continue
        if stat.S_ISLNK(info.st_mode):
            raise InputError(f"symlink path component is refused: {current}")
    return path


def read_regular_file(path_text: str, *, maximum: int, label: str) -> tuple[Path, bytes | None, int, str]:
    path = absolute_without_symlink(path_text, must_exist=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise InputError(f"could not open {label}: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise InputError(f"{label} must be a regular file")
        if before.st_size <= 0 or before.st_size > maximum:
            raise InputError(f"{label} must be non-empty and no larger than {maximum} bytes")
        digest = hashlib.sha256()
        data = bytearray() if label.endswith("signature") or label == "notes" else None
        total = 0
        while True:
            chunk = os.read(fd, CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise InputError(f"{label} exceeds its {maximum}-byte limit")
            digest.update(chunk)
            if data is not None:
                data.extend(chunk)
        after = os.fstat(fd)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after or total != before.st_size:
            raise InputError(f"{label} changed while it was being read")
        return path, bytes(data) if data is not None else None, total, digest.hexdigest()
    finally:
        os.close(fd)


def file_identity(path_text: str) -> tuple[int, int]:
    path = absolute_without_symlink(path_text, must_exist=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise InputError(f"could not open input for identity check: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise InputError("package, signature, and notes inputs must be regular files")
        return info.st_dev, info.st_ino
    finally:
        os.close(fd)


def read_signature(path_text: str, *, platform: str) -> tuple[Path, str, int, str]:
    path, data, size, digest = read_regular_file(
        path_text, maximum=MAX_SIGNATURE_BYTES, label=f"{platform} signature"
    )
    assert data is not None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputError(f"{platform} signature must be UTF-8 text") from exc
    text = text.removesuffix("\n").removesuffix("\r")
    if not text or text != text.strip() or any(ord(char) < 0x20 or ord(char) == 0x7F for char in text):
        raise InputError(f"{platform} signature must be one non-empty printable line")
    return path, text, size, digest


def read_notes(path_text: str | None) -> str:
    if path_text is None:
        return ""
    _, data, _, _ = read_regular_file(path_text, maximum=MAX_NOTES_BYTES, label="notes")
    assert data is not None
    try:
        notes = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputError("notes must be UTF-8 text") from exc
    if "\x00" in notes:
        raise InputError("notes must not contain NUL")
    return notes.removesuffix("\n")


def artifact_record(path_text: str, signature_text: str, platform: str, suffix: str, tag: str) -> tuple[dict[str, Any], dict[str, Any]]:
    artifact_path, _, artifact_size, artifact_hash = read_regular_file(
        path_text, maximum=MAX_PACKAGE_BYTES, label=f"{platform} package"
    )
    signature_path, signature, signature_size, signature_hash = read_signature(
        signature_text, platform=platform
    )
    asset_name = artifact_path.name
    signature_name = signature_path.name
    if not _ASSET_NAME_RE.fullmatch(asset_name) or not asset_name.endswith(suffix):
        raise InputError(f"{platform} package filename must be a safe basename ending in {suffix}")
    if not _ASSET_NAME_RE.fullmatch(signature_name):
        raise InputError(f"{platform} signature filename is not a safe basename")
    if not signature_name.endswith(".sig"):
        raise InputError(f"{platform} signature filename must end in .sig")
    if asset_name == signature_name:
        raise InputError(f"{platform} package and signature must be separate files")
    url = f"{RELEASE_BASE}/{tag}/{asset_name}"
    manifest_platform = {"url": url, "signature": signature}
    inventory_platform = {
        "platform": platform,
        "package": {"name": asset_name, "bytes": artifact_size, "sha256": artifact_hash},
        "signatureFile": {"name": signature_name, "bytes": signature_size, "sha256": signature_hash},
        "releaseUrl": url,
    }
    return manifest_platform, inventory_platform


def build_documents(
    *, tag: str, linux_package: str, linux_signature: str,
    windows_package: str, windows_signature: str, notes_file: str | None,
) -> tuple[bytes, bytes]:
    version = parse_tag(tag)
    input_texts = [linux_package, linux_signature, windows_package, windows_signature]
    if notes_file:
        input_texts.append(notes_file)
    normalized_inputs = [
        str(absolute_without_symlink(value, must_exist=True)) for value in input_texts
    ]
    if len(set(normalized_inputs)) != len(normalized_inputs):
        raise InputError("package, signature, and notes inputs must be distinct files")
    identities = [file_identity(value) for value in input_texts]
    if len(set(identities)) != len(identities):
        raise InputError("package, signature, and notes inputs must not be hard-link aliases")
    release_file_names = [
        Path(absolute_without_symlink(value, must_exist=True)).name
        for value in (linux_package, linux_signature, windows_package, windows_signature)
    ]
    if len(set(release_file_names)) != len(release_file_names):
        raise InputError("package and signature basenames must be globally unique")
    linux, linux_inventory = artifact_record(
        linux_package, linux_signature, "linux-x86_64-appimage", ".AppImage", tag
    )
    windows, windows_inventory = artifact_record(
        windows_package, windows_signature, "windows-x86_64-nsis", ".nsis.zip", tag
    )
    if linux["url"] == windows["url"]:
        raise InputError("Linux and Windows package assets must be distinct")
    notes = read_notes(notes_file)
    manifest = {
        "version": version,
        "notes": notes,
        "platforms": {
            "linux-x86_64-appimage": linux,
            "windows-x86_64-nsis": windows,
        },
    }
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    inventory = {
        "format": "raiun-desktop-update-artifact-inventory-v1",
        "repository": REPOSITORY,
        "tag": tag,
        "version": version,
        "manifest": {
            "name": "desktop-update.json",
            "bytes": len(manifest_bytes),
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        },
        "artifacts": [linux_inventory, windows_inventory],
        "cryptographicSignatureVerification": "not performed by this helper",
    }
    return (
        manifest_bytes,
        (json.dumps(inventory, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )


def exclusive_write(path_text: str, data: bytes) -> Path:
    path = absolute_without_symlink(path_text, must_exist=False)
    if not path.parent.is_dir():
        raise InputError(f"output parent directory must already exist: {path.parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise InputError(f"refusing to replace existing output: {path}") from exc
    except OSError as exc:
        raise InputError(f"could not create output {path}: {exc}") from exc
    try:
        with os.fdopen(fd, "wb", closefd=False) as file:
            file.write(data)
            file.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    return path


def run(args: argparse.Namespace) -> tuple[Path, Path]:
    manifest_path = absolute_without_symlink(args.manifest_out, must_exist=False)
    inventory_path = absolute_without_symlink(args.inventory_out, must_exist=False)
    input_paths = [
        absolute_without_symlink(value, must_exist=True)
        for value in (args.linux_package, args.linux_signature, args.windows_package, args.windows_signature)
    ]
    if args.notes_file:
        input_paths.append(absolute_without_symlink(args.notes_file, must_exist=True))
    if len(set(input_paths)) != len(input_paths):
        raise InputError("package, signature, and notes inputs must be distinct files")
    if manifest_path == inventory_path or manifest_path in input_paths or inventory_path in input_paths:
        raise InputError("output paths must be unique and cannot replace an input")
    if manifest_path.exists() or inventory_path.exists():
        raise InputError("refusing to replace an existing output")
    manifest, inventory = build_documents(
        tag=args.tag,
        linux_package=args.linux_package,
        linux_signature=args.linux_signature,
        windows_package=args.windows_package,
        windows_signature=args.windows_signature,
        notes_file=args.notes_file,
    )
    written_manifest = exclusive_write(str(manifest_path), manifest)
    try:
        written_inventory = exclusive_write(str(inventory_path), inventory)
    except Exception:
        # Do not remove or overwrite a file after a partial output failure.
        raise
    return written_manifest, written_inventory


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--tag", required=True, help="Exact desktop-v<SemVer> release tag")
    result.add_argument("--linux-package", required=True, help="Final Linux x86_64 AppImage file")
    result.add_argument("--linux-signature", required=True, help="Signature text for the exact final AppImage")
    result.add_argument("--windows-package", required=True, help="Final Windows x86_64 Tauri NSIS updater .nsis.zip")
    result.add_argument("--windows-signature", required=True, help="Signature text for the exact NSIS updater archive")
    result.add_argument("--notes-file", help="Optional UTF-8 plain-text release notes file (default: empty)")
    result.add_argument("--manifest-out", required=True, help="New output path for desktop-update.json")
    result.add_argument("--inventory-out", required=True, help="New output path for deterministic SHA256 inventory JSON")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        manifest_path, inventory_path = run(args)
    except (InputError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"manifest: {manifest_path}")
    print(f"inventory: {inventory_path}")
    print("note: signature text is inventoried, not cryptographically verified by this helper")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

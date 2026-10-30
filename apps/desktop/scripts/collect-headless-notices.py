#!/usr/bin/env python3
"""Collect the locked agent/CLI Linux and Windows notice closure, entirely offline.

Includes non-dev build/proc-macro dependencies conservatively. This source/notice
inventory is not an exact linked-binary SBOM. Existing GUI inventory is untouched.
"""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ("x86_64-unknown-linux-gnu", "x86_64-pc-windows-gnullvm")
ROOTS = {"raiun-agent", "raiun-cli"}
MAX_TEXT = 2 * 1024 * 1024
NOTICE_NAME = re.compile(r"^(licen[cs]e|copying|notice|copyright)(?:$|[._-])", re.I)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def retained_notice(record):
    path = ROOT / record["path"]
    body = path.read_bytes()
    if len(body) != record["bytes"] or digest(body) != record["sha256"]:
        raise RuntimeError("retained notice hash mismatch: " + record["path"])
    return record


def put_missing(body, relative):
    if len(body) > MAX_TEXT:
        raise RuntimeError("notice exceeds 2 MiB bound: " + str(relative))
    destination = ROOT / "legal" / "rust" / relative
    if destination.exists():
        if destination.read_bytes() != body:
            raise RuntimeError("existing notice differs; preserved: " + str(relative))
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)
    return {"path": str(destination.relative_to(ROOT)), "bytes": len(body), "sha256": digest(body)}


def archive_notices(package, checksum, cargo_home):
    name = package["name"] + "-" + package["version"]
    archives = list((cargo_home / "registry/cache").glob("*/" + name + ".crate"))
    archive_path = next((path for path in archives if digest(path.read_bytes()) == checksum), None)
    if archive_path is None:
        raise RuntimeError("no exact locked cached registry archive: " + name)
    explicit = package.get("license_file")
    if explicit:
        explicit = Path(explicit)
        if explicit.is_absolute():
            explicit = explicit.relative_to(Path(package["manifest_path"]).parent)
        explicit = explicit.as_posix()
    notices = []
    vcs_commit = None
    with tarfile.open(archive_path) as archive:
        for member in sorted(archive.getmembers(), key=lambda item: item.name):
            parts = PurePosixPath(member.name).parts
            if not parts or parts[0] != name or ".." in parts or PurePosixPath(member.name).is_absolute():
                raise RuntimeError("unexpected cached archive member path")
            relative = PurePosixPath(*parts[1:])
            if not member.isfile():
                continue
            if str(relative) == ".cargo_vcs_info.json":
                vcs_commit = json.load(archive.extractfile(member)).get("git", {}).get("sha1")
            if NOTICE_NAME.match(relative.name) or str(relative) == explicit:
                if member.size > MAX_TEXT:
                    raise RuntimeError("cached notice exceeds bound: " + name)
                body = archive.extractfile(member).read(MAX_TEXT + 1)
                notices.append(put_missing(body, Path(name) / str(relative)))
    return notices, vcs_commit


def main():
    lock_body = (ROOT / "Cargo.lock").read_bytes()
    locked = {
        (row["name"], row["version"], row.get("source")): row.get("checksum")
        for row in tomllib.loads(lock_body.decode())["package"]
    }
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    provenance_file = ROOT / "legal/upstream-notice-provenance.json"
    provenance = {
        record["package"]: record
        for record in json.loads(provenance_file.read_bytes())["packages"]
    }
    rows = {}
    workspace = set()
    gaps = []
    for target in TARGETS:
        graph = json.loads(subprocess.check_output([
            "cargo", "metadata", "--offline", "--locked", "--format-version", "1",
            "--filter-platform", target, "--manifest-path", str(ROOT / "Cargo.toml"),
        ], cwd=ROOT))
        packages = {row["id"]: row for row in graph["packages"]}
        nodes = {row["id"]: row for row in graph["resolve"]["nodes"]}
        pending = [key for key, row in packages.items() if row["name"] in ROOTS and row.get("source") is None]
        seen = set()
        while pending:
            key = pending.pop()
            if key in seen:
                continue
            seen.add(key)
            package = packages[key]
            pending.extend(
                dependency["pkg"] for dependency in nodes[key]["deps"]
                if any(kind["kind"] != "dev" for kind in dependency["dep_kinds"])
            )
            if package.get("source") is None:
                workspace.add(package["name"])
                continue
            identity = (package["name"], package["version"], package["source"])
            if identity not in rows:
                checksum = locked.get(identity)
                if not checksum:
                    raise RuntimeError("external dependency lacks exact registry checksum: " + package["name"])
                texts, commit = archive_notices(package, checksum, cargo_home)
                row = {
                    "ecosystem": "cargo", "name": package["name"], "version": package["version"],
                    "source": package["source"], "registry_crate_sha256": checksum,
                    "declared_license": package.get("license"), "repository": package.get("repository"),
                    "notice_files": texts, "targets": [],
                }
                supplement = provenance.get(package["name"] + "@" + package["version"])
                if supplement:
                    if checksum != supplement["crate_sha256"] or commit != supplement["vcs_commit"]:
                        raise RuntimeError("upstream supplement checksum/commit mismatch")
                    for notice in supplement["supplemental_notices"] + supplement["registry_metadata_files"]:
                        retained_notice(notice)
                    row["notice_files"].extend(supplement["supplemental_notices"])
                    row["upstream_notice_provenance"] = {
                        "path": "legal/upstream-notice-provenance.json", "vcs_commit": commit,
                        "registry_crate_sha256": checksum, "resolution": supplement["resolution"],
                    }
                row["notice_files"] = sorted({text["path"]: text for text in row["notice_files"]}.values(), key=lambda text: text["path"])
                if not row["notice_files"]:
                    gaps.append({"package": package["name"] + "@" + package["version"], "reason": "no cached license/notice text or verified retained supplement"})
                if not package.get("license") and not package.get("license_file"):
                    gaps.append({"package": package["name"] + "@" + package["version"], "reason": "no license expression or license_file declared"})
                rows[identity] = row
            rows[identity]["targets"].append(target)
    if (ROOT / "Cargo.lock").read_bytes() != lock_body:
        raise RuntimeError("Cargo.lock changed while collecting; rerun against final lock")
    old = json.loads((ROOT / "legal/dependency-inventory.json").read_bytes())
    runtime = [retained_notice(notice) for notice in old["rust_toolchain_notices"]]
    eme = retained_notice(old["eme_notice"])
    result = {
        "schema": "raiun-headless-offline-notice-inventory-v1", "targets": list(TARGETS),
        "roots": sorted(ROOTS), "workspace_packages": sorted(workspace),
        "scope": "Locked non-dev dependency closure from raiun-agent and raiun-cli for Linux and Windows GNULLVM; conservatively includes build/proc-macro dependencies; source/notice inventory, not an exact linked-binary SBOM",
        "lock_sha256": {"Cargo.lock": digest(lock_body)},
        "rust_packages": sorted(rows.values(), key=lambda row: (row["name"], row["version"])),
        "rust_toolchain_notices": runtime, "eme_notice": eme, "gaps": gaps,
        "system_libraries": "Linux FUSE/system libraries and Windows OS APIs are prerequisites, not copied by this collector. Cross-toolchain/compiler runtime notices are additionally retained in candidate packaging as applicable; this inventory is limited to Cargo closure and existing Rust/EME notices.",
    }
    (ROOT / "legal/headless-dependency-inventory.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    counts = {target: sum(target in row["targets"] for row in rows.values()) for target in TARGETS}
    begin = "<!-- BEGIN HEADLESS CLI NOTICES -->"
    end = "<!-- END HEADLESS CLI NOTICES -->"
    section = f"""{begin}
## Headless CLI MVP notices

The unpublished headless agent/CLI candidate has a separate offline inventory:
[legal/headless-dependency-inventory.json](legal/headless-dependency-inventory.json).
It covers **{len(rows)} distinct external crate versions**, with {counts[TARGETS[0]]} in the
Linux x86_64 closure and {counts[TARGETS[1]]} in the Windows x86_64 GNULLVM closure. The
closure excludes dev-only edges and conservatively includes build/proc-macro
dependencies. It is a source/notice inventory, **not a linked-binary SBOM**.

The exact workspace `Cargo.lock` SHA-256 is
`{digest(lock_body)}`. Generate/check the
inventory entirely offline with `python3 scripts/collect-headless-notices.py`.
Each cached registry archive is verified against its locked checksum before
license text is read. Existing notice files are verified and preserved; only
missing cached texts are copied. Any applied upstream supplement must match
the retained registry checksum, VCS commit and notice hashes. The collector
fails when required text is missing and never downloads it.

The hidden token prompt adds `rpassword 7.5.4` and `rtoolbox 0.0.6`, both declared
Apache-2.0. Their complete cached texts are retained as
[rpassword LICENSE-APACHE](legal/rust/rpassword-7.5.4/LICENSE-APACHE) and
[rtoolbox LICENSE-APACHE](legal/rust/rtoolbox-0.0.6/LICENSE-APACHE). All package
versions, declared expressions, repositories, target membership and text hashes
are in the headless inventory. Retained Rust toolchain/EME notices and any
candidate-specific cross-toolchain notices accompany packaging. Linux FUSE and
Windows OS APIs remain platform prerequisites, not copies made by this collector.

The earlier GUI/Linux inventory and its full notice tree below are preserved
independently. This headless collection does not change the app version,
publish a release or certify exact binary linkage.
{end}"""
    notice_path = ROOT / "THIRD-PARTY-NOTICES.md"
    notice = notice_path.read_text()
    if begin in notice:
        start = notice.index(begin)
        finish = notice.index(end, start) + len(end)
        notice = notice[:start] + section + notice[finish:]
    else:
        anchor = "## Scope and retained texts"
        if anchor not in notice:
            raise RuntimeError("third-party notice insertion point is unavailable")
        notice = notice.replace(anchor, section + "\n\n" + anchor, 1)
    notice_path.write_text(notice)
    print(json.dumps({"rust_packages": len(rows), "targets": list(TARGETS), "lock_sha256": digest(lock_body), "gaps": gaps}, indent=2))
    if gaps:
        raise SystemExit("headless notice text gaps remain; no download was attempted")


if __name__ == "__main__":
    main()

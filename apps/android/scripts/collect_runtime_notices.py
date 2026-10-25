#!/usr/bin/env python3
"""Collect release runtime license evidence from the resolved dependency list.

Run from any directory. POMs and archives are read from the Gradle module cache;
the pinned scanner SDK is read from the installer's verified Maven cache;
when a POM is absent, the script requests it from the official Google or Maven
Central repository and follows parent POMs for inherited license declarations.
Unknown or unavailable declarations are recorded as gaps, never guessed.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import shutil
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs/release-audit/runtime-dependencies.json"
DEFAULT_CACHE = Path.home() / ".gradle/caches/modules-2/files-2.1"
SCANNER_LOCK = ROOT / "scripts/offline-scanner-sdk.lock.json"
OUTPUT = ROOT / "app/src/main/assets/third-party/runtime-notices"
RUNTIME_JSON = OUTPUT / "runtime-inventory.json"
THIRD_PARTY_MD = ROOT / "THIRD-PARTY-NOTICES.md"
LICENSE_FILENAMES = re.compile(
    r"(^|/)(?:LICENSE|LICENCE|NOTICE|COPYING|COPYRIGHT|THIRD[-_ ]PARTY[-_ ]NOTICES?)"
    r"(?:[._ -].*)?$",
    re.IGNORECASE,
)

# These exact texts were reviewed and shipped with the previous runtime notice
# inventory. Keep them through offline regeneration, but reject altered copies.
# The source URLs are provenance from that inventory, not a fresh network check.
VETTED_LICENSE_TEXTS = {
    ("com.google.protobuf:protobuf-javalite", "3.25.8", "BSD-3-Clause"): (
        "BSD-3-Clause.txt",
        "6e5e117324afd944dcf67f36cf329843bc1a92229a8cd9bb573d7a83130fea7d",
        "https://raw.githubusercontent.com/protocolbuffers/protobuf/v25.8/LICENSE",
    ),
    ("com.goterl:lazysodium-android", "5.2.0", "Mozilla Public License, Version 2.0"): (
        "Mozilla_Public_License_Version_2.0.txt",
        "3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04",
        "https://www.mozilla.org/MPL/2.0/index.txt",
    ),
    ("net.java.dev.jna:jna", "5.17.0", "LGPL-2.1-or-later"): (
        "LGPL-2.1-or-later.txt",
        "20e50fe7aae3e56378ebf0417d9de904f55a0e61e4df315333e632a4d3555d95",
        "https://www.gnu.org/licenses/old-licenses/lgpl-2.1.txt",
    ),
    ("org.bouncycastle:bcprov-jdk18on", "1.85.2", "Bouncy Castle Licence"): (
        "Bouncy_Castle_Licence.txt",
        "0e01f1549c9022f406392ac2947d32223b7c2e977d21ea2f8c182fdeb4dae5fd",
        "https://raw.githubusercontent.com/bcgit/bc-java/r1rv85v2/LICENSE.md",
    ),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def scanner_release(scanner: Path, lock: dict[str, str]) -> dict[str, tuple[bytes, str]]:
    """Validate the installed Maven tree and retain license evidence from the pinned ZIP."""
    archive = scanner / lock["archive"]
    if not archive.is_file() or sha256(archive.read_bytes()) != lock["sha256"].lower():
        raise SystemExit(f"Scanner SDK archive missing or SHA-256 mismatch: {archive}")
    maven = scanner / "maven"
    with zipfile.ZipFile(archive) as bundle:
        expected = {name.removeprefix("maven/") for name in bundle.namelist() if name.startswith("maven/") and not name.endswith("/")}
        actual = {path.relative_to(maven).as_posix() for path in maven.rglob("*") if path.is_file()}
        if actual != expected:
            raise SystemExit(f"Scanner SDK Maven cache differs from pinned archive: {maven}")
        for relative in expected:
            if (maven / relative).read_bytes() != bundle.read("maven/" + relative):
                raise SystemExit(f"Scanner SDK Maven cache differs from pinned archive: {maven / relative}")
        processing = f"maven/dev/offlinescan/scanner-processing-opencv/{lock['version']}/scanner-processing-opencv-{lock['version']}.aar"
        with zipfile.ZipFile(io.BytesIO(bundle.read(processing))) as aar:
            sources = {
                "apache": (bundle.read("LICENSE"), f"scanner SDK {lock['version']} Maven ZIP / LICENSE"),
            }
            for key, name in {
                "libyuv": "assets/offline-scanner-notices/libyuv-LICENSE.txt",
                "onnxruntime": "assets/third_party_licenses/onnxruntime/LICENSE.txt",
            }.items():
                sources[key] = (aar.read(name), f"scanner SDK {lock['version']} processing AAR / {name}")
    return sources


def parse_pom(data: bytes) -> tuple[list[dict[str, str]], dict[str, str] | None]:
    root = ET.fromstring(data)

    def child(parent: ET.Element | None, name: str) -> str:
        if parent is None:
            return ""
        for item in parent:
            if item.tag.rsplit("}", 1)[-1] == name:
                return (item.text or "").strip()
        return ""

    licenses: list[dict[str, str]] = []
    for node in root.iter():
        if node.tag.rsplit("}", 1)[-1] == "license":
            name = child(node, "name")
            url = child(node, "url")
            if name or url:
                licenses.append({"name": name, "url": url})
    parent = next((n for n in root if n.tag.rsplit("}", 1)[-1] == "parent"), None)
    parent_data = None
    if parent is not None:
        group = child(parent, "groupId")
        artifact = child(parent, "artifactId")
        version = child(parent, "version")
        if group and artifact and version:
            parent_data = {"group": group, "artifact": artifact, "version": version}
    return licenses, parent_data


def repositories(group: str) -> list[str]:
    if group == "dev.offlinescan" or group.startswith("dev.offlinescan."):
        return []
    if group.startswith("androidx.") or group.startswith("com.android."):
        return ["https://dl.google.com/dl/android/maven2"]
    return ["https://repo.maven.apache.org/maven2", "https://dl.google.com/dl/android/maven2"]


def maven_path(group: str, artifact: str, version: str) -> str:
    return f"{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.pom"


def portable_source(source: str, cache: Path, scanner: Path, version: str) -> str:
    if not source or source.startswith(("https://", "http://", "POM unavailable")):
        return source
    path = Path(source)
    try:
        return "bundled updater / " + path.resolve().relative_to((ROOT / "third_party/android-updater").resolve()).as_posix()
    except (ValueError, OSError):
        pass
    try:
        return "Gradle module cache / " + path.resolve().relative_to(cache.resolve()).as_posix()
    except (ValueError, OSError):
        pass
    try:
        return f"scanner SDK {version} Maven ZIP / " + path.resolve().relative_to(scanner.resolve()).as_posix()
    except (ValueError, OSError):
        return "local source file (path omitted)"


def fetch_url(url: str) -> bytes | None:
    request = urllib.request.Request(url, headers={"User-Agent": "runtime-notice-audit/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.read()
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def bundled_updater_file(group: str, artifact: str, version: str, suffix: str) -> Path | None:
    if (group, artifact) != ("io.github.phillip9933", "android-updater"):
        return None
    bundle = ROOT / "third_party/android-updater"
    relative = f"maven/io/github/phillip9933/android-updater/{version}/android-updater-{version}{suffix}"
    path = bundle / relative
    pins = dict(line.split("  ", 1)[::-1] for line in (bundle / "SHA256SUMS").read_text().splitlines() if line)
    if relative not in pins or not path.is_file() or sha256(path.read_bytes()) != pins[relative]:
        raise SystemExit(f"Missing or modified pinned updater artifact: {relative}")
    return path


def local_pom(cache: Path, group: str, artifact: str, version: str) -> Path | None:
    bundled = bundled_updater_file(group, artifact, version, ".pom")
    if bundled is not None:
        return bundled
    base = cache / group / artifact / version
    if not base.exists():
        return None
    exact = base / f"{artifact}-{version}.pom"
    if exact.is_file():
        return exact
    return next(iter(base.rglob(f"{artifact}-{version}.pom")), None)


def scanner_pom(scanner: Path, group: str, artifact: str, version: str) -> Path | None:
    if group != "dev.offlinescan":
        return None
    candidate = scanner / "maven" / group.replace(".", "/") / artifact / version / f"{artifact}-{version}.pom"
    return candidate if candidate.is_file() else None


def pom_evidence(
    cache: Path, scanner: Path, group: str, artifact: str, version: str, scanner_version: str
) -> tuple[bytes | None, str]:
    local = (scanner_pom(scanner, group, artifact, version) if group == "dev.offlinescan" else local_pom(cache, group, artifact, version))
    if local:
        return local.read_bytes(), portable_source(str(local), cache, scanner, scanner_version)
    relative = maven_path(group, artifact, version)
    for repository in repositories(group):
        data = fetch_url(f"{repository}/{relative}")
        if data is not None:
            return data, f"official repository: {repository}/{relative}"
    return None, "POM unavailable in local cache and official repositories"


def inherited_licenses(
    cache: Path, scanner: Path, group: str, artifact: str, version: str, scanner_version: str
) -> tuple[list[dict[str, str]], list[str], str, str]:
    data, source = pom_evidence(cache, scanner, group, artifact, version, scanner_version)
    if data is None:
        return [], [], source, "missing_pom"
    try:
        licenses, parent = parse_pom(data)
    except ET.ParseError as exc:
        return [], [], source + f" (invalid XML: {exc})", "invalid_pom"
    chain = [source]
    inherited = False
    seen = {(group, artifact, version)}
    while not licenses and parent:
        key = (parent["group"], parent["artifact"], parent["version"])
        if key in seen:
            break
        seen.add(key)
        pdata, psource = pom_evidence(cache, scanner, *key, scanner_version)
        if pdata is None:
            chain.append(psource)
            break
        chain.append(psource)
        try:
            licenses, parent = parse_pom(pdata)
            inherited = inherited or bool(licenses)
        except ET.ParseError:
            break
    return licenses, chain, source, "inherited" if inherited else ("declared" if licenses else "no_license_declared")


def artifact_file(cache: Path, group: str, artifact: str, version: str) -> Path | None:
    base = cache / group / artifact / version
    if not base.exists():
        return None
    files = [p for p in base.rglob("*") if p.is_file() and p.suffix.lower() in {".aar", ".jar"}]
    files.sort(key=lambda p: (p.suffix.lower() != ".aar", p.name))
    return files[0] if files else None


def find_artifact(cache: Path, scanner: Path, group: str, artifact: str, version: str) -> Path | None:
    bundled = bundled_updater_file(group, artifact, version, ".aar")
    if bundled is not None:
        return bundled
    if group == "dev.offlinescan":
        base = scanner / "maven" / group.replace(".", "/") / artifact / version
        if base.exists():
            candidates = [p for p in base.glob(f"{artifact}-{version}.*") if p.suffix.lower() in {".aar", ".jar"}]
            candidates.sort(key=lambda p: (p.suffix.lower() != ".aar", p.name))
            return candidates[0] if candidates else None
        return None
    return artifact_file(cache, group, artifact, version)


def extract_notices(archive: Path | None, coordinate: str, dest: Path) -> list[dict[str, str]]:
    if archive is None:
        return []
    key = coordinate.replace(":", "_").replace(".", "_")
    found: list[dict[str, str]] = []
    try:
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                name = info.filename.replace("\\", "/")
                scanner_notice = coordinate.startswith("dev.offlinescan:") and name.startswith(("assets/offline-scanner-notices/", "assets/third_party_licenses/"))
                if info.is_dir() or not (LICENSE_FILENAMES.search(name) or scanner_notice):
                    continue
                data = zf.read(info)
                if not data:
                    continue
                out = dest / key / PurePosixPath(name)
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(data)
                found.append({
                    "archive_entry": name,
                    "path": out.relative_to(OUTPUT).as_posix(),
                    "sha256": sha256(data),
                    "size_bytes": len(data),
                })
    except (OSError, zipfile.BadZipFile):
        return []
    return found


def preserved_license_texts(directory: Path) -> dict[str, bytes]:
    preserved = {}
    for filename, expected, _ in VETTED_LICENSE_TEXTS.values():
        path = directory / filename
        if not path.is_file():
            raise SystemExit(f"Missing vetted license text: {path}")
        data = path.read_bytes()
        if sha256(data) != expected:
            raise SystemExit(f"Vetted license text checksum mismatch: {path}")
        preserved[filename] = data
    return preserved


def license_texts(licenses: list[dict[str, str]], sources: dict[str, tuple[bytes, str]], dest: Path, coordinate: str, version: str, preserved: dict[str, bytes]) -> list[dict[str, str]]:
    resolved: list[dict[str, str]] = []
    for lic in licenses:
        name, url = lic.get("name", ""), lic.get("url", "")
        data = None
        source = ""
        lower = (name + " " + url).lower()
        if coordinate == "io.github.phillip9933:android-updater" and "affero" in lower:
            license_path = ROOT / "third_party/android-updater/LICENSE"
            pins = dict(line.split("  ", 1)[::-1] for line in (license_path.parent / "SHA256SUMS").read_text().splitlines() if line)
            raw = license_path.read_bytes()
            if sha256(raw) != pins.get("LICENSE"):
                raise SystemExit("Bundled updater license checksum mismatch")
            data, source = raw, "bundled updater / LICENSE"
        if "apache" in lower:
            raw, candidate_source = sources["apache"]
            if b"Apache License" in raw and b"Version 2.0" in raw:
                data, source = raw, candidate_source
            if data is None:
                data = fetch_url("https://www.apache.org/licenses/LICENSE-2.0.txt")
                source = "https://www.apache.org/licenses/LICENSE-2.0.txt" if data else ""
        if data is None and "libyuv" in lower:
            data, source = sources["libyuv"]
        if data is None and "mit" in lower:
            data, source = sources["onnxruntime"]
        if data is None and coordinate == "com.google.protobuf:protobuf-javalite" and version == "3.25.8":
            upstream = "https://raw.githubusercontent.com/protocolbuffers/protobuf/v25.8/LICENSE"
            raw = fetch_url(upstream)
            if raw and b"Redistribution and use in source and binary forms" in raw and b"Neither the name" in raw:
                data, source = raw, upstream
        if data is None and url:
            normalized = url.replace("http://", "https://", 1)
            data = fetch_url(normalized)
            if data and data.lstrip().lower().startswith((b"<!doctype html", b"<html")):
                data = None
            source = normalized if data else ""
        fallback = VETTED_LICENSE_TEXTS.get((coordinate, version, name))
        if fallback and (data is None or sha256(data) != fallback[1]):
            filename, expected, previous_source = fallback
            data = preserved[filename]
            if sha256(data) != expected:
                raise SystemExit(f"Vetted license text checksum mismatch: {filename}")
            source = f"preserved vetted release text (original source: {previous_source})"
        if data:
            slug = re.sub(r"[^A-Za-z0-9.-]+", "_", name or url or "license").strip("._")
            path = dest / f"{slug}.txt"
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_bytes(data)
            resolved.append({"name": name, "url": url, "path": path.relative_to(OUTPUT).as_posix(), "source": source, "sha256": sha256(data)})
    return resolved


def main() -> int:
    lock = json.loads(SCANNER_LOCK.read_text(encoding="utf-8"))
    scanner_version = lock["version"]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--scanner", type=Path, default=ROOT / ".gradle" / f"open-android-doc-scanner-{scanner_version}", help="verified SDK installer cache")
    parser.add_argument("--offline", action="store_true", help="do not fetch official POMs or license texts")
    args = parser.parse_args()
    global fetch_url
    if args.offline:
        fetch_url = lambda _url: None  # type: ignore[assignment]

    sources = scanner_release(args.scanner, lock)
    preserved = preserved_license_texts(OUTPUT / "license-texts")

    deps = json.loads(INVENTORY.read_text(encoding="utf-8"))
    if not isinstance(deps, dict):
        raise SystemExit("runtime-dependencies.json must be a coordinate-to-version object")
    if any(version != scanner_version for coordinate, version in deps.items() if coordinate.startswith("dev.offlinescan:")):
        raise SystemExit(f"Scanner inventory version differs from pinned SDK {scanner_version}")
    if (OUTPUT / "embedded").exists():
        shutil.rmtree(OUTPUT / "embedded")
    if (OUTPUT / "license-texts").exists():
        shutil.rmtree(OUTPUT / "license-texts")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    records = []
    missing_full_text: set[str] = set()
    for coordinate, version in sorted(deps.items()):
        if not isinstance(version, str) or coordinate.count(":") != 1:
            records.append({"coordinate": coordinate, "version": version, "status": "invalid_inventory_entry"})
            continue
        group, artifact = coordinate.split(":", 1)
        licenses, pom_sources, pom_source, license_status = inherited_licenses(args.cache, args.scanner, group, artifact, version, scanner_version)
        pom = scanner_pom(args.scanner, group, artifact, version) if group == "dev.offlinescan" else local_pom(args.cache, group, artifact, version)
        archive = find_artifact(args.cache, args.scanner, group, artifact, version)
        embedded = extract_notices(archive, coordinate, OUTPUT / "embedded")
        texts = license_texts(licenses, sources, OUTPUT / "license-texts", coordinate, version, preserved)
        recorded_names = {(x.get("name", "").lower(), x.get("url", "").lower()) for x in texts}
        for lic in licenses:
            if (lic.get("name", "").lower(), lic.get("url", "").lower()) not in recorded_names:
                missing_full_text.add(f"{coordinate}:{version}: {lic.get('name') or lic.get('url') or 'unnamed license'}")
        records.append({
            "coordinate": coordinate,
            "version": version,
            "pom_source": pom_source,
            "pom_chain": pom_sources,
            "pom_sha256": sha256(pom.read_bytes()) if pom else None,
            "license_status": license_status,
            "licenses": licenses,
            "artifact": portable_source(str(archive), args.cache, args.scanner, scanner_version) if archive else None,
            "artifact_sha256": sha256(archive.read_bytes()) if archive else None,
            "embedded_notice_files": embedded,
            "license_texts": texts,
        })
    report = {
        "schema_version": 1,
        "source_inventory": "docs/release-audit/runtime-dependencies.json",
        "dependency_count": len(records),
        "cache_root": "Gradle module cache at ~/.gradle/caches/modules-2/files-2.1",
        "scanner_reference": f"https://github.com/phillip9933/open-android-doc-scanner/blob/v{scanner_version}/THIRD-PARTY-NOTICES.md",
        "missing_full_license_texts": sorted(missing_full_text),
        "dependencies": records,
    }
    RUNTIME_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    lines = [
        "# Third-party notices",
        "",
        "This file records license declarations for the runtime coordinates in `docs/release-audit/runtime-dependencies.json`. POMs and artifacts are identified in the adjacent [runtime inventory](app/src/main/assets/third-party/runtime-notices/runtime-inventory.json). Full license texts and embedded upstream notices collected from the resolved artifacts are retained in that asset directory.",
        "",
        f"The scanner SDK modules are maintained in the [scanner library reference](https://github.com/phillip9933/open-android-doc-scanner/blob/v{scanner_version}/THIRD-PARTY-NOTICES.md), which documents their native build provenance and additional notices.",
        "",
        "| Coordinate | Version | Declared license(s) | Evidence status |",
        "| --- | --- | --- | --- |",
    ]
    for record in records:
        names = record.get("licenses") or []
        text_by_license = {
            (item.get("name", "").lower(), item.get("url", "").lower()): item["path"]
            for item in record.get("license_texts", [])
        }
        labels = []
        for lic in names:
            title = lic.get("name") or "unnamed license"
            text_path = text_by_license.get((lic.get("name", "").lower(), lic.get("url", "").lower()))
            if text_path:
                labels.append(f"[{title}](app/src/main/assets/third-party/runtime-notices/{text_path})")
            else:
                labels.append(title + " (full text unavailable)")
        label = "; ".join(labels) or "No license declaration found"
        if record["coordinate"].startswith("dev.offlinescan:") and names:
            label += " (Apache 2.0; see scanner notices)"
        lines.append(f"| `{record['coordinate']}` | `{record['version']}` | {label} | {record.get('license_status', 'unknown')} |")
    if missing_full_text:
        lines.extend(["", "## Missing license texts", "", "The following declared licenses did not have a full text available locally or from their official URL. The declaration is retained above; no license was inferred.", ""])
        lines.extend(f"- {item}" for item in sorted(missing_full_text))
    THIRD_PARTY_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    missing = [r for r in records if r.get("license_status") in {"missing_pom", "no_license_declared", "invalid_pom"}]
    print(f"Wrote {len(records)} dependency records; {len(missing)} lack declared POM licenses; {len(missing_full_text)} full license texts are unavailable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

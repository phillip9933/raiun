#!/usr/bin/env python3
"""Verify pinned Android native bytes and query source identities, with explicit gaps."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import zipfile
import zlib

import check_runtime_advisories as osv

HEX = re.compile(r"[a-f0-9]{64}")
ADVISORY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
NATIVE = re.compile(r"lib/(arm64-v8a|x86_64)/[^/]+\.so")
MAX_JSON = 1024 * 1024
MAX_LIBRARY = 128 * 1024 * 1024
MAX_NATIVE_TOTAL = 512 * 1024 * 1024
MAX_RESOLUTIONS = 200
MAX_RESOLUTION_EVIDENCE = 20
MAX_RESOLUTION_RATIONALE = 2000


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path):
    if path.stat().st_size > MAX_JSON:
        raise osv.CheckUnavailable("native metadata exceeds size limit")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise osv.CheckUnavailable("duplicate native metadata key")
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def require(condition, message):
    if not condition:
        raise osv.CheckUnavailable(message)


def validate_review_findings(findings, components):
    require(isinstance(findings, list) and len(findings) <= MAX_RESOLUTIONS,
            "invalid native review findings")
    keys = set()
    for finding in findings:
        require(isinstance(finding, dict), "invalid native review finding")
        component, advisory_id = finding.get("component"), finding.get("id")
        require(isinstance(component, str) and component in components,
                "unknown native review finding component")
        require(isinstance(advisory_id, str) and ADVISORY_ID.fullmatch(advisory_id),
                "invalid native review finding ID")
        key = (component, advisory_id)
        require(key not in keys, "duplicate native review finding")
        keys.add(key)
    return keys


def validate_resolutions(resolutions, data):
    if resolutions is None:
        resolutions = []
    require(isinstance(resolutions, list) and len(resolutions) <= MAX_RESOLUTIONS,
            "invalid native resolutions")
    components = data["components"]
    artifacts = data["artifacts"]
    evidence = data["evidence_files"]
    seen = set()
    validated = {}
    required_fields = {"component", "id", "status", "justification", "artifacts",
                       "evidence_files", "rationale"}
    compatible = {"fixed": "source_patch_applied",
                  "not_affected": "component_not_present"}
    for resolution in resolutions:
        require(isinstance(resolution, dict) and set(resolution) == required_fields,
                "invalid native resolution fields")
        component, advisory_id = resolution["component"], resolution["id"]
        require(isinstance(component, str) and component in components,
                "unknown native resolution component")
        require(isinstance(advisory_id, str) and ADVISORY_ID.fullmatch(advisory_id),
                "invalid native resolution ID")
        key = (component, advisory_id)
        require(key not in seen, "duplicate native resolution")
        seen.add(key)
        status, justification = resolution["status"], resolution["justification"]
        require(status in compatible and compatible[status] == justification,
                "incompatible native resolution status/justification")
        component_artifacts = components[component]["artifacts"]
        recorded_artifacts = resolution["artifacts"]
        require(isinstance(recorded_artifacts, dict) and
                set(recorded_artifacts) == set(component_artifacts),
                "native resolution artifact set mismatch")
        for coordinate in component_artifacts:
            require(recorded_artifacts[coordinate] == artifacts[coordinate]["sha256"],
                    "native resolution artifact hash mismatch")
        evidence_files = resolution["evidence_files"]
        require(isinstance(evidence_files, list) and
                0 < len(evidence_files) <= MAX_RESOLUTION_EVIDENCE and
                len(set(evidence_files)) == len(evidence_files),
                "invalid native resolution evidence list")
        for name in evidence_files:
            require(isinstance(name, str) and name not in (".", "..") and
                    Path(name).name == name and name in evidence,
                    "native resolution evidence is not hash-verified")
        rationale = resolution["rationale"]
        require(isinstance(rationale, str) and 0 < len(rationale) <= MAX_RESOLUTION_RATIONALE
                and rationale.strip() and rationale.isprintable(),
                "invalid native resolution rationale")
        validated[key] = resolution
    return validated


def make_review_summary(matches, findings, resolutions):
    observed = {(component, advisory_id)
                for component, advisory_ids in matches.items()
                for advisory_id in advisory_ids}
    observed.update((finding["component"], finding["id"]) for finding in findings)
    resolved, unresolved = [], []
    for component, advisory_id in sorted(observed):
        resolution = resolutions.get((component, advisory_id))
        if resolution is None:
            unresolved.append({"component": component, "id": advisory_id})
        else:
            resolved.append({"component": component, "id": advisory_id,
                             "status": resolution["status"],
                             "justification": resolution["justification"],
                             "rationale": resolution["rationale"],
                             "evidence_files": resolution["evidence_files"]})
    return {"resolved": resolved, "unresolved": unresolved}


def load_inventory(path, pins_path):
    data = read_json(path)
    require(isinstance(data, dict), "invalid native inventory object")
    require(data.get("schema_version") == 1, "unsupported native inventory schema")
    pins = {p["coordinate"]: p["sha256"] for p in osv.read_pins(pins_path)}
    require(isinstance(data["evidence_files"], dict), "invalid native evidence inventory")
    for relative, expected in data["evidence_files"].items():
        require(isinstance(relative, str) and isinstance(expected, str) and relative not in (".", "..") and Path(relative).name == relative and HEX.fullmatch(expected), "invalid native evidence record")
        require(digest((path.parent / relative).read_bytes()) == expected, "native source evidence hash mismatch")
    artifacts = data["artifacts"]
    require(isinstance(artifacts, dict) and 0 < len(artifacts) <= 50, "invalid native artifacts")
    components = data["components"]
    require(isinstance(components, dict) and 0 < len(components) <= 100, "invalid native components")
    for coordinate, artifact in artifacts.items():
        require(isinstance(artifact, dict), "invalid native artifact object")
        require(artifact["sha256"] == pins.get(coordinate), f"native artifact pin mismatch: {coordinate}")
    for name, component in components.items():
        require(isinstance(component, dict), "invalid native component object")
        require(isinstance(component["artifacts"], list), "invalid component artifacts")
        require(component["artifacts"] and set(component["artifacts"]) <= set(artifacts), f"unbound component: {name}")
        require(component["evidence"] and component["coverage_gap"], f"missing provenance/coverage statement: {name}")
        query = component.get("osv_query")
        if query is not None:
            require(isinstance(query, dict) and isinstance(query.get("package"), dict), "invalid native query")
            require(component.get("version") and query.get("package", {}).get("ecosystem") == "GIT", f"invalid native query identity: {name}")
            require(query["package"]["name"].startswith("https://") and query["package"]["name"].endswith(".git"), "invalid source repository")
            require(query.get("version") == component["source_tag"], f"source version/tag mismatch: {name}")
            version = component["version"]
            require(component["source_tag"] in (version, "v" + version, version + "-RELEASE"), f"component version/tag mismatch: {name}")
    validate_review_findings(data.get("review_findings"), components)
    data["validated_resolutions"] = validate_resolutions(data.get("resolutions", []), data)
    if "opencv" in components or "ndk-libcxx" in components:
        require("scanner-native-build-manifest.json" in data["evidence_files"], "missing scanner evidence hash")
        source = read_json(path.parent / "scanner-native-build-manifest.json")
        require(source["openCvVersion"] == components["opencv"]["version"], "OpenCV source version mismatch")
        require(source["ndkVersion"] == components["ndk-libcxx"]["version"], "NDK source version mismatch")
    libraries = data["libraries"]
    require(isinstance(libraries, list) and 0 < len(libraries) <= 200, "invalid native libraries")
    seen = set()
    used_artifacts = set()
    used_components = set()
    for item in libraries:
        entry = item["apk_entry"]
        require(isinstance(entry, str) and NATIVE.fullmatch(entry) and entry not in seen, "duplicate/invalid native entry")
        seen.add(entry)
        require(HEX.fullmatch(item["sha256"]) is not None, "invalid native hash")
        require(item["artifact"] in artifacts and item["components"] and set(item["components"]) <= set(components), "unbound native library")
        require(item["source_entry"] == entry.replace("lib/", "jni/", 1), "invalid AAR native entry")
        for name in item["components"]:
            require(item["artifact"] in components[name]["artifacts"], "component/artifact binding mismatch")
        used_artifacts.add(item["artifact"])
        used_components.update(item["components"])
    require(used_artifacts == set(artifacts) and used_components == set(components), "orphan native provenance")
    return data


def zip_entries(path, prefix):
    with zipfile.ZipFile(path) as archive:
        entries = {}
        total = 0
        for info in archive.infolist():
            if info.filename.startswith(prefix) and info.filename.endswith(".so"):
                require(info.filename not in entries, "duplicate native ZIP entry")
                total += info.file_size
                require(len(entries) < 200 and total <= MAX_NATIVE_TOTAL, "native ZIP inventory exceeds size/count limit")
                require(info.file_size <= MAX_LIBRARY, "native library exceeds size limit")
                require(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "unsupported native ZIP compression")
                hashed = hashlib.sha256()
                read_bytes = 0
                try:
                    with archive.open(info) as stream:
                        while chunk := stream.read(1024 * 1024):
                            read_bytes += len(chunk)
                            require(read_bytes <= MAX_LIBRARY, "native ZIP payload exceeds size limit")
                            hashed.update(chunk)
                except (RuntimeError, EOFError, zlib.error) as exc:
                    raise osv.CheckUnavailable("native ZIP member could not be decompressed") from exc
                entries[info.filename] = hashed.hexdigest()
        return entries


def verify_apk(data, apk, roots):
    expected = {i["apk_entry"]: i["sha256"] for i in data["libraries"]}
    actual = zip_entries(apk, "lib/")
    require(set(actual) == set(expected), f"native entry set mismatch: missing={sorted(set(expected)-set(actual))}, unexpected={sorted(set(actual)-set(expected))}")
    require(actual == expected, "APK native library SHA-256 mismatch")
    verified = {}
    for coordinate, artifact in data["artifacts"].items():
        group, name, version = coordinate.split(":")
        candidates = set()
        for root in roots:
            # Both conventional Gradle-cache and Maven-repository layouts. Only
            # an explicit flat root is searched directly; no whole-cache walk.
            candidates.update(root.glob("*.aar"))
            for directory in (root / group / name / version,
                              root / group.replace(".", "/") / name / version):
                if directory.is_dir():
                    candidates.update(directory.rglob("*.aar"))
        path = None
        for candidate in sorted(candidates):
            require(candidate.stat().st_size <= MAX_NATIVE_TOTAL, "AAR exceeds size limit")
            if file_digest(candidate) == artifact["sha256"]:
                path = candidate
                break
        require(path is not None, f"missing pinned AAR: {coordinate}")
        source = zip_entries(path, "jni/")
        for item in data["libraries"]:
            if item["artifact"] == coordinate:
                require(source.get(item["source_entry"]) == item["sha256"], f"AAR/APK native provenance mismatch: {item['apk_entry']}")
        verified[coordinate] = artifact["sha256"]
    return {"status": "verified", "apk_sha256": file_digest(apk), "libraries": actual, "artifacts": verified}


def query_sources(components):
    names = [name for name, c in components.items() if c.get("osv_query")]
    entries = {name: [] for name in names}
    for name in names:
        query = components[name]["osv_query"].copy()
        for _ in range(osv.MAX_PAGES_PER_PACKAGE):
            payload = osv._post_queries([query])
            result = payload["results"][0]
            require(isinstance(result, dict) and not (set(result) - {"vulns", "next_page_token"}), "malformed native advisory result")
            vulns = result.get("vulns", [])
            require(isinstance(vulns, list), "malformed native advisory list")
            for vuln in vulns:
                require(isinstance(vuln, dict) and isinstance(vuln.get("id"), str) and 0 < len(vuln["id"]) <= osv.MAX_ADVISORY_ID_CHARS and vuln["id"].isprintable(), "malformed native advisory ID")
                entries[name].append(vuln["id"])
            token = result.get("next_page_token")
            if token is None:
                break
            require(isinstance(token, str) and 0 < len(token) <= osv.MAX_PAGE_TOKEN_CHARS and token.isprintable(), "invalid native advisory page token")
            query["page_token"] = token
        else:
            raise osv.CheckUnavailable("native advisory pagination exceeded limit")
    return entries


def run(inventory, pins, apk=None, roots=(), scan=False):
    result = {"checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "inventory_sha256": file_digest(inventory), "integrity": {"status": "not_requested"}, "advisories": {"status": "not_requested"}}
    try:
        data = load_inventory(inventory, pins)
        result["metadata"] = "verified_against_runtime_pins"
        result["coverage_gaps"] = {name: c["coverage_gap"] for name, c in data["components"].items()}
        result["review_findings"] = data["review_findings"]
        result["review_summary"] = {"resolved": [], "unresolved": []}
        matches = {name: [] for name, c in data["components"].items() if c.get("osv_query")}
        if apk:
            require(bool(roots), "APK verification requires artifact roots")
            result["integrity"] = verify_apk(data, apk, roots)
        if scan:
            matches = query_sources(data["components"])
            result["advisories"] = {"status": "matches_found" if any(matches.values()) else "no_matches_in_queried_sources", "source_queries": {n: c["osv_query"] for n,c in data["components"].items() if c.get("osv_query")}, "matches": matches}
        result["review_summary"] = make_review_summary(
            matches, data["review_findings"], data["validated_resolutions"])
        result["status"] = ("attention_required" if result["review_summary"]["unresolved"]
                            else "bounded_check_complete_with_coverage_gaps")
    except (osv.CheckUnavailable, OSError, ValueError, KeyError, TypeError, AttributeError, zipfile.BadZipFile) as exc:
        result["status"] = "unavailable"
        result["error"] = str(exc)
        if scan and result["advisories"]["status"] == "not_requested":
            result["advisories"]["status"] = "unavailable"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--pins", type=Path, required=True)
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--artifact-root", type=Path, action="append", default=[])
    parser.add_argument("--scan", action="store_true", help="Query OSV source identities; errors fail closed")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run(args.inventory, args.pins, args.apk, args.artifact_root, args.scan)
    except OSError as exc:
        result = {"status": "unavailable", "error": str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    print(f"Native dependency check: {result['status']}; see {args.output}")
    # Inventory integrity is useful independently of advisory triage. A scan fails
    # on known findings, while an integrity-only check reports them without hiding them.
    return 2 if result["status"] == "unavailable" else (1 if args.scan and result["status"] == "attention_required" else 0)


if __name__ == "__main__":
    raise SystemExit(main())

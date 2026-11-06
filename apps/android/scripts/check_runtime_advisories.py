#!/usr/bin/env python3
"""Check the pinned Android runtime Maven coordinates against public OSV data."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

OSV_URL = "https://api.osv.dev/v1/querybatch"
MAX_PACKAGES = 500
MAX_PAGES_PER_PACKAGE = 8
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_PIN_FILE_BYTES = 256 * 1024
MAX_ADVISORY_ID_CHARS = 256
MAX_PAGE_TOKEN_CHARS = 8 * 1024
TIMEOUT_SECONDS = 20
PIN_LINE = re.compile(r"^([0-9a-fA-F]{64})\s+([^:\s]+):([^:\s]+):([^:\s]+)$")


class CheckUnavailable(Exception):
    """The inventory or OSV response could not be checked completely."""


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CheckUnavailable("OSV redirects are not accepted")


OSV_OPENER = urllib.request.build_opener(RejectRedirects())


def read_pins(path: Path) -> list[dict[str, str]]:
    if path.stat().st_size > MAX_PIN_FILE_BYTES:
        raise CheckUnavailable("runtime pin inventory exceeds the size limit")
    by_coordinate: dict[str, str] = {}
    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = PIN_LINE.fullmatch(line)
        if not match:
            raise CheckUnavailable(f"invalid pin record on line {number}")
        digest, group, artifact, version = match.groups()
        if max(len(group), len(artifact), len(version)) > 256:
            raise CheckUnavailable(f"coordinate on line {number} exceeds the length limit")
        coordinate = f"{group}:{artifact}:{version}"
        digest = digest.lower()
        previous = by_coordinate.get(coordinate)
        if previous is not None and previous != digest:
            raise CheckUnavailable(f"conflicting hashes for {coordinate}")
        by_coordinate[coordinate] = digest
    if not by_coordinate:
        raise CheckUnavailable("runtime pin inventory is empty")
    if len(by_coordinate) > MAX_PACKAGES:
        raise CheckUnavailable(f"runtime pin inventory exceeds {MAX_PACKAGES} packages")
    return [
        {"coordinate": coordinate, "sha256": digest}
        for coordinate, digest in sorted(by_coordinate.items())
    ]


def _post_queries(queries: list[dict[str, object]]) -> dict[str, object]:
    body = json.dumps({"queries": queries}, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_REQUEST_BYTES:
        raise CheckUnavailable("OSV request exceeded the size limit")
    request = urllib.request.Request(
        OSV_URL,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with OSV_OPENER.open(request, timeout=TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise CheckUnavailable("OSV returned an unexpected HTTP status")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        raise CheckUnavailable("OSV request failed") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise CheckUnavailable("OSV response exceeded the size limit")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CheckUnavailable("OSV returned malformed JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise CheckUnavailable("OSV response has no results list")
    if set(payload) != {"results"}:
        raise CheckUnavailable("OSV response contains unexpected fields")
    if len(payload["results"]) != len(queries):
        raise CheckUnavailable("OSV result count does not match the query count")
    return payload


def query_osv(packages: list[dict[str, str]]) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for package in packages:
        entries.append(
            {
                "coordinate": package["coordinate"],
                "sha256": package["sha256"],
                "advisories": [],
            }
        )
    pending = list(range(len(entries)))
    tokens: dict[int, str] = {}
    page_counts = [0] * len(entries)
    while pending:
        queries: list[dict[str, object]] = []
        for index in pending:
            group, artifact, version = entries[index]["coordinate"].split(":", 2)
            query: dict[str, object] = {
                "package": {"ecosystem": "Maven", "name": f"{group}:{artifact}"},
                "version": version,
            }
            if index in tokens:
                query["page_token"] = tokens[index]
            queries.append(query)
            page_counts[index] += 1
            if page_counts[index] > MAX_PAGES_PER_PACKAGE:
                raise CheckUnavailable("OSV pagination exceeded the page limit")
        payload = _post_queries(queries)
        next_pending: list[int] = []
        for index, result in zip(pending, payload["results"], strict=True):
            if not isinstance(result, dict):
                raise CheckUnavailable("OSV result entry is malformed")
            if set(result) - {"vulns", "next_page_token"}:
                raise CheckUnavailable("OSV result entry contains unexpected fields")
            vulns = result.get("vulns", [])
            if not isinstance(vulns, list):
                raise CheckUnavailable("OSV vulnerability list is malformed")
            for vuln in vulns:
                if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str):
                    raise CheckUnavailable("OSV advisory entry is malformed")
                advisory_id = vuln["id"]
                if not advisory_id.strip() or len(advisory_id) > MAX_ADVISORY_ID_CHARS or not advisory_id.isprintable():
                    raise CheckUnavailable("OSV advisory identifier is malformed")
                advisory = {"id": vuln["id"]}
                if isinstance(vuln.get("summary"), str):
                    advisory["summary"] = vuln["summary"]
                if isinstance(vuln.get("modified"), str):
                    advisory["modified"] = vuln["modified"]
                entries[index]["advisories"].append(advisory)
            token = result.get("next_page_token")
            if token is not None:
                if (
                    not isinstance(token, str)
                    or not token
                    or len(token) > MAX_PAGE_TOKEN_CHARS
                    or not token.isprintable()
                ):
                    raise CheckUnavailable("OSV pagination token is malformed")
                tokens[index] = token
                next_pending.append(index)
            else:
                tokens.pop(index, None)
        pending = next_pending
    return entries


def run(pins_path: Path) -> dict[str, object]:
    checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    scope = {
        "source": "gradle/runtime-artifact-pins.sha256",
        "ecosystem": "Maven",
        "coverage": "OSV advisories for pinned runtime coordinates and original upstream inputs retained for native-only backports",
        "excludes": [
            "scanner/updater bundled implementation and source behavior",
            "native libraries, model assets, and embedded non-Maven components",
            "build and test dependencies not present in the runtime pin inventory",
        ],
    }
    try:
        packages = read_pins(pins_path)
        entries = query_osv(packages)
    except (CheckUnavailable, OSError, UnicodeError) as exc:
        return {
            "status": "unavailable",
            "checked_at": checked_at,
            "scope": scope,
            "error": str(exc),
        }
    advisory_count = sum(len(entry["advisories"]) for entry in entries)
    return {
        "status": "advisories_found" if advisory_count else "no_advisories",
        "checked_at": checked_at,
        "scope": scope,
        "package_count": len(entries),
        "advisory_count": advisory_count,
        "packages": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pins", type=Path, required=True, help="runtime-artifact-pins.sha256 path")
    parser.add_argument("--output", type=Path, required=True, help="JSON results path")
    args = parser.parse_args()
    result = run(args.pins)
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        print("Unable to write advisory results", file=sys.stderr)
        return 2
    status = result["status"]
    if status == "unavailable":
        print(f"Runtime advisory check unavailable: {result['error']}", file=sys.stderr)
        return 2
    if status == "advisories_found":
        print(f"OSV reported {result['advisory_count']} advisory match(es) across pinned runtime packages.")
        return 1
    print(f"No OSV advisory matches across {result['package_count']} pinned runtime packages.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Verify the unsigned Raiun Play bundle without signing or installing it."""

import argparse
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from zipfile import ZipFile

ANDROID = "{http://schemas.android.com/apk/res/android}"
PACKAGE = "app.raiun.cloud"


def verify_manifest(manifest_text, version_name, version_code):
    manifest = ET.fromstring(manifest_text)
    if manifest.get("package") != PACKAGE:
        raise ValueError("Wrong application ID")
    if manifest.get(ANDROID + "versionName") != version_name:
        raise ValueError("Wrong version name")
    if manifest.get(ANDROID + "versionCode") != version_code:
        raise ValueError("Wrong version code")
    sdk = manifest.find("uses-sdk")
    if sdk is None or sdk.get(ANDROID + "minSdkVersion") != "31" or sdk.get(ANDROID + "targetSdkVersion") != "36":
        raise ValueError("Expected minimum API 31 and target API 36")

    for element in manifest.iter():
        name = element.get(ANDROID + "name", "")
        authorities = element.get(ANDROID + "authorities", "").split(";")
        if name == "android.permission.REQUEST_INSTALL_PACKAGES":
            raise ValueError("Play bundle requests APK installation")
        if name.startswith("io.github.phillip9933.appupdater.") or PACKAGE + ".android-updates" in authorities:
            raise ValueError("Play bundle contains an APK updater component")


def verify_elf_alignment(zip_file, entries):
    with tempfile.TemporaryDirectory() as directory:
        scratch_file = Path(directory) / "library.so"
        for entry in entries:
            scratch_file.write_bytes(zip_file.read(entry))
            headers = subprocess.check_output(["readelf", "-lW", str(scratch_file)], text=True)
            alignments = [
                int(line.split()[-1], 16) for line in headers.splitlines()
                if line.split() and line.split()[0] == "LOAD"
            ]
            if not alignments or any(alignment < 0x4000 for alignment in alignments):
                raise ValueError(f"Expected 16 KiB ELF load alignment: {entry}")


def verify_archive(bundle):
    with ZipFile(bundle) as zip_file:
        entries = zip_file.namelist()
        manifests = [name for name in entries if name.endswith("/manifest/AndroidManifest.xml")]
        if manifests != ["base/manifest/AndroidManifest.xml"]:
            raise ValueError("Unexpected bundle module manifest layout")
        if any(re.fullmatch(r"META-INF/(?:[^/]+\.(?:SF|RSA|DSA|EC)|SIG-[^/]+)", name, re.I) for name in entries):
            raise ValueError("Expected an unsigned validation bundle")
        dex_files = [name for name in entries if re.fullmatch(r"base/dex/classes\d*\.dex", name)]
        if not dex_files:
            raise ValueError("Bundle contains no application classes")
        if any(b"Lio/github/phillip9933/appupdater/" in zip_file.read(name) for name in dex_files):
            raise ValueError("Play bundle contains APK updater classes")
        libraries = [name for name in entries if re.fullmatch(r"base/lib/[^/]+/[^/]+\.so", name)]
        if {name.split("/")[2] for name in libraries} != {"arm64-v8a", "x86_64"}:
            raise ValueError("Expected native libraries for arm64-v8a and x86_64")
        verify_elf_alignment(zip_file, libraries)
        return len(libraries)


def read_checked_version():
    gradle_source = (Path(__file__).resolve().parents[1] / "app/build.gradle.kts").read_text(encoding="utf-8")
    names = re.findall(r'^[ \t]*versionName = "([^"]+)"$', gradle_source, re.M)
    codes = re.findall(r"^val appVersionCode = ([1-9]\d*)$", gradle_source, re.M)
    if len(names) != 1 or len(codes) != 1:
        raise ValueError("Could not identify a single release version in the Android build")
    return names[0], codes[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--bundletool", type=Path, required=True)
    args = parser.parse_args()
    tool = ["java", "-jar", str(args.bundletool)]
    bundle_arg = f"--bundle={args.bundle}"
    name, code = read_checked_version()
    subprocess.run([*tool, "validate", bundle_arg], check=True)
    manifest = subprocess.check_output([*tool, "dump", "manifest", bundle_arg, "--module=base"], text=True)
    verify_manifest(manifest, name, code)
    config = subprocess.check_output([*tool, "dump", "config", bundle_arg], text=True)
    if "PAGE_ALIGNMENT_16K" not in config:
        raise ValueError("Bundle does not request 16 KiB ZIP alignment for generated APKs")
    libraries = verify_archive(args.bundle)
    print(f"Verified unsigned Raiun {name} ({code}); {libraries} native libraries pass 16 KiB ELF alignment.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, ET.ParseError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"Play bundle check failed: {error}") from error

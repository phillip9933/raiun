#!/usr/bin/env python3
"""Generate manifest-only APKs signed for the current debug Android test build.

These are synthetic instrumentation assets, not release artifacts. The matching
signer is Gradle's default debug keystore; the other signer is a disposable key.
"""

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from xml.sax.saxutils import escape


VERSION = "99.0.0"


def sdk_directory(project: Path) -> Path:
    for variable in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        if os.environ.get(variable):
            candidate = Path(os.environ[variable]).expanduser()
            if candidate.is_dir():
                return candidate
    properties = project / "local.properties"
    if properties.is_file():
        for line in properties.read_text(encoding="utf-8").splitlines():
            if line.startswith("sdk.dir="):
                candidate = Path(line.partition("=")[2].replace("\\:", ":").replace("\\\\", "\\"))
                if candidate.is_dir():
                    return candidate
    candidate = Path.home() / "Android" / "Sdk"
    if candidate.is_dir():
        return candidate
    raise SystemExit("Android SDK not found; set ANDROID_HOME or sdk.dir in local.properties")


def newest(directory: Path, required: tuple[str, ...]) -> Path:
    candidates = [
        item for item in directory.iterdir()
        if item.is_dir() and all((item / name).is_file() for name in required)
    ]
    if not candidates:
        raise SystemExit(f"No usable Android SDK installation under {directory}")
    return max(candidates, key=lambda item: tuple(int(part) for part in re.findall(r"\d+", item.name)))


def run(*arguments: str, env: dict[str, str] | None = None) -> None:
    subprocess.run(arguments, check=True, env=env, stdout=subprocess.DEVNULL)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--java-home", required=True, type=Path)
    parser.add_argument("--keystore", required=True, type=Path)
    parser.add_argument("--key-alias", required=True)
    parser.add_argument("--application-id", required=True)
    parser.add_argument("--installed-code", required=True, type=int)
    parser.add_argument("--min-sdk", required=True, type=int)
    parser.add_argument("--compile-sdk", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.installed_code <= 0 or args.min_sdk < 1:
        parser.error("version code and minimum SDK must be positive")
    if not args.keystore.is_file():
        raise SystemExit("Gradle's default debug keystore is missing")
    if os.environ.get("FIXTURE_STORE_PASSWORD") != "android":
        raise SystemExit("Only the standard Android debug-key password is supported")

    sdk = sdk_directory(args.project)
    executable_suffix = ".exe" if os.name == "nt" else ""
    java = args.java_home / "bin" / f"java{executable_suffix}"
    keytool = args.java_home / "bin" / f"keytool{executable_suffix}"
    if not java.is_file() or not keytool.is_file():
        raise SystemExit("The Gradle JDK must include java and keytool")
    tools = newest(sdk / "build-tools", (f"aapt{executable_suffix}", "lib/apksigner.jar"))
    apksigner = tools / "lib" / "apksigner.jar"
    platform_jar = sdk / "platforms" / f"android-{args.compile_sdk}" / "android.jar"
    if not platform_jar.is_file():
        raise SystemExit(f"Compile SDK platform is missing: android-{args.compile_sdk}")
    environment = os.environ.copy()
    args.output.mkdir(parents=True, exist_ok=True)
    specs = {
        "valid-higher.apk": (args.application_id, args.installed_code + 1, False, False),
        "wrong-package.apk": (args.application_id + ".other", args.installed_code + 1, False, False),
        "old-version.apk": (args.application_id, args.installed_code, False, False),
        "debuggable.apk": (args.application_id, args.installed_code + 1, True, False),
        "wrong-signer.apk": (args.application_id, args.installed_code + 1, False, True),
    }
    with tempfile.TemporaryDirectory(prefix="raiun-updater-test-") as directory:
        work = Path(directory)
        wrong_key = work / "wrong-signer.jks"
        run(
            str(keytool), "-genkeypair", "-keystore", str(wrong_key),
            "-storepass:env", "FIXTURE_STORE_PASSWORD", "-keypass:env", "FIXTURE_STORE_PASSWORD",
            "-alias", "wrong-signer", "-keyalg", "RSA", "-keysize", "2048", "-validity", "3650",
            "-dname", "CN=Synthetic Updater Fixture,O=Raiun Tests,C=ZZ", env=environment,
        )
        for name, (package, code, debuggable, different_signer) in specs.items():
            manifest = work / "AndroidManifest.xml"
            manifest.write_text(
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                f'package="{escape(package)}" android:versionCode="{code}" '
                f'android:versionName="{VERSION}">'
                f'<uses-sdk android:minSdkVersion="{args.min_sdk}" android:targetSdkVersion="35"/>'
                f'<application android:hasCode="false" android:debuggable="{str(debuggable).lower()}"/>'
                '</manifest>\n', encoding="utf-8",
            )
            unsigned = work / "unsigned.apk"
            run(str(tools / f"aapt{executable_suffix}"), "package", "-f", "-M", str(manifest),
                "-I", str(platform_jar), "-F", str(unsigned))
            signed = work / name
            keystore = wrong_key if different_signer else args.keystore
            alias = "wrong-signer" if different_signer else args.key_alias
            run(
                str(java), "-jar", str(apksigner), "sign", "--ks", str(keystore),
                "--ks-key-alias", alias, "--ks-pass", "env:FIXTURE_STORE_PASSWORD",
                "--key-pass", "env:FIXTURE_STORE_PASSWORD", "--v1-signing-enabled", "true",
                "--v2-signing-enabled", "true", "--v4-signing-enabled", "false",
                "--out", str(signed), str(unsigned), env=environment,
            )
            run(str(java), "-jar", str(apksigner), "verify", "--min-sdk-version", str(args.min_sdk), str(signed))
            shutil.copyfile(signed, args.output / name)
            print(f"{name}: {signed.stat().st_size} synthetic bytes")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Build framework-only two-phase unshrunk-to-minified synthetic upgrade fixture.

Does not build/install/run target or alter keep rules. Use seed against empty,
disposable baseline code53; stop target immediately and replace with code>53,
then install mapped fixture and run verify. Baseline work has a 90-second delay.
Only existing standard Android debug signing material is supported.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import zipfile

from generate_updater_test_apks import newest, run, sdk_directory

PACKAGE = "app.raiun.test.r8recovery"
HOLDERS = {
    "eu.opencloud.android.next.core.security.KeystoreCredentialStore": {"<init>", "readBasicPassword", "saveBasicCredentials"},
    "eu.opencloud.android.next.core.database.FileBrowserDatabase": {"instance"},
    "androidx.room.RoomDatabase": {"getOpenHelper"},
    "androidx.sqlite.db.SupportSQLiteOpenHelper": {"getWritableDatabase"},
}


def symbols(mapping: Path | None) -> dict[str, str]:
    """Resolve exact names and moved holders; never invent an optimized signature.

R8 may merge KeystoreCredentialStore into another live class. Qualified records
are accepted only if their residual method name matches the needed method
shape at runtime. Ambiguity is explicitly unsupported, never a fixture pass.
"""
    if mapping is None:
        return {}
    classes: dict[str, str] = {}
    candidates: dict[str, set[tuple[str, str]]] = {}
    original_holder = residual_holder = ""
    for line in mapping.read_text().splitlines():
        if line and not line[0].isspace() and not line.startswith("#"):
            match = re.fullmatch(r"(.+) -> (.+):", line)
            if match:
                original_holder, residual_holder = match.groups()
                classes[original_holder] = residual_holder
        elif original_holder and " -> " in line and not line.lstrip().startswith("#"):
            original, residual = line.strip().rsplit(" -> ", 1)
            original = re.sub(r"^\d+:\d+:", "", original)
            member = original.split("(", 1)[0].rsplit(" ", 1)[-1]
            owner = original_holder
            if "." in member:
                owner, member = member.rsplit(".", 1)
            if owner not in HOLDERS or member not in HOLDERS[owner]:
                continue
            if member == "<init>" and residual != "<init>":
                continue  # An inlined constructor inside an unrelated method is not callable.
            candidates.setdefault(owner + "#" + member, set()).add((residual_holder, residual))
    result = {holder: classes[holder] for holder in HOLDERS if holder in classes and "REMOVED" not in classes[holder]}
    for key, values in candidates.items():
        if len(values) == 1:
            holder, name = next(iter(values))
            result[key] = name
            result[key + "@holder"] = holder
            result.setdefault(key.split("#")[0], holder)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--java-home", required=True, type=Path)
    parser.add_argument("--keystore", required=True, type=Path)
    parser.add_argument("--key-alias", required=True)
    parser.add_argument("--compile-sdk", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--mapping", type=Path)
    args = parser.parse_args()
    if os.environ.get("FIXTURE_STORE_PASSWORD") != "android" or args.key_alias != "androiddebugkey":
        raise SystemExit("Only the existing standard Android debug key is supported")
    if not args.keystore.is_file():
        raise SystemExit("Existing standard debug key is missing")
    sdk = sdk_directory(args.project)
    tools = newest(sdk / "build-tools", ("aapt", "zipalign", "lib/apksigner.jar", "lib/d8.jar"))
    platform = sdk / "platforms" / f"android-{args.compile_sdk}" / "android.jar"
    java = args.java_home / "bin/java"
    javac = args.java_home / "bin/javac"
    if not platform.is_file():
        raise SystemExit("Compile SDK missing")
    args.output.mkdir(parents=True, exist_ok=True)
    resolved = symbols(args.mapping)
    literal = "{" + ",".join("{" + json.dumps(k) + "," + json.dumps(v) + "}" for k, v in sorted(resolved.items())) + "}"
    template = Path(__file__).parent / "r8_recovery_fixture/R8RecoveryInstrumentation.java"
    source = template.read_text().replace("__SYMBOLS__", literal).replace("__MAPPED__", str(args.mapping is not None).lower())
    with tempfile.TemporaryDirectory(prefix="raiun-r8-recovery-") as directory:
        work = Path(directory)
        src = work / "R8RecoveryInstrumentation.java"
        src.write_text(source)
        classes, dex = work / "classes", work / "dex"
        classes.mkdir()
        dex.mkdir()
        run(str(javac), "-source", "8", "-target", "8", "-bootclasspath", str(platform), "-d", str(classes), str(src))
        run(str(java), "-cp", str(tools / "lib/d8.jar"), "com.android.tools.r8.D8", "--min-api", "26", "--lib", str(platform), "--output", str(dex), *map(str, sorted(classes.rglob("*.class"))))
        manifest = work / "AndroidManifest.xml"
        manifest.write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            f'package="{PACKAGE}" android:versionCode="1" android:versionName="1">'
            '<uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35"/>'
            '<application android:label="Synthetic R8 recovery fixture" android:debuggable="true" android:allowBackup="false"/>'
            f'<instrumentation android:name="{PACKAGE}.R8RecoveryInstrumentation" android:targetPackage="app.raiun.cloud" android:functionalTest="true"/>'
            '</manifest>'
        )
        unsigned, aligned = work / "unsigned.apk", work / "aligned.apk"
        run(str(tools / "aapt"), "package", "-f", "-M", str(manifest), "-I", str(platform), "-F", str(unsigned))
        with zipfile.ZipFile(unsigned, "a") as apk:
            apk.write(dex / "classes.dex", "classes.dex")
        run(str(tools / "zipalign"), "-f", "4", str(unsigned), str(aligned))
        result = args.output / "r8-recovery-fixture.apk"
        run(str(java), "-jar", str(tools / "lib/apksigner.jar"), "sign", "--ks", str(args.keystore), "--ks-key-alias", args.key_alias, "--ks-pass", "env:FIXTURE_STORE_PASSWORD", "--key-pass", "env:FIXTURE_STORE_PASSWORD", "--out", str(result), str(aligned))
        run(str(java), "-jar", str(tools / "lib/apksigner.jar"), "verify", str(result))
        (args.output / "recovery-fixture.json").write_text(json.dumps({
            "apk_sha256": hashlib.sha256(result.read_bytes()).hexdigest(),
            "mapping_sha256": hashlib.sha256(args.mapping.read_bytes()).hexdigest() if args.mapping else None,
            "source_sha256": hashlib.sha256(template.read_bytes()).hexdigest(),
            "symbols": resolved,
            "boundary": "Only framework classes packaged; no target keep roots. Seed requires empty disposable baseline code53. Verify requires higher code, different PID, real Room/Keystore APIs, cold recovered WorkSpecs and deterministic local transfer rejection before network. Unsupported residual shape is not pass.",
        }, indent=2) + "\n")


if __name__ == "__main__":
    main()

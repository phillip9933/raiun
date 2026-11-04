#!/usr/bin/env python3
"""Build, inventory, and run the opt-in minimized-app instrumentation suite.

The runner accepts only an explicitly named Android emulator whose AVD and API
match the arguments. It preserves the standalone APK/mapping before building
the instrumented variant and retains every command log, including failures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path


APP_ID = "app.raiun.cloud"
TEST_RUNNER = "app.raiun.cloud.test/androidx.test.runner.AndroidJUnitRunner"
ABI_RULES = "r8-test-abi.pro"
MAX_TIMEOUT_SECONDS = 4 * 60 * 60


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def run_logged(name: str, argv: list[str], log_path: Path, env: dict[str, str], timeout: int) -> str:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, errors="replace", env=env, timeout=timeout, check=False)
        output = result.stdout or ""
        timed_out = False
        code = result.returncode
    except subprocess.TimeoutExpired as error:
        raw = error.stdout or ""
        output = raw.decode(errors="replace") if isinstance(raw, bytes) else raw
        timed_out = True
        code = None
    log_path.write_text(
        json.dumps({"step": name, "argv": argv, "exit_code": code, "timed_out": timed_out,
                    "timeout_seconds": timeout, "elapsed_seconds": round(time.monotonic() - start, 3)}, indent=2)
        + "\n--- output ---\n" + output
    )
    if timed_out:
        raise TimeoutError(f"{name} exceeded {timeout}s; details preserved in {log_path}")
    if code != 0:
        raise RuntimeError(f"{name} failed with exit code {code}; details preserved in {log_path}")
    return output


def adb_command(adb: Path, serial: str, *args: str) -> list[str]:
    return [str(adb), "-s", serial, *args]


def checked_output(argv: list[str], env: dict[str, str], timeout: int = 30) -> str:
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            errors="replace", env=env, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(argv)}\n{result.stdout}")
    return result.stdout.strip()


def validate_emulator(adb: Path, serial: str, expected_avd: str, api: int,
                      env: dict[str, str]) -> dict[str, str]:
    if not serial.startswith("emulator-"):
        raise ValueError("Refusing non-emulator serial; use an emulator-<port> serial")
    state = checked_output(adb_command(adb, serial, "get-state"), env)
    if state != "device":
        raise ValueError(f"ADB device state is {state!r}, expected 'device'")
    avd_output = checked_output(adb_command(adb, serial, "emu", "avd", "name"), env)
    avd_names = [line.strip() for line in avd_output.splitlines()
                 if line.strip() and line.strip() not in ("OK",)]
    actual_avd = avd_names[-1] if avd_names else ""
    if actual_avd != expected_avd:
        raise ValueError(f"Connected AVD is {actual_avd!r}, expected {expected_avd!r}")
    actual_api = checked_output(adb_command(adb, serial, "shell", "getprop", "ro.build.version.sdk"), env)
    if actual_api != str(api):
        raise ValueError(f"Emulator API is {actual_api!r}, expected {api}")
    qemu = checked_output(adb_command(adb, serial, "shell", "getprop", "ro.kernel.qemu"), env)
    if qemu != "1":
        raise ValueError(f"Emulator safety property ro.kernel.qemu is {qemu!r}, expected '1'")
    return {"serial": serial, "avd": actual_avd, "api": actual_api, "qemu": qemu}


def preserve_file(source: Path, destination: Path, required: bool = True) -> dict | None:
    if not source.is_file():
        if required:
            raise FileNotFoundError(f"Required build output missing: {source}")
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return {"source": str(source.resolve()), "path": str(destination.resolve()),
            "bytes": destination.stat().st_size, "sha256": sha256(destination)}


def parse_instrumentation(output: str) -> dict[str, int | str]:
    status_codes = [int(value) for value in re.findall(r"INSTRUMENTATION_STATUS_CODE:\s*(-?\d+)", output)]
    count_matches = [int(value) for value in re.findall(r"INSTRUMENTATION_STATUS:\s*numtests=(\d+)", output)]
    summary = re.search(r"OK\s*\((\d+) tests?\)", output)
    if summary:
        total = int(summary.group(1))
    else:
        detailed = re.search(r"Tests run:\s*(\d+),\s*Failures:\s*(\d+),\s*Errors:\s*(\d+)(?:,\s*Skipped:\s*(\d+))?", output)
        total = int(detailed.group(1)) if detailed else (max(count_matches) if count_matches else 0)
    failures = sum(code in (-1, -2) for code in status_codes)
    skipped = sum(code in (-3, -4) for code in status_codes)
    if not failures:
        detailed = re.search(r"Tests run:\s*\d+,\s*Failures:\s*(\d+),\s*Errors:\s*(\d+)", output)
        if detailed:
            failures = int(detailed.group(1)) + int(detailed.group(2))
    passed = status_codes.count(0)
    complete = bool(summary and re.search(r"(?m)^INSTRUMENTATION_CODE:\s*-1\s*$", output)
                    and passed + skipped + failures == total)
    return {"tests": total, "passed": passed, "failures": failures, "skipped": skipped, "complete": complete,
            "instrumentation_status_codes": len(status_codes)}


def gradle_base(project: Path, offline: bool) -> list[str]:
    command = [str(project / "gradlew")]
    if offline:
        command.append("--offline")
    return command


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, type=Path, help="Android Gradle project root")
    parser.add_argument("--output", required=True, type=Path, help="New, empty evidence directory")
    parser.add_argument("--java-home", required=True, type=Path, help="JDK used by Gradle and TraceReferences")
    parser.add_argument("--sdk", required=True, type=Path, help="Android SDK root")
    parser.add_argument("--serial", required=True, help="Explicit emulator serial, for example emulator-5554")
    parser.add_argument("--expected-avd", required=True, help="Exact AVD name expected on the serial")
    parser.add_argument("--api", required=True, type=int, choices=(26, 35), help="Expected emulator SDK/API level")
    parser.add_argument("--offline", action="store_true", help="Pass Gradle --offline to every Gradle phase")
    parser.add_argument("--timeout-seconds", type=int, default=30 * 60,
                        help="Maximum duration for each build/instrumentation phase (default: 1800)")
    args = parser.parse_args()
    project, output = args.project.resolve(), args.output.resolve()
    java_home, sdk = args.java_home.resolve(), args.sdk.resolve()
    if not 60 <= args.timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError(f"--timeout-seconds must be between 60 and {MAX_TIMEOUT_SECONDS}")
    if not (project / "gradlew").is_file() or not os.access(project / "gradlew", os.X_OK):
        raise FileNotFoundError(f"Gradle wrapper missing or not executable: {project / 'gradlew'}")
    if not (java_home / "bin/java").is_file():
        raise FileNotFoundError(f"Java executable missing: {java_home / 'bin/java'}")
    adb = sdk / "platform-tools" / "adb"
    if not adb.is_file():
        raise FileNotFoundError(f"ADB missing: {adb}")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError(f"Evidence directory must be new/empty; preserving existing contents: {output}")
    env = os.environ.copy()
    env.update({"JAVA_HOME": str(java_home), "ANDROID_HOME": str(sdk), "ANDROID_SDK_ROOT": str(sdk)})
    result: dict = {"status": "running", "project": str(project), "output": str(output),
                    "emulator": None, "phases": {}, "artifacts": {}}
    results_path = output / "RESULTS.json"
    try:
        result["emulator"] = validate_emulator(adb, args.serial, args.expected_avd, args.api, env)
        gradle = gradle_base(project, args.offline)
        bootstrap = gradle + ["-Praiun.r8Validation=true", ":app:verifyR8ValidationRuntimeArtifacts",
                              ":app:assembleR8Validation", ":app:assembleR8ValidationAndroidTest"]
        run_logged("bootstrap_standalone", bootstrap, output / "logs/bootstrap-standalone.log", env,
                   args.timeout_seconds)
        result["phases"]["bootstrap_standalone"] = "passed"

        standalone_apk = preserve_file(project / "app/build/outputs/apk/r8Validation/app-r8Validation.apk",
                                      output / "standalone/app-r8Validation.apk")
        result["artifacts"]["standalone_apk"] = standalone_apk
        for name in ("mapping.txt", "configuration.txt", "seeds.txt", "usage.txt", "resources.txt"):
            record = preserve_file(project / f"app/build/outputs/mapping/r8Validation/{name}",
                                   output / f"standalone/mapping/{name}", required=(name in ("mapping.txt", "configuration.txt")))
            if record:
                result["artifacts"][f"standalone_{name}"] = record

        inventory_dir = output / "inventory"
        inventory_dir.mkdir()
        init_script = project / "scripts/inventory_r8_test_abi.init.gradle"
        inventory = gradle + ["-Praiun.r8Validation=true", "-I", str(init_script),
                              f"-Praiun.inventoryOutput={inventory_dir / 'resolved-artifacts.json'}",
                              ":app:traceClassfileInventory"]
        run_logged("inventory_classfiles", inventory, output / "logs/inventory-classfiles.log", env,
                   args.timeout_seconds)
        result["phases"]["inventory_classfiles"] = "passed"

        prepare = [sys.executable, str(project / "scripts/prepare_r8_test_abi.py"),
                   "--project", str(project), "--output", str(inventory_dir),
                   "--java-home", str(java_home), "--sdk", str(sdk)]
        run_logged("prepare_test_abi", prepare, output / "logs/prepare-test-abi.log", env,
                   args.timeout_seconds)
        result["phases"]["prepare_test_abi"] = "passed"
        rules = inventory_dir / ABI_RULES
        if not rules.is_file():
            raise FileNotFoundError(f"Prepared test ABI rules missing: {rules}")

        instrumented_build = gradle + ["-Praiun.r8Validation=true", "-Praiun.r8Instrumentation=true",
                                       f"-Praiun.r8TestAbiRules={rules}",
                                       ":app:verifyR8ValidationRuntimeArtifacts",
                                       ":app:assembleR8Validation", ":app:assembleR8ValidationAndroidTest"]
        run_logged("build_instrumented_apks", instrumented_build,
                   output / "logs/build-instrumented-apks.log", env, args.timeout_seconds)
        result["phases"]["build_instrumented_apks"] = "passed"
        target = preserve_file(project / "app/build/outputs/apk/r8Validation/app-r8Validation.apk",
                               output / "instrumented/app-r8Validation.apk")
        test_apk = preserve_file(project / "app/build/outputs/apk/androidTest/r8Validation/app-r8Validation-androidTest.apk",
                                 output / "instrumented/app-r8Validation-androidTest.apk")
        result["artifacts"]["instrumented_app_apk"] = target
        result["artifacts"]["instrumentation_apk"] = test_apk
        if target["sha256"] == standalone_apk["sha256"]:
            raise ValueError("Instrumented target APK hash equals the preserved standalone APK hash")

        # Recheck immediately before any install, so a changed/disconnected device cannot inherit the earlier check.
        result["emulator"] = validate_emulator(adb, args.serial, args.expected_avd, args.api, env)
        run_logged("install_target_apk", adb_command(adb, args.serial, "install", "-r", str(output / "instrumented/app-r8Validation.apk")),
                   output / "logs/install-target.log", env, 5 * 60)
        run_logged("install_test_apk", adb_command(adb, args.serial, "install", "-r", str(output / "instrumented/app-r8Validation-androidTest.apk")),
                   output / "logs/install-test.log", env, 5 * 60)
        result["phases"]["install_apks"] = "passed"

        private_output = f"/data/user/0/{APP_ID}/cache/raiun-r8-native-checks"
        instrumentation = adb_command(adb, args.serial, "shell", "am", "instrument", "-w", "-r",
                                      "-e", "additionalTestOutputDir", private_output, TEST_RUNNER)
        test_output = run_logged("instrumentation_suite", instrumentation,
                                 output / "logs/instrumentation-suite.log", env, args.timeout_seconds)
        counts = parse_instrumentation(test_output)
        result["instrumentation"] = {**counts, "private_output_directory": private_output,
                                     "runner": TEST_RUNNER}
        if counts["tests"] == 0:
            raise ValueError("Instrumentation output contained no parseable executed-test count")
        if counts["passed"] == 0 or counts["instrumentation_status_codes"] == 0:
            raise ValueError("Instrumentation output contained no raw executed-pass statuses")
        if not counts["complete"]:
            raise ValueError("Instrumentation did not report a complete successful suite")
        if counts["failures"] != 0:
            raise ValueError(f"Instrumentation reported {counts['failures']} failure/error status codes")
        result["phases"]["instrumentation_suite"] = "passed"
        result["status"] = "passed"
    except Exception as error:
        result["status"] = "failed"
        result["error"] = str(error)
        raise
    finally:
        results_path.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"run_r8_native_checks: {error}", file=sys.stderr)
        raise SystemExit(1)

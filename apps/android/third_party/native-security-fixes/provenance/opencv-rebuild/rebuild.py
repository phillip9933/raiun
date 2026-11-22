#!/usr/bin/env python3
"""Replay the scanner OpenCV Android build in a fresh directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import zipfile


RECIPE = Path(__file__).resolve().parent
BUNDLE = RECIPE.parent.parent
ABIS = ("arm64-v8a", "x86_64")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require_digest(path, expected):
    actual = digest(path)
    if actual != expected:
        raise SystemExit(f"{path}: expected SHA-256 {expected}, got {actual}")


def require_tool_output(command, expected):
    output = subprocess.check_output(command, text=True)
    if expected not in output.splitlines()[0]:
        raise SystemExit(f"{command[0]}: expected {expected}, got {output.strip()}")


def run_logged(command, log, work, env, stdin=None):
    print(f"{log.stem}: {log}", flush=True)
    with log.open("w") as stream:
        result = subprocess.run(
            command, cwd=work, env=env, stdin=stdin,
            stdout=stream, stderr=subprocess.STDOUT,
        )
    if result.returncode:
        raise SystemExit(f"{log.stem} failed ({result.returncode}); see {log}")


def read_command(abi, phase, substitutions):
    arguments = json.loads((RECIPE / f"{abi}-{phase}.args.json").read_text())
    for token, path in substitutions.items():
        arguments = [argument.replace(token, str(path)) for argument in arguments]
    return arguments


def rebuild(archive, sdk, work):
    provenance = json.loads((RECIPE.parent / "opencv-build.json").read_text())
    native_source = provenance["native_source"]
    recorded_build = provenance["build"]
    ndk_revision = recorded_build["ndk"].split()[0]
    patch = BUNDLE / "sources/opencv-split-function-pointer.patch"
    require_digest(archive, native_source["sha256"])
    require_digest(patch, native_source["patch_sha256"])

    cmake = sdk / "cmake/3.22.1/bin"
    ndk = sdk / "ndk" / ndk_revision
    clang = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/clang"
    require_tool_output([cmake / "cmake", "--version"], "cmake version 3.22.1-g37088a8")
    require_tool_output([cmake / "ninja", "--version"], "1.10.2")
    require_tool_output([clang, "--version"], "clang version 19.0.1")
    revisions = dict(
        (key.strip(), value.strip())
        for key, value in (
            line.split("=", 1) for line in (ndk / "source.properties").read_text().splitlines() if "=" in line
        )
    )
    if revisions.get("Pkg.Revision") != ndk_revision:
        raise SystemExit("NDK revision differs from the recorded build")

    work.mkdir()
    temporary = work / "tmp"
    temporary.mkdir()
    env = dict(
        os.environ, ANDROID_HOME=str(sdk), ANDROID_SDK_ROOT=str(sdk),
        PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(temporary),
    )
    with zipfile.ZipFile(archive) as source_archive:
        source_archive.extractall(work / "source")
    source = work / "source/opencv-4.12.0"
    with patch.open("rb") as patch_input:
        run_logged(
            ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-d", source],
            work / "patch.log", work, env, stdin=patch_input,
        )
    require_digest(source / "modules/core/src/split.dispatch.cpp", native_source["patched_source_sha256"])

    hooks = work / "offline-hooks"
    hooks.mkdir()
    (hooks / "OPENCV_DOWNLOAD_PRE.cmake").write_text(
        'message(FATAL_ERROR "Dependency download forbidden in bounded source build")\n'
    )
    python = Path(sys.executable)
    substitutions = {"@SDK@": sdk, "@WORK@": work, "@PYTHON@": python}
    results = {}
    for abi in ABIS:
        build = work / f"build-{abi}"
        run_logged(read_command(abi, "configure", substitutions), work / f"{abi}-configure.log", work, env)
        modules = [
            line.split("=", 1)[1] for line in (build / "CMakeCache.txt").read_text().splitlines()
            if line.startswith("OPENCV_MODULES_BUILD:")
        ]
        expected_modules = set(recorded_build["compiled_modules"])
        if len(modules) != 1 or set(modules[0].split(";")) != expected_modules:
            raise SystemExit(f"{abi}: CMake configured an unexpected module set: {modules}")

        for name in ("modules/core/version_string.inc", "opencv_data_config.hpp"):
            generated = build / name
            content = generated.read_text()
            for path, prefix in (
                (source, "/opencv-source"), (work, "/opencv-build"),
                (sdk, "/android-sdk"), (python, "/build-tools/python"),
            ):
                content = content.replace(str(path), prefix)
            generated.write_text(content)

        run_logged(read_command(abi, "build", substitutions), work / f"{abi}-build.log", work, env)
        library = build / "jni" / abi / "libopencv_java4.so"
        expected = recorded_build["abis"][abi]
        actual = digest(library)
        results[abi] = {
            "library": str(library.relative_to(work)),
            "bytes": library.stat().st_size,
            "sha256": actual,
            "expected_sha256": expected["sha256"],
            "matches": actual == expected["sha256"] and library.stat().st_size == expected["bytes"],
        }
        print(f"{abi}: {actual} ({'match' if results[abi]['matches'] else 'MISMATCH'})", flush=True)
    (work / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    return 0 if all(result["matches"] for result in results.values()) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path, help="pinned OpenCV 4.12.0 ZIP")
    parser.add_argument("--sdk", required=True, type=Path, help="Android SDK root")
    parser.add_argument("--work", required=True, type=Path, help="new build directory on a disk-backed filesystem")
    args = parser.parse_args()
    if (platform.system(), platform.machine()) != ("Linux", "x86_64"):
        parser.error("the recorded Android toolchain requires Linux x86_64")
    if sys.version_info[:3] != (3, 14, 8):
        parser.error("use Python 3.14.8 as in the recorded build")
    sdk, work = args.sdk.resolve(), args.work.resolve()
    if work.is_relative_to(BUNDLE):
        parser.error("--work must be outside the pinned bundle")
    if work.exists():
        parser.error("--work must not already exist")
    if any(character.isspace() for path in (sdk, work, Path(sys.executable)) for character in str(path)):
        parser.error("SDK, work and Python paths must not contain whitespace")
    return rebuild(args.archive.resolve(), sdk, work)


if __name__ == "__main__":
    sys.exit(main())

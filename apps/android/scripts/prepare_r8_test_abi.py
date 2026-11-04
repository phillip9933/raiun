#!/usr/bin/env python3
"""Create exact, name-preserving R8 test-to-target ABI rules from compiled inputs.

First run, from the Android project root:
  ./gradlew -Praiun.r8Validation=true -I scripts/inventory_r8_test_abi.init.gradle \
    -Praiun.inventoryOutput=/absolute/output/resolved-artifacts.json :app:traceClassfileInventory
Then run this tool with --project, --output, --java-home, and --sdk. It reads
only existing classfiles and resolved artifacts; it does not invoke Gradle,
download dependencies, or build the app.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import io
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path


CONFIGURATIONS = (
    "releaseRuntimeClasspath",
    "r8ValidationRuntimeClasspath",
    "r8ValidationAndroidTestRuntimeClasspath",
    "r8ValidationAndroidTestCompileClasspath",
)
APP_COMPILE = Path("app/build/intermediates/compile_app_classes_jar/r8Validation/bundleR8ValidationClassesToCompileJar/classes.jar")
TEST_DIRS = (
    Path("app/build/tmp/kotlin-classes/r8ValidationAndroidTest"),
    Path("app/build/intermediates/javac/r8ValidationAndroidTest/compileR8ValidationAndroidTestJavaWithJavac/classes"),
)
TEST_R = Path("app/build/intermediates/compile_and_runtime_not_namespaced_r_class_jar/r8ValidationAndroidTest/processR8ValidationAndroidTestResources/R.jar")
SCANNER_SENTINELS = (
    "dev/offlinescan/core/ImageProcessor.class",
    "org/opencv/core/CvException.class",
    "ai/onnxruntime/OrtEnvironment.class",
)
APP_SENTINEL = "eu/opencloud/android/next/ui/EncryptedPdfDocument.class"
ABI_SENTINELS = (
    "public okhttp3.OkHttpClient$Builder addInterceptor(okhttp3.Interceptor);",
    "public boolean isBackingCleared$app_r8Validation();",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_pins(path: Path) -> dict[str, str]:
    pins = {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise ValueError(f"Malformed runtime pin line: {line!r}")
        if match.group(2) in pins:
            raise ValueError(f"Duplicate canonical runtime pin: {match.group(2)}")
        pins[match.group(2)] = match.group(1)
    return pins


def runtime_identities(runtime: list[dict], pins: dict[str, str]) -> list[tuple[str, str]]:
    identities = []
    for item in runtime:
        component, path = item["component"], Path(item["path"])
        if component not in pins:
            raise ValueError(f"Release runtime artifact is absent from canonical pins: {component}")
        if not path.is_file():
            raise FileNotFoundError(f"Resolved release runtime artifact is missing: {path}")
        actual_hash = sha_file(path)
        if actual_hash != pins[component]:
            raise ValueError(f"Pinned runtime artifact hash mismatch for {component}: {actual_hash}")
        identities.append((component, actual_hash))
    return identities


def validate_variant_runtime_equality(release: list[dict], validation: list[dict],
                                      pins: dict[str, str]) -> list[dict]:
    release_multiset = Counter(runtime_identities(release, pins))
    validation_multiset = Counter(runtime_identities(validation, pins))
    if release_multiset != validation_multiset:
        raise ValueError(
            "Release and r8Validation runtime coordinate/hash multisets differ: "
            f"release_only={list((release_multiset - validation_multiset).items())}, "
            f"validation_only={list((validation_multiset - release_multiset).items())}"
        )
    return [{"component": component, "sha256": artifact_hash, "count": count}
            for (component, artifact_hash), count in sorted(release_multiset.items())]


def validate_runtime_inventory(runtime: list[dict], pins: dict[str, str]) -> tuple[list[dict], list[dict], list[str]]:
    canonical: dict[str, dict] = {}
    identities: dict[str, dict[str, list[str]]] = {}
    for item, (component, actual_hash) in zip(runtime, runtime_identities(runtime, pins)):
        path = Path(item["path"])
        identities.setdefault(component, {}).setdefault(actual_hash, []).append(str(path.resolve()))
        canonical.setdefault(component, item)
    duplicates = [
        {"component": component, "sha256": artifact_hash, "paths": paths}
        for component, hashes in sorted(identities.items())
        for artifact_hash, paths in sorted(hashes.items())
        if len(paths) > 1
    ]
    unused_pins = sorted(set(pins) - set(canonical))
    return list(canonical[key] for key in sorted(canonical)), duplicates, unused_pins


def missing_target_diagnostics(lines: list[str]) -> list[str]:
    namespaces = ("eu.opencloud.android.next.", "dev.offlinescan.",
                  "org.opencv.", "ai.onnxruntime.")
    missing = [line.strip() for line in lines if re.search(r"Missing (?:class|method|field) ", line)]
    return [line for line in missing
            if any(namespace in line.split(" (referenced from:", 1)[0] for namespace in namespaces)]


def classify_missing_diagnostic(line: str) -> str | None:
    # TraceReferences appends the caller context; it is not part of the missing symbol.
    lower = line.split(" (referenced from:", 1)[0].lower()
    if "androidx.test.internal.runner.hidden.exposedinstrumentationapi" in lower:
        return "hidden_android_api"
    if "com.google.errorprone.annotations." in lower:
        return "compile_time_test_annotation"
    if any(value in lower for value in ("java.beans.", "org.easymock.", "org.jmock.")):
        return "optional_jvm_test_integration"
    if any(value in lower for value in ("java.lang.invoke.stringconcatfactory", "javax.lang.model.element.modifier", "sun.misc.unsafe")):
        return "jvm_or_compiler_runtime"
    return None


def validate_rule_inventory(text: str) -> int:
    blocks = re.findall(r"(?m)^-keep[^\n]*\{\n(?:[^\n]*\n)*?\}", text)
    if not blocks:
        raise ValueError("TraceReferences generated no test-to-target roots")
    if "*" in text or "..." in text:
        raise ValueError("Wildcard present in generated ABI rules")
    absent = [sentinel for sentinel in ABI_SENTINELS if sentinel not in text]
    if absent:
        raise ValueError(f"Critical test ABI sentinel missing from generated rules: {absent}")
    return len(blocks)


def read_classes_from_jar(path: Path, role: str, classes: dict, owners: dict,
                          overlaps: list, target_classes: dict | None = None,
                          target_owners: dict | None = None) -> None:
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if not name.endswith(".class") or name.startswith("META-INF/") or name.endswith("module-info.class"):
                continue
            data = archive.read(name)
            if target_classes is not None and name in target_classes:
                same = digest(data) == digest(target_classes[name])
                overlaps.append({"class": name, "origin": str(path) + "!/" + name,
                                 "target_origin": target_owners[name][0], "identical": same})
                if not same:
                    raise ValueError(f"Nonidentical source/target class overlap: {name} ({path})")
                continue
            if name in classes[role]:
                if digest(classes[role][name]) != digest(data):
                    raise ValueError(f"Conflicting {role} class {name} at {path}")
                owners[role][name].append(str(path) + "!/" + name)
            else:
                classes[role][name] = data
                owners[role][name] = [str(path) + "!/" + name]


def add_artifact(path: Path, component: str, configuration: str, role: str,
                 pins: dict[str, str], classes: dict, owners: dict,
                 manifest: list, target_classes: dict | None = None,
                 target_owners: dict | None = None, overlaps: list | None = None) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Resolved artifact is missing: {path}")
    data = path.read_bytes()
    file_hash = digest(data)
    if configuration == "releaseRuntimeClasspath" and pins.get(component) != file_hash:
        raise ValueError(f"Release runtime artifact is not checksum-pinned: {component} ({path})")
    entry = {"role": role, "component": component, "configuration": configuration,
             "path": str(path.resolve()), "sha256": file_hash, "bytes": len(data),
             "nested_jars": []}
    if path.suffix == ".aar":
        with zipfile.ZipFile(io.BytesIO(data)) as aar:
            for name in aar.namelist():
                if name == "classes.jar" or (name.startswith("libs/") and name.endswith(".jar")):
                    nested = aar.read(name)
                    entry["nested_jars"].append({"entry": name, "sha256": digest(nested), "bytes": len(nested)})
                    if target_classes is not None and overlaps is not None:
                        read_classes_from_bytes(nested, path, name, role, classes, owners,
                                                target_classes, target_owners, overlaps)
                    else:
                        read_classes_from_bytes(nested, path, name, role, classes, owners, None, None, [])
    elif path.suffix == ".jar":
        if target_classes is not None and overlaps is not None:
            read_classes_from_jar(path, role, classes, owners, overlaps, target_classes, target_owners)
        else:
            read_classes_from_jar(path, role, classes, owners, [], None, None)
    else:
        raise ValueError(f"Unexpected external artifact type: {path}")
    manifest.append(entry)


def read_classes_from_bytes(data: bytes, outer: Path, nested_name: str, role: str,
                            classes: dict, owners: dict, target_classes: dict | None,
                            target_owners: dict | None, overlaps: list) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name in archive.namelist():
            if not name.endswith(".class") or name.startswith("META-INF/") or name.endswith("module-info.class"):
                continue
            payload = archive.read(name)
            origin = f"{outer}!/{nested_name}!/{name}"
            if target_classes is not None and name in target_classes:
                same = digest(payload) == digest(target_classes[name])
                overlaps.append({"class": name, "origin": origin, "target_origin": target_owners[name][0], "identical": same})
                if not same:
                    raise ValueError(f"Nonidentical source/target class overlap: {name} ({origin})")
                continue
            if name in classes[role]:
                if digest(classes[role][name]) != digest(payload):
                    raise ValueError(f"Conflicting {role} class {name} at {origin}")
                classes[role][name].append(origin)
            else:
                classes[role][name] = payload
                owners[role][name] = [origin]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, type=Path, help="Android Gradle project root")
    parser.add_argument("--output", required=True, type=Path, help="Evidence/output directory")
    parser.add_argument("--java-home", required=True, type=Path, help="JDK used to run TraceReferences")
    parser.add_argument("--sdk", required=True, type=Path, help="Android SDK root")
    parser.add_argument("--compile-sdk", default="36", help="Compile SDK platform (default: 36)")
    parser.add_argument("--resolved-artifacts", type=Path, help="Inventory JSON; defaults to OUTPUT/resolved-artifacts.json")
    parser.add_argument("--d8-jar", type=Path, help="R8/D8 tool jar; defaults to latest SDK build-tools")
    args = parser.parse_args()
    project, output, sdk = args.project.resolve(), args.output.resolve(), args.sdk.resolve()
    java_home = args.java_home.resolve()
    resolved_path = (args.resolved_artifacts or output / "resolved-artifacts.json").resolve()
    output.mkdir(parents=True, exist_ok=True)
    resolved = json.loads(resolved_path.read_text())
    if set(resolved) != set(CONFIGURATIONS):
        raise ValueError(f"Inventory configurations differ: {sorted(resolved)}")
    pins_path = project / "gradle/runtime-artifact-pins.sha256"
    pins = load_pins(pins_path)
    raw_release_runtime = resolved["releaseRuntimeClasspath"]
    runtime, runtime_duplicates, unused_pins = validate_runtime_inventory(raw_release_runtime, pins)
    runtime_multiset = validate_variant_runtime_equality(
        raw_release_runtime, resolved["r8ValidationRuntimeClasspath"], pins)
    for config in CONFIGURATIONS:
        for item in resolved[config]:
            if not Path(item["path"]).is_file():
                raise FileNotFoundError(f"Resolved {config} artifact missing: {item['path']}")

    classes = {name: {} for name in ("target", "source", "library")}
    owners = {name: {} for name in classes}
    manifest, overlaps = [], []
    app_jar = project / APP_COMPILE
    if not app_jar.is_file():
        raise FileNotFoundError(f"Missing compiled r8Validation app classes: {app_jar}")
    read_classes_from_jar(app_jar, "target", classes, owners, [])
    module_jars = sorted(project.glob("**/build/intermediates/runtime_library_classes_jar/release/*/classes.jar"))
    if not module_jars:
        raise FileNotFoundError("No compiled release-fallback module class JARs found")
    for jar in module_jars:
        read_classes_from_jar(jar, "target", classes, owners, [])
    compiled_inputs = [app_jar, *module_jars]
    for item in runtime:
        add_artifact(Path(item["path"]), item["component"], "releaseRuntimeClasspath", "target",
                     pins, classes, owners, manifest)
    for sentinel in (APP_SENTINEL, *SCANNER_SENTINELS):
        if sentinel not in classes["target"]:
            raise ValueError(f"Required Raiun/scanner target signature absent: {sentinel}")

    for relative in TEST_DIRS:
        path = project / relative
        if not path.is_dir():
            raise FileNotFoundError(f"Missing compiled r8ValidationAndroidTest classes: {path}")
        for file in sorted(path.rglob("*.class")):
            compiled_inputs.append(file)
            name = file.relative_to(path).as_posix()
            data = file.read_bytes()
            if name in classes["target"]:
                same = digest(data) == digest(classes["target"][name])
                overlaps.append({"class": name, "origin": str(file.resolve()),
                                 "target_origin": owners["target"][name][0], "identical": same})
                if not same:
                    raise ValueError(f"Nonidentical source/target class overlap: {name}")
            elif name in classes["source"] and digest(data) != digest(classes["source"][name]):
                raise ValueError(f"Conflicting test class {name}: {file}")
            else:
                classes["source"][name] = data
                owners["source"].setdefault(name, []).append(str(file.resolve()))
    test_r = project / TEST_R
    if not test_r.is_file():
        raise FileNotFoundError(f"Missing r8ValidationAndroidTest generated R.jar: {test_r}")
    compiled_inputs.append(test_r)
    read_classes_from_jar(test_r, "source", classes, owners, [], classes["target"], owners["target"])

    seen = set()
    for item in resolved["r8ValidationAndroidTestRuntimeClasspath"]:
        path = Path(item["path"]).resolve()
        if path not in seen:
            seen.add(path)
            add_artifact(path, item["component"], "r8ValidationAndroidTestRuntimeClasspath", "source",
                         pins, classes, owners, manifest, classes["target"], owners["target"], overlaps)
    for item in resolved["r8ValidationAndroidTestCompileClasspath"]:
        path = Path(item["path"]).resolve()
        if path not in seen:
            seen.add(path)
            add_artifact(path, item["component"], "r8ValidationAndroidTestCompileClasspath", "library",
                         pins, classes, owners, manifest)
    for name in list(classes["library"]):
        if name in classes["source"]:
            if digest(classes["library"][name]) != digest(classes["source"][name]):
                raise ValueError(f"Compile/runtime class mismatch: {name}")
            del classes["library"][name]
            del owners["library"][name]

    toolchain = Path(args.d8_jar).resolve() if args.d8_jar else None
    if toolchain is None:
        candidates = sorted((sdk / "build-tools").glob("*/lib/d8.jar"),
                           key=lambda path: tuple(int(part) if part.isdigit() else part
                                                  for part in re.split(r"([0-9]+)", path.parents[1].name)))
        if not candidates:
            raise FileNotFoundError(f"No build-tools/*/lib/d8.jar under {sdk}")
        toolchain = candidates[-1]
    platform = sdk / "platforms" / f"android-{args.compile_sdk}"
    lib_jars = [classes_path := output / "library.jar", platform / "android.jar"]
    lib_jars.extend(sorted((platform / "optional").glob("android.test.*.jar")))
    source_jar, target_jar = output / "source.jar", output / "target.jar"
    for role, path in (("source", source_jar), ("target", target_jar), ("library", lib_jars[0])):
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in sorted(classes[role].items()):
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data)
        (output / f"{role}-class-provenance.json").write_text(json.dumps({
            name: {"sha256": digest(classes[role][name]), "origins": owners[role][name]}
            for name in sorted(classes[role])
        }, indent=2) + "\n")
    (output / "artifact-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (output / "source-target-overlap.json").write_text(json.dumps(overlaps, indent=2) + "\n")

    java = java_home / "bin/java"
    if not java.is_file():
        raise FileNotFoundError(f"Java executable not found: {java}")
    raw_rules = output / "test-to-target-keep.raw.pro"
    command = [str(java), "-cp", str(toolchain), "com.android.tools.r8.tracereferences.TraceReferences",
               "--keep-rules", "--allowobfuscation", "--source", str(source_jar), "--target", str(target_jar)]
    for library in lib_jars:
        if not library.is_file():
            raise FileNotFoundError(f"TraceReferences library input missing: {library}")
        command += ["--lib", str(library)]
    command += ["--map-diagnostics:MissingDefinitionsDiagnostic", "error", "warning", "--output", str(raw_rules)]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    (output / "trace-diagnostics.log").write_text(result.stdout)
    if result.returncode:
        raise RuntimeError(f"TraceReferences failed ({result.returncode}); see {output / 'trace-diagnostics.log'}")
    diagnostics = result.stdout
    missing_lines = [line.strip() for line in diagnostics.splitlines()
                     if re.search(r"Missing (?:class|method|field) ", line)]
    if missing_target_diagnostics(missing_lines):
        raise ValueError("TraceReferences reported a missing Raiun/scanner target signature; see diagnostics")
    unclassified = [line for line in missing_lines if classify_missing_diagnostic(line) is None]
    if unclassified:
        raise ValueError(f"TraceReferences reported unapproved missing definitions: {unclassified}; see diagnostics")
    raw_text = raw_rules.read_text()
    if not raw_text.strip():
        raise ValueError("TraceReferences generated an empty rule inventory")
    stable_text = raw_text.replace("-keep,allowobfuscation ", "-keep ")
    block_count = validate_rule_inventory(stable_text)
    stable = output / "r8-test-abi.pro"
    stable.write_text(stable_text)
    diagnostic_groups = {
        "hidden_android_api": [], "compile_time_test_annotation": [],
        "optional_jvm_test_integration": [], "jvm_or_compiler_runtime": [],
    }
    for line in missing_lines:
        category = classify_missing_diagnostic(line)
        assert category is not None
        diagnostic_groups[category].append(line)
    input_manifest = {
        "resolved_artifacts": {"path": str(resolved_path), "sha256": sha_file(resolved_path)},
        "runtime_pins": {"path": str(pins_path.resolve()), "sha256": sha_file(pins_path)},
        "compiled_classfiles": [{"path": str(path.resolve()), "sha256": sha_file(path),
                                 "bytes": path.stat().st_size} for path in compiled_inputs],
    }
    (output / "input-manifest.json").write_text(json.dumps(input_manifest, indent=2) + "\n")
    summary = {
        "outcome": "TraceReferences completed from compiled classfiles/JARs.",
        "rule_file": {"path": str(stable), "sha256": sha_file(stable), "bytes": stable.stat().st_size},
        "rule_blocks": block_count, "wildcards_present": False,
        "name_policy": "Removed only allowobfuscation; ABI names remain stable.",
        "inputs": {"class_counts": {key: len(value) for key, value in classes.items()},
                   "manifest": str(output / "input-manifest.json"),
                   "release_external_artifacts_verified": len(raw_release_runtime),
                   "identical_release_artifact_duplicates": runtime_duplicates,
                   "unused_runtime_pins": unused_pins,
                   "release_r8_validation_runtime_multiset": runtime_multiset,
                   "nonidentical_source_target_overlaps": [x for x in overlaps if not x["identical"]],
                   "jars": {p.name: {"path": str(p), "sha256": sha_file(p), "bytes": p.stat().st_size}
                            for p in (source_jar, target_jar, classes_path)}},
        "tool": {"path": str(toolchain), "sha256": sha_file(toolchain), "bytes": toolchain.stat().st_size,
                 "argv": command, "exit_code": result.returncode,
                 "diagnostic_mapping": "MissingDefinitionsDiagnostic error->warning in TraceReferences only; diagnostics retained."},
        "diagnostics": {"missing_definition_count": len(missing_lines),
                        "classified": diagnostic_groups,
                        "mapping": "MissingDefinitionsDiagnostic error->warning in TraceReferences only."},
        "limitations": "Test-only dependencies are resolved from the opt-in r8ValidationAndroidTest variant configurations.",
    }
    (output / "RESULTS.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # preserve a concise CI failure while leaving inputs intact
        print(f"prepare_r8_test_abi: {error}", file=sys.stderr)
        raise SystemExit(1)

# Release shrinking evaluation — #53

Production `release` builds still have R8 disabled. The local evaluation for [issue #53](https://github.com/phillip9933/raiun/issues/53) adds an opt-in `r8Validation` build type; it does not enable shrinking for published builds. Building a candidate, resolving its dependencies or passing host tests does not establish runtime compatibility.

## Build and test the isolated candidate

Run from the Android project root. Normal commands continue to select the existing build types:

```sh
./gradlew :app:verifyReleaseRuntimeArtifacts :app:assembleRelease
```

The following explicit property creates `r8Validation`, initializes it from `release`, and selects it as the app's instrumentation target:

```sh
./gradlew -Praiun.r8Validation=true \
  :app:verifyR8ValidationRuntimeArtifacts \
  :app:assembleR8Validation \
  :app:assembleR8ValidationAndroidTest
```

This candidate enables code optimization/minification and resource shrinking. It remains **non-debuggable**, inherits the release build's empty development-server credentials, and uses only Gradle's existing standard **debug signing configuration**. It keeps the application ID and numerical version code, with a `-r8-validation` version-name suffix for the synthetic test journeys; it is not a production-signed replacement or an update for an owner installation. Install it only on the disposable emulator/test installation authorized for this work. No production signing configuration is introduced.

`verifyR8ValidationRuntimeArtifacts` first requires the existing release checksum verifier, then compares the complete sorted multiset of third-party runtime coordinates and SHA256 hashes against the verified release classpath. A missing, additional or modified runtime binary refuses the candidate. Project modules still compile from the current source. The variant falls back to library `release` variants and adds no debug runtime dependency.

Both updater-verification APKs and the separate incoming-share provider APK are generated as instrumentation assets using the standard debug key. Their generators run for `mergeR8ValidationAndroidTestAssets` as well as the normal debug test assets. These fixture APKs are not assets of the application being shipped.

On each explicitly selected disposable API 26/API 35 emulator, run the app's native suite:

```sh
ANDROID_SERIAL=<authorized-emulator-serial> ./gradlew -Praiun.r8Validation=true \
  :app:connectedR8ValidationAndroidTest
```

Omit the property to return to the normal debug instrumentation target. Without it, the validation build type and its tasks do not exist. Do not persist the opt-in in a developer's global Gradle settings. AGP 8.13.2 is the pinned build plugin; the separate optional AGP property `android.r8.optimizedResourceShrinking=true` changes the resource-shrinking pipeline and must be recorded if used. The current evaluation does not silently add that global property.

## Historical size baseline

The retained `outputs/android-next-issues-20261104/apk-baseline-breakdown.json` describes the earlier local **#21/#54 candidate**, before the current #51/#52/#55 hardening source. It is a historical comparison point, not a measurement of the current source or a completed R8 result.

| ZIP category | Uncompressed entry bytes | Compressed entry bytes |
| --- | ---: | ---: |
| Native libraries, both supported ABIs | 77,932,232 | 77,932,232 |
| DEX | 67,901,772 | 20,577,271 |
| Assets | 20,850,023 | 13,311,457 |
| Resources | 2,167,621 | 2,067,057 |
| Other entries | 1,578,394 | 1,343,759 |

The historical complete APK was **115,503,766 bytes**, including ZIP/signature/alignment overhead. Native libraries account for about **67.47%** of that file; compressed DEX accounts for about **17.82%**. R8 does not rewrite the native ELF payloads or interpret opaque model assets. The uncompressed DEX total must not be reported as achievable download savings.

Build the ordinary and minimized APKs from the same frozen current source before making a size claim. Record both hashes, complete APK bytes and compressed/uncompressed category totals. Compare native-library and model entry hashes to distinguish shrinking from a dependency, ABI or asset change. Preserve the R8 mapping, merged configuration, usage/seeds, resource reports and every warning or failed attempt. No measured reduction is recorded here yet.

## Native and reflection boundaries

Inspection of the actual pinned scanner `0.8.0-beta.1`, JNA `5.17.0`, Lazysodium Android `5.2.0` and ONNX Runtime `1.24.1` artifacts found no bundled consumer keep rules in those AARs or their nested JARs. That absence is a reason to inspect dynamic entry points, not to keep whole packages.

**JNA initialization is a concrete blocker.** Its tagged [`native/dispatch.c`](https://github.com/java-native-access/jna/blob/5.17.0/native/dispatch.c#L2714) eagerly resolves Java classes, methods and fields by string name. The Android default native-method-name rules do not preserve every Java-only member involved. Examples include `Pointer(long)` and `Pointer.peer`, `Native.dispose` and its conversion helpers, `Structure.getTypeInfo`/`newInstance`/`autoRead`/`autoWrite`, and the thirteen `Structure$FFIType$FFITypes.ffi_type_*` fields. Preserve exact class names and exact looked-up member descriptors where required. Keeping names while allowing those members to be removed is insufficient.

JNA's tagged [`Structure.java`](https://github.com/java-native-access/jna/blob/5.17.0/src/com/sun/jna/Structure.java#L1900) also gives the FFI layout fields an explicit field-order annotation. Renaming or removing its `size`, `alignment`, `type` or `elements` fields can break reflective layout. The late error path in [`native/callback.c`](https://github.com/java-native-access/jna/blob/5.17.0/native/callback.c#L345) resolves `Callback$UncaughtExceptionHandler`, `Native.callbackExceptionHandler` and `uncaughtException` by name. Positive crypto calls alone do not cover callback failure paths.

The actual Lazysodium Android `5.2.0` bytecode calls `Native.register(Sodium.class, "sodium")` and `Native.register(SodiumAndroid.class, "sodium")`. JNA's tagged [`Native.register`](https://github.com/java-native-access/jna/blob/5.17.0/src/com/sun/jna/Native.java#L1674) enumerates native methods reflectively and resolves their function names. Retain the applicable default native-name rules and inspect the surviving bindings; a blanket keep of all Lazysodium classes is not justified by this observation.

**OpenCV has a specific native exception path.** The scanner embeds `opencv-java-4.12.0.jar`. Tagged [`Mat.cpp`](https://github.com/opencv/opencv/blob/4.12.0/modules/java/generator/src/cpp/Mat.cpp#L10) uses `FindClass("org/opencv/core/CvException")` followed by `ThrowNew`. One narrowly justified example is:

```proguard
-keep,allowoptimization class org.opencv.core.CvException {
    public <init>(java.lang.String);
}
```

This example is not a complete scanner configuration. Standard processing and the learned detector use different native dependencies. The pinned learned-detector source invokes `OrtEnvironment`, `OrtSession` and `OnnxTensor`; ONNX native-to-Java callbacks/constructors and model execution still require a complete audit. No package-wide ONNX or scanner keep is inferred. Review missing-class diagnostics individually rather than copying a generated suppression file without understanding the paths involved.

Research-only candidate JNA rules, artifact hashes, bytecode and source references are retained outside Git under `outputs/android-next-issues-20261104/r8-inspection/`. Those proposed rules are not active application configuration and do not establish a safe minimized release.

## Acceptance limits

Inspect the merged R8 configuration and the standalone candidate before running instrumentation. An instrumentation build can add retention roots for classes and methods referenced by its tests; test dependencies can also make otherwise absent code available. A direct test reference or reflective test helper can therefore hide a defect in the standalone application. Preserve and compare the actual app APKs/configurations used in the build and native runs; do not assume they are equivalent.

The `core:crypto` native suite exercises that library's own test APK. Its result alone does not prove JNA/Sodium works inside the app's minimized DEX. Acceptance needs actual minimized-app crypto operations and failure handling, worker reconstruction and Room reopen/migration, Keystore/OAuth/serialization, provider/app-lock enforcement, incoming URI admission, OpenCV processing/export and learned ONNX inference. Include dynamic error paths, process/restart behavior where relevant, and both supported Android API baselines. ARM64 physical-device acceptance remains distinct from x86_64 emulator execution.

Build success, host tests and a subset of native tests are useful bounded evidence. Production shrinking stays disabled until the standalone candidate, its exact narrow rules and the required runtime paths are demonstrated compatible. Signing, publication and a change to the default release configuration remain separate decisions.

## Executed evaluation — 4 November 2026

The opt-in app and its test APK build after two **test-APK-only** suppressions
for AndroidX Test's absent compile-time Error Prone annotations
(`CanIgnoreReturnValue`, `MustBeClosed`). No application keep rule was added.
Both dependency verifiers pass: 128 third-party runtime binaries match the
normal release's exact coordinates and SHA256 hashes.

The current unshrunk unsigned APK is 115,521,986 bytes; the minimized debug-key
candidate is 98,491,882 bytes, about 17 MB / 14.7% smaller. A same-debug-key
unshrunk non-debuggable control was also retained for the runtime comparison;
exact signed sizes and hashes are in `apk-r8-measurement.json`. Native libraries
and ONNX model entries are byte-identical. This is a test candidate measurement,
not a prediction of a production-signed release's final size.

The AndroidX instrumentation attempt is **not runtime acceptance**: API 35 stops
before tests on `NoClassDefFoundError: androidx.tracing.Trace`, and the initial
API 26 invocation remained running and was stopped. Optimized target/test
classpath compatibility needs separate work. No crypto/scanner test pass is
inferred from those attempts, and no application keep roots were added to hide
the harness problem.

The independent framework-only probe generator
[`generate_r8_probe_fixture.py`](../scripts/generate_r8_probe_fixture.py) packages
no AndroidX, JUnit or target-library code. It loads exact native-facing names
through the target app's class loader, without rebuilding or adding roots to the
measured app. Build it with the same `--project`, `--java-home`, `--keystore`,
`--key-alias`, `--compile-sdk`, `--output` arguments used by the other fixture
builders and `FIXTURE_STORE_PASSWORD=android`; only the standard debug test key
is supported. On an explicitly selected disposable emulator:

```sh
adb -s <serial> install <output>/r8-probe-fixture.apk
adb -s <serial> shell am instrument -w -e probe jna \
  app.raiun.test.r8probe/.R8ProbeInstrumentation
adb -s <serial> shell am instrument -w -e probe opencv-exception \
  app.raiun.test.r8probe/.R8ProbeInstrumentation
```

On **both API 26 and API 35**, packaged JNA initialization fails with
`UnsatisfiedLinkError` in the minimized APK, and the exact OpenCV exception
lookup fails with `ClassNotFoundException`. Both probes pass in the unshrunk
non-debuggable control. The JNA outcome is consistent with the inspected dynamic
bindings; the bounded result deliberately does not identify the first missing
member or claim its exact root cause. OpenCV's exact native-facing class is
absent. The control rules out treating a generally broken probe as success.
These two checks do not exercise full encryption, inference, upgrade or scanner
journeys.

**Decision: leave production R8 and resource shrinking disabled.** The evaluation
is useful evidence for #53, not an enabled feature. Further work needs exact
native/reflective retention rules, their error-path tests, a working optimized
instrumentation harness and the broader acceptance matrix described above.
Mappings, configuration, seeds/usage/resource reports, APKs, bounded probe results,
AndroidX failures and the unchanged native/model hashes remain in
`outputs/android-next-issues-20261104/`. No production key or owner device was used.

# Release shrinking evaluation — #53

The Android 1.4.0/code 55 candidate enables R8 code optimization/minification and resource shrinking for `release`; debug builds remain unshrunk. The dated sections below preserve the local evaluation evidence and its limits. They do not establish any additional device, network or failure-mode acceptance. Current release validation and publication status are recorded separately in [Testing](TESTING.md).

Runtime retention is limited to the audited native ABI and generated settings schema in `proguard-native-r8.pro` and `proguard-storage-r8.pro`. Test ABI roots and the nonexported Compose test host are confined to the explicitly opted-in instrumentation target, never ordinary release.

## Build and test the isolated candidate

Run from the Android project root. Normal commands continue to select the existing build types:

```sh
./gradlew :app:verifyReleaseRuntimeArtifacts :app:assembleRelease
```

The following explicit property creates `r8Validation`, initializes it from `release`, and selects it as the app's instrumentation target:

```sh
./gradlew -Praiun.r8Validation=true \
  :app:verifyR8ValidationRuntimeArtifacts \
  :app:assembleR8Validation
```

This candidate enables code optimization/minification and resource shrinking. It remains **non-debuggable**, inherits the release build's empty development-server credentials, and uses only Gradle's existing standard **debug signing configuration**. It keeps the application ID and numerical version code, with a `-r8-validation` version-name suffix for the synthetic test journeys; it is not a production-signed replacement or an update for an owner installation. Install it only on the disposable emulator/test installation authorized for this work. No production signing configuration is introduced.

`verifyR8ValidationRuntimeArtifacts` first requires the existing release checksum verifier, then compares the complete sorted multiset of third-party runtime coordinates and SHA256 hashes against the verified release classpath. A missing, additional or modified runtime binary refuses the candidate. Project modules still compile from the current source. The variant falls back to library `release` variants and adds no debug runtime dependency.

Both updater-verification APKs and the separate incoming-share provider APK are generated as instrumentation assets using the standard debug key. Their generators run for `mergeR8ValidationAndroidTestAssets` as well as the normal debug test assets. These fixture APKs are not assets of the application being shipped.

Preserve that standalone APK, mapping and merged configuration before building the instrumentation target. The test harness has a separate opt-in for AndroidX tracing/Kotlin helper methods and the updater verifier's test-only reflection seam. Those rules must not be used for standalone size or native-probe acceptance. They are not production requirements. The current harness also needs an exact compiled test-to-target ABI inventory, described below; the two opt-in flags alone do not retain every method called by the separate test APK.

On each explicitly selected disposable API 26/API 35 emulator, build and run the app's native suite with the explicit harness property:

```sh
ANDROID_SERIAL=<authorized-emulator-serial> ./gradlew \
  -Praiun.r8Validation=true -Praiun.r8Instrumentation=true \
  -Praiun.r8TestAbiRules=/absolute/path/to/current-test-abi.pro \
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

Build the ordinary and minimized APKs from the same frozen current source before making a size claim. Record both hashes, complete APK bytes and compressed/uncompressed category totals. Compare native-library and model entry hashes to distinguish shrinking from a dependency, ABI or asset change. Preserve the R8 mapping, merged configuration, usage/seeds, resource reports and every warning or failed attempt. The historical executed evaluation below records its own measurements; new source needs a new comparison.

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

Build success, host tests and a subset of native tests are useful bounded evidence, not standalone runtime acceptance. The later local enablement at the end of this guide records the additional completed gates. Rerun the relevant checks when compiler, native dependency, serializer or recovery boundaries change; signing/publication remain separate actions.

## Historical first evaluation — 4 November 2026

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

## Earlier local native-rule and harness follow-up — 4 November 2026

The `r8Validation` variant adds [`proguard-native-r8.pro`](../app/proguard-native-r8.pro) and [`proguard-storage-r8.pro`](../app/proguard-storage-r8.pro). The release variant uses the required native and settings-schema rules. The dated evaluation below records the dependency and reflection review; re-audit these bindings when pinned dependencies change.

The optional `raiun.r8Instrumentation=true` property requires `raiun.r8Validation=true` and adds [`proguard-r8-instrumentation.pro`](../app/proguard-r8-instrumentation.pro). AGP's app/test classpath sharing requires the AndroidX tracing methods and Kotlin lazy facade used by the test runner to survive in the target. The private updater-verifier reflection entrypoint is also retained solely for its test. Exact coroutine subclass/default-interface callback methods are retained for target-to-test calls not visible to static reference tracing. These rules do not change ordinary `release`; omit the instrumentation property for independent probes and measurement. A successful instrumented private-verifier test cannot establish retention of that entrypoint in the standalone APK.

The independent framework fixture now accepts `--mapping <exact-standalone-mapping.txt>` and the additional probes `crypto-known-answer`, `scanner-standard` and `scanner-learned`. It packages only framework code and target-name metadata. The crypto probe checks a fixed public encrypted fixture and rejects tampering before plaintext output. Scanner probes use a synthetic bitmap; the standard path also invokes OpenCV's native exception path, and the learned path uses the bundled model. If optimization removes or changes a reflected shape, the fixture returns `unsupported-optimized-shape`; this is neither a pass nor automatically an app defect. Run an unshrunk control without mapping as well. Never retain target code merely to make this independent probe work.

The additional optional `raiun.r8TestAbiRules=/absolute/path/to/current-test-abi.pro` is accepted only with the instrumentation flag, verifies the file exists, and appends it only to the instrumentation target. The current inventory was generated by R8 TraceReferences from **classfile/JAR inputs**, not APK/DEX: the actual `r8Validation` app classes, release-fallback module classes and all 128 verified external runtime artifacts are the target; actual `r8ValidationAndroidTest` classes and test-only classes are the source. Android 36 and compile-only classes form the tool library. Shared source/target class definitions are byte-identical. Test-only external artifacts came from the shared `debugAndroidTestRuntimeClasspath` inventory, whose current dependencies are declared in the common `androidTestImplementation` configuration; variant-specific dependency changes require a new inventory.

The resulting 493 exact class/member blocks contain no wildcard. The final test inventory also preserves their ABI names: removing `allowobfuscation` from 471 blocks leaves the same members; 22 enum blocks already preserved names. Coroutine tooling can generate calls with original method names after target mapping, so preserving reachability alone was insufficient. Raw and stable inventories, hashes and the exact flag-only derivation are retained separately. This preserves methods legitimately inlined/deleted in the standalone app but called across the test APK boundary, such as `OkHttpClient.Builder.addInterceptor`. Use the inventory only for this test target, regenerate it after compiled input/dependency changes, and retain the input hashes and command. APK-only tracing returned an empty inventory and was rejected. Optional/hidden platform and annotation diagnostics were downgraded only within the tracing tool, retained and reviewed; no application warning suppression was added. The complete reproducible preparation script, inputs/provenance and exact commands are in `outputs/android-refactor-shrinking-20261104/trace-classfiles/`. This is local evaluation tooling, not a general production keep configuration.

Rule inventories, exact source and bytecode references, failed attempts and execution evidence are retained under `outputs/android-refactor-shrinking-20261104/`. At this earlier evaluation stage, production shrinking remained disabled; the later enablement is documented below.

### Standalone results and limits

The same-source, non-debuggable standard-debug-key control is **115,583,773 bytes** and the standalone minimized APK is **98,491,878 bytes**: **17,091,895 bytes / 14.787% smaller**. All 20 native libraries and every non-profile asset, including `assets/docquad/docquadnet256.ort`, are byte-identical. Code-dependent ART baseline profiles differ as expected. Both APKs pass 16-KiB ZIP/native-load alignment checks. The ordinary unsigned APK is 115,521,982 bytes; signing overhead is not counted as shrinking savings.

The exact standalone APK (without tracing, updater-test or test-ABI keep roots) has SHA256 `87179e75a5b940839332e862fe0e3465ace5e998be1768c06c1df4f289d40c12`. Independent probes on **both API 26 and API 35** show:

| Probe | Unshrunk control | Standalone R8 |
| --- | --- | --- |
| Packaged JNA initialization | Pass | Pass |
| Exact OpenCV native exception class/constructor lookup | Pass | Pass |
| Fixed crypto known-answer and tamper rejection before plaintext | Pass | Pass |
| Standard scanner detection and native exception invocation | Pass | Unsupported optimized constructor shape |
| Learned scanner bundled-model inference, finite metrics and actual native OpenCV exception | Pass | Pass |
| Protobuf parse/serialize/reopen of all 14 nondefault settings fields | Pass | Pass |

The learned detector was checked for silent fallback: this method requires ONNX session execution and materialization of both model outputs. The probe does not assert corner accuracy, document quality, export or ARM64 behavior. Bounded cold launcher startup reports success on both APIs; it is not sign-in or file-operation acceptance.

Retained failed attempts exposed two further JNA full-mode dependencies: the `FFIType` field-order annotation needs its class kept, and reflective constructor access needs `Klass.newInstance` to stay in its original package without inlining/relocation. The final narrow rules address both; the successful crypto probes exercise their initialization. An API 26 unshrunk scanner failure was a probe defect: enumerating unrelated methods resolved API 28-only signatures. The corrected probe looks up only the specific detection method. The optimized standard constructor remains unavailable to that probe and is not counted as a pass.

The broader optimized run exposed a real storage defect after the harness could reach UI startup: generated Protobuf Lite message metadata references the original AppSettings field names. The storage rule retains only those 14 exact fields/types; it keeps no parser, builder or probe entrypoint. No `.proto`, wire format, Room schema or persisted setting is changed. The independent probe uses the actual optimized parser/schema/encoder, compares exact canonical wire bytes, reopens the output and checks all fields, including repeated values. Reaudit this rule when `app_settings.proto` changes.

### Optimized instrumentation outcome

The final instrumentation APK is a distinct artifact from the standalone APK. It includes the explicit stable test ABI inventory, the narrow reflection/callback rules, and a **nonexported** Compose host activity through `src/r8Instrumentation/AndroidManifest.xml`. The overlay is selected only with `raiun.r8Instrumentation=true`. Normal/standalone manifests contain no such host; packaged manifest inspection confirms unchanged permissions, production components, package, version code and non-debuggable state. No third-party dependency or checksum equality requirement was added or weakened to supply the host.

The complete app suite passes **API 26: 30 cases, 6 explicit skips; API 35: 33 cases, 5 explicit skips**, using the same final target/test APK hashes. API 26 initially failed five screenshot-output-directory checks when explicitly sent to an unavailable external path. An unchanged-APK full rerun using the target's private cache passes with the original assertions. Private output was not extracted through `run-as`; no root/permission change was used. An earlier preflight encountered stopped emulators before executing any tests; task-owned read-only copies were restarted, preserving originals and failed logs. These harness corrections do not turn the earlier failed runs into passes.

The suite exercises the optimized app's parser, crypto, scanner JPEG/PDF export, updater verification and security/UI paths. Direct static test references and the private-verifier keep roots affect this instrumentation target, so these results cannot certify standalone retention of all those paths. The independent standalone probes above remain separate. Native library-module suites run against their own unshrunk test APKs, as recorded in [Testing](TESTING.md).

**Historical decision at this point in the evaluation: production shrinking remained disabled.** The follow-up work and later enablement are recorded in the dated sections below. Physical ARM64 acceptance remains distinct from x86_64 emulator results. These historical notes do not claim current-release checks or publication.

## Acceptance and local enablement — 4 November 2026 (historical candidate evidence)

The remaining gates passed against both the validation build and the **actual release build type**, without test retention roots. `release` now enables `isMinifyEnabled` and `isShrinkResources`, with the same native/storage rules inherited by `r8Validation`. The app ID, version name/code, provider authorities, signing configuration, Room schema 28 and persisted formats are unchanged. An explicitly guarded `raiun.r8UpgradeVersionCode=54` was used only for synthetic higher-version testing; the default remains 1.3.3/code 53.

### Independent standalone scanner and data checks

Both API 26/API 35 pass standard detection, learned inference, native OpenCV errors, crypto known-answer/tamper rejection and all 14-field Protobuf parse/serialize/reopen in the actual minified release. Standard processing no longer depends on a removed public constructor: the fixture obtains the real processor through the surviving learned-detector quality binding and invokes the actual static residual method.

The independent `scanner-export` probe verifies a 2300×3100 JPEG, black-text/white-paper pixel content, a two-page PDF with 552×744-point pages and both 2300×3100 embedded images, cancellation after staging creation, staging cleanup and unchanged source bytes. No app class/method was retained just for a probe. Optimized exporter/callback shapes were reviewed from fresh APK disassembly and bound to the exact APK/mapping; reviewed recipes and provenance remain with the evidence. Missing or changed shapes fail rather than guess arguments. This does not establish ScanSession import/close, mid-PDF cancellation or camera/image-quality acceptance.

### Cold upgrade and real worker reconstruction

The baseline uses the exact published 1.3.3 APK payload, locally re-signed with the existing standard debug key. All675 non-signature ZIP entries match the official asset. This synthetic trust domain avoids production-key activation while retaining package identity/UID across the update. Disposable clones were recreated before seeding; the seed operation must never be applied to an owner installation merely because its account list is empty.

On both APIs, baseline 53→actual minified release 54 preserves a synthetic account, pinned offline bytes, real settings protobuf bytes and encrypted v2 credential ciphertext. The candidate reopens the real Room database through its open helper and decrypts the existing password through the actual Android Keystore-backed store in a different process. Baseline work remains delayed/ENQUEUED at the seed boundary, and the baseline is force-stopped before replacement.

Real startup reconstructs three stale-worker intents (QUEUED/RETRY/RUNNING). Actual Upload/DownloadWorker instances reach a deliberately unsupported location before authorization/network, producing typed FAILED/UNSUPPORTED and failed WorkSpecs with their original UUID, progress, attempts and ETag retained. SUCCEEDED/CANCELLED/AWAITING_UNLOCK/CONFLICT/unknown rows remain unchanged with no new WorkSpecs. The baseline-persisted cleanup worker reconstructs and succeeds; the orphan is removed while pinned data survives. Startup cleanup may remove the orphan before that delayed worker, so deletion is not attributed exclusively to it.

These are real cold-start scheduling and data-preservation checks, **not successful network-transfer/resume**, death during an active transfer, encrypted-payload/biometric hardware, or production-key upgrade acceptance. Unsupported encrypted byte-offset continuation remains outside this work.

### Reproducible CI and symbols

`scripts/run_r8_native_checks.py` builds/preserves the standalone APK and map, inventories current compiled validation app/test inputs, generates exact name-preserving ABI rules and builds/runs the separate optimized app suite. It refuses a non-emulator or mismatched AVD/API, uses private-cache screenshot output, requires raw completed test outcomes and preserves failed logs. `prepare_r8_test_abi.py` verifies every resolved binary against canonical pins, exact release/validation coordinate-hash multisets, identical alias duplicates and unknown missing definitions. Unused allowed pins are recorded rather than treated as required platform artifacts. No application warning suppression is generated.

The emulator workflow retains all eight normal suites and adds this gate on API 26/API 35. Local execution is acceptance evidence; no remote CI run, commit or push occurred. Focused helper tests cover pin/hash/class conflicts, diagnostic classification, nonempty complete test outcomes and stale mapping rejection.

`archive_r8_artifacts.py` checks the mapping ID embedded in root DEX and archives mapping/configuration/seeds/usage/resources under version + unsigned-APK SHA256, refusing conflicting overwrites. Both packaging helpers call it before signing; the quality workflow retains release maps. Copy the version/hash archive to durable release evidence outside `build` before cleaning local outputs. No symbol archive is added to the published APK asset folder.

Current evidence, exact APK/mapping hashes, source snapshots and preserved failed tooling attempts are in `outputs/android-shrinking-acceptance-20261104/`. Physical ARM64/OEM acceptance remains distinct; no production signing, installation on an owner device, commit, push or publication is implied by local enablement.

### Final local results

The actual default unsigned release is 98,479,598 bytes versus 115,521,982 bytes for the retained same-source unshrunk unsigned control: **17,042,384 bytes / 14.753% smaller**. Default code 53 DEX is byte-identical to the actual-release code 54 DEX exercised in the cold-upgrade and scanner probes; only the testing version override differs. Native libraries/non-profile assets/model remain byte-identical, ZIP 16-KiB alignment passes, the app remains nondebuggable, and the normal manifest/configuration contain neither test host nor test-only ABI/verifier rules.

The complete regular gate passes 2,094 host cases with zero failures/skips, screenshot verification, formatting/static analysis, release lint and debug/minified-release assembly. The portable CI runner completes all phases locally on API 26 with raw outcomes **30 passes/6 explicit skips**; its exact final app/test artifacts pass **33 cases/5 skips** on API 35. Ten focused Python helper checks pass; both packaging scripts parse without executing signing. The matching symbol archive is retained outside `build` in the task evidence. No remote CI run or publication is claimed.

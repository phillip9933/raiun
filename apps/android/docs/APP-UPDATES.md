# App updates

Android 1.1.0 adds in-app update checks and optional downloads using the standalone Android App Updater library. Android 1.0.0 did not include this feature. This guide describes Raiun's integration and release requirements.

Raiun keeps its Material settings/notice screens and translations in `feature/settings`. `RaiunUpdates.kt` supplies the public GitHub repository, Android tag/asset naming and explicitly accepted historical tags to the standalone Android App Updater library. It does not give the updater an OpenCloud HTTP client, account token or vault access.

Tap the version at the bottom of the navigation menu to open App updates directly, or use Settings → App updates. The page shows the installed version and links to the GitHub project and that version's release notes. Release links use validated Android tags; debug builds link to their corresponding release version. Back returns to Settings.

When a newer compatible release is found, Raiun shows a **New version available** popup after the app is unlocked. It includes release notes and Download update, or Install update when a verified download is ready. **Later** dismisses the current offer; it remains available in App updates, and a different newer release can prompt again. The focused popup tests cover the button callback, but do not establish dismissal behavior across process death. Returning to the foreground requests a check through the library's existing daily throttle; the library respects Check automatically. No extra polling or automatic installation is added.

The unreleased candidate pins `io.github.phillip9933:android-updater:0.2.1` in `gradle/libs.versions.toml`. The independent library source is maintained outside this monorepo. Raiun consumes its exported Maven publication in `third_party/android-updater/`, including a complete corresponding source snapshot and license. Gradle verifies SHA-256 pins and the exact Maven file set during configuration; repository content filtering prevents falling back to a mutable local or remote copy. Builds do not follow a sibling source checkout or use `mavenLocal()`.

Version 0.2.1 is published in [`phillip9933/android-app-updater`](https://github.com/phillip9933/android-app-updater/releases/tag/v0.2.1), at source revision `60b8fb82aa14ab0fc115ee9f9f96d3cc2c60f5fc`. Published Raiun 1.1.0 continues to contain updater 0.2.0. The library uses the neutral Kotlin package `io.github.phillip9933.appupdater`. The vendored artifact/source bundle allows a clean Raiun checkout to build without a sibling checkout. Verify the immutable release, corresponding source and artifact hashes for every pin update. This work does not change Kura's networking policy or manifest.

## Ownership and compatibility

The library owns feed parsing, daily checks, Wi-Fi download work, private APK cache, strict verification and construction of an installer Intent. It contributes the nonexported `${applicationId}.android-updates` FileProvider with read grants restricted to `cache/updates/`. Raiun owns network/install permissions, app-lock placement, user-visible prompts, channel choices and launching Android's installer after a foreground tap. Returning from an installer or permission screen does not prove installation succeeded.

Raiun's existing application ID, signing identity and all cloud/offline/vault/backup data remain unchanged. The existing updater preferences (`android_updates`), APK cache subdirectory (`updates`) and FileProvider authority are retained. Scheduled work is updated to the library worker class rather than keeping requests that name removed classes. Persisted public configuration lets workers restart without an Activity; configuration tokens prevent old work from acting on a changed release source.

Only one update configuration per app process is supported. This library targets universal APK releases from public GitHub repositories, with matching version names and increasing version codes. The policy requires the installed signing identity, a non-debuggable APK and a higher version code. Historical consumer test evidence and remaining acceptance limits are recorded below and in TESTING.md. Desktop and Play split-package updating need their own installation flows.

**Android 15 debug-APK verification:** native API 35 testing found that archive `ApplicationInfo.flags` can be zero even when the compiled manifest declares `android:debuggable="true"`. Version 0.1.2 therefore failed debug-APK rejection on API 35; package identity, version and signing-key checks still passed. Version 0.1.3 reads the compiled manifest through public Android resource APIs and fails closed if it cannot read it. The library's isolated harness passed ten native cases on each API 26 and API 35, including resource-valued flags. Raiun's 0.1.3 published-artifact verifier/provider suite passed nine tests on each API 26 and API 35. This includes rejection of the correctly signed debug fixture that previously failed on API 35. System-installer upgrade evidence is recorded in TESTING.md; these synthetic tests do not establish a production-signed phone upgrade.

## Updating the library pin

1. Make and validate a standalone library change. Increase its version for any artifact already distributed; never replace published bytes under an existing version.
2. Build its versioned Maven publication and use its `scripts/export_bundle.py` to export to a new, empty directory. The export includes AAR, POM, module metadata, sources JAR, complete source ZIP, license and SHA256SUMS.
3. Review the source/API/dependency changes and replace Raiun's bundle deliberately. Update the version catalog pin. Gradle must reject modified or unlisted Maven files.
4. Run library tests and Raiun's quality/build gates. Repeat the signed Android installation/upgrade journey before release; host tests cannot prove platform installer behavior.

See [release asset rules](RELEASING.md#in-app-android-updates), [privacy](../PRIVACY.md#app-update-checks), and [acceptance checks](TESTING.md#android-updater-acceptance).

## Raiun 1.1.0 release status

Android 1.1.0 (version code 48) is published at tag [`android-v1.1.0`](https://github.com/phillip9933/raiun/releases/tag/android-v1.1.0), source commit [`90540f3`](https://github.com/phillip9933/raiun/commit/90540f3363bd6aa16f06b12ee3b0334061e7bd85). Both release workflows passed: [quality](https://github.com/phillip9933/raiun/actions/runs/40203652287) and [API 26/API 35 emulator matrix](https://github.com/phillip9933/raiun/actions/runs/40203652384). The production-signed APK and SHA256SUMS were uploaded and verified. The later popup follow-up is not part of 1.1.0; its focused lifecycle, persistence and layout tests, plus remaining process/device limits, are recorded in [TESTING.md](TESTING.md#new-version-popup-follow-up).

## Public library adoption — 2026-10-24

Adopted the downloaded 0.1.2 public Maven/source bundle after verifying its release checksum and internal pins. The previous local 0.1.1 bundle is preserved in project outputs. Only the library pin/bundle and corresponding verification entries changed; existing unpublished app work is preserved. The app itself is not published by this adoption.

Adoption verification passed `:app:verifyReleaseRuntimeArtifacts :feature:settings:compileDebugKotlin` in 2 seconds: 88 tasks, 1 executed / 87 up-to-date. Runtime notices were regenerated (171 dependency records; no missing POM declarations; two existing unavailable full license texts remain reported). This is dependency/settings validation, not fresh app tests or a signed upgrade. The public library CI independently passed 43 host tests. No unrelated source was staged, signed or published.


## Corrected library adoption — 2026-10-24

The independent library publisher released immutable version 0.1.3 with the compiled-manifest check. Raiun independently downloaded the public bundle, checked its tag/source revision, and verified all six payload hashes before updating its Maven/source/license pins. The previous 0.1.2 bundle and its failing native evidence are preserved outside the checkout. No Raiun signing, commit, push or release is part of this adoption. Runtime verification passed for 128 artifacts, and debug/instrumentation assembly passed. Gradle verification now records 894 components and 1,598 artifact hashes, with the new entries checked against the public bundle. The published production source and AAR match the isolated tested fix. Exact consumer native results are recorded in TESTING.md.

The final 0.1.3 consumer gate passed all 1,376 host tests, static checks, screenshot verification, release lint and debug/unsigned release assembly. On both API 26 and API 35, nine verifier/provider tests and the opt-in real-installer journey passed. The synthetic upgrade retained private sentinel data. This clears the earlier API 35 verifier blocker; production-signed phone and real-data upgrade acceptance remain separate release requirements. See TESTING.md for scope and evidence.

The independent library publisher subsequently confirmed passing [quality CI](https://github.com/phillip9933/android-app-updater/actions/runs/40052660786) and [API 26/API 35 native CI](https://github.com/phillip9933/android-app-updater/actions/runs/40052660831), with ten native tests and no failures/errors/skips on each platform. Initial native-CI setup failures were corrected by workflow-only commits; tag `v0.1.3` and its published artifact bytes remain unchanged. This is separate library CI evidence, not Raiun release-commit CI.

## Namespace and metadata hardening — 0.2.0

Version 0.2.0 changes the Maven group and Kotlin package, plus the SDK's private bootstrap preference namespace. Raiun retains its application identity, signing identity, user-facing `android_updates` settings, cache path and provider authority. The library keeps one configured feed; registration and initialization must happen again after the namespace change so workers can start in a later process. Raiun retains its existing foreground initialization in `MainActivity.onCreate`: open the app once after upgrading a local 0.1.x test build to register the new bootstrap and reschedule checks. Existing unique work names are reused with UPDATE/REPLACE policies. An old worker invoked before that first open can fail because its former class is absent; this is not a promise to resume an already-running 0.1.x download. Published Raiun 1.0.0 did not contain the updater; Android 1.1.0 introduces the integration.

Release metadata now requires the expected JSON field types instead of coercing arbitrary primitives. Existing trusted GitHub URL/redirect rules, exact installed-signer checks, debug-APK rejection and installer-time revalidation remain enforced. The release adds hostile-URL, forged/unsigned APK and changed-cache regressions. Its exporter rejects dirty/untracked source, archives committed files and builds artifacts from that isolated snapshot; that improves artifact/source provenance rather than changing Raiun's cloud encryption.

The library publisher records 55 host tests, nine exporter regressions and 13 native verifier tests on each API 26 and API 35, with passing independent CI and a byte-identical AAR. Those library results do not replace Raiun's exact-artifact consumer tests, which are recorded in TESTING.md after execution.

Raiun independently verified the public 0.2.0 bundle, tag/source and seven payload pins. The old vendor bundle is preserved. The final consumer gate passed all 1,376 host tests, static checks, screenshots, release lint and debug/release assembly; the exact native APKs passed nine verifier/provider tests, one migration probe and one synthetic installer journey on each API 26 and API 35. The restored app's first offline Activity open retained update choices and registered the new bootstrap. Disabled update checks left no stale updater work. A new production-signed owner test is available locally; phone acceptance and a future higher-version in-app upgrade remain separate. See TESTING.md for fixture corrections, hashes and scope.

## Stable updater adoption — 27 October 2026

The local candidate consumes immutable updater 0.2.1. Its public Maven/source bundle SHA-256 is `cc528b338cb293851ccca3ff964ede320a9e63d0bf2b1c586f92cebb3926a9a6`; the AAR SHA-256 is `78d5f42c866c2430c52e858a653e8f54b1a4d344cefdd0762ea267e5e3b5373b`. Both the outer checksum and all seven payload pins were independently checked. Previous 0.2.0 vendor bytes remain in local project outputs.

The patch cancels obsolete queued automatic downloads when there is no eligible candidate. Public APIs, internal test-constructor shape, runtime dependency versions, minimum API 26, namespaces, settings, cache/provider paths and app identity are unchanged. Publisher [quality](https://github.com/phillip9933/android-app-updater/actions/runs/40324634811) and [API 26/API 35 native](https://github.com/phillip9933/android-app-updater/actions/runs/40324634783) workflows passed on the released source; those are library results, not Raiun phone-upgrade evidence. Consumer validation and remaining physical higher-version acceptance are recorded in TESTING.md. No Raiun signing or publication is included.

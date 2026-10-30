# Testing

Run commands from the Android project root (`apps/android`) after the [development setup](../CONTRIBUTING.md#development). Use `./gradlew` on Linux/macOS and `./gradlew.bat` on Windows. Python 3 and PowerShell (`pwsh` in CI) are required for the helper checks below.

## Build and quality checks

```sh
python scripts/install_offline_scanner_sdk.py
./gradlew ktlintCheck detekt testDebugUnitTest :app:verifyRoborazziDebug :app:lintRelease :app:assembleDebug :app:assembleRelease
```

These Gradle tasks match the [quality workflow](../../../.github/workflows/quality.yml). Detekt also depends on the Compose design-token check. Release output is unsigned until signed locally; see [the release procedure](RELEASING.md). Review screenshot changes visually; recording new images is not a passing verification result.

For focused changes, run the affected module's tests first. Documentation-only changes need path, link and command inspection rather than an app suite. A release candidate still needs the complete quality and emulator gates on the exact commit proposed for release.

## OpenCloud 9 and guest links

See [OpenCloud 9 compatibility](OPENCLOUD-9.md) for the protocol scope, security boundaries and pending real-server acceptance. Guest tests use synthetic mock responses; they must not send live invitation or renewal emails. Existing 1.2.0 device acceptance does not establish this new feature.

## Android emulator gates

Run the connected instrumentation suites on **both API 26 and API 35**, matching the API matrix in the [emulator workflow](../../../.github/workflows/emulator.yml). The documented task list below is the release gate; ensure CI runs every listed module, including `core:sync`, on both API levels. The gate must pass on the exact release commit; historical runs on earlier commits do not establish that result.

```sh
./gradlew :app:connectedDebugAndroidTest \
  :core:crypto:connectedDebugAndroidTest \
  :core:security:connectedDebugAndroidTest \
  :core:sync:connectedDebugAndroidTest \
  :core:database:connectedDebugAndroidTest \
  :core:documentsprovider:connectedDebugAndroidTest \
  :core:ui:connectedDebugAndroidTest \
  :feature:files:connectedDebugAndroidTest
```

Use a disposable emulator or authorized test device with synthetic files and test accounts, not a personal account or production server. Inspect test fixtures and server requirements before running individual journeys. Emulator tests do not establish physical camera behavior, hardware biometric enforcement, external-editor behavior or compatibility with every server/provider combination.

## 0.9.0 beta evidence

The historical 0.9.0 beta work recorded 1,125 passing host tests and 18 passing Android-native tests on API 35. The owner accepted the test 16 build on a Pixel. These results are useful implementation and device evidence, but the release gate is the quality and API 26/API 35 emulator matrix rerun on the exact 0.9.0 release commit. Earlier API 26 emulator results are historical and do not replace that release-commit run. Record any missing run explicitly; do not imply that planned checks have passed.

## Translations

```sh
python scripts/test_locale_validator.py
for locale in de fr es pt-rPT ja; do
  pwsh -File scripts/validate-locale-resources.ps1 -Locale "$locale"
done
```

These checks match CI. Add `-RequireComplete` when checking a complete translation update. Missing translations may otherwise fall back to English. Review changed layouts for long text, large fonts, accessibility and right-to-left layout where applicable.

### Unpublished translation update (2026-10-14)

On the dirty pre-1.0 development worktree based on 0.9.3 (`59659926`), strict validation passed for German, French, Spanish, European Portuguese and Japanese: 1,360 string/plural keys per locale across 12 modules, including the pinned scanner overlay. The eight validator regression tests passed. All ten pre-existing German `strings.xml` files retain their recorded hashes; missing German strings were added separately.

The 24 focused host tests passed: language selection/persistence, scanner overlays and English fallback, settings interactions, and seven settings layout cases (14 screenshots), including enlarged Portuguese and German text. Selected screenshots were visually reviewed. App formatting, settings formatting/static analysis, release lint (zero errors; 260 warnings and one hint), and debug assembly passed. Translation-specific plural warnings were corrected.

A follow-up removed the duplicated Kotlin language list: the picker and manifest now share `feature/settings/src/main/res/xml/locales_config.xml`. All 19 focused language/settings/layout tests passed, including picker interaction on API 26 and API 35; formatting, settings static analysis, release lint and debug assembly also passed. Existing screenshot baselines remained unchanged.

These are draft translations with targeted cross-review of security and data-loss warnings. They have not received complete native-speaker or physical-device acceptance. This check did not repeat the full pre-1.0 host/emulator matrix, sign a production APK, or publish a release. Earlier test APKs do not contain this translation update.

## Release-candidate review fixes (2026-10-14)

The unpublished worktree based on 0.9.3 (`59659926`) passed `ktlintCheck`, `detekt`, all 1,323 host tests (no failures or skips), screenshot verification, release lint (zero errors; 263 warnings and one hint), and debug assembly after the review fixes. All ten preserved German resource files still match their recorded hashes. No production signing or publication was performed.

The complete `core:sync` instrumentation suite passed nine tests on API 26 and nine on API 35, with no failures or skips. This includes native XML parsing of fragmented CDATA, the combined text/element node bound, DTD rejection, bounded listings and provider cancellation. This is a targeted emulator run, not a repeat of the complete multi-module release matrix.

Host regressions cover encrypted offline publication cancellation, rejected completion, account removal, accepted completion during cancellation, restart recovery, transfer-history interleaving, and continuation to the next queued import. Restart recovery uses captured provisional storage and durable transfer outcomes; it is not a physical process-kill test. UI tests cover scanner navigation without replaying upload notices, background queue handoff, and verification after retrying the same offline transfer.

Phone checks still needed:

- Save an encrypted file offline, then cancel a replacement download. The previous verified offline copy should remain usable; retry should complete normally.
- Retry a failed encrypted offline save without leaving the folder. It should finish verification, and later queued files should continue.
- Queue an upload, enter the scanner and return. The old upload confirmation should not appear again; a newly queued upload should still show its confirmation.

These checks cover the review-fix source snapshot, not a release commit or complete physical-device/server acceptance. The full release gates must run on the final release commit.

## Navigation and transfer-filter follow-up (2026-10-14)

The unpublished candidate based on `59659926` passed formatting, Detekt/design-token checks, all 1,340 host tests (no failures or skips), screenshot verification, release lint (zero errors; 263 warnings and one hint), and release assembly. Strict resource validation passed for all five translated locales (1,393 keys across 12 modules), alongside eight validator tests. Preserved German resource hashes remain unchanged.

New regression coverage includes combined direction/type/status/date filters, local date boundaries across daylight-saving changes, opening/cancelling the date picker, persisted dock choices and limits, unpinned menu access, encrypted nested/root Back behavior, and the unlock/enrollment confirmation policy. Updated navigation/settings/transfer screenshots were deliberately reviewed and recorded. No new native emulator matrix or physical face-authentication acceptance was performed for these UI changes.

On the phone, combine transfer filters and reset them; choose a custom date range; change bottom navigation in Appearance and restart the app; verify unpinned destinations remain in the menu. Unlock an encrypted location and press Back at both a nested folder and the root. Face unlock requests no confirmation for unlocking only; Android/device policy may still require confirmation. Enrollment retains confirmation and strong biometric cryptographic binding remains required.

### Navigation drag-and-drop follow-up

The navigation editor uses drag handles rather than arrow buttons, with live neighbor movement and a raised preview. Host interaction tests exercise a real handle drag, Save/Cancel, and restoring the original order when a gesture is cancelled. Handle queries use the unmerged semantics tree so test gestures hit the handle rather than the merged row label. Appearance and drag-preview screenshots were visually reviewed; all five translated locales passed strict completeness checks (1,397 keys per locale). Phone acceptance should include dragging first-to-last and last-to-first, cancelling an edit, and scrolling on a small screen.

## Record results

Record the revision, commands, environment and outcomes. Separate current results from historical evidence, and unit/screenshot checks from device or server acceptance. Do not include credentials, private URLs, machine-specific paths or personal files in public reports. See [beta limitations](ENCRYPTED-VAULTS-PLAN.md#not-included-in-this-beta) even when automated checks pass.

## Android updater acceptance

### New-version popup follow-up

For a newer compatible release, check that the popup appears after app unlock, shows the version and release notes, and requires a tap to download or install. Tap **Later**, restart Raiun and check again: that release should stay dismissed but remain available in App updates. A different newer release should prompt again. With automatic checks disabled, returning to the app must not start a check; **Check now** remains available. With checks enabled, foreground returns use the SDK's daily throttle, including a process kept alive for more than a day. Installer confirmation and APK verification remain required.

An earlier 2026-10-26 run passed all 20 `AppUpdatesScreenTest` cases. They cover offer/release gating, release text, Later and explicit download/install callbacks; real Compose `ON_RESUME` events checking the injected SDK manager; automatic-check disablement; the daily throttle and expiry; dismissal and attempted-check restoration after manager recreation; and a new tag reappearing as an offer. Five localized popup interactions also passed at 320 × 640 dp and 1.3 font scale, using resource-provided labels for German, French, Spanish, European Portuguese and Japanese. The current source adds API 26 coverage for the lifecycle/persistence cases and requires displayed-state plus separate Download/Later interactions in the locale cases; this expanded version is awaiting the coordinated all-module run. An earlier 12-case run also passed app/settings formatting, settings static analysis, debug assembly, eight locale-validator regressions and strict completeness checks for all five locales (1,450 keys/plurals). The feed is injected; these tests make no live GitHub request. Manager recreation with the same SharedPreferences is not a process-kill test. The tests do not establish physical-device installation or a production-signed in-app upgrade. Locale checks establish resource structure and key coverage only. Native-speaker sign-off is not a release requirement; use the [translation feedback guide](TRANSLATION-REVIEW.md) to report wording or layout problems.


### Historical initial updater implementation — 2026-10-24

The initial updater work was local and uncommitted on published Android 1.0.0 (`6d8f561`), with no version-code change at that point. Its host tests covered Android-only release selection, stable/beta ordering, URL restrictions, package/version/signer policy, failed checks, saved preferences, cache recovery and cleanup, streamed size/hash rejection, cancellation, and settings interactions. The new light/dark settings screenshots were visually reviewed. Strict resource validation passed for German, French, Spanish, European Portuguese and Japanese (1,438 keys/plurals per locale), along with eight locale-validator regression tests. Later release and acceptance evidence follows.

Before library extraction on 2026-10-24, Linux/JDK 21 verification passed `ktlintCheck`, `detekt`, all 1,371 host tests (zero failures or skips), `:app:verifyRoborazziDebug`, `:app:lintRelease`, `:app:assembleDebug` and `:app:assembleRelease`. Release output is unsigned. Earlier combined runs hit a Robolectric native-runtime initialization race; the new pure screen tests now use a plain test Application rather than starting production background jobs. The final combined run passed with one Gradle worker. This is host/build evidence, not a production-signed upgrade or emulator result.

After extraction on 2026-10-24, the standalone library passed all 40 host tests (zero failures or skips), ktlint, detekt, release lint (zero errors; 11 warnings and one hint), and local Maven publication. Tests preserve the earlier feed/policy/download regressions and cover a second app identity, worker class migration, configuration changes, process recreation, host-version startup gates, denied network-state permission and failed preference registration. The focused read-only extraction review found worker migration and provider ownership issues; both were fixed.

Raiun then passed `ktlintCheck`, `detekt`, all 1,348 remaining host tests (zero failures or skips), screenshot verification, release lint and debug/unsigned release assembly against the pinned 0.1.0 artifact. Engine tests moved to the library rather than being dropped. The merged manifest contains exactly one nonexported updater provider, with read grants scoped to `cache/updates/`. In isolated copies, Gradle rejected both a modified AAR and an unlisted Maven file before resolution. The artifact/source bundle is pinned and no sibling source path is used. These are local results; no GitHub CI or native signed installation is claimed. See [library integration](APP-UPDATES.md).

Before release, test the complete upgrade with two consecutively versioned APKs using the original signing identity on API 26 and API 35, plus a physical phone. Automated metadata-policy tests do not establish native APK signature enforcement or a successful system installation.

- In Settings → App updates, check manually, switch channels, and disable automatic checks. The current release should report no newer release until a newer eligible Android APK exists. Desktop releases must never appear.
- With a newer eligible release, read its notes, dismiss it with Later, download it, cancel, and retry. Automatic download must wait for unmetered Wi-Fi; manual download may use cellular.
- Restart after download. The verified update should remain available without another download. A missing, truncated, altered, differently signed or older APK must not become installable.
- Tap Install, deny the Android permission, then allow it and retry. Cancelling the installer must leave the current app working. A successful upgrade must retain accounts, vault preferences, offline files and backup settings. No background action may open the installer.

Those host results did not include a full emulator matrix or an in-app production-signed upgrade. A production-signed local test APK was subsequently prepared for owner acceptance; signing a test build does not establish that the updater's complete installation journey has passed. Current follow-up results are recorded separately below.

### Local hardening follow-up — 2026-10-24

Against the 0.1.2 library pin, the combined run passed `ktlintCheck`, `detekt`, all 1,376 Android host tests (zero failures or skips), screenshot verification, release lint (zero errors; 267 warnings and one hint), debug/unsigned release assembly, and assembly of the eight documented native test suites. The two changed updater screens were deliberately recorded and visually reviewed; other baselines were preserved. All five draft locales passed strict validation for 1,441 keys/plurals each, and all eight validator regressions passed. Previously recorded translation files retain their baseline hashes.

The initial combined run exposed a host-fixture problem: the production Application started asynchronous transfer recovery that could outlive a Robolectric sandbox. App host tests now default to plain `Application`, with explicit per-class overrides retained. The full app suite subsequently passed; this change does not disable production startup or substitute for native startup tests.

The library 0.1.1 candidate passed 43 host tests, ktlint, detekt and release lint before the independent publication work moved the pin to 0.1.2. The vendored 0.1.2 runtime AAR is byte-identical to that reviewed 0.1.1 AAR. Its publication metadata/source bundle is separately pinned. All 1,596 entries in Gradle verification metadata have independent publisher or local-bundle provenance. The explicit runtime gate correctly rejected a wrong checksum and a missing pin; the pin file was restored after both checks. Existing updater bundle-tamper tests remain historical evidence above.

Native API 26 passed nine verifier/provider tests. On both API 26 and API 35, a synthetic higher-version APK passed verification, reached Android's actual installer, installed after an explicit system confirmation, and retained a synthetic private-data sentinel. These journeys used disposable emulators and the default debug signing identity, with a manifest-only replacement APK; they do not prove a production-signed Raiun upgrade, schema migrations, GitHub download delivery or physical-phone behavior. The installer fixture now waits for staging to finish before instrumentation exits.

Updater APK fixtures are generated into Android-test build assets using the current default debug signing key and app version code. No machine-specific APKs or signing key are checked into source. `:app:assembleDebugAndroidTest` runs generation after debug signing validation; production signing is not used. The generator uses the Gradle JDK and Android SDK tools, with Python 3 on PATH (`python` on Windows, `python3` elsewhere); override the executable with `-PpythonExecutable=...` if needed. Synthetic future version names and incremented version codes keep these tests independent of the next Raiun release bump. The opt-in installer journey must run only on a fresh, disposable emulator app installation.

**Historical 0.1.2 native failure:** API 35 passed eight of nine verifier/provider tests. A debug-marked, correctly signed fixture was accepted because archive `ApplicationInfo.flags` was zero, while directly reading its compiled manifest returned `debuggable=true`. The isolated test reproduced in a fresh instrumentation process. This blocked acceptance of 0.1.2; the failure was not waived. See [the integration note](APP-UPDATES.md#ownership-and-compatibility). The separate fixed-library probe did not replace consumer acceptance.

The corrected direct-ADB native matrix subsequently passed all eight modules on API 26. On API 35, seven modules passed and the app's only failure was the debug-APK check above. The files test module contained no executable tests. Backup-window screenshot tests require `-e additionalTestOutputDir /data/user/0/app.raiun.cloud/files/test-output` when invoked directly with `am instrument`; supplying that normal runner argument resolved the initial three harness failures. No application code was changed to bypass the screenshots. The new native staged-folder test passed on both platforms, covering batch-boundary paging, authenticated records, absence of the plaintext sentinel in SQLite and cleanup.

The portable generated-fixture verifier/provider subset then passed nine tests on API 26 and eight of nine on API 35, reproducing only the known 0.1.2 failure. A separate disposable probe app using the proposed library fix passed all ten native verifier cases on each API. Those cases include literal and resource-referenced debug flags, valid release metadata, wrong identity/version/signing key and a missing application declaration. The scratch library passed all 43 host tests, ktlint, detekt and release assembly. The patch changes one verifier source file; the probe harness is not production app code. The scratch artifact retains the old version solely for isolated testing and must not be distributed under it. These results preceded publication of library 0.1.3. Raiun's adoption and exact-artifact acceptance are recorded separately below; no Raiun release was performed by this task.


### Published library 0.1.3 acceptance — 2026-10-24

Raiun now consumes the independently downloaded immutable [0.1.3 release](https://github.com/phillip9933/android-app-updater/releases/tag/v0.1.3), tagged at `6c5dea178527c218204a877b449e5477c13b08af`. The public bundle hash, all six payload pins and the tag revision were verified. The published AAR and all ten production source files match the isolated tested fix; the library's independent quality CI also built the identical AAR. The previous vendor bundle and failing 0.1.2 results remain preserved in project outputs.

Against this new pin, the full local gate passed `ktlintCheck`, `detekt`, all 1,376 host tests (zero failures/errors/skips), screenshot verification, release lint (zero errors; 267 warnings and one hint), and debug/unsigned release assembly. The gate finished in 2m 48s with 1,482 actionable tasks. Runtime verification passed for 128 artifacts. The 894 components and 1,598 artifact hashes in Gradle verification metadata have corresponding provenance; its SHA-256 is `c65848904743059762714c450a189e31ba58cbef90a7296ead68c72982612694`. All 242 protected resource files retain their recorded baseline hashes.

The exact new app/test APKs passed nine verifier/provider tests on each API 26 and API 35, including rejection of the debug APK that 0.1.2 incorrectly accepted on API 35. On both disposable AVDs, the opt-in installer test also passed: the real library staged the synthetic same-signer APK, Android's installer upgraded code 47 to synthetic version 99.0.0/code 48 after explicit system confirmation, and a private-data sentinel survived. The initial API 26 attempt stopped at its fresh-state guard without installing; clearing only the disposable app's prior synthetic state allowed the recorded run. The code-47 debug app was restored and both owned AVDs stopped afterward.

This was a targeted rerun of updater native acceptance, not a fresh full eight-module emulator matrix. It used the default debug signing identity, generated manifest-only candidates and synthetic data. It does not prove production-key upgrade compatibility, schema migrations, real accounts/offline/backup retention, physical-phone behavior or GitHub download delivery. Those signed phone/server acceptance checks remain required before a Raiun release. Evidence is retained in project outputs under `android-hardening-20261024/` and `native-updater-acceptance/013/`. No Raiun signing, commit, push or publication was performed.


### Production-signed owner test 2 — 2026-10-24

A fresh owner-test APK was signed locally with the original published certificate after the 0.1.3 consumer gate passed. Package `app.raiun.cloud`, version 1.0.0/code 47, minimum API 26, target API 36, non-debuggable status, empty development credentials, one expected signer and 16-KiB ZIP alignment were verified. All 669 unsigned ZIP entries remain byte-identical in the signed APK. It is a local test candidate with the existing version, not a new release or proof of phone installation. The previous signed test is preserved. The test APK, checksum, build evidence and plain-language phone checklist are retained outside Git under `outputs/android-updater-signed-test-2/`. Owner phone acceptance remains pending; nothing was committed, pushed or published.


### Updater 0.2.0 adoption and owner test 3 — 2026-10-24

The app now pins `io.github.phillip9933:android-updater:0.2.0` from public tag `v0.2.0`, source revision `90367917ac451bb1b065d4a49044df23ed3138a6`. The independently downloaded bundle SHA-256 is `7b8cd5befbb65142c96fd16cbb84b069c51d029370ca1e198ed6440c11520b1d`; all seven payload pins were verified. The AAR SHA-256 is `ede8c4b3660654918b15004b17d0633bc8c7e1989c1548786671b98be9ea4854`. The older 0.1.3 bundle and signed test APK remain preserved in project outputs.

The final full gate passed ktlint, Detekt, all 1,376 host tests with no failures/errors/skips, screenshot verification, release lint (zero errors; 267 warnings and one hint), debug and unsigned release assembly. It completed in 47 seconds with 1,482 actionable tasks. The first run found three formatting violations from namespace import order and a long provider component expression; these were corrected and the final debug/test APKs remained byte-identical to the frozen native inputs. Runtime verification passed for 128 artifacts. Dependency verification/provenance now covers 895 components and 1,600 artifact hashes; XML SHA-256 `604a98f2f02ca2dd814c993284b9139c6abc670416a251663fad87ffe75ff3b6`. All 242 protected resource files retain their recorded hashes.

The exact app/test APKs passed nine verifier/provider tests, one local-0.1.3 migration probe and one opt-in installer journey on each API 26 and API 35. The migration probe restored a separately scoped synthetic ready APK/cache and retained normal `android_updates` choices. Its first API 26 attempt failed because the externally seeded test XML had the wrong owner/SELinux label; after correcting only the disposable fixture's permissions, both probes passed. No SDK or production behavior was changed to waive that failure.

On both emulators Android installed synthetic version 99.0.0/code 48 from debug code 47 after explicit system confirmation; the private sentinel survived and cached APK hashes matched the frozen assets. The current debug code-47 app was restored. Its first offline Activity open registered the new bootstrap namespace while retaining normal settings automatic=false, Wi-Fi=true and channel=BETA. With checks disabled, no old or new updater worker remained. This verifies disabled-work cleanup, not execution of every possible pending 0.1.x job. Foreground initialization remains deliberate; open the app once after a local 0.1.x test upgrade. Published Raiun 1.0.0 had no updater to migrate.

A fresh local owner test 3 was signed with the original production certificate. Package/version/SDK identity, non-debuggable status, empty development credentials, one expected signer, updater 0.2.0 inventory and 16-KiB ZIP alignment were checked. All 669 unsigned APK entries match the signed payload. Version remains 1.0.0/code 47. Evidence and a short phone checklist are outside Git under `outputs/android-updater-signed-test-3/`; native logs and synthetic state are under `outputs/native-updater-acceptance/020/`. Phone acceptance of this test remains pending. These targeted native tests do not replace the complete release-commit matrix, real-data/server checks or a future higher-version production-signed in-app upgrade. No Raiun commit, push, tag or publication was performed.


### Issue #4: cancel all upload conflicts — 2026-10-25

The browser's Upload conflict dialog and Transfers menu now offer account-scoped cancellation of all currently conflicting uploads, with a separate confirmation. The database performs one conditional update for `accountId`, `direction=UPLOAD` and `state=CONFLICT`; it does not apply stale transfer snapshots. Cancelled rows persist across database reopen. Local/cloud files, backup enqueue receipts, other accounts, downloads and non-conflicting transfers are unchanged. Future uploads can encounter new conflicts; this is not a permanent skip/overwrite policy. The separate foreground encrypted copy/move naming prompt is outside this queued-upload action.

Focused backend validation passed 21 tests, including account/direction/state/location isolation, retry/error cleanup, receipt retention, a concurrently resolved row, database reopen and manager delegation. UI checks cover both confirmations, dismissing without mutation, disabling actions during cancellation, selection of encrypted upload rows and switching accounts while confirmation is visible. The transfer error path uses localized generic feedback instead of displaying exception details. New labels are present in the default resources and all five locales, with all 1,449 keys/plurals passing strict structural validation. All 242 protected resource files retain their prior hashes.

The final gate passed ktlint, Detekt, all 1,387 host tests (zero failures/errors/skips), screenshot verification, release lint and debug/unsigned release assembly in 4m 40s. Initial quality attempts found UI parameter-order/count and complexity issues; the dialog removed a redundant account parameter and the transfer UI was simplified before the successful full rerun. Only the intentional `file_browser_upload_conflict` screenshot was recorded and visually reviewed; other baselines remain unchanged.

A production-signed local conflict test APK was prepared with the existing 1.0.0/code-47 identity and updater 0.2.0. Its original certificate, non-debuggable status, empty development credentials and ZIP alignment are verified. Phone acceptance and a fresh release-commit native matrix remain pending. No real server/account test, commit, push or publication was performed. Evidence, preserved attempt logs, checksums and a plain-language phone checklist are outside Git under `outputs/issue-4-bulk-conflicts-20261025/`.

## Android 1.1.0 release freeze — 2026-10-25

Version 1.1.0/code 48 includes updater 0.2.0, bulk conflict cancellation, encrypted upload recovery and streamed ordinary-folder refreshes. It preserves the original package/certificate and includes the newer desktop history without changing its published version. The release is published at [`android-v1.1.0`](https://github.com/phillip9933/raiun/releases/tag/android-v1.1.0), source commit [`90540f3`](https://github.com/phillip9933/raiun/commit/90540f3363bd6aa16f06b12ee3b0334061e7bd85). Both independent workflows passed on that release revision: [quality](https://github.com/phillip9933/raiun/actions/runs/40203652287) and [API 26/API 35 emulator matrix](https://github.com/phillip9933/raiun/actions/runs/40203652384). The original production-signed APK and SHA256SUMS were uploaded and verified. Release logs, checksums and upgrade evidence are retained outside Git under `outputs/android-release-1.1.0/`. Earlier local/test-APK results remain historical evidence with their own scope, not substitutes for the passing release gates.

The final notice audit restored four previously shipped full license texts. Offline regeneration now keeps their exact verified bytes and records the original upstream provenance. All 171 runtime records have full license text coverage, and 283 inventory asset references/hashes were checked; repeat generation was byte-identical. No version or signing-identity change is hidden in that packaging correction.

Phone acceptance of the earlier test build is useful but does not establish every workflow on every server or OEM. The production-key emulator upgrade uses synthetic private data; it cannot prove real-account/offline/biometric retention on a physical phone. Keep the manual acceptance scenarios and format/external-app limitations above visible when assessing this release.

## Historical reliability acceptance checklist (written after 0.9.3)

This retained checklist records acceptance scenarios written after 0.9.3. It is not a current implementation-status report; individual features have evolved and later releases have shipped. The scenarios below do not prove that all relevant device/server workflows passed for Android 1.1.0 or any later candidate. Use release-specific evidence above and record any needed acceptance run against the source under review.

- **Large libraries:** exercise more than 100,000 files and more than 100,000 nested directory entries using synthetic providers. Check bounded batches, exclusion pruning, cancellation, provider errors and provider-declared incomplete listings. An interrupted scan must not advance the safe scan cursor. Restart after interruption and verify receipts prevent duplicate uploads. Check temporary traversal cleanup without deleting another active scan's state.
- **Directory discovery:** validate a large response with the collection record last, malformed XML after otherwise valid children, an oversized response and an encrypted collection. Never publish an incomplete deletion snapshot or expose encrypted children through the ordinary browser. Run XML rejection tests on both supported emulator API levels; host-JVM parsing alone is insufficient.
- **Recovery and reporting:** interrupt transfers before sending, during sending and after the server accepts a write but before the reply arrives. Test a missing destination and an existing different file. Retry must preserve conditional writes and stop after its bounded automatic attempts. Permission loss, quota, local storage, source availability and integrity failures must have distinct, actionable messages. Diagnostics must exclude credentials, raw responses, private paths and decrypted names.
- **Backup repair:** remove source permission, confirm the last scan failure remains visible after restarting, then choose a permitted source in Manage backup. Cancel must preserve the original source. A late picker or permission callback must not modify another account or backup. A successful complete scan clears only the matching failure; skipping work for battery/network constraints does not count as a successful scan.
- **Encrypted background work:** lock, background and restart during ciphertext transfer. No job may persist vault keys or decrypted child names. An interrupted download resumes only against a matching strong version, and remains unavailable offline until full authentication under a valid unlock. Verify account removal, cancellation, disk exhaustion, changed source metadata and corrupted staged ciphertext. Existing valid offline copies must survive failed replacement.
- **Copying across the encryption boundary:** cover files, directories, empty directories, both directions and separate encrypted locations. Verify conflict handling and explicit disclosure when the chosen destination is ordinary storage. A move must verify every copied file and the complete source/destination snapshots before deletion starts. Source changes, destination changes, cancellation and partial deletion must preserve remaining source data and report incomplete work without automatic destructive replay.

After these gates, review authentication, conditional writes, account/session cancellation, persistent metadata, temporary files and exported Android components. Run the complete quality and API 26/API 35 matrix on the final candidate. An automated source review does not establish absence of vulnerabilities; retain documented format and external-app handoff limitations.

### Local validation — 2026-10-13

Unpublished development source based on 0.9.3 (`59659926d138acc69f0e8c45d01c5a325b85bc5f`), with database schema 26. These results apply to this working-tree candidate, not a published 1.0 commit or a live-server acceptance run.

- `ktlintCheck`, `detekt`, `testDebugUnitTest`, `:app:verifyRoborazziDebug` and `:app:lintRelease` passed together. All 1,297 host tests passed, with no skips. Historical database upgrade coverage preserves data from schemas 1 through 25 and checks the new selective backup lookup index.
- The full configured connected-test matrix passed on API 26 and API 35: 74 executed cases passed, with five expected skips across both devices. Four skipped cases require explicit live-server configuration; one requires a newer Android task-appearance API. No live account was used. The feature/files connected task currently has no instrumentation source; its host and app integration tests still ran.
- Native checks include rclone content compatibility, Android Keystore envelopes, account cleanup, database persistence, hardened SAX parsing, offline manifests, actual descriptor polling and cancellation of an unwritten pipe. Emulators do not establish physical-device biometric or OEM power-management behavior.
- Debug and unsigned release APK assembly passed. Production signing, publication and version changes were not performed. Two changed screenshot baselines were visually reviewed: the encrypted destination footer's new Other location control and the transfer error layout.
- Translation-validator tests (8) and German resource structure validation passed; new control/error resources include German translations in separate named XML files. Existing ignored translation files were preserved. Release lint reports zero errors and 260 non-blocking warnings, mainly unused-resource and dependency-version notices.
- A focused security/lifecycle review and the public Maven advisory check are recorded in [ENCRYPTED-SECURITY-REVIEW.md](ENCRYPTED-SECURITY-REVIEW.md#pre-10-development-review--2026-10-13). Neither automated checks nor this source review guarantee absence of vulnerabilities.

Phone/server acceptance before 1.0, using disposable test files:

1. Start an encrypted file upload, leave the folder and briefly turn connectivity off. Restore it and check that the upload finishes once, with the original file opening correctly in Web.
2. Save an encrypted file offline, allow the encrypted download to finish, then turn on airplane mode and unlock its location. Confirm that the file becomes available only after verification and still opens after restarting Raiun.
3. Copy and move files/folders between ordinary and encrypted locations, including two different encrypted locations. Check the unencrypted-destination warning, Cancel/Keep both conflicts, content in Web, and that a failed or cancelled move does not silently delete remaining sources.
4. Scan a large nested backup, interrupt/restart it and check progress, duplicate prevention and the last-scan error display. Revoke a disposable source permission and use the replacement-source picker to recover.
5. Upgrade an existing 0.9.3 installation on the test phone. Check retained accounts, backup settings, offline files, biometric unlock and normal browsing. Test screen locking and leaving the app during uploads, copies and previews.

## 0.9.2 beta: backup editor and upload retry

On a disposable backup, check these interactions:

- Add a new backup and open the date-pattern editor. Enable date folders, choose a preset, insert a date part, and check the preview. Cancel must leave the saved pattern unchanged; Done followed by Save must retain it. Repeat with an existing backup.
- Repeatedly scroll up and down in both backup forms. The form must remain fixed, with Save and Cancel accessible; swiping down and pressing Back must not dismiss it.
- Pause an existing backup and save. Reopen it and confirm the paused indicator. Resume and save to allow scanning again. Uploads queued before pausing may still finish.
- In Transfers, retry recoverable failed uploads together. Downloads, canceled uploads, name conflicts and permission failures must not be silently restarted or resolved. Confirm the feedback and resolve remaining attention items individually.

Local validation for this follow-up: 13 backup-editor host tests, 15 transfer-recovery host tests, two Transfers state tests, and seven backup screenshot tests passed. Five Android 15 emulator tests passed, covering fixed-window scrolling/back behavior, explicit Save/Cancel, new-backup date presets and light/dark exclusions dialogs. Affected Kotlin style/static checks and German resource structure validation passed. Main editor and date-dialog screenshots were reviewed. These checks do not establish phone/server acceptance.

## 0.9.2 beta: backup exclusions

In a backup's settings, open **Exclusions** and enter one pattern in each row. Use the plus control to add a row and the minus control beside a row to remove it. Confirm the dialog, then save the backup. Matching is case-sensitive and uses paths inside the chosen source folder, before date-folder organization. A name without `/` matches anywhere; a pattern containing `/` matches from the source root. `*` matches within a name, `?` matches one character, and `**` can match across folders. A trailing `/` applies only to folders. Matching a folder skips its contents too.

Use a disposable source and destination to check:

- Select all files and add `*.tmp` and `.thumbnail`. Put matching files at the root and in nested folders, and put a normal photo inside `.thumbnail`. None should be uploaded; an ordinary sibling photo should upload.
- Use `Cache/` and confirm it skips a directory named Cache but permits a file with that name. Confirm `cache` remains distinct.
- Use `Camera/*.tmp` and confirm it applies relative to the source root. Check matching before enabling date folders so destination organization cannot hide a matching error.
- Add and remove rows, confirm the dialog, save, leave, and reopen the backup editor. Rules should survive app restart. Canceling the dialog must discard its edits; canceling the backup editor must preserve saved rules. Rotate while the dialog is open and confirm its draft survives.
- Remove a rule and rescan. Previously excluded files should become eligible under the existing backup rules. Files already uploaded must remain in the cloud when exclusions are added. Previously queued uploads may still complete.
- Upgrade from a database created by 0.9.1. Existing backups should retain their destinations, history, and empty exclusion rules.

These instructions describe acceptance checks, not completed device/server testing.

The initial exclusions implementation based on `9668f3f` passed 562 focused host tests (database, sync and files), affected-module ktlint/Detekt checks, debug assembly, locale-validator tests and German resource structure validation.

The subsequent row-dialog UI passed all 58 files-module host tests, affected static checks, backup editor/picker screenshot verification and debug assembly. Two Android 15 emulator instrumentation tests passed for light/dark rendering and add/remove/apply/cancel interactions; both screenshots were visually reviewed. Native-graphics Robolectric dialog rendering timed out, so popup rendering was verified on Android instead. These are uncommitted development results, not a release gate or physical-device/server acceptance result.

## 0.9.1 beta: date folders, video thumbnails and large encrypted previews

Test with synthetic files before using a real backup source:

- Enable date folders in a backup and try `[YYYY]/[MM]/[DD]` and `[MMM]-[YY]`. Verify photo/video capture dates, automatic nested-folder creation and the provider-added/modified fallback for other files. Sources without a usable date belong in `Undated`.
- Put a same-name file in the destination before uploading. Reopen Files from another folder and resolve the persisted conflict. Confirm local originals remain on the device.
- Check video thumbnails in ordinary and encrypted folders, in list and grid views. Unsupported codecs or unavailable server previews may retain the file icon.
- Open encrypted images and PDFs larger than 8 MiB and text larger than 256 KiB. Large text is shown in sections; edit a section and verify the rest of the file remains unchanged in Web.
- Lock or leave an encrypted location during preview loading and reopen it. Preview access must stop; temporary preview storage must contain ciphertext rather than a plaintext file.

WebFinger-based OIDC issuer discovery already exists. Its issuer parsing, legacy compatibility and discovery fallback are covered by the network tests; verify login separately against the intended server configuration.

The local 0.9.1-test.1 working tree passed the complete quality task list above, including 1,148 host tests, screenshot verification, release lint, and debug/release assembly. The targeted native PDF suite passed two tests on each of API 26 and API 35, including a preview larger than 8 MiB. At that point, this was not a complete emulator release matrix or physical-device acceptance run; phone/server checks were pending.

Before the security audit fixes, the clean 0.9.1 release candidate passed the same quality task list with 1,148 host tests. The complete documented API 26/API 35 task matrix also completed: 53 native tests reported, 48 passed, 5 skipped, and no failures or errors. The `feature:files` connected tasks currently have no instrumentation sources and are recorded as no-tests. These results do not establish validation of later changes; publishing still requires checks tied to its final release commit.

## Security audit regressions

Metadata limits apply to server responses describing files and accounts, not to file transfer contents. Verify that chunked and compressed oversized metadata is rejected, small normal responses still work, and the metadata deadline preserves any shorter caller timeout.

For incoming shares, use synthetic files from another app. Selecting Raiun should allow destination selection before file contents are copied. Confirm Upload, cancel during preparation, and retry. Include a provider that stalls, reports an incorrect size, or runs out of simulated free space. Failed intake must not leave partial files or a background writer able to publish later. Already queued uploads must remain retryable without duplication.

Incoming-provider cancellation is best effort before the provider returns a file descriptor: Android cannot force an uncooperative remote provider to honor its cancellation signal. Once a descriptor is available, stalled pipe reads must be cancellation-aware on both supported emulator API levels. These checks do not establish that every third-party provider behaves correctly.

The security-fix candidate (version code 42) passed the complete quality task list above with 1,154 host tests, screenshot verification, release lint, and debug/release assembly. Targeted `core:sync` instrumentation passed three tests on each of API 26 and API 35 (six total, no failures or skips), including stalled-pipe cancellation and asset offset/length preservation. Locale-validator tests passed (eight tests), and German resource structure validation passed with default-language fallback for missing translations. This is a targeted emulator regression run, not a repeat of the complete release matrix or physical-device/server acceptance.

## Backup destination picker

For the 0.9.1 candidate, use a small synthetic source folder and check:

- Choose a destination under Personal, a writable Space, and a writable folder shared with you. Confirm the files appear only in the selected location.
- Use date folders inside a received share and confirm any new folders remain inside that share. Read-only shares and encrypted locations must not become writable backup destinations.
- Edit an existing backup, browse to another destination, then cancel. The original destination and settings must remain unchanged.
- Change a destination and save. Confirm the new location receives the files and local originals remain on the phone. Existing backups that were not changed must retain their upload history after the update.
- Revoke shared-folder upload permission or disable the backup during preparation. No new uploads should be queued afterward; a folder creation already accepted by the server cannot be rolled back automatically.

At the time of the backup-picker candidate, download checksum verification and interruption/offline reliability work were tracked separately. The later combined 0.9.1 candidate includes checksum verification.

The backup-picker candidate (version code 43) passed the complete quality task list with 1,163 host tests, screenshot verification, release lint, and debug/release assembly. The complete API 26/API 35 module matrix reported 57 native tests: 52 passed, five skipped, and no failures or errors. The skipped tests require server configuration or a newer platform; `feature:files` currently has no instrumentation tests. Locale-validator tests passed (eight tests), and German resource structure validation passed with 152 default-language fallbacks. These results belong to the uncommitted candidate source snapshot, not a published release commit. At that point, physical-device and real-server backup acceptance were pending.

## Download integrity follow-up, now included in 0.9.1

This work was isolated from the earlier 0.9.1 backup-picker candidate and was later included in the combined 0.9.1 scope. For ordinary and incoming-share downloads, a supported server checksum is checked over the complete private file before publication, including resumed bytes. Metadata must refer to the requested path, size and strong ETag. Servers without a usable strong ETag or supported optional checksum retain the existing download checks; this is not a guarantee of cryptographic authentication. SHA-1 and MD5 are legacy corruption checks, not modern authentication mechanisms. Encrypted file authentication and transformed thumbnails use their existing paths.

Regression checks should cover checksum mismatch, changed metadata, forbidden metadata, optional unsupported properties, cancellation and interrupted/resumed transfers. A mismatch must not publish the new file or replace an existing valid offline copy.

For specific video playback acceptance, keep an ordinary MP4 offline, disable networking, open it in a player and seek to the middle and end. Repeat with a temporary copy and an inherited folder offline pin. Removing the local copy should make offline open unavailable. Saved incoming-share files currently require a fresh online authorization check; this follow-up preserves that permission policy.

The isolated follow-up passed network and sync lint, Detekt and unit tests: 219 network tests and 410 sync tests, with no failures or skips. App debug Kotlin compilation and German resource structure validation also passed. This is focused host validation, not a new full release/emulator gate, physical-device test, or server acceptance run. No follow-up APK was packaged or signed.


## Combined 0.9.1 candidate with scanner 0.7.0

The scanner update is combined with the backup, security, checksum and transfer work for 0.9.1. The results below were recorded on an uncommitted candidate snapshot; the final release commit needs its own required gates.

`ScannerSdkIntegrationAndroidTest` exercises the actual packaged native processor and exporter using a synthetic 2300 × 3100 page. It checks that JPEG and two-page PDF exports retain those dimensions, PDF page size remains consistent, diagnostics are absent by default, originals remain unchanged, and cancellation clears export staging. Both ordinary and encrypted host routes explicitly disable diagnostic retention. The test does not establish real camera focus, physical-device memory behavior or subjective filter quality.

For phone acceptance, scan a normal printed page and a page with faint writing or shadows. Compare Original, Auto and Black and white, then save a JPEG and a multipage PDF. Zoom into small text in the saved files. Repeat saving into an encrypted folder or Space, including cancellation and locking during the scan. Verify the selected destination, upload retries and saved-file previews. Paper cleanup can still affect faint marks; use Original when exact visual preservation matters.

The combined local candidate (version name 0.9.1, version code 44) passed the complete quality task list: 1,174 host tests, screenshot verification, release lint, and debug/release assembly. The complete API 26/API 35 emulator matrix reported 61 tests: 56 passed, five skipped, and no failures or errors. The four new scanner processor/exporter checks passed (two per API). `feature:files` has no instrumentation sources. Eight locale-validator tests and German resource structure validation also passed, with 152 default-language fallbacks. The APK permission list is unchanged from the previous picker candidate, and all 20 packaged native libraries pass the 16 KB ELF alignment check. Alignment checks do not replace a physical 16 KB-page device run.

These results cover an uncommitted source snapshot based on 542c91e, not a published release commit. Source hashes, build logs and per-module emulator reports are retained with the local integration handover. The owner accepted the combined version-code-44 APK on a physical phone as working OK; this is general device acceptance, not a claim that every camera, filter, server-upload or backup scenario above was tested. The earlier follow-up-only validation paragraph records historical evidence before this combined candidate. Record the required quality and emulator gates again against the exact release commit before publication.

## 0.9.3 beta: missing upload recovery

The checksum-enabled upload verifier now preserves confirmed HTTP 404 responses so the existing conditional recovery can recreate missing destinations. Transient metadata failures fall back to full byte verification. Existing files, pending server processing, and changed remote content remain protected against unconditional replay.

Development validation: all 220 network and 421 sync host tests passed, including real-client regressions for missing destinations, pending processing and changed bytes. Both modules passed ktlint and detekt, and release assembly passed. The owner installed the production-signed recovery test APK and confirmed retrying the affected queue recovered the missing photos. This is device acceptance of the fix, not evidence that the final 0.9.3 release commit has passed CI. Run quality and both API 26/API 35 emulator gates on that exact commit and record the results with the release evidence.

## Monorepo migration validation (2026-10-18)

The unpublished candidate based on `59659926` was moved into `apps/android`.
Fresh debug and unsigned release assembly passed there. The first attempted
build exposed absolute paths retained in old generated intermediates; project
build/cache state was preserved outside source, and a fresh rebuild passed.
The pinned scanner 0.7.0 archive and installed Maven tree were verified again.

Formatting, Detekt/design-token checks, all 1,341 host tests (zero failures,
errors or skips), screenshot verification and release lint passed from the new
Android root. Lint reported 230 warnings and one hint, with zero errors.
No screenshot baseline was re-recorded. All five locales passed strict
validation of 1,397 string/plural keys across 12 modules each; the eight validator
regression tests passed. Existing application source, scripts, schemas,
translations and fixtures retain their pre-move hashes.

The release APK still reports `app.raiun.cloud`, version name 0.9.3 and code 46.
Release development credentials are empty, and the release is non-debuggable.
Version bumps remain deferred to the coordinated release freeze. No production
signing, installation, commit, push, tag or publication was performed.

Both workflow YAML files and action paths were reviewed for the new layout;
report/APK upload globs match local outputs. The translation workflow invokes
each validator in a separate PowerShell process so its exit cannot stop the
remaining languages. CI itself and the complete API 26/API 35 emulator matrix
were not rerun for this migration, and physical-device/server acceptance was
not repeated. These remain final release requirements. Desktop source and its
ongoing development were not changed or imported.

## Android roadmap closeout — 2026-10-26 (unreleased)

The combined updater, directory and documentation changes passed the complete local quality command: formatting, Detekt/design checks, all 1,432 host tests (zero failures/errors/skips), screenshot verification, release lint and debug/unsigned release assembly. Release lint reports zero errors, 267 warnings and one hint; comparison with the published CI report found a new dependency-version advisory, not a new warning on the changed implementation. The eight validator regressions and strict completeness checks passed for German, French, Spanish, European Portuguese and Japanese: 1,456 keys/plurals per locale. No dependency or application/signing identity was changed.

Focused native acceptance ran the app, database, sync and document-provider suites on independent disposable API 26 and API 35 emulator copies. API 26: 44 passed, five assumption skips; API 35: 46 passed, four assumption skips; no failures. The skips cover opt-in updater migration/installation, development/server probes, and the API-26 task-appearance limitation. This is a four-module affected-code run, not the complete eight-module release matrix or a physical-phone upgrade. Native SQLite tests cover root/resource page ordering, exclusions, access revocation, same-count shared-list replacement invalidation and rollback of the TEMP revision counter.

The ordinary-directory fixture has 100,001 rows. It checks first/middle/last windows of at most 128 rows plus a mixed case with 1,100 locked-root descriptors. One measured host run returned ordinary windows in 82–156 ms and the mixed window in 108 ms. These are workstation fixture timings, not phone/network guarantees or whole-process heap measurements. Shared-directory fixtures stream 20,000 children, retain no ordinary child list in the metadata-only refresh, publish/read at most 256 rows per batch, and preserve prior cache state after failed/cancelled/malformed/duplicate discovery. Vault-marker discovery separately tests 20,000 ordinary children while retaining only actual markers. Selection, picker permissions and cached-cursor revocation have focused regressions.

The updater suite now has 23 executions, including lifecycle/daily-throttle and persisted-dismissal cases on API 26/35, and five locale popup interactions at 320 dp with 1.3 font scale. Reconstructing the pinned SDK manager is a host restart model, not an Android process-kill or production phone installation. A future higher-version physical installer journey remains open. Native-speaker sign-off is not required for release; translation problems can be reported through GitHub issues. Automated resource checks remain in place. Encrypted byte-offset upload continuation remains disabled pending a supported finalization contract and its acceptance tests.

Current build logs, source manifests, fixture timings and native results are retained outside Git as closeout evidence. The changes do not select a release version, activate production signing, or publish an APK. Original Android 1.1.0 assets and tags remain unchanged. A future release still requires the full exact-candidate CI/emulator gates and its recorded device acceptance.

### Translation policy — 26 October 2026

The owner removed native-speaker review as a release gate. Earlier entries describing missing linguistic review are historical evidence boundaries, not outstanding release requirements. Automated resource checks remain required; wording and layout problems can be reported through [GitHub issues](https://github.com/phillip9933/raiun/issues/new). No native-speaker review is claimed to have occurred.

### Wi-Fi routing and scoped TLS client certificates — 26 October 2026

The local `work/android-network-auth` candidate passed the full formatting/static-analysis, 1,450 host tests, screenshot verification, release lint and debug/unsigned-release build gate. Five-locale resource completeness passed with 1,500 keys/plurals each. The complete affected native security module passed four tests each on API 26 and API 35 with the same test APK. This repeats that module, not the full eight-module release matrix. Local evidence is in project `outputs/android-network-auth-20261026/`, especially `RESULTS.json` and `quality-final-source.log`.

Native API 26 found that the TLS key-manager callback could lack a handshake session. Exact requested-host/port socket binding fixes that case; default-platform TLS tests verify configured versus unrelated origins on both APIs. Host tests also verify wrong-port rejection. Test identities are disposable synthetic fixtures, never release signing inputs; none are included in the release APK. Host provider-setup failures and initial capture-helper failures are retained separately from successful final runs. No existing screenshot baseline was rewritten.

Actual Wi-Fi/VPN/background permission transitions and real Android KeyChain/browser/IdP provisioning and code-exchange/refresh remain deployment acceptance. Preferences are shared by accounts at the same canonical server address. Local routing retains the public HTTPS hostname/certificate, port and base path. Client-certificate support is at the TLS server/IdP boundary; OAuth mTLS client authentication, endpoint aliases and certificate-bound tokens remain unsupported. See [server connections](SERVER-CONNECTIONS.md). No new version, production signing, push or release is included.

### Published library updates — 27 October 2026

The local candidate now pins updater **0.2.1** (stable, source `60b8fb82aa14ab0fc115ee9f9f96d3cc2c60f5fc`) and scanner **0.8.0-beta.1** (source `8d9a451c27ed87d20110d25dcedb81001e0f521f`). Public release bundles, tag targets and payload checksums were verified before changing Gradle verification/runtime pins and notices. Older updater/scanner material remains preserved. The five consumed scanner modules use one version; the optional OCR engine and model assets are not included. Scanner UI, camera and export AAR bytes are unchanged; OpenCV shared-library bytes are unchanged, while the packaged NDK C++ runtime changed and was exercised by consumer native tests.

Full local quality/build gates passed: 1,450 host tests with no failures/errors/skips, static checks, screenshot verification, release lint, debug and unsigned release assembly. Strict resource completeness passes for all five translated locales with 1,500 keys/plurals each. All 128 release runtime artifacts passed checksum verification. Runtime notices cover 171 dependency records with no missing POM license declarations or unavailable full license texts. The unsigned release APK passes 16-KiB ZIP alignment.

Targeted consumer instrumentation passed **11 tests on API 26 and 11 on API 35**, without failures or skips: two native scanner JPEG/PDF/resolution/cancellation cases, seven updater APK-verification cases and two updater platform/provider cases. This is targeted integration evidence, not the full release native matrix, real photography/card accuracy acceptance or a production-signed future-version installer journey. Publisher CI also passed on the exact updater and scanner release commits. Existing screenshot baselines were not rewritten.

The first host run hit the shared `/tmp` tmpfs capacity and produced file-write/native-runtime-loader failures. Logs and failing reports were preserved; the successful rerun redirected `TMPDIR` and `JAVA_TOOL_OPTIONS=-Djava.io.tmpdir=...` to task-owned storage on the project disk. No unrelated temporary/recovery files were removed. Evidence and artifact hashes are in project `outputs/android-library-upgrades-20261026/RESULTS.json`. No Raiun version bump, production signing, commit/push or publication is included.

## Settings button alignment — 27 October 2026

Local Navigation and permission controls now use the existing filled tonal button style; the Language selector sits beside its title with a bounded width for enlarged text. All 23 focused settings interaction, permission and translated screenshot checks passed. Settings static analysis, settings/design-system formatting checks and debug assembly passed. Eight intentional appearance/permissions screenshot baselines were refreshed; enlarged German/Portuguese and the permission layout were visually inspected. No signing or publication was performed. Evidence: `outputs/settings-button-*-20261027.log` in the project container.

## Wi-Fi and certificate settings UX — 27 October 2026

The local `work/android-connection-settings-ux` UI uses the Wi-Fi icon and **Wi-Fi & certificates** label, a concise server context, optional Wi-Fi/certificate setup, help dialogs and a persistent Save/Cancel footer. All 1,454 host tests passed with no failures/errors/skips, including eight API26/API35 connection-screen executions covering cancellation, optional fields, certificate boundary disclosure and draft preservation. Formatting, static analysis, existing screenshot verification, release lint and debug assembly passed; all five translated locales have 1,510 resource keys with no missing entries. The updated API35 default layout was visually reviewed. Existing screenshot baselines and network/authentication policy were not changed. No native emulator/phone run, production signing, commit or publication was performed. Evidence: `outputs/android-connection-settings-ux-20261027/RESULTS.json` in the project container.


### Local OpenCloud 9 guest-link candidate — 28 October 2026

The uncommitted candidate in `worktrees/android-updater` passed the full local quality gate: ktlint, Detekt, all **1,507 host tests** (zero failures, errors or skips), screenshot verification, release lint, debug assembly and unsigned release assembly. The gate completed in 1m 54s. Version/application identity remain 1.2.0/code 49 and `app.raiun.cloud`; these are local build artifacts, not a new published version.

The 53 guest-specific cases include HTTPS cookie-only requests, custom cookie names, no account authorization headers, permission/share binding, nested DAV browsing, metadata/path/crypto-marker rejection, conditional downloads, cancellation and fixed safe errors. UI tests require explicit invitation/revocation actions. Recipient tests cover server confirmation without a request, content-URI-only export, picker handoff/reauthentication, screen-off and configuration-change retention. API 26/API 35 cases here use **Robolectric**, not connected instrumentation or a physical phone. The confirmation diagnostic screenshot was visually inspected. All five locales passed strict validation for 1,567 keys/plurals each; eight validator regressions passed. No native-speaker or physical layout acceptance is implied.

An independent scoped source review identified a configurable cookie-name compatibility issue, which was fixed and covered by HTTPS/cookie tests. A final delta review found no additional high/medium auth, credential-leak or path-scope finding in the reviewed code; that is not a guarantee or a live penetration test. Intermediate failing parser/test-fixture/static-analysis/lifecycle runs remain preserved in outputs; only the final successful gate establishes these results. Existing lock/provider checks were not weakened.

Evidence is in `outputs/opencloud9-guest-links-20261028/{RESULTS.json,host-test-results.json,acceptance-gate.log}` outside Git. No invitation/renewal email or live server mutation occurred. No signing, commit, push, tag or release occurred. Connected native CI was not rerun; the separately recorded API 26/API 35 lock/window failures remain undiagnosed. Use [the server/device checklist](OPENCLOUD-9.md#acceptance-still-required) before publication.


### Scoped live OpenCloud 9 checks — 28 October 2026

The owner installed server 9.0.0 with SMTP and separately reported that guest links work in the web client. The dedicated `chatgpt` web session displayed the Guest invitation option; no invitation was sent by the agent. `/status.php` confirmed product version 9.0.0.

Two opt-in native negative-contract cases passed against the live guest endpoint: one on API 26 and one on API 35, using normal DNS, platform TLS trust and hostname verification. Each made one request with a synthetic invalid token and received HTTP 404 `tokenNotFound`, correctly classified as `NotFound`. These are connected-native endpoint checks, not positive guest access, native invitation creation, mail delivery, revocation or file-provider acceptance. The account-authenticated read-only probe was explicitly skipped because the dedicated debug login was not configured; its runner's `OK` summary must not be described as an executed pass.

Earlier copied AVD fixtures could not connect: API 35 retained airplane mode from prior offline tests, while the exact old API 26 fixture-network mechanism was not established. API 35 passed after only its disposable runtime was brought online; API 26 passed in a fresh config-only task AVD with no copied userdata. Original AVDs and the phone were untouched. Both task emulators are stopped. No certificate checks, app locks, provider tests or server settings were weakened.

The final app formatting/static-analysis/instrumentation-build gate passed in 13 seconds. Only opt-in instrumentation sources were added during this live phase; the previously validated production APK remains byte-identical. No production signing, publication or guest emails occurred. Evidence and a creation-first phone checklist are under `outputs/opencloud9-live-20261028/`. The existing unrelated native CI lock/window failures remain separately undiagnosed.


### Guest invitation capability/UI correction — 28 October 2026

The owner reported a false denial on opening guest management in the production-signed guest test1. Exact tagged OpenCloud9 source confirmed OCS `version.string` is legacy compatibility `0.1.0`, not the product release. Guest availability now uses actual boolean `files_sharing.guest_links.enabled` plus ordinary sharing. Malformed or absent guest advertisement cannot enable guests and does not disable otherwise-valid ordinary capabilities. Real server permissions and all account/lock/cancellation/fresh-metadata checks remain authoritative. Unsupported feature and actual permission denial now render different messages.

The full local gate passed **1,518 host tests**, ktlint, Detekt, screenshot verification, release lint, debug/unsigned-release assembly and instrumentation APK assembly. Five locales passed strict completeness for1,570 keys each. The own Guest access category uses the Internal/External typography and primary-button styling. API26/API35 Robolectric layout tests expand the actual Material sheet before checking offscreen sections; the earlier two layout failures are preserved, and the final assertions remain in place. Diagnostic API35 rendering was visually checked.

Guest test2 was signed with the original production identity under the ongoing owner-authorized phone-test task. Version remains1.2.0/code49; development credentials are empty, non-debuggable status/certificate/16-KiB alignment are verified, and each unsigned application payload entry is byte-identical after signing. The earlier guest test1 and unrelated dirty work remain preserved. Evidence is `outputs/opencloud9-guest-fix-20261028/RESULTS.json`; the APK/checksum are in `outputs/android-guest-signed-test-2-20261028/`. No commit, push, release, live invitation or mail was performed. Positive phone creation/access acceptance remains pending; this does not establish a fresh connected-native full matrix or clear the separately recorded CI failures.


### Guest empty-permissions metadata fix / phone test 3 — 28 October 2026

OpenCloud v9.0.0 omits the permissions collection `value` when an item has no shares. The client now accepts that response only after validating role metadata; explicit malformed collection types and mutation results remain strict. Source-derived file/folder fixtures cover discovery, refresh and invitation, and the UI regression confirms an empty list allows opening Invite without sending a request. All **1,522 host tests** passed with zero failures/errors/skips, along with formatting, static analysis, screenshot verification, release lint, debug/unsigned-release and instrumentation APK assembly. No fresh connected-native full matrix was run; earlier CI lock/window failures remain undiagnosed.

The owner-approved replacement phone APK is `outputs/android-guest-signed-test-3-20261028/raiun-android-1.2.0-guest-test.3.apk` in the project container, SHA256 `9beba7047a4bf6f86cd7d9cd3646a0526f1b12f773f4e4307f6b38f6f44383ef`. Production certificate, unchanged payload, empty development credentials, non-debuggable state and 16-KiB alignment were verified. Identity remains `app.raiun.cloud`, 1.2.0/code49. No live invitations/emails, commit, push or release occurred. Positive phone invitation acceptance remains pending. Evidence: `outputs/opencloud9-guest-metadata-20261028/RESULTS.json`. The server contract lesson was passed to the Desktop Client chat.


### Guest recipient phone report — 28 October 2026

The owner confirmed creating/sending an invitation in guest test 3, and recipient browsing/downloading in the web client. Native recipient acceptance remains incomplete: pasting into **Open guest invitation** reportedly returns to the regular Personal files screen. This was not the normal server-address login field. Root cause is not established; a used token, parse failure or crash must not be asserted without evidence. A new synthetic full review/redemption/Graph/DAV/render regression passes on Robolectric API26/API35; all four GuestLinkScreenTest executions and app formatting/static checks pass. These are not physical or live positive recipient acceptance. No production source change, replacement signing or publication occurred during this investigation. Desktop Client received the scoped acceptance and outstanding issue. Evidence: `outputs/opencloud9-guest-entry-20261028/RESULTS.json` in the project container.


### Guest sender-only scope / phone test 4 — 28 October 2026

The owner withdrew native recipient access for now. Removed the login/Shares opening buttons, text-share dispatch, private guest activity/session, recipient network/cookie/DAV code and recipient-only resources/tests. Exact backups of the 26 task-created removed files are outside Git in `outputs/opencloud9-guest-sender-only-20261028/removed-recipient-source/`, with SHA256 receipts. Existing ordinary sharing and guest invitation creation/list/update/revocation remain, including the explicit capability and empty-permissions fixes. Recipients use the server web client. Desktop Client was sent the scope change. The earlier phone return-to-Personal root cause was not established and is not claimed fixed.

All **1,485 host tests** passed with zero failures/errors/skips; the final gate passed formatting, static analysis, screenshot verification, app and security-module release lint, debug/unsigned release and instrumentation assembly. Five locales are complete for 1,546 keys each; eight validator regressions passed. An initially broader library-lint run found the security module lacked its own ACCESS_NETWORK_STATE declaration. That declaration is now present and module lint passes; comparison with test 3 confirms the app permission list is unchanged. Earlier failed logs remain in evidence. No new connected-native matrix or physical acceptance is implied; prior CI lock/window failures remain undiagnosed.

The production-signed replacement APK is `outputs/android-guest-signed-test-4-20261028/raiun-android-1.2.0-guest-test.4.apk`, SHA256 `7a95b44d5b01c633742b1ed597453a6b6bab47217d7f3ef46be3ec07f5089f64`. Original signer, non-debuggable state, empty development credentials, 16-KiB alignment and unchanged signing payload were verified; removed recipient classes are absent from DEX. App identity remains app.raiun.cloud, 1.2.0/code49. The owner accepted invitation send and web recipient browse/download on prior test 3; this replacement APK has not yet been tested on the phone. No commit, push, tag, publication or live invitation/email was performed. Evidence: `outputs/opencloud9-guest-sender-only-20261028/RESULTS.json`.


### Owner sender-only phone acceptance / test 4 — 28 October 2026

The owner tested `raiun-android-1.2.0-guest-test.4.apk` and reported “looks like it works fine.” This records general owner-reported phone acceptance of the sender-only candidate identified in the preceding entry, superseding its pending-phone status. The earlier test 3 report separately established invitation sending and browser recipient browsing/downloading. No exhaustive role, expiry, update or revocation matrix is claimed. Native guest receiving/browsing remains outside scope; the historical return-to-Personal cause remains undiagnosed.

This owner report is separate from automated validation. It does not establish a fresh connected-native matrix or clear the prior CI lock/window failures. No new build, signing, commit, push or publication was performed for this documentation update.


### Native UI readiness and OpenCloud 9 upload assessment — 28 October 2026

The four affected app regressions passed individually on fresh task-owned API26/API35 emulators, and the unfiltered app suite passed in normal order (34/35 executed cases, optional/platform skips separate). A controlled API26 screen-off setup reproduced the same lock-screen text assertion while dumps showed the display remained asleep. This establishes an environmental reproduction, not the historical CI run's root cause; its exact APKs were unavailable and that failed run remains failed.

The test fixture now explicitly wakes the display, dismisses only an unsecured keyguard, and refuses a secure locked device with manual-unlock guidance. Backup input waits for the target app's active window before gestures/raw Back; it does not retry failed input. All original lock-screen, provider-denial, Save/Cancel, geometry and non-dismissal assertions remain. Bounded stage/lifecycle/lock/focus diagnostics omit exception messages, intent data and accessibility text; CI now collects the additional-output directory. Complete lock/provider assertions pass from an intentionally asleep start on both APIs.

The final eight-module native matrix passed: **API26: 52 executed passes, 6 explicit skips; API35: 54 executed passes, 5 explicit skips**. The files module has no instrumentation cases. Report counts were computed from testcase nodes because UTP's tests attribute can exclude skipped cases. All **1,485 host tests** and full formatting/static/screenshot/app-lint/debug/release build gates passed. Source/evidence, baseline results, controlled failure, native XMLs and task-AVD provenance are preserved in `outputs/android-backlog-next-20261028/`; both task-owned emulators are stopped, originals/phone untouched. This is local candidate validation, not a new independent exact-commit GitHub CI run or physical Wi-Fi/mTLS/guest-revocation acceptance.

Exact OpenCloud9/Reva source confirms missing durable conditions in public TUS initiation; #11 stays open and byte-offset encrypted uploads remain disabled. Ordinary PUT forwards expected-ETag conditions. Create-only behavior has a narrower pre-initialization timing qualification, while new-at-initialization decomposedfs finalization already atomically refuses name collisions. No live race/exploit or exhaustive global ingress audit is claimed. See OPENCLOUD-9.md and the source assessment/qualifications plus unsent upstream report draft in `outputs/android-backlog-next-20261028/upload-resume/`.

The unsigned production runtime APK is byte-identical to the accepted signed guest test4's original payload, so these test/docs/workflow changes do not require another phone build. No production signing, commits, pushes, tags or publication occurred. Native guest receiving remains withdrawn.

### Shared design review follow-up

Issue [#42](https://github.com/phillip9933/raiun/issues/42) tracks the shared Raiun design reference. Android's local native mapping is documented in [Shared design](SHARED-DESIGN.md), with scoped validation below. Desktop catalog/token results do not grade Android. Physical accessibility and focus acceptance remain separate; palette contrast alone does not establish whole-app readiness.


### Shared native Material style candidate — 28 October 2026

The owner authorized fixes for the ten findings in the shared-style review and a production-signed phone test. The candidate now maps the frozen shared draft explicitly to native light/dark Material roles, with readable authentication errors, stronger control outlines and quiet decorative dividers. Stable account accents and a sanitized account/server header improve account context. Labelled metadata toggling, compact/large-text updater reflow and crop pan accessibility actions have targeted regressions. Backup Save emphasis, contextual transfer replacement confirmation, native disabled danger colors, neutral Space/encrypted headers and unknown-size progress complete the reviewed flow changes. Native fonts, controls and text/icon overflow menus remain.

All **1,501 host tests** pass with zero failures/errors/skips. Formatting, static analysis, screenshot verification, release lint, debug/unsigned-release and instrumentation assembly pass. The eight-module native matrix passes: **API26: 52 executed passes, 6 explicit skips; API35: 54 executed passes, 5 explicit skips**. The files module has no instrumentation cases. Counts use testcase nodes, avoiding UTP tests-attribute ambiguity. All five locales are complete for 1,554 keys each; eight validator regressions pass. Seven fresh host renders and representative light/dark golden images were reviewed. The global palette intentionally changes 117 baselines; all 136 prior baselines and intermediate failures are preserved outside Git. This is scoped evidence, not whole-app TalkBack/keyboard certification or independent GitHub CI.

Evidence is in `outputs/android-style-fixes-20261028/{RESULTS.json,quality-final-source.log,native-matrix.log,PHONE-TESTS.md}` in the project container. Only fresh task-owned API26/API35 AVDs were used and stopped; originals and the phone were untouched. The production-signed `outputs/android-style-signed-test-20261028/raiun-android-1.2.0-style-test.1.apk` preserves `app.raiun.cloud`, version1.2.0/code49 and the original signing certificate. Non-debuggable state, empty development credentials, 16-KiB alignment and byte-identical unsigned payload after signing are verified. Physical style acceptance remains pending. No commit, push, tag or release occurred; prior unpublished connection and sender-only guest work remain preserved.


### Compact native header and phone-unlock session candidate — 28 October 2026

Owner feedback replaces the separate account identity row with the account accent behind the existing menu/search/profile app bar. Account details remain in the existing account action and accessible context. Native status-bar padding stays outside the accent so existing system-icon contrast follows the screen theme; native inset consumption avoids another row or doubled inset.

Encrypted preferences now has a labelled Material **Ask every time** switch. Default off: after the first successful password/biometric proof, up to eight exact-location verified keys may stay only in process memory while a secure phone is awake and unlocked. Every reentry closes/replaces the route session and repeats repository account/access/proof checks. Screen-off, observed locked/insecure/unavailable state, explicit location lock, access resets and policy changes revoke appropriate grants; process death loses them. Ordinary OAuth refresh preserves the grant. Strong biometric Keystore envelopes, account identity, ciphertext formats and offline data remain unchanged. This intentionally keeps verified keys in memory longer; Ask every time retains stronger per-entry authentication. Buffer wiping remains best-effort.

All **1,535 host tests** pass, zero failures/errors/skips, with full formatting/static/screenshot/release-lint/debug/release/instrumentation build gates. The eight-module native matrix passes **API26: 52 executed, 6 explicit skips; API35: 54 executed, 5 explicit skips**. After the final toolbar-inset-only adjustment, affected app/files native tasks were rerun successfully; the six core test APK hashes remained identical to the passing full matrix. The files module has no native cases. Twenty-one deliberate visual baselines changed, with all 136 previous images preserved outside Git. Five locales are complete for 1,557 keys; eight validator regressions pass. Separate source/delta security review found no remaining definite defect in the reviewed changes. New password/biometric admission and fake online/offline reentry host tests do not establish physical phone or new live server acceptance. Existing authenticated-offline sync tests also pass.

Evidence is `outputs/android-phone-unlock-20261028/`, including RESULTS.json, SECURITY-REVIEW.md, PHONE-TESTS.md and exact logs. The original-production-key phone APK is `outputs/android-phone-unlock-signed-test-20261028/raiun-android-1.2.0-style-test.2.apk`, SHA256 `1acfc7828208e667d102610602e67e55f62eb1a77f007f96030c75715d412999`. Signing verification confirms original certificate, app.raiun.cloud1.2.0/code49, nondebuggable/empty development credentials, 16-KiB ZIP alignment and unchanged unsigned payload after signing. Two fresh task-owned AVDs were stopped; originals/phone untouched. Physical style/biometric/lifecycle acceptance remains pending; no commit, push, tag or release.


### Subtle account color candidate / phone style test 3 — 28 October 2026

Owner approved replacing full account-colored chrome with normal Material toolbar colors, a slim theme-adjusted avatar ring, and a soft selected-account tint. Account information now exposes Account color → Edit, with Automatic, eight named families, Light/Dark previews and explicit Save/Cancel. Named choices are stored locally per account and removed by account cleanup; no account ID, server profile/photo, credential, signing or ciphertext format changes. A separate color revision updates markers without triggering profile-picture reloads. Toolbars use normal native colors/insets and no additional identity row. Prior phone-unlock and guest/connection work remains preserved.

All **1,542 host tests** pass, zero failures/errors/skips. Full formatting/static/screenshot/release-lint/debug/release/instrumentation assembly passed; final app/static/screenshot/lint verification also passed after a test-only font-harness correction. Dialog windows did not inherit the earlier simulated density override: the corrected host API35 test sets Android font scale and asserts the actual text-layout density is2.0, then selects a lower palette item and activates Save. Its old mis-scaled image is preserved outside Git. The release runtime APK stayed byte-identical across that test-only change.

The scoped connected-native app/UI regressions passed **API26: 31 executed, 6 explicit skips; API35: 33 executed, 5 explicit skips**. This run covers app, core/ui and files (files has no cases); it is not a fresh eight-module matrix or independent exact-commit CI. Five locales pass strict completeness for1,573 keys each and eight validator regressions pass. Twenty-three existing baselines intentionally changed and two picker images were added; all136 prior baselines remain backed up. Representative neutral-browser/account/picker light/dark renders were reviewed. Full TalkBack/keyboard and owner physical acceptance remain separate.

Evidence: `outputs/android-account-colors-20261028/` in the project container, including RESULTS.json and PHONE-TESTS.md. Production-signed local APK: `outputs/android-account-colors-signed-test-20261028/raiun-android-1.2.0-style-test.3.apk`, SHA256 `5c47dc2bb8397025f6560c9e4dfdd120fad7bfc03a938e6e34bddffeabba1ad2`. Original certificate, app.raiun.cloud1.2.0/code49, nondebuggable/empty development credentials,16-KiB alignment and unchanged unsigned signing payload verified. Two fresh task-owned AVDs were stopped; originals/phone untouched. No commit, push, tag or release.


## Local overnight Android candidate (28–29 October 2026)

The dirty `work/android-connection-settings-ux` worktree remains based on published Android 1.2.0 (`0bb587e`), with no new version, commit or publication. The candidate adds paged Favorites/ordinary Offline inventories and online/offline encrypted directories, bounded unlock/worker metadata handling, encrypted scanner/text transfer admission, fresh Office browser recovery and clearer offline-capacity failures. This is local candidate evidence, separate from the owner's earlier style3 visual acceptance and published upgrade acceptance.

The final complete quality/build gate passed **1,630 host tests, zero failures/errors/skips**, formatting checks, static analysis, screenshot verification, release lint, debug and unsigned-release assembly, and instrumentation assembly. Release lint reports zero errors, 250 warnings and one hint. All prior accepted snapshot image hashes remain unchanged; no golden recording was used to hide a failure. Five locales pass strict completeness for 1,575 keys across 12 modules, and eight locale-validator regressions pass. These are structural/local checks, not native-speaker acceptance.

The eight-module connected-native matrix passed **API 26: 55 executed passes, six explicit skips; API 35: 57 executed passes, five explicit skips**. Counts use testcase nodes, not the UTP console's inflated completion count. `feature/files` contains no native cases. The core runs and final app/UI runs are composed from unchanged APKs; the sole core APK changed by the final UI dimension token (`core/ui`) was rerun on both APIs. The five other core APK hashes remained identical. Opt-in installer/migration/live-server journeys remain skipped; API 26 also skips the API-specific dark-recents case. Three new encrypted-index native cases on each API cover encrypted staging, paging, owned cleanup and app-private alias/symlink behavior; they are included once in the matrix totals.

Initial failures remain in the evidence directory. Host/native picker fixtures were updated to explicitly bind the new source-admission callback while retaining their copy/move/offline assertions. An actual 320-dp/2×-font regression first reproduced encrypted Next clipping; both actual-density click tests now pass with shared responsive controls. The final native fixture formatting/static checks also pass. These results do not establish physical biometrics, camera quality, live server concurrency, Wi-Fi routing, browser/IdP/KeyChain or two-user Office save convergence.

A bounded independent security/data-safety review and a separate code-health review found no remaining actionable finding in their documented scopes. A new recovery test found and fixed a pre-existing conflicting-response-ETag gap. The review is not a security certification or a whole-codebase guarantee. Byte-offset encrypted upload continuation remains disabled without a verified conditional commit contract. Recursive encrypted offline pinning remains foreground; the authenticated offline manifest retains its 16-MiB capacity bound and complete-refresh/prune semantics.

Evidence and simple phone checks are outside Git in the Raiun container: `outputs/android-overnight-20261028/`, including RESULTS.json, CHECKPOINT.json, full-quality-4.log, final-host-results.json, final-native-results.json, SECURITY-REVIEW.md, CODE-HEALTH-REVIEW.md and PHONE-TESTS.md. The original signing material and accepted style3 APK remain untouched. The new release payload is unsigned, `app.raiun.cloud` 1.2.0/code49, with empty development credentials and verified 16-KiB ZIP alignment. Only task-owned disposable AVDs were used and stopped; the phone and original AVDs were untouched. No live server/mail/file mutation, new installation of tools, production signing, commit, push, tag or release occurred.

### Retained transfers and boundary operations — overnight Phase 2

The later local candidate adds 128-row retained-transfer queries, global filter/count semantics, scalar browser/backup summaries and whole-account bulk actions guarded by an account incarnation and monotonic queue-admission watermark. Regressions include 100,000 retained rows, date/DST and Unicode file-type equivalence, later backdated admissions, identical account removal/recreation and retry compare-and-set races. Both download waiters now observe a single account-scoped row. Opening a downloaded ordinary file rechecks cancellation, the captured app-action permit and the original path/parent/kind/ETag before validating current cache data.

Boundary exact-target/name/empty/post-delete proofs are streamed; scoped entry handles survive unrelated UI paging and writes without authorizing a different file descriptor. Same-session source/readback and destination content streams use separate temporary instances of the actual rclone engine. Native synthetic-loopback tests exercise a larger-than-pipe-buffer copy and readback, wrong-MIME descriptor refusal, stalled cancellation, fork closure and refusal after session closure. The first native fixture incorrectly manufactured `text/plain` where production vault descriptors expose no MIME type; exact matching rejected it before transfer. The fixture was corrected and retains explicit descriptor equality and mismatch-refusal assertions. Earlier failed logs are preserved; production checks were not relaxed.

The complete local gate passes **1,670 host tests, zero failures/errors/skips**, formatting/static checks, screenshot verification, release lint, debug/unsigned-release builds and affected instrumentation assembly. Release lint remains zero errors, 250 warnings and one hint. All 36 accepted screenshot baselines and ten protected German resource hashes are unchanged; six paging resource files moved byte-identically from `feature:files` to shared `core:ui`. All five locales pass strict 1,575-key completeness across 12 modules and eight validator regressions.

The full eight-module connected matrix passes **API 26: 57 executed passes, 6 explicit skips; API 35: 59 executed passes, 5 explicit skips**, with no failures/errors. Counts use XML testcase nodes; `feature:files` has no native cases. The real-rclone pair also passed separately on each API. These tests use local synthetic data, not the owner's phone, a production upgrade or live server/mail acceptance. Evidence is `outputs/android-overnight-20261028/phase2/`, including RESULTS.json, full-quality-3.log, native-api26-results.json, native-api35-results.json and PHONE-TESTS.md. The unsigned payload remains `app.raiun.cloud` 1.2.0/code49; no new release or production signing occurred.

Recursive boundary lists/complete child comparisons and destination name sets still use legacy collection paths. Temporary-copy maintenance remains a separate full-inventory path; its next bounded design must preserve pin/active-reader/active-download guards, cache-lock ordering and candidate/account identity. Generic encrypted byte-offset upload resume stays disabled without a verified conditional server-finalization contract. Transparent background recursive offline refresh/prune remains unfinished. Scoped reviews and passing local tests do not establish an independent security certification or physical deployment acceptance.

### Recursive transfer snapshots — overnight Phase 3

The next local slice replaces recursive `BoundaryTransfer` child lists and complete-child maps with independent encrypted `BoundaryDirectorySnapshot` stages. Production ordinary/vault adapters await complete streamed validation before returning descriptors. The final manifest proof uses one expected record at a time, keyed actual lookup and exact frozen counts, preserving the full source/destination verification barrier before source deletion. Empty comparisons also recheck snapshot ownership. Destination chooser lists and conflict-name sets remain separate legacy paths; this does not claim every large-folder interaction is finished.

The full local quality/build gate passes **1,692 host tests, zero failures/errors/skips**, including **635 sync cases**, formatting/static checks, screenshot verification, release lint, debug/unsigned-release builds and instrumentation assembly. The first run passed its tests/builds but failed one path-condition complexity check; a boolean extraction preserved validation and the complete rerun passed. The final native-only integration assertions were separately formatted, statically checked and compiled afterward. No baseline recording or guard/test weakening was used. Lint remains zero errors, 250 warnings and one hint; accepted golden images and protected German resources retain their hashes. Production resources are byte-identical to the Phase 2 locale-validated set.

The complete eight-module native matrix passes **API 26: 58 executed passes, 6 explicit skips; API 35: 60 executed passes, 5 explicit skips**, with no failures/errors. Both task emulators ran in one Gradle pass; the API26-named log includes both devices because the project serial property did not filter `connectedDebugAndroidTest`. Results are separated by the actual device names in XML, not inferred from that filename. `feature:files` has no native cases. Three focused cases additionally passed on each API: the production SQLite/JCA stage with 333 descriptors; real vault-stream/name-decryption/stage integration and larger-than-pipe-buffer native copy/readback; and stalled native cancellation/fork cleanup.

Host regressions cover 1,025-entry and byte-budget pages, exact null/empty/MIME/version tuples, hidden/Unicode and long paths, oversized records, duplicate IDs/canonical paths, malformed/truncated codec data, encrypted stage corruption, frozen-count truncation, cancellation/late delivery, guard/close races and independent owned-file cleanup. Recursive tests exercise 302 files across batches and nested directories; late capture refusal starts no child copies, and same-count identity/version/MIME changes prevent source deletion. Actual endpoint tests include a greater-than-2-MiB encrypted listing, UI/destination-mutation independence, trailing ordinary encrypted markers and malformed final XML.

Evidence is `outputs/android-overnight-20261028/phase3/`, especially RESULTS.json, full-quality-2.log, native-fixture-gate.log, final-host-results.json, final-native-results.json, SECURITY-AND-HEALTH-REVIEW.md and PHONE-TESTS.md. Earlier Phase 1/2 snapshots and artifacts remain intact. The new release payload is unsigned, still `app.raiun.cloud` 1.2.0/code49, with verified 16-KiB ZIP alignment. Only task-owned emulators were used and stopped. No production signing, commits, pushes, releases, new tools, live server/mail changes or owner-phone changes occurred. Physical/live deployment acceptance, byte-offset upload finalization, durable recursive offline groups and temporary-copy maintenance remain separate work.

### Destination name reservations — overnight Phase 4

Placement planning now captures complete validated parent names once into a private HMAC-only membership/reservation index. Production adapters include ordinary encrypted-marker names without manufacturing readable descriptors; vault adapters retain full child decryption/framing checks. Atomic reservations preserve exact Unicode/case and suffix/extension behavior. The index closes before conflict UI, all-source preflight or copying; Keep both captures a fresh parent. Requests and chosen target names still use memory proportional to the selected items. Chooser folder lists remain a separate unbounded path.

The combined local quality/build gates pass **1,713 host tests, zero failures/errors/skips**, formatting/static analysis, screenshot verification, release lint, debug/unsigned-release builds and native fixture assembly. Two initial test-format diagnostics were already corrected by the formatter; the complete rerun passed without semantic changes. The unused Set-based production naming helper was removed, with its three existing filename assertions moved to the actual indexed planner. An independent previous-Set oracle exercises full controller choices, first conflict, fresh Keep both, Cancel and all-source preflight. Production resources remain byte-identical to the earlier five-locale-validated set; accepted screenshots and protected translations are preserved.

The final complete eight-module native matrix passes **API 26: 59 executed passes, 6 explicit skips; API 35: 61 executed passes, 5 explicit skips**, with no failures/errors. Four targeted native cases also pass separately on each API, covering HMAC-only membership/lifecycle, encrypted descriptor pages, actual vault stream/name-decryption/both-index integration and native content roundtrip/cancellation. `feature:files` has no native cases. Counts use actual XML testcase nodes and `ANDROID_SERIAL` restricts each run to its task emulator.

The first full API35 run failed the native cancellation fixture: it revoked permission before cancelling the child, and a correctly timed AccessDenied escaped its unhandled launch. The corrected fixture accepts only deliberate AccessDenied or cancellation after a real PUT starts. Unexpected success/other errors, nontermination, active fork leaks, deletion, source loss and post-close access still fail. Production code was unchanged by this correction. Both full matrices were rerun against the final fixture; first failures/reports remain preserved and are not labelled harmless flakes.

Exact evidence is `outputs/android-overnight-20261028/phase4/`, including RESULTS.json, full-quality-2.log, native-fixture-gate-2.log, final-host-results.json, final-native-results.json, native-api35-first-results.json, INDEPENDENT-REVIEW.md and PHONE-TESTS.md. The app identity/version remains `app.raiun.cloud` 1.2.0/code49; release output is unsigned. Earlier green snapshots and artifacts are immutable. No production signing, Git publication, new tooling, live server/mail writes or owner-phone changes occurred. Destination chooser paging, temporary-copy maintenance, metadata lookup latency, offline-group recovery and server-conditional byte-offset resume remain explicit limits.


### Destination chooser paging — overnight Phase 5

The interactive copy/move chooser now retains one bounded page from an owned encrypted folder-metadata snapshot. Complete raw child validation precedes filtering/publication, including ignored files. Independent ordering tests compare 534 entries and byte-short chunks against the former stable ROOT-lowercase order under a Turkish default locale; default vault-browser order remains unchanged. Marker IDs/paths are preserved for unlock routing. Lifecycle tests cover late captures/pages, cancellation, failed targets, empty guards, source-session ownership and cleanup. A real 320dp dialog fixture with resource font scale 2 verifies paging and placement controls; this is Robolectric window validation, not physical phone acceptance.

The complete quality gate passes **1,736 host tests, zero failures/errors/skips**, formatting/static checks, screenshot verification, release lint, debug/unsigned-release builds and native assembly. The first gate exposed a real raw-ID/path registration mistake in the ordinary producer; independent ID/path registration and ignored-file duplicate/alias regressions correct it. Its other failing test incorrectly injected font scale outside the dialog window; resource-level font scale now reaches the actual layout, retaining the original assertions. Initial reports remain in phase5/gate1-host-test-reports; the targeted correction gate and complete rerun pass. The final native-only integration assertion was separately formatted, statically checked and compiled. Lint remains zero errors, 250 warnings and one hint. All 517 production resource files are byte-identical to the earlier locale-validated set; 36 accepted goldens and ten protected German resources are unchanged.

The final eight-module native matrix passes **API 26: 60 executed passes, 6 explicit skips; API 35: 62 executed passes, 5 explicit skips**, with no failures/errors. Each run was restricted by ANDROID_SERIAL to its task-owned emulator. Five focused cases also passed separately on each API, including the new actual SQLite/JCA 339-folder metadata/marker/order case and the real vault parser/content pipeline. The files module has no native cases. Counts use testcase nodes, not UTP's aggregate tests attribute.

Evidence is outputs/android-overnight-20261028/phase5/, including full-quality-2.log, native-fixture-gate.log, final-host-results.json, final-native-results.json, INDEPENDENT-REVIEW.md and PHONE-TESTS.md. The payload remains unsigned, app.raiun.cloud 1.2.0/code49. This is local synthetic acceptance, not a new exact-commit GitHub CI run, signed phone upgrade, live server/Office trial or physical Wi-Fi/KeyChain deployment check. Temporary-copy maintenance, selected-item memory, repeated fresh-parent lookup latency, the 16-MiB offline manifest, durable recursive offline groups and conditional byte-offset upload recovery remain explicit limits. Earlier snapshots/artifacts and failures are preserved; no signing, publication, new tools or live server/mail/phone changes occurred.


### Offline metadata and ordinary temporary cleanup — 29 October 2026 (unpublished)

The continuation adds frozen file-backed ordinary temporary-copy inventories and authenticated RVO2 offline metadata generations. Original complete resource rows are paged in 128-row BINARY identity windows; new downloads do not enter a running cleanup. Account-incarnation/full-row CAS and pin/ancestor/download/cache-use/path/size/age checks precede deletion. OS ownership locks support bounded stale-stage reclamation without sweeping live, unknown or symlink files. This does not change the separate explicit Remove all or shared-cache maintenance semantics.

The RVO2 index removes the 16-MiB aggregate metadata cap while retaining bounded records/chunks. Complete ordered membership/count/AEAD validation precedes use; generation/blob leases protect readers. Successful mutations import authenticated RVO1 without rewriting ciphertext or changing key identities. Read-only legacy access preserves the old format; old binaries cannot read RVO2 after migration. v3 local PREPARED/COMMITTED recovery is separate from v1/v2 Room-authorized transfer recovery. Owned directory entries are synchronized before publication; ambiguous commits retain both sides and the journal. This is not proof of a complete Room/filesystem power-loss transaction.

All **1,778 host tests pass with zero failures/errors/skips**, including **695 sync cases and 138 database cases**. Full formatting/static/screenshot checks, release lint, debug/unsigned-release builds and instrumentation assembly pass. Lint remains zero errors, 250 warnings and one hint. All 517 production resource files, 36 accepted golden images and ten protected German resources retain their hashes; existing five-locale validation applies to that identical resource set.

The final complete eight-module native matrix passes **API 26: 67 executed passes, 6 explicit skips; API 35: 69 executed passes, 5 explicit skips**, with no failures/errors. The files module has no native cases; counts use XML testcase nodes. The two new actual SQLite/file-lock cases and five index/durability cases also passed separately on each API. Native tests include >16-MiB streamed metadata, a 3-MiB chunked record, tamper/cancellation/reader cleanup, public Android directory fsync and real rclone content with local receipt recovery. Host fixtures use real JVM directory force because Robolectric ShadowLinux cannot open a directory through AndroidOs; the native path remains the actual Android implementation.

Initial failed gates are preserved in outputs/android-continuation-20261029/: rawQuery null binds, SQLite PRAGMA result handling, an invalid readonly BEGIN mode, a syntax extraction error, stale-base-reader cleanup after accepted cancellation, backup-only catalog capture, directory confinement/SDK API issues and absent-directory synchronization were corrected without weakening the original assertions. Two new integration fixtures incorrectly used INSERT for existing rows and now use actual UPDATE. Host-runner directory-open failures are distinguished from actual Android results. See foundation/RESULTS.json, full-quality-1.log, full-host-results.json, final-native-results.json, TEMPORARY-CLEANUP-RESULTS.json and PHONE-TESTS.md for exact scope.

The application remains app.raiun.cloud 1.2.0/code49; the new payload is unsigned. No production signing, commit, push, release, tool installation, live server/mail writes or owner-phone changes occurred. Physical signed-upgrade, Wi-Fi/KeyChain/IdP and Office acceptance remain separate. Durable encrypted offline groups and verified server-conditional upload continuation are not claimed delivered by this foundation. The owner requested continued work; implementation proceeds after preserving this green source/artifact/evidence.


### Combined offline groups and maintenance — 29 October 2026 (unpublished)

The subsequent combined candidate implements prepared whole-folder/Space offline groups, strict single-resource DAV metadata requests, bounded explicit ordinary local-copy removal, terminal group-history compaction and precise local/unlock feedback. Group capture requires a live unlocked session; background transfer carries ciphertext without unlock keys. A later unlock authenticates every member before one strict-base offline refresh/prune. Room advances to schema 27. RVO2 and the new database cannot be read by older builds; do not downgrade after opening this candidate. Remote file ciphertext, account/signing identity and master encryption keys are not rewritten by these local migrations.

The full combined quality gate passed **1,882 host tests with zero failures/errors/skips**, including 758 sync, 164 database and 276 network cases. Formatting, Detekt/design checks, screenshot verification, release lint, debug/unsigned-release assembly and app instrumentation assembly passed together. Lint reports zero errors, 250 warnings and one hint. All eight locale-validator regressions passed, and strict completeness passed for German, French, Spanish, European Portuguese and Japanese: 1,580 keys/plurals each. The prior 517 production resource files, 36 accepted goldens and ten protected German strings files retain their foundation hashes; twelve new locale resource files supply the new errors. No baseline was recorded to pass this gate.

The complete documented eight-module native matrix passed **API 26: 76 executed passes and six explicit skips; API 35: 78 executed passes and five explicit skips**, with no failures/errors. The files module contains no native cases. Counts use XML testcase nodes rather than the runner's progress totals. Connected tests exercise real Android Room/SQLite, private owner locks, XML validation, directory synchronization and rclone content. The two transfer-inventory UI regressions are host Robolectric SDK-35 tests, not connected-native cases. Opt-in live server/installer/migration probes and API-specific assumptions remain skips, not deployment acceptance.

Focused group tests separately passed 51 host cases and three native cases on each API before the final combined matrix. Focused maintenance passed 164 database and 86 selected sync cases; the final matrix repeats the native paths. Preserved initial failures include invalid Room/fixture compilation, a duplicate fixture name, incorrect test-only URL encoding expectations and a native test assuming `/data/data` and `/data/user/0` always canonicalize identically. The last fixture now creates a real private symlink; reader-retention assertions remain intact and pass on both APIs. Production guards were not weakened. Host crypto uses the real JVM sodium provider in test code, and host directory synchronization uses real JVM force; native tests use the Android implementations.

Evidence is in outputs/android-continuation-20261029/: combined-quality-1.log, combined-host-results.json, combined-native26-results.json, combined-native35-results.json, combined-locale-checks.log, combined-preservation-results.json and FINAL-SECURITY-HEALTH-REVIEW.md. Final source/artifact manifests identify the dirty local snapshot; these local runs do not establish independent CI or release-commit acceptance. Earlier foundation and failed-gate records remain preserved.

Phone testing should use replaceable copies: save an encrypted folder with mixed files and an empty child; leave/lock after capture; unlock again after transfer for verification; then check airplane-mode access. Interrupt or cancel an update and confirm the old accepted copy survives before retrying. Also save an individual file behind an active folder job, clear completed history, reopen and save again. Report the step, exact message, transfer/verification state and whether the old copy remains readable. See groups/PHONE-TESTS-DRAFT.md in the evidence directory for the full checklist.

This is local source, still app.raiun.cloud 1.2.0/code49, with an unsigned nondebuggable release artifact. No production signing, commit/push, release, installation of tools, live server/mail writes or owner-phone changes occurred. Physical upgrade/background/reboot, Wi-Fi/browser/IdP/KeyChain and Office acceptance remain outstanding. Generic encrypted byte-offset upload continuation remains disabled until durable conditional server finalization is verified; whole-object conditional upload/readback remains authoritative. Local receipts/directory synchronization do not prove a joint Room/filesystem power-loss transaction or resistance to a complete valid old-snapshot replay. External Open with still gives plaintext to another app.


### Owner phone follow-up: populated folders and key-verification UI — 29 October 2026

The owner found that saving the entire open encrypted folder from its top three-dot menu failed, while individual file saves worked. Three regressions reproduced the failure at the directory-size validator: the actual DAV parser preserves aggregate collection sizes, but group-plan validation had required zero. The fix authenticates the original nonnegative directory sizes, requires no directory payload, and totals only file ciphertext. Real SAX/MockWebServer root and issued-subfolder captures, sealed plans and actual Android private-plan readback cover it. All 54 focused group tests and 31 sync-native tests on each API passed before the subsequent diagnostic/UI change. The first fixture compile/style failures and the three pre-fix failing regressions remain preserved; no guard or assertion was removed to pass them.

The owner also confirmed that password-based key reuse works, while biometric-based reuse still asks again on Back/reopen without screen-off. That root cause is not established. The candidate adds only fixed US1–US7 in-memory reason codes for rejected biometric cache admission or failed cached-key proof; expected first unlocks and Ask-every-time do not warn. The original password reuse, account/credential, secure-device and pre-authentication generation guards remain authoritative. A neutral accessible Verifying key waiting view replaces the loading password form; idle authentication controls remain available when a fresh unlock is needed. Encryption passwords are not persisted for reuse.

After these changes the complete local quality/build task list passed **1,894 host tests**, zero failures/errors/skips, formatting/Detekt/design checks, screenshot verification, lint and debug/unsigned-release/app-test assembly. All 37 focused session/waiting tests also passed. Strict five-locale validation covers 1,583 keys/plurals each; all eight validator regressions passed. Lint has zero errors, 251 warnings and one hint: the one added warning is the now-unused legacy vault_unlocking resource, retained with the protected translation files. No screenshot baseline was re-recorded.

The final complete documented native matrix passed API26:76 executed cases/6 explicit skips and API35:78 executed cases/5 explicit skips, with zero failures/errors. Native counts use XML testcase nodes, and files has no native cases. Earlier full-matrix and intermediate affected-suite results are separate evidence.

Evidence is outputs/android-offline-phone-fixes-20261029/: quality-2.log, final-host-results.json, phone-session-targeted-results.json, final-native*-results.json, locale-final.log, lint-delta.json and PHONE-TESTS.md. Physical folder-save and biometric code acceptance remains pending. The app remains app.raiun.cloud 1.2.0/code49 and Room27/RVO2; no older-build downgrade is supported. Signing a corrected local phone-test APK is authorized within the owner's ongoing test request; no commit, push, release, live server/mail change or owner-device action is part of this follow-up.


### Remember on this phone — 29 October 2026 (unpublished)

The owner replaced the process-only convenience with explicit **Remember on this phone** consent. The candidate uses a separate hardware-backed AES-GCM Keystore key and a no-backup record, supported on Android 15+ with a secure screen lock. It restores after app restarts and later phone unlocks, then proves the exact online/offline root again. The password is not saved; old per-use biometric consent is not automatically converted. Ask every time, explicit location Lock, Settings reset and account/credential revocation fence remembered access. Screen-off closes decrypted routes while retaining the selected device record. Existing app lock remains separate.

The focused core gate passed all 79 host cases, formatting, static analysis and native assembly. A prior gate exposed missing Android Keystore in a Robolectric policy fixture; a narrowly injected fake-provider store now exercises the real durable policy fence with the original RAM assertions. Later source-refactor parse/static failures are preserved separately. No production fallback, key-policy check or security assertion was disabled. The independent source review found enrollment cleanup, plaintext ownership, alias-collision and interrupted Lock/coordinator issues; fixes and rechecks are retained with their exact scope in the evidence directory.

The complete local quality/build gate passes **1,933 host cases, zero failures/errors/skips**, formatting/static/design checks, screenshot verification, release lint and debug/unsigned-release/app-test assembly. Lint remains zero errors, 251 warnings and one hint. All five locales pass strict completeness for 1,595 string/plural keys, and all eight validator regressions pass.

The full-suite follow-up corrected legacy host fixtures whose default real IO escaped the test scheduler, preserved their race/paging/navigation assertions, and made explicit Lock completion deterministic before a fresh unlock. The new phone-mode tests use injected providers; production hardware requirements remain enforced. One encrypted-preferences screenshot was visually reviewed and intentionally updated for the changed explanation/status layout; the remaining accepted images and protected German strings are preserved. Earlier compile/static/test failures remain in the evidence directory.

The complete documented eight-module native matrix passes **API26: 78 executed passes / 7 explicit skips; API35: 78 executed passes / 8 explicit skips**, with no failures/errors. Counts use actual XML testcase nodes; the files module has no native cases. The new older-Android credential/strict-mode checks run on API26. The new API35 hardware-positive test is explicitly skipped because the disposable emulator has no configured secure screen lock; it does not establish hardware Keystore enforcement. Only task-owned read-only emulator copies were used. Physical phone acceptance remains separate from these host and emulator results. Physical OEM Keystore enforcement, locked/unlocked behavior and process-kill acceptance remain separate from fake-store and emulator tests. A Lock still pending when the process dies is not a completed durable revocation. No automatic key destruction is promised after removing and re-adding a screen lock while the app is dead.

Evidence: outputs/android-device-remember-20261029/, including CONTRACT.md, DESIGN-REVIEW.md, REVIEW.md, core-gate-*.log and PHONE-TESTS.md. No release/version change, Git publication, tool installation, live server/mail action or owner-phone operation is part of this local candidate.


### Android WebFinger platform and OIDC scopes — 30 October 2026 (unpublished)

The initial full-gate results below identify the first fix snapshot; the live-format follow-up records the subsequent compatibility correction separately.

Issue [#47](https://github.com/phillip9933/raiun/issues/47) is reproduced by synthetic platform-gated OpenCloud responses. Before the fix, five of six new network tests failed (missing platform, split comma-containing tokens, null handling and malformed metadata), and both new discovery-to-PKCE cases failed when the fixture withheld Android metadata. The original implementation was unchanged during those runs.

The candidate adds `platform=android`, preserving resource/issuer relation and the existing redirect/PKCE/trust checks. Typed JSON scope arrays retain server-defined tokens, including the custom `opencloud` scope, and reject malformed selected scope metadata with controlled InvalidResponse errors. Token validation follows [RFC 6749 section 3.3](https://www.rfc-editor.org/rfc/rfc6749#section-3.3) without a scope-name allowlist. Nonempty advertised scopes take precedence over the provider list; an explicit empty advertised array keeps the existing minimal `openid profile` default. Missing/null optional scopes retain legacy discovery fallback for deployments without WebFinger configuration. This fix does not guess an administrator's required custom scopes or change that fallback into a new scope policy.

The end-to-end fixture advertises metadata only for the Android platform. It checks blank and supplied client-ID input, configured-client precedence over dynamic registration, exact resulting authorization scopes without unrelated address/phone scopes, and scope refresh despite a cached client binding. Tests use two local MockWebServer origins and synthetic memory-only credentials. No real account signs in and no group membership or server setting is changed. The reporter's exact OpenCloud8.1/Authelia deployment still needs live acceptance; successful mocks do not establish token-claim issuance or repair existing server memberships. Existing accounts are not rewritten; corrected discovery applies when a new sign-in/discovery runs.

The first affected run passed all 282 network and 13 authentication cases, while failing one test-only formatting check. After that correction, the complete local gate passes **1,941 host cases, zero failures/errors/skips**, formatting/static/design checks, screenshot verification, release lint, debug/unsigned-release builds and app instrumentation assembly. Lint remains zero errors, 251 warnings and one hint. Native instrumentation was compiled, not executed for this fix; earlier emulator results cover their own source snapshots. No locale/resource or screenshot baseline change was needed. No new production signing or publication was performed. Evidence: outputs/issue-47-webfinger-fix-20261030/. The preceding signed Remember phone-test APK is preserved and does not contain this subsequent fix.


#### OpenCloud grouped WebFinger scopes follow-up

An unauthenticated HTTPS metadata read of the owner's server returned a nonempty Android client ID and the valid OpenCloud shape `scopes: ["openid profile email offline_access"]`. No sign-in or server mutation was performed. The first hardened parser incorrectly assumed every WebFinger array member was one scope token. The discovery-to-PKCE regression reproduces that error with the server-shaped array before the compatibility correction.

WebFinger string-array entries may contain space-separated scope text, which is normalized into individual tokens without changing their order or names. Only literal ASCII spaces are separators; blank entries, control characters and malformed types remain rejected. The IdP's separate `scopes_supported` array retains strict individual-token validation. The platform query, client precedence, optional metadata/default handling and redirect/PKCE trust boundaries remain unchanged.

A nonempty advertised client ID does not prove its identity-provider registration allows Raiun's redirect. Administrators must associate that client ID with the public client configured for `app.raiun.cloud://oauth`. Existing sign-ins are not rewritten and the manual client-ID option remains available. The public metadata check does not establish a successful Authentik/Authelia login or server group-claim behavior.

The final compatibility correction passes all **283 network and 13 authentication host cases** (zero failures/errors/skips), affected formatting/static checks, release lint and debug/unsigned-release/app-instrumentation assembly. Release lint remains zero errors, 251 warnings and one hint. The earlier complete 1,941-case suite belongs to the initial issue-47 snapshot; it was not repeated for this bounded format follow-up. No fresh native matrix, real OAuth authorization or physical sign-in acceptance is claimed. Evidence: outputs/issue-47-webfinger-compat-20261030/, including the controlled pre-fix failure, live public metadata receipt and final affected-gate results. Nothing was signed, published or installed on the owner's phone.


### Android 1.3.0 release acceptance

The owner accepted combined production-signed phone test 4 for encrypted-folder access and for a complete logout followed by server-address discovery selecting the correct client ID. This is scoped owner-reported acceptance, not a claim that every encryption, provisioning, certificate or server scenario was tested. App and signing identities remain unchanged.

The release uses version 1.3.0/code 50 and an isolated checkout based on the latest published repository main, preserving the existing dirty Android checkout and newer desktop source. Run the complete quality and API26/API35 native gates on the exact release commit before publication. Release results, artifact hashes and previous-release upgrade evidence are retained outside Git under outputs/android-release-1.3.0/. Historical candidate results above retain their original source and scope; publication does not make missing physical/deployment checks pass.

### Android 1.3.1 authentication review — 30 October 2026

The local authentication candidate passed all 1,987 host cases with zero failures,
errors or skips, formatting, static/design checks, screenshot verification,
release lint, debug and unsigned release builds, and instrumentation assembly.
Strict locale checks passed for all 1,596 keys in German, French, Spanish,
European Portuguese and Japanese; all eight locale-validator regressions passed.

New regressions cover previously saved lowercase Bearer schemes, initial resource
requests, malformed token metadata, refresh rotation and omitted scope preservation,
non-destructive unclassified HTTP 401 handling, exact discovery issuer comparison,
advertised flow capabilities, reserved authorization query parameters, callback
issuer checks before code exchange, legacy no-issuer responses and pending-login
restoration. Existing state, PKCE, account-removal and credential-persistence guards
remain covered. The independent source review's empty-scope finding was corrected;
malformed explicit scope values are rejected while omitted/null values stay compatible.

These results do not establish a live Authelia deployment retest, a physical
browser/IdP/KeyChain matrix, full OIDC relying-party conformance or complete
multi-provider mix-up protection for legacy providers without response issuer
proof. See [Authentication](AUTHENTICATION.md). Historical native results above
retain their original revision; publication still requires the release revision's
API26/API35 matrix and signed-artifact checks.

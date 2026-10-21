# Testing

Run commands from the Android project root (`apps/android`) after the [development setup](../CONTRIBUTING.md#development). Use `./gradlew` on Linux/macOS and `./gradlew.bat` on Windows. Python 3 and PowerShell (`pwsh` in CI) are required for the helper checks below.

## Build and quality checks

```sh
python scripts/install_offline_scanner_sdk.py
./gradlew ktlintCheck detekt testDebugUnitTest :app:verifyRoborazziDebug :app:lintRelease :app:assembleDebug :app:assembleRelease
```

These Gradle tasks match the [quality workflow](../../../.github/workflows/quality.yml). Detekt also depends on the Compose design-token check. Release output is unsigned until signed locally; see [the release procedure](RELEASING.md). Review screenshot changes visually; recording new images is not a passing verification result.

For focused changes, run the affected module's tests first. Documentation-only changes need path, link and command inspection rather than an app suite. A release candidate still needs the complete quality and emulator gates on the exact commit proposed for release.

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

The current beta work has 1,125 passing host tests and 18 passing Android-native tests on API 35. The owner accepted the test 16 build on a Pixel. These results are useful implementation and device evidence, but the release gate is the quality and API 26/API 35 emulator matrix rerun on the exact 0.9.0 release commit. Earlier API 26 emulator results are historical and do not replace that release-commit run. Record any missing run explicitly; do not imply that planned checks have passed.

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

## Pre-1.0 reliability work: acceptance gates

This work is under development after 0.9.3. The following are acceptance requirements, not completed device or server results. Keep the published release's limitations separate from uncommitted implementation evidence.

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

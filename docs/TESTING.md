# Testing

Run commands from the repository root after the [development setup](../CONTRIBUTING.md#development). Use `./gradlew` on Linux/macOS and `./gradlew.bat` on Windows. Python 3 and PowerShell (`pwsh` in CI) are required for the helper checks below.

## Build and quality checks

```sh
python scripts/install_offline_scanner_sdk.py
./gradlew ktlintCheck detekt testDebugUnitTest :app:verifyRoborazziDebug :app:lintRelease :app:assembleDebug :app:assembleRelease
```

These Gradle tasks match the [quality workflow](../.github/workflows/quality.yml). Detekt also depends on the Compose design-token check. Release output is unsigned until signed locally; see [the release procedure](RELEASING.md). Review screenshot changes visually; recording new images is not a passing verification result.

For focused changes, run the affected module's tests first. Documentation-only changes need path, link and command inspection rather than an app suite. A release candidate still needs the complete quality and emulator gates on the exact commit proposed for release.

## Android emulator gates

Run the connected instrumentation suites on **both API 26 and API 35**, matching the API matrix in the [emulator workflow](../.github/workflows/emulator.yml). The documented task list below is the release gate; ensure CI runs every listed module, including `core:sync`, on both API levels. The gate must pass on the exact release commit; historical runs on earlier commits do not establish that result.

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
pwsh -File scripts/validate-locale-resources.ps1 -Locale de
```

These checks match CI. Missing translations may fall back to English. Review changed layouts for long text, large fonts, accessibility and right-to-left layout where applicable.

## Record results

Record the revision, commands, environment and outcomes. Separate current results from historical evidence, and unit/screenshot checks from device or server acceptance. Do not include credentials, private URLs, machine-specific paths or personal files in public reports. See [beta limitations](ENCRYPTED-VAULTS-PLAN.md#not-included-in-this-beta) even when automated checks pass.

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

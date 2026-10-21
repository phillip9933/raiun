# OpenCloud Android Next 0.1.0-beta.1

First public beta of this independent, ground-up Android client for OpenCloud. It is not an official OpenCloud GmbH release.

## Included

Personal files and Spaces; favorites, search, recents and offline files; durable uploads/downloads; server-confirmed copy/move; public sharing; Android file-picker and Send integration; folder/camera backup; light/dark themes and optional device/biometric locking; offline PDF/JPEG scanning with the separately versioned Open Android Doc Scanner SDK.

Hardening includes upload collision protection, transfer verification/recovery, a patched Protobuf parser, changed-source backup discovery fixes, and clearer photo metadata choices. Missing translations fall back to English.

## Install

- Android 8.0/API 26 or later; arm64-v8a or x86_64 only.
- Download `opencloud-next-0.1.0-beta.1.apk`; verify it against `SHA256SUMS`.
- Future releases from this repository will use the same release signing identity.

## Known limitations

This is best-effort beta software with no warranty. Keep backups. Large mobile/Wi-Fi handoffs may restart transfers or produce server HTTP 502/timeouts requiring retry. External-editor and Office/server combinations are not fully accepted. Scanner pages not exported may be lost after process death. Folder backup queues uploads rather than mirroring both ways. Android may include or omit photo metadata; there is no guarantee of stripping it.

See the repository README, privacy statement, third-party notices and release procedure. The exact tagged source is available with this release; scanner SDK provenance and its source revision are pinned in scripts/offline-scanner-sdk.lock.json.

## Validation

764 local unit/UI tests pass with zero failures/errors/skips. Formatting, static analysis and screenshot verification pass. Secret scans of Git history and publication candidates found no findings. Device/server acceptance remains limited as described above. Remote CI status is recorded against the tagged revision on GitHub.

## License

Application code: AGPL-3.0-only (matching Kura's actual license file). Full license and notices are included in the source and APK. Third-party components retain their own licenses.

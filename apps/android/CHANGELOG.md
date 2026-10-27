# Changelog

## 1.2.0

- Match Navigation and permission buttons to the other settings controls, and align the Language selector beside its title.

- Update the app updater to 0.2.1, including cleanup of obsolete queued update downloads.
- Update the scanner to 0.8.0-beta.1 with improved card-edge detection. Optional OCR is not enabled by this dependency update.

- Add optional Wi-Fi local server routing while preserving the public HTTPS identity and existing account data.
- Add Android-managed TLS client certificates for selected server/identity-provider origins, with connection settings available before sign-in and in Settings. OAuth certificate-bound tokens remain unsupported.

- Make the new-version popup clearer and check for updates when returning to the app, respecting automatic-check settings and the daily limit. Dismissed releases remain available in App updates.

- Browse large personal and shared folders in pages, including backup destination selection, while keeping the previous verified cache when refresh fails.
- Stream locked-folder discovery and shared metadata reads instead of keeping every ordinary child in memory. Shared Android file-picker cursors recheck access and invalidate when their listing changes.
- Clarify published versus historical architecture/testing records and document how to report translation problems.

## 1.1.0

- Add automatic Android update checks, stable/beta channels and an App updates page in Settings. Optional unmetered-Wi-Fi downloads use updater 0.2.0's stricter release validation and open Android's installer for confirmation.
- Cancel all conflicting uploads for the current account from the conflict popup or Transfers, without deleting files or stopping other transfers.
- Improve encrypted upload recovery when the server takes time to show a completed file, verifying uncertain uploads before marking them complete or retrying.
- Refresh large ordinary folders through temporary encrypted storage and publish the complete listing in batches, keeping the previous listing if refresh fails.
- Clean up failed sign-in credentials, prevent stale discovery after account access is revoked, and verify dependency checksums during builds.

## 1.0.0 — 2026-10-21

- Move the Android project into `apps/android` while preserving app identity and existing data compatibility.

- Rename Uploads to Transfers and add direction, file type, status and date filters.
- Match encrypted upload, scan and create-folder actions to the regular browser's wording, icons and order.
- Use a uniform bottom navigation bar with Recents and Shares, and let users choose and reorder the destinations in the bar; other items stay in the menu.
- Return to the previous location when leaving an encrypted folder and request face unlock without an extra confirmation where supported by Android.
- Harden folder response parsing, correct encrypted offline cancellation, and prevent old upload confirmations from repeating after scanning.
- Complete missing German text and add draft French, Spanish, European Portuguese and Japanese translations, including the scanner.

- Process large backup trees in batches and read folder responses without buffering the entire XML document.
- Improve transfer recovery and explain source, permission, storage, server and integrity failures more clearly. Backup settings retain the last scan failure and allow choosing a replacement source folder.
- Add background encrypted file uploads and offline downloads, with verification before files become available offline.
- Add copying and moving between ordinary and encrypted locations, with destination browsing, conflict choices and an explicit warning when files will become unencrypted.

The application ID and original signing identity are preserved for in-place updates. See the release notes and testing guide for validation and remaining device/server limits.

## 0.9.3 beta

- Fixed uploads getting stuck on “Verifying transfer” when the destination file is missing. Retries can safely upload the missing file without overwriting existing content.

## 0.9.2 beta

- Added file and folder exclusions to folder and camera backups, and made backup settings easier to use with clearer date controls and pause status.
- Added retry for failed uploads and fixed scrolling in backup settings.

## 0.9.1 beta

- Updated the document scanner to 0.7.0 for sharper JPEG/PDF output, improved paper and shadow cleanup, and capture-quality warnings. Extra diagnostic image copies remain disabled in Raiun.
- Added an explicit backup destination picker for Personal, Spaces and writable received shared folders, with scoped uploads and preserved existing backup settings.
- Added custom date folders for automatic uploads, using photo/video capture dates where available and provider-added or modified dates as fallback.
- Added video thumbnails for ordinary and encrypted files, with safe fallbacks when a preview is unavailable.
- Removed fixed encrypted preview file-size limits. Large previews use temporary encrypted storage; large text files can be edited in sections without buffering the whole file.
- Added regression coverage for upload conflicts surviving app reopen and appearing outside the destination folder. Backup continues to preserve local originals.
- Hardened server metadata handling against oversized responses without restricting file transfers.
- Delayed copying incoming shared files until Upload is confirmed, with safer storage reservation, cancellation and cleanup.
- Added supported server checksum verification before making ordinary and received-share downloads available, including resumed downloads. Servers without supported checksums retain the existing size and version checks.
- Added a regression test for resuming after the connection drops, checking the complete resulting file.

## 0.9.0 beta

- Added encrypted folders and Spaces with password unlock, optional phone biometric access, and encrypted offline copies.
- Added memory-only encrypted image, PDF and text previews, bounded encrypted text editing, and PDF/JPEG scanning into an encrypted location.
- Improved Space discovery and management screens, menus, and normal/encrypted copy and move with in-place destination browsing and consistent conflict handling.
- Polished backup and encrypted-preference settings screens, and aligned ordinary-file name-conflict dialogs.
- Added a warned “Open with” flow for temporary plaintext handoff to another app, with read-only access, expiry and cleanup attempts. The receiving app can retain an open file or its own copy.
- Fixed empty notification inbox handling.
- Documented the Web-compatible encryption format’s security limits and preview/edit size bounds.

## 0.8.1

See [0.8.1 release notes](docs/RELEASE-NOTES-0.8.1.md).

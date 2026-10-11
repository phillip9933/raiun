# Changelog

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

# Raiun Desktop changelog

## Unreleased

- Linux: add **Verify uploaded copy** for newly recorded uncertain media uploads.
  It checks the saved cloud destination without changing source files, retrying
  the upload, or clearing recovery. Older attempts remain inspection-only.
- Windows development: verified test installers and guarded cloud-drive save
  completion are in progress. Automatic drive activation remains disabled while
  native acceptance is completed; Windows is not yet a public release.

## 0.7.0-beta.1 — 2026-10-21

First public Linux x86_64 beta, released alongside Raiun Android 1.0.0.

- One OpenCloud drive per account, containing Personal and Spaces, with
  on-demand file access and guarded save-back.
- Configurable folder sync, exclusions, pause/resume and per-Space controls.
- Offline caching and retained dirty edits/conflicts for recovery.
- Explicit encrypted-location unlock/lock, supported encrypted file operations
  and optional OS-protected remembered unlock with per-vault opt-in.
- Tray, account/status, transfer, recovery and startup controls.
- Upload-only media-job setup and local Preview.
- Linux user installation with payload verification and preserved rollback.

### Beta limits

Native account-selector/file-manager workflows, disconnect Cancel/OK, media
upload/duplicate avoidance/restart, actual desktop-login startup and full
advanced encrypted/offline behavior remain unverified. Focused checks establish
selected account-isolation, dirty-recovery/reconciliation, Startup toggle and
installation behavior; they do not certify every feature or absence of bugs.

Cross-vault moves and remote encrypted-folder deletion remain unsupported or
restricted. Fail-closed restrictions preserve uncertain edits rather than
performing destructive replay. Retained local working/recovery copies can be
plaintext: cloud encryption is not local-disk encryption.

The Linux tarball requires the documented system dependencies, including Zenity
and an unlocked Secret Service for persistent credentials. An AppImage is also
available alongside the tarball. Windows and macOS are not offered in this release.

# Raiun Desktop changelog

## 0.7.4 Beta — 2026-10-27

- Windows installer upgrades existing same-user installations in place by default, without requiring a manual uninstall. Running program files block replacement with Retry/Cancel; the installer does not force Raiun to stop.
- Dedicated Offline files and Encrypted files pages, clearer storage usage, and expandable help reduce clutter.
- Ordinary sync folders and upload-only media folders share one Sync Folders workspace and list; direction, file filters, exclusions and existing-copy behavior remain explicit.
- Sync Folders adds editable directions, All files/Photos/Videos filters, and multiple file-type or path-pattern exclusions. Existing literal exclusions keep their meaning; editing keeps source and destination locations fixed.
- Account accents cover the selected card and header, with color swatches and authenticated server avatars where supported. Settings are grouped, with removed accounts at the bottom.
- Periodic refresh preserves appropriate focus/scroll and avoids unchanged full-page redraws.
- Explicit account removal signs out, revokes remembered vault-password access and stops the account while preserving local files, recovery and path reservations. Removed accounts can be restored to the same profile; sign-in and vault passwords are required again.
- Light/Dark/System themes, per-account accents, consistent account selection, a standard settings icon and a compact account/Refresh strip.
- Mount is unavailable when already mounted; encrypted-file help distinguishes Lock from forgetting a saved password.
- Account display names can be edited without changing profile identity, credentials or data paths.
- Windows refresh scheduling uses a 30-second lead instead of 300 seconds, avoiding an immediate repeated-refresh cycle for five-minute access tokens.
- Reconnect failure details remain available inline after a toast is dismissed. Redacted diagnostics accept legitimate disconnected Windows status, omit cleanup extension data and report app/agent versions separately.

This numeric `0.7.4` release remains on the Beta channel and retains the beta.3 sign-in/Space fixes. The owner verified Windows reconnect behavior with the Default and a newly added account. Exact package hashes and version-bound update signatures were verified. Focused native Windows preview-to-final installation preserved settings, profile metadata and same-user DPAPI data; the busy guard refused replacement without killing the agent. Headless/CLI distribution and MSI packaging are outside this release.

## 0.7.0-beta.3 — 2026-10-27

Focused Linux and Windows sign-in and encrypted Space fixes.

- Linux: retry saved sign-in when the keyring or network is not ready at startup,
  preserving refreshed credentials across a temporary connection failure. A
  sign-out or account change cancels the old restore attempt.
- Windows: show a retained sign-in as reconnecting and retry temporary failures
  even when the saved token is still fresh. A repeated Sign in request no longer
  disconnects the existing drive before rejecting the duplicate request.
- Refresh the selected account status after a failed sign-in attempt.
- Allow an encrypted Space display name to differ from its exact server resource
  identifier. Folder and child location checks remain strict.

- Prepare the updater for future numeric Beta versions (`0.x.y`) while keeping
  Stable-channel filtering strict. This final `0.7.0-beta.3` bridge preserves the
  automatic update path for existing beta.2 clients.

This patch does not include the planned navigation, appearance or CLI changes.
Existing beta.2 upgrade/recovery limits continue to apply.

## 0.7.0-beta.2 — 2026-10-27

Linux and Windows x86_64 beta, with matching Desktop versions.

- Check compatible Desktop GitHub releases automatically or manually, dismiss
  individual update notices, and explicitly download and install version-bound
  signed updater packages. Desktop and Android release selection stay separate.
- Windows: guarded encrypted-file save-back, durable completed-save history and
  explicit Save Copy recovery, including history beyond the active index limit.
  Registered cloud-root pinning preserves the exact recovery scope.
- Linux: add **Verify uploaded copy** for newly recorded uncertain media uploads.
  It checks the saved cloud destination without changing source files, retrying
  the upload, or clearing recovery. Older attempts remain inspection-only.
- Verified native upgrades preserve settings and synthetic documents; Windows
  additionally preserves same-user DPAPI data. Focused Windows recovery checks
  preserve 129 retained edits, refuse destination overwrite and leave custody
  unchanged. Both platforms retain their safe shutdown and recovery checks.

### Upgrade and beta limits

Desktop beta.1 predates in-app updates: install beta.2 manually once. Future
compatible releases can use beta.2's App updates controls. Downloads and
installation require separate user actions; missing trust metadata fails closed.
The Windows updater signature authenticates the updater package; it is not an
Authenticode certificate for the standalone installer.

Acceptance uses isolated native synthetic data and offline release fixtures;
advanced encrypted/offline and full account/file-manager workflows are not
exhaustively certified. The original 129-save test failure is retained; the
corrected Save Copy path passed a separate focused native continuation. Release
notes document supported behavior and remaining limits rather than claiming
whole-category completion. Local working/recovery copies may be plaintext;
cloud encryption is not local-disk encryption.

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

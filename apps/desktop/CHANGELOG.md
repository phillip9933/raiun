# Raiun Desktop changelog

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

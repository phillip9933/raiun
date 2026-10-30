# Raiun release history

Android and desktop have independent versions and release pages.

## Android 1.3.1 — 2026-10-30

Fix Authelia sign-ins that completed but received HTTP 401 for file requests, including accounts already saved on the phone. Preserve saved credentials after unexplained token-endpoint 401 responses, improve validation of login metadata and fix intermittent database locks while preparing encrypted folders for offline use. See the [Android release notes](apps/android/docs/RELEASE-NOTES-1.3.1.md).

## Android 1.3.0 — 2026-10-30

Guest invitation management, clearer account colors and settings, improved large-folder and encrypted offline handling, optional remembered encrypted access on this phone, and corrected Android sign-in discovery. See the [Android release notes](apps/android/docs/RELEASE-NOTES-1.3.0.md).

## Desktop 0.7.4 Beta — 2026-10-27

The Linux and Windows Desktop Beta uses numeric versioning. It brings a
unified Sync Folders workspace, editable sync filters/exclusions, grouped Settings,
per-account appearance, retained-account controls and the Windows in-place
installer. The Windows reconnect fix was owner-verified with both the Default and
a newly added account. Focused package/upgrade and data-retention checks passed; broader beta limits
remain documented. Android remains on 1.2.0. See the [Desktop
changelog](apps/desktop/CHANGELOG.md) and [Sync Folders guide](apps/desktop/docs/SYNC-FOLDERS.md).

## Coordinated release — 2026-10-27

- Android **1.2.0/code 49**: clearer update notices, bounded large-folder browsing,
  supported server connection options, library updates and settings fixes.
- Linux and Windows Desktop **0.7.0-beta.2**: matching Desktop versions, verified
  GitHub updater packages, Windows encrypted-save history and Save Copy recovery.
- Existing Android application/signing identity and independent Desktop identities
  are preserved; release notes describe remaining device/deployment and beta limits.

## Android 1.1.0 — 2026-10-25

Add in-app updates, bulk cancellation of upload conflicts, encrypted upload recovery and safer large-folder refreshes. See the [Android release notes](apps/android/docs/RELEASE-NOTES-1.1.0.md). Desktop versions are unchanged.

## Coordinated release — 2026-10-21

- Android **1.0.0**: Transfers filters, customizable drag-and-drop navigation,
  encrypted/offline and backup improvements, and additional translations.
- Linux Desktop **0.7.0-beta.1**: first public Linux beta with cloud-drive,
  folder-sync, offline, encrypted-access and recovery controls; known validation
  limits are documented in its release notes.
- Complete Android project under `apps/android` and history-preserving desktop
  import under `apps/desktop`; shared branding and product docs at the root.
- Separate Android and desktop CI, dependency locks and platform-specific tags.
  Existing Android tags and release assets remain unchanged.

## Platform history

- [Android changes](apps/android/CHANGELOG.md)
- [Desktop changes and beta limits](apps/desktop/CHANGELOG.md)

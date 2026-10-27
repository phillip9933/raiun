# Raiun release history

Android and desktop have independent versions and release pages.

## Desktop 0.7.4 Beta — prepared; publication pending final package gates

The prepared Linux and Windows Desktop Beta uses numeric versioning. It brings a
unified Sync Folders workspace, editable sync filters/exclusions, grouped Settings,
per-account appearance, retained-account controls and the Windows in-place
installer. The Windows reconnect fix was owner-verified with both the Default and
a newly added account. Final package gates remain pending; this entry does not
announce a published release. Android remains on 1.2.0. See the [Desktop
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

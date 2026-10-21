# Raiun release history

Android and desktop have independent versions and release pages.

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

# Raiun release history

Android and desktop have independent versions. A coordinated announcement can include both apps without forcing version numbers to match.

## Unreleased repository changes

- Move Android into `apps/android`, with its own build setup, tests, scripts, changelog and docs.
- Keep shared branding and product guidance at the root, ready for a later desktop import into `apps/desktop`.
- Run Android CI from its new directory. Preserve existing tags and use platform-specific tags for future releases.

The intended joint launch is Android 1.0 and desktop 0.7 beta. Both remain subject to validation and owner acceptance; this layout change does not publish or bump either app.

## Platform history

- [Android changes and complete existing history](apps/android/CHANGELOG.md), including the unpublished pre-1.0 work.
- Desktop history will join its source at `apps/desktop/CHANGELOG.md` when the import is ready. No desktop release is claimed here.

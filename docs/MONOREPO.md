# Raiun repository layout

Raiun uses one product repository with independent platform projects:

```text
raiun/
  .github/workflows/   # Android and desktop CI, all executable workflows here
  apps/
    android/          # Complete Gradle project, modules, resources and scripts
    desktop/          # Rust engine, Tauri UI, native adapters and packaging
  design/             # Shared branding and product design references
  docs/               # Product layout and coordinated release guidance
```

## Platform ownership

Open `apps/android` in Android Studio and run its Gradle wrapper there. Use JDK
21 and Android SDK 36; the scanner SDK remains independently checksum-pinned.
Run desktop Cargo/build commands from `apps/desktop`; its UI is under
`desktop-shell`. Android does not require Rust/Node and desktop does not require
the Android SDK. Each app owns its locks, native resources, tests, packaging,
implementation docs, privacy notice and dependency notices.

GitHub executes workflows only at the repository root. Android retains
`quality.yml` and `emulator.yml`; `desktop-ci.yml` uses explicit app working
and artifact paths. Portable Rust checks on Windows/macOS are not releases of
those desktop platforms. No shared runtime or top-level build system is added.

## Preserved history and compatibility

Android history and existing tags retain their original revisions and paths.
The unpublished Android candidate was frozen before integration. Desktop's
original Git history and frozen 0.7 beta source were merged without squashing,
with its tree under `apps/desktop`. The original development checkouts, ignored
files, test binaries and recovery material remain separate and preserved.

Relocation does not change Android's `app.raiun.cloud` application ID, signing
certificate, database/provider identities or credential aliases. Desktop's
`org.raiun.desktop` identity, executable names, state and credential locations
are also preserved. Installed Android updates need the original certificate
and a strictly increasing version code.

Keep signing keys, local properties, credentials, account state, test evidence,
caches and generated build outputs outside Git. Never import a moving checkout
or personal data to make a build portable. Shared branding does not merge
private app state or grant cross-account access.

## Independent releases

The coordinated launch pairs Android **1.0.0** with Linux Desktop
**0.7.0-beta.1**. Tags and assets are platform-specific, and each release has
its own maturity and known limits. Historical tags are not renamed. See
[Releasing](RELEASING.md), [Android changes](../apps/android/CHANGELOG.md) and
[Desktop changes](../apps/desktop/CHANGELOG.md).

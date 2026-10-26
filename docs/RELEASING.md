# Raiun coordinated releases

Each app has an independent version, build and acceptance gate. The first coordinated launch paired Android 1.0.0 with Linux Desktop 0.7.0-beta.1; Android 1.1.0 was an independent follow-up. The next coordinated launch pairs Android 1.2.0 with Linux and Windows Desktop 0.7.0-beta.2. Desktop has been imported with its Git history under `apps/desktop`. Signing and publication remain explicit maintainer actions.

## Versions and tags

Android version name/code remain in `apps/android/app/build.gradle.kts`. Set the final version at release freeze and increase its code above every previously distributed build. Preserve `app.raiun.cloud` and the original certificate for compatible updates.

Desktop retains its own authoritative package versions and platform identities after import. Verify Cargo, UI and package versions together using its actual packaging procedure.

Use platform-specific tags for future releases:

| App | Example tag | GitHub release |
| --- | --- | --- |
| Android | `android-v1.0.0` | Raiun Android 1.0.0 |
| Desktop | `desktop-v0.7.0-beta.2` | Raiun Desktop 0.7.0 beta 2 for Linux and Windows; marked prerelease |

Tags may point to the same validated commit for a coordinated launch. Separate release pages distinguish downloads, notes, beta status and app updates. Future patches need not change the other app's version. Preserve existing tags and assets; never rename historical Android tags.

## Release checks

1. Freeze the intended platform release revision. Review each changelog, limitations, privacy notice and notices. Write short, plain-language release notes and describe supported platforms honestly.
2. Run Android's [quality and API 26/API 35 emulator gates](../apps/android/docs/TESTING.md) and [packaging/signing checks](../apps/android/docs/RELEASING.md) on that exact source. Owner device/server acceptance remains required. Historical checks on the old layout are not migration results.
3. Run the relevant desktop source gates, Linux packaging and focused exact-package isolated checks on the candidate. Reuse unchanged validated safety evidence and disclose the beta's unverified workflows; whole-category certification is not required for this beta. Desktop CI is `.github/workflows/desktop-ci.yml`; Desktop 0.7.0-beta.2 ships Linux x86_64 AppImage and Windows x86_64 NSIS packages with the same Desktop version.
4. Build and verify exact distributables. CI produces Android debug and unsigned release APKs; production signing remains local with the original identity. Keep credentials outside source and CI logs. Source relocation never authorizes a new identity.
5. Verify Android name/code, application ID, certificate, empty development credentials, APK/native alignment and upgrade over the previous release. Verify desktop identities and upgrade/data compatibility separately.
6. Use distinct assets such as `raiun-android-1.0.0.apk` and `raiun-desktop-0.7.0-beta.1-<os>-<arch>.<package>`, with checksums per release. Audit desktop updater handling of these tags before enabling it: a generic latest-release lookup may choose the other platform. GitHub supplies source archives automatically.
7. Only after owner release acceptance, create platform tags and publish their pages/assets from the validated commit. Neither these workflows nor this migration publish automatically. Announce both apps together while making their different maturity clear.

If either app fails its gates, retain the candidate and report the failure. Android validation does not establish desktop readiness, and a desktop beta does not replace Android device acceptance.

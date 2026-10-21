# Raiun

Independent OpenCloud apps for Android and desktop, built around the same product and design. This is not an official OpenCloud GmbH product or supported client.

I build projects to solve problems I run into in my own life. I share them because I believe in open source and hope others can learn from them, adapt them or find them useful. Making them public does not mean they are suitable for every setup, and I can't promise a support schedule.

## Apps

| Platform | Source and setup | Release status |
| --- | --- | --- |
| Android | [apps/android](apps/android/README.md) | Published 0.9.3 beta; unreleased work is being prepared for 1.0 |
| Desktop | Developed separately until import into `apps/desktop` | In development; not included or built by this checkout yet |

The planned joint launch is Android 1.0 with a separately versioned desktop 0.7 beta, subject to each app's own testing and release checks. Preparing this repository does not publish either app.

Android includes Personal files and Spaces, encrypted folders and Spaces, offline access, transfers, folder/camera backup and document scanning. See its [features and limitations](apps/android/README.md), [privacy notice](apps/android/PRIVACY.md) and [changelog](apps/android/CHANGELOG.md).

## Develop

Each app owns its toolchain, dependency locks, tests and build outputs. To build Android:

```sh
cd apps/android
python3 scripts/install_offline_scanner_sdk.py
./gradlew :app:assembleDebug
```

Use JDK 21 and Android SDK 36. Open `apps/android` in Android Studio. GitHub Actions remain in the repository's `.github/workflows` directory and run Android from that same project directory. See [Contributing](CONTRIBUTING.md) and the [monorepo guide](docs/MONOREPO.md).

Shared [branding and design references](design/) stay at the repository root. Each app owns its native resources and packaging.

## Releases and security

Download published Android APKs from [GitHub Releases](https://github.com/phillip9933/raiun/releases). Install a release signed with the original identity over an existing Raiun installation to preserve app data. Read the app's limitations and keep independent backups.

New releases will use platform-specific tags and assets so Android and desktop can version independently. Existing tags remain unchanged. See [Releasing](docs/RELEASING.md), [version history](CHANGELOG.md), [security reporting](SECURITY.md), [privacy](PRIVACY.md) and [third-party notices](THIRD-PARTY-NOTICES.md).

## AI usage and license

I use AI tools to help with development, including analysis, code, tests and documentation. Validation records distinguish checks actually run from checks still required. Source review and automated tests are not security certification.

Licensed under [AGPL-3.0-only](LICENSE). See [NOTICE](NOTICE); third-party components retain their own licenses and notices. The license does not grant rights to third-party trademarks.

# Android development on Linux

Run commands from `apps/android`, the Android project root inside the Raiun monorepo. Open that directory in Android Studio.

Use JDK 21, Python 3, Android SDK platform 36 and build tools 36.0.0. Set `ANDROID_HOME` to the SDK installation, or put `sdk.dir` in the ignored `apps/android/local.properties`. Never commit local account credentials or signing configuration. PowerShell (`pwsh`) is used for translation validation, including on Linux CI.

```sh
cd apps/android # From the monorepo root.
python3 scripts/install_offline_scanner_sdk.py
./gradlew :app:assembleDebug
```

The scanner installer checks the version and checksum in `scripts/offline-scanner-sdk.lock.json`. Its verified Maven cache belongs in this project's `.gradle` directory. No desktop toolchain is required for Android.

The debug APK is `app/build/outputs/apk/debug/app-debug.apk`. Unsigned release output is `app/build/outputs/apk/release/app-release-unsigned.apk`. Debug signing is separate from the production identity; an ordinary debug APK cannot update a production-signed installation.

See [Testing](TESTING.md) for formatting, static analysis, host tests, screenshot verification and the API 26/API 35 emulator matrix. See [Releasing](RELEASING.md) for production signing and update-compatibility checks. Do not use the historical Windows DPAPI password backup as a Linux credential format.

This guide describes the moved project setup. Actual migration validation is recorded separately; installed tools and older test results alone do not establish release readiness.

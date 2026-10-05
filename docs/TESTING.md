# Testing

Run commands from the repository root after the [development setup](../CONTRIBUTING.md#development). Use `./gradlew` on Linux/macOS and `./gradlew.bat` on Windows. Python 3 and PowerShell (`pwsh` in CI) are required for the helper checks below.

## Build and quality checks

```sh
python scripts/install_offline_scanner_sdk.py
./gradlew ktlintCheck detekt testDebugUnitTest :app:verifyRoborazziDebug :app:lintRelease :app:assembleDebug :app:assembleRelease
```

These Gradle tasks match the [quality workflow](../.github/workflows/quality.yml). Detekt also depends on the Compose design-token check. Release output is unsigned until signed locally; see [the release procedure](RELEASING.md). Review screenshot changes visually; recording new images is not a passing verification result.

For focused changes, run the affected module's tests first. Documentation-only changes need path, link and command inspection rather than an app suite. A release candidate still needs the complete quality and emulator gates on the exact commit proposed for release.

## Android emulator gates

Run the connected instrumentation suites on **both API 26 and API 35**, matching the API matrix in the [emulator workflow](../.github/workflows/emulator.yml). The documented task list below is the release gate; ensure CI runs every listed module, including `core:sync`, on both API levels. The 0.9.0 beta gate must pass on the exact release commit; historical runs on earlier commits do not establish that result.

```sh
./gradlew :app:connectedDebugAndroidTest \
  :core:crypto:connectedDebugAndroidTest \
  :core:security:connectedDebugAndroidTest \
  :core:sync:connectedDebugAndroidTest \
  :core:database:connectedDebugAndroidTest \
  :core:documentsprovider:connectedDebugAndroidTest \
  :core:ui:connectedDebugAndroidTest \
  :feature:files:connectedDebugAndroidTest
```

Use a disposable emulator or authorized test device with synthetic files and test accounts, not a personal account or production server. Inspect test fixtures and server requirements before running individual journeys. Emulator tests do not establish physical camera behavior, hardware biometric enforcement, external-editor behavior or compatibility with every server/provider combination.

## 0.9.0 beta evidence

The current beta work has 1,125 passing host tests and 18 passing Android-native tests on API 35. The owner accepted the test 16 build on a Pixel. These results are useful implementation and device evidence, but the release gate is the quality and API 26/API 35 emulator matrix rerun on the exact 0.9.0 release commit. Earlier API 26 emulator results are historical and do not replace that release-commit run. Record any missing run explicitly; do not imply that planned checks have passed.

## Translations

```sh
python scripts/test_locale_validator.py
pwsh -File scripts/validate-locale-resources.ps1 -Locale de
```

These checks match CI. Missing translations may fall back to English. Review changed layouts for long text, large fonts, accessibility and right-to-left layout where applicable.

## Record results

Record the revision, commands, environment and outcomes. Separate current results from historical evidence, and unit/screenshot checks from device or server acceptance. Do not include credentials, private URLs, machine-specific paths or personal files in public reports. See [beta limitations](ENCRYPTED-VAULTS-PLAN.md#not-included-in-this-beta) even when automated checks pass.

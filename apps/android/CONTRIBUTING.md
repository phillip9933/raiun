# Contributing to Raiun

Raiun is a personal project maintained for the maintainer's own use and shared on a best-effort basis. It is not an official OpenCloud GmbH product or supported client. This independent client is in beta hardening. Start with [README](README.md), the [current layout](docs/README.md#repository-layout) and [Security](../../SECURITY.md). Please report reproducible bugs first; discuss major feature or dependency changes in an issue before implementing them.

## Development

Use JDK 21, Android SDK platform 36 and Python 3. Set `ANDROID_HOME` or an ignored `local.properties` containing `sdk.dir`. Use the checked-in Gradle wrapper from the Android project root (`apps/android`). On Windows, substitute `.\gradlew.bat` for `./gradlew`.

```sh
cd apps/android # From the monorepo root.
python scripts/install_offline_scanner_sdk.py
./gradlew :app:assembleDebug
```

The installer downloads and verifies the pinned scanner SDK; see [SDK setup](docs/OFFLINE-SCANNER-SDK.md). Do not commit development credentials or private signing keys. Debug builds can read development credentials from local properties; release builds use empty values.

## Choose tests by change

See [Testing](docs/TESTING.md) for executable quality and device commands. Run checks relevant to the changed behavior and state what was not run. Keep regression tests focused on behavior. Review screenshot changes rather than accepting them automatically. GitHub quality and emulator checks must pass before release; that requirement is not evidence that a particular commit passed.

## Structure and code style

I prioritize data safety, security, correctness and privacy, followed by usability, maintainability, simplicity, compatibility, extensibility, performance and architectural purity. Prefer small, understandable changes with clear ownership. Explain exceptions to defaults and preserve existing data and public contracts. Consider accessibility and localization when changing UI. These are review priorities, not a claim that every current implementation meets them.

Follow `.editorconfig`, ktlint and detekt. Keep UI in feature modules, shared design tokens in `core/designsystem`, and storage, networking and worker behavior with their existing owners. Preserve account separation, queued transfers, provider contracts and database compatibility. This client needs network access to its server; the scanner dependency's offline constraints do not make the host app offline-only.

New UI text should use Android resources. English fallback is supported; complete translations are not a prerequisite. See [Testing](docs/TESTING.md#translations) for resource checks.

## AI usage

Disclose material AI assistance in the PR/commit summary: whether it was used for analysis, documentation, code or tests, and which checks you personally verified. You remain responsible for understanding the submitted change. Do not present generated test claims as observed results or share credentials, private server data or personal files with an assistant.

## Reports and pull requests

Include the app version, Android version, server version if known, reproduction steps, and expected versus actual behavior. Remove tokens, passwords, private URLs and personal files from reports. Use the private reporting route in [Security](../../SECURITY.md) for vulnerabilities.

PRs should explain the problem, final behavior, checks run and remaining limits. Update affected docs. See [Releasing](docs/RELEASING.md) for packaging and signing.

I'm happy to help where I can, but I can't promise a response or support schedule. Keep discussion respectful and technical.

Contributions use the project's [AGPL-3.0-only license](LICENSE); retain [third-party notices](THIRD-PARTY-NOTICES.md).

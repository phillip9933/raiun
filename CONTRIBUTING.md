# Contributing to Raiun

Raiun is an independent OpenCloud client maintained on a best-effort basis. Report reproducible bugs and discuss large feature or dependency changes before implementation. Report vulnerabilities through [Security](SECURITY.md).

## Choose an app

Android source, Gradle configuration, dependency locks, tests and scripts live in `apps/android`. Start with the [Android contribution guide](apps/android/CONTRIBUTING.md) and [testing guide](apps/android/docs/TESTING.md). Open that directory in Android Studio and run its wrapper there.

Desktop remains in its separate development repository until a reviewed import into `apps/desktop`. Do not copy a moving checkout, create a second implementation here, or add CI jobs that claim to build absent source. The [monorepo guide](docs/MONOREPO.md) describes the import and platform boundaries.

Shared branding and product design references live in `design/`. Keep native UI code, dependencies and platform behavior inside the app that uses them. Introduce shared source packages only when actual consumers need them.

## Change expectations

Prioritize data safety, security, correctness and privacy, then usability and maintainability. Preserve application identities, user data, account separation and compatibility. Changes to one app must not require installing another app's toolchain.

Run checks appropriate to the change. Review visual diffs deliberately, preserve translations and document checks that could not run. Platform workflows live in `.github/workflows` at the root; commands and artifact paths must point to the correct app. See [Releasing](docs/RELEASING.md).

Keep credentials, private signing material, local account data, build products and recovery records out of Git. Tests use synthetic files and accounts. See [Privacy](PRIVACY.md).

## Reports and AI usage

Identify the affected platform, app version, OS version, server version if known, reproduction steps, expected behavior and actual behavior. Remove credentials, tokens, private URLs, filenames and file contents from reports. Explain the concrete change, relevant validation and remaining limits in pull requests.

Disclose material AI assistance and distinguish observed validation from planned checks. Contributors remain responsible for understanding their changes. Keep discussion respectful; there is no guaranteed support schedule.

Contributions use [AGPL-3.0-only](LICENSE). Retain platform [third-party notices](THIRD-PARTY-NOTICES.md).

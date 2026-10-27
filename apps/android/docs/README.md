# Android documentation index

Start with [README](../README.md) for installation and current limitations, and [Contributing](../CONTRIBUTING.md) for setup and change expectations.

| Document | Purpose |
| --- | --- |
| [Product backlog](../../../docs/PRODUCT-BACKLOG.md) | Queued Android and shared product improvements |
| [Testing](TESTING.md) | Quality commands, device requirements and validation limits |
| [Linux development](LINUX-DEVELOPMENT.md) | Installed local toolchain, commands and validation evidence |
| [Encrypted vault guide](ENCRYPTED-VAULTS-PLAN.md) | Android 1.0.0 encrypted-vault features, boundaries and interoperability |
| [Scanner SDK](OFFLINE-SCANNER-SDK.md) | Pinned dependency setup and host ownership |
| [Screenshot testing](SCREENSHOT_TESTING.md) | Golden ownership and review |
| [Release procedure](RELEASING.md) | Packaging, signing continuity and release checks |
| [Android 1.1.0 release notes](RELEASE-NOTES-1.1.0.md) | Android 1.1.0 changes and update guidance |
| [Release notes](RELEASE-NOTES-0.9.3.md) | Historical 0.9.3 beta changes, limits and feedback |
| [Changelog](../CHANGELOG.md) | Version history |
| [Encrypted security review](ENCRYPTED-SECURITY-REVIEW.md) | Encryption compatibility, local key handling and explicit plaintext handoff boundaries |
| [Security](../../../SECURITY.md) and [Privacy](../PRIVACY.md) | Reporting and data-handling boundaries |
| [Third-party notices](../THIRD-PARTY-NOTICES.md) | Dependency declarations and retained evidence |
| [Phase 0 architecture proposal](ARCHITECTURE.md) | Historical design intent, not the current module inventory |

## Android project layout

Paths below are relative to `apps/android`. This map reflects [settings.gradle.kts](../settings.gradle.kts). The Phase 0 proposal includes planned modules that are not present in this checkout.

| Path | Responsibility |
| --- | --- |
| `app/` | Android host, app wiring, instrumentation, screenshot fixtures and bundled legal assets |
| `core/model/`, `core/ui/`, `core/designsystem/` | Shared models, UI helpers and design tokens |
| `core/network/`, `core/security/` | Server protocols, credentials and trust behavior |
| `core/database/`, `core/datastore/` | Database and preference persistence |
| `core/sync/`, `core/documentsprovider/` | Background transfers and Android file-provider integration |
| `feature/` | Auth, files, search, transfers, settings, account, shares and spaces |
| `scripts/` | Scanner installation, translation checks, notices and packaging |
| `gradle/`, `config/` | Wrapper/version catalog and static-analysis configuration |
| `../../.github/workflows/` | Repository-level Android CI and reports |
| `docs/` | Current guides, historical proposals and retained release audit data |

Tests live with their modules under `src/test` and `src/androidTest`. The scanner is a pinned binary dependency, not a source module in this repository. Keep module boundaries within this platform project. See the [monorepo guide](../../../docs/MONOREPO.md) for repository-wide ownership and the later desktop import.

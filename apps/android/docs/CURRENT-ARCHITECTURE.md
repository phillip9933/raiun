# Current Android architecture

This describes the Android source layout and runtime boundaries in the Android 1.4.0/code 55 candidate. It is distinct from the [historical Phase 0 proposal](ARCHITECTURE.md). Room schema remains 28. Signing, publication and exact release validation are recorded separately. See [testing](TESTING.md) for commands and evidence boundaries, and [authentication](AUTHENTICATION.md) for protocol details.

## Modules and ownership

The module inventory comes from [settings.gradle.kts](../settings.gradle.kts). Paths are relative to `apps/android`.

| Modules | Responsibility |
| --- | --- |
| `app` | Activity/application host, navigation, ordinary/encrypted route composition, Android manifest and integration/screenshot fixtures |
| `core:model` | Shared resource, account, authentication and transfer models and path/cache helpers |
| `core:crypto` | Rclone-compatible vault codec; authenticated block and encrypted-name processing |
| `core:security` | Keystore-backed credentials, app-lock sessions, vault keys/remembered unlock and scoped network trust/routing policy |
| `core:network` | OpenCloud Graph, WebDAV, OCS and authentication protocol clients and validation |
| `core:database` | Room records/DAOs, accepted listings, transfers, operation journals, exclusions and durable recovery state |
| `core:datastore` | User preferences and preference flows |
| `core:sync` | Transfer scheduling/WorkManager execution, ordinary/shared/vault operations, offline publication, backup and private incoming-share staging |
| `core:documentsprovider` | Android SAF roots, metadata, reads, guarded edits and provider mutations |
| `core:designsystem`, `core:ui` | Material design tokens/theme and shared UI components |
| `feature:auth`, `feature:account` | Sign-in and account management UI |
| `feature:files`, `feature:spaces`, `feature:shares` | Browsing, spaces, ordinary sharing and guest invitation management |
| `feature:search`, `feature:transfers`, `feature:settings` | Search, transfer/recovery UI and app/server preferences |

Feature screens generally consume controller/ViewModel state; not every screen has a separate repository layer. `FileBrowserStore` is a facade over Room and related stores, while `TransferManager` coordinates durable transfer records with WorkManager. The scanner and updater are pinned artifacts, not source modules or dependencies on sibling working directories.

## Data flow

1. A user action enters a feature controller/ViewModel or a checked Android provider entry point. Account availability, app lock, resource scope and operation-specific permissions govern admission.
2. Network clients validate responses before accepting listings or protocol results. Database snapshot/journal code publishes accepted metadata and records exclusions/recovery state; an unverified network response is not a completed local transfer.
3. Durable transfer records schedule worker execution. Workers use account/session and destination checks before publication. Private staged files, local-copy leases and operation journals bridge asynchronous work; cancellation and ambiguous remote outcomes retain their existing recovery rules.
4. Room flows drive persisted file/transfer state; StateFlows and preference flows drive screen state. Lifecycle-aware Compose collection follows a started screen. Background workers have their own durable scheduling and are not tied to that collection.
5. SAF reads and external edits cross an explicit Android sharing boundary. Reads validate ordinary/shared access and cache identity; edits prepare a private working copy, then revalidate before journal admission. External plaintext handoff is distinct from encrypted storage.

## Invariants to preserve

- Account identity includes the exact server/user relationship. An account's asynchronous work must not acquire a later session simply because an identifier was reused.
- Ordinary file access must respect vault exclusions, including stale metadata. Shared resources have a separately checked catalog/scope; ordinary and vault paths are not interchangeable.
- Vault key verification and block authentication precede accepted plaintext publication. The rclone format does not authenticate whole-file length, path or version; see the [codec notes](../core/crypto/README.md) and [security review](ENCRYPTED-SECURITY-REVIEW.md).
- Credentials and private staging remain private; no credential values, exception payloads or shared content belong in diagnostics. A readable incoming URI is a capability, not proof of the original sender's identity or ownership of the source.
- Work that may outlive a screen needs durable state and explicit cancellation/recovery. A lifecycle collection change must not silently cancel an accepted transfer or approve an ambiguous remote operation.
- App identity, provider authorities, signing identity and existing user-data compatibility are separate from module organization. Signing, release and server/device acceptance require their own evidence.

## Version boundaries

Android 1.3.2 ([tag](https://github.com/phillip9933/raiun/releases/tag/android-v1.3.2), source `f19c3ede8e7d1aff3514680d22782f56fb32b188`) contains the folder/transfer fixes and durable account-removal, credential-key, provider-boundary and lifecycle maintenance from PR #50. Room schema 28 retains pending-removal admission and cleanup recovery. Its published validation does not certify later changes.

Android 1.3.3 connects the ordinary file menu to the existing server document-app chooser and adds versioned credential envelopes with exact storage-slot AAD. See [server document apps](SERVER-DOCUMENT-APPS.md) and [credential storage](CREDENTIAL-STORAGE.md) for implementation and trust boundaries. Existing server-editor leases and vault exclusions remain authoritative; legacy credential migration retains the original key alias and uses serialized checked writes.

Android 1.3.3 also extracts destination-picker ownership inside `app`, centralizes transfer-state semantics without changing persisted TEXT values, requires successful download outcomes before cache use, checks active-account admission before claiming work, and adds launch-time caller URI checks on API 35+. API 26–34 retain the existing incoming-share behavior without a general sender-provenance guarantee. See [Android hardening](ANDROID-HARDENING.md) for ownership decisions, unknown-state handling and exact acceptance limits.

Android 1.4.0 continues issue #51 decomposition within existing modules. It moves focused Room entity/DAO declarations into same-package persistence files while `FileBrowserDatabase` retains registration and migrations at schema version 28. It also extracts the backup settings UI into `FolderBackupSettings.kt` and preview/thumbnail content ownership into `VaultPreviewContent`; the ViewModel retains route, account, session, generation and revocation decisions. These source moves do not change the persisted schema or migration behavior.

This document describes source behavior. Executed checks, release status and unrun device/server scenarios belong in [Testing](TESTING.md).

## Follow-up boundaries

[Component decomposition](https://github.com/phillip9933/raiun/issues/51) remains incremental. Android 1.4.0 adds focused database, backup UI and preview-content extractions alongside the earlier destination-picker owner; no new vault module or complete ViewModel/file-browser split is claimed. [Typed transfer states](https://github.com/phillip9933/raiun/issues/52), incoming-share caller checks on API 35+ ([#55](https://github.com/phillip9933/raiun/issues/55)), [release shrinking](https://github.com/phillip9933/raiun/issues/53) and [credential slot binding](https://github.com/phillip9933/raiun/issues/54) are described above and in their linked guides. Full process-kill, chooser and profile acceptance remain separate. The credential envelope retains the Keystore alias and legacy reads while introducing a new envelope for writes and validated migrations.

Android 1.4.0 separates `VaultRepository` discovery/creation from `VaultSession` live encrypted operations, with focused models, cipher adapters and shared support. Android vault adapters and route contracts also have separate files. The ViewModel still owns route/account/generation/key/session decisions; source moves do not change persisted class identities, Room 28 or the encryption format.

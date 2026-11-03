# Current Android architecture

This describes the Android source layout and runtime boundaries as of 3 November 2026. It is distinct from the [historical Phase 0 proposal](ARCHITECTURE.md). The unpublished maintenance candidate is 1.3.2/code 52 with Room schema 28. Published Android remains 1.3.1/code 51; the changes described below as candidates are not a new release. See [testing](TESTING.md) for commands and evidence boundaries, and [authentication](AUTHENTICATION.md) for protocol details.

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

## PR #50 and the current local candidate

[Draft PR #50](https://github.com/phillip9933/raiun/pull/50), source `8bea4cae586759f85cbffd9257211dc2339f24e1`, contains the seven reviewed quality fixes: bounded synchronous encrypted listing staging across thread hops; conditional SENT copy/move recovery; exact account identity reuse; external-edit revalidation after preparation; bounded single-name lookup; certificate replacement/removal-state correction; and nonsensitive connection draft restoration. Their prior local validation and signed phone candidate are evidence for that source, not automatic validation of later changes.

The current unpublished follow-up adds durable account-removal admission/recovery, credential envelope/key failure handling with bounded diagnostics, vault-exclusion checks for provider metadata/search/paging as well as direct reads, and incoming-share rejection of Raiun's own private providers. It also replaces UI flow collection with lifecycle-aware collection and waits for document-edit downloads using observed transfer state while retaining cancellation and authorization checks. These changes preserve external backup sources already readable through Android grants; they do not establish original-sender provenance. Provider metadata hardening is not evidence that ciphertext was previously disclosed.

This document records implementation intent and boundaries, not passing validation. Current follow-up results must be recorded separately on its final source; historical tests, signed APKs and native runs do not certify this candidate. The local candidate version is 1.3.2/code 52; publication remains a separate step.

## Deferred work

The public roadmap tracks [component decomposition](https://github.com/phillip9933/raiun/issues/51), [typed transfer states](https://github.com/phillip9933/raiun/issues/52), [release shrinking](https://github.com/phillip9933/raiun/issues/53) and [credential slot-AAD migration](https://github.com/phillip9933/raiun/issues/54). [Incoming-share sender provenance](https://github.com/phillip9933/raiun/issues/55) is also tracked separately. Current credential hardening retains the existing envelope and Keystore alias.

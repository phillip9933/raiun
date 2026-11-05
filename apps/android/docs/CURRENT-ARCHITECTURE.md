# Current Android architecture

This describes the Android source layout and runtime boundaries, including the Android 1.5.0/code 58 release source. Release preparation does not imply publication or passing release gates. It is distinct from the [historical Phase 0 proposal](ARCHITECTURE.md). Room schema remains 28. Signing, publication and exact release validation are recorded separately. See [testing](TESTING.md) for commands and evidence boundaries, and [authentication](AUTHENTICATION.md) for protocol details.

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

[Component decomposition](https://github.com/phillip9933/raiun/issues/51) remains incremental. Android 1.4.0 added focused database, backup UI and preview-content extractions alongside the earlier destination-picker owner. Android 1.5.0 adds the browser, transfer-execution and cohesive encrypted-session owners described below; no new vault module or complete ViewModel/file-browser split is claimed. [Typed transfer states](https://github.com/phillip9933/raiun/issues/52), incoming-share caller checks on API 35+ ([#55](https://github.com/phillip9933/raiun/issues/55)), [release shrinking](https://github.com/phillip9933/raiun/issues/53) and [credential slot binding](https://github.com/phillip9933/raiun/issues/54) are described above and in their linked guides. Full process-kill, chooser and profile acceptance remain separate. The credential envelope retains the Keystore alias and legacy reads while introducing a new envelope for writes and validated migrations.

Android 1.4.0 separates `VaultRepository` discovery/creation from `VaultSession` live encrypted operations, with focused models, cipher adapters and shared support. Android vault adapters and route contracts also have separate files. At that version, the ViewModel retained route/account/generation/key/session decisions; Android 1.5.0 delegates that authority to the lifecycle owner described below. These source moves do not change persisted class identities, Room 28 or the encryption format.

## Android 1.5.0 component refactoring — #51

The ordinary browser keeps route composition in `FileBrowserScreen.kt`, with navigation and status chrome in `FileBrowserChrome.kt`, file list/grid presentation in `FileBrowserContent.kt`, and actions/dialogs in `FileBrowserActions.kt`. Callbacks, layout, accessibility semantics and persisted preferences stay the same.

`BackupDestinationPickerOwner` owns backup destination navigation, ordinary/shared paging, picker revisions and shared snapshots. `FileBrowserViewModel` retains account authority, its account-job lifetime, accepted UI state and discovery observation. The picker uses the same ViewModel scope; results still need the matching account, location and picker revision. Its ordinary-read interface permits controlled late-result tests without moving account or write authority into a test adapter.

`OrdinaryPlacementOwner` owns copy/move enqueue attempts, the in-flight gate, batch remainders and keep-both conflict presentation. The ViewModel retains selection preparation, current account/location and the state reducer; `FileOperationManager` still validates and journals each conditional operation. Navigation may hide an old busy indicator, but cannot start a second attempt while the first enqueue is pending. Both initial placement and keep-both retries retain the original name binding and do not automatically replay admitted sources. A separate lifecycle fix adds a captured context revision: leaving and returning to the same account or folder cannot admit an older result, while a same-location refresh does not invalidate an active attempt.

`BrowserAccountContext` supplies immutable per-load bindings and navigation requests. Ordinary account collectors, directory/search/offline results and asynchronous completion UI are admitted on Main against the captured binding. Saved-folder and shortcut reads run off Main, then need the same account epoch and navigation request before changing the location. Account changes clear prior account metadata and action state; the transient `accountRevision` also resets resource-bearing dialogs and previews. Resource actions reject another account's retained resource. Shared UI preferences and already-admitted backend operations remain separate from this presentation lifetime.

`CachedCollectionPager` returns the accepted request when changing accounts and serializes result/byte-memo admission with account and option changes. A failed page keeps the last verified rows and reports its attempted request; it does not count as a successful replacement. Encrypted-folder discovery invalidates even when the new account has no available Space. Creation results carry the original account binding, while their single global busy gate remains tied to the accepted creation. Backup-picker jobs publish on Main and capture revision/path in their location identity so reopening the same root cannot lose its new request through flow conflation.

The encrypted route keeps lifecycle, navigation and callback wiring in `VaultRoute.kt`. `VaultRouteModels.kt` holds presentation state and callbacks, `VaultUnlockContent.kt` renders password/key verification, `VaultPromptController.kt` owns Android prompt presentation and cancellation, and `VaultPreviewDialog.kt` owns preview presentation and decoded bitmap cleanup. These same-package declarations retain their class identities. `VaultViewModel` delegates unlock/enrollment and session authority to `VaultSessionLifecycle`; the prompt controller cannot approve a session by itself.

`VaultDirectoryContent` owns encrypted-directory snapshots, visibility-stable first-page acquisition and page bookmarks. The ViewModel coordinates directory actions and validates mutation sources using the lifecycle owner's admitted account, generation and session. The lifecycle owner schedules/cancels the shared operation job and admits session publication; directory workers cannot replace its session or keys. A late first page closes its unadopted snapshot; a late page cannot close a replacement snapshot. Action leases are cleared when directory contents close, before the ViewModel closes the session. These are transient in-memory helpers; persisted models, Room schema and encrypted data formats are unchanged.

`VaultPickedTransferExecution` owns provider metadata/stream IO, queued-upload presentation and incomplete-export cleanup for a request already consumed by the ViewModel. The ViewModel wires picker leases, route-stop/device-lock events and source/destination revalidation; `VaultSessionLifecycle` supplies job, generation and session/key authority. Failure handling uses that same admitted route context. Uploads retain the existing checks around metadata and directory validation; exports retain strong-version/identity/size validation before opening the destination. Stream closure and non-cancellable best-effort deletion of an incomplete newly created export move with execution. No vault key is persisted or independently retained by the helper.

A separate `feature:vault` module remains deferred. The route currently depends on host resources, the Activity and biometric host, secure-window lifecycle, scanner/SAF entry points and the lifecycle owner's session authority. Moving those files into a Gradle module now would either create a dependency back to `app` or require a wider host-contract redesign. The existing `core:crypto`, `core:security` and `core:sync` boundaries continue to separate codec, protected storage and encrypted operations. Further ViewModel decomposition should move a cohesive responsibility with its cancellation and admission rules, rather than exposing shared mutable session/key state.

`VaultSessionLifecycle` is the single mutable owner of route/account admission, generation, the operation job, live session, selected target, verified key material, account proof, credential permit, pending biometric requests and remember/forget state. The ViewModel reads that context and supplies presentation, content cleanup and post-open effects. The owner uses the existing ViewModel scope and explicit target transitions; no second session/key authority or new persistence format is introduced.

Session and first-directory adoption run synchronously after the final admission check. Local session, snapshot and material ownership is relinquished before any suspended post-open transfer; cancelling that transfer cannot close the adopted session. Late diagnosis is checked again before changing UI state, and post-open work checks the current session before replacing the offline observer. A late unknown remember outcome still blocks its durable identity, but only clears temporary key material belonging to its own live session. Password/request buffers and unadopted resources retain cancellation cleanup; directory snapshots and action leases close before the backing session.

Remembered-key admission skips the biometric-only diagnostic lookup after checking the current account snapshot. Key currency, owner binding, route/generation, server proof and directory/root validation remain mandatory. An internal, disabled-by-default measurement seam separates local restore, server verification, initial directory acquisition and final admission through publication. It accepts only fixed stage/outcome enums and elapsed nanoseconds; it adds no runtime logging, persistent timing history or secret-bearing diagnostic data. “Verifying key” covers all of these stages, including server and directory work.

# Raiun — Phase 0 Architecture Proposal

**Historical proposal:** This document records Phase 0 design intent from 2026-09-06. It is not a current implementation or acceptance checklist. See the [current repository layout](README.md#repository-layout) and [testing guide](TESTING.md) before using its proposed paths or phases.

**Status at time of writing:** Proposed for review
**Date:** 2026-09-06  
**Scope:** Phase 0 analysis and architecture only. Phase 1 project initialization is intentionally out of scope.  
**Application ID:** `eu.opencloud.android.next`  
**Reference repositories (read-only):**

- `C:\src\OpenCloud-Workspace\opencloud-web`
- `C:\src\OpenCloud-Workspace\opencloud-android`

## 1. Purpose and principles

Raiun is a native Android application built with Kotlin and Jetpack Compose. It aims to provide an OpenCloud mobile experience and preserve relevant protocol, offline, transfer, and system-integration behavior.

> **Provenance review:** Earlier wording described this project as “ground-up” and “not a fork.” That clean-room claim has not been independently verified and should be reviewed before it is relied on. This document does not assert any external attribution.

### Non-negotiable rules

1. Production code is 100% Kotlin; no Java and no XML layouts.
2. All new source lives under `C:\src\OpenCloud-Workspace\opencloud-android-next`.
3. The legacy Android and web repositories remain read-only specifications.
4. Compose/Material 3 provide implementation primitives; OpenCloud web tokens control the visual system. Dynamic color is disabled by default because pixel/brand parity is required.
5. The app is offline-first. Room is the durable UI source of truth; a network response is never directly treated as final screen state.
6. Long-running work must survive process death, device reboot where Android permits, storage pressure, and background restrictions through persisted state plus WorkManager.
7. The app must integrate with Android's Storage Access Framework (SAF), including a DocumentsProvider, rather than merely offering in-app file browsing.

## 2. Reference evidence reviewed

### Web UX/design-system sources

- `packages/design-system/src/styles/defaults.css` — semantic light color roles.
- `packages/design-system/src/styles/tailwind.css` — 4 px spacing scale and responsive breakpoints.
- `packages/design-system/src/styles/fonts.css` — Inter variable font.
- `packages/design-system/src/composables/useIsMobile/index.ts` — mobile and tablet behavior.
- `packages/web-runtime/src/layouts/Application.vue` — application shell.
- `packages/web-runtime/src/components/Topbar/TopBar.vue` — compact top bar.
- `packages/web-runtime/src/components/SidebarNav/SidebarNavMobile.vue` — mobile navigation drawer.
- `packages/web-pkg/src/components/AppBar/AppBar.vue` — files app bar, selection state, actions.
- `packages/design-system/src/components/OcBreadcrumb/OcBreadcrumb.vue` — mobile breadcrumb behavior.
- `packages/web-pkg/src/components/FilesList/ResourceTable.vue` and `ResourceListItem.vue` — list rows.
- `packages/design-system/src/components/OcDrop/OcMobileDrop.vue` and `OcBottomDrawer.vue` — action-sheet behavior.

### Legacy Android sources

- `opencloudData/.../datasources` — remote contracts for authentication, files, sharing, users, spaces, capabilities, OAuth, app providers, and WebFinger.
- `opencloudComLibrary/.../resources` — OCS, Graph, WebDAV, OIDC, WebFinger, and TUS protocol operations.
- `opencloudData/.../OpencloudDatabase.kt` and `.../db` — Room schema concepts.
- `opencloudApp/.../workers` and `WorkManagerProvider.kt` — transfer, available-offline, automatic upload, cleanup, and discovery behavior.
- `opencloudApp/.../providers/FileContentProvider.kt` — historical Android provider/SQLite behavior and system-file integration inventory.

## 3. Product architecture

### 3.1 User-visible architecture

```text
Compose UI
  → feature Action
  → ViewModel reducer/use case
  → repository
  → local database and/or protocol client
  → Room Flow
  → immutable UiState
  → Compose UI
```

Each feature uses an MVVM/MVI hybrid contract:

- **UiState:** complete, immutable, renderable state.
- **Action:** a user, lifecycle, permission, or system input.
- **Effect:** a non-replayable navigation, snackbar, picker, or permission request.
- **ViewModel:** action reducer and use-case orchestrator; no direct view references.
- **Route:** lifecycle-aware state/effect collection and navigation wiring.
- **Screen:** stateless Compose rendering wherever possible.

Feature state is exposed as `StateFlow`; one-off effects use a buffered `SharedFlow` or `Channel`. UI state restores navigation/filter/view preferences from saved state and validated persistent settings, never from unvalidated raw storage values.

### 3.2 Module layout

```text
opencloud-android-next/
├── app/                              # Application, single activity, DI bootstrap
├── build-logic/                       # Gradle convention plugins (Phase 1)
├── core/
│   ├── common/                        # Result, dispatchers, logging, utilities
│   ├── model/                         # Protocol-independent domain models
│   ├── designsystem/                  # Theme, tokens, reusable Compose primitives
│   ├── ui/                            # Shared UI state/error/preview utilities
│   ├── navigation/                    # Typed destinations and navigation host
│   ├── network/                       # HTTP, protocol clients, auth interceptors
│   ├── database/                      # Room DB, DAOs, migrations, entity mappers
│   ├── datastore/                     # Validated app preferences and repair logic
│   ├── security/                      # Keystore, token and TLS trust management
│   ├── documentsprovider/             # DocumentsContract provider and document IDs
│   ├── sync/                          # WorkManager orchestration and worker support
│   └── testing/                       # Fakes, fixtures, test dispatchers, screenshot tools
├── feature/
│   ├── auth/
│   ├── files/
│   ├── spaces/
│   ├── shares/
│   ├── transfers/
│   ├── search/
│   ├── settings/
│   └── account/
└── docs/
    └── ARCHITECTURE.md
```

Dependencies point inward: feature modules depend on core abstractions and domain models, not on other feature implementations. `core:documentsprovider` reads repositories/DAOs through a narrowly scoped document-access facade and never imports Compose code.

### 3.3 Technology choices

| Concern | Proposal | Rationale |
|---|---|---|
| Build | Kotlin DSL, version catalog, convention plugins | Consistent, modern, maintainable Gradle setup. |
| UI | Jetpack Compose + Material 3 | Compose-only requirement; custom OpenCloud tokens prevent stock Material appearance. |
| State | ViewModel, Coroutines, Flow | Lifecycle-aware, testable one-way data flow. |
| DI | Koin BOM, Compose/ViewModel/WorkManager artifacts | Current Koin supports all required Android integrations; minimizes boilerplate. |
| Database | Room + KSP | Observable, transactional offline source of truth. |
| Preferences | Proto DataStore | Schema-based settings and corruption handling; no raw SharedPreferences for new settings. |
| Credentials | Android Keystore-backed encrypted storage | Tokens and secrets never belong in Room or DataStore. |
| Networking | OkHttp plus protocol-specific clients | Required for streaming, WebDAV methods, multipart/TUS, custom trust, and interceptors. |
| Serialization | Kotlin serialization or Moshi, decided after fixture validation | Must correctly parse OCS wrappers, Graph payloads, discovery, and TUS metadata. |
| Background work | WorkManager + foreground services via `ForegroundInfo` | Durable background execution within Android policy. |
| Images | Coil | Compose-native thumbnail and preview loading. |
| Testing | JUnit, coroutine test, MockWebServer, Room tests, Compose tests, screenshot tests | Validates protocol and visual parity. |

Phase 1 should begin with `minSdk = 26`, `compileSdk = 36`, `targetSdk = 36`, JVM bytecode target 17, and an internally compatible stable AGP/Gradle/Kotlin/Compose set. The workstation has JDK 21 available, but Java 17 remains the application compilation target initially.

## 4. Compose design system derived from mobile web

### 4.1 Responsive modes

The web design system defines `xs=580`, `sm=640`, `md=960`, `lg=1200`, and `xl=1600` CSS-pixel breakpoints. It treats widths below 640 as mobile and widths at/below 960 as compact/tablet.

Android uses available window dp and `WindowSizeClass`, not a literal CSS-pixel conversion. The native modes preserve the same UX intent:

| Native mode | Behavior |
|---|---|
| Compact | Phone shell: hamburger drawer, single pane, mobile breadcrumb, gradient FAB, action bottom sheets. |
| Medium | Compact shell remains preferred; more room for actions and list metadata. |
| Expanded | Future adaptive layout: persistent navigation and optional details pane. Phone parity remains first priority. |

### 4.2 Shell and interaction parity

- Top bar: roughly 52 dp content row, 16 dp horizontal inset, hamburger, mobile logo, and account/notification actions.
- Main shell: 8 dp outer inset over `surfaceContainer`; white/surface content panel with 12 dp corners.
- Compact navigation: modal drawer, 85% window width capped around 320 dp, 40% black scrim, 200 ms slide/fade.
- File app bar: 16 dp horizontal inset and at least 48 dp controls row; optional action row around 40 dp.
- Mobile breadcrumb: back icon plus centered, bold current folder; hide full trail below the matching compact breakpoint.
- Resource rows: 24 dp icon/thumbnail, 8 dp icon-to-name gap, primary title and secondary metadata/path when applicable, trailing quick/context action, 48 dp minimum touch target.
- Context actions: modal bottom sheet with 40% black scrim, 12 dp top corners, title/back/close header, surface groups, default maximum height 66% viewport.
- Create/upload: compact-screen gradient FAB from secondary to primary with medium elevation/shadow.
- Selection: replace normal action controls with batch actions and a clear selection/count control.

### 4.3 Semantic light palette

Dynamic color is disabled. The initial `OpenCloudLightColorScheme` maps the web defaults directly:

| Role | Value | Role | Value |
|---|---:|---|---:|
| background/surface | `#FFFFFF` | onBackground/onSurface | `#191C1D` |
| chrome/secondary | `#20434F` | onChrome/onSecondary | `#FFFFFF` |
| primary | `#00677F` | onPrimary | `#FFFFFF` |
| primaryContainer | `#B7EAFF` | onPrimaryContainer | `#001F28` |
| secondaryContainer | `#CFE6F1` | onSecondaryContainer | `#071E26` |
| tertiary | `#5A5C7E` | tertiaryContainer | `#E0E0FF` |
| surfaceContainer | `#F6F8FA` | surfaceContainerHigh | `#F2F4F5` |
| surfaceContainerHighest | `#ECEEF0` | surfaceContainerLow | `#FBFCFE` |
| surfaceDim | `#D8DADC` | surfaceVariant | `#DBE4E8` |
| onSurfaceVariant | `#40484C` | outline | `#70787C` |
| outlineVariant | `#BFC8CC` | error | `#BA1A1A` |
| errorContainer | `#FFDAD6` | scrim/shadow | `#000000` |

The inspected source exposes authoritative default-light tokens only. Dark-mode pixel parity is deferred until an actual OpenCloud dark theme/configuration is captured. The app must not invent a dark palette and describe it as web parity.

### 4.4 Typography, dimensions, motion

- Font: Inter variable (`100..900`, oblique `0..12deg`) after explicit font-license approval. Use a platform fallback until approved.
- Spacing: 4 dp base: `4, 8, 12, 16, 20, 24, 32` dp semantic tokens.
- Type tuning: 12 sp auxiliary, 14 sp metadata, 16 sp body/control, 18 sp large control, 20 sp screen/folder heading; selected/current titles use 600–700 weight.
- Shapes: 2–4 dp thumbnail corners; 8 dp grouped action surface; 12 dp cards/sheets/content shell; pill/full where web buttons/FAB require it.
- Motion: 200 ms drawers/sheets, 300 ms fade, 350 ms emphasized pane transitions; respect animator-duration scale and reduced-motion accessibility settings.
- Accessibility: visible elements may match the web at 24/32 dp, but interactive surfaces keep at least 48 dp touch targets and descriptive Compose semantics.

### 4.5 `core:designsystem` primitives

- `OpenCloudTheme`, `OpenCloudColorScheme`, dimensions, shapes, motion, type.
- `OcTopBar`, `OcContentSurface`, `OcMobileBreadcrumb`, `OcNavigationDrawer`.
- `OcGradientFab`, `OcModalActionSheet`, `OcActionRow`, button variants (filled/outline/raw/raw-inverse).
- `OcResourceIcon`, `OcResourceRow`, `OcSelectionBar`, empty/loading/error states.

All foundational components need previews plus screenshot tests at 360x800 and 412x915, font scales 1.0 and 1.3, and semantic tests for icon-only controls.

## 5. Networking and server protocol inventory

The legacy app relies on multiple protocol families. The new app must use protocol-specific clients behind repository interfaces; it must not reduce all operations to a fixed Retrofit-style REST interface.

### 5.1 Discovery and authentication

- Server status and canonical base-URL normalization, including permanent redirects.
- Basic-auth login verification.
- Bearer-token login verification.
- OIDC discovery at `/.well-known/openid-configuration`.
- Authorization Code with PKCE, token exchange, refresh, and dynamic client registration if server-required.
- WebFinger at `/.well-known/webfinger` for instance and OIDC issuer/client discovery.
- Capability discovery: `GET /ocs/v2.php/cloud/capabilities?format=json` with `OCS-APIREQUEST: true`.
- Current-user info: `GET /ocs/v2.php/cloud/user?format=json`.

### 5.2 Graph, OCS, WebDAV, and app providers

- Spaces/drives: `GET /graph/v1.0/me/drives`.
- Avatar: `GET /graph/v1.0/me/photo/$value`.
- Quota: WebDAV depth-0 `PROPFIND` for quota properties.
- File operations: `PROPFIND`, `MKCOL`, `MOVE`, `COPY`, `DELETE`, `GET`, `PUT`, conditional requests/ETags, metadata reads, and listing.
- Shares: OCS get/create/update/delete plus paginated sharee search under `ocs/v2.php/apps/files_sharing/api/v1`.
- App registry and “open in web”/create-file APIs: use server capability-advertised endpoints only.
- TUS: create upload, query offset, patch chunks, complete/resume, checksum, and expiry handling.

### 5.3 Protocol client design

```text
Repository
  ├── DiscoveryClient       # status, redirects, WebFinger
  ├── OidcClient            # discovery, registration, code/token/refresh
  ├── OcsClient             # capabilities, user, shares, sharees
  ├── GraphClient           # drives/spaces/avatar and Graph resources
  ├── WebDavClient          # streaming DAV operations and XML multistatus parsing
  ├── TusClient             # resumable transfer protocol
  └── AppProviderClient     # dynamic, capability-provided endpoint URLs
```

All clients return typed outcomes that preserve HTTP status, retryability, server error data, network/TLS failures, and cancellation. Repositories map these to domain errors; UI does not parse transport exceptions.

## 6. Persistence and offline-first schema

The legacy Room database is at version 49 and includes app registry, folder backup, capabilities, files, file sync state, shares, transfers, spaces, space specials, and quotas. It also has historical SQLite/content-provider tables.

This app does **not** reuse, import, or migrate that database. It begins with a clean Room schema and fresh authentication, avoiding propagation of legacy database assumptions.

### 6.1 Proposed Room entities

- `AccountEntity`: local ID, canonical server URL, server user ID, display name, auth type, issuer, active status; **no secrets**.
- `ServerCapabilityEntity`: normalized capabilities and fetch metadata by account.
- `SpaceEntity`: account + drive ID, type/alias/name, owner, description, root ID, root WebDAV URL, root ETag, quota, disabled/deleted state.
- `ResourceEntity`: account + space + stable remote item ID, parent ID/path, name, MIME/folder, size, ETags, permissions, timestamps, links, share flags, local copy fields, offline policy, sync timestamps.
- `ShareEntity`: account + server share ID, target resource/path, type, target, permissions, link/token/name, dates.
- `TransferEntity`: UUID, account/space/resource IDs, direction, source URI/path, destination path, byte counts, state/error, WorkManager ID, overwrite/local behavior, complete TUS resume state, timestamps.
- `FolderBackupEntity`: source tree URI, media type, destination, account/space, constraints, behavior, last safe scan time.
- `AppProviderEntity`, `UserProfileEntity`, `SyncCheckpointEntity`, and document-provider metadata as required.

Use composite unique indices keyed by account/space/server IDs, never only an opaque local numeric ID. Every multi-table remote refresh runs transactionally so observers never see an internally inconsistent folder snapshot.

## 7. Defensive settings and persistence

New settings use **Proto DataStore**. SharedPreferences is not used for new feature state; if a platform/library requirement leaves a SharedPreferences file, wrap it behind the same defensive repository policy.

### 7.1 Settings requirements

1. Define an explicit protobuf schema with defaults for every field.
2. Read through a single `SettingsRepository` that converts storage data to canonical domain settings.
3. Catch `IOException`, protobuf parse errors, enum unknown values, and unexpected runtime decoding failures. Emit canonical defaults rather than crash app startup/UI rendering.
4. Validate every persisted value: URL shape, enum membership, numeric range, path/URI format, account references, selected sort/view mode, and feature-dependent values.
5. Repair invalid data atomically using `DataStore.updateData`; record a non-sensitive diagnostic reason and return the repaired canonical value.
6. Treat missing keys as defaults, not exceptional state.
7. On a corrupt DataStore file, use a corruption handler that replaces it with default settings, logs telemetry without secrets, and surfaces a recoverable informational message only after the app is usable.
8. Keep UI state resilient when a referenced account/space no longer exists: fall back to current valid account, then onboarding/auth state.
9. Version settings independently, write migrations as pure transformations, and test missing/corrupt/old/future-value cases.

### 7.2 Canonical fallback examples

| Invalid stored value | Canonical fallback |
|---|---|
| Unknown list sort enum | Name ascending |
| Unknown view mode | List mode |
| Invalid active-account ID | First valid account, otherwise signed-out |
| Missing upload target space | Personal/default supported space |
| Invalid content/tree URI | Disable that backup configuration and expose repair UI |
| Invalid cache retention duration | Product default bounded duration |
| Unrecognized theme value | OpenCloud light theme |

The startup path must be safe even if all preference files are missing or corrupt.

## 8. Security, credentials, and custom TLS

### 8.1 Credentials

- Store access tokens, refresh tokens, client secrets, and account-sensitive encryption material in Android Keystore-backed encrypted storage.
- Room/DataStore persist only account IDs and non-secret auth metadata.
- Scope credential records by canonical account ID and issuer/server identity.
- Serialize refresh per account with a mutex/single-flight coordinator to avoid token-refresh storms.
- On invalid grant/revocation, clear only the affected account credential, preserve offline metadata where safe, and route to re-authentication.
- Never include Authorization headers, tokens, passwords, private links, or raw server documents in logs, crash reports, or worker output data.

### 8.2 Custom SSL certificates

Custom certificate behavior is a first-class security subsystem, not an `OkHttpClient` bypass.

- Default policy: platform trust store and hostname verification; no trust-all manager, no hostname-verification bypass.
- During discovery/auth, expose certificate failures as explicit, typed states containing non-secret certificate identity data (subject, issuer, SHA-256 fingerprint, validity dates).
- A user/admin may explicitly trust a certificate or public-key pin for a canonical host after informed confirmation; enterprise/MDM policy may preconfigure trust.
- Persist trust decisions securely, bound to exact host/port and certificate/pin identity; invalidate/ask again when the presented identity changes.
- Apply the selected trust policy to all protocol clients and all workers consistently.
- Support removal/review of trusted certificates in settings.
- Add MockWebServer TLS integration tests for platform trust, explicit acceptance, rejection, certificate rotation, and hostname mismatch.

## 9. SAF and DocumentsProvider integration

The app will expose OpenCloud files to Android's system picker and external apps through a real `DocumentsProvider`, declared in the app manifest with its own authority derived from the side-by-side app ID (for example, `eu.opencloud.android.next.documents`). This is distinct from merely receiving upload files through `ACTION_OPEN_DOCUMENT`.

### 9.1 Provider contract

Implement the applicable `DocumentsContract` operations:

- `queryRoots`: expose authenticated account roots and supported spaces.
- `queryChildDocuments`: expose cached folders/resources with stable ordering and pagination behavior.
- `queryDocument`: map a stable opaque document ID to metadata.
- `openDocument`: serve local cached content immediately; enqueue/download missing content under an Android-compatible strategy and return a readable descriptor only when available.
- `openDocumentThumbnail`: return cached/generated thumbnail when supported.
- `createDocument`, `renameDocument`, `moveDocument`, `deleteDocument`: delegate through repository operations only where capabilities/permissions allow.
- `isChildDocument`, `findDocumentPath`, `querySearchDocuments`, and `getDocumentType` where supported by the current feature level.

Document IDs are opaque, URL-safe, versioned identifiers containing no credentials and no mutable path as their sole identity. They are based on local account ID, space ID, and stable server resource ID. Remote rename/move must not invalidate existing grants where Android permits a stable document ID.

### 9.2 Provider constraints and reliability

- Provider calls run on binder threads and must not perform unbounded network I/O.
- Metadata comes from Room; stale metadata is marked/updated asynchronously.
- The provider exposes only accounts/spaces that are valid and authorized.
- Respect Android persistable URI permissions for incoming SAF upload sources and validate access before queued work begins.
- Use pipe/file-descriptor streaming only after transfer design and cancellation semantics are proven; initial implementation may require a completed local cache for missing remote content to avoid blocking external callers indefinitely.
- Notify document changes with `ContentResolver.notifyChange` after local/remote mutations, download completion, sync refresh, and account removal.
- Do not expose private local cache paths, access tokens, server URLs with credentials, or unsupported remote operations.
- Test with Android system picker, Files by Google/AOSP DocumentsUI, create/open/save flows, account removal, offline resources, revoked source permissions, and process restart.

## 10. Background sync and transfer architecture

### 10.1 Durable work model

WorkManager owns scheduling and execution; Room owns the durable transfer/sync state machine. A worker is restartable because all required input is in Room, not only in WorkManager `Data`.

```text
UI / DocumentsProvider / share intent
  → create/update TransferEntity transactionally
  → enqueue unique work with TransferEntity UUID only
  → Worker reloads full transfer, credentials, capability, and checkpoint state
  → streams with progress checkpoints to Room
  → transactionally writes terminal/retry state
  → Room Flow updates UI/provider; notification reflects durable state
```

### 10.2 Worker set

- `UploadWorker`: content URI or local-file upload; validates persisted permission/cache; chooses plain/chunked/TUS transport from capabilities and file size.
- `DownloadWorker`: downloads to a `.part` file, verifies outcome, atomically renames, then updates resource/cache metadata.
- `OfflineSyncWorker`: refreshes selected offline resources/folders, recursively where policy permits.
- `FolderBackupScanWorker`: scans SAF tree URIs with safety timestamp, deduplicates, and enqueues uploads.
- `AccountDiscoveryWorker`: refreshes capabilities/profile/spaces following successful auth or scheduled refresh.
- `CacheCleanupWorker`: removes eligible local copies while preserving pin/offline/document-provider requirements.

### 10.3 WorkManager policy

- Use unique work names based on stable account/resource/transfer identity; `KEEP` prevents duplicate uploads/downloads while an equivalent durable transfer is active.
- Require `NetworkType.CONNECTED` for remote work; apply unmetered, charging, and battery-not-low constraints from settings/backup policy.
- Use exponential backoff for transient DNS/network/5xx/429/TUS-offset recovery; do not retry auth, permission, corrupt-source, or unrecoverable TLS errors without user action.
- Promote large active transfers to foreground work with user-visible, cancelable notifications and Android-version-compatible foreground-service types/permissions.
- Persist worker UUID, attempt count, bytes, current chunk/offset, server ETag, and TUS session state after durable checkpoints.
- Reconcile stale `RUNNING` rows at process startup and before enqueueing: if WorkManager has no active matching work, transition safely to queued/retry/paused according to durable checkpoint and cause.
- Re-enqueue eligible queued/retry transfers after app restart, device reboot, network return, or account unlock without duplicating completed work.
- Workers must cooperate with cancellation, close streams promptly, leave resumable TUS state valid, and never mark success before database/cache commit succeeds.

### 10.4 Large/chunked/TUS specifics

- Persist TUS upload URL, protocol version, offset, total length, metadata, checksum, expiration, and last successful checkpoint in `TransferEntity`.
- Before resuming, validate source availability/length/checksum and server session state. If stale or invalid, clear only invalid resume state and create a new session when safe.
- For `content://` uploads, preserve URI permission, copy to an app-private cache with a `.part` file when random access/retry is required, validate byte count and checksum, then atomically publish the cache file.
- Ensure remote parent folders exist before upload; resolve collisions deterministically unless overwrite is explicitly authorized.
- Use ETag/precondition headers for overwrite/conflict detection and preserve enough state to present a conflict-resolution UI later.
- For downloads, retain partial data only when the server/range protocol and integrity rules make safe resume possible; otherwise delete invalid partials.

### 10.5 Pre-1.0 implementation update (unreleased)

Backup scanning emits batches of at most 256 files and keeps its directory queue and visited identities in private temporary SQLite storage. It no longer builds the whole tree in memory or stops at 100,000 entries. Provider-declared loading/error states fail the scan instead of advancing its completion cursor. Active-upload detection uses an indexed existence query; startup transfer recovery also reads bounded pages.

DAV discovery parses one response element at a time with a hardened SAX parser. Ordinary folder refresh stages entries in temporary SQLite storage, with encrypted record payloads, HMAC identity indexes and keys held only in the process. Duplicate identities and incomplete listings fail before the prior snapshot is replaced. Publication validates and reads bounded pages inside one Room transaction, preserving the prior snapshot on failure. The streaming refresh accepts at most 256 MiB of DAV metadata; per-element and record-size limits remain deliberate abuse boundaries. Other callers of the list-returning discovery API retain its 32-MiB cap and typed resource list. The browser still observes the visible directory as a list: this improves discovery and publication memory use without claiming a fully paged UI.

Picked encrypted uploads first stage immutable ciphertext while unlocked. `VaultUploadWorker` can then transfer and verify those bytes without an encryption key. Retrying replays the staged object conditionally; it does not use byte-offset upload resume. `VaultDownloadWorker` stages encrypted offline files and uses range continuation only when a matching strong ETag protects the checkpoint. Its network-complete state is `AWAITING_UNLOCK`; the session authenticates the content before an offline manifest and `SUCCEEDED` state are published. Scanner uploads, text saves and recursive encrypted offline pinning remain foreground operations.

`BoundaryTransfer` handles ordinary/encrypted and cross-encrypted copies using bounded plaintext pipes and an encrypted, process-keyed traversal manifest. Move is copy, full verification, snapshot revalidation, then conditional source cleanup; partial results require inspection rather than automatic destructive retry. Account identity and live unlock leases govern the source and destination browser. These operations remain foreground and cancel when the protected route closes.

Errors exposed to users use typed descriptions and fixed diagnostic codes. Backup scan failures persist a safe code and timestamp tied to the saved configuration. Raw server bodies, credentials and exception strings are not diagnostics. See [TESTING.md](TESTING.md) for acceptance gates and verified results.

## 11. Feature phases

### Phase 0 — complete after this document is written

- Architecture and module plan.
- Mobile-web design-system extraction.
- Legacy endpoint and persistence inventory.
- Security, SAF, settings, and background-work decisions.

### Phase 1 — repository initialization and foundation

- Kotlin DSL, version catalog, convention plugins, `applicationId = "eu.opencloud.android.next"`.
- Single-activity Compose application and base core modules.
- OpenCloud light theme and foundational component previews.
- No auth/network/file implementation beyond static placeholders.
- Baseline lint, unit tests, screenshot tests, and CI configuration.

### Phase 2 — authentication and networking

- Discovery, WebFinger, Basic/OIDC PKCE authentication, token management, capabilities, and custom-TLS trust UI.

### Phase 3 — core file browsing

- Spaces, Room-backed resource browsing, file CRUD, selection/actions, mobile-web visual parity, and initial DocumentsProvider metadata integration.

### Phase 4 — sync and uploads

- Full WorkManager transfer pipeline, TUS, background sync, available-offline, folder/camera backup, DocumentsProvider content delivery, conflicts, retries, and cleanup.

## 12. Acceptance gates and open risks

### Phase 1 acceptance gate

- `eu.opencloud.android.next` installs side-by-side with the legacy application.
- No Java production sources and no XML layouts.
- Build/test/lint succeed from a clean checkout.
- OpenCloud light palette is implemented without dynamic color.
- Shell, drawer, breadcrumb, content surface, FAB, and action sheet have previews/screenshots.
- Reference repositories remain unchanged.

### Risks to resolve before implementation reaches the affected phase

1. **Dark tokens:** capture authoritative runtime dark theme values before claiming dark parity.
2. **Font licensing:** verify Inter bundle/license and any OpenCloud logo/icon asset redistribution rights before adding assets.
3. **Custom TLS policy:** align user approval, MDM policy, certificate rotation, and security review before Phase 2 release readiness.
4. **Dynamic app-provider endpoints:** validate per-server capability semantics and authorization requirements with fixtures; never hardcode them.
5. **DocumentsProvider behavior:** validate remote/open semantics across supported Android versions and DocumentsUI clients before promising online-only provider reads.
6. **Protocol fixtures:** create server/MockWebServer fixtures for OCS, Graph, DAV XML, redirects, TUS, OIDC, and WebFinger before client implementation.
7. **Database evolution:** export Room schemas and test every future migration from version 1; do not inherit legacy schema versions.

## 13. Implementation constraints for subsequent phases

- Rewrite business logic into suspendable use cases/repositories; do not copy legacy operation classes.
- Keep all blocking I/O off the main thread and all database writes transactional.
- Treat server capability data as required input for conditional UI/actions.
- Do not log secrets or private paths/links.
- Validate persisted state at all system boundaries: settings, intents, `Uri`s, DocumentsProvider calls, worker input, deep links, and network payloads.
- Add tests alongside each new protocol/state-machine branch, including process-death and corrupted-persistence recovery tests.

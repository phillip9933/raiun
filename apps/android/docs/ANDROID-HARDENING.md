# Android hardening and decomposition follow-up

Android 1.4.0 includes the destination-picker, database, backup-editor and vault-preview decomposition described here, along with the typed-transfer and incoming-share caller checks from issues [#52](https://github.com/phillip9933/raiun/issues/52) and [#55](https://github.com/phillip9933/raiun/issues/55). This page records implementation boundaries; current executed checks and device requirements belong in [Testing](TESTING.md). Credential records and server document apps have their own [storage](CREDENTIAL-STORAGE.md) and [server-app](SERVER-DOCUMENT-APPS.md) guides.

[Release shrinking](RELEASE-SHRINKING.md) describes [#53](https://github.com/phillip9933/raiun/issues/53) and its acceptance boundaries. The source decomposition here does not itself establish compatibility.

## Destination-picker ownership — #51

[VaultDestinationPicker](../app/src/main/kotlin/eu/opencloud/android/next/ui/VaultDestinationPicker.kt) owns destination jobs, directory snapshots, source presentation bindings and page bookmarks within `app`. `VaultViewModel` retains route/account/lock generations, session and key lifetime, source revalidation and error handling. Requests capture the session, account, route generation, lock revision, visibility and source-folder exclusion before suspension. A result must still match its picker revision and route owner before publication.

Clearing the picker cancels its job, closes its adopted snapshot and drops captured source metadata before the ViewModel closes the session. An unadopted late snapshot is closed when it returns. A late page cannot publish into or close a replacement picker, or change its bookmarks. Copy/move actions revalidate the source through the live session; a captured presentation entry does not restore an old action lease.

This is a bounded extraction within the host module. A new `feature:vault` module would require a separate design for the shared route, key, offline-completion and directory-lease boundaries; file length alone does not justify moving them. The broader decomposition issue remains incremental, including future evaluation of cohesive file-browser surfaces and Android adapters.

## Additional decomposition in Android 1.4.0 — #51

Android 1.4.0 moves account, space and resource records/DAOs, transfer records/DAO, backup records/DAO and share records/DAO into focused same-package persistence files. `FileBrowserDatabase` retains entity/converter registration, migrations and database construction. The Room version remains 28; these declaration moves do not introduce a schema change.

`FolderBackupSettings.kt` owns the backup settings dialog/content and its exclusion/date editors. `BackupDraft` retains its package and public API. The browser keeps its unrelated layout, destination, shortcut and paging helpers.

`VaultPreviewContent` owns preview and thumbnail loading, publication and plaintext cleanup. `VaultViewModel` remains responsible for route, account, session and generation ownership, admission, and revocation/error policy. A route change rejects late publications; clearing the preview wipes memory content and closes its encrypted backing.

These extractions do not change Room version or migration behavior. Executed release checks are recorded separately in [Testing](TESTING.md).

## Typed transfer semantics — #52

[TransferState](../core/model/src/main/kotlin/eu/opencloud/android/next/core/model/TransferState.kt) in `core:model` defines shared state semantics. The database exposes a compatibility type alias and parses `TransferEntity.state` through `typedState`. Room remains at schema 28; `transfers.state` stays `TEXT` with the same exact, case-sensitive values. No migration or automatic rewrite of existing rows is introduced.

| Persisted values | Meaning |
| --- | --- |
| `QUEUED`, `RUNNING`, `RETRY` | Runnable durable intents, including interrupted work recovered at startup |
| `AWAITING_UNLOCK` | Active ciphertext awaiting authentication; transport recovery must not run it or publish plaintext |
| `FAILED`, `CONFLICT` | Needs attention; a conflict requires its explicit resolution path |
| `SUCCEEDED`, `CANCELLED` | Retained history; only success authorizes download completion |

Unrecognized values map to the read-only `UNKNOWN` sentinel. Its typed serializer refuses writes. The original raw row and payload are retained, shown under attention with a safe localized explanation, and excluded from automatic scheduling, retry and completion. Ordinary and single-vault rows can be explicitly cancelled. An inconsistent vault-group parent remains subject to the existing group/parent identity guards; there is no cancellation bypass or automatic repair.

Typed checks are used by DAO admission, scheduling, workers, recovery and transfer filters. SQL predicates still enforce worker identity, runnable state and upload destination ordering. Retry compares the full expected row before renewing queue admission; progress and completion cannot overwrite cancellation or a replacement worker. A claim now checks the active account inside the same transaction before changing the row, refusing pending-removal accounts. Conflict, awaiting-unlock and encrypted-publication guards remain in place, with no change to byte verification or remote replay policy.

Ordinary resource preparation and Android document-provider download waiting require persisted `SUCCEEDED` before inspecting or opening cache data. A failed, cancelled, conflicting, awaiting-unlock, missing or unrecognized transfer cannot make an existing cache entry count as its successful download. Resource identity, access, app-lock and cancellation checks still apply.

## Incoming-share caller proof — #55

On API 35+, `IncomingShareActivity` checks each unique content URI from `ACTION_SEND`/`ACTION_SEND_MULTIPLE` streams and ClipData with `ComponentCaller.checkContentUriPermission(READ)`. One denied, non-content or uncheckable URI refuses the batch before the upload route. Receiver readability, an existing persisted grant, grant flags and referrer extras cannot substitute for this caller check.

The Android API checks the launch-time permission snapshot for URIs actually carried by the launch intent; it is not a live permission or source-ownership guarantee. Android also requires the receiver to have URI access. See the official [ComponentCaller contract](https://developer.android.com/reference/android/app/ComponentCaller#checkContentUriPermission(android.net.Uri,int)).

Recreation checks the original launch again instead of restoring an approval boolean. A forced `onNewIntent` delivery is visibly rejected, preserving the original intent, caller and batch. The Activity does not rebind them with `setIntent`; see [Activity.getCaller](https://developer.android.com/reference/android/app/Activity#getCaller()). Existing private-provider restrictions, user upload confirmation, staging limits and cancellation remain authoritative.

API 26–34 retain the existing incoming-share flow and cannot establish this general `startActivity` caller proof. A readable source on those versions must not be described as verified sender provenance. The newer check does not identify the original human sender or establish permission across every chooser/profile forwarding chain.

## Validation boundaries

Regression coverage targets late destination results, snapshot/session close ordering, state/SQL correspondence, database reopen and startup scheduling, cancellation and worker replacement, account removal, failure-to-cache boundaries and caller-scoped URI admission. Coverage definitions alone do not establish passing execution; consult [Testing](TESTING.md) for fresh results.

Reopen and startup fixtures are not a full process-kill acceptance matrix. Scoped framework tests are not exhaustive chooser, managed-profile, OEM or physical-device acceptance. Signing, publication and exact release validation are recorded separately in [Testing](TESTING.md).

## Android 1.4.0 connection and incoming-share behavior

The Android 1.4.0/code 55 candidate preserves Room 28, credential aliases, provider authorities and the rclone-compatible encryption format. Existing short encryption passwords remain valid for unlocking/import; new encrypted folder and Space creation requires at least 12 Unicode code points, matching confirmation and passphrase guidance. Length is not a guarantee of password strength.

TLS policy uses the same endpoint parser as requests, including supported underscore hostnames. Malformed configured URLs are rejected rather than bypassing pins, client certificates or Wi-Fi routing. Only the explicit empty authentication bootstrap remains unconfigured; OIDC issuer identity rules are unchanged. Unreachable pin enrollment APIs are removed while existing stored pins remain enforced.

Ordinary HTTP clients share account-free connection and executor resources, with separate cancellation dispatchers. Scoped certificate and Wi-Fi transports retain dedicated connection pools, exact origin checks and redirect protections. Request authorization remains per request; no credential, cookie jar or cache is added to the shared base.

Incoming-share confirmation reviews bounded file-name/provider metadata before staging content. Metadata is untrusted, may change and does not identify the original sender. Unavailable metadata remains unknown; unresponsive providers cannot grow review workers or block the UI deadline. Content-only and private-provider exclusions, app lock, API 35 caller checks and destination admission remain unchanged. Older Android versions still cannot establish general original-sender provenance.

Source decomposition separates repository, live session, models, cipher adapter and shared helpers, plus Android route adapters/contracts. The ViewModel remains the single owner of route, account, session and key state. Broad exception boundaries and their cancellation behavior are retained.

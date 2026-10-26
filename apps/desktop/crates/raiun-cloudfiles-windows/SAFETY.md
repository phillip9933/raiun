# Cloud Files adapter safety boundary

All Cloud Files API declarations, Win32 ownership checks, and unsafe calls are
confined to `src/native.rs`. The safe surface can inspect and pin an explicitly
selected ordinary empty directory, but it does not register it as a provider
root. The only currently callable registration flow creates a randomly named
temporary directory, registers it, connects a fixed synthetic provider, creates
two directory and two file placeholders, enumerates their metadata, and
hydrates deterministic in-memory byte ranges. The `PlaceholderBackend` trait
is an identity-only seam; no production backend is connected.

There is also crate-private configured-root connection scaffolding for the
next integration step. It consumes a `ConfiguredRootLease` rather than a path,
rechecks the pinned root's volume/file identity before registration and
connection, and retains the no-follow component handles for the connection's
entire lifetime. If connection fails after registration, it removes callback
state and attempts to unregister before returning; if rollback cannot be
verified, it deliberately retains the root lease instead of cleaning by path.
Shutdown keeps callback state installed through `CfDisconnectSyncRoot`, then
removes the registry entry, cancels and drains admitted work, rechecks the root
identity, and unregisters. It never deletes the configured directory. No agent
or UI path calls this scaffold, and it is not exposed as a public arbitrary-path
registration function. It is not production provider support.


The safe `OpenCloudPlaceholderBackend` is now a transport adapter for synthetic
tests and future integration work only. The trusted caller must provide the
already-authenticated `OpenCloudClient` and immutable profile/account/origin
scope; construction rejects a client whose canonical server origin differs.
For each registered file it performs a fresh ordinary DAV stat and stores the
logical Space/path, stable remote ID, ETag, and size behind a generated opaque
identity. Callback bytes contain no path or credential. Each range read is
bounded to 64 KiB, requests `Range` plus `If-Match`, requires an exact 206,
Content-Range, Content-Length, and ETag, then re-stats and rechecks identity,
ETag, and size before copying bytes to the callback buffer. Redirects remain
disabled by `OpenCloudClient`; same-origin DAV checks, logical path validation,
and encrypted Space/vault ancestor rejection apply to both metadata and range
reads. Account/profile separation depends on the trusted agent supplying the
matching current session client and scope; this adapter is not itself an
authentication authority.

This transport adapter is not connected to native Cloud Files callbacks, does
not enumerate a production namespace, does not create placeholders, and does
not make the application a sync provider. `provider_supported` and mounted
status must remain false until a separately reviewed agent integration binds
real account lifecycle and safely publishes the provider.

The configured-root lease gate was also run in the isolated Windows VM from
the filtered composite-namespace snapshot (SHA-256
`bc801c383fa6c2ca34e5c86fc74b8466588cf2c9f3d73a8686452438860558df`). The
SDK layout check passed; all four ignored synthetic Cloud Files tests passed,
including an empty configured-root registration/connect/disconnect/drain/
unregister round trip that confirmed the same root identity remained and the
directory was preserved. Adapter tests (27), OpenCloud range tests (20), and
strict Clippy passed. This still did not exercise an agent-mounted root, account
integration, ordinary-user Explorer behavior, or production write handling.

The synthetic fixture's two directory placeholders are empty and are created
with `CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION`. This avoids
claiming directory-population callback support: the adapter registers FETCH_DATA
and CANCEL_FETCH_DATA only. Its root uses the documented FULL population policy;
connected identity validation accepts only the required PLACEHOLDER and SYNC_ROOT
bits plus documented state bits, with PARTIALLY_ON_DISK requiring PARTIAL. Real
directory enumeration/population is not implemented by this fixture.

The test root is created with a protected DACL granting full access only to the
current token's user SID. A directory handle is held with `FILE_SHARE_DELETE`
omitted, preventing rename/replacement while Cloud Files path-based calls are
active. The handle's volume serial and file index are checked against a fresh
no-follow path handle before path operations. Reparse points and unexpected
children are rejected. Child volume/file IDs are captured when the fixture is
created and checked on every later verification. Disconnect can materialize
empty directory placeholders as ordinary directories; teardown accepts that
transition only for a directory whose captured file ID still matches, and
only after successful callback disconnect. Reads and deletion use an
opened child handle whose identity is checked before data access or a
handle-based delete disposition; root removal is likewise handle-based. Cleanup
disconnects first, confirms the exact fixture entries, unregisters, then
removes only those verified handles. If
disconnect, identity verification, or unregister fails, code does not proceed
to path deletion; failed callback disconnects intentionally retain the
callback-state registry entry so the OS cannot call freed state.

The file verifier accepts either the expected cloud placeholder before a read,
a fully hydrated ordinary file, or the Cloud Files fully hydrated in-sync
placeholder state observed after a read. In every case, the open handle's
volume/file identity and exact synthetic payload are checked before cleanup.

The callback context is an opaque pointer value used only as a key in a locked
registry. Callback entry clones the `Arc` and increments the active count while
holding the registry lock. The registry entry remains installed through
`CfDisconnectSyncRoot`. Microsoft documents that callbacks may occur during
disconnect but none are delivered after it returns. On successful return, the
entry is removed under the same lock and admitted callbacks are drained before
the owned state is released. A failed disconnect keeps both state and root
alive. The callback resolves only bounded opaque identities through the
backend trait; it never consults the callback's normalized path. It caps each
read buffer at 64 KiB, each request at 16 MiB, and concurrent backend fetches
at eight. Range checks reject negative, overflowing, misaligned, oversized,
and out-of-file requests; EOF requests are clamped to the exact file size. A
request-scoped cancellation token is registered by the native request key and
checked before and after each backend range read. Cancel callbacks are
range-aware: a partial cancellation does not abort a still-needed tail, while
a cancellation covering the full remaining range stops backend work. The
synthetic backend does no filesystem content lookup, network access, account
work, or provider work.

The hand-written ABI structs have compile-time x64 size and important field
offset assertions. The key wrappers follow `cfapi.h`: `CF_CONNECTION_KEY` is
one `LONGLONG`, and `CF_TRANSFER_KEY` and `CF_REQUEST_KEY` are each one
`LARGE_INTEGER` (8 bytes apiece). The callback and operation layouts are sized
with those 8-byte keys. These Rust assertions are not generated from, or
compiled alongside, the Windows SDK headers; compare them with the guest SDK
and run the isolated Windows VM tests after any ABI or callback change. An
independent review of `native.rs` remains a merge gate. A production provider
should replace these declarations with generated bindings and separate its
callback/runtime lifecycle from this fixture.

For `CF_CALLBACK_TYPE_FETCH_DATA`, `ParamSize` accepts only two ABI-derived
sizes: the documented `sizeof(FetchData) + sizeof(ULONG)` value (60 bytes with
the x64 SDK's 56-byte arm), or the fully aligned arm extent (64 bytes). The
isolated Windows 11 runtime trace reported 64 and completed a successful
transfer. The callback records the actual value, and the synthetic VM test
requires callback invocations, an observed size of 60 or 64, and the expected
total transferred byte count. Every other size fails closed. Keep this distinct
from the 64-byte `sizeof(CF_CALLBACK_PARAMETERS)` and reconfirm both the SDK
formula and runtime behavior if callback validation changes.

The SDK-layout harness at `sdk_layout_check.cpp` uses compile-time assertions
against the installed Windows SDK's own `cfapi.h`. Compile it from an x64
Developer Command Prompt with `cl /nologo /std:c++17 /c sdk_layout_check.cpp`;
the file has no runtime behavior. A successful SDK-header compile is required
before transferring a changed ABI snapshot to the Windows VM.

The test-only root is not a production sync root and the adapter never reports
Raiun drive support or mounted status. These routines exist to test the Windows
Cloud Files API boundary in a disposable VM under its current test account;
they do not validate standard-user UI behavior or production provider
readiness.

The callback table also includes `NOTIFY_FILE_CLOSE_COMPLETION`. The callback
is advisory and does not block the application. It accepts the callback's
documented volume-device path or the observed single-leading-slash
volume-rooted path; the latter is mapped only through that callback's
`VolumeDosName`. It requires a descendant of the retained root,
opens the entry without following reparse points or allowing delete sharing,
and checks the volume serial, callback file ID, root file ID, Cloud Files tag,
and placeholder state before querying `CF_PLACEHOLDER_RANGE_INFO_MODIFIED`.
The range query uses a fixed 64-entry buffer; API errors, oversized results,
deletion notifications, or any identity mismatch are recorded as unresolved
rather than treated as clean. For a modified, fully materialized regular file
within the 16 MiB bound, the callback also asks the exact OpenCloud identity
binding for an account/root lease, snapshots the bytes through a normal data
handle while a no-follow entry handle pins the name, rechecks file identity,
size, write time, and modified ranges, then appends a current-user-DPAPI-
protected local record. The protected metadata includes account/profile,
server origin, Space/root/resource IDs, the local file ID, virtual path, and
the observed remote size/ETag baseline. Missing or weak ETags are retained as
local evidence but are not sufficient for future conditional upload. An
incomplete or over-limit file, failed identity check, expired binding, or
journal failure remains unresolved; original placeholder bytes and registration
are retained. A journaled close is still considered dirty and explicit
unregister remains refused. Ordinary disconnect preserves the registration
and bytes. This is local recovery evidence only, not upload/sync support.
Every append first authenticates the existing journal and enforces a 10,000
record and 512 MiB total-content bound. An interrupted staging record blocks
new appends rather than being silently discarded. Appends from close callbacks
are serialized within the agent process; the agent remains the sole writer for
the selected profile.
Cloud Files file attributes are not a security boundary and this adapter does
not yet re-open records into a user-facing recovery flow, reconcile remote
changes, conditionally upload, or resolve conflicts.

Configured-root reconnect and explicit unregister also perform a bounded
revalidation scan, because close-notification counters are process-local. The
scan pins the root and each child with no-follow handles, checks exact volume
and file identities, queries the Cloud Files modified-range information for
regular file placeholders, and caps traversal at 10,000 entries and 64 levels.
Modified ranges block unregister. Materialized ordinary files or directories,
Cloud placeholder directories whose children cannot be safely enumerated,
unknown reparse points, range-query failures, and any incomplete or over-limit
scan are treated as unresolved. No absent in-memory record means “clean.” This
may retain registrations for clean hydrated content; it prefers recoverability
until the durable edit journal is exposed through an explicit recovery flow and
a remote clean baseline is verified. The scan does not upload, restore, or
delete bytes. Journaled records are not yet consulted by this reconnect scan,
so absence of a journal lookup never clears the conservative blocker.

The filtered Windows 11 snapshot `88ed6a7a6006ab1cfed6cf9543ebbaa6f8a86cc17af7d3873c899882eeacd052`
passed the SDK layout check, 29 package tests, all five ignored native tests,
and strict Clippy. Its restart test edits a synthetic placeholder in a child
process, disconnects and releases the original provider handles, reconnects
the same OS registration in another child process, and verifies that the
filesystem scan rediscovers unresolved state, explicit unregister is refused,
and the edited bytes remain. This exercises a synthetic same-user reconnect;
it does not prove Explorer write patterns, ordinary-user app integration,
upload/recovery, or production-provider readiness.

The isolated Windows 11 synthetic gate for filtered source archive
`e570329dd230b06477c114a8ea7274622d975d2920314c7173441c9d11975a7a` passed the
SDK layout compile, package tests, all five ignored native tests, and strict
Clippy. `modified_placeholder_close_blocks_unregister_and_retains_bytes`
verified a user-mode edit triggers close notification, remains present after
ordinary disconnect, and prevents explicit unregister. This proves only the
synthetic same-user fixture lifecycle; it is not Explorer save-pattern,
account integration, upload, or production-provider acceptance.

The remaining writable milestone must add a user-facing recovery view for these
journal records, then conditional remote commit/readback with explicit conflict
or uncertain states. It must exercise Explorer save/replace/rename patterns
before any production root is enabled. No production root is connected by the
application.

Filtered Windows 11 snapshot `e8ac9b752855b7156a7ddbf42dcc1127661f394bd00bc86317338f0da71d4dc1`
passed the SDK layout check, package tests, all six ignored native tests, and
strict Clippy. The OpenCloud-backed close test now starts a separate recovery
process after disconnect, reopens the exact protected journal, authenticates
the account/root scope, and verifies the edited bytes and captured baseline.
This VM test ran as `SYSTEM`; it proves cross-process current-user DPAPI
recovery for that Windows identity, not ordinary interactive-user Explorer
behavior or production provider readiness.

The API behavior and layouts are based on Microsoft's documentation for
[CfRegisterSyncRoot](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfregistersyncroot),
[CfUnregisterSyncRoot](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfunregistersyncroot),
[CfConnectSyncRoot](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfconnectsyncroot),
[CfDisconnectSyncRoot](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfdisconnectsyncroot),
[CF_CALLBACK_REGISTRATION](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/ns-cfapi-cf_callback_registration),
[CF_CALLBACK_INFO](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/ns-cfapi-cf_callback_info),
[CF_CALLBACK_PARAMETERS](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/ns-cfapi-cf_callback_parameters),
[CF_OPERATION_INFO](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/ns-cfapi-cf_operation_info),
[CF_OPERATION_PARAMETERS](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/ns-cfapi-cf_operation_parameters),
[CfCreatePlaceholders](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfcreateplaceholders),
[CF_PLACEHOLDER_CREATE_INFO](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/ns-cfapi-cf_placeholder_create_info),
[CfExecute](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfexecute),
[CfGetPlatformInfo](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfgetplatforminfo), and the
[sync policy documentation](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/ns-cfapi-cf_sync_policies).


The verified-edit completion boundary uses the existing account publication gate
and token-generation permit through both durable catalog refresh and
`CfSetInSyncState`. Its prepared capability can refresh only an existing opaque
identity's ETag/size, retaining the account/root/path/resource tuple. A busy
binding-state mutex fails without waiting while that permit is held.

Before completion, the native path pins the no-follow registered root, ancestors
and exact file, compares its opaque Cloud Files identity, and opens the ordinary
stream excluding write/delete sharing. It reads a nonzero file USN before a
fresh full-content hash against the protected snapshot, then requires unchanged
USN and metadata. This fresh local revalidation permits a reopened handle after
upload; merely sampling a new USN without rehashing would be insufficient.
`FSCTL_READ_FILE_USN_DATA` uses a bounded aligned output buffer and accepts only
well-sized V2 records with the exact 64-bit file ID. Unsupported/zero USNs and V3
identities fail closed. The two matching positive USN reads are consistency
observations. Content exclusion is enforced by the combined publication and
exclusive-reference boundary described below; the OS call passes a null optional USN pointer
without a USN comparison. This is the sole design path, never a fallback
or retry after comparison failure.
No dehydration, truncation, path-based deletion or journal retirement occurs.
If post-completion validation fails, recovery remains even if the OS has already
accepted the in-sync state. The fresh handoff carries the actual pinned local
location independently of the remote path. Successful native postchecks append
an exact-record protected local-acknowledgement event under the same publication
permit; encrypted bodies remain retained. Production activation stays disabled.

Windows journal scans and atomic staged-file publication share an in-process
mutex. Scanners retain no-delete read handles, while publication needs DELETE
access for its pinned rename; those phases must not overlap in the agent.
Writers acquire append/event locks before this mutex, and scanners never acquire
those writer locks. Staging writes remain outside it. This adds no delete sharing
and makes no cross-process serialization claim; external contention still fails
closed and preserves recovery.

These contracts follow [CfSetInSyncState](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfsetinsyncstate)
and [FSCTL_READ_FILE_USN_DATA](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_read_file_usn_data).
Source review and compilation do not establish runtime Cloud Files acceptance.


The completion candidate opens the pinned entry with
`CfOpenFileWithOplock(EXCLUSIVE | WRITE_ACCESS)`. Its opaque owner is closed only
with `CfCloseHandle`. A successful `CfReferenceProtectedHandle` retains the
borrowed Win32 handle through identity checks, full hashing, USN checks, native
completion and durable acknowledgement; release precedes closing the owner.
The borrowed handle is never converted to an owning `File` or independently
closed. No foreground/share-all or ordinary-handle fallback is used.

This handle is asynchronous. Each read/USN request has its own initialized x64
`OVERLAPPED` and manual-reset event. The protected reference, structure, event
and buffers remain live until `GetOverlappedResult` reports definitive completion.
Pending submission is distinguished from failure. Reads must return the full
bounded expected length; short reads and invalid USN output fail closed. Disk
completion waits are blocking, not bounded timeouts or cancellation claims.
Existing path/file identity, full-hash, two positive USN observations and
protected journal rules remain. This is an unaccepted native candidate, not evidence that
ordinary handles caused the observed in-sync refusal.

See [protected open](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfopenfilewithoplock),
[borrowed handle](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfgetwin32handlefromprotectedhandle),
and [overlapped completion](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getoverlappedresult).

The backend's existing publication/token permit is acquired **before** the
protected open/reference and retained through fresh residency checks, full hash,
OS marking, identity/root postchecks and durable acknowledgement. The same
backend permit surrounds every payload-bearing `CfExecute`; no separate gate or
new actor is introduced. Acquiring the reference before waiting for this permit
would invert the order against an already publishing callback and is forbidden.
Partial residency is refused before reading, preventing a hydration callback
from waiting on the permit/state held by its own read.

Successful share-none open excludes ordinary write handles. RH grant excludes
pre-existing writable mappings, and the retained reference preserves the borrowed
handle across the operation. RH/reference alone is not sufficient: provider
payload writes are independently excluded by the publication permit. Together
these guards retain the exact verified local content through OS marking and
journal acknowledgement. The optional OS USN output is not acknowledgement authority. The native
82ec check observed S_OK with a zero output for zero input, so the call now
passes NULL explicitly and does not misclassify absent output as root replacement.
Native writer-exclusion and normal save/lifecycle acceptance remain required;
source review does not establish those results.

## Configured vault callbacks and cleanup

Configured roots request `CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH` because fetch
admission needs the callback path. Microsoft only promises that metadata with
the [connection flag](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/ne-cfapi-cf_connect_flags).
Bounded decoding, no-follow path pins, exact root/file/opaque identity and
publication fences still apply. The original isolated fixture now reads all
65,537 decrypted bytes with the expected hash (fetch stage 14); this alone does
not establish Lock or production vault support.

Close processing proves native path/file custody and queries modified ranges
before requesting an account-bound edit lease. Clean read-only closes need no
write authority. A modified file still requires the lease before any recovery
read/publication; refusal records modified and unverifiable state. Native clean
close observations passed. Counters are never reset to admit cleanup.

The sole cleanup caller revokes and drains the exact vault route before deriving
its owned opaque identities. Cleanup requires a complete hydration inventory,
exact registered physical root, pinned no-follow ancestors, exact file/opaque
identity, clean in-sync/unpinned state, zero native modified ranges and no
unresolved recovery. One EXCLUSIVE protected read handle and its retained
reference cover admission through the update and postproof. Read-only attributes
and permissions are never cleared or changed. Ordinary edit completion retains
its separate WRITE_ACCESS handle mode.

### Fixed protected-handle byte eviction

Earlier candidates passed a nonzero `UpdateUsn` to `CfUpdatePlaceholder`. Native
runs repeatedly refused with `0x80070179`, including with one continuous
protected handle and a positive fresh journal CLOSE record. After refusal, the
queried USN differed while identity, snapshot and modified ranges stayed stable.
These observations do not prove an OS bug or authorize a retry/rebase.

The current fixed method uses the exclusive handle as its payload writer fence
and passes NULL `UpdateUsn` on its first and only update. This **does not retain
the kernel atomic metadata-USN comparison**. A journal baseline remains positive
and freshly checked immediately before the call; that is a precheck, not a CAS.
The argument for safe byte eviction is:

- [CfOpenFileWithOplock EXCLUSIVE](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfopenfilewithoplock)
  obtains share-none access and an RH oplock. Existing data-writer handles and
  new data-write opens conflict. A successful retained protected-handle
  [reference](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfreferenceprotectedhandle)
  prevents automatic closure/acknowledgement during the proof. Generic RH alone
  is not this guarantee.
- Existing writable user mappings prevent RH grant under Microsoft's
  [oplock grant rules](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/granting-oplocks),
  even after their original file handle closes. No native mapping acceptance
  is claimed without a mapping test.
- The route is revoked and publication permits drained first. No deferred
  provider payload can republish while the same handle excludes local writers.
- Native dirty/recovery checks remain mandatory. The update supplies NULL
  filesystem metadata and identity, one whole-file range and only
  VERIFY_IN_SYNC. Windows still checks update authorization and in-sync state.
  No mark-clean, force, unpin, policy override, permission change or second
  attempt follows refusal.
- Admission requires READONLY. After the update, exact identity, size, last-write
  time, READONLY/directory/reparse attributes, a documented Cloud Files tag,
  root/opaque identity,
  in-sync state and zero modified ranges are rechecked. Success additionally
  requires an empty bounded ONDISK range response. Rows stay in the inventory
  on both success and failure.

Metadata-only handles may change attributes/USN without payload writes; this
method does not reject all such changes atomically. NULL filesystem metadata
leaves those fields intact. The stated custody attributes and last-write time
must match at postproof; mismatch is incomplete cleanup. Never describe this
as full atomic metadata continuity or as a successful lock after refusal.

The isolated stage-diagnostic run observed a successful update with the same
physical identity, size, last-write time and custody attributes, while the tag
changed from `CLOUD_6` (`0x9000601a`) to `CLOUD_4` (`0x9000401a`). The postcheck
therefore accepts only the exact sixteen `CLOUD` through `CLOUD_F` tags defined
in Microsoft's [SDK header](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h),
both before and after the update. It ignores only those four documented variant
bits (`0xF000`), not the broader historical mask used elsewhere in this crate.
This is driver-tag classification, not identity authority: physical/opaque/root
identity, unchanged custody metadata, clean ranges and empty ONDISK remain
mandatory. Unknown tags, symbolic links and unlisted low tag bits refuse. The
diagnostic run failed before ONDISK proof; it does not establish cleanup success.

The journal barrier uses
[FSCTL_WRITE_USN_CLOSE_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_write_usn_close_record)
on that same referenced handle. It requires exactly eight output bytes, a
positive USN and an exact-file matching
[fresh read](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_read_file_usn_data),
followed by snapshot/in-sync/identity/dirty checks. It appends a journal record;
it neither changes data nor marks clean, and is never used to rebase a refusal.

Acceptance of this method requires the original hydrated positive case, a real
writable-file writer-exclusion case using cleanup's read handle (including
writer success after release), and a real dirty-placeholder refusal retaining
exact local bytes. Injected counters are insufficient. Native results for this
fixed method now establish writer exclusion and clean-file ONDISK-empty cleanup;
real dirty-edit refusal remains pending. Production vault admission remains disabled. The
separate no-payload broker credential fixture cannot qualify plaintext cleanup.

## Protected vault publication history (local, disabled)

Vault adapters require an immutable custody view bound to the exact current
provider generation, full canonical account/vault scope and physical root. A
root-wide protected manifest records membership before a per-vault document may
be created. Missing historical child documents refuse; repeated membership is
never permission to initialize a missing child. Names and stable opaque IDs are
persisted as one full-byte CAS before the staged catalogue becomes visible.
The native data sink records the exact pinned root/file/opaque identity, length
and physical components before recording volatile hydration or calling native
TRANSFER_DATA. Any persistence uncertainty denies publication and retains
history. Protected metadata is separate from saved passwords; Forget does not
remove it.

The native sink calls its already-prepared fetch's captured view. It must not
resolve the route again while holding publication permits: recursive route
read-lock acquisition can deadlock behind a waiting writer. Storage callbacks
perform no backend, token, session or route-lock reentry.

The borrowed root context is constructed from real component leases and the
live authenticated composite backend. It re-pins before and after protected
initialization, distinguishing a proven empty new root from an existing checked
registration. Its registration domain includes the checked SyncRootIdentity and
expected authenticated composite identity; it does not claim native readback of
CF_SYNC_REGISTRATION.FileIdentity. The metadata view confers no unlock, route,
cleanup or historical-completeness authority. The historical native consumer
is now joined in source; its native acceptance remains pending and the
production vault capability remains disabled.

Source validation includes Windows GNU Agent and Cloud all-target checks and
strict lint, 19 portable model/service checks, and Linux workspace regression
checks. Portable service tests use an explicit Cloud type shim; native fixture
views use explicit memory-only bookkeeping. Neither substitutes for actual
protected broker publication or restart acceptance.

### Retained provider-publication lineage

The protected root manifest starts only with a pinned empty new root. Membership,
child document, catalogue and native hydration intent must be durably published
in that order before provider plaintext can be transferred. A legacy retained
root cannot initialize this lineage, missing children are never healed, and rows
are never removed. This establishes history for bytes this provider published;
it is not anti-rollback protection against same-user restoration of an older
valid protected document, or ownership of arbitrary user-created copies. Such
files are never adopted, removed or declared clean by this protocol.

For a retained connection, the native owner reads the entire protected manifest
and every child only after CfConnectSyncRoot has established the sole root
connection, while callbacks remain Initializing. A snapshot taken while another
provider could still publish would be insufficient. Before Ready, every retained
intent must pass the unchanged exact native root/file/opaque/path/length, dirty,
exclusive-reference and ONDISK-empty cleanup proof. Failure retains history and
uncertain data, blocks vault admission and leaves ordinary connectivity separate.
Only the resulting private native proof can satisfy the new connection's initial
unknown-history fence; it can never clear a sticky runtime-incomplete flag.

The generic unknown-namespace scan is retained for legacy/failing paths and
destructive unregister. Protected-lineage admission concerns provider-published
payload only and confers no permission to delete or unregister unknown objects.
No root-wide filesystem census, force-dehydrate, arbitrary-path cleanup or
public history-reset operation was added.

The focused reconnect fixture creates a new Agent, vault coordinator and native
connection for the same protected profile/root, checks that Forget remains in
effect and locked reads fail without downloads, then performs a fresh manual
read and Lock. It follows a successful prior Lock; it is not an OS-process crash
or a proof of cleanup after unclean shutdown with resident data. Those native
acceptance limits remain explicit.

### Fresh-close deferred upload notification

A retained existing vault edit remains protected historical evidence and native
incomplete data. Its optional deferred notification is a process-local locator,
not an upload/session/cleanup permit. Only acknowledged new indexed capture and
full protected readback may supply it; Existing/reopened captures and the
capture-only default supply None. The broker notification implementation owns
only a bounded nonblocking publisher and locator fields. Dropping it never sends;
refused publication queues nothing and never retries or alters dirty history.

The local capture adapter obtains the opaque dispatch stamp from the existing
binding identity while already inside the route/token/opaque-epoch publication
fences. The stamp contains only a Weak of that immutable binding marker: no
keys, epoch lease, body, Clone/serialization or historical reconstruction. An
optional consuming attachment on ExistingVaultUploadTarget is checked only by
the receiving current binding under its usual guards. The early target check
validates current binding and exact saved original metadata locally, with no
body reads, HTTP, coordinator or provider reentry. Actual upload retains its
existing full custody/account/root/original entry and cancellation validation.

Native capture keeps a deferred value private until durable retain and lexical
callback acknowledgement both succeed. Any callback error, missing retention,
or repeated capture failure drops the value without publication. The native
close outcome remains distinct from ordinary journaling. The existing sticky
modified-close observation is committed before record_placeholder_close returns
the optional value. Its exact per-file dirty observation is also registered
inside the original publication fence before the deferred value can escape;
explicit completion resolves only that observation as described below.
All path/read handles, DPAPI/custody locks, route/token/epoch guards and the
close-pool permit have then unwound. Only at the final outer close-callback
statement, after explicitly dropping callback lifetime accounting, is the
one-use try_publish invoked. No callback/native pointer or borrowed guard is
carried by the notification. The new call contains panic propagation at the FFI
boundary and does not retry a refused send.

Notifications do not reconstruct current authorization. The receiver must check
its expected provider generation, root/account and broker instance, the original
binding stamp and actual current token/opaque epoch before its durable one-attempt
upload. A retired/replaced/re-unlocked route cannot adopt an old notification.
Network work remains outside the provider command thread and every publication
lock. Public upload and writable publication remain disabled; verified remote
upload still leaves native dirty data and recovery history pending. No native
acknowledgement or cleanup authority follows from notification publication;
explicit fresh native completion is a separate operation described below.

### Fresh per-file vault completion (source only, disabled)

The alternative live upload API returns an owned, non-cloneable continuation of
that exact composite/route/client/opaque epoch and remote byte verification.
It retains the actual provider-generation atomic, cancellation token and original
operation deadline. Historical readback records cannot reconstruct it. HTTP
holds no route/token/session leases. Native completion runs on the existing
connection owner thread after its independent current binding checks.

Completion drains this vault's publication gate exclusively, holds token and
opaque session leases continuously, and invalidates every prior staged read,
prepared range and enumeration using a checked publication revision. The same
opaque ID is promoted from the original exact ID/path/ETag/length to the newly
verified version. Protected catalogue/hydration promotion occurs only in the
broker's fresh Prepared CAS callback, after native proof; runtime catalogue and
hydration length follow under the same fence. Storage callbacks must perform
only local protected persistence, never auth/backend/coordinator reentry.

The native method first uses existing EXCLUSIVE|WRITE_ACCESS
`ProtectedCompletionFile::open`, retains its reference and no-follow ancestor
chain, requires exact root/file/opaque identity, full resident bytes and a
matching bounded SHA-256, then verifies two positive stable USN reads. That same
handle excludes writers through Prepared, metadata/in-sync calls, full native
postproof and the exact NativeCompleted CAS/readback callback. Failure after a
possible Prepared transition revokes future route publication before releasing
the exclusive gate; pending bytes and references are retained.

Actual dirty fixture attributes were `0x420`; clean vault cleanup requires
READONLY. The metadata update restores only READONLY. It queries all four actual
positive timestamps using existing `GetFileInformationByHandleEx` FileBasicInfo
class/layout, supplies the actual edited length and same opaque identity to
existing `CfUpdatePlaceholder`, with VERIFY_IN_SYNC | MARK_IN_SYNC(3), no dehydration ranges and a
positive input USN CAS. The optional output USN is not completion authority.
There is no fallback, force, permission change, READONLY clearing or weaker open.
The fixed mark-first order described below establishes in-sync before the
coherent-current metadata update and exact final postproof.

The bounded input accepts only standard READONLY/HIDDEN/SYSTEM/ARCHIVE bits plus
intrinsic REPARSE. It supplies the current standard bits plus READONLY (for example, current `0x420` supplies
`0x21` and requires actual `0x421`). The baseline is sampled after Mark, not
assumed from the earlier dirty observation. The result must equal that current
baseline plus READONLY, with unchanged timestamps, size, physical/opaque identity,
cloud tag/state and body. Unknown flags refuse rather than being masked away.
Microsoft documents [CfUpdatePlaceholder metadata, flags and USN semantics](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfupdateplaceholder),
[CF_FS_METADATA](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/ns-cfapi-cf_fs_metadata),
[FileBasicInfo](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ne-minwinbase-file_info_by_handle_class),
and [ordinary settable attributes versus intrinsic reparse points](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileattributesw).
The CfUpdate-specific input mask is not explicitly documented there: preserving
the intrinsic REPARSE bit with standard-only input is an inference requiring the
exact isolated native case, not an OS behavior already qualified by source tests.

Per-file dirty observations are inserted inside the original capture publication
fence, before it is released. Completion holds the observation lock through
both durable callbacks and resolves only the exact sequence/file/body/components
it proved. Other files, unknown/overflow/poisoned history, ordinary edits and
unverifiable closes remain blocking. The global modified-close counter remains
monotonic telemetry. NativeCompleted history alone grants no cleanup authority;
Lock still requires fresh native cleanup proof and an absence of all unresolved
history. Public capability/readonly flags and the existing remote-only upload
API remain unchanged. Windows compilation and native acceptance are pending the
combined parent source; this section claims source behavior only.


### Referenced Win32 handle selected before vault completion

Only the new `complete_vault_upload` selects the borrowed Win32 handle upfront
for `CfUpdatePlaceholder`, `CfSetInSyncState` and its `CfGetPlaceholderInfo`
identity checks. The same `ProtectedCompletionFile` retains ownership of the
opaque handle and its successful reference throughout every native call, full
postproof and durable callback. The raw handle is never reopened or closed and
is not converted into an owning Rust file. This is one fixed operation path;
there is no retry after failure or switch to weaker sharing.

Microsoft's [CfGetWin32HandleFromProtectedHandle contract](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfgetwin32handlefromprotectedhandle)
permits handle-based Win32 APIs while the reference synchronizes use with oplock
break acknowledgement. [CfReferenceProtectedHandle](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfreferenceprotectedhandle)
explains that a retained reference prevents break acknowledgement. The individual
[update](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfupdateplaceholder),
[in-sync](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfsetinsyncstate)
and [information](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfgetplaceholderinfo)
APIs accept a file HANDLE; their documented access requirements remain enforced.

R8 observed ERROR_INVALID_HANDLE (`0x80070006`) from the opaque-handle metadata
call while referenced raw metadata/USN queries had succeeded. A pending oplock
break affecting an internal opaque re-reference is a plausible inference, not a
proven or documented cause of that failure. Raw handle validity does not prove
the replacement update will succeed. The exact native case remains required.
All root/body/USN/auth/epoch/storage/metadata predicates remain unchanged. Fixed
synthetic diagnostics expose only numerical attributes/tag/state and timestamp
equality after metadata and in-sync calls; they add no completion authority.
Existing ordinary completion and readonly cleanup retain their qualified paths.


### Mark-first completion with coherent current metadata

The new completion path uses one fixed fresh-attempt order: existing verified
remote/native body proof and Prepared publication, then existing in-sync marking,
then readonly metadata restoration with VERIFY_IN_SYNC | MARK_IN_SYNC and positive input USN.
[In-sync marking](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfsetinsyncstate)
is authorized by the exact fresh byte proof and continuously retained writer
fence, not by recovered evidence. Prepared/dirty history remains pending even if
Mark succeeds; any later failure poisons route publication and blocks cleanup.
There is no second Mark, retry after refusal, force, dehydration or weaker open.

Immediately after Mark, one completion-only
[FSCTL_WRITE_USN_CLOSE_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_write_usn_close_record)
forces a journal record containing current reasons on the same referenced raw
file. It requires exactly eight output bytes, a positive USN, and exact
file-ID-bound READ_FILE_USN_DATA readback. The returned USN itself starts the
metadata/body bracket; it is never refreshed after a failed update. The existing
cleanup helper and its callers remain unchanged. [READ_FILE_USN_DATA](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_read_file_usn_data)
returns the last USN written to the journal; it does not force current reasons.
This supplies a freshly journaled baseline without disabling the atomic metadata
USN comparison. R11 passed Mark/postproof and still returned ERROR377 from the
readonly update; stale journal baseline is a hypothesis, not an established
cause or a promise this barrier resolves the refusal. The failed case remains
preserved and a fresh native case must qualify actual behavior.

Using that same returned baseline, the method brackets the CURRENT native snapshot, all four
actual positive basic timestamps/known attributes and full body hash between two
equal positive USN reads. The first USN is sampled BEFORE current metadata; a
newer later USN cannot authorize stale attributes. Snapshot/basic identity and
full resident/in-sync state must be stable. Readonly input preserves that current
metadata, including any legitimate changes before its coherent snapshot, rather
than restoring pre-Mark timestamps or attributes. Root/file/opaque identity and
edited length are never rebased.

At this one successful Mark boundary, both tags must pass the existing exact
sixteen-tag cloud classifier. The tag must remain identical, except for the
single observed `IO_REPARSE_TAG_CLOUD_2` (`0x9000201a`) to
`IO_REPARSE_TAG_CLOUD_6` (`0x9000601a`) transition. Placeholder state must equal
its original value with IN_SYNC added. [Microsoft's tag definitions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4)
identify both as Cloud Files filter tags; they do not document this transition
or assign semantics to their differing bit. This narrow exception is empirical:
R10 observed successful Mark and this transition with unchanged attributes and
expected state, then refused the old tag-equality predicate before completion.
It grants no authority to other tag changes or reverse transitions. The current
post-Mark tag remains exact through the coherent USN bracket, metadata update,
full postproof and durable completion checks. All root/file/opaque/body and
continuous publication/token/epoch/reference fences remain required. R10's
failure is preserved; a fresh native case must qualify the new predicate.

The sole [metadata update](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfupdateplaceholder)
uses VERIFY_IN_SYNC | MARK_IN_SYNC(3) with that SAME positive bracketed USN input CAS, no data
ranges and NULL FileIdentity/0 with NO REMOVE_FILE_IDENTITY flag. Opaque identity
is independently checked before/after. VERIFY keeps its current in-sync
precondition; MARK requests in-sync on successful metadata update in that same
API operation. There is no second standalone in-sync call or optional USN
removal. Output USN is not completion authority. Fresh positive-USN/full-body,
root/file/opaque, exact current timestamps/only READONLY gain, in-sync/resident and
zero-modified-range postproof precedes the unchanged NativeCompleted CAS,
postchecks, exact dirty resolution and synthetic end-of-critical-span hook.

The fixed combined flags are selected upfront for this fresh attempt, never as
a retry or fallback after a refused update. The
[SDK flag definitions](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/cfapi.h)
provide combinable VERIFY(1) and MARK(2); the documented MARK behavior is to mark
the placeholder in-sync upon a successful metadata update. Neither VERIFY nor
the positive metadata-USN CAS is removed. R14's uncontended normal case still
returned ERROR377 after Mark, fresh journal baseline and postproof; no API
ordering or internal cause has been established, and this flag choice is not a
proven fix. Prior failed cases remain preserved. Exact native acceptance is
still required for the combined operation and all unchanged postproofs.

The NULL optional-USN alternative remains unapplied: a WRITE_ATTRIBUTES-only
race could overwrite newer metadata unnoticed. The coherent current snapshot
and atomic positive update USN comparison are retained here. R9's observed 377
refusal does not establish whether USN, dirty state or another internal condition
caused it. Mark-first establishes the documented in-sync precondition; only the
next fresh native case can qualify actual behavior. Ordinary completion and
readonly cleanup retain their existing paths unchanged.

### Explicit writable-byte completion (source only, disabled)

`complete_writable_vault_upload` chooses its private operation mode before any
native action. It shares the exact fresh live route/token/opaque epoch, physical
root/file/opaque identity, resident full-body/hash, positive stable USN, retained
exclusive reference, Prepared CAS and runtime catalogue/hydration promotion of
the readonly method. It performs the same single legitimate in-sync Mark and
coherent current post-Mark metadata/body/USN proof, then omits the ENTIRE
`CfUpdatePlaceholder`/filesystem-metadata overwrite. No metadata write loses an
atomic USN guard; there is no retry, NULL-USN fallback, attribute/timestamp write
or second standalone Mark. The readonly method still performs its original
positive-USN guarded readonly metadata update.

Writable final postproof requires the exact current post-Mark basic attributes
and all four timestamps, tag/state, physical/opaque identity, full body/hash,
zero modified ranges and the SAME positive USN. Those proofs and current fences
span NativeCompleted CAS/readback, final native checks and exact dirty-sequence
resolution. Any uncertainty preserves protected/native bytes and poisons future
route publication under the existing fence. Historical NativeCompleted is only
byte/in-sync history: it does not assert READONLY restoration or authorize
cleanup. Readonly cleanup predicates remain unchanged; a writable file may
therefore keep Lock/stop cleanup incomplete even after byte completion. Other
files, unknown history and the monotonic global telemetry remain untouched.
Normal writable publication, fresh-worker activation and public RPC stay
disabled. Exact native acceptance remains pending the combined source gates.

### Two-phase same-connection writable cache eviction (source only)

Writable completion reserves one of at most 1024 volatile connection receipts
before Prepared. Only successful NativeCompleted CAS/readback, exact final native
proof, dirty-sequence resolution and the test end hook permit publishing that
receipt under the same live fences/reference. It contains the existing Weak
binding marker and exact root/file/opaque/components/length/SHA, no keys/body or
serialized authority. A checked model generation prevents stale reserve or
cleanup commits. Reservations, capacity/poison failures and later invalidation
remain incomplete; no entry is silently evicted. Modified or uncertain closes
invalidate before deferred publication; global dirty/unknown sources never reset.

`begin_cleanup_retired_vault_route` first revokes/drains the exact retained route.
A pure Weak binding comparison works after retirement without auth/epoch lookup.
Only matching ready receipts enter the NEW writable primitive. Missing receipts
still face the unchanged readonly helper; invalid/foreign/reserved receipts
refuse. The old readonly per-file primitive is byte-identical. Current complete
hydration inventory, physical root/file/opaque/path, resident/in-sync full body
SHA, empty MODIFIED ranges and coherent positive CURRENT USN/basic/snapshot
brackets are independently checked. The receipt cannot substitute for those
current proofs or adopt a replacement connection/binding.

The new path uses the existing byte-only eviction shape: NULL metadata/identity,
one whole-file range, VERIFY_IN_SYNC only and NULL optional UpdateUsn. This is
not removal of a metadata CAS from a write: no metadata/identity overwrite,
READONLY restore, force, mark, unpin, permission change, cloud deletion or capture
retirement occurs. There is one operation, with no retry/rebase after refusal.
The same successful EXCLUSIVE RH reference and no-follow root/ancestor/file pins
span the complete body admission, eviction and native root/file/opaque/in-sync,
empty MODIFIED and bounded empty ONDISK postproof. Current last-write time and
custody attributes are preserved using the existing byte-eviction postconditions;
platform cache-state effects are not described as explicit attribute writes.

The opaque non-Send `VaultCleanupFence` retains EVERY writable reference/pin
through all route rows and the owner's coordinator key-clear step. Finish must
run on the same connected CallbackState/root, with the same retained binding,
unchanged exact inventory, current empty ranges/native proof and global clean
sources; only then does the model atomically confirm all tickets before releasing
references. Dropping/aborting a fence preserves EvictedUnconfirmed history and
releases native resources without success. A fresh begin for that same live
receipt may prove CURRENT empty state with no hydration or second eviction API;
invalidated/uncertain eviction cannot resume. Agent owner-thread hold management
supplies the separately reviewed finite 30-second/caller-loss boundary and aborts
holds before disconnect/drain; native handles never cross threads.

Confirmed tombstones remain for late activity. Status drops receipt locks before
sampling dirty/recovery/global sources, then rechecks current receipt state;
errors/late invalidation remain incomplete even after retired-route removal.
Lock order stays publication/token/epoch -> native exclusive -> dirty -> receipt
for completion/capture. Cleanup drains publication before native/receipt work;
no receipt lock is held while acquiring dirty/recovery/auth locks. This avoids
self-deadlock in the existing unresolved-data predicate. Final held-reference
proof after keys are locked is an operation linearization point, NOT permanent
write protection: new external writes after release are new activity and make
current cleanup status incomplete. No DACL or indefinite RH fence is added.

Synthetic helpers only query ONDISK through exact current root/path/file pins,
binding the fixed components to the complete native hydration inventory's file
ID while permitting a changed CURRENT size; they never hydrate. The separate
forget helper deletes only a matching volatile receipt so history-alone denial
can be tested. It grants no cleanup capability. Normal writable publication,
public upload RPC and automatic fresh-worker activation remain disabled. Source
checks do not qualify actual Windows cache eviction or the final key boundary.

### Scoped existing-file publication policy

The original vault backend constructor remains readonly. The explicit
`new_with_existing_file_saves` constructor captures immutable ORIGINAL worker
activity and provider-generation Arcs with a nonzero expected generation. It
checks that gate before construction I/O, inside the existing exact authenticated
publication fence and before returning. Preparation checks it before/after remote
listing and protected catalogue commit; begin-publish checks before and after the
existing route/token/opaque-epoch publication permit. There is no gate setter or
adoption of a replacement worker. `existing_file_saves_active` reports only this
current worker/generation mode plus route revocation; its caller still supplies
exact authenticated account/root/epoch readiness. It never reacquires auth locks.

A prepared vault enumeration owns eligible opaque IDs and the exact original
child tuple derived from its already-persisted catalogue/listing. Only existing
nondirectory files with admitted original metadata, bounded ID/path, a strong
quoted ETag and size at most 512 KiB are eligible. Invalid, unknown, oversized,
weak-baseline or forged child tuples remain readonly. Authenticated RemoteEntry
fields (including writable/encrypted presentation fields), original resource,
ETag/path and protected custody records are never rewritten to grant this mode.
The existing broker checks and full native capture/upload proof still apply.

PreparedEnumeration's per-file readonly default delegates to its old listing
policy. Thus existing ordinary adapters and readonly vault callers retain their
attributes. Both the successful directory callback and initial root population
ask the per-child policy while existing publication permits are held; directory
attributes remain unchanged. The old native bool wrapper remains for error and
compatibility callers. No filesystem metadata overwrite, post-publication
READONLY clearing or new unsafe/native syscall is introduced. Previously
published readonly stubs remain readonly.

This is bounded same-file in-place publication, not namespace write support.
Initial size eligibility cannot prevent an editor growing past the capture
bound; existing overflow/unknown/dirty handling must preserve native bytes and
refuse automatic upload/cleanup. Creation, replacement-by-rename, deletion and
folder operations gain no cloud mutation route. Their OS denial is not claimed;
existing encrypted exclusions and retained/unknown handling remain intact.
Capture, byte completion, two-phase key-clear cleanup and historical recovery
rules are unchanged. Repeated saves must use the freshly promoted protected and
runtime baseline, not a replayed capture. Full combined source/native normal
workflow and package acceptance remain separate from focused policy tests.

### Fresh clean-read provenance and confirmed-empty re-enrollment

Existing eligible writable files that were read but never edited now use a
separate, process-local Hydration origin. Durable hydration intent/inventory is
still recorded BEFORE transfer and is never treated as successful delivery. The
existing authenticated immutable private stage is re-read locally in zeroized
bounded chunks for a full SHA-256 only at sizes <=512 KiB, with exact file length,
private identity checks and final actual binding/revision admission. No extra
HTTP, Control-store API, private path/handle, key or retained plaintext escapes.

The default PreparedFetch hook returns None. Only the exact vault prepared
fetch, current original worker/generation gate and authenticated original entry
can create an opaque non-Clone/non-serializable capsule before first CfExecute.
It binds the original Weak read binding/revision and exact pinned native
root/file/opaque/components/length/full-stage SHA. Native reserves a bounded
Hydration-origin row before plaintext. Only execute_transfer S_OK AND successful
commit_transfer_result for the final slice of that requested callback range,
under the SAME backend/request/token/opaque-epoch permits, can acknowledge and
publish it. The posthook uses pure Weak/atomic checks and local memory only:
no hashing, filesystem/DPAPI, auth/registry/coordinator reacquisition or network.
An error invalidates the known receipt/reservation; no read heals dirty,
Invalidated, uncertain or editor-Ready state. Read acknowledgement is not a full
native-body proof, capture, upload, NativeCompleted or historical authority.

A confirmed Evicted receipt can be re-enrolled only for the same connection and
exact native context/body SHA with a freshly admitted NEW binding. The model
snapshot is dropped before current pinned EMPTY ONDISK/in-sync/no-MODIFIED,
positive stable USN/basic/snapshot and global-clean checks; no missing native
bytes are read. A strict old-owner/generation/phase CAS then creates a NEW
Hydration reservation before plaintext. EvictedUnconfirmed/invalidated history
cannot take this path. Original logical version is retained and compared by
resource ID/path/strong ETag/size/directory, with writable=false separately.
Encrypted/modified-time presentation differences on protected restoration grant
no authority and are not equality predicates; originals are not normalized.
Successful Edit completion receipts also retain this exact promoted tuple,
derived locally from their immutable original plus already-verified new ETag
and size before the receipt lock, without auth or catalogue lookup. This keeps
normal Edit -> Lock -> fresh unlock -> read compatible without history adoption.

For the NEW Hydration origin, cleanup requires bounded ONDISK coverage of the
ENTIRE independently verified logical file before any full native read. Empty,
malformed, noncontiguous or insufficient cache ranges refuse; nonempty partial
caches stay incomplete and Lock never requests missing plaintext. Then the
existing exclusive referenced no-follow file/current full-body SHA, stable
positive USN/basic/native identity/in-sync/no-MODIFIED proof precedes the same
single byte-only VERIFY eviction. ALL writable references/pins still span key
clear and final empty-range confirmation. Existing Edit cleanup guards, readonly
helper and native completion ordering are preserved; no metadata write, Mark,
READONLY clearing, force or cloud deletion is added. Retirement cleanup uses the
pure original Weak identity rather than reacquiring keys or requiring a retired
publication revision to remain current. Missing/recovered provenance fails
closed. Synthetic markers expose only enrollment/acknowledgement stage names;
actual Windows full-read/re-unlock/Lock qualification remains a separate gate.

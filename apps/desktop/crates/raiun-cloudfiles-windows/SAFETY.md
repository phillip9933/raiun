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

Configured roots request `CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH` at connection
because fetch admission requires the callback placeholder path. The platform
only promises that path when the flag is requested; see Microsoft's
[CF_CONNECT_FLAGS contract](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/ne-cfapi-cf_connect_flags).
This requests callback metadata only: bounded decoding, no-follow native path
checks, exact root/file/opaque identity checks and publication fences remain
mandatory. A missing or invalid path still fails closed. The prior isolated
Windows case stopped at normalized-path decoding (stage 1002). The original
selector now completes a 65,537-byte decrypted read with the expected hash and
fetch stage 14, but subsequently refuses retired-route cleanup with
`UnresolvedPlaceholderEdits`. This is read acceptance only, not a successful
lock or production vault capability.

Close processing checks exact native root/file/path custody and modified ranges
before requesting an account-bound edit lease. A clean read-only vault close
needs no write authority. A nonempty modified range still requires that lease
before reading content or publishing recovery; inability to obtain it remains
unresolved. No counters or cleanup guards are reset. The reordered close path
passed the focused native close observation: modified/unverifiable counters
remained zero. Cleanup then failed opening its write-access protected handle
with `0x80070005`; no successful lock is claimed. Close telemetry in the
synthetic selector reports only fixed counters/stages.

Vault cleanup alone now requests an EXCLUSIVE protected read handle and retains
its RH oplock/reference through the same root/file/opaque checks, native modified
ranges, nonzero USN comparison, VERIFY_IN_SYNC update and zero-residency postproof.
Both cleanup preflight and actual dehydration use that handle mode. Ordinary edit
completion still requests EXCLUSIVE plus WRITE_ACCESS. Cleanup never clears the
read-only attribute, changes permissions or retries with weaker sharing. The
synthetic selector verifies the read-only attribute remains after cleanup.
[Microsoft documents](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfopenfilewithoplock)
that omitting WRITE_ACCESS avoids requesting FILE_WRITE_DATA at open.
[CfUpdatePlaceholder](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfupdateplaceholder)
still enforces its update authorization independently; these documents do not
guarantee a read handle can authorize that update. If it refuses, cleanup must
remain incomplete with its inventory retained. This narrower open requires
focused native acceptance, not a permission bypass or a lock-success claim.

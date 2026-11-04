# Win32 adapter safety boundary

The workspace denies unsafe code by default. This adapter is a separately
reviewed native boundary. Its crate-level `unsafe_code = deny` policy is
lowered only for the native `src/win32.rs` and `src/session_store.rs` modules;
the portable `raiun-control` crate remains unsafe-free.

The adapter obtains the current process token SID from Win32 and uses that
trusted value to form both the pipe name and protected DACLs. The pipe is
created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, a current-user-only SDDL DACL,
and `PIPE_REJECT_REMOTE_CLIENTS`. It never starts a service, requests
elevation, accepts caller-provided pipe paths, or inherits handles.

All overlapped I/O keeps its `OVERLAPPED` and event alive until completion or
cancellation is drained. Read and write buffers remain borrowed for that
interval. OS handles are immediately wrapped in `OwnedHandle`. Security
descriptor memory returned by Win32 is freed after pipe creation. The shared
safe crate owns JSON serialization, one-megabyte framing limits, and buffer
zeroization.

The session-store adapter obtains `%LOCALAPPDATA%` from the current process,
creates `Raiun/sessions` with a protected DACL granting access only to that
user SID, and re-applies the protected DACL to existing directories before
use. Session filenames contain only a SHA-256 identity digest. DPAPI protects
each opaque session with current-user scope and identity-derived optional
entropy; machine-wide protection is never enabled. Files are created with the
same protected DACL, reparse points are rejected, and replacement is atomic.
Decrypted Win32 output is zeroized before `LocalFree`, and loaded payloads use
zeroizing buffers. The serialized session remains capped at 65,536 bytes.

The Windows-only tests must exercise local same-user request/response, the
65,536-byte session bound, and DPAPI save/load/replace/remove in a synthetic
user account. Remote
client rejection is set at pipe creation; VM tests do not claim that a remote
host was connected. The adapter does not make the Windows agent or filesystem
provider supported by itself.

Vault custody metadata uses a separate `vault-custody` document domain, file
and scope-derived DPAPI entropy. It shares the existing credential document's
bounded, pinned private-file CAS implementation; credential directory names,
entropy and envelope bytes remain compatible. Both document payloads are
limited to one MiB and decrypted buffers are zeroized. Missing custody reads
create no directories. Writes hold the private lock through exact plaintext
comparison, encryption, write-through replacement and protected readback; a
failed write/readback does not promise that the old document survived.

Custody records contain sensitive names and ownership metadata, never saved
passwords or keys. Forgetting a saved key does not erase this separate history.
The caller must validate canonical full account/vault/physical-root scope and
establish complete write-ahead history; this opaque storage API provides no
unlock, native-file ownership, or cleanup authority. Production vault access
remains disabled. The new isolated native custody regression is pending; GNU
all-target compilation and strict linting alone do not verify DPAPI execution.

`DpapiSessionStore::from_existing_private_directory` accepts only an already
admitted `PrivateDirectory`, verifies its pinned path and retains its ancestor
pins. It neither selects an environment path nor creates or repairs a root.
Recovery protection of that exact admitted root verifies its existing policy
instead of replacing its inheritable DACL with the legacy root policy. Derived
profiles use the same verification path; the default GUI session-root selection
and legacy-root behavior are preserved. A synthetic Windows regression checks
repeated protection and refusal after a deliberate test-owned ACL change;
native execution of this GUI-specific regression remains pending.

## Shared directory hints and single-owner observer

The bounded directory notification parser and same-batch pairing expose untrusted
relative names only. They grant no FileID, ancestry, storage classification,
provider/account binding or mutation authority. Ambiguity, malformed buffers and
loss require reconciliation. No new provider watcher is attached by exporting
these APIs.

The separately reviewed native module owns one directory handle, event, and fixed
boxed DWORD-aligned buffer/OVERLAPPED pair. UnsafeCell permits kernel writes while
the operation is pending; the owner is neither Send nor Sync. Only observed
completion permits reuse or release. Cancellation, timeout and NOT_FOUND retain
all resources. Drop deliberately drains with a potentially unbounded wait;
consumers must retain a pending owner and keep blocking Drop off GUI/callback
threads. No driver-completion deadline can justify freeing live kernel storage.

Ordinary construction retains existing no-follow ancestor pins. The borrowed
handle factory reopens only a bounded kernel-derived local Volume GUID locator
and joins original/reopened physical FileID and type/tag observations. It does
not authenticate provider/account/registration/ancestry or change ACLs, privileges,
saved sessions, state paths or default registration behavior. Recognized Cloud
Files tags alone confer no namespace authority. Source checks and original scoped
observer evidence do not establish automatic GUI rename acceptance.

# In-memory vault session registry

`raiun_vault::session::VaultSessionCoordinator` owns an in-memory
`VaultSessionRegistry` with up to 16 verified vault sessions. Each entry is
keyed by the tuple of local account ID, canonical HTTP(S) server origin, Graph
Space ID, and DAV resource ID. Resource IDs are not globally unique. Scope
construction rejects empty, oversized, or control-containing IDs and rejects
origin URLs containing credentials, paths, queries, or fragments.

The coordinator serializes password derivation with one nonblocking permit. A
concurrent unlock returns a busy error immediately and wipes its mutable
password buffer without waiting. One coordinator must own all app account
sessions to enforce the app-wide session cap; separate coordinator instances
have separate caps and KDF permits. Lock and logout do not acquire the KDF
permit or hold the registry mutex during scrypt. Scrypt cannot be interrupted:
lock/logout invalidate the ticket, and the verified session is dropped when
derivation finishes instead of being published.

Unlock callers capture a single-use `UnlockTicket` before running password
derivation and integrity-token verification. A newer unlock attempt for the
same scope supersedes the older ticket. The coordinator automatically cancels
pending tickets when derivation or token verification fails, including during
unwind. At the lower-level registry API, callers must call
`cancel_unlock(ticket)` after failure; dropping a ticket alone does not remove
its bounded pending record. `lock(scope)` and `logout_account(account_id)`
remove active sessions and pending tickets, even when unlock has not inserted
a session yet. `lock_all()` clears active sessions and pending tickets across
accounts without waiting for scrypt. It does not reset ticket generations, and
an in-flight derivation retains the coordinator's busy permit until it returns;
its invalidated ticket then prevents publication. `lock_all()` is an explicit
session-clear operation, not a permanent shutdown latch: later explicit
unlocks are allowed. A real shutdown must separately stop accepting new unlock
requests and guard account generations. A stale or cross-registry ticket
cannot publish its verified session; the rejected session is dropped.
Replacing an active session drops the old owned codec. The coordinator exposes
scoped name/path encoding/decoding, bounded local file crypto and status; it
does not expose the registry, codec, key material, or a closure that could
retain a session reference. It has no automatic expiry or key persistence.

The registry bounds retained sessions and tracks at most 16 current pending
scopes. The coordinator bounds KDF concurrency to one per coordinator, but it
does not limit superseded KDFs across independent coordinators. Use one shared
coordinator for the application. A successful verified token
establishes key compatibility with that token, not server honesty or binding
to the claimed root metadata. The caller must pair the session with the
corresponding independently discovered vault record and continue treating DAV
IDs, sizes, names, ETags, and root hints as untrusted.

Locking drops and zeroizes the owned codec's retained key bundle, but cannot
erase plaintext `String` or path values already returned to callers, caller UI
copies, process allocator remnants, or OS-paged memory. Callers should keep
decoded metadata short-lived and avoid storing plaintext names beyond their
immediate operation. Password derivation still uses the existing scrypt
implementation and has a separately documented scratch-memory zeroization
limitation.

## Agent integration

One profile manager owns the shared coordinator across all local accounts.
The agent snapshots account identity and generation before metadata work and
rejects results after logout or shutdown. An explicit account-transition flag
also rejects new requests that arrive during those transitions. User requests
supply logical selections, never arbitrary DAV URLs or trusted proof tokens.

Scoped file operations keep keys inside the registry and hold its mutex only
for local crypto/file I/O, never network requests. Lock/logout waits for active
local crypto. The agent additionally serializes encrypted pair operations,
conflict decisions and vault control through its sync gate, so lock completes
after the active transfer boundary. The lower-level coordinator alone cannot
cancel network work already started by a caller.

`begin_create` captures a pending ticket for the newly-created DAV resource
before KDF work and returns a non-cloneable pending draft. It exposes only its
encrypted token. `finish_create` requires the same coordinator, current ticket
and exact remote token readback. Dropping a pending draft cancels its ticket;
lock/logout invalidates it before any late finish can publish keys.

The dedicated UI secret command clears its password fields and explicitly
owned Rust buffers without recording passwords in configuration or history.
JavaScript strings and parser intermediates still prevent a guarantee of
complete memory erasure. Directory display uses the whole-batch validation in
[VAULT-DIRECTORIES.md](VAULT-DIRECTORIES.md).

Local folder pairs, their inventories, transfer history and recovery copies
remain plaintext. Lock does not erase them. The new read-only folder-vault FUSE
candidate adds the route lifecycle described below; mounted writes and whole
Space browsing remain disabled. See [ENCRYPTED-SYNC.md](ENCRYPTED-SYNC.md) for these
application boundaries and recovery behavior.

## Read-only mounted browsing integration in progress

The new route layer binds each explicitly unlocked folder vault to its account,
server origin, Space, physical root path and stable root resource identity.
Its registry is separate from the ordinary backend: discovering an encrypted
entry never permits an ordinary read or write below it. Each mounted node and
open handle captures a route generation. Re-locking invalidates that generation;
unlocking again must not revive old handles or inode identities.

Operations hold a route read lease through delivery of the FUSE reply. Lock
waits for these leases, drops route-owned readers, purges directory snapshots
and inode entries, invalidates kernel metadata, and then removes the session.
Read-only encrypted opens use direct I/O rather than the kernel file cache.
Failure to invalidate leaves the route revoked and reports incomplete locking.
Every mutation path must reject encrypted route nodes. This is an integration
contract, not a claim that native mounted browsing has passed acceptance.

Decrypted file reads use verified private staging rather than the persistent
engine cache or transfer history. On Linux the completed file is opened and
unlinked before it is returned as an owned reader. Lock/release closes that
reader. A crash during download may leave named plaintext staging files;
there is no secure-erasure, swap protection, or local-disk encryption promise.
Lock cannot retract bytes already copied into another application's memory.
The initial implementation may wait for an active bounded network operation;
it must not show a successful lock before revocation finishes.

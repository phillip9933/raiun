# Offline files and pending edits

The agent can retain verified, ordinary OpenCloud file versions for browsing
and reading when the network is unavailable. Cache storage is private and
separate for each authenticated account. Cache scope is bound to the normalized
server origin, account identity, Space, and server-reported root resource ID.
Caller-supplied profile or server values never choose a cache namespace.

Each account starts with a 1 GiB quota for recent, evictable content. Explicit
Always available policies, recursive folder pins, recovery data, and dirty
content are protected from recent-content eviction; their usage is reported
separately, so total on-disk use may exceed 1 GiB. The agent reports total,
pinned, and protected bytes without evicting during status reads. A pin is
ready only after the complete directory manifest and every exact file version
are present and verified. One recursive pin job may run per account at a time.

File policies are `recent`, `always_offline`, and `cloud_only`. Changing a
policy requires a fresh authenticated server check. `always_offline` first
downloads and verifies the current file version. Folder pins are a separate
explicit operation and reject encrypted content. Cancellation is cooperative:
an in-flight blocking request finishes before cancellation takes effect.

The 19 October Linux source candidate also supports `cloud_only` for ordinary
folders, including a Personal or Space root. It collects bounded live metadata
without publishing partial listings, then commits the verified listings, stable
folder intent, and eligible Recent-content removal in one cache transaction.
Later descendants inherit the setting through exact account/root and resource
identities, rather than a path prefix. Metadata or protection refusals leave
listings, settings, and bytes unchanged. Missing or ambiguous cached ancestry
requires a refresh before retrying; encrypted selected content is refused.

Folder Cloud only refuses conflicting saved copies, Always available file
settings, pending edits, and recovery or ciphertext protection. It never unpins
automatically or deletes cloud files. Recently used clears only that folder's
own intent: it does not download evicted bytes, remove pins, or override a
parent folder's Cloud only setting. The controls report the effective inherited
setting. This source candidate still requires acceptance of its exact packaged
Linux build; it does not describe a new installed build. Windows folder policy
implementation remains outside this Linux-first change.

The Always available policy commits only while the exact plaintext version is
still indexed with the complete listing's resource ID, ETag, and size, under the
same cache transaction. If recent-content eviction wins before admission, the
request fails and retains the previous policy. Once admission wins, recent
content eviction observes the protected policy. A completed download followed
by an evicted cache record never creates a Ready offline promise.

The R116 source candidate refreshes a complete parent listing after a failed
ordinary upload when metadata is still reachable. It uses the unchanged verified
account/root identity and preserves the upload error and dirty journal; it never
restores pre-mutation rows or treats a lost upload acknowledgement as success.
Mutation invalidation marks only affected Ready file policies stale, using exact
paths, descendant boundaries and affected cached resource IDs. Unrelated Ready
policies still require a complete directory listing before offline reads work.
If that listing cannot be refreshed, retained content alone does not restore
namespace enumeration. Actual R112 offline restart exposed this gap; R116
package/native acceptance remains pending.

Offline fallback is limited to transport-level offline failures. Authentication,
permission, conflict, server-identity, and malformed-response failures remain
visible errors. Encrypted vault metadata and content are not placed in this
ordinary cache. The installed Linux build supports cached ordinary reads,
offline ordinary edits with conditional retry, separately sealed encrypted
snapshots, and restricted offline edits to already-cached encrypted files when
the mounted agent reports that capability ready. Encrypted behavior is
described below.
Reliable disconnected startup/mount restoration and pin migration between
accounts remain unsupported.

When startup restores a saved namespace during a transport outage, folder sync
is temporarily gated while that namespace is read-only. This does not change the
saved Pause setting. On reconnect, Raiun probes the live namespace, verifies the
same Personal drive identity, then publishes the update to the mounted account
Engine. Sync resumes only if the saved account preference was unpaused; a
user-paused account remains paused.

If private cache storage cannot be opened, the authenticated online session
continues and status reports the cache as unavailable.

## Installed behavior: refresh and offline edits

While connected, the account scheduler refreshes protected ordinary files and
folder snapshots at startup, forced sync and roughly every five minutes. It
tracks stable resource identity rather than adopting a replacement at the
same path. New snapshots become ready only after all required versions are
verified. Failed refreshes preserve older protected bytes and show stale or
unavailable status. Recent cache eviction never requests a cloud deletion.

Existing cached ordinary files can be edited offline in the candidate. A
private durable journal retains the original server revision and independent
local bytes. Local reads see the queued edit. Reconnection submits only a
conditional upload against that original revision and verifies the result.
Conflicts retain local bytes and the cloud version without automatic overwrite.
Transfers shows pending and conflicting offline edits; Retry uploads observes
account/Space pause and account-generation cancellation. **Save local copy**
exports a conflict's local bytes through a native Save dialog to a new chosen
file. It does not overwrite an existing destination or resolve/remove the
conflict. A paused account retains its edits. Offline creation, rename and
deletion are not supported by this slice. Old unscoped provider-spool manifests
remain recovery-only and are never automatically adopted by another root or
account.

## Candidate: failed ordinary creation recovery

The 16 October Personal-creation candidate permits new ordinary files while
online using conditional creation bound to the exact Space identity. If close
or upload fails, the provider spool preserves the local bytes across agent
restart. These copies are separate from the cached-file edit journal and its
pending-write count. Settings → Saved upload copies → View copies/Open folder
provides inspection and manual recovery; Sync now does not replay these creates.

An explicit upload-retry action for this spool remains unimplemented. It must
resolve an opaque recovery identifier internally, validate the original
account, Space, root, creation condition and record revision, and reserve the
same path against mounted writers throughout upload and cleanup. A changed
root, existing remote target or ambiguous earlier upload must preserve the
copy as a conflict. Only a verified upload may release recovery bytes; cache
eviction must never trigger that cleanup or a cloud deletion.

## Installed behavior: encrypted offline access

Encrypted pins retain ciphertext file bodies and sealed directory metadata
separately from ordinary plaintext cache records. Cached locations are
discovered using opaque identifiers. An explicit typed or remembered password
must verify the sealed root before its path is displayed or files are decrypted.
The encrypted cache is read-only except for the restricted offline overwrite
path in the installed Linux build dated 2026-10-11 12:47:04 UTC. When the
mounted agent reports that capability ready, already-cached regular files can
be edited; offline creation, folder creation, rename and delete remain
unsupported. Lock revokes old handles and invalidates cached names. A pin is
ready only after the full selected tree is verified. While Raiun is running,
connected and unlocked, encrypted snapshots are refreshed periodically (about
once an hour); refresh may be delayed while offline or busy. A cloud mutation
invalidates that exact vault cache generation before sending the request, so an
ambiguous result cannot expose stale entries through offline fallback.

Encrypted edit uploads can be started with the explicit **Retry uploads**
action after the same vault is unlocked and the account/Space is online and
unpaused. The scheduler also makes bounded automatic retries after successful
authenticated connection cycles for active unlocked vaults, with a five-minute
per-location backoff. Reconnection never unlocks a vault or queries the
keyring. Both retry paths check the original remote identity and version;
changed versions remain conflicts, with local copies retained. Transfers
shows the latest job while the agent is running, but in the installed build
dated 2026-10-11 12:47:04 UTC it lists configured encrypted pair roots only.
The latest job status is in memory; after agent restart, durable edits remain
available for explicit retry although the prior job status may be unavailable.
The installed build also registers the pathless `raiun://unlock` handler: the
URI contains profile/Space/resource identifiers but no filesystem path,
filename or password, and opening it only routes to the locked unlock screen.
Native file-manager launch remains unverified; parser and installer
registration have synthetic coverage.

This does not make the whole computer encrypted: sync folders, ordinary cache,
pending ordinary edits and recovery copies can contain plaintext. Decryption
uses private temporary files; normal cleanup is not secure erasure and cannot
guarantee removal after a crash. The agent and mount must remain running for
mounted offline access. Explicit logout is distinct from a network outage;
Raiun does not promise cached-vault discovery after logout.

## Cloud-only failure handling

Cloud-only changes commit the local policy and index removal before deleting
recent cached bytes. A failed SQLite commit therefore preserves indexed content.
If later local deletion or directory sync fails, the policy may already be
applied while cleanup is incomplete; callers should refresh policy state. This
ordering does not establish cross-process publication/deletion coordination.

## Windows storage integration status

Production Windows cache opening remains disabled. The reviewed rollback VFS
keeps SQLite and its private directory handles under one database owner;
threaded transaction and lifecycle tests pass. The shared schema initializer
now has a test-only Windows path that verifies DELETE journaling, FULL sync,
and memory-only temporary storage before applying the actual cache schema.
This is infrastructure validation, not production cache availability.

Cache content APIs return `CacheContentReader`, a read-only stream with seek and
metadata access. Engine snapshots and vault root-envelope reads retain this
wrapper rather than extracting a file. On Windows it can own the immutable
file and directory pins together. The wrapper is not proof of scope, digest or
version validation: converting an already-owned Windows private reader only
retains that reader. Cache API boundaries still perform their existing exact
scope, policy, generation, length and digest checks before returning content.
Production cache opening still uses the portable implementation and rejects
Windows; this API migration does not enable Windows cache availability.

The test-only Windows publisher now returns a receipt retaining the immutable
reader, exact file identity, name, length, digest, and whether this publication
created the object. Exact reuse reports `created = false`. Creation alone never
authorizes cleanup: database references and identity must still be checked.
R17b passed its native Windows harness build, strict cache Clippy, and all ten
blob tests under an ordinary synthetic user. Evidence:
`outputs/vm-lab/windows-publication-receipt-20261016-r17b-windows-r1/result.md`.

Before enabling Windows caching, retain the private root/content directory
handles in the cache and replace every pathname-based content operation:

- Publish staged blobs through identity-checked, no-replace handle operations;
  verify an existing destination's length and digest before accepting a race.
- Open immutable content through a validated handle that excludes replacement
  and modification for the reader's lifetime.
- Centralize eviction, abandoned staging, orphan and journal cleanup behind
  identity-checked deletion. Directory enumeration supplies names only; every
  candidate must be independently validated. Uncertain publication or cleanup
  must preserve recoverable content, and eviction must never delete cloud data.
- Hold generation locks on validated persistent lock files without deleting or
  recreating those files while another process might still use them.

Native tests must cover replacement, reparse/hardlink rejection, concurrent
publication and reopen. A Windows no-op directory sync is not proof of durable
deletion. Existing schema migration steps also are not one atomic transaction;
this limitation is unchanged by sharing the initializer.

### Publication versus orphan cleanup (R14)

A reproduced race allowed a second cache instance's startup scan to remove an
immutable blob after publication but before its index transaction committed.
The implementation uses a persistent per-directory `content-publication.lock` shared
lease across all four blob-writing funnels. Orphan cleanup attempts an exclusive
lease without waiting and defers when publication is active. Queue/replacement
paths release their publication and database guards before requesting cleanup.
The lock file is never removed. Deferred orphan reclamation preserves bytes;
it does not imply a cloud deletion or an acknowledged upload.

The regression failed before the fix and passes afterward. Source workspace
checks and isolated native validation pass. The exact VM-verified R14 package
was installed on the laptop at 2026-10-16 04:42 UTC and left closed.
This narrowly fences orphan scans against publication; CloudOnly, eviction and
other deletion paths still require broader cross-instance coordination. Native
Windows persistent caching remains disabled. Evidence:
`outputs/vm-lab/cache-cleanup-lease-20261016-r14/`.

### Deletion coordination (R15, installed in R16b)

CloudOnly cleanup, recent eviction, ciphertext invalidation and unreferenced
ciphertext-write cleanup now acquire the exclusive content lease before database
access, retaining it through commit and unlink. Invalidation orders its locks as
content lease, pin-generation lease, then database. A callback under the pin lease
must not publish, evict or invalidate. Eviction only unlinks after exactly one
index row was deleted and synchronizes its directory afterward.

Publication already holding a shared lease may finish before a waiting CloudOnly
request or invalidation; deletion then removes eligible recent bytes. A publisher
starting afterward observes the updated policy/epoch. Dirty and pinned references
remain protected by existing transactional checks. Tests cover a separate cache
republishing the same version during eviction and a database-declined deletion.
Source gates and native R16b validation pass; R16b is installed and closed.
The original R15 parallel rename failure remains recorded separately. R16b
verified offline pinned reads and failed-close recovery across restart; an
offline-start mount still needs an online restart to regain writable permissions.
Evidence: `outputs/vm-lab/cache-deletion-lease-20261016-r15/`.

### Mounted permissions after reconnect (R18)

R18 is installed and closed. A separate account/handle-bound live permission
snapshot updates existing mounted Space gates only after proof and application
identity validation. Startup fallback remains read-only when mounted offline;
validated reconnect restores matching live permissions without remounting.
Removed or changed Space roots/classification and invalid/authentication failures
revoke grants. Revocation is generation-fenced so a stale response cannot clear a
newer accepted grant. Saved offline namespace data is never used as a new write
grant. Dirty handles and recovery are preserved. Exact-package testing verified
Personal 0555 -> 0755 on the same PID/mount and unchanged pin/recovery hashes.
Evidence: `outputs/vm-lab/reconnect-mount-permissions-20261016-r18/`.

### Windows provider read-through cache (R39 source, verified in R41f)

The Windows library constructor is verified in R37. R41f verifies the integration
that binds an optional cache to the already authenticated placeholder backend, after
verified account, Personal root, configured local root and generation checks.
Each ordinary Space/root gets a separate scope using normalized origin, canonical
account ID, Space ID and remote root resource ID. Callback identities do not
select the cache directory or account. The Windows parent is the existing
current-user protected state directory; the cache retains its own pinned private
directories, SQLite VFS owner and immutable content handles.

Only complete ordinary-directory listings are published, after root and directory
identity checks before and after traversal. Complete file versions are retained
only when their verified resource/version/size also occurs in a complete cached
listing. A partial callback never becomes an offline file. Whole-file retention
and verification are bounded by the existing 16 MiB callback staging limit;
larger files require a later bounded download/pin path. Missing listing metadata,
CloudOnly policy or cache budget refusal can skip retention while preserving a
successful verified online read. Cache I/O/corruption errors remain failures.

Fallback uses the shared client's Offline classification: transport unavailability
and temporary HTTP 502/503/504 responses. Authentication denial, absence, root or
validator conflict never triggers fallback and fences the entire cached backend
until the agent verifies a replacement. Cache bytes are preserved rather than
deleted. Cached results retain token-generation and callback revocation checks;
a cancellation during a cache commit may retain fully verified Recent data for
the same account, but the callback discards delivery. No offline write grant is
created. Namespace discovery/startup remains online-only and the production
Windows provider remains disabled pending its native acceptance gates.

R41f passed supported Windows workspace check/clippy, 28 provider/cache integration
tests, all six native Cloud Files tests, the native agent recovery test and 59
cache tests under an ordinary synthetic user. Production provider activation is
still disabled pending initialization readiness and interactive Explorer gates.

## Saved edits after directory metadata becomes unavailable

Ordinary directory listings stay invalidated after an uncertain mutation when a
fresh complete listing cannot be verified. Retained local edits are separately
listed in Transfers under their exact saved Space/root identity; those labels
are historical and do not establish current cloud state or directory reachability.

The R123 source increment allows an explicit **Save local copy** for a pending
or conflicted ordinary edit with a known saved root. Export reads only the exact
persisted origin/account/Space/root/write scope, requires referenced plaintext
Dirty content and verifies its length/hash. It writes a private staging file and
publishes to the selected local destination without replacing an existing file.
The journal remains unresolved; no retry, upload, deletion, policy change or
ordinary namespace restoration happens. Damaged, missing, verified, mismatched
or ciphertext-only records cannot use this path. Encrypted exports retain their
separate unlock/recovery rules. Exact-package native acceptance and installation
of this increment are tracked separately from source checks.

Saved-copy export also requires the journal page's captured auth generation and
opaque account-scope fingerprint. These travel through the native Save dialog;
a later account in the same profile cannot reuse old Space/root/write labels to
export different bytes. Legacy pages without this binding remain visible but do
not offer this export action. The action rechecks generation and saved account
settings before publication and never treats an export as upload completion.

## Historical copies after an uncertain change (Linux candidate)

When a cached folder pin becomes stale or incomplete, the Linux cloud drive can
show a **Saved offline copies** folder in Personal or the relevant Space. These
are historical, read-only snapshots. They may differ from the current cloud;
missing entries do not prove cloud deletion. Incomplete pins can retain names
without retaining every file's bytes. Unavailable content fails to open.

Copy a readable file out to another local folder to keep a separate copy. This
view does not upload, reconcile, delete, or restore the current cloud listing.
Encrypted vault content remains behind its separate unlocked-vault checks.
Removing a pin prevents new opens through its old snapshot nodes; an already
opened immutable reader can finish within the existing mount/account session.

The folder chooses a different label if a current cloud entry uses its name.
Names emitted for this historical view remain protected against mutations until
that mount is closed, including a concurrent cloud operation completing at the
same name. Remount to release these conservative name reservations. This source
candidate still requires exact-package isolated VM acceptance before delivery.

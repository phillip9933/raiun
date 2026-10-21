# Encrypted folder sync

Raiun's encrypted sync uses the OpenCloud Web v8 rclone-crypt vault format.
The Linux implementation connects the codec to folder-pair reconciliation:
remote names and file contents are encrypted; the local sync folder remains
an ordinary readable folder. Other applications can open those local files.
This is cloud-side encryption, not local-disk encryption.

## Accessing encrypted files

The installed encrypted-access build adds **Unlock encrypted files** on the
account Overview. Choose Personal or a Space, then select an encrypted folder;
an encrypted Space opens its unlock screen directly. This does not create a
sync pair. The dialog reports mounted availability and write readiness from the
agent, so unlocking alone does not imply that the drive is mounted or writable.
Configured encrypted folder pairs and mounted vaults can edit online when the
agent reports write access. The current Linux source candidate supports a
restricted encrypted offline edit path when the exact location is unlocked and
the agent reports it ready. A saved snapshot alone does not imply the edit path
is ready. Locking revokes the route and invalidates existing mounted handles;
close and reopen files after unlocking again. These source-candidate details do
not imply that an installed package has been updated.

## Writable mounted-drive candidate

The installed Linux writable build supports regular-file creation, editing,
rename and deletion, plus folder creation, inside explicitly unlocked folder
vaults and non-personal encrypted Spaces. A never-attempted queued folder
subtree can be renamed only within the 64-operation and 64 MiB bounds described
below; restart, child creation, and reconciliation passed in the installed R28
candidate. Unsupported or unresolved subtrees are retained unchanged. Remote
folder deletion is
unsupported; an empty never-attempted queued folder can be canceled locally
only when it has no open handles or dependent operations. The dialog reports
actual mounted write availability; a read-only fallback is retained when the
writer or private local storage is unavailable. Cross-vault moves and changes
to vault roots are rejected.

Edits use private local plaintext working copies and conditional encrypted
uploads. A conflicting server revision leaves local edits available for review
rather than overwriting the newer remote file. Editor replacement uses an
intermediate recovery name; if cleanup fails, that encrypted recovery sibling
can remain visible. Moving between vaults is not an atomic supported operation.

The account-wide encrypted recovery view lists local records and opens their
private folder. It does not replay, restore or delete them. The per-location
operation list shows decoded paths only while that exact encrypted root is
unlocked; locked recovery metadata does not expose paths. Header status does not
attest to the full integrity of a saved content body. Successful unchanged
copies can be retired after verified upload; dirty or uncertain copies are
preserved. The mounted working-copy limit is 64 GiB.
Locking prevents later access through mounted handles, but does not encrypt or
remove retained local copies or recall bytes already read by another app.

## Encrypted offline edits in the current source candidate

When the agent confirms that private edit storage is ready, an explicitly
unlocked encrypted location can queue overwrites of cached regular files,
regular-file creation, same-vault regular-file rename and deletion, and folder
creation. A newly queued folder can contain queued files and folders. Renaming
a queued folder is supported only for a complete subtree of never-attempted
queued operations, with a limit of 64 operations and 64 MiB of aggregate file
content. The R28 installed candidate passed VM restart, child creation under the
renamed folder, and reconciliation. A subtree over either limit,
or containing an attempted, uncertain, conflicting, dirty, open, or otherwise
unsupported item, remains unchanged and requires review. Remote folder deletion
is unsupported; an empty never-attempted queued folder may be canceled locally
only when no open handles or dependent operations remain. The
installed application may not contain later source changes; check its
release notes/version before relying on them. If storage or mount readiness is
unavailable, the location remains read-only.

Removing a remote encrypted folder through Raiun is disabled because WebDAV
DELETE may remove a collection recursively, and the protocol does not provide a
verified atomic condition that the folder is still empty at deletion time.
Review and remove its contents deliberately in an OpenCloud-supported file
manager; Raiun will not turn an empty-folder check into a potentially recursive
DELETE.

**Retry uploads** remains an explicit action for the exact unlocked Space and
vault root. After successful authenticated scheduler cycles, Raiun also makes
bounded automatic retries for active, already-unlocked roots when account and
Space sync are not paused; each location has a five-minute backoff. The agent
never unlocks a vault or checks saved keys automatically. Both retry paths use
the original remote identity and version, and an upload is confirmed only after
a conditional write and successful remote readback. Changed versions remain
conflicts; retries do not auto-rebase and unresolved local copies stay saved.
Confirmed uploads may be retired from local recovery after readback.

Transfers shows the latest retry job while the agent is running. This status
is held in memory only; after an agent restart it may be unavailable even
though saved edits remain available for explicit retry. The source candidate
also lists authenticated queued operations for unlocked roots; this operation
status does not attest to the full integrity of every saved content body. An
interrupted create whose server outcome is unknown is retained for attention
and is not automatically replayed. A crash-left regular-file create in an
`Attempting` state can be retried only through a separate user action for that
exact operation and revision. Raiun rechecks the root and parent, requires the
destination to be absent, and uses the original create-if-absent condition.
The encrypted body remains in recovery until remote content readback succeeds;
an occupied destination, including one with identical bytes, is retained as a
conflict rather than claimed as Raiun's upload. A lost response therefore
requires review and another explicit action; it never triggers a background
replay. Each action advances a durable retry generation, so an old request or
late completion cannot claim or retire a newer attempt.

## Using encrypted sync

In **Synced Folders → Add folder**, choose a local directory and OpenCloud Space.
Browse the remote location. Select an encrypted folder to unlock it, or choose
**Create encrypted folder** in an ordinary writable parent. Creation appends
`.vault` to the cleartext root name. Enter and confirm a password, then select
the vault root or an internal folder and choose the sync direction.
Existing encrypted Spaces are selected as a vault rooted at `/`.

The **Encryption** control on a saved pair opens its vault controls. Unlocking
allows the background scheduler to resume its encrypted pairs. Locking waits
for the active sync operation, then removes the in-memory session keys and
stops further encrypted sync. Closing the ordinary app window leaves the tray
and agent running, so it does not lock vaults. Logout, agent exit, and a fresh
agent startup discard the unlocked state. Unlocking remains explicit after
startup. In the installed offline-stale build, **Remember on this device** is
an unchecked opt-in that stores the vault password in the operating system's
Secret Service, scoped to the profile, server, Space and vault resource. It
requires `secret-tool` and an available Secret Service. There is no plaintext
settings fallback. **Unlock with saved key** is a separate explicit action;
normal status checks do not open the keyring or unlock a vault.

**Lock now** clears the current unlocked session while retaining the saved
credential. **Forget saved key** durably revokes Raiun's authority to reuse that
credential, including after restart, without locking the already-open vault.
Logout revokes the profile's saved-credential authority. Secret Service physical
deletion is best effort because a locked keyring can retain an old entry;
Raiun reports that uncertainty and cannot reuse the retired generation. Keep
your own recovery password even when remembered access is enabled.

Lock does not remove or make unreadable the local folder, conflict copies,
SQLite inventories, transfer history, or local temporary/recovery files. These
can contain plaintext names and contents. Use local storage protection if that
is part of your threat model. The root vault label, hierarchy, approximate
sizes, timestamps and traffic patterns are not hidden from the server.

Keep the vault password in your own password manager or recovery records.
There is no server-side password reset that can decrypt a vault, and Raiun does
not keep a recovery key. Do not rename or replace an established vault's
integrity property to change its password: data would need to be re-encrypted.
Password rotation and shared key management are not implemented.

## Transfer and recovery behavior

The encrypted adapter is explicitly bound to the local account, server origin,
Space, physical vault root and stable DAV resource identity. Every operation
rechecks the root identity and its password proof. A missing session, changed
root, invalid proof or invalid directory fails without plaintext fallback.
Ordinary sync and mount operations retain their encrypted-area guards.

Uploads encrypt into a private ciphertext staging file and use conditional
WebDAV PUT: create-if-absent or match the last observed ETag. Downloads stage
the ciphertext, check its length/revision, authenticate the blocks, and only
then publish a local result. Sync history and conflict resolution use the same
engine as ordinary pairs. A stale conflict decision is rejected; local recovery
copies follow the existing engine's preservation rules. Missing files are
reported for attention rather than automatically propagating deletions.

For an unresolved offline-edit conflict, **Save local copy** opens a native
Save dialog and writes the local conflict bytes to the chosen destination. It
does not overwrite an existing file or resolve/remove the conflict. The cloud
copy and local journal remain available for review.

New folder creation consists of MKCOL and a separate integrity-property write.
MKCOL must create a new root; Raiun never initializes an arbitrary existing
folder. The property write has an ETag precondition and exact identity/token
readback before a session is published. If setup fails, the created root is
retained. It may be empty and uninitialized, or initialized with the entered
password if the response was lost. Inspect it before retrying. Raiun does not
automatically delete or overwrite that partial root.

The format authenticates each content block, not the total file length,
metadata, or filename-to-content relationship. Raiun compares server lengths
and ETags for transfer consistency, but those are not cryptographic proof
against a malicious server. Whole-block truncation or rollback cannot be
fully detected by this interoperable format. Empty files have no authenticated
content block; unlocking relies on the separate integrity token.

## Bounds and current limits

- File crypto streams 64 KiB plaintext blocks; files are not loaded wholly into
  memory. Staging requires free local disk space proportional to the transfer.
  The adapter's maximum plaintext file size is 1 TiB; this is a size bound, not
  evidence of a tested 1 TiB transfer.
- One password derivation runs at a time across all accounts; at most 16 vault
  sessions are retained. Passwords are UTF-8, nonempty and at most 4,096 bytes.
  Owned password/key buffers are wiped, but JavaScript/serialization and the
  scrypt dependency do not provide a complete process-memory erasure guarantee.
- Directory decoding is atomic and bounded to 10,000 entries and 2 MiB of DAV
  XML. Portable-name and Unicode compatibility collisions fail closed. The
  ordinary engine's wider listing limit does not override this vault bound.
- Transfers use a bounded total deadline, not an idle timeout, and are not
  resumable. Lock/pause is observed at operation boundaries, so an active
  network request may need to finish or time out first.
- The current Linux source candidate supports explicitly unlocked encrypted
  folder vaults and non-personal encrypted Spaces in the existing drive when
  mounted. Unlocking does not require saving a local sync pair. Online writes
  are available only when the agent reports the location writable. The current
  source candidate also queues supported offline file and folder operations;
  a queued-folder rename is limited to a never-attempted subtree of at most 64
  operations and 64 MiB of file data. See “Encrypted offline edits in the
  current source candidate” for limits. This does not claim that an installed
  package includes these changes. Retries may run after successful
  authenticated scheduler cycles for active unlocked roots, or the user can
  choose **Retry uploads**. Reconnection never unlocks a vault or reads saved
  keys. Locked roots remain hidden.
- Mounted file opens download and verify a complete private plaintext snapshot.
  Completed snapshots are unlinked before use and closed on release/lock.
  Lock waits for active reads/downloads, retires old handles and cached names,
  and denies subsequent reads even after a later unlock. Already copied bytes
  in other applications cannot be recalled. A crash during download can leave
  private named plaintext staging files; this is not local disk encryption.
- The encrypted offline-pin and mounted-write paths passed synthetic VM tests.
  Native window interaction and live-server acceptance remain separate checks.
- New encrypted Spaces, nested vaults, password changes and encrypted sharing
  workflows are not created by this UI. Existing encrypted Spaces can be bound
  for folder-pair sync. Windows and macOS vault-native integration is pending.

See [codec compatibility](ENCRYPTION-INTEROP.md),
[session lifecycle](VAULT-SESSIONS.md), and the pinned
[WebDAV write contract](VAULT-WRITE-CONTRACT.md). Final build/test evidence is
recorded in [implementation status](IMPLEMENTATION.md); this guide alone is
not evidence of native or live-server acceptance.

## Native acceptance checklist

Use a disposable vault and local test folder for the first installed run:

1. Create a vault, add a two-way pair, and sync a Unicode filename, an empty
   file and a file larger than 64 KiB. Unlock it in OpenCloud Web and compare
   names and bytes. This cross-application live check is still pending.
2. Edit a file in Web and confirm a later sync downloads it. Change the same
   file on both sides and verify the conflict choice preserves the displaced
   version. Check Transfers for this computer's operation results.
3. Lock the vault, edit a local test file and verify no new encrypted transfer
   occurs. The local file must remain readable. Unlock and verify sync resumes.
4. Quit and reopen Raiun. Confirm the vault starts locked, an incorrect password
   fails, and the correct password resumes the saved pair.
5. With multiple accounts configured, verify a vault unlocked in one account
   stays unavailable in the other. Logout must discard that account's keys.
6. Use the `raiun://unlock` address printed in a locked encrypted folder's
   README with the desktop's URL-opening action. Confirm Raiun selects the exact
   configured account and stops at the locked password screen without unlocking
   automatically. The README prints an address, not a verified clickable
   control. Native URI launch has not been tested; only parser and installer
   registration tests are recorded.

The Linux installer registers the `raiun://` handler, and its strict parser and
installer entry are covered by synthetic tests. Opening a locked-folder link
from the file manager has not been verified in a native desktop session. These
are owner acceptance steps, not a claim that the native UI or your real server
has already passed them. The automated suite uses isolated fixtures.

# OpenCloud vault interoperability

`crates/raiun-vault` implements the OpenCloud Web rclone-crypt profile without
remote I/O. Its verified session coordinator is used by the explicit encrypted
folder-pair backend. See [encrypted sync](ENCRYPTED-SYNC.md) for application
behavior and the separate local-plaintext and mounted-access limits.

OpenCloud describes vaults as compatible with rclone crypt in its [official
7.5.0 release notes](https://github.com/opencloud-eu/opencloud/releases/tag/v7.5.0). The
Android implementation in `core/crypto` independently documents and verifies
the Web v8 profile against pinned Web and official rclone outputs. Its
`README.md` records source revisions, binary provenance, and cross-direction
checks. The Rust crate imports only those synthetic binary fixtures and their
manifests, not user data or credentials.

## Supported profile

- Password: UTF-8 bytes, non-empty, at most 4,096 bytes; the derivation API
  overwrites its mutable input buffer. Passwords above 4 KiB fail before scrypt. scrypt `N=16384, r=8, p=1`, fixed
  rclone default salt, 80 output bytes.
- Key bundle: bytes `0..32` encrypt content, `32..64` encrypt names, and
  `64..80` are the AES-EME tweak.
- File: `RCLONE\0\0`, 24-byte nonce, then independently authenticated
  XSalsa20-Poly1305 blocks of up to 65,536 plaintext bytes. Each block carries
  a 16-byte tag; the 24-byte nonce is incremented little-endian between blocks.
- Names: AES-256 EME wide-block transform, PKCS#7 padding to 16 bytes, and
  unpadded base32hex. A path is slash-separated encoded components.
- Integrity: the Web token is base64-encoded rclone ciphertext whose plaintext
  must be a canonical 36-character, hyphenated hexadecimal UUID.

Password derivation, authenticated integrity proofs, portable name/path
encoding and decoding, and bounded streaming file encryption/decryption are
implemented. `VaultCipher` is the low-level codec; existing vaults obtain a
`VerifiedVaultSession` only after `verify_and_unlock(integrity_token)`.
New vaults produce a `NewVaultDraft`, which cannot encrypt user data or be
inserted into the session registry. Exact generated-token readback is required
before the draft becomes a verified session. The agent's pending creation
ticket additionally prevents late publication after lock/logout.

File and integrity-token writes use fresh OS-random 24-byte nonces. The public
writer cannot accept a caller-selected nonce. Private deterministic test seams
compare exact bytes with the pinned Web/Android/rclone fixtures; normal writes
use fresh nonces. Directory name encryption is deterministic as required by
the format. Local crypto uses a 64 KiB block buffer and private no-clobber
staging; the network adapter applies HTTP preconditions separately.

## Safety properties and limits

`decrypt_file_transactional` writes to a private temporary file beside the
requested destination and publishes with no-clobber semantics only after all
present blocks authenticate and optional trusted plaintext length metadata
matches. On a late error, the staged output is removed and no destination is
published. The caller must keep the destination directory private while this
operation runs. On Unix the published file has mode 0600. On Windows the
temporary file inherits the destination directory ACL; the crate does not set
or verify an owner-only ACL. The file itself is synced before publication, but
the parent directory is not synced, so the rename may not survive a sudden
power loss. Removing a temporary file is not secure erasure; filesystem
journaling, snapshots, and storage media can retain blocks, so deployments that
require protection at rest need OS-level disk encryption.

The format authenticates each block, but not the filename, total block count,
or final plaintext length. A header-only object is the valid encoding of an
empty file; it has no authenticated block and therefore cannot prove a key.
Vault unlock must be gated on the separate authenticated UUID integrity token. A file truncated exactly on a block boundary is
indistinguishable from a valid shorter file unless the caller supplies a
trusted `expected_len` (for example, a length verified through authenticated
metadata). A successful decode alone does not prove completeness. DAV/Graph size and ETag values are not cryptographically authenticated by this
vault format. Passing the server-reported size as `expected_len` can detect
accidental truncation or inconsistent metadata, but a malicious server can
truncate whole blocks and alter its own size/ETag response; there is no
cryptographic guarantee against that attack. Only length metadata protected by
a separate trusted mechanism can detect full-block truncation. Integration
must bind decoded components to a vault root and prevent path escape.

The verified session returns portable path components, not an absolute path
or a joined `PathBuf`. It rejects Windows-invalid characters, trailing dots
or spaces, drive/ADS colons, and reserved device names instead of rewriting
them. Single-name/path decoding does not check collisions against siblings.
Directory callers must use the scoped batch API in
[VAULT-DIRECTORIES.md](VAULT-DIRECTORIES.md), which checks bounded
compatibility-caseless collisions before returning the full result.

Decryption uses a fixed 65,552-byte encrypted-block buffer plus one block of
plaintext and crypto state; it never buffers the whole file. A caller-provided
maximum plaintext size is mandatory. Scrypt is memory-hard and synchronous;
integration must cap concurrent unlock attempts. A `VaultCipher` is a
short-lived in-memory session and zeroizes its retained key bundle on drop;
AES round-key schedules also use the AES crate’s `zeroize` feature. This is not
a claim of complete process-memory erasure: RustCrypto `scrypt` 0.11 keeps its
B/V/T KDF scratch allocations in ordinary vectors without zeroization, and UI
string copies, allocator remnants, and OS paging are outside this crate’s
control. Treat KDF scratch wiping as a release-review item and evaluate an
upstream zeroizing implementation before making stronger erasure claims. Password
input is a mutable byte slice and is overwritten during derivation, including
on errors; the caller should use a mutable secret buffer and clear any separate
UI string. Key-material input is copied and must be zeroized by the caller.
Avoid logging or persisting passwords, avoid global/shared cipher caches, and
drop the session on lock/logout. No secret is accepted from logs or
read from an account store here.

The EME transform is adapted from `rfjakob/eme` v1.2.0 under MIT; the complete
license is in `crates/raiun-vault/EME-MIT-LICENSE`. Crypto primitives are Rust
crypto crates; dependency versions are pinned by the workspace lockfile. No unsafe code is permitted.

## Synthetic compatibility fixtures

The checked-in fixtures are copied from the Android repository's tests and are
synthetic (password `potato`, generated byte patterns, no user content):

- `@fyears/rclone-crypt` 0.0.7, from OpenCloud Web v8.0.0 source commit
  `fe7ce657bcf92566986ed1572f90e1cbb4683464`, with Unicode names, token, and
  file sizes 0, 1, 65,535, 65,536, and 65,537 bytes.
- Official rclone v1.75.1 Linux amd64, release commit `687d264`, with the same
  lengths and Unicode path components. The Android README records the archive
  SHA-256 and generation procedure.

Rust tests assert decoded plaintext, paths, token validity, size boundaries,
wrong-key and tamper rejection, no-clobber and permission behavior, short and
interrupted reads, 0600 publication, and that failures (including truncation
detected by separately trusted length metadata) leave no published plaintext
or temp file. They also test portable filename rules and the verified-session
unlock boundary. These fixtures establish codec compatibility only; they do not establish safe end-to-end vault discovery, metadata binding,
key persistence, or engine/UI behavior.

## Application integration evidence

The coordinator in [VAULT-SESSIONS.md](VAULT-SESSIONS.md) now participates in
agent logout/shutdown, scoped unlock and conditional creation. The read-only
`vault_readonly.rs` fixture remains as a metadata-only regression test.
`vault_creation.rs` verifies new-root initialization and retained partial
failures; `vault_backend.rs` exercises ciphertext WebDAV operations. These
synthetic checks are separate from native UI and live deployment acceptance.
See [ENCRYPTED-SYNC.md](ENCRYPTED-SYNC.md) and the current build evidence in
[IMPLEMENTATION.md](IMPLEMENTATION.md).

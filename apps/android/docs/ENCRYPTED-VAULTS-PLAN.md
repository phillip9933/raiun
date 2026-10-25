# Encrypted folders and Spaces

This guide describes the encrypted-vault features included in the published Raiun Android 1.0.0 release, plus their security and interoperability boundaries. Historical implementation plans and test notes remain historical records; current validation evidence is maintained in [TESTING.md](TESTING.md).

## Android 1.0.0 transfer behavior

Picked-file uploads are encrypted locally while the location is unlocked, then scheduled using only ciphertext. Once preparation finishes, the network upload can continue after locking or process restart. Recovery checks for an already committed identical ciphertext before retrying a conditional write. Upload retries can resend the complete staged ciphertext; this does not claim byte-offset upload resume or unsafe overwrite-based finalization.

Individual files selected for offline access can download ciphertext in the background. A matching strong ETag permits byte-range continuation; without one, the download starts again. Download completion alone is not offline readiness: the file stays pending verification until a matching live unlock authenticates all its encrypted content. A protected empty root manifest established at selection allows that verification on a later offline unlock, without storing the password or unlocked key material. Existing valid offline copies are preserved until replacement succeeds.

Copy and move can choose another ordinary or encrypted location in the same account. Crossing into ordinary storage requires confirmation because the destination contains plaintext. Transfers requiring decryption remain bound to live unlocks and stop on lock/background or process death. Moves verify copied contents and source/destination snapshots before source deletion; a partial cleanup is reported rather than replayed automatically. Conflicting names offer Cancel or Keep both, and conditional writes still protect against races after the choice.

Recursive offline folder capture, scanner uploads and encrypted text saves retain their foreground session behavior. The protocol format and external-app handoff limitations below remain unchanged.

## Android 1.0.0 feature scope

Raiun recognizes encrypted folders and encrypted Spaces in the normal Files and Spaces surfaces while keeping them outside ordinary plaintext file queues and caches. Users can unlock with a vault password and, where the device enforces strong biometrics through Android Keystore, opt into biometric key access. Password recovery remains necessary. The feature targets the OpenCloud Web rclone-crypt profile; it does not guess alternate rclone modes.

The release includes online browsing and internal text, image and PDF viewing; encrypted text editing; encrypted folder scanning; same-vault file operations; encrypted-location management; and offline snapshots. Picked-file encrypted uploads and individual encrypted-file offline downloads run in background after preparation/selection. Copy and move can cross between ordinary and encrypted locations, with confirmation before a destination receives plaintext. Secure scanner output is temporary app-private data and uses the encrypted session upload path, not the ordinary persistent upload queue. Offline snapshots store ciphertext and protected metadata. External-app opening is an explicit plaintext handoff with a warning, read-only URI grant, bounded new-access lifetime and best-effort cleanup.

See the dated [testing record](TESTING.md) and [security review](ENCRYPTED-SECURITY-REVIEW.md) for retained evidence and limits. Historical checks are not claims that those checks were rerun for this documentation update, and automated evidence is not a security certification or a guarantee for every OpenCloud installation, Android device or external app.

## Interoperability contract

The target is the OpenCloud Web v8.0.0 rclone-crypt profile used by OpenCloud 8.0.1: scrypt `N=16384, r=8, p=1`, 80 derived key bytes, AES-256 EME encrypted names, and `RCLONE\0\0` content files with 64-KiB XSalsa20-Poly1305 blocks. The integrity UUID property is used as password proof only when it contains nonempty authenticated content. Android streams blocks and authenticates each complete block before exposing its plaintext.

The codec has independent Web and rclone interoperability fixtures. The code supports the compatible profile only. Non-default password2, alternate filename modes and alternate encodings are not supported. Other OpenCloud/server versions and administrator-customized Web deployments require separate compatibility verification.

The format authenticates content blocks, not the complete file, path, final length or version. It cannot by itself detect every rollback, whole-block tail removal or valid same-key file substitution. Names and metadata such as file sizes, timestamps, hierarchy, root labels and membership may remain visible. Do not describe ETags or offline manifests as protection against a malicious server rewriting all associated metadata.

## Protection boundaries

Vault passwords derive encryption keys locally and are not sent to the server by Raiun. OAuth credentials separately authorize server operations. Optional biometric access wraps derived key material with Android Keystore and requires strong, hardware-enforced biometric authorization; unsupported devices retain password-only access. Unlocked keys and decrypted previews are held in memory for the active session. Buffer clearing is best-effort and does not guarantee erasure from managed-runtime memory or platform rendering buffers.

Offline data contains encrypted file blobs and identity-bound protected metadata. Root existence and labels can remain visible for navigation. Removing a server share cannot revoke keys or copies that a user already obtained. Local deletion unlinks files but is not forensic erasure from flash storage.

An external app can read the plaintext copy during the handoff and can save, share or back it up. The bounded URI expiry denies future opens; Android cannot revoke an already-open descriptor or erase a recipient's copy. Use internal viewing when external plaintext exposure is unacceptable.

## Remaining feature boundaries

- Recursive encrypted-folder offline capture, scanner uploads and encrypted text saves remain foreground operations. Work requiring decrypted content remains bound to a live unlocked session and stops on lock, backgrounding or process death.
- Public links, per-child sharing, encrypted DocumentsProvider access and server-side Office editing are not included.
- Upload retries may resend complete staged ciphertext; they do not provide byte-offset upload resume. Encrypted downloads resume by byte range only when a matching strong ETag is available; otherwise they restart. Download completion requires later authentication during unlock before content is treated as available offline.
- Alternate rclone profiles, password rotation/re-encryption and account-token storage migration are unsupported. The compatible profile does not imply compatibility with every server version, and the source review is not a formal security audit.

Raiun's encrypted-vault security review records format limitations and the external handoff boundary in more detail. Public protocol references include the [rclone crypt format](https://rclone.org/crypt/) and [OpenCloud Web v8.0.0 vault implementation](https://github.com/opencloud-eu/web/tree/v8.0.0/packages/web-app-rclone-crypt).

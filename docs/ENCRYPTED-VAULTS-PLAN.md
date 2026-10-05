# Encrypted folders and Spaces

This document describes the encrypted-vault work in the Raiun 0.9.0 beta. It supersedes the early read-only implementation plan below and in older test notes; those notes are historical records, not current feature status.

## Current beta scope

Raiun recognizes encrypted folders and encrypted Spaces in the normal Files and Spaces surfaces while keeping them outside ordinary plaintext file queues and caches. Users can unlock with a vault password and, where the device enforces strong biometrics through Android Keystore, opt into biometric key access. Password recovery remains necessary. The feature targets the OpenCloud Web rclone-crypt profile; it does not guess alternate rclone modes.

The beta includes online browsing and internal text, image and PDF viewing; encrypted text editing; encrypted folder scanning; same-vault file operations; encrypted-location management; and read-only offline snapshots. Secure scanner output is temporary app-private data and uses the encrypted session upload path, not the ordinary persistent upload queue. Offline snapshots store ciphertext and protected metadata. External-app opening is an explicit plaintext handoff with a warning, read-only URI grant, bounded new-access lifetime and best-effort cleanup.

These features have been exercised with synthetic fixtures and emulator tests, with owner acceptance on the Pixel test build. Automated evidence is not a security certification or a guarantee for every OpenCloud installation, Android device or external app. See [testing](TESTING.md) and the [security review](ENCRYPTED-SECURITY-REVIEW.md) for evidence and limits.

## Interoperability contract

The target is the OpenCloud Web v8.0.0 rclone-crypt profile used by OpenCloud 8.0.1: scrypt `N=16384, r=8, p=1`, 80 derived key bytes, AES-256 EME encrypted names, and `RCLONE\0\0` content files with 64-KiB XSalsa20-Poly1305 blocks. The integrity UUID property is used as password proof only when it contains nonempty authenticated content. Android streams blocks and authenticates each complete block before exposing its plaintext.

The codec has independent Web and rclone interoperability fixtures. The code supports the compatible profile only. Non-default password2, alternate filename modes and alternate encodings are not supported. Other OpenCloud/server versions and administrator-customized Web deployments require separate compatibility verification.

The format authenticates content blocks, not the complete file, path, final length or version. It cannot by itself detect every rollback, whole-block tail removal or valid same-key file substitution. Names and metadata such as file sizes, timestamps, hierarchy, root labels and membership may remain visible. Do not describe ETags or offline manifests as protection against a malicious server rewriting all associated metadata.

## Protection boundaries

Vault passwords derive encryption keys locally and are not sent to the server by Raiun. OAuth credentials separately authorize server operations. Optional biometric access wraps derived key material with Android Keystore and requires strong, hardware-enforced biometric authorization; unsupported devices retain password-only access. Unlocked keys and decrypted previews are held in memory for the active session. Buffer clearing is best-effort and does not guarantee erasure from managed-runtime memory or platform rendering buffers.

Offline data contains encrypted file blobs and identity-bound protected metadata. Root existence and labels can remain visible for navigation. Removing a server share cannot revoke keys or copies that a user already obtained. Local deletion unlinks files but is not forensic erasure from flash storage.

An external app can read the plaintext copy during the handoff and can save, share or back it up. The bounded URI expiry denies future opens; Android cannot revoke an already-open descriptor or erase a recipient's copy. Use internal viewing when external plaintext exposure is unacceptable.

## Not included in this beta

- Cross-vault, vault-to-ordinary and ordinary-to-vault copy or move.
- Public links, per-child sharing, encrypted DocumentsProvider access and server-side Office editing.
- Background-resumable encrypted transfers or continuing work that requires vault keys after lock or process death.
- Alternate rclone profiles, password rotation/re-encryption, and account-token storage migration.
- A claim of compatibility with every server version or a formal security audit.

Raiun's encrypted-vault security review records format limitations and the external handoff boundary in more detail. Public protocol references include the [rclone crypt format](https://rclone.org/crypt/) and [OpenCloud Web v8.0.0 vault implementation](https://github.com/opencloud-eu/web/tree/v8.0.0/packages/web-app-rclone-crypt).

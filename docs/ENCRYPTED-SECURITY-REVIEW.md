# Encrypted folders and Spaces: security review

Review date: 2026-10-06 (owner timezone). Scope: current vault-test.16 source, encryption compatibility, biometric key storage, offline files, explicit external-app handoff and cleanup. This is a focused source review plus regression tests, not an independent penetration test or certification. No claim of zero vulnerabilities is made.

## Protection and evidence

- The compatible rclone-crypt profile uses scrypt (N=16384, r=8, p=1, default Web salt), AES-EME for names, and XSalsa20-Poly1305 SecretBox for content. Each 64-KiB block is authenticated before its plaintext is emitted; nonces use SecureRandom. The 80-byte key bundle is copied defensively and explicitly cleared on session close. Existing Web-v8 and rclone known-answer tests check both directions and boundary sizes; wrong-key and altered-block tests reject content. See `core/crypto/RcloneVaultCipher.kt` and its host/native tests.
- Biometrics wrap the key bundle using AES-GCM and Android Keystore keys. Strong biometric authorization is bound to the actual cipher operation, not just a successful UI callback. Hardware enforcement is checked; unsupported devices fall back to password entry rather than weaker key storage. Associated data binds the envelope to account, server, drive and encrypted location. Biometric enrollment changes invalidate the wrapping key. Password recovery remains essential; this convenience is local to the phone.
- Offline contents remain original ciphertext. The encrypted manifest uses an identity-bound HKDF-derived AES-GCM key and stores the blob digest and expected length. Loading rejects changed blobs, wrong keys and cross-identity manifests. Account removal/revocation invalidates existing access. Public root descriptors and previously seen location labels remain available for navigation: the existence, root label and location identity are not hidden by the vault encryption. Child names/content require unlock.
- Internal image/PDF/text previews use memory, without creating the external-app plaintext files. Encrypted edits are volatile. Closing/locking drops session keys and sensitive preview state. Explicit byte-array clearing reduces exposure, but managed-runtime strings, UI bitmaps and third-party native buffers do not provide a guarantee of complete RAM erasure. A compromised/rooted OS or an app running with Raiun privileges is outside this boundary.
- Online reads check the issued source, current account/session, expected ciphertext length and available strong ETag. Short/changed transfers are rejected. This is additional transport/change detection, not a cryptographic proof that the server has never replayed older content.

## Open with: deliberate plaintext handoff

After a warning and explicit acceptance, Raiun creates a decrypted file in private no-backup storage. It gives the selected app a read-only grant through a non-exported provider using an opaque UUID URI. Registry/path validation rejects invented paths and write access. Before launch, the VM checks that the account, session, source and route generation still match. Failed and cancelled exports never receive a published lease.

Raiun attempts deletion and grant revocation on return/navigation. A monotonic ten-minute expiry denies new provider opens independently of the wall clock; WorkManager schedules physical cleanup, and startup removes interrupted exports. Test16 adds retry scheduling for failed deletion of partial exports, plus fail-closed export storage when startup cleanup cannot finish. An export-storage error no longer prevents the rest of the app from starting. Failed scheduling/storage operations can still require a later successful startup before physical deletion completes.

This file is plaintext while it exists: it is no longer protected by the vault password. Android sandbox/device storage protections apply. Deletion unlinks Raiun’s file; it is not guaranteed forensic erasure from flash. Android can delay background work, especially during force-stop or power restrictions. Ten minutes is a deadline for **new URI access**, not a guarantee of physical deletion at that instant. A receiving app can retain an already-open descriptor, save another copy, share it or back it up. Raiun cannot erase those copies. Use the internal viewer when this disclosure is unacceptable.

## Format limitations preserved for Web compatibility

The rclone format authenticates individual content blocks, not a complete file/path/version manifest. Filename encryption is deterministic and is not authenticated; file lengths, directory relationships and server metadata remain observable. A malicious server with control of both ciphertext and advertised metadata can replay valid older ciphertext, substitute a valid same-key file, or remove complete trailing blocks without violating those remaining block tags. Expected-length/ETag checks detect inconsistent transport or stale operations, not every malicious metadata rewrite. Strong, unique encryption passwords matter because an attacker with ciphertext can perform offline password guesses. These are limitations of the compatible format, not promises that Raiun can remove without changing interoperability.

## Primary references

- [rclone crypt specification](https://rclone.org/crypt/)
- [Android WorkManager scheduling and delay rules](https://developer.android.com/develop/background-work/background-tasks/persistent/getting-started/define-work)

Verification evidence and release gates are recorded in [TESTING.md](TESTING.md). Physical-device biometrics, OEM storage behavior and a third-party audit remain separate validation.

## Release dependency check

The 0.9.0 release refresh flagged four advisories against Bouncy Castle 1.81. Raiun's direct uses are scrypt and AES, rather than the reported GOST, certificate-validation, LDAP and ASN.1 paths. The release nevertheless updates to 1.85.2 and reruns interoperability and application checks. The refreshed OSV Maven inventory records the result; native/model assets remain a separate review boundary.

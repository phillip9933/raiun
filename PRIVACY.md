# Raiun privacy

Raiun is an independent Android client for OpenCloud. It is not an official OpenCloud GmbH product or service. The maintainer provides it on a best-effort basis.

Raiun connects to the server and identity provider you configure. File contents, names and account information are sent to those services when needed for your requested operations. Server administrators and identity providers control their own logging and retention. The app does not operate an analytics or advertising backend.

## Encrypted vaults

Encrypted folder and Space contents use the OpenCloud Web-compatible rclone-crypt format. The vault password derives the content and filename keys locally; it is not sent to the server by Raiun. Optional biometric access wraps a derived key with Android Keystore on this device. The password remains necessary for recovery and other devices. Account credentials authorize server requests and are separate from the vault password.

Vault files deliberately saved for offline use remain encrypted ciphertext. The local offline index protects its metadata and checks stored content before use. Some information remains visible without unlocking, including the existence and label of known roots, file sizes and server-side metadata. The compatible file format authenticates content in blocks but does not authenticate the whole file, path or final length. See [the vault security review](docs/ENCRYPTED-SECURITY-REVIEW.md) for the limits and threat boundaries.

Internal previews and edits use app memory and temporary app-private storage as needed. Explicitly opening a vault file in another app creates a temporary decrypted copy in private app storage and grants the selected app read access. Raiun attempts to revoke access and remove its copy when the handoff ends; new URI access expires after a bounded period. Android may delay physical cleanup, an app that already opened the file can retain it, and Raiun cannot remove copies the receiving app saves or shares. Screen locking cannot retract bytes already read by another app.

Ordinary uploads, downloads, offline pins and temporary files use private app storage. Files deliberately pinned offline are handled separately from temporary files and can be removed in Settings. App data and offline content are excluded from Android backup and device transfer. Uninstalling removes private app data, subject to Android storage behavior. App locking is an access control and is not separate encryption of every ordinary local file.

Scanning runs locally through the bundled scanner SDK. Secure vault scanning uses temporary output in app-private no-backup storage while the secure scan is active; scanner output is uploaded through the encrypted-vault session and is not sent through the ordinary persistent upload queue. Cancellation, locking and startup cleanup remove the temporary output on a best-effort basis. Android may retain storage blocks after deletion; this is not forensic erasure.

Avatars are fetched from your server, not Gravatar. Android may include or omit photo metadata; Raiun does not strip metadata or promise anonymization. Notifications may show filenames; Android notification settings control their visibility. Optional local diagnostics are disabled by default and use a bounded set of event types and timestamps. Disabling diagnostics clears their history.

Explicitly opening or sharing files, handing files to another app, or opening browser links transfers data or control to the recipient you choose. Those recipients have their own policies. Please exclude private documents, passwords, tokens and server logs containing secrets from public bug reports.

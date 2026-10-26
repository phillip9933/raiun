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

## App update checks

By default, Raiun checks the public GitHub releases for this project about once a day, subject to Android background scheduling. Turn automatic checks off in Settings → App updates; manual checks remain available. The check uses a separate public HTTP client and sends no OpenCloud account credentials, tokens, file names or file contents. GitHub receives ordinary connection information such as the requesting IP address and HTTP headers.

Automatic APK downloads on unmetered Wi-Fi are off by default. If enabled, GitHub and its release-asset hosting receive the APK download request. Downloads stay in the app-private update cache, separate from cloud files and vault credentials. Partial downloads are discarded on cancellation or failure; obsolete APKs are pruned. Android can also reclaim cache files.

The updater checks the package ID, newer version code, supported Android version and installed signing identity. It verifies a published SHA-256 digest when available and records a local digest for subsequent rechecks. Android performs the final package-signature checks and installation. Only an explicit foreground Install action opens the system installer; background work never installs an APK. A permission or installer return is not treated as proof of installation.

## Optional server connection preferences (unreleased)

Wi-Fi local routing can match the connected Wi-Fi name to a saved preference. Android requires precise location permission and enabled Location services to expose that name; Raiun requests permission only through the current-Wi-Fi control and does not request background location or send the Wi-Fi name to a service. Missing network information uses the public route. Preferences, including internal addresses and Wi-Fi names, stay in app-private no-backup storage.

Optional TLS client certificates use Android KeyChain. Raiun stores the selected alias, certificate fingerprint and explicitly approved HTTPS origins, not a private key or certificate password. Configured origins can observe the presented certificate and its identifying fields. The separate sign-in browser controls its own certificate access. These preferences apply to accounts sharing the same server address; removing the final account forgets Raiun's local preference but does not remove the system-managed certificate. See [server connection behavior and limits](docs/SERVER-CONNECTIONS.md).

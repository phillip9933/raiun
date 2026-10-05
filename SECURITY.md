# Raiun security

Please report vulnerabilities privately using GitHub's **Report a vulnerability** feature on this repository. Do not include credentials, private file contents, private server URLs or exploit details in a public issue. If private reporting is unavailable, open an issue asking for a private reporting channel without disclosing the vulnerability.

Raiun is an independent OpenCloud client maintained on a best-effort basis. There is no guaranteed response time, support period or security certification. Use the latest release and keep independent backups. Automated tests and source review do not establish security for every server, device, operating-system version or external application.

The encrypted-vault implementation uses the Web-compatible rclone-crypt profile and Android Keystore for optional biometric key wrapping. Its documented limits matter: file blocks are authenticated individually, while paths, final length and whole-file history are not authenticated by that format. Offline content remains ciphertext, while known root labels and some server metadata remain visible. External-app handoff deliberately exposes a decrypted copy to the receiving app, which can retain it. See [the encrypted-vault security review](docs/ENCRYPTED-SECURITY-REVIEW.md) and [privacy notice](PRIVACY.md).

Security reports should identify the affected release, Android version and device class when safe to do so. Use synthetic accounts and files; redact credentials, tokens, private URLs, filenames and personal content from diagnostics. Do not test against a server or account without authorization.

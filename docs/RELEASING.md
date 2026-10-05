# Raiun release procedure

For the 0.9.0 beta, freeze features and verify the app version name and strictly increasing version code before validation. Run the quality checks and Android emulator matrix on the exact commit intended for the release. Review all failures; do not silently waive checks. Build with development credentials empty, verify package/version, APK signature, the original release-certificate fingerprint and 16-KiB ZIP/native alignment. Publish only artifacts built from that validated commit, with release notes, known limitations, third-party notices and SHA256SUMS. A beta tag must point to the validated commit.

The emulator gate covers API 26 and API 35. Run the full connected instrumentation task list on both versions, including app, crypto, security, sync, database, documents provider, UI and files. CI results are useful evidence but do not replace the owner's supported-device acceptance. Record which checks ran, the exact revision and any remaining limitations without including private URLs or local machine paths.

## Signing on Linux

Use the original Raiun release identity so existing installations can receive updates. Keep the signing key and recovery material in an encrypted desktop wallet or other protected OS-managed storage outside the repository and outside build outputs. Unlock it locally for signing; never place a password in source, a shell command, persistent environment configuration, CI setting, issue, chat or build log. The local signer may pass a wallet credential only through a short-lived child-process environment and must clear it afterward. Do not export or copy private key material into the worktree. If the wallet cannot sign through a local provider, use a temporary protected location outside the repository and remove temporary exports after signing.

Use the locally installed Android SDK build tools to sign the release APK and verify the result against the public certificate at `docs/release-certificate.pem`. Compare the certificate fingerprint, package ID and version with the expected values before distribution. The certificate is public; its matching private key is not. This repository does not configure remote signing or upload credentials to CI.

## Windows signing (maintained alternate)

The historical PowerShell packaging helper uses a PKCS#12 keystore and a password file protected by Windows DPAPI for the creating user and machine. DPAPI-protected material is not a Linux credential format or portable backup. On Windows, keep the signing directory outside the repository, protect the keystore backup offline, and store recovery information in a password manager. Never publish the private key or password. Losing the original signing identity prevents compatible updates.

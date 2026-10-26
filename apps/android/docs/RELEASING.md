# Raiun Android release procedure

Run build and packaging commands from `apps/android`. See the [coordinated release procedure](../../../docs/RELEASING.md) for platform-specific tags and independent Android and desktop releases.

For each release, freeze features and verify the app version name and strictly increasing version code before validation. Run the quality checks and Android emulator matrix on the exact commit intended for the release. Review all failures; do not silently waive checks. Build with development credentials empty, verify package/version, APK signature, the original release-certificate fingerprint and 16-KiB ZIP/native alignment. Publish only artifacts built from that validated commit, with release notes, known limitations, third-party notices and SHA256SUMS. A release tag must point to the validated commit.

The emulator gate covers API 26 and API 35. Run the full connected instrumentation task list on both versions, including app, crypto, security, sync, database, documents provider, UI and files. CI results are useful evidence but do not replace the owner's supported-device acceptance. Record which checks ran, the exact revision and any remaining limitations without including private URLs or local machine paths.

## Signing on Linux

Use the original Raiun release identity so existing installations can receive updates. Keep the signing key and recovery material in an encrypted desktop wallet or other protected OS-managed storage outside the repository and outside build outputs. Unlock it locally for signing; never place a password in source, a shell command, persistent environment configuration, CI setting, issue, chat or build log. The local signer may pass a wallet credential only through a short-lived child-process environment and must clear it afterward. Do not export or copy private key material into the worktree. If the wallet cannot sign through a local provider, use a temporary protected location outside the repository and remove temporary exports after signing.

Use the locally installed Android SDK build tools to sign the release APK and verify the result against the public certificate at `docs/release-certificate.pem`. Compare the certificate fingerprint, package ID and version with the expected values before distribution. The certificate is public; its matching private key is not. This repository does not configure remote signing or upload credentials to CI.

## Windows signing (maintained alternate)

The historical PowerShell packaging helper uses a PKCS#12 keystore and a password file protected by Windows DPAPI for the creating user and machine. DPAPI-protected material is not a Linux credential format or portable backup. On Windows, keep the signing directory outside the repository, protect the keystore backup offline, and store recovery information in a password manager. Never publish the private key or password. Losing the original signing identity prevents compatible updates.

## In-app Android updates

The engine is an explicitly pinned standalone library; see [ownership, artifact pins and library upgrade procedure](APP-UPDATES.md). Release rules below are Raiun’s configuration, not library-wide branding.

The updater reads this repository's public release list and selects Android releases only. Publish a release with tag `android-v<version>` and exactly one signed universal APK named `raiun-android-<version>.apk`. Do not attach debug, test or unsigned APKs to that release. The APK version name must match the tag suffix. Its version code must increase across all distributed builds, including beta builds, and it must retain the original application ID and release signing identity.

Mark beta tags such as `android-v1.0.1-beta.1` as GitHub prereleases. The Stable channel excludes prereleases; Stable and beta selects the highest eligible semantic version. Changing channels never authorizes a downgrade. Desktop tags and assets are excluded. Legacy `v0.9.3` is recognized only as a migration fallback.

GitHub asset metadata supplies a SHA-256 digest for current uploads. Keep SHA256SUMS for independent manual verification as well. The updater streams into a private partial file, checks exact size and any advertised digest, validates APK metadata/signers, and publishes a verified cache file. It repeats the verification immediately before opening Android's installer. A different signing identity must produce a clear rejection; never advise uninstalling the app to make an update install.

## Dependency maintenance

Gradle's `gradle/verification-metadata.xml` pins downloaded dependency artifacts and metadata, including the build and test components resolved during validation. `:app:verifyReleaseRuntimeArtifacts`, required by `preBuild`, separately checks release runtime binaries against `gradle/runtime-artifact-pins.sha256`. The vendored updater also has an exact bundle-file inventory and source/archive pins.

When updating a dependency, independently compare its proposed hashes with publisher artifacts or published module hashes before changing these files. Generating checksums from the local cache alone does not establish provenance. Do not disable verification or add blanket trust rules to make a build pass. Update the runtime notices and dated advisory/provenance evidence in `docs/release-audit/`, then run the normal release gates. The recorded provenance report identifies the exact verification-file digest it covers; refresh it when that file changes. Hash matching establishes byte identity with the recorded publisher data, not that a dependency is free of vulnerabilities.

For acceptance, test a production-signed older installation with a newer signed release, decline and grant Android's install-from-Raiun permission, cancel the system installer, cancel/interruption/retry during download, and switch stable/beta channels. Confirm that accounts, encrypted unlock preferences, offline files, transfers and backups survive. APK installer behavior and real signing verification still need supported-device acceptance; pure host tests do not establish these outcomes.

# Raiun

An independent Android client for OpenCloud. It is not an official OpenCloud GmbH product, release, or supported client.

## About this project

I build projects to solve problems I run into in my own life. I share them because I believe in open source and hope others can learn from them, adapt them or find them useful.

Making it public does not mean it is a polished production product or suitable for every setup. Please read the documented limitations and decide whether it fits your needs. I'm happy to help where I can, but I can't promise a support schedule.

## Features

- Personal files and project Spaces, search, favorites, recents and offline access.
- Uploads, downloads, copy/move, sharing links and Android file-picker integration.
- End-to-end encrypted folders and Spaces using a Web-compatible rclone crypt format. Unlock with the encryption password; optionally store a biometric unlock key on the phone.
- Keep encrypted folders or files offline for later password-authenticated access. Offline copies remain ciphertext on the device.
- Encrypted folder and Space locations remain in their normal browser views when offline; without saved content, an item is visible but unavailable until you connect and save it offline.
- Encrypted image, PDF and text previews decrypt only in memory. Larger previews use a temporary encrypted cache; large text files can be viewed and edited in sections.
- Scan PDFs and JPEGs directly into an encrypted folder or Space. Encrypted copy and move browse destinations within the same encrypted location.
- Explicit “Open with” handoff to another app is available after a warning. It creates a temporary plaintext file; see the security limits below before using it.
- Folder/camera backup with custom date-based destination folders, per-backup file and folder exclusions, pause controls and optional biometric/device locking.
- Video thumbnails from supported server previews or local files, including encrypted locations.
- Cloud folders for other apps, built-in text/PDF/image viewers and file version history.
- File and folder activities showing changes reported by the server.
- Home screen folder shortcuts with color choices and custom images.
- Shared-folder downloads, server notifications and Space member management.
- English and German, with an independent app-language choice and grouped Appearance settings.
- PDF/JPEG scanning through a pinned, separately versioned [offline scanner SDK](https://github.com/phillip9933/open-android-doc-scanner).

## Install

Download the 0.9.2 beta APK from [GitHub Releases](https://github.com/phillip9933/raiun/releases), read the [0.9.2 beta release notes](docs/RELEASE-NOTES-0.9.2.md), and verify the APK against the attached SHA256SUMS file. Install over an existing Raiun release to keep its app data. Raiun is still beta; please report problems through the project's issue tracker. The previous OpenCloud Android Next release downloads have been retired.

## Build and test

Use JDK 21, Android SDK 36 and the included Gradle wrapper. First install the checksum-pinned scanner artifacts:

```sh
python scripts/install_offline_scanner_sdk.py
./gradlew ktlintCheck detekt testDebugUnitTest :app:verifyRoborazziDebug :app:lintRelease :app:assembleRelease
```

On Windows use `gradlew.bat`. Release builds contain no development credentials and are unsigned until the maintainer signs them. See [release procedure](docs/RELEASING.md), [privacy](PRIVACY.md), [security reporting](SECURITY.md) and [third-party notices](THIRD-PARTY-NOTICES.md).

Translations use Android resource files. Missing translations fall back to English; new languages are deferred during the beta freeze.

## Known beta limitations

- Encrypted storage follows the Web-compatible rclone crypt format. It authenticates content blocks, but the format does not authenticate filenames or a complete file manifest. Server metadata can be observed, and a malicious server can replay valid older ciphertext or alter metadata in ways the format cannot detect. See the [encrypted security review](docs/ENCRYPTED-SECURITY-REVIEW.md#format-limitations-preserved-for-web-compatibility).
- Encrypted location identity and root labels may be visible while locked so locations can be listed; child names and file contents require unlock.
- Encrypted previews have no fixed file-size limit. Available device storage, supported file formats and decoder capabilities still apply; large text files are edited one section at a time.
- “Open with” sends a temporary plaintext file to another app only after confirmation. Raiun revokes access and attempts cleanup on return; Android may delay physical deletion, and another app can retain an open descriptor or make its own copy. Deletion is not guaranteed forensic erasure.
- Keep the encryption password as your recovery method. The security review is a focused source review, not an independent penetration test or certification.
- HTTP 502/timeouts have been observed on some server/network paths, particularly when network stability is inconsistent.
- External editor, Office/server integrations and some Android document-provider combinations have not been fully tested.
- Folder backup queues uploads; it is not a bidirectional mirror and does not delete source files. Changed destination names can require conflict resolution.
- Exclusions apply during future scans. They do not remove files already in the cloud, and uploads already queued may still finish after you pause a backup.
- Metadata comes from Android's supplied file representation; Raiun does not guarantee removal or preservation of GPS or other metadata.

The project is provided without warranties; test your server and workflow before relying on it.

## Contribute

Start with [Contributing](CONTRIBUTING.md) for setup, change boundaries and reporting. The [documentation index](docs/README.md) links to the current layout, tests and release procedure.

## AI usage

I use AI tools to help with development, including analysis, code, tests and documentation. I care about security, privacy and protecting people's data, and I try to reflect that in how I build these projects.

I document validation and known limitations so you can assess the evidence for yourself. Contributions should disclose material AI assistance and distinguish checks actually run from checks still needed.

See [beta limitations](#known-beta-limitations), [testing guidance](docs/TESTING.md) and [contribution guidance](CONTRIBUTING.md#ai-usage).

## Source licensing

Licensed under the [GNU Affero General Public License version 3 (AGPL-3.0-only)](LICENSE). See [NOTICE](NOTICE). Third-party components retain their own licenses and notices. The license does not grant rights to third-party trademarks.

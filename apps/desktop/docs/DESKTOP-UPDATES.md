# Raiun Desktop updates

Raiun Desktop checks the public `phillip9933/raiun` GitHub releases once a day
while the app is open. A manual check bypasses the daily limit. The selected
channel is stored locally (`beta` by default for this beta build). “Later” hides
one exact release tag; a later tag is shown normally. The app never downloads
or installs an update without an explicit click.

The release list is filtered to strict `desktop-v<SemVer>` tags. Android and
other monorepo releases are ignored. The selected tag is used to build the
exact `desktop-update.json` URL; the GitHub `/latest` endpoint is not used. A
manifest is accepted only when its version equals the selected tag, it contains
the current OS, architecture, and installed bundle type, and its package URL
matches an asset listed on that same release. Redirects must remain HTTPS and
end at a small fixed set of GitHub release hosts.

The update package is bounded, downloaded only after the user chooses Download,
and verified with the pinned Tauri updater using the embedded public key. The
signature must bind to the announced version, and downgrades are disabled.
The verified package is kept in a bounded in-memory cache until the app closes;
the app stores only automatic-check preference, channel, last-check time, and
the one dismissed tag on disk. Closing the app discards the package, so it must
be downloaded again before a later install.

Install is a separate user action. Raiun first sets the existing shutdown latch,
asks the agent to stop, confirms the control socket is gone, and confirms the
owned agent process exited. If any check fails, the installer is not started and
the app reports the error. Linux restarts only after Tauri reports installation
success. Windows uses the standard Tauri NSIS updater bundle.

## Version numbering and the compatibility bridge

Desktop numeric versions beginning with `0` belong to the Beta channel: for
example `0.7.4`. The second number identifies the beta revision and the third
identifies its update. These releases must still have GitHub's prerelease flag
set. Stable-channel checks exclude the entire `0.x` line; `1.x` numeric releases
use the Stable channel. Legacy hyphenated prerelease tags remain recognized.
GitHub's flag must agree with this classification.

`0.7.0-beta.3` is the final legacy-format bridge release. Existing beta.2 clients
require the GitHub prerelease flag to match a hyphenated SemVer suffix, so they
can discover this bridge automatically. The bridge recognizes later numeric
beta releases, such as `desktop-v0.7.4`, without a manual reinstall. Retain the
bridge release so older clients can upgrade through it.

## Release asset contract

Each supported Desktop release must publish `desktop-update.json` and its
signed update package as assets on that exact `desktop-v...` release. The
manifest follows Tauri's version 2 static manifest shape:

```json
{
  "version": "1.2.3",
  "notes": "Plain text release notes",
  "platforms": {
    "linux-x86_64-appimage": {
      "url": "https://github.com/phillip9933/raiun/releases/download/desktop-v1.2.3/raiun-desktop-1.2.3-linux-x86_64.AppImage",
      "signature": "<Tauri signature text>"
    },
    "windows-x86_64-nsis": {
      "url": "https://github.com/phillip9933/raiun/releases/download/desktop-v1.2.3/raiun-desktop-1.2.3-x64-setup.nsis.zip",
      "signature": "<Tauri signature text>"
    }
  }
}
```

The names above illustrate the expected bundle suffix; the manifest URL must
name the exact release asset. Debian packages use the `linux-<arch>-deb` target
and `.deb` package. AppImages use `.AppImage`; Windows NSIS updates use
`.nsis.zip`. Tauri signatures must be generated from the exact updater bytes,
and the signed version must equal the manifest version. Ordinary builds leave
`createUpdaterArtifacts` false, so unsigned beta/package builds do not try to
produce updater artifacts. The static
`desktop-shell/src-tauri/tauri.updater-release.conf.json` overlay enables
artifact generation only for an explicit artifact or release build. Official
Linux and Windows packaging scripts load the trimmed public key from
`desktop-shell/update-public-key.pub` when `RAIUN_DESKTOP_UPDATE_PUBKEY` is
unset; a nonempty environment value overrides it for test or fork builds. The
public key is not secret. Artifact-only mode (`RAIUN_DESKTOP_UPDATER_ARTIFACTS=1`
or `-UpdaterArtifacts`) embeds the public key and emits updater-format
packages without requiring or reading a private key. Those packages are
recorded as unsigned and cannot be installed through the updater until a
separately authorized host signing step. Release mode additionally requires the authorized private
signing key through `TAURI_SIGNING_PRIVATE_KEY_PATH` and signs the final
package bytes; private key material must stay outside isolated build VMs.

For Linux AppImage releases, sign the exact final `.AppImage` bytes after any
repack step; any later repack invalidates that signature. For Windows, publish
the standard Tauri NSIS updater `.nsis.zip` artifact and its matching signature.
Do not substitute the setup `.exe` or create a separate unsigned zip.

The public key is embedded in the app and is not a secret. If no public key,
manifest, or matching platform package is available, the app marks
automatic installation unavailable and offers the fixed GitHub release page
for manual downloads. It never falls back to unsigned installation.

The published `desktop-v0.7.0-beta.1` application predates these update controls;
users of that build must install the first updater-capable release manually.
That release also has no updater manifest or signed updater package, so the
new candidate cannot offer it as an installable update. Signed-package
verification and native package upgrade checks remain necessary before release. The owner-authorized dedicated
Desktop key is stored outside Git and build VMs; Desktop 0.7.4 publishes matching version-bound signed packages and metadata
for Linux and Windows. Earlier withdrawn Windows beta.2/beta.3 assets remain
unavailable; use the current Windows setup installer for a manual in-place update when needed.

## Preparing release metadata

Ordinary package builds remain unsigned. The explicit updater-release paths
load the checked-in public key and require an independently authorized
`TAURI_SIGNING_PRIVATE_KEY_PATH` for signing. Linux opts in with
`RAIUN_DESKTOP_UPDATER_RELEASE=1`; Windows uses `-UpdaterRelease`.
Windows retains its existing Authenticode policy and separately stages the
version-bound NSIS updater archive. No signing key is supplied by this source.

After the final AppImage and NSIS updater archive have been signed, run the
offline metadata helper with their exact files and adjacent signatures:

```sh
python3 scripts/desktop_update_manifest.py \
  --tag 'desktop-v<version>' \
  --linux-package '<final.AppImage>' --linux-signature '<final.AppImage.sig>' \
  --windows-package '<final.nsis.zip>' --windows-signature '<final.nsis.zip.sig>' \
  --notes-file '<release-notes.txt>' \
  --manifest-out '<new-directory>/desktop-update.json' \
  --inventory-out '<new-directory>/desktop-update-inventory.json'
```

The helper checks the Desktop tag, supported target names, bounded regular
inputs and unique release asset names. It inventories exact package, signature
and manifest hashes and refuses to replace outputs. It does not verify
signatures cryptographically or publish assets. The updater verifier and native
package acceptance must still validate the exact artifacts before release.

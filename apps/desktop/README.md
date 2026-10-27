# Raiun Desktop

An OpenCloud desktop client for Linux and Windows with a Rust background engine, a Tauri
tray/settings UI, and a separate filesystem root per account:

```
OpenCloud/
  Personal/
  Spaces/
    Team space/
```

**Desktop 0.7.4 Beta for Linux and Windows x86_64 is prepared for release.** Final package checks and publication are pending. Source is in the Raiun monorepo at `apps/desktop`, alongside Android at `apps/android`; each app has its own version and build. Linux and Windows share the Desktop version. The release will use the [Desktop 0.7.4 Beta page](https://github.com/phillip9933/raiun/releases/tag/desktop-v0.7.4) after publication. macOS is not released.

The 0.7.4 numeric version remains on the Beta update channel. Compatible installed clients can check for releases and explicitly download/install verified updates; see [Desktop updates](docs/DESKTOP-UPDATES.md) for channels and trust.

The app provides an OpenCloud drive, folder sync, offline caching, encrypted file access, account controls, transfers and recovery. The Sync Folders workspace presents ordinary sync folders and upload-only media folders together; Sync Folders supports two-way and one-way directions, Photos/Videos filters and editable exclusions. Settings include Light/Dark/System themes, per-account colors, account rename/removal/restore and grouped storage, network and security controls. Windows uses an in-place installer upgrade by default. The owner verified the reconnect fix with both the Default and a newly added Windows account. These checks do not certify every native account/file-manager workflow or all advanced encrypted/offline behavior. Media import runs remain bounded by documented stability, file-size and conflict rules; source files stay in place and older cloud versions are not automatically retained. See the [beta changelog](CHANGELOG.md), [Sync Folders guide](docs/SYNC-FOLDERS.md) and [acceptance records](docs/MVP-ACCEPTANCE.md).

## Screenshots

Browser layout previews of the Desktop interface; no account connected. These show the themes, not a running native connection.

| Light | Dark |
| --- | --- |
| <img src="https://raw.githubusercontent.com/phillip9933/raiun/main/docs/screenshots/desktop-light.png" alt="Desktop light interface" width="420"> | <img src="https://raw.githubusercontent.com/phillip9933/raiun/main/docs/screenshots/desktop-dark.png" alt="Desktop dark interface" width="420"> |

## Components

- `raiun-core`: configuration validation, cloud backend contracts, namespace names.
- `raiun-opencloud`: Graph discovery and conditional streaming WebDAV operations.
- `raiun-engine`: SQLite inventories, baselines, verification, and transfer history.
- `raiun-agent`: local control socket, background scheduler, browser sign-in, keyring.
- `raiun-fuse`: Linux filesystem adapter with local write spooling.
- `raiun-cli`: offline configuration commands and bounded media-destination
  preview from an explicit JSON manifest, plus a bounded local `media-scan`
  command. Neither imports, renames, or uploads files.
- `desktop-shell`: Tauri 2 native tray with account settings, the unified Sync Folders
  workspace, conflict review, saved-copy recovery and transfers.
- `raiun-vault`: streaming vault encryption/decryption, scoped unlock lifecycle,
  and portable directory validation. Explicit encrypted folder pairs use a
  separate verified backend; ordinary sync and the on-demand mount retain
  encrypted-area guards. See [encrypted sync](docs/ENCRYPTED-SYNC.md).

## Build and test

Install Rust stable, Node.js/npm, GTK 3, WebKitGTK 4.1, Ayatana AppIndicator,
FUSE 3, Zenity, and Secret Service tools. On Arch Linux the additional UI packages are
`webkit2gtk-4.1`, `libayatana-appindicator`, and `zenity`; keyring access uses `secret-tool`.
Zenity is required for confirmation dialogs with the Linux dialog backend.
A running, unlocked desktop Secret Service is required to persist credentials.

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
scripts/build-linux.sh
```

The build script produces a portable directory and tarball under `target/`.
Extract the tarball and run its `install.sh` to install to the current user's
application directory. Dependencies remain system packages; the tarball is not
an AppImage and does not bundle GTK/WebKit. No installation, autostart, mount,
or sign-in occurs just by compiling it.

New Linux bundles include an inert `manifest.txt` with UTC build time, Git
commit/dirty status, and hashes of the three executables and icon. The installer
validates the fixed manifest and staged payloads before replacing files, then
installs the manifest beside them. `bash scripts/test-linux-installer.sh` tests
rejection and preservation using temporary synthetic bundles. These unsigned
hashes detect corruption or mismatch; they do not authenticate the publisher.
Commit plus dirty status is not a reproducible identity for uncommitted source.

## AppImage

An x86_64 AppImage is provided with the [Desktop 0.7.4 Beta release](https://github.com/phillip9933/raiun/releases/tag/desktop-v0.7.4) after publication. It targets Ubuntu 24.04-era systems (glibc 2.39 or newer), bundles the interface and background agent, and uses the same existing account/settings locations. Cloud-drive mounting still needs system FUSE 3; persistent sign-in needs a desktop keyring. See [AppImage setup](docs/APPIMAGE.md) for launch, startup and integration details.

## Development operation

`raiun-agent serve` runs the per-user agent. The installed shell starts its
sibling agent if needed. Agent state defaults to
`$XDG_STATE_HOME/raiun-desktop` (otherwise `~/.local/state/raiun-desktop`);
`RAIUN_STATE_DIR` overrides it for isolated tests. Secrets reside in the OS
keyring, not settings JSON or SQLite. `raiun-agent request '<JSON>'` is a local
control diagnostic; never send credentials through it.

Folder-pair deletion propagation is currently conservative: missing baseline
items and conflicting edits require attention. The cloud mount is a separate
projection; local folder pairs cannot overlap it. `media-preview` is a bounded offline CLI planner. The unified Sync Folders workspace also configures recurring upload-only media jobs. Each source stays in place; staged stability checks and explicit conflict review govern uploads. Full native media restart acceptance remains outside the claims made here.

Read [architecture](docs/ARCHITECTURE.md),
[language decision](docs/LANGUAGE-DECISION.md), and
[implementation status](docs/IMPLEMENTATION.md) for rationale and limitations.
See the [desktop feature roadmap](docs/DESKTOP-FEATURE-ROADMAP.md),
[media design](docs/MEDIA-SYNC-DESIGN.md), and
[encryption interoperability limits](docs/ENCRYPTION-INTEROP.md) for planned work.


### Desktop 0.7.4 Beta release preparation

This numeric `0.7.4` release is a Beta for Linux and Windows. The release page
is prepared, but publication remains pending the final package gates. It includes
Windows in-place upgrades, dedicated Offline files and Encrypted files
workspaces, one combined Sync Folders workspace, account-scoped appearance and
controls, and the reconnect fixes verified with Default and newly added Windows
accounts. The older beta.2/beta.3 Windows downloads remain withdrawn.

Account removal preserves local files and recovery copies while revoking saved
sign-in and remembered vault-password access; the profile can be restored and
must be signed in again. Permanent deletion of Raiun-managed local copies is not
included. Native workflow gaps and broader advanced encrypted/offline acceptance
remain documented in [MVP acceptance](docs/MVP-ACCEPTANCE.md).

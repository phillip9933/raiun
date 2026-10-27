# Raiun Desktop

> **Windows beta withdrawn — 27 October 2026.** Windows beta.2 and beta.3 installers and updater packages have been removed while a reported sign-in/reconnection failure affecting both Default and newly added accounts is investigated. Linux downloads and Linux update support remain available. Earlier Windows acceptance notes describe synthetic checks and do not establish resolution of this deployment issue.

An OpenCloud desktop client for Linux and Windows with a Rust background engine, a Tauri
tray/settings UI, and a separate filesystem root per account:

```
OpenCloud/
  Personal/
  Spaces/
    Team space/
```

**Desktop 0.7.0-beta.3 for Linux and Windows x86_64.** Source and packages are part of the Raiun
monorepo at `apps/desktop`, alongside Android at `apps/android`. Each app has its
own version and build. Linux and Windows share the same Desktop version;
macOS is not released. Download the AppImage or Windows setup installer from the
[Desktop beta release](https://github.com/phillip9933/raiun/releases/tag/desktop-v0.7.0-beta.3).

Beta.1 users must install beta.2 manually once. Beta.2 adds automatic or manual
GitHub release checks with dismissible notices and explicit signed Download/Install
controls. See [Desktop updates](docs/DESKTOP-UPDATES.md) for channels and trust.
Beta.3 bridges the legacy version format to future numeric Beta releases such as
`0.7.4`; numeric `0.x` releases remain on the Beta channel.

The app provides an OpenCloud drive, folder sync, offline caching, encrypted
file access, account controls, transfers and recovery UI. Focused tests cover
account-scoped dirty-edit recovery/reconciliation, selected filesystem paths,
startup settings and package installation. Native account-selector/file-manager
workflows, disconnect confirmation, media upload/deduplication/restart and some
advanced encrypted/offline controls remain unverified. Media preview and backup
job creation were observed; a click alone is not proof of an upload. See the
[beta changelog](CHANGELOG.md) and [acceptance records](docs/MVP-ACCEPTANCE.md).

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
- `desktop-shell`: Tauri 2 native tray with TypeScript account settings, folder-pair,
  conflict-review, saved-copy recovery, transfers, and media-backup UI.
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

An additional x86_64 AppImage is available from the [Linux beta release](https://github.com/phillip9933/raiun/releases/tag/desktop-v0.7.0-beta.3). It targets Ubuntu 24.04-era systems (glibc 2.39 or newer), bundles the interface and background agent, and uses the same existing account/settings locations. Cloud-drive mounting still needs system FUSE 3; persistent sign-in needs a desktop keyring. See [AppImage setup](docs/APPIMAGE.md) for launch, startup and integration details.

## Development operation

`raiun-agent serve` runs the per-user agent. The installed shell starts its
sibling agent if needed. Agent state defaults to
`$XDG_STATE_HOME/raiun-desktop` (otherwise `~/.local/state/raiun-desktop`);
`RAIUN_STATE_DIR` overrides it for isolated tests. Secrets reside in the OS
keyring, not settings JSON or SQLite. `raiun-agent request '<JSON>'` is a local
control diagnostic; never send credentials through it.

Folder-pair deletion propagation is currently conservative: missing baseline
items and conflicting edits require attention. The cloud mount is a separate
projection; local folder pairs cannot overlap it. `media-preview` is a bounded offline CLI planner. The UI also configures
recurring upload-only media jobs; full native upload/deduplication/restart
acceptance remains unverified for this beta.

Read [architecture](docs/ARCHITECTURE.md),
[language decision](docs/LANGUAGE-DECISION.md), and
[implementation status](docs/IMPLEMENTATION.md) for rationale and limitations.
See the [desktop feature roadmap](docs/DESKTOP-FEATURE-ROADMAP.md),
[media design](docs/MEDIA-SYNC-DESIGN.md), and
[encryption interoperability limits](docs/ENCRYPTION-INTEROP.md) for planned work.

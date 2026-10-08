# Raiun Desktop

A Linux-first OpenCloud desktop client with a Rust background engine, a Tauri
tray/settings UI, and one filesystem root:

```
OpenCloud/
  Personal/
  Spaces/
    Team space/
```

**Status: MVP integration in progress.** Linux OAuth and Graph access, expiration
refresh, session and mount restoration, explicit unmount/remount, FUSE
operations, and both conflict choices have passed installed acceptance checks.
The saved-copy recovery endpoint and offline `media-preview` sample also passed
against the installed build. Manual close-X/tray-click behavior, recovery-panel
interaction, and actual desktop-session autostart remain unverified. Anonymous
WebFinger discovery returned client `opencloud` with scopes
`openid profile email`, without `offline_access`; the verified authenticated
deployment uses manual client `OpenCloudDesktop`. Automatic-client callback
compatibility is unverified for this deployment and is not an MVP gate. See [MVP
acceptance](docs/MVP-ACCEPTANCE.md). Do not use development builds as the only
copy of important files.

The desktop project has its own repository and local folder, separate from
Raiun Android. One repository owns shared Rust components and platform adapters.
Windows and macOS adapters are planned; Linux support does not imply they ship.

## Components

- `raiun-core`: configuration validation, cloud backend contracts, namespace names.
- `raiun-opencloud`: Graph discovery and conditional streaming WebDAV operations.
- `raiun-engine`: SQLite inventories, baselines, verification, and transfer history.
- `raiun-agent`: local control socket, background scheduler, browser sign-in, keyring.
- `raiun-fuse`: Linux filesystem adapter with local write spooling.
- `raiun-cli`: offline configuration commands and bounded media-destination
  preview from an explicit JSON manifest (no file scanning or cloud access).
- `desktop-shell`: Tauri 2 native tray with TypeScript settings, folder-pair,
  conflict-review, on-demand saved-copy recovery, and transfer UI.

## Build and test

Install Rust stable, Node.js/npm, GTK 3, WebKitGTK 4.1, Ayatana AppIndicator,
FUSE 3, and Secret Service tools. On Arch Linux the additional UI packages are
`webkit2gtk-4.1` and `libayatana-appindicator`; keyring access uses `secret-tool`.
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

## Development operation

`raiun-agent serve` runs the per-user agent. The installed shell starts its
sibling agent if needed. Agent state defaults to
`$XDG_STATE_HOME/raiun-desktop` (otherwise `~/.local/state/raiun-desktop`);
`RAIUN_STATE_DIR` overrides it for isolated tests. Secrets reside in the OS
keyring, not settings JSON or SQLite. `raiun-agent request '<JSON>'` is a local
control diagnostic; never send credentials through it.

Folder-pair deletion propagation is currently conservative: missing baseline
items and conflicting edits require attention. The cloud mount is a separate
projection; local folder pairs cannot overlap it. `media-preview` is a bounded
offline planner rather than an importer; media workflow extensions remain future
work.

Read [architecture](docs/ARCHITECTURE.md),
[language decision](docs/LANGUAGE-DECISION.md), and
[implementation status](docs/IMPLEMENTATION.md) for rationale and limitations.

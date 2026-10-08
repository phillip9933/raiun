# Desktop implementation status

Updated 9 October 2026 (Tokyo). Raiun Desktop is a Linux-first integration
build with working protocol, engine, agent, FUSE, CLI, and Tauri shell
components. OAuth, Graph discovery, keyring recovery, a real FUSE mount, and
isolated live file and folder-pair operations now work. The latest installed
build restored its saved session and mount and passed explicit unmount/remount,
recovery endpoint, media-preview, and both live conflict-choice checks. Manual
window interaction and actual session-login autostart remain unverified; this is
not an MVP completion claim.
See [MVP acceptance](MVP-ACCEPTANCE.md) for verified checks and outstanding
gates.

## Current implementation

- `raiun-core` defines the versioned folder-pair configuration, path validation,
  namespace labels, and cloud-backend data contracts. `raiun-cli` retains the
  initial offline configuration and validation commands.
- `raiun-opencloud` implements Graph/Spaces discovery and streaming WebDAV
  operations, including conditional writes, permission and encrypted-area
  checks, bounded response handling, and revision verification. Metadata calls
  use a 120-second timeout. Body transfers use a total deadline of 120 seconds
  plus `ceil(bytes / 256 KiB)`, capped at 24 hours. This is not an idle timeout;
  transfers are not resumable, and cancellation is observed at operation
  boundaries or when the deadline expires.
- `raiun-engine` stores inventories, baselines, and transfer outcomes in
  SQLite. Folder-pair scans stage local and remote entries in bounded batches
  and reconcile through indexed pages. Writes are verified and conditional;
  missing content is not treated as deletion. A sync-pause flag stops work at
  scan and reconciliation boundaries. Clean provider reads use temporary
  snapshots; persistent cache data is separate. The local hash cache reuses a
  hash only on ext4, Btrfs, XFS, or tmpfs when device, inode, size, and
  nanosecond mtime/ctime match; it audits cached entries every 120 scans and
  hashes fully on other filesystems. Pre-write and conflict checks still hash
  current file contents. The Linux fingerprint includes ctime nanoseconds and
  cache reuse is disabled when ctime nanoseconds are zero, avoiding coarse
  ext2/3 timestamps. The cache adds metadata/SQLite work while avoiding reads
  of unchanged file contents. On tmpfs, a synthetic 512 MiB library averaged
  554 µs for 117 warm scans versus 242 ms for a forced full-hash audit, with
  no transfer bytes; the 1,748 ms cold initial sync is not directly comparable.
  The million-empty-file warm example measured 19,722 ms with cache versus the
  earlier pre-cache 14,004 ms baseline, showing metadata overhead on a
  listing-dominated workload; no new RSS sample was collected. Installed
  cache performance on representative non-synthetic workloads remains
  unmeasured.
- `raiun-agent` owns the per-user Linux control socket, account state, scheduler,
  OAuth PKCE flow, and keyring integration. The Tauri shell and agent's
  diagnostic request command use typed control requests; `raiun-cli` provides
  offline configuration plus `media-preview`, which plans destinations from a
  bounded, already classified JSON manifest without source scanning or network
  access. OAuth authorization and Graph Spaces discovery
  succeeded against the target instance on 9 October 2026 (Tokyo time), and the
  saved session restored after an agent restart. True expiration-driven refresh
  advanced the stored refresh timestamp while the account remained connected.
  WebFinger discovery has protocol coverage and a live anonymous check: blank
  client ID discovers `opencloud` with `openid profile email`, and the scope
  parser handles the returned scope string. The target server's discovered
  client does not advertise `offline_access`; the verified authenticated session
  uses the manual `OpenCloudDesktop` client and refresh. Automatic-client
  callback compatibility remains unverified for this deployment, but is not an
  MVP gate.
- `raiun-fuse` exposes one Linux root with Personal and Spaces. It verifies
  revisions, persists dirty writes in a local spool, and retains recovery data
  after failed uploads. The disposable host-mount test passed. On 9 October
  (Tokyo time), live mounted read and rename passed after the snapshot fix, and
  fresh-file create, overwrite, read, and delete passed after the atomic-truncate
  fix; the `O_CREAT`-on-existing-file regression is fixed and the full checks
  pass. In the isolated synthetic Personal folder
  `Raiun-MVP-Acceptance-88d932bcf2`, a 25-byte upload was verified; the folder
  pair was removed, but the folder and
  earlier failed-open recovery copy `renamed.txt` remain. Protect that copy from
  truncation. Encryption and cross-Space moves remain unsupported.
- `desktop-shell` is a separate Tauri 2 Cargo package with a compact TypeScript
  settings, folder-pair, conflict-review, saved-copy recovery, and transfers UI,
  native folder selection, tray controls, and local control IPC. The recovery
  list is requested on demand through the offline-capable agent action, paged
  below a 900 KiB IPC response cap, and exposes path, Space, size, and warning
  metadata only. It does not read copy contents, replay uploads, or delete
  recovery data. A normal launch opens the
  window; `--background` starts the tray without creating the initial webview
  when tray creation succeeds. If the tray is unavailable, it opens a window as
  a fallback. Linux autostart entries pass `--background`. A process-level
  second-launch check confirms a normal launch reuses an existing background
  shell. Tray status is read at startup and every 15 seconds while the tray is
  available; only one status request runs at a time, and status errors take
  priority over the connected label. Manual close-X and tray-click interaction
  remains unverified. The `auth_begin` IPC response timeout is 65 seconds to
  accommodate bounded WebFinger discovery.
  Conflict review requires an explicit Keep local or Keep cloud choice. The
  displaced version is preserved as a recovery copy; the UI does not silently
  choose a side. A blank OAuth client ID requests automatic WebFinger client
  and scope discovery, and a typed value is a manual override. Anonymous
  discovery is verified; automatic-client callback compatibility for the
  current server remains unverified and is not an MVP gate.
- The latest Linux package was installed with `install.sh` to
  `/home/phil/.local/share/raiun-desktop`. The installed agent starts, rejects
  a duplicate instance, and shuts down; saved session and mount restoration,
  explicit unmount/remount, recovery endpoint, media-preview sample, and live
  conflict resolution passed. Isolated-XDG autostart enable/disable resolves to
  the installed sibling shell. Actual session-login autostart remains
  unverified. Windows and macOS filesystem adapters and packages are not
  implemented.

## Verified checks

The workspace formatting and Clippy checks pass. The latest workspace test log
records 120 passing tests and one ignored live-FUSE test; that live host test was
run explicitly and passed. The Tauri shell's six lifecycle tests pass, as do
its frontend checks and production build. The offline media-preview CLI tests
cover unsafe paths, collisions, malformed and oversized requests. Latest
installed checks passed session and mount restoration, explicit unmount/remount,
the recovery endpoint, the media-preview example, and both conflict choices with
recovery bytes verified. The synthetic scale example tests empty files and a
generated remote inventory without a live server; see [scaling
results](SCALING-RESULTS.md). These checks establish component behavior only
within their fixtures and current host.

## Current safety boundaries

Folder-pair deletion propagation is disabled. Missing items and incomplete
listings never imply deletion. Conflicting initial content and simultaneous
edits are preserved and reported rather than silently overwritten. Provider
writes use a durable local spool and conditional remote revisions. Encryption is
blocked rather than treated as ordinary content. Expiration-driven token refresh
is verified. Manual close-X and tray-click interaction remains unverified.

OAuth and Graph discovery now succeed, and the keyring-restored session
survived an agent restart. A live folder-pair test passed initial download,
local upload, and download of a remote modification. Pair sync pause/resume state
worked; simultaneous local and remote edits reported one conflict and preserved
both versions. The pair was removed after testing. FUSE read and rename passed
after the snapshot fix, and fresh-file create, overwrite, read, and delete passed
after the atomic-truncate fix. The `O_CREAT`-on-existing-file regression was
fixed and full checks passed. The synthetic Personal folder
`Raiun-MVP-Acceptance-88d932bcf2` remains with the earlier failed-open recovery
copy `renamed.txt`; protect it from truncation. The final installed agent
restarted and restored its session, mounted successfully, and passed an immediate
overwrite/read test of the existing `overwrite-fresh.txt` after a cold mount.
Both conflict-resolution choices were verified against local and remote versions;
the displaced bytes were checked at the returned recovery path. One-item
pagination and the empty result after resolving all conflicts were also checked
in the latest installed build, and the synthetic test pair was removed. The
installed recovery endpoint returned a valid empty page for the saved account.
The installed media-preview sample reported a collision and planned video row.
The latest background shell process used 56,316 KiB RSS without WebKit child
processes; a normal second launch exited successfully after reusing its PID and
creating WebKit children. Manual close-X/tray-click interaction, recovery-panel
interaction, and actual desktop-session autostart remain unverified.
Automatic-client callback compatibility for the current server is unverified,
but is not an MVP gate: the discovered client does not advertise
`offline_access`, while manual `OpenCloudDesktop` login and refresh were
verified. The conservative hash cache passed 27 engine tests and has a
transparent tradeoff:
it reduces unchanged-file reads but adds metadata and SQLite work. The current
million-empty-file example took 19,722 ms with cache versus 14,004 ms in the
pre-cache run; no new RSS sample was collected. The 512 MiB tmpfs content
benchmark averaged 554 µs for warm scans across 117 scans versus 242 ms for a
forced full-hash audit, with no warm-scan transfer bytes. Cache performance on
representative non-synthetic workloads remains unmeasured.

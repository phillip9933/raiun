# Linux MVP acceptance

This is a release checklist, not a completion claim. The Linux integration
build has passed workspace checks and a host FUSE test. OAuth, Graph discovery,
keyring recovery, true token-expiration refresh, a real FUSE mount, and isolated
live file and folder-pair operations now work. The latest installed Linux build
restored its saved session and mount, passed explicit unmount/remount, recovery
index, media-preview, and live conflict-resolution checks. Manual native UI
interaction and actual desktop-session autostart checks remain open; this is not
an MVP completion claim.

## Verified

- [x] Workspace formatting and Clippy checks pass; the latest Rust workspace
  test log records 120 passing tests and one live-FUSE test ignored by default.
- [x] The ignored host FUSE test was explicitly run against a disposable mount
  and passed its read, refresh, create/upload, safe replacement, and unmount
  checks. It did not modify real account files.
- [x] The native Tauri shell builds and launches on the development host. Its
  six lifecycle tests, frontend typecheck, production build, and optimized Linux
  release build pass. Startup status is refreshed initially and every 15 seconds
  while the tray is available; overlapping status reads are prevented, and an
  agent error takes priority over the connected tray label. The `auth_begin`
  shell request has a bounded 65-second response timeout to allow WebFinger
  discovery to finish.
- [x] Process-level startup check: latest shell PID 228193 launched with
  `--background` at 56,316 KiB RSS and no WebKit child processes. A regular
  second launch exited successfully, reused that PID, and created WebKit
  children. This verifies background startup and single-instance window launch
  at process level; manual close-X and tray-click interaction remains
  unverified.
- [x] The latest Linux package was installed with `install.sh` to
  `/home/phil/.local/share/raiun-desktop`. The installed agent starts, rejects a
  duplicate instance, and shuts down. Autostart enable/disable was checked with
  an isolated temporary `XDG_CONFIG_HOME` and points to the installed sibling
  shell; the real user's autostart configuration was not changed.
- [x] Manual `OpenCloudDesktop` OAuth authorization and Graph Spaces discovery
  succeeded against the target instance on 9 October 2026 (Tokyo time). The
  latest installed build restored its saved session and mounted cloud root.
- [x] Anonymous WebFinger discovery returned the automatic client ID
  `opencloud` and scopes `openid profile email`; the scope parser handles the
  server's space-separated scope string. The target server's discovered client
  does not advertise `offline_access`, so the installed authenticated flow was
  verified with the manual `OpenCloudDesktop` client instead. Automatic-client
  callback compatibility remains unverified for this deployment and is not an
  MVP gate.
- [x] `raiun media-preview --input <json>` reads a typed manifest up to 1 MiB
  and prints deterministic plan rows. CLI tests cover unsafe paths, source and
  existing-destination collisions, unknown fields, and oversize requests. It
  is an offline planning command, not a media importer: it does not scan source
  files, extract metadata, write files, or contact a server.
- [x] The installed `media-preview` command processed a sample with a
  colliding destination and a planned video row. This validates the offline
  planner CLI only; it does not import media.
- [x] The Settings recovery index lists saved provider-write copies on demand
  through the `recoveries` action, including while disconnected when a saved
  account is available. Pagination is bounded by a 900 KiB IPC response cap;
  the UI uses the next-page cursor and shows scan truncation, unrecognized
  entries, and record warnings. It displays local and remote paths, Space names
  (falling back to IDs), and file sizes. The list does not read saved file
  contents, replay uploads, or delete copies; listed copies may still be pending
  or associated with an active write. With no saved account, the action returns
  an empty page.
- [x] Agent checks reject a symlinked cloud root. Unmount failure preserves the
  mounted state and saved intent so the operation can be retried. An HTTP
  fixture verified a Unicode remote filename through the engine's atomic
  snapshot path.
- [x] Real expiration-driven token refresh advanced `last_refresh_at` from
  `1791478169` to `1791478469` while the account stayed connected. After an
  agent restart, the saved session restored and the enabled cloud root mounted
  automatically.
- [x] On 9 October 2026 (Tokyo time), the `O_CREAT`-on-existing-file fix and
  full FUSE checks passed. Mounted read and rename passed after the snapshot fix;
  fresh-file create, overwrite, read, and delete passed after the atomic-truncate
  fix.
- [x] In the isolated synthetic Personal folder
  `Raiun-MVP-Acceptance-88d932bcf2`, a 25-byte upload was verified. The folder
  pair was removed after testing. The folder remains, including an earlier
  failed-open recovery copy named `renamed.txt`; protect it from truncation.
- [x] A live folder-pair test passed initial download, local upload, and download
  of a remote modification. Pausing and resuming the pair's sync state worked.
  Simultaneous local and remote edits reported one conflict and preserved both
  versions. The pair was removed after testing; the isolated test folder remains.
- [x] Both explicit conflict choices were verified: Keep local and Keep cloud
  retained the selected side, and the displaced bytes were checked at the
  returned recovery path. One-item pagination and an empty result after
  resolving the conflicts were checked; the synthetic test pair was removed.
- [x] In the latest installed build, Keep local and Keep cloud each retained
  the selected version and preserved displaced bytes at the reported recovery
  path. Pagination and the empty list after resolving both conflicts passed;
  the test pair was removed.
- [x] The installed recovery endpoint returned a valid empty page with the
  saved account. The UI source and IPC behavior are verified, but clicking and
  paging through the recovery panel in the native window remains unverified.
- [x] The final installed agent restarted and restored its session, then mounted
  successfully. After the cold mount, overwriting the existing
  `overwrite-fresh.txt` and immediately reading it back passed against the
  isolated server. Explicit unmount reported `mounted=false`; remount reported
  `mounted=true`.
- [x] Synthetic engine scale runs completed at 10k, 100k, and 1m files. These
  measure the engine example only; see [scaling results](SCALING-RESULTS.md).

## Still required

- [ ] Verify a user can close and reopen the native shell while the agent
  remains available by closing the window with its X and reopening it from the
  tray. Process-level startup is verified, but this manual UI interaction is
  still pending.
- [ ] Manually open and page through the saved-copy recovery panel in the native
  window; source and endpoint behavior pass, but the UI interaction is not yet
  accepted.
- [ ] Verify autostart at actual desktop-session login. Only isolated
  configuration-path behavior has been checked so far.

## Conservative behavior and limits

Folder-pair deletion propagation is disabled. Missing baseline items, first
enrollment absence, and incomplete listings do not trigger deletion. Conflicting
initial content and simultaneous edits are preserved and require attention
rather than being silently overwritten. Conflict review offers explicit Keep
local and Keep cloud actions, preserves the displaced version as a recovery
copy, and does not choose a side automatically. Provider writes use conditional
revisions and a durable spool; failed content remains locally recoverable.
Encrypted content and cross-Space moves are unsupported for this milestone.

The polling scheduler does not yet use a filesystem watcher. The local hash
cache is implemented and covered by engine tests: it reuses hashes only on
ext4, Btrfs, XFS, or tmpfs when device, inode, size, and nanosecond mtime/ctime
match, audits cached entries every 120 scans, and fully hashes on other file
systems. Cache reuse also requires nonzero ctime nanoseconds, which avoids
coarse ext2/3 timestamps. Writes and conflict checks still hash current
content. The cache adds metadata/SQLite overhead while avoiding reads of
unchanged content: the synthetic one-million-empty-file warm run took 19,722 ms
with cache versus 14,004 ms before cache, and no new RSS sample was collected.
On tmpfs, the separate 512 MiB content test averaged 554 µs for 117 warm scans
versus 242 ms for a forced full-hash audit; warm scans moved no transfer bytes.
The 1,748 ms cold initial sync is not comparable. Installed end-to-end
performance on representative non-synthetic workloads remains unmeasured.
A directory listing is bounded at 100,000 entries.

Metadata/control requests use a 120-second timeout. Body transfers use a total
deadline of 120 seconds plus `ceil(bytes / 256 KiB)`, capped at 24 hours. This
is not an idle timeout; transfers are not resumable, and cancellation is
observed at operation boundaries or when the deadline expires.
Offline pinning is not implemented, and manual UI conflict-choice interaction
still needs acceptance. The scaling measurements use synthetic empty files and
warm baselines, and exclude the shell, agent, FUSE memory, keyring, live
provider, transfers, and network. They are not whole-application resource
claims.

Windows and macOS adapters and installed packages have no acceptance evidence.
The latest Linux installed checks pass; manual native UI and actual desktop-login
checks remain. Do not label those remaining acceptance gates complete until they
are exercised.

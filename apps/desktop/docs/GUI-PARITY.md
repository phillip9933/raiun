# Linux / Windows GUI parity gate

Assessment: **29 October 2026**, Desktop `work/desktop-0.7.5`, baseline
`77ba21c1b675e29f15fb312696b81fbdd0cfe2ac`. This inventories existing GUI
features and their native seams. It is not a claim that either platform has
completed every category in [COMPLETION-CHECKLIST.md](COMPLETION-CHECKLIST.md).

The owner's 29 October requirement supersedes treating limited Windows writes
as enough for the next release: ordinary file/folder create, mkdir, rename,
move, delete, in-place and replacement saves, including safe writes above
16 MiB, must work on Personal and writable Spaces. Linux and Windows must have
GUI feature parity and the practical CLI MVP must be complete before release.
Permission, conflict, account/root/generation, recovery and verified-publication
guards remain required. This adds no signing or publication authorization.

## Reading the matrix

“Source” means a callable implementation exists, not native/package acceptance.
Reuse valid unchanged native evidence with an explicit source comparison. This
matrix is not a blanket instruction to repeat all historical tests. Focus new
acceptance on changed behavior and unresolved gaps.

The same frontend is built for both systems, but capability flags, adapters,
credential stores and provider behavior differ. A visible button or successful
RPC is insufficient proof of its complete workflow. Paths below are relative
to `apps/desktop/`; RPC names refer to the account-scoped `request` bridge in
[`desktop-shell/src/main.ts`](../desktop-shell/src/main.ts). Agent dispatch is
in [`agent_unix.rs`](../crates/raiun-agent/src/agent_unix.rs) and
[`agent_windows.rs`](../crates/raiun-agent/src/agent_windows.rs).

| Existing feature / concrete seam | Linux source | Windows source / concrete gap | Remaining focused native/package acceptance |
| --- | --- | --- | --- |
| **Accounts and sessions:** add/select/rename/remove/restore; browser sign-in, cancellation, saved-session refresh. `auth_begin`, `auth_cancel`, `accounts`, `account_select`, `account_add`; frontend `removeSelectedAccount` / `restoreRemovedAccount`; agent `auth.rs`, `profiles.rs`, `windows_profiles.rs`. | Secret Service-backed saved sign-in and authority revocation; account-scoped runtime/root/cache/recovery. | DPAPI-backed sessions and account-scoped provider runtime. Earlier affected-laptop saved-sign-in/renewal acceptance is scoped historical evidence, not all current account flows. | Exact final package: fresh and saved sign-in, refresh, switch while requests are outstanding, removal without deleting files, same-ID restore requiring renewed authority; prove no account crossover. Current physical Linux preview restored its saved account and stayed unmounted. |
| **Cloud drive and reads:** `spaces`, `list`, `mount`; `open_cloud_folder` Tauri command; `raiun-fuse`, `raiun-cloudfiles-windows`. One account root contains Personal and Spaces. | Native FUSE enumeration, on-demand reads and scoped writable routes. | Cloud Files registration, placeholders, range hydration and existing-object editing. Same UI does not supply missing provider mutations. | Exact installed GUI: open root in native file manager, Personal and writable/read-only Spaces, refresh/reconnect, ordinary applications and unchanged account/root identity. Linux signed-out package smoke proves launch only. |
| **Ordinary native mutations:** FUSE `Filesystem::{create,mkdir,unlink,rmdir,rename}`, write/flush/fsync/release; `Engine::{commit_file_write_scoped,mkdir,rename,delete}` in `crates/raiun-engine/src/lib.rs`; transport in `crates/raiun-opencloud/src/lib.rs`. GUI folder picker separately calls `create_folder`. | Source CRUD exists. Replacement-save uses a recoverable multi-request backup/publish sequence, not a single atomic remote replacement. Cross-Space FUSE rename is refused. Server conditional-operation qualifications still apply. | **Release blocker:** current mounted provider has no general ordinary new-file/new-directory/rename/move/delete/replacement-save propagation. A picker-created remote folder does not establish Explorer mkdir. Existing opaque-placeholder save recovery is narrower. | On both systems and Personal/Spaces: native create, zero-byte/truncate, mkdir, rename/move, file/empty-directory delete, common editor replacement save; verify remote content/identity and no false clean on conflict/403/disconnect. Agree cross-Space copy/move semantics explicitly; do not call existing single-Space rename full cross-Space support. |
| **Ordinary large writes and pending edits:** `ordinary_write_recovery.rs`, `cache_pending_writes`, `cache_reconcile_writes`, `cache_reconcile_status`, Tauri `save_saved_edit_copy`; Windows `edit_journal.rs` / `recovery_reconcile.rs` under `raiun-cloudfiles-windows/src/` and `raiun-control-windows/src/session_store.rs`. | Disk-backed FUSE working copies and scoped streaming engine writes; failed edits retain recovery state. This alone does not prove every server finalization condition. | **Release blocker:** ordinary close capture, protected journal, recovery transport/reconciliation and native completion have whole-body 16-MiB limits. Raising one constant cannot safely remove this pipeline limit. C8/C9 CLI tests cover existing-object saves, not broad GUI parity. | Exact provider package: >16-MiB edits with bounded memory/disk, readback verification, retained dirty bytes and recoverable failures, retry/export, restart and replacement-save. Preserve exact local-file/root/session proof and do not substitute a success response for verified completion. |
| **Offline files/folders and storage:** `cache_policy_get/set`, `cache_pins`, `cache_pin_start/status/cancel`; `offline-storage.ts`, `offline-snapshot.ts`; Windows `windows_offline_jobs.rs`, frontend `windows-offline-file.ts`, `windows-offline-folder.ts`, `windows-device-cache.ts`. | Cache policy, pin jobs, quota controls, cached namespace and pending-write reconciliation. | Separate device-cache/file/folder jobs and capability-specific controls; source implementations exist, but do not infer identical policy behavior from common navigation. | Compare keep-offline/cloud-only, bounded quota/eviction, cancel/resume, offline restart/reconnect and reconciliation on final packages. Eviction must preserve cloud objects and dirty edits. Current signed-out Linux fixture could not exercise quota controls. |
| **Sync Folders / Space controls:** `folder-workspace.ts`, `folder-settings.ts`, `pair_update`, `space_pause`, `space_sync_now`, `space_disconnect`; engine folder workers; Windows `windows_folder_sync.rs` / `windows_folder_requests.rs`. | Existing folder-pair direction, exclusions, review/conflict settings, pause/resume and targeted Space controls. | Corresponding Windows folder workers and settings backend exist; parity requires actual execution as well as equivalent form rendering. | Preserve established GUI capability while integrating provider work; verify one bounded configured workflow, exclusions/update, pause/resume and disconnect preserving local data on both packages. **New CLI folder sync stays disabled until its complete MVP passes.** |
| **Media backup:** unified folder workspace, `media-jobs.ts`; engine media workers; Windows `windows_media_control.rs` / `windows_media_requests.rs`. | Upload-only media jobs and source-preserving worker flow. | Native Windows media worker/control implementation exists. | Same configured upload-only result, duplicate avoidance, cancel/restart and source retention on both packages; reuse unchanged evidence with explicit source comparison. Do not turn optional richer organization ideas into new parity scope. |
| **Encrypted access and operations:** `vault_inspect`, `vault_list`, `vault_create`, `vault_lock`, dedicated `vault_secret` bridge; `vault_copy_start/status/cancel`, `vault_copy_verify_*`, `vault_operations`; agent `vaults.rs`, `vault_mount.rs`, Windows `windows_vault_control.rs` / `windows_vault_requests.rs`; FUSE `vault_write.rs`. | Native mounted vault routes plus guarded GUI create/browse/copy/recovery flows. Operation readiness is explicitly reported. | **Known parity gaps:** Windows selects `vault_access_mode=native_read_only`, hides in-app vault browsing, encrypted offline pins, vault creation and cross-vault Copy. Unlock can report `vault_mount_existing_file_in_place=true` for connected saves up to **512 KiB**, while `vault_mount_writable=false` and `vault_mount_existing_file_overwrite=false`. New file/folder, replacement-save, rename/move/delete and offline edits are unsupported, not merely awaiting root readiness. See the operation audit below. | Compare supported unlock/browse/open/edit/create-folder/rename/move/delete and cross-vault verified copy/move. Where safe support is absent, record the actual gap; retain lock/read denial and verify destination before conditional source removal. No blanket recursive encrypted-delete acceptance. |
| **Remembered unlock and recovery:** `vault_forget`, remembered option in `unlockVault`; `vault_secrets.rs`, `windows_vault_credentials.rs`; `vault_reconcile_edits_*`, `encrypted_edit_recoveries`, `windows_vault_capture_recovery_list`, Tauri `save_protected_vault_capture_copy`; `windows-recovery-controller.ts`. | OS-protected per-account/vault opt-in; pending edits, export and explicit retry paths. | DPAPI-backed vault credentials/custody, protected capture export/history and exact-root recovery. Historical sustained-save/Save Copy evidence remains narrowly scoped. | Opt-in/restart/Lock/Forget, account binding, no read after lock, conflict preservation, local-copy no-clobber export and explicit retry on each final package. Preserve unresolved/ambiguous custody; do not replay against a changed object or generation. |
| **Sharing:** `sharing-controller.ts`, `sharing-workspace.ts`, `sharing-inventory.ts`, `guest-sharing.ts`; agent `sharing_wire.rs` / `guest_sharing_wire.rs`; OpenCloud `sharing_inventory.rs`. Existing-grant inventory, ordinary user/group sharing, public links and sender-side guest invitations. | Common guarded frontend/protocol flow and Unix dispatch. Current protected public-link create reached server, but its confirmation was falsely uncertain because canonical `@libre.graph.displayName` was not parsed. Parent has implemented the canonical-name/legacy-alias correction locally, with conflicting aliases refused; 141 OpenCloud tests pass, including debug-ID redaction. Final integrated source/package acceptance remains separate. | Common frontend/protocol with separate Windows secret admission/dispatch. Same source needs native Windows UI proof. | After canonical-name fix: exact-package create with role/password/expiry rules, list, edit/readback and exact revoke on both systems. Existing live test applied protected create, passed name/access edit and exact revoke with unrelated grant unchanged and folder empty; no cleanup remains. Sender guest management remains; native guest recipient browsing was withdrawn. |
| **Appearance/navigation/settings:** `main.ts` pages Overview, Sync Folders, Offline files, Encrypted files, Sharing, Transfers, Settings; `ui-preferences.ts`, `account-avatar.ts`, `passive-refresh.ts`, shared CSS. | Per-account appearance/navigation and stable refresh source. | Same UI with Windows capabilities; unavailable operations must remain honestly represented. | Installed visual/interaction comparison: account colors/avatar/fallback, theme/appearance persistence, navigation, refresh preserving drafts and focus, dialogs/keyboard and unavailable/error states. Source/frontend tests do not establish native WebView behavior. |
| **Network/transfers/diagnostics:** `network_proxy`, `network_proxy_set`, `bandwidth_limits`, `bandwidth_limits_set`, transfer retry/cancel; `network-proxy.ts`, `transfer-limits.ts`, `transfer-presentation.ts`, `windows-compatibility.ts`; Tauri `export_diagnostics`. | Proxy applies to sign-in/refresh/file traffic; transfer controls/status and redacted diagnostics. | Windows proxy/bandwidth adapters and nullable pause/diagnostic differences are explicit. Compatibility warnings cover Windows naming/path hazards. | Exact GUI route/limit save and reconnect, transfer retry/cancel without false completion, useful exported diagnostics with secret/path redaction, and representative incompatible-name warning. Historical broker export is not physical export-button acceptance. |
| **Tray/startup/lifecycle:** Tauri `lifecycle.rs` / `main.rs`, `set_autostart`, agent `autostart.rs`. | Tray show/normal Quit and GUI launch-at-login integration. | Native tray/startup and shutdown adapters; CLI scheduled-task work is independently owned. | Exact current package tray/show/normal Quit with owned agent/provider cleanup; GUI startup enable/disable/restart. Current Linux fresh-profile normal tray Quit passes. CLI C9 same-user InteractiveToken manual-start rounds do not establish Windows before-login service acceptance. |
| **Updates/installers:** `desktop-shell/src-tauri/src/desktop_updates.rs`, `desktop_updates_policy.rs`; `scripts/test-windows-installed-package.ps1`, Linux packaging scripts. | Manual App updates, automatic checks, Later dismissal, verified download/install and safe shutdown source; tar/AppImage packages. | Same update policy, Windows NSIS in-place installation and running-process refusal; signature/archive validation is distinct from Authenticode. | Final-source installer/upgrade and exact installed shell/agent/CLI hashes; settings, credentials and synthetic data retention; visible version/App updates and normal Quit. Newer compatible offer/manual controls and tamper/version refusal. Current `77ba21c` run 40803675511 build and installed-upgrade jobs succeeded; receipts are being preserved. Both this and preceding `813746e` acceptance use a hosted interactive administrator runner, not ordinary laptop proof. |

## Encrypted operation audit: actual capability differences

This bounded source audit distinguishes missing operations from a supported
operation temporarily blocked by an unavailable root. Sources are
`desktop-shell/src/main.ts` (`nativeVaultAccess`, `nativeVaultDrivePanel`,
`nativeExistingFileSaveMessage`, `copyProducerFeatureAvailable`),
`crates/raiun-agent/src/windows_vault_session_control.rs`,
`crates/raiun-agent/src/vaults.rs`, and
`crates/raiun-fuse/src/{lib.rs,vault_routes.rs,vault_write.rs}`.

| Operation | Linux callable behavior | Windows callable behavior / parity action |
| --- | --- | --- |
| Browse/open and create encrypted folder | In-app `vault_list` and `vault_create`; mounted FUSE routes support ordinary encrypted child creation/mkdir when the route backend permits writes. | Inspect/unlock/Lock/Forget and native drive opening exist. In-app browsing and vault creation are hidden in native mode. Mounted child mkdir/new-file creation is unsupported. Implement the existing Linux workflows before parity can be claimed. |
| Rename/move/delete inside one vault | FUSE `rename`/`unlink`/`rmdir` dispatch through exact route leases. Online writable routes can use their mutation backend; offline routes separately allow regular-file create/rename/delete and folder creation. Offline folder rename is limited to a never-attempted queued subtree (64 operations / 64 MiB); existing remote folder deletion is unsupported offline. Empty never-attempted queued folders can be canceled under dependency/open-handle guards. | Native-mode UI explicitly says rename/move/delete are unsupported. These do not become available merely by remounting/unlocking. Windows needs the corresponding safe supported Linux operation paths; do not promise arbitrary recursive encrypted deletion. |
| Cross-vault Copy / Move | GUI `vault_copy_start/status/cancel` copies one regular file into another unlocked writable online vault, re-encrypts and retains the source. `canStartVaultCopyFrom` requires a strong source ETag; destination uses bound directory identity/ETag. **Move is not implemented:** FUSE cross-route rename returns EPERM because verified destination-before-delete protocol is absent. No GUI Move action exists. | `copyProducerFeatureAvailable` explicitly excludes Windows; Copy is a real missing Linux GUI capability. Cross-vault Move remains an agreed completion requirement with a shared implementation gap; neither platform may claim it delivered. Do not relabel Copy as Move. |
| Edit limits / replacement | Linux vault working-copy policy is 64 GiB (`MAX_VAULT_WORKING_COPY_BYTES`), not proof of native acceptance at that size. Route/backend readiness and original-identity checks still govern writes. | Connected existing-file in-place saves are limited to 512 KiB (`MAX_VAULT_EDIT_CAPTURE_BYTES`), separately from the ordinary 16-MiB ceiling. Replacement editors, offline writes and creates are unsupported. Ordinary streaming work does not resolve this encrypted parity gap automatically. |
| Encrypted offline and retry UI | `vault_pins`, `vault_pin_start/status/cancel/remove`, cached-root unlock and `vault_reconcile_edits_*` expose verified snapshot/offline/retry flows. | `vaultOfflinePinPanel` returns empty in native mode; the dialog also omits the Linux saved-edit retry panel. Windows protected native capture/history and Save Copy are separate, narrower recovery surfaces. Implement or explicitly close these known parity gaps; no current equivalence claim. |
| Remember / Lock / Forget / recovery | Per-vault OS-store opt-in, saved unlock, Lock, Forget, retry and local export are callable. | DPAPI opt-in/saved unlock/Lock/Forget and protected capture list/Save Copy are callable; their existence is not a missing-feature claim. Source/native recovery evidence is operation-specific. Retain account/vault binding, lock denial, no-clobber export and unresolved custody. |

For either platform, `vault_mount_ready=false`, `drive_not_mounted`,
`private_spool_unavailable`, `route_not_installed`, a locked/read-only route,
or cleanup still pending can block a supported operation. These are different
from the hard Windows exclusions above. Linux `vault_mount_writable=null` is
unknown readiness, not proof of absent support; Windows explicitly returning
false alongside the narrower in-place flag is not general writability.
Exact current native/package acceptance for every listed encrypted operation is
not established by this audit; reuse the scoped historical evidence in
[IMPLEMENTATION.md](IMPLEMENTATION.md) and test affected integrated seams.

## Evidence boundaries

Maintainer-local evidence below is **outside Git**, rooted at
`/home/phil/Projects/raiun/outputs/`; do not copy private profiles, account IDs,
server URLs or credentials into this document.

- `desktop-release-prep-20261029/STATUS.json`, source logs and `linux/run-3/`:
  baseline 77ba21c passes 1,215 Rust cases (14 existing ignores), 346 frontend
  cases and 49 Tauri cases, formatting and strict Clippy. Exact tar/AppImage
  fresh-UID signed-out launch, normal tray Quit and canary retention pass.
  Physical Linux preview restored the same saved account; it was unmounted.
- `desktop-release-prep-20261029/windows-ci-77ba21c/`: full native suite, build and installed-upgrade jobs passed
  in run 40803675511 per the coordinator's latest observation; exact receipts
  are being preserved. `STATUS.json` can lag this observation. `windows-ci-813746e/acceptance/` is the preceding
  exact 0.7.4-to-0.7.5 hosted-runner upgrade, not proof for changed final source
  or a standard-user laptop.
- `desktop-release-prep-20261029/sharing/r5-edit-revoke-result.json` and paired
  live results: scoped create/uncertain confirmation, successful edit/revoke,
  preserved other grant and completed cleanup. Parent's local canonical-name fix
  changes this baseline; its 141 OpenCloud tests pass, and final integrated
  package evidence remains separate.
- `headless-mvp-acceptance-20261029/OWNER-RELEASE-REQUIREMENTS-20261029.md`,
  `windows-candidate8/`, candidate9 receipts and `linux-vm/` describe independent
  CLI requirements/acceptance. Existing native ordinary-write results are useful
  narrow baselines, not full CRUD or GUI parity.
- `headless-mvp-acceptance-20261029/full-operations-design/` contains
  `remote-operations-plan.md`, `streaming-writeback-plan.md` and
  `windows-native-plan.md`: **proposals and source/server assessment**, not
  implemented or native-accepted capabilities. Conditional create, MOVE/DELETE,
  replacement and cross-Space semantics need the stated server qualifications.

## Integration ownership and owner-ready queue

Desktop coordinator owns this worktree's Sharing/security/UI integration and
draft PR #45. CLI coordinator owns shared provider/filesystem implementation in
the independent dirty `worktrees/headless-cli/`, based on
`73eb58ece99fa934296aeeef818d78191f5dcf5b`. This Desktop baseline is 77ba21c,
not the CLI source. Exchange reviewed patches with a source manifest and
explicit seam ownership; never overwrite either live checkout or transplant
whole dirty directories. Preserve Android, older checkouts, user data,
credentials and all original failure/recovery artifacts.

1. Validate and commit the local canonical Sharing confirmation repair with
   affected evidence; preserve the completed live cleanup record.
2. Agree shared operation/snapshot APIs and server-condition proof, then
   integrate CLI-owned ordinary CRUD, editor replacement and bounded >16-MiB
   writeback. Assign the encrypted parity gaps above explicitly; they are not
   delivered by ordinary provider changes alone. Keep metadata-only IPC and
   platform-owned native identity checks.
3. Build exact integrated packages and exercise the matrix's changed workflows
   in Linux file managers/applications and ordinary-user Windows Explorer/editors,
   Personal and writable Spaces. Reuse unchanged acceptance explicitly; record
   unsupported operations and pending cases rather than a parity percentage.
4. Close final installer/updater/GUI checks and complete CLI login/configuration,
   secure persistence, mount/startup and native acceptance requirements. Keep
   CLI folder sync unstarted and next-release readiness false until these gates
   are met. Signing, merge and publication remain separately authorized actions.

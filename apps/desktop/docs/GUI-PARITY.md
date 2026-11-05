# Linux / Windows GUI parity

## Windows transfer and recovery update — 5 November 2026

Windows GUI and headless mounts now share the SDK's consolidated ordinary-create
preparation. Fresh Space, root, ordered parent and target-absence facts are reused
within one operation; original parent conditions, late root revision fencing,
protected streams and full conditional SHA-256 readback remain. Windows directory
population authenticates its protected catalogue once per bounded listing and
indexes existing identities, while preserving tombstones and cancellation.
These are source changes, not measured Windows speed claims.

Windows saved edits now offer **Check cloud copy**, including uncertain new
uploads with an authenticated namespace/snapshot join. The headless command is
`raiun drive edits check --id HEX --generation N`. A match describes current
cloud bytes only: the saved copy remains retained and Windows sync status is
unchanged. It sends no upload or deletion, creates no retry, and never clears
custody. Missing is reported only after a qualified target lookup; ambiguous
root/parent failures remain unavailable.

Ordinary-file recovery no longer has a separate default 1-GiB file cap. An
omitted file allowance follows the configured aggregate recovery quota (8 GiB
by default, within existing supported configuration bounds). Explicit owner
file limits remain unchanged; ciphertext overhead, retained records, disk
availability and aggregate quotas can still refuse a capture. Encrypted vault
limits are separate and are not lifted by an ordinary-file policy change.

Windows clients authenticate their connected control-pipe owner and live server
TokenUser before exchanging messages. Updated listeners set their actual user
as owner. An older elevated Agent with an Administrators-owned pipe must be
restarted normally before a new client can connect.

Normal Personal and writable-Space folder creation is already enabled. The
remaining false directory-routing flag belongs to the old fixture route and is
not a production feature limit. Account, folder/media and vault capabilities
are also enabled in production. Headless mode retains its explicit mount-only
scope on both operating systems. Native callback chunk sizes are staging
windows, not total-file limits.

Routine Windows OAuth renewal now retains the account's shared authentication
owner and native connection. A fresh token must verify the original account and
Personal root before a short admitted credential update. An opaque provider
credential lease retains the original native/journal generation through benign
rotation; actual bearer generations still advance, and security/account changes
permanently revoke the old in-memory owner before draining. Pending rotated
refresh tokens are retained across transient storage/root-read failures. Startup,
rejected authentication and account replacement retain the strict disconnect path.

Windows ordinary uploads now use four SDK workers with per-file native custody
and exact result routing. Up to four independently qualified new files in the
same parent form one upload wave. Different parents, directories, renames and
vault operations remain ordered; close/dirty-state uncertainty still fences the
whole wave. This removes the global one-file custody bottleneck without making
folder dependency or native completion concurrent.

Cached stable-directory rename/delete and replacement-style editors still need
their native custody paths; they cannot be enabled by deleting a capability
check. Recovery quotas, conditional writes, root/account binding and exact native
completion remain required. These source changes do not establish equal measured
transfer speed or final Windows native acceptance.

## Earlier implementation — 4 November 2026

GUI and CLI share the canonical `worktrees/desktop-followup-ui` source and one
engine. The owner resumed the remaining Windows work after the earlier `d8113b7`
unsigned packages were delivered. Those packages are preserved; they do not
contain the additions below. Older sections retain historical evidence rather
than current capability claims.

| Area | Current implementation | Remaining work |
| --- | --- | --- |
| GUI accounts, settings, Sharing, ordinary offline files and Sync Folders | Shared frontend and account-scoped services; Windows uses DPAPI and Cloud Files, Linux uses Secret Service and FUSE. Windows encrypted folder pairs now use the exact unlocked vault backend, and saved local-only folder settings remain editable offline after the old worker drains. | New integrated candidate packaging and basic workflow; encrypted local folder copies remain plaintext by design. |
| Ordinary Windows drive operations | File/folder creation, clean file and empty-directory deletion, file/folder rename and same-Space moves, streamed existing saves and recoverable replacement saves are connected for Personal and writable Spaces. Unicode rename hints use Windows ordinal alias checks. | Finished-candidate basic file workflow; existing permission, conflict and dirty-state refusals remain. |
| Encrypted online Windows files | File/folder creation, streamed existing saves, protected replacement saves, clean file/folder rename and same-vault moves, file deletion and empty-directory deletion are integrated. Remote mutations are conditional and completion requires verified remote and native readback. | Final-package basic workflow; compilation is not native acceptance. |
| Encrypted Windows offline content | Snapshot controls, password-authenticated cached unlock, native browsing, queued in-place file saves, file/folder creation, file rename/move/delete and queued subtree retarget are connected. Empty never-attempted queued directory cancellation retains a protected intent, native absence proof and sealed terminal receipt. Reconnect retains exact protected pending edits; explicit retry joins fresh SDK verification, native completion and durable custody. Cache-only clients have no bearer credential or network authority. | Final candidate packaging and basic native workflow. Stable existing-folder rename/delete stay online-only; replacement-style editors are not advertised for cached access. |
| Cross-vault file transfers | Shared explicit Copy and Move re-encrypt into the destination and verify readback. Move removes only the unchanged source after destination verification. Any unresolved source removal retains a protected, non-replayable review row; no generic delete retry can dispatch it. Both systems provide read-only interrupted-Copy verification, with protected pending rows visible for the exact unlocked scope. | Finished-candidate basic workflow. File-only, online, 16 MiB limit; no recursive cross-vault Move. |
| Headless CLI MVP | Both systems support foreground serve, status, Spaces, mount/unmount, configuration and supported sign-in/reconnect operations. Platform credential, registration, service and state-isolation policies remain explicit. | No missing Windows command-layer MVP was found. Headless mount-only mode excludes folder/media sync and vault commands on both systems. |

Encrypted creation and supported saves currently accept files up to 1 GiB on
Windows using bounded streams and protected recovery. Explicit Copy and Move between two
unlocked vaults is limited to 16 MiB on both platforms. Clean directory operations
use a bounded exact subtree; recursive cloud deletion is not enabled. Unknown,
foreign, dirty or active-writer state refuses rather than discarding local data.
Queued file/directory retarget is bounded to 64 operations and 64 MiB.
Cached access advertises only supported operations; stable directory rename/delete
and replacement-style editors require an online route. Guarded cached retry does
not admit copy operations without their source-specific proof.
The initial encrypted replacement path requires a previously hydrated original;
unsupported replacement strategies retain local recovery instead of claiming
successful completion. These bounds are not a claim of unlimited parity.

Completed original custody, captures and body history remain additive. Rename,
replacement and deletion histories project only exact verified current identities;
old records are not rewritten to manufacture new authority. Lock/reconnect keeps
account/vault/root binding, and cache eviction remains separate from cloud deletion.

The 4 November additions are source changes, not installed/native acceptance.
Affected Linux Agent/CLI compilation, Windows Agent/CLI cross-compilation,
formatting and the frontend build are checked during integration; package and
laptop results must identify the final source independently.

Preserved Linux `777bc3d` unsigned GUI/CLI packages passed signed-out startup,
normal quit and CLI help/version; no exact-source sign-in/file workflow is claimed.
Windows `56f1077` was installed in the owner's original profile with exact
payloads and selected settings/root/startup preservation. Its original ordinary
file create succeeded, and an early edit was finalized through explicit protected
recovery. The same local and remote 70-byte body was verified, followed by normal
shutdown/restart with no pending saved edits. The first post-conversion completion
refusal remains undiagnosed; narrow static native error classification now
preserves the specific failing boundary and native read error without weakening
any identity, USN, hash or cancellation checks. Compilation and successful recovery
do not establish an unqualified first-pass native workflow or exhaustive parity
acceptance. No candidate has been signed or published.

Validation stays within the owner's reduced scope: affected build and formatting,
basic install/upgrade/startup/sign-in, one normal file workflow and essential data
preservation. No full-suite reruns, expanded matrices or new VM/account/browser
setup are release requirements. Unchanged earlier evidence is reused only within
its actual scope.

The earlier `d8113b7` Windows installer passed the CI upgrade/data-preservation
check and was received and hash-verified by the Windows laptop. The previous
`d8233c1` installation started in a standard synthetic account, whose browser also
failed to launch outside Raiun. That environment limitation does not establish an
application sign-in regression and is not authority for account/browser resets.
Earlier Linux packages passed basic startup and, for the unchanged ordinary
engine, one synthetic file workflow. New packages must identify their actual
source and must not inherit unsupported native-acceptance claims.

## Earlier assessment and feature matrix

Assessment: **29 October 2026**, Desktop `work/desktop-0.7.5`, production behavior assessed at source
`c584b8f11f506d4acbc4ad4e7697990430b2a4af`. This inventories existing GUI
features and their native seams. It is not a claim that either platform has
completed every category in [COMPLETION-CHECKLIST.md](COMPLETION-CHECKLIST.md).

Source integration update, **31 October 2026**: the GUI candidate now composes
the shared same-parent Personal file-rename executor, authenticated intent store,
revision-conditioned content witnesses and native identity-only completion
adapter. This is an explicit callable engine seam, not an automatic Explorer
rename feature. An optional admitted rename-store factory is now available;
the observer, fresh candidate helper and GUI provider lifecycle caller remain
unwired. Namespace storage is not enabled by the current GUI factory. Its
prepared health query conservatively reports unknown until an authenticated
namespace-history consumer can distinguish completed and unresolved work,
including evidence retained across startup without an opt-in context. The
existing GUI saved sign-in, streamed
save/Retry, cache quota and completed-copy retention paths are preserved.
Isolated native identity-update acceptance belongs to the shared engine test
source; the integrated native rename workflow and this GUI package remain
unverified. These additions do not close the ordinary-mutation release blocker
or establish broader Personal/Spaces or encrypted parity.

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
| **Ordinary large writes and pending edits:** `ordinary_write_recovery.rs`, `cache_pending_writes`, `cache_reconcile_writes`, `cache_reconcile_status`, Tauri `save_saved_edit_copy`; Windows `edit_journal.rs` / `recovery_reconcile.rs` under `raiun-cloudfiles-windows/src/` and `raiun-control-windows/src/session_store.rs`. | Disk-backed FUSE working copies and scoped streaming engine writes; failed edits retain recovery state. This alone does not prove every server finalization condition. | **Released/installed baseline:** whole-body ordinary recovery has a 16-MiB limit. The newer local candidate wires streamed capture and same-job verified recovery into the GUI factories, with explicit account-bound Retry. Diagnostic native existing-file streaming and isolated GUI storage/factory checks passed separately; actual GUI cloud-save/Retry ACK acceptance, configurable GUI policy and completed-copy reclamation remain release gaps. No general file-operation parity is implied. | Exact provider package: >16-MiB edits with bounded memory/disk, readback verification, retained dirty bytes and recoverable failures, retry/export, restart and replacement-save. Preserve exact local-file/root/session proof and do not substitute a success response for verified completion. |
| **Offline files/folders and storage:** `cache_policy_get/set`, `cache_pins`, `cache_pin_start/status/cancel`; `offline-storage.ts`, `offline-snapshot.ts`; Windows `windows_offline_jobs.rs`, frontend `windows-offline-file.ts`, `windows-offline-folder.ts`, `windows-device-cache.ts`. | Cache policy, pin jobs, quota controls, cached namespace and pending-write reconciliation. | Separate device-cache/file/folder jobs and capability-specific controls; source implementations exist, but do not infer identical policy behavior from common navigation. | Compare keep-offline/cloud-only, bounded quota/eviction, cancel/resume, offline restart/reconnect and reconciliation on final packages. Eviction must preserve cloud objects and dirty edits. Current signed-out Linux fixture could not exercise quota controls. |
| **Sync Folders / Space controls:** `folder-workspace.ts`, `folder-settings.ts`, `pair_update`, `space_pause`, `space_sync_now`, `space_disconnect`; engine folder workers; Windows `windows_folder_sync.rs` / `windows_folder_requests.rs`. | Existing folder-pair direction, exclusions, review/conflict settings, pause/resume and targeted Space controls. | Corresponding Windows folder workers and settings backend exist; parity requires actual execution as well as equivalent form rendering. | Preserve established GUI capability while integrating provider work; verify one bounded configured workflow, exclusions/update, pause/resume and disconnect preserving local data on both packages. **New CLI folder sync stays disabled until its complete MVP passes.** |
| **Media backup:** unified folder workspace, `media-jobs.ts`; engine media workers; Windows `windows_media_control.rs` / `windows_media_requests.rs`. | Upload-only media jobs and source-preserving worker flow. | Native Windows media worker/control implementation exists. | Same configured upload-only result, duplicate avoidance, cancel/restart and source retention on both packages; reuse unchanged evidence with explicit source comparison. Do not turn optional richer organization ideas into new parity scope. |
| **Encrypted access and operations:** `vault_inspect`, `vault_list`, `vault_create`, `vault_lock`, dedicated `vault_secret` bridge; `vault_copy_start/status/cancel`, `vault_copy_verify_*`, `vault_operations`; agent `vaults.rs`, `vault_mount.rs`, Windows `windows_vault_control.rs` / `windows_vault_requests.rs`; FUSE `vault_write.rs`. | Native mounted vault routes plus guarded GUI create/browse/copy/recovery flows. Operation readiness is explicitly reported. | **Known parity gaps:** Windows retains `vault_access_mode=native_read_only`. Online in-app browsing is implemented with selected-account/root/session guards and passes native refusal-boundary tests; positive mounted GUI browsing remains unverified. Encrypted offline pins, vault creation and cross-vault Copy remain hidden. Unlock can report `vault_mount_existing_file_in_place=true` for connected saves up to **512 KiB**, while `vault_mount_writable=false` and `vault_mount_existing_file_overwrite=false`. New file/folder, replacement-save, rename/move/delete and offline edits are unsupported, not merely awaiting root readiness. See the operation audit below. | Compare supported unlock/browse/open/edit/create-folder/rename/move/delete and cross-vault verified copy/move. Where safe support is absent, record the actual gap; retain lock/read denial and verify destination before conditional source removal. No blanket recursive encrypted-delete acceptance. |
| **Remembered unlock and recovery:** `vault_forget`, remembered option in `unlockVault`; `vault_secrets.rs`, `windows_vault_credentials.rs`; `vault_reconcile_edits_*`, `encrypted_edit_recoveries`, `windows_vault_capture_recovery_list`, Tauri `save_protected_vault_capture_copy`; `windows-recovery-controller.ts`. | OS-protected per-account/vault opt-in; pending edits, export and explicit retry paths. | DPAPI-backed vault credentials/custody, protected capture export/history and exact-root recovery. Historical sustained-save/Save Copy evidence remains narrowly scoped. | Opt-in/restart/Lock/Forget, account binding, no read after lock, conflict preservation, local-copy no-clobber export and explicit retry on each final package. Preserve unresolved/ambiguous custody; do not replay against a changed object or generation. |
| **Sharing:** `sharing-controller.ts`, `sharing-workspace.ts`, `sharing-inventory.ts`, `guest-sharing.ts`; agent `sharing_wire.rs` / `guest_sharing_wire.rs`; OpenCloud `sharing_inventory.rs`. Existing-grant inventory, ordinary user/group sharing, public links and sender-side guest invitations. | Common guarded frontend/protocol flow and Unix dispatch. Current protected public-link create reached server, but its confirmation was falsely uncertain because canonical `@libre.graph.displayName` was not parsed. The canonical-name/legacy-alias correction is committed in c584b8f, with conflicting aliases refused and debug-ID redaction retained. Source and exact-package build checks pass; corrected live create confirmation remains unverified. | Common frontend/protocol with separate Windows secret admission/dispatch. Same source needs native Windows UI proof. | After canonical-name fix: exact-package create with role/password/expiry rules, list, edit/readback and exact revoke on both systems. Existing live test applied protected create, passed name/access edit and exact revoke with unrelated grant unchanged and folder empty; no cleanup remains. Sender guest management remains; native guest recipient browsing was withdrawn. |
| **Appearance/navigation/settings:** `main.ts` pages Overview, Sync Folders, Offline files, Encrypted files, Sharing, Transfers, Settings; `ui-preferences.ts`, `account-avatar.ts`, `passive-refresh.ts`, shared CSS. | Per-account appearance/navigation and stable refresh source. | Same UI with Windows capabilities; unavailable operations must remain honestly represented. | Installed visual/interaction comparison: account colors/avatar/fallback, theme/appearance persistence, navigation, refresh preserving drafts and focus, dialogs/keyboard and unavailable/error states. Source/frontend tests do not establish native WebView behavior. |
| **Network/transfers/diagnostics:** `network_proxy`, `network_proxy_set`, `bandwidth_limits`, `bandwidth_limits_set`, transfer retry/cancel; `network-proxy.ts`, `transfer-limits.ts`, `transfer-presentation.ts`, `windows-compatibility.ts`; Tauri `export_diagnostics`. | Proxy applies to sign-in/refresh/file traffic; transfer controls/status and redacted diagnostics. | Windows proxy/bandwidth adapters and nullable pause/diagnostic differences are explicit. Compatibility warnings cover Windows naming/path hazards. | Exact GUI route/limit save and reconnect, transfer retry/cancel without false completion, useful exported diagnostics with secret/path redaction, and representative incompatible-name warning. Historical broker export is not physical export-button acceptance. |
| **Tray/startup/lifecycle:** Tauri `lifecycle.rs` / `main.rs`, `set_autostart`, agent `autostart.rs`. | Tray show/normal Quit and GUI launch-at-login integration. | Native tray/startup and shutdown adapters; CLI scheduled-task work is independently owned. | Exact current package tray/show/normal Quit with owned agent/provider cleanup; GUI startup enable/disable/restart. Current Linux fresh-profile normal tray Quit passes. CLI C9 same-user InteractiveToken manual-start rounds do not establish Windows before-login service acceptance. |
| **Updates/installers:** `desktop-shell/src-tauri/src/desktop_updates.rs`, `desktop_updates_policy.rs`; `scripts/test-windows-installed-package.ps1`, Linux packaging scripts. | Manual App updates, automatic checks, Later dismissal, verified download/install and safe shutdown source; tar/AppImage packages. | Same update policy, Windows NSIS in-place installation and running-process refusal; signature/archive validation is distinct from Authenticode. | Final-source installer/upgrade and exact installed shell/agent/CLI hashes; settings, credentials and synthetic data retention; visible version/App updates and normal Quit. Newer compatible offer/manual controls and tamper/version refusal. Current c584b8f run 40816324924 build and installed-upgrade jobs passed. The physical Windows laptop separately passed normal 0.7.4-to-0.7.5 upgrade, installed/runtime pins, saved-account reconnect and normal tray Quit. This does not establish positive encrypted browsing or full operations. |

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
| Browse/open and create encrypted folder | In-app `vault_list` and `vault_create`; mounted FUSE routes support ordinary encrypted child creation/mkdir when the route backend permits writes. | Inspect/unlock/Lock/Forget and native drive opening exist. Online in-app browsing is implemented in c584b8f, with positive native GUI acceptance pending an authorized fixture. Vault creation remains hidden in native mode. Mounted child mkdir/new-file creation is unsupported. Implement the existing Linux workflows before parity can be claimed. |
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

## Current acceptance update (29 October 2026)

- c584b8f Linux CI passed 350 frontend tests and 49 Tauri tests. Windows native
  build and 15-phase installed-upgrade acceptance passed. The physical Windows
  laptop passed normal over-install, exact installed/runtime hashes, restored
  saved sign-in, read-only Sharing inventories and normal Quit with zero remaining
  Raiun processes. Its drive was unconfigured/unmounted; positive encrypted
  browsing, pending-list Lock/account switching and slow-server UI were not run.
- The laptop Sharing editor observation remains incomplete: its actions collapsed
  without a persistent editor, and authentication generation changed over the
  observation interval. Cause is unestablished; no grant was changed.
- An earlier same-source push run 40816318069 failed the encrypted-cache test
  `ciphertext_epoch_change_during_pin_never_activates_the_partial_generation`
  before reaching its content-download checkpoint. Later passes do not erase it.
  The test's fixed readiness/delay timing has been replaced locally by an explicit
  GET gate, with local full gates, independent source review and one focused
  native Windows execution passing. This is test-proof hardening, not an
  established production root-cause fix for the original CI failure.
- Independent isolated Ubuntu VM package checks passed for the CI merge build
  0e1e6555d5c4059295951fc28d64bbc7528860f3. GitHub comparison proved its complete
  source tree identical to c584b8f. Package/installed hashes, dependencies,
  isolated installer, CLI entry points and retained canary passed; GUI launch,
  accounts and mounted workflows were not exercised in that check.
- C13 diagnostic ordinary capture/recovery passed four separately focused
  Windows cases: Personal/Space saves of 17 MiB + 7 bytes with verified readback
  and independent-process recovery, plus refused saves retaining local dirty
  bytes without replay. Earlier stage-19 failures remain retained.
- The actual GUI DPAPI constructor's local storage compatibility passed a fresh
  isolated Windows save/reopen fixture at the same size. Its strict shared-lock,
  original-root identity, legacy sentinel and modern v2 child checks passed.
  The first fixture's Busy assertion failure remains retained; its actual error
  was unrecorded. A corrected candidate recognizes fs2's native contention code.
  This establishes local storage compatibility, not installed GUI cloud saves.
- The subsequent C14 job/policy closure is composed locally into the Desktop
  source, with independent integration review, 1,309 host tests passing and
  strict Linux/Windows checks. One original cancellation/deadline job follows
  capture, queue, upload, independent readback and native completion. The next
  local GUI candidate now wires both current-user factories through the admitted
  streaming policy and retains the live job through explicit recovery completion.
  Its fresh isolated Windows factory prepare/reopen and three pure guard tests
  passed; this does not establish installed GUI cloud saves or native retry ACK.
  The default policy is 1 GiB per file, 8 GiB retained recovery state and a six-hour
  job. User-configurable GUI policy settings remain unimplemented. Source review
  also confirms that acknowledged bodies and their reservations remain accounted
  against the shared recovery-state budget. Repeated successful saves can therefore
  exhaust it; no supported completed-only reclamation path exists yet. This is a
  release gap, not a demonstrated native failure. Raising the budget does not
  reclaim space, and manual removal of protected recovery files is not a remedy.
  C13 native acceptance does not validate these newer C14 changes. C14's separate
  observer fixture failed preparation with PermissionDenied; directory and paced
  stages were not run in that invocation. The job closure excludes the observer,
  so an independent paced-save cohort can proceed without repeating that failure.
  Neither source totals nor these scoped tests remove the released 16-MiB
  ordinary or 512-KiB encrypted Windows ceilings or establish full parity.

- The independent C14 paced cohort passed existing-file saves of 2 MiB + 7 and
  17 MiB + 7 with conditioned readbacks lasting 32/34 seconds, exact native
  completion and independent DPAPI restart. The directory primitive passed only
  its Personal case; Space setup failed before mutation and the other three
  cases did not run. C15's corrected observer still failed with AccessDenied at
  reopen; connected-observer and expiry stages did not run. These failures stay
  separate from the successful paced-save evidence.
- The local Windows saved-edits UI now has explicit confirmed Retry behind an
  exact agent capability. Requests and replies bind profile, sign-in generation
  and recovery-root token; stale confirmations/results are discarded. Cloud
  verification and local completion are reported separately; immutable recovery
  records remain retained. There is no automatic retry or export action. This
  paired integration passed 1,311 host tests, 363 named frontend tests and strict
  Linux/Windows checks with independent review. Actual GUI retry and native ACK
  acceptance remain pending; the installed laptop remains c584b8f.
- C15's separate deadline-expiry cohort retained the exact pending edit across
  an independent DPAPI restart after readback exceeded its 60-second job budget.
  It issued no native in-sync acknowledgement or automatic replay. This is
  expiry-retention acceptance, not explicit user cancellation or GUI Retry acceptance.
- The separate C17 CLI candidate passed ordinary directory notifications and
  connected-root notification, revocation/drain and same-identity reconnect checks
  on Windows. Automatic Personal folder creation then failed before any remote
  mutation. A C18 diagnostic also stopped without remote mutation and did not
  establish the cause. These source snapshots are separate from this GUI branch;
  observer acceptance does not establish automatic folder creation or GUI parity.
- The shared new-vault primitive now supports repeated observed parent-identity
  checks while retaining partial folders on failure. This is not an atomic
  remote parent transaction, and Windows creation remains unavailable. A separate
  reviewed DAV parser correction joins bounded text/entity/CDATA fragments before
  interpreting metadata, accepts predefined and valid numeric XML references,
  and rejects unknown entities and DTDs. It does not establish the cause of the
  earlier native observer failures or add file-operation authority.

These records are under `desktop-release-prep-20261029/windows-ci-c584b8f/`
and `linux/c584b8f-vm-acceptance/` outside Git. Full file operations and GUI
parity remain unfinished. Reuse historical evidence only within its tested scope.

## Integration ownership and owner-ready queue

The 2 November source checkpoint adds guarded new-file creation in Personal and
existing managed Personal subfolders, owned SDK worker phases and metadata-only
population classification. Directory scheduling on the same SDK workers and
account-change drain ordering are integrated and source-checked; connected
device and exact-package acceptance remain open.
Normal CLI streamed-factory qualification is compiled only and stays disabled.
Production
creation remains disabled; compiled fixtures do not establish native or package
acceptance, and the verified create-only server-contract gate remains open.
Parent-folder/Space creation, replacement, deletion and encrypted parity are separate
remaining work. See [implementation status](IMPLEMENTATION.md).

The Desktop coordinator owns shared provider/filesystem, CLI, GUI, security and
release integration in this worktree. Windows laptop work is bounded native
testing under that ownership. Preserve the archived CLI handoff worktree,
Android, older checkouts, user data, credentials and original failure/recovery
artifacts. The project output `desktop-consolidation-20261031/READY-QUEUE.json`
holds the short live queue; the following items describe remaining gate groups.

1. Verify corrected-package live Sharing confirmation and investigate the
   incomplete editor observation; preserve completed live cleanup and failed CI evidence.
2. Finish shared ordinary CRUD, editor replacement and bounded >16-MiB
   writeback, with account/root binding and server-condition qualifications.
   Automatic new-file admission also requires a verified create-only
   server contract; local capture or successful readback alone is insufficient.
   Parent owns GUI recovery policy and reviewed completed-copy
   reclamation; preserve every pending, conflicting or uncertain record. The
   shared guarded-parent vault creation primitive is a prerequisite only;
   Windows creation admission and native route publication remain disabled.
   Assign the encrypted parity gaps above explicitly; they are not
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

## Earlier explicit rename storage integration

This section records the pre-owner-loop stages. The current checkpoint above
supersedes its statements that the automatic caller is unwired or unattached;
its narrow component evidence does not become mounted/package acceptance.

The GUI source includes shared admitted rename storage and a read-only health
consumer. Exact account/root authenticated metadata distinguishes completed and
unresolved rename history. Corrupt/unsupported evidence stays unknown; startup
without explicit namespace setup refuses retained matching history. Cached status
does not perform disk reads. Existing content streaming, retention and Retry
remain separate. These source changes do not activate automatic rename operations.
New Windows metadata controls require their own fresh owned native cohort; host
tests and cross-target compilation do not establish mounted GUI acceptance.

The composed partial binding-candidate API joins known opaque source/parent
identities to a typed same-batch rename hint. It grants no mutation authority
and makes no current parent/native classification claim. Fresh-proof native qualification
and the connected observer/owner-thread runtime remain outstanding. The four
original Windows candidate controls qualify the helper only; they are not
mounted GUI or CLI acceptance.

The explicit connected observer API is now composed with owner-thread, revocation
and drain/retention guards. It remains unattached by GUI production code. The
GUI test fixture uses only a fresh explicit private state root; no installed
account/default-state access is allowed. Native GUI observer execution, fresh-proof qualification and owner-thread
runtime wiring remain separate pending gates.

The explicit fresh-parent bridge is source-composed and cross-target checked.
Actual connected/native entry is still unexecuted. Before enabling a caller,
shared admission must exclude unfinished content and callback capture work;
existing save/Retry scheduling flags alone are insufficient. GUI owner-thread
wiring, namespace attention status and mounted/package acceptance remain open.

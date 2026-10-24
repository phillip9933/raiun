# Desktop implementation status

## Current release — Linux Desktop 0.7.0-beta.1, 21 October 2026

The first public Linux beta is based on the R200 implementation, with coherent
0.7.0-beta.1 package/binary versions and a history-preserving import into
`apps/desktop`. See [the app changelog](../CHANGELOG.md) for features and known
verification limits. Windows/macOS are not released. Earlier R-number entries
below are historical engineering evidence, not semantic release versions or
claims that each workflow is verified on this beta. Local evidence/output paths
refer to maintainer archives that are not part of this public source tree.

## Local next-release packages — 23 October 2026 JST

The frozen `4fb6b43` candidate now has an unsigned Windows installer built from
non-test Agent/CLI/Tauri binaries. An isolated ordinary-user fresh installation
passed installed-file hash/version checks, offline account creation/switching,
selection persistence after relaunch and two normal tray quits. The app and
agent were absent afterward and the VM shut down normally. This does not verify
prior-version upgrade or authenticated cloud/file-manager use. Earlier native
save/lifecycle and account-isolation component evidence remains separate.

The same source built a Linux tarball and AppImage on Ubuntu 24.04/glibc 2.39.
Exact tarball and extracted AppImage payloads displayed the revised Transfers
and Media Include explanations in isolated UI checks, with no remote writes.
Normal Quit and independent closure were verified. Original harness failures
(counter comparison and cleanup permissions) remain recorded; they are not
reported as an overall successful test run. Direct AppImage FUSE/file-manager
integration was not exercised. These packages are local candidates, with no
publication or new laptop installation.

Later source changes are separate from these frozen packages. Six focused
ordinary-user native checks now pass for protected existing-store inventory,
SQLite reopen, exact source receipts, account/source separation, folder sync and
media worker operations. The first test's wrapper parser failure is preserved
separately from its verified native pass; it was not rerun. The VM shut down
normally. Source exclusions include disabled media jobs and restored pairs.

The non-test candidate now enables folder sync, media backup and their existing
pause controls. Unit-test builds remain inactive. Final source gates and an
exact installer upgrade/offline GUI check are next; the previously accepted b7
installer remains installed and closed in the VM. This is not authenticated
packaged cloud acceptance or whole-category completion. Vault unlock remains
unavailable in that Windows package and its capability stays disabled.

## Latest local Windows acceptance — 24 October 2026 JST

The corrected non-test folder/media candidate (`4a60be3c` source archive,
installer SHA256 `2704c192a8c2718505b0ab92a5925c8c8ef5b3b80652523e8617affdadfdc22a`)
passed an ordinary-user offline upgrade, exact installed payload/version checks,
sign-in-required startup, account selection and persistence after reopening.
Both normal tray quits left zero Raiun processes; the VM shut down normally.
It remains installed and closed in that isolated VM. This supersedes b7 as the
latest local installed candidate, with earlier binaries and failure evidence
preserved. Nothing new is published or installed on the laptop.

The first activated package exposed a signed-out collection refresh error; the
corrected UI skips authenticated pair queries for disconnected Windows accounts
while preserving Linux behavior. Signed-out Media secondary wording is still
confusing and is a nonblocking known limitation. Connected packaged transfers
were not tested. The six native component passes and full source gates remain
separate evidence; Windows encrypted native access is still incomplete.

## Local Windows encryption work — 24 October 2026 JST

The next source batch connects verified vault reads to the existing single drive
backend, keeps historical encrypted locations out of the ordinary identity
catalogue, and shares one vault-session coordinator across account profiles.
Focused Windows component checks passed for verified reading and catalogue
exclusions. The hydration source also passed formatting, full workspace linting
and 959 Linux tests (14 ignored), with Windows cross-compilation tracked
separately. These checks do not establish packaged or native mounted-vault use.

Native hydration now records exact local file ownership before transferring
plaintext. Disconnect retains revoked routes through local cleanup and refuses
success when edits, uncertain state or cleanup errors remain. This lifecycle is
joined to typed broker unlock/lock requests behind a disabled production gate.
Unlock verifies current account/root and fresh vault metadata, persists the
historical exclusion before route installation, and clears the session on a
failed preparation. Per-vault lock retains cleanup ownership on failure and
clears scoped keys even when local cleanup cannot finish. Windows compilation
and strict linting passed for that request/cleanup batch.

The following source adds a pinned parent-directory population request after
route installation. It requests a future enumeration; it does not prove an
immediate Explorer refresh or remove cached children. The next source also resolves nested remote parents only through an exact
catalogue identity and current root label; native identity and fresh server
revalidation remain required. Native refresh, a complete mounted read/lock workflow,
cached decrypted-name visibility and restart cleanup coverage remain open.
A retained registration starts with unknown historical hydration custody, and
new vault activation is refused before password verification in that state.
This conservative guard prevents falsely certifying empty cleanup; it does not
remove or hide old plaintext/names. Durable historical custody is still pending.
User-facing vault unlock/lock stays disabled. No new installer or public release
is implied. The installed, closed VM candidate remains the 2704 build.

The next-source Media wording now distinguishes a reachable signed-out agent
from an unavailable agent; 22 focused UI tests and the UI build passed. That
wording correction is not yet part of the installed candidate above.

## Local Windows startup control — 24 October 2026 JST

The next source connects the existing Start at login control to an explicit
current-user opt-in. Status only reads the setting; installation, startup and
these tests never enable it. The command targets the actual packaged
`raiun-desktop-shell.exe`, is fully quoted, and respects the Windows Run command
length limit. Unknown or foreign entries are not overwritten or removed.
Concurrent changes can make the outcome uncertain; an error does not promise
that every attempted change was rolled back.

Four pure policy/format tests and Windows compilation/linting pass. The combined
Linux workspace gates pass with 963 tests and 14 ignored. Actual Windows startup
activation and packaged GUI acceptance remain unverified; the installed 2704
candidate is unchanged. The encrypted-folder native diagnostic now observes
successful directory population, but its external content read still fails;
read and lock-cleanup acceptance are not complete.

## Windows cloud-drive candidate — 23 October 2026 JST

The isolated ordinary-user Windows save and conditional lifecycle checks passed
on the exact 9219 source: ordinary OS saving reached verified remote readback,
native in-sync marking, all identity postchecks and protected local completion;
reopen/lifecycle also passed. The non-test candidate now enables the existing
account-bound provider and verified-save path. Ordinary unit tests remain
kernel-inactive and ignored native fixtures retain explicit per-instance opt-in.
Actual non-test package installation and offline GUI checks passed as described
above; authenticated native file-manager package acceptance remains unclaimed. No new Windows release has been published, and no real
cloud account or files were used for acceptance. Folder/media candidate activation is described above. Vault capability remains disabled.

## Windows accounts — 23 October 2026 JST

The non-test candidate broker now routes independent profile runtimes, persists
selection before publishing it, refreshes every account and joins every runtime
on shutdown. Selecting an account does not log out the others. A persistent
private-file ownership lock spans registry access, pipe reconnections and all
shutdown joins. Configure requires an authenticated session before reserving a
root; exclusions are persisted before configuration and retained after failure
or logout. Protected metadata inventory includes logged-out registered roots;
metadata alone cannot authorize account restoration or native registration.

Native component tests have passed profile/session isolation, foreign-scope
refusal and registry replacement/reopen. Four focused native checks also passed
logged-out root inventory, lifetime owner exclusion, issuer-bound metadata decoding
and integrated broker routing/persistence/reopen. Account switching is now exposed
only by the non-test broker; ordinary unit builds remain inactive. The exact
non-test installer and sign-in-first account dialog passed focused offline
package acceptance; authenticated live-account acceptance remains unclaimed. Cross-account folder/media source admission now has focused native acceptance;
exact candidate package acceptance remains pending.
These source changes are unpublished and do not change the installed beta.

## Windows folder and media integration — 23 October 2026 JST

The Windows engine retains private state, cache and media-staging directories
with its guarded SQLite owner. Its fixed `engine.sqlite3` uses rollback
journaling; Linux retains WAL. The account-scoped settings document compares
exact previous bytes, full account identity and revision before publication,
preserving folder pairs, pause settings, media jobs and retired pair IDs.

The existing Windows command worker owns ordinary-folder operations independently
of Cloud Files registration. One focused ordinary-user native workflow passed
initial download, conditional edit upload, pause/resume, exclusion, removal and
runtime reopen while preserving local data. This is component acceptance;
non-test candidate capability flags are enabled and packaged GUI acceptance is pending.
Account transitions revoke subsequent writes and drain the worker before
credential replacement. Source and destination handles reject reparse points;
immutable source handles span upload and verified readback.

Media source traversal uses a duplicate of a pinned directory handle. Protected
staging uses existing private-file APIs, flushes and no-replace publication,
then retains an immutable reader through attempt creation, upload, readback and
receipt commit. Cleanup checks the exact file identity; uncertain results retain
recovery. Local recovery can use the held account-bound engine database instead
of reopening SQLite by path. Existing Windows recovery RPCs check the saved job,
account and revision before and after the read.

Explicit media runs now have gated prepare → queued acknowledgement → execution
on that same worker. Preparation checks enabled state, global/Space pause,
recovery, overlap and the live destination identity. The admitted source pin
stays held, and Engine compares its identity with the opened root before scanning.
Cancellation checks account generation, revocation and source-path validity.
Idle media selection also reuses this worker, durable run status and existing
intervals; it does not replay uncertain attempts or create another scheduler.
Fresh admission does not claim persisted historical source identity across restarts.

Early Windows compilation now covers idle scheduling. Two ordinary-user MSVC
engine cases passed normal media import/verified updates and collision/lost-response
recovery across engine reopen. The actual ordinary-user worker-control case also passed stability waiting,
verified upload, pause and account-scoped recovery checks. This is not GUI or
packaged acceptance. Media execution and its UI capability are enabled in the non-test candidate;
exact package acceptance is pending and no new public release is claimed.

Windows also has a read-only vault-inspection path using existing authenticated
Graph/DAV metadata. It grants no unlocked session, remembered password, verified
cryptographic state or decrypted native route; the vault UI capability stays off.
Inspection does not unlock a vault or authorize encrypted transfers.

## Next-release Windows save-back work — 23 October 2026 JST

Windows save-back now has a fresh, read-only verification result that binds the
protected edit metadata to an exact current remote resource, strong ETag, size
and content hash, with authorization checked again after readback. An upload
success or cached journal outcome cannot construct this result. A leased
existing-identity catalog refresh and guarded native completion operation build
on that proof. The native operation pins the exact local file, checks its full
hash and two matching positive USN observations. The current candidate holds
the existing publication/token fence before opening an exclusive protected file
handle and retains both through proof, OS marking and durable acknowledgement.
The shared fence also excludes provider payload writes; the protected reference
excludes ordinary writers. OS marking passes a null optional USN pointer without a USN
comparison as this design's sole path, never a failure fallback or retry. The fresh callback now carries its actual pinned local
path and opaque identity, separately from the remote path. The worker joins that
handoff to a fresh readback proof, native completion, and a protected terminal
local-acknowledgement event. That event resolves only the exact immutable record;
it preserves all encrypted bodies, including other edits of the same file in the
same account generation. Remote verification alone leaves recovery unresolved.
Publication, OS completion, and the durable event share the same account fence;
a partial failure keeps recovery available. Retained acknowledged snapshots still
count toward the existing journal quota; this change does not delete them. Focused portable integration checks
pass. Actual MSVC compilation and linking now pass, but the focused ordinary-user
save case still fails at Windows' final in-sync comparison (`0x80070179`) after
verified upload/readback. An access-mask experiment did not resolve it and was
reverted. Recovery remains retained, lifecycle acceptance was not advanced after
the failure, and both activation switches remain off. Actual numeric diagnostics
showed both pre-CAS reads at USN 150231648 and a single read after refusal at
150240984. This establishes journal movement, not the reason or a successful fix.
Posting pending NTFS journal reasons before the first snapshot was tested and
also failed at the same comparison; that experiment has been removed. The close
callback was captured and journaled successfully in that run. A later protected
handle with the same OS comparison also refused completion. The current combined
content-exclusion design is independently reviewed but still requires native
writer-exclusion, normal save and lifecycle acceptance. Recovery remains retained;
there is no post-proof refresh or retry, and no successful native completion is
claimed.

## Next-release media recovery — 23 October 2026 JST

New media upload attempts retain the destination root resource identity alongside
the existing account, origin, Space, job revision and attempt generation. The
additive database migration preserves older attempts with an unknown (`NULL`)
root identity; it does not infer one from current settings.

The next Linux candidate adds an explicit **Verify uploaded copy** action for
newly bound uncertain attempts. It conditionally reads the exact destination
and compares its bytes with the saved attempt hash without reading or changing
the original/staged copy. A match is a point-in-time observation; it does not
commit a receipt, resume the schedule, clear recovery, or replay an upload.
Legacy/unbound attempts remain inspection-only. Focused engine, agent and UI
checks pass. The exact Linux candidate's single native action passed with source
and recovery unchanged, no additional PUT/MOVE/DELETE, and normal app closure.
That acceptance is scoped to this action. This work is not in the published beta
or the older frozen Windows installer candidate.


## Current recorded state — R180 installed and left closed, 18 October 2026 JST

The exact unsigned R180 Linux package passed an isolated upgrade from a genuine
R172 schema-6 synthetic cache to schema 7. The same account, scope, write ID and
48 MiB unsynced edit survived unchanged. The packaged Transfers action and native
Save dialog exported it once with mode 0600 and matching bytes. Native tray Quit
closed the exact shell with exit 0, its agent, control socket and OpenCloud mount.
Private test-session closure preserved all 44 unrelated mount entries. Parent
review checked 488 raw evidence hashes. Harness assertion failures are preserved;
no repeated export or successful cloud write occurred. This does not establish
a slow export lasting over ten seconds or whole-checklist completion.

The laptop was already closed. Its six previous public installed files were
verified against the preserved R172 backup, then the exact R180 package was
installed with exit 0. All installed payload and manifest hashes match the
VM-verified archive, SHA-256
`a8bdbee0d005c29641bfd78a1b1cc75979858a8a4e5ecc8756dc19d2acff0be6`.
The app and agent remain closed. No host profile was opened or migrated for this
test. Previous binaries are retained; schema-6 binaries cannot open a cache after
it has migrated to schema 7, so retaining binaries does not authorize downgrade
or discarding edits.

Windows R178's eleven journal/backend native cases and R179's four discovery
delta cases passed parent review. R179's required source gates and 28 focused UI
tests/build pass. R181's unsigned test-version 0.1.6 installer was generated and
parent-verified against its exact manifest and 212 source inputs. Its wrapper
reported exit 1 after generation because it expected the wrong output directory;
that failure is preserved and read-only postflight recovered the existing
artifact without rebuilding. The related synthetic R79f 0.1.5 installation was
upgraded once to the exact R181 0.1.6 package under the genuine ordinary WTS user.
Installer and user-child exits were 0; the three installed package payloads,
registration, both shortcut targets, absent startup Run value and two fresh
synthetic state markers passed comparison. Scoped registry observations were
unchanged but do not establish all retained Cloud Files root identities. The
first preflight argument-framing failure occurred before state creation or
installer execution and is preserved separately.

The isolated installed Windows app has rendered the correct 0.1.6 footer and
signed-out UI. Normal window Close retained the pinned shell and agent in the
tray. An overly broad guard first rejected an unrelated retained suspended test
process before app launch; parent kernel-image/hash/thread proof permits only
that exact non-shell test as an exception, untouched. Native tray Quit now passes:
the parent reviewed the exact shell-owned menu, one Quit click closed shell
9348 and agent 4476 with numeric exits 0, and the SID control pipe was absent.
The WTS child also exited 0. Earlier harness failures are preserved: a case-only
Explorer path mismatch was corrected from read-only HWND evidence, and the R4
continuation retained R2-labelled output filenames. Collection was corrected
without repeating Close or Quit. The installed test app is left closed.
Windows reported low disk space (C: 1.129 GiB free, R: 65.83 GiB free, both NTFS).
No old scopes, recovery or user data were cleaned and no OS policy was changed.
One native default uninstall removed the four installed files and registration
while preserving both synthetic state markers, the absent startup value and
scoped registry observations. Its completed UI was closed once, and actual WTS-session evidence confirms
the window, processes and SID pipe are absent. A post-click harness error lost
the UI exit code, which remains unavailable; Close was not repeated. The exact unsigned package was then freshly reinstalled with installer and
WTS-child exits 0. Payload hashes, uninstaller/version, registration, both
shortcut targets, preserved markers, absent startup value and scoped registry
baseline match; the SID pipe and app/agent processes are absent. It is installed
and left closed. The earlier UI-exit gap remains; this is not an all-exits-zero
lifecycle or whole-checklist completion claim. Earlier harness
failures were preserved, and the recovered original launcher exit is unavailable.
R182e now passes the first Explorer views for Personal, Spaces and Projects in
the isolated synthetic Windows lifecycle fixture. Initial and three stable UIA
samples contain the exact expected entries, native enumeration callbacks advance,
and screenshots show the entries. Each owned Explorer window closed normally;
the registered root identity remained unchanged throughout. The Rust test,
responder and ordinary WTS child all exited 0. Parent review independently
rehashed 20 guest/local evidence files and inspected all three screenshots.
Personal's item content is visible although some Explorer chrome was unpainted.
Explorer identity is authenticated by the external WTS evidence; the Rust test
explicitly treats it as harness-reported.

Earlier sharing-reader, foreground and caption-hit-test failures remain preserved.
R182d stopped before an unsafe focus click and exited naturally with 101; its
owned window was subsequently closed in the actual interactive session. R182e
used the unchanged test binary and a reviewed ItemsView background focus fallback.
No successful view was repeated merely to repair evidence.

Production Windows provider activation remains false. This synthetic read-only
fixture does not establish normal save-to-cloud, real account sign-in or the
packaged app's account/root lifecycle. Conditional dirty-save and recovery
reconciliation remain required before activation; C02 remains open.

Source follow-up R183b limits generic encrypted-write retries to established
operation classes. Copy and unknown future transfer classes cannot enter that
queue; restart regressions preserve the saved bytes and ordinary retry flow.
Required host format, lint and workspace tests pass. Both exact portable cache
regressions also pass natively under the ordinary Windows user; test build,
selector listing, check, clippy, test exits and wrapper exit are all 0. Parent
review independently rehashed 23 raw guest/local files. The original R183
Unix-only test-placement failure is retained. Cross-vault move remains unsupported;
this is its retry-safety foundation. Installed R180/R181 packages are unchanged
and closed; R183b is source/component verification, not a new installation.

R184 adds a separate initial-save admission foundation for Windows. It admits
only never-attempted journal snapshots, persists reservation before upload, and
permits a bounded retry only within that same invocation. Recovered uncertain
or terminal attempts still require explicit review. Fourteen focused host
reconciliation tests and all required workspace source gates pass. Independent
source review found no admission bypass. All three exact native Windows cases
pass; parent independently rehashed 31 raw guest/local files. No background save
trigger or provider activation is enabled by this change. Cross-vault source removal also
remains disabled pending a proven atomic resource-identity/validator contract.

R185 binds the next save handoff to an opaque, single-use receipt from the exact
new durable append. It rejects other prepared instances, reopened instances,
changed metadata and previously attempted records. The initial dispatcher is
now private to the adapter crate. Five focused receipt tests pass and independent
review found no preservation or replay regression. All required workspace checks
pass. All five exact native Windows receipt cases pass; parent independently
rehashed 47 raw guest/local files. No new package was installed.

R186 batches the next integration work: durable close capture now hands off a
bounded queue of opaque receipts to the exact live connection. A gated worker
route retains the publishing recovery instance, verifies the current root and
account generation, and freshly validates the ordinary Space before conditional
save/readback. Overflow preserves the durable edit. Seventeen focused host tests
and all required workspace source gates pass. Exact Windows verification is in
progress. Both production
activation and initial-save dispatch remain disabled. Native acknowledgement of
an unchanged local file and restart acceptance are still required.

Linux is now the primary release target by owner instruction, 18 October.
Windows verification continues in parallel; new Windows feature implementation
is deferred. R189 corrects ordinary FUSE directory listing failures that were
silently shown as empty directories while offline. An unavailable listing now
returns the original offline error unless an authenticated active vault overlay
is available; verified cached listings and pinned vault routes retain their
existing behavior. Two focused regressions and all required full source gates pass.
This is source work only: bounded ordinary offline namespace recovery,
exact-package restart/reconnection and successful save-back acceptance remain
open. R180 is still installed and closed. No completion category is newly closed.

R189's new Linux package is built and parent-verified against 201 unchanged
public build inputs and all 13 archive members. The first build's missing
pre-build pin record is preserved; a separate incremental build supplies the
complete before/after provenance. No new laptop installation has occurred.
Isolated native ordinary-save and offline-error acceptance is being prepared
against that exact package; restored NAS connectivity does not itself establish
acceptance.

R190 adds a separate read-only retained-pin metadata query for future offline
recovery. It retains explicit historical pin state, exact account/root binding,
read-only entries, bounded metadata and validated parent/path ancestry. It never
publishes a current listing, infers remote absence or mutates pending writes.
Five focused cases and all required workspace source gates pass. This primitive
is not yet integrated into the visible filesystem; C03 remains open.

R191 adds the account-bound Engine consumer for historical pin metadata and
repairs an independently reproduced API boundary: rebinding a cache-bearing
Engine to a different account previously retained the old cache handle. The
replacement now retains it only for the same prior account and canonical server;
the original Engine and retained data are preserved. Same-account origin
canonicalization, rejected origin changes, cross-account denial and stale-pin
recovery without current-listing publication have focused regression coverage.
Independent review found no remaining concrete issue. Normal Unix account setup
uses a fresh account-specific Engine, so this synthetic API defect does not
establish exposure through the native account-switch flow. All required source gates pass; no packaged or native acceptance is claimed
for R190/R191 beyond their inclusion in the unaccepted R192 candidate.

R192 is the consolidated Linux candidate for R189–R191. Parent review verified
203 unchanged declared public inputs and all 13 archive members; native package
acceptance and installation remain pending. Intermittent NAS transport left an
unknown R189 transfer destination, which is preserved untouched. R192 uses a new
isolated scope and synthetic account/server for ordinary save-back and offline
error/restart retention checks; no real credentials or account data are staged.

The C04 audit identified a missing per-Space folder-sync disconnect. R193 now
implements that agreed control in Linux source and UI. It removes all folder
pair connections for the chosen Space through one durable settings update and
one shared dispatch fence, retains retired-ID tombstones, and rejects delayed
sync snapshots. Local/cloud files, account/cloud-drive browsing, media jobs and
recovery are preserved. Persistence-failure and multi-pair isolation regressions
pass; independent review is clear, the UI build and shell completion-wait test
pass, and all required workspace source gates pass. This disconnect applies to folder
sync connections; it does not remove a Space from the account's cloud drive.
R193 is not included in R192 and has no native/package acceptance yet.

R194 adds exact historical pin-content reads for the planned read-only recovery
view. It validates full manifest membership and account/server/root scope, opens
only the cached resource/version, checks length and rechecks the manifest after
integrity verification. It never resolves the old path against the live cloud.
The focused byte-read/forged-path regression, independent policy/identity review
and all required workspace checks pass. Ordinary FUSE sessions retain a fixed
Engine; account transitions wait for unmount/session shutdown. This primitive
alone does not establish complete offline availability or native acceptance.

R195 integrates an explicitly historical, read-only “Saved offline copies” folder
when ordinary folder pins are stale or incomplete. It exposes retained exact
versions without restoring a current listing or inferring cloud absence. Cached
bytes can be read after an Engine/cache restart; absent bytes remain unavailable.
Account/server/root binding and encrypted-scope exclusion remain enforced.
Source review identified a concurrent name-replacement hazard; mount-lifetime
alias deny records now preserve mutation rejection even after an already admitted
cloud create replaces a displayed name. Four focused filesystem tests pass,
including that interleaving, stale-inode rejection and collision-safe naming.
All required workspace formatting, lint and test gates pass on stable final
sources. The regression uses an observable conditional-delete backend and
confirms zero calls after name replacement. R196 packages R193–R195 over R192;
parent audit verifies 205 unchanged declared public build inputs and all 13
archive members (archive SHA-256
`fa8d92f8869b7301a06af245f2168a0c9977e2b1d8a48418fdf12235a03539e6`).
R196 exact-package native phases now pass ordinary conditional save/readback
and restart/reopen, no-pin offline dirty preservation with explicit reconciliation,
and historical plaintext pin recovery after an offline restart. The recovery
phase read and exported the exact 67-byte saved version, rejected all five
attempted recovery mutations with EACCES, preserved the 56-byte unsent edit and
its journal/cache, and left the remote snapshot unchanged. Both agent instances
and the synthetic fixture/keyring/private bus closed with numeric exit 0; the
control socket and mount were absent. The prior successful phases were not
replayed. See the recovery audit (maintainer-local evidence: `../../outputs/linux-ordinary-save-20261018-r196/parent-native-recovery-review-r196-r12.json`)
and save/reconciliation audit (maintainer-local evidence: `../../outputs/linux-ordinary-save-20261018-r196/parent-native-phase-review-r196-r9.json`).
R196 also has independently recovered native per-Space pause/resume evidence.
The exact packaged app accepted both AT-SPI press actions; authoritative status
paused only Space A, then restored its original empty paused set, while global
pause stayed false and Space B remained unaffected. The original durable
checkpoints were collected read-only after the later traversal failure; these
actions were not replayed. See the partial controls audit (maintainer-local evidence: `../../outputs/linux-ordinary-save-20261018-r196/r18-exported-checkpoints-parent-r1/parent-phase-review-r1.json`).
The target-sync result checkpoint is absent, so targeted completion, exclusions,
disconnect and restart are not accepted by this run. Its owned processes,
endpoints and mount closed; adopted numeric exits remain unavailable.
Remaining native UI controls, media and other checklist flows still require
acceptance. R196 is not release-ready or installed; installed Linux remains R180.
No whole completion checklist category is promoted by these partial phases.
R192 product tests never started: its exact archive and eight auxiliary inputs
were transferred and verified, but staging stopped before profile creation at a
manifest-key assertion. The partial scope and subsequent read-only transport
timeouts are preserved. R196 now supersedes the pending R192 runtime cycle so
ordinary-save and new recovery checks use the current package;
no obsolete package is installed merely to complete that old checkpoint.

Evidence: parent Linux VM audit (maintainer-local evidence: `../../outputs/vm-lab/linux-folder-offline-write-20261018-r180/evidence-r180/parent-native-acceptance-r180.json`),
installed state (maintainer-local evidence: `../../outputs/install-candidates/r180/installed-state.json`),
previous public binary backup (maintainer-local evidence: `../../outputs/install-backups/r172-before-r180-20261018T010817Z/backup-proof.json`).
Windows GUI evidence: parent native GUI audit (maintainer-local evidence: `../../outputs/windows-package-r181/windows/evidence/parent-native-gui-acceptance-r181.json`).
Windows component evidence: parent three-view Explorer audit (maintainer-local evidence: `../../outputs/windows-explorer-first-view-20261018-r182/windows/r182e-itemsview-background-focus/evidence/parent-native-acceptance-r182e.json`),
parent native retry audit (maintainer-local evidence: `../../outputs/cross-vault-move-foundation-20261018-r183b/windows/evidence/parent-native-acceptance-r183b.json`).
Save component evidence: parent initial-dispatch audit (maintainer-local evidence: `../../outputs/windows-initial-save-admission-20261018-r184/windows/native-runner-r184/native-evidence-r184/parent-native-acceptance-r184.json`),
parent fresh-receipt audit (maintainer-local evidence: `../../outputs/windows-fresh-edit-receipt-20261018-r185/windows/native-runner-r185/native-evidence-r185/parent-native-acceptance-r185.json`).
Earlier installation/process statements below are historical records.

Canonical state: desktop-continuation-state-20261017.json (maintainer-local evidence: `../../outputs/desktop-continuation-state-20261017.json`).
R130 evidence: native acceptance (maintainer-local evidence: `../../outputs/vm-lab/linux-cache-publication-fence-20261017-r130/native-acceptance.json`),
install record (maintainer-local evidence: `../../outputs/vm-lab/linux-cache-publication-fence-20261017-r130/laptop-install-r130.json`),
and continuation status (maintainer-local evidence: `../../outputs/vm-lab/linux-cache-publication-fence-20261017-r130/evidence-linux-r130/R130-continuation-status.md`).

## Historical installation: R123, closed — 17 October 2026 JST

The exact R123 Linux package is installed and left closed. Its isolated native
Transfers flow exported a 53-byte pending saved edit while a fresh complete
listing was unavailable, preserved the dirty journal and cache bytes, and made
no additional PUT or destructive request. The exported file was private and
byte-exact. Normal owned tray Quit and independent process/socket/mount closure
passed. The previous R119c binaries and launcher are backed up; real profiles
and recovery data were not changed. The original UI selector failures are
preserved, and no numeric shell exit code is claimed because its original
parent had exited; separate closure proof passed.

Evidence: parent acceptance (maintainer-local evidence: `../../outputs/vm-lab/linux-saved-edit-export-20261017-r123/native-acceptance.json`),
installed state (maintainer-local evidence: `../../outputs/vm-lab/linux-saved-edit-export-20261017-r123/laptop-install-r123.json`),
and native details (maintainer-local evidence: `../../outputs/vm-lab/linux-saved-edit-export-20261017-r123b/R123b-acceptance-status.md`).
R126 now has 12 individually verified native Windows filter passes: four
account/root-fenced cache-status tests and eight exact-binding cache tests.
The first harness stopped after two passes; a fresh continuation ran only the
remaining ten. Raw numeric exits, stdout and pre-resume identity/hash checks
passed, and scoped processes were closed afterward. Final wrapper summary/exit
records are unavailable and are not claimed as a clean aggregate wrapper run.
Parent native review (maintainer-local evidence: `../../outputs/vm-lab/windows-cache-policy-binding-20261017-r126/parent-native-acceptance.json`).
R127 cache-publication hardening passed 784 host tests (13 ignored), formatting
and strict Clippy. Its exact R128 Windows cache artifact passed all 15 serial
native policy/invalidation tests, including final metadata revalidation and
preserved dirty bytes; native process and wrapper exits were both zero and
postflight found no scoped process. Parent native review (maintainer-local evidence: `../../outputs/vm-lab/windows-cache-publication-fence-20261017-r128/parent-native-acceptance.json`).
**Earlier status, superseded by R130 acceptance and installation:** the combined
R130 Linux package had passed its fresh-home VM installer check, while its
native runtime/export acceptance was still pending and R123 remained installed.
R131 adds test-only positive connected-worker cache-status request coverage;
Windows compilation/native acceptance via R132 remains pending. Windows production activation and full verified AlwaysOffline
workflows remain disabled/incomplete. This installation does not complete the
backlog or add cold-login/Wayland/live-server acceptance.


## Earlier installation: R119c, closed — 17 October 2026 JST

R119c is installed on the Linux laptop after exact-package isolated VM
verification. Saved edits now expose their exact saved-root identity through
an explicit keyboard-operable disclosure; focus and expansion survived passive
refresh. The pending 49-byte synthetic edit retained its exact journal ID,
root binding and content hash, and native tray Quit left the scoped app, agent,
socket and mount closed. The fixture snapshot remained unchanged with zero
successful PUT/DELETE/MOVE. AT-SPI omitted the state label and controls relation;
these are recorded limitations. Detached helper and attached shell numeric exit
codes are unavailable, rather than reported as zero; independent closure proof
passed. No new cold-login or offline-restart acceptance is claimed.

Package SHA-256: `b3932a858d09dbf7d797765614a6567a5e57650afeaa4318106e82b84d24cca5`.
Previous R116a binaries and launcher are preserved at
`../outputs/install-backups/r119c-before-install-20261017T061603Z/`.
Recovery and profile data were untouched; the app remains closed.
See parent acceptance (maintainer-local evidence: `../../outputs/vm-lab/linux-offline-recovery-identity-20261017-r119c/native-acceptance.json`)
and installed hashes (maintainer-local evidence: `../../outputs/vm-lab/linux-offline-recovery-identity-20261017-r119c/laptop-install-r119c.json`).


## Current laptop installation: R116a — 17 October 2026 JST

R116a is installed, all payload hashes verified and the app left **closed**.
Archive SHA-256 is
`c857e88af79acd43c0a0b930051471a23ddcd9ed99f796ce56bb59bbc79d0a8e`;
agent SHA-256 is
`3dd33e40dfb9437cffcb7798ebc7223da1e89ebcdc63e9fe84925f879734730a`.
R112 binaries and launcher are preserved at
`../outputs/install-backups/r116a-before-install-20261017T051630Z/`.
Profiles, recovery, accounts and real cloud data were untouched.

The exact agent/UI binaries passed native file-policy acceptance and an actual
agent-process restart in the same warm synthetic keyring/private bus. A fresh
complete root listing survived the rejected dirty PUT. After restarting offline,
the pinned 35-byte file read exactly with zero file-body GETs; CloudOnly refused
with EHOSTUNREACH, and the pending 34-byte edit, journal and exact bytes survived.
The snapshot stayed unchanged with zero successful PUT/DELETE/MOVE or identity
provider requests. Native tray Quit closed the UI/agent; its helper exited 0.
The attached shell's numeric exit remains unavailable because the first driver
failed before policy actions; no zero was inferred. The restarted agent exited 0.

R116's first host install was safely refused before mutation because the custom
bundle timestamp did not match the installer's strict UTC format. R116a changes
only that manifest timestamp; its other 12 members are byte-identical to the
native-tested package. The exact corrected archive passed an isolated fresh-HOME
VM installer gate before laptop installation. Source format, strict Clippy and
workspace gates passed (767 tests, 13 ignored). Earlier harness failures and
original package/install records remain preserved. See
R116a acceptance (maintainer-local evidence: `../../outputs/vm-lab/linux-failed-upload-listing-refresh-20261017-r116a/native-acceptance.json`)
and installed state (maintainer-local evidence: `../../outputs/vm-lab/linux-failed-upload-listing-refresh-20261017-r116a/laptop-install-r116a.json`).

This does not establish cold-login/keyring restoration or recovery enumeration
when a mutation invalidates a parent listing and fresh metadata is unavailable.
R118 recursive-folder native acceptance passed on the same R116a binaries.
Windows R117d catalog/cache preflight passed; actual duplicate-edit process
restart remains open. Windows production activation remains disabled. Older
installation checkpoints below are historical.

## Recursive ordinary offline folder acceptance — R118, exact R116a package

Native Keep offline produced a Ready five-entry manifest with three verified
files across two nested directories. After normal Quit and agent-only restart
in the same warm private keyring session, all three files read exact bytes
offline with zero body GETs. A later same-length edit under rejected synthetic
PUTs stayed pending. The native dirty-file CloudOnly request was refused; the
folder's separate “Remove stale snapshot” action removed only the pin manifest
and retained the 34-byte edit and journal ID 1. The server snapshot stayed
unchanged, with zero successful PUT, DELETE or MOVE.

Normal tray Quit left the shell, agent, socket and FUSE mount absent. Attached
shell exit codes were unavailable and are not recorded as zero. Earlier selector,
readiness, UID, staging and mutable-state harness failures remain preserved;
the accepted continuation used the same processes without reseeding or replaying
the edit. This establishes warm process restart and pin removal, not cold-login
restoration or recovery enumeration after invalidated metadata. See
R118 parent acceptance (maintainer-local evidence: `../../outputs/vm-lab/linux-recursive-always-offline-20261017-r118/evidence-linux-r118/parent-native-acceptance.json`).

## Nested encrypted copy acceptance — R113b, exact R112 package

The native destination chooser successfully copied one 56-byte synthetic file
into an existing authenticated `/Existing` directory in another unlocked vault.
Plaintext readback matched, the source stayed unchanged, and the destination
journal retired. The copy made one conditional PUT and five conditional GETs,
with zero DELETE/MOVE. The exact shell's normal tray Quit closed shell and agent
without changing the fixture snapshot. Parent reviewed the chooser screenshot.
Earlier fixture content-type assumptions and pre-action Quit harness failures
remain preserved; the fresh corrected scope passed. This covers one nested
existing-parent copy, not folder creation, moves or live interoperability.
The laptop already has this R112 package installed and remains closed; no
reinstall was needed. See
R113b acceptance (maintainer-local evidence: `../../outputs/vm-lab/linux-vault-copy-nested-existing-parent-20261017-r113/evidence-linux-r113b/r113b-native-acceptance.json`).

## Windows catalog preflight diagnosis — R114d / R117 source candidate

The isolated standard-user R114d diagnostic failed at catalog upsert. Its
bounded probe could create the 275 UTF-16-unit directory but could not apply
the current-user protection through the raw Win32 path; shorter depths passed.
The raw Rust result is one failed test. The wrapper incorrectly converted a
missing process exit code to success, so its `native_passed` record is invalid;
raw logs and that discrepancy are preserved. There was one native test launch;
a second wrapper invocation was refused by its freshness guard.

R117a passed its Windows build gates and the long-path DPAPI and 14 cache
checks, but the actual agent diagnostic failed before catalog creation:
its public extended-length root was rejected by the private-directory path
policy. The failed runtime and profile remain preserved; there was no retry.

R117b kept the canonical public DOS path and passed both native control
checks plus all 14 cache tests. Its actual agent diagnostic then reached the
long-path cache open and failed with SQLite “unable to open database file.”
The failed standard-user profile remains loaded and its evidence is preserved.
An earlier wrapper staging-path guard failure occurred before account creation
or native tests and is recorded separately.

R117c introduced the locking `win32-longpath` VFS and internal canonical
extended aliases; its Windows compilation passed, but its wrapper expected the
wrong SQLite test count. It was never run natively. Parent review then found a
pre-existing lower-VFS ABI bug: SQLite filename helpers inspect metadata outside
a visible C string, so handing lower `xOpen` a plain CString was invalid.

R117d retains public DOS matching and directory/identity guards, and owns a
`sqlite3_create_filename` allocation for the full lifetime of every lower file
and context lease. Only its database/journal aliases reach lower `xOpen`; WAL
remains refused. Independent ownership/security review found no blocker.
Host and fresh Windows build gates passed. Native standard-user verification
passed all 33 tests: two control, 14 cache, 16 SQLite VFS and the actual agent
catalog/cache preflight. The raw native exit was zero, the fresh profile was
unloaded and no scoped process remained. The account was actually named
`raiunC117c` (SID ending 1211) despite the R117d scope suffix; its absence guard
and token checks proved it was fresh, and no prior profile was reused. Earlier
pre-build wrapper hash/path refusals remain preserved. Provider activation and
actual duplicate-edit process restart acceptance remain open. See
R117d parent acceptance (maintainer-local evidence: `../../outputs/vm-lab/windows-private-state-long-path-20261017-r117d/parent-native-acceptance.json`). See
R114d raw evidence review (maintainer-local evidence: `../../outputs/vm-lab/windows-restart-preflight-diagnostic-20261017-r114d/native-evidence/evidence-review.txt`),
R117a native failure (maintainer-local evidence: `../../outputs/vm-lab/windows-restart-preflight-diagnostic-20261017-r117a/native-evidence-failure-1/review.txt`),
R117b native evidence (maintainer-local evidence: `../../outputs/vm-lab/windows-private-state-long-path-20261017-r117b/native-runner/native-evidence-run-2/`)
and R117c path review (maintainer-local evidence: `../../outputs/vm-lab/windows-private-state-long-path-20261017-r117c/review-advisory.md`).

R119 adds the persisted root identity to Linux saved-edit responses and separates
same-Space edits by saved root in Transfers. It makes no claim that a retained
journal row proves readable bytes or current cloud state. Host gates pass
(768 tests, 13 ignored), four UI scope tests and the full Linux package build
pass. R119's native HTML disclosure did not expand through the tested AT-SPI
or pointer paths, so no native acceptance or laptop install was claimed.
R119b replaced it with an explicit native button; R119c also preserves exact
scope/account focus across renders. The R119c exact-package native disclosure and normal-Quit gates passed;
the package is now installed and closed (see current installation above). The original failed R119 VM shell/profile remain intact; prior R116a
binaries and launcher are backed up.

## Offline restart gap confirmed — R115, 17 October 2026 JST

An actual offline restart of the installed R112 package mounted the expected
cloud root but left Personal empty: its exact account/root cache scope retained
the AlwaysOffline content and dirty journal, but had no saved directory listing.
The same private keyring remained running; no credential reseeding or login was
performed. The synthetic remote snapshot and successful mutation counts stayed
unchanged. The failed runtime is preserved for diagnosis. This is a functional
offline availability gap, not a completed restart acceptance.

R116 source work attempts a narrow repair: after a failed upload, read a fresh,
complete parent listing under the unchanged verified root when metadata remains
reachable. Never restore invalidated stale rows or treat an unacknowledged upload
as verified. If metadata is unavailable, listings still fail closed and protected
bytes remain retained; a separate safe recovery projection is still needed.
R116 is not packaged, VM-accepted, or installed. Evidence:
R115 preserved diagnosis (maintainer-local evidence: `../../outputs/vm-lab/linux-offline-process-restart-20261017-r115/`).

## Installed R112 cache retention acceptance — 17 October 2026 JST

R112 is installed on the Linux laptop, hashes verified and left **closed**.
The exact archive SHA-256 is
`c0ec0b59fd2b939f8121f7456d4382a84c8ec5539795fe3ecfa9c4f5cdb205ef`;
the agent is `d7341efb03f6e75d0726c1bc737d607911f4e0a5d3fe2e07997a3373b7dfcd03`.
R108 binaries and launcher are preserved at
`../outputs/install-backups/r112-before-install-20261017T042855Z/`.
Recovery and profile data were untouched.

Exact-package native Linux UI acceptance passed for Always available offline,
a verified 35-byte cached read while the synthetic cloud refused requests,
and Cloud only eviction of exactly 31 clean cached bytes. Offline file-body
GETs stayed zero; three blocked metadata probes were recorded. A same-length
34-byte local dirty edit was retained when Cloud only was refused: policy stayed
Recently used, the full journal row set and exact dirty bytes survived, and
read-only checks after shutdown confirmed the journal/blob persisted. The
synthetic remote snapshot stayed unchanged; four conditional PUT attempts were
blocked, with zero successful PUT, DELETE or MOVE.

The process-owned native tray Quit closed the shell and agent. The attached
shell's numeric exit code was unavailable. The helper then unnecessarily tried
a shutdown RPC after the agent socket was already gone, so its exit 1 and
FileNotFound error remain recorded; this is observed normal Quit acceptance,
not a clean helper pass. Earlier seed/selector failures occurred before policy
mutation; the corrected driver resumed the same runtime and shell. Host gates
passed (762 tests, 13 ignored). Evidence:
R112 native acceptance (maintainer-local evidence: `../../outputs/vm-lab/linux-offline-policy-commit-20261017-r112/native-acceptance.json`)
and installed hashes (maintainer-local evidence: `../../outputs/vm-lab/linux-offline-policy-commit-20261017-r112/laptop-install-r112.json`).

This run covers ordinary files with a warm verified cache. It does not establish
offline process restart/login, recursive folder pin acceptance, Windows policy
UI, Explorer integration, or production Windows provider activation. The R111
Windows duplicate-restart preflight failure remains under diagnosis; R114 adds
a test-only diagnostic and does not enable the provider. The R108 copy result
below remains valid for its exact earlier package; R113b adds nested copy
acceptance on R112 while moves remain open. Dated installed-version statements below are historical.

## Installed R108 copy acceptance — 17 October 2026 JST

R108 is installed on the Linux laptop, its installed files match the package
manifest, and the app is closed. The exact package SHA-256 is
`3222fb7f2b1768696eefcd43fb972f33d75b13529f77465cd67feee9916823f8`. The
pre-install R107 binaries and launcher are preserved at
`../outputs/install-backups/r108-before-install-20261017T033439Z/`; recovery
and profile data were left untouched.

The exact package passed native UI copy acceptance. Using the real UI, the test
copied a source file to a destination vault root and observed the completed
state. FUSE readback returned the 56-byte plaintext with SHA-256
`4581f78f22fc67fce34380246359f27cdc6b31ceea5bb8ed2606054d9457c393`. The
source ciphertext, resource ID, ETag, and plaintext stayed unchanged; the
synthetic server recorded one conditional PUT, five conditional GETs, no
DELETE/MOVE. The local destination journal was retired. Evidence:
`native-acceptance.json` (maintainer-local evidence: `../../outputs/vm-lab/linux-vault-copy-ui-plan-20261017-r108/native-acceptance.json`).

A shutdown-only follow-up launched the same package and exited through its
process-owned native tray Quit menu with UI and agent exit codes 0. No copy was repeated and the remote snapshot and
mutation counters stayed unchanged during shutdown. An earlier window-destroy
attempt failed with GdkBadDrawable and is retained as a failed harness attempt;
it is not counted as graceful shutdown acceptance.

This acceptance covers destination-vault-root copy only. Nested destination
folders and cross-vault moves remain unsupported or unaccepted. Windows Copy UI
is still hidden; Windows provider activation remains disabled, and the Windows
recovery/cache milestones below do not establish product UI parity. The package
includes the Linux source UI and the root-ETag/auth-generation status binding.

R109 adds a Windows native lifecycle result from the pre-existing synthetic
`raiunGuiR66a` console session (WTS session 1): the exact `native_normal_lifecycle_restores_and_reconnects_registered_namespace` test passed once (1 passed, 0 failed) and reported implicit OS-read hydration for Personal and Projects Space. The same suspended process was verified by PID, image hash, SID, session and command line, then resumed once and exited naturally with code 0. The initial wrapper attempt stopped because CIM returned a null executable path; that failure is preserved, so this is not a clean wrapper pass. Developer Mode was restored exactly. The synthetic root/profile remain; no registration enumeration or cleanup was performed, and a protected cache path was not inspectable from SYSTEM. This is native test evidence only, not Explorer acceptance, packaged GUI acceptance, RecoveryRoot hydration acceptance, or production provider enablement. Evidence: `native-acceptance.json` (maintainer-local evidence: `../../outputs/vm-lab/windows-wts-isolated-native-20261017-r109/evidence/native-acceptance.json`) and `status.md` (maintainer-local evidence: `../../outputs/vm-lab/windows-wts-isolated-native-20261017-r109/evidence/status.md`).

R110 verifies a Windows cache-policy source foundation in focused native tests.
The cache setter transactionally fences the exact ordinary-file ID, path, ETag,
and size against a complete, unambiguous local listing in the registered
account/root scope. The backend binds the operation to its exact registered file
identity and account/root, drains in-flight `PreparedFetch` leases with bounded
cancellation, and holds the publication/token-generation fence through the local
update. `CloudOnly` refuses pinned, retained, or journal-referenced dirty content.
The setter performs no HTTP request, remote deletion, or OS dehydration. Both new
setter APIs reject `AlwaysOffline` until a verified full-download workflow exists.
On Windows, nine cache tests and one focused range integration test passed under
a fresh standard user; each exited 0, and the profile unloaded. Host format,
strict Clippy and workspace tests (760 passed, 13 ignored), plus Windows workspace
check, strict Clippy and test-binary builds passed. This is a 109-file R103d-based
source candidate with four overlays, not a full current product package; RPC/UI
and installed-package acceptance remain open. R108 remains installed on Linux
and closed. See the R110 native acceptance record (maintainer-local evidence: `../../outputs/vm-lab/windows-cache-policy-fence-20261017-r110/evidence/native-acceptance.json`) and gate status (maintainer-local evidence: `../../outputs/vm-lab/windows-cache-policy-fence-20261017-r110/STATUS.txt`).

R111 hardens the existing `AlwaysOffline` commit: the same SQLite transaction
now requires the exact complete ordinary listing and a matching cached version
with the listed byte length. If eviction wins first, pin admission fails; if
admission wins first, later eviction preserves the offline copy. Required host
gates pass (762 tests, 13 ignored); all eleven focused cache tests also pass on
Windows under a fresh standard user. The separate new duplicate-edit restart
native test **failed** in its first prepare child before Cloud Files registration:
the composite Personal/Spaces preflight refused connection. No duplicate upload
or restart-success claim follows from this run. Its ordinary root and private
state remain preserved, Developer Mode was restored exactly, the WTS profile
remains loaded, and no scoped test process remains. SYSTEM could not inspect the
private journal directory. Diagnosis continues without weakening the scope
checks. See the R111 failed native record (maintainer-local evidence: `../../outputs/vm-lab/windows-dirty-duplicate-success-plan-20261017-r111/windows/evidence/continuation-run-1/diagnostics/acceptance-result.json`).

R112 packages the cache-commit hardening for Linux. Its exact isolated native
UI/cache acceptance is in progress; it is not installed. R108 remains the
hash-verified laptop installation and is closed.

The sections below are dated implementation checkpoints; where their status
conflicts with the installed-package result above, this current R108 status is
authoritative.

## Source follow-up R69 under validation — 17 October 2026 JST

A Windows control-server lifetime audit found that a readiness probe can connect
and close without a frame, while the server treated the resulting reply failure
as fatal. Source now isolates client disconnects from listener ownership errors
and honors an admitted shutdown even if its reply is lost. Required host gates
pass. R68b reproduced the failure with the immutable R59 Windows 0.1.2
package in a fresh standard-user profile: a zero-byte readiness connection
caused the exact agent process to exit with a bounded-response error before a
valid status request could complete. Windows setup is now stable; the frozen
R69 source passes Windows workspace check and strict Clippy. Its broader native
run exposed four recovery-transport fixture failures; the fixture did not reset
Windows accepted sockets to blocking mode, unlike the existing vault and engine
fixtures. The test-only R70 correction passes all seven focused tests on Linux;
full host gates and Windows revalidation are pending. Independent fixed-agent
lifetime checks continue. A replacement package and actual Windows GUI acceptance
remain pending. This is not delivered Windows acceptance
yet. Linux runtime source is unchanged and R59 remains installed and closed;
no new Linux package has been prepared. Reproduction evidence is retained at
`../outputs/vm-lab/windows-agent-pipe-probe-20261017-r68b/evidence/`.

## R61 actual refresh-to-native reconnect acceptance — 17 October 2026 JST

R61 extends test coverage only; R59 remains installed, hash-verified and closed.
The Windows native lifecycle test now restores a saved synthetic session,
performs an actual loopback refresh-token HTTP request, persists rotated access
and refresh tokens, and reconnects the exact registered Personal/Spaces root
through the ordinary refresh worker. The fixture refuses the old bearer after
rotation. Initial empty-root setup still uses explicit test-only admission;
this does not establish real identity-provider sign-in or interactive Explorer.

Host required gates passed (736 Rust tests, 13 ignored). Exact 108-file Windows
source hashes matched before/after; workspace check, strict Clippy and binaries
built successfully. Ordinary-user suites passed: 49 agent unit +3 native,
80 Cloud Files unit +8 native, 28 range, 59 cache and one control test. Test
account removed/profile unloaded/scoped processes and Cargo/Rust processes zero;
Developer Mode restored. No new product package was built or installed and
production activation remains disabled. Evidence:
`../outputs/vm-lab/windows-native-refresh-20261017-r61/`.

Windows GUI acceptance is currently limited by the guest's visible initial-setup
recovery screen, rather than SSH/QGA authentication. The isolated console works;
normal setup recovery is being investigated independently of Linux acceptance.

## Installed R59 recovery panel and Windows package — 17 October 2026 JST

R59 was installed at 02:16 JST, hashes verified and left closed. R56 is backed
up at `../outputs/install-backups/20261016T171650Z/`. Exact Linux archive:
`61fbabbc0d61f8616de1458f3b1b2d66dccf07f6417ce3e3467bb1a9d39edb9d`.

Windows Settings now has a read-only Saved file edits panel. Status, request and
response share an exact account/root/authentication-generation/agent scope token;
refresh clears old rows and late replies are discarded. The first page is
bounded to 50 rows with an explicit incomplete-list notice. No retry, upload,
delete or plaintext-open action is exposed. Production activation remains off.

Host format/strict Clippy/workspace gates passed (736 tests, 13 ignored), as did
66 UI tests and the frontend build. Windows strict check/Clippy and ordinary-user
49 agent unit +3 native, 80 Cloud Files unit +8 native, 28 range and 59 cache tests
passed. Developer Mode was restored; the synthetic account is absent and scoped
process count is zero. The exact Linux package passed native Settings platform
visibility, diagnostics allowlisting/private permissions/no overwrite, and
Escape/Close restoration to the exact opener. The older diagnostics filename
selector failed first; the proven editable-field harness passed without product
changes. The extra mounted/root check was after focus setup. All scoped services
closed, the synthetic root unmounted, and recovery data was retained. Evidence:
`../outputs/vm-lab/windows-recovery-panel-20261017-r59/`.

Unsigned Windows v0.1.2 built from the same frozen 188-file source manifest:
`c090e9816672acb9d14335a1b1df16bf13731290ced2eb43bfd20dc1fb943277`.
R60 passed standard-user 0.1.1 install, 0.1.2 upgrade and uninstall, preserving
account/cache/recovery/local-root sentinels and old installers. Autostart stayed
absent; test account removed/profile unloaded/install and Start Menu removed/
scoped processes zero. The app was not launched in this lifecycle test. Evidence:
`../outputs/vm-lab/windows-installer-acceptance-20261017-r60/`.

Interactive Windows panel/tray/Explorer, actual OAuth refresh admission, forced
OS disconnect failure, Linux speech/IME/desktop-login, and the broader feature
and interoperability backlog remain open. These are test builds, not a release.

## Installed R56 recovery cursor scope — 17 October 2026 JST

R56 was installed at 01:45 JST, hashes verified and left closed. R55 is preserved
at `../outputs/install-backups/20261016T164541Z/`. Exact Linux package SHA-256:
`9515e29bb0370389eff2f132e7a5bb199fd15066c9b035e77c2d59eca0706f68`. The isolated Linux VM verified this archive and all payloads;
executables still match the native-tested R49d/R50 Linux payloads.

Windows recovery pagination now rejects cursors from another account, server,
profile, local root, authentication generation or agent instance. The cursor
carries a versioned context digest including a fresh random instance nonce;
entropy failure reports an error. Old tuple-only cursors require refreshing the
list. Viewing remains read-only and production provider activation remains off.
Frontend eligibility/page validation helpers are included in source with seven
focused tests; the recovery panel is not wired in this installed package.

Required host gates passed (736 Rust tests, 13 ignored), all 60 UI tests passed,
and Windows strict check/Clippy passed. Ordinary-user tests passed: 49 agent unit
and 3 native tests, 80 Cloud Files unit and 8 native tests, 28 range and 59 cache
tests. Developer Mode was restored, synthetic account removed, and scoped
process count verified zero. Evidence:
`../outputs/vm-lab/windows-recovery-cursor-20261017-r56/`.

R54f separately passed exact unsigned Windows v0.1.0 install, v0.1.1 upgrade and
uninstall under a synthetic standard user. Payload and account/cache/recovery/
local-root sentinel hashes were verified; app files/Start Menu were removed,
login autostart stayed absent, recovery sentinels remain, and account/process
cleanup was verified. These installers came from frozen R51b source via R52/R54,
not R56. No application GUI was launched. Evidence:
`../outputs/vm-lab/windows-installer-acceptance-20261017-r54f/`.

Current follow-ups: latest-core Windows GUI packaging, read-only recovery panel
wiring/native acceptance, interactive Windows GUI/tray/Explorer, actual OAuth
refresh lifecycle admission, forced OS disconnect failure, and Linux speech/IME/
desktop-login acceptance. Broader feature/interop gates below remain open; no
release or production activation is established by these checks.

## Installed R55 logout generation fencing — 17 October 2026 JST

R55 was installed at 01:32 JST, hashes verified and left closed. R53e is backed
up at `../outputs/install-backups/20261016T163203Z/`. Exact Linux archive SHA-256:
`c69dce8b4ec23bc9d54072cf6cef1bc528961b1b3199c2a13481840d83908620`. Its executable payloads remain identical to R49d/R50; the isolated
Linux VM verified this exact archive and payload manifest.

Windows logout now invalidates the provider generation and blocks new lifecycle
admission before disconnecting. An incomplete logout retains credentials and
recovery ownership for explicit retry while suppressing automatic refresh in the
current process. It never reports successful logout when durable pointer revocation
fails. This process-local pending guard does not establish durable revocation if
protected storage refuses the change and the process restarts.

All required host gates passed (736 tests, 13 ignored). Windows workspace check
and strict Clippy passed, with 48 agent unit tests, 3 native agent tests, 80 Cloud
Files unit tests, 8 native tests, 28 range tests and 59 cache tests. The new idle
logout test verifies generation invalidation and stale command refusal; the
pointer-failure test verifies retained session/pointer and suppressed refresh.
Synthetic account removal, Developer Mode restoration and no scoped processes
were verified. Production provider activation remains disabled. Evidence:
`../outputs/vm-lab/windows-logout-generation-20261017-r55/`.

Windows GUI installers R52/R54 built successfully from frozen R51b source;
current installer lifecycle acceptance is still being diagnosed in isolated
synthetic profiles. Interactive Windows GUI/tray and Explorer, recovery GUI
wiring, actual OAuth refresh admission, forced native disconnect failure, and
Linux speech/IME/desktop-login acceptance remain open. These packages are
unsigned and unpublished; the broader backlog is not complete.

## Installed R53e Windows lifecycle integration — 17 October 2026 JST

R53e was installed at 01:25 JST and left closed; R51b is backed up at
`../outputs/install-backups/20261016T162554Z/`. Exact Linux package SHA-256:
`503a3fba3d9ef84731838915c3a04cb4f7aa38ee605967ff668cf94b6eed27c7`.
All executable payloads match the native-tested R49d/R50 Linux payloads; the exact
archive and payload manifests were verified in the isolated Linux VM.

Windows native acceptance now exercises the normal configure/reconnect lifecycle
through a per-instance test-only activation flag. It verifies registered-root
restore after restart, repeated-hook and repeated-configuration idempotence,
exact identity/ancestry overlap checks, stale binding refusal, revoked-backend
refusal, and no fixture PUT. Production activation remains disabled. This exposed
and fixed a retained account-state mutex across the lifecycle hook and plain-root
checks incorrectly rejecting an exactly registered Cloud Files root.

Required source gates passed (736 Rust tests, 13 ignored); Windows workspace check
and strict Clippy passed, plus 47 agent unit tests and 3 native agent tests,
80 Cloud Files unit tests and 8 native tests, 28 range tests and 59 cache tests.
Synthetic accounts were removed, Developer Mode restored, and scoped processes
closed. Evidence: `../outputs/vm-lab/windows-agent-lifecycle-20261017-r53e/`.
R53b deadlock, R53c native refusal and R53d test compile failure are retained.

Separately, R52 built the unsigned Windows GUI installer from frozen R51b source;
R54 built its 0.1.1 upgrade overlay. Installer acceptance remains in progress:
R54 child startup failed; R54a starts but its child exits with an error still
under investigation. These are not accepted Windows installers or current R53e
Windows packages. Interactive GUI/tray, Explorer, recovery GUI wiring, actual
OAuth refresh admission, and logout-versus-background-connect generation
invalidation remain gates. The lifecycle test explicitly admits a verified
synthetic session and does not force an actual OS disconnect failure.

## Installed R51b bounded recovery discovery — 17 October 2026 JST

R51b was installed at 00:49 JST and left closed. R49d is preserved at
`../outputs/install-backups/20261016T154926Z/`. Exact package SHA-256:
`8367dc4a061d9ebf3c2d0c8ec5cfd3e3fd60bb15ff3c15cf22d5e896cf95099c`.
Evidence: `../outputs/vm-lab/recovery-metadata-budget-20261017-r51b/`.

Windows discovery now authenticates at most 256 catalog scopes (including foreign
scopes), 2,000 selected edit records and 20,000 aggregate entries, with a 64 MiB
aggregate read allowance and 4 MiB serialized metadata allowance. Catalog reads
are conservatively charged at their maximum allowed size. Retries share the same
allowance; exceeding any bound returns an explicit error and no partial page.
Bodies are fully authenticated and hash-validated, then zeroized before the next
record; authenticated recovery events are still validated against retained
metadata. Output cloning can temporarily double the metadata allowance in memory.

Discovery opens existing journal directories only. Startup, unresolved checks and
retry resolution also refuse missing catalog-referenced journals without silently
recreating them. Only append may finish journal creation after catalog registration;
a scan racing that small creation interval can temporarily fail closed. Tests
cover exact/over-budget limits, retained bodies, malformed recovery events,
selected corruption, absent catalog/journals and isolation from foreign bodies.
The read-only guarantee concerns recovery catalog/journal contents and remote
files; constructing the authenticated context still prepares private session
directories and enforces their DACLs. Discovery never uploads, retires or repairs
an edit. A larger valid recovery set is an explicit scan-limit refusal, not data
corruption or permission to evict dirty data.

Host format/strict clippy and 736 Rust tests (13 ignored) passed. Windows strict
check/clippy, 47 agent unit + two native, 80 Cloud Files unit + eight native,
28 provider/range and 59 cache tests passed. Developer Mode was restored and the
synthetic account removed. Linux verified the exact archive and all payloads;
executables match native-tested R49d, so unchanged runtime evidence was reused.
Normal Windows activation, Explorer and recovery GUI wiring remain outstanding.

R50 independently verified actual GTK/WebKit focus return using that same shell:
keyboard Escape and the visible bottom Close action each closed the locked-vault
dialog and restored FOCUSED to its exact synthetic picker opener. There is no
Cancel-labelled control. No password was read from the UI or remembered. All
scoped services were closed and synthetic data retained. Failed harness attempts
are retained; this is not spoken screen-reader or IME acceptance. Evidence:
`../outputs/vm-lab/locked-location-focus-return-20261017-r50/`.

## Installed R49d recovery and diagnostics batch — 17 October 2026 JST

R49d was installed at 00:23 JST and left closed. R46 binaries and launcher are
preserved at `../outputs/install-backups/20261016T152335Z/`. Exact package SHA-256:
`57abaeb473c6987f4fba35a6969edf22c46edbb999a23b5630f272f48490326d`.
Evidence: `../outputs/vm-lab/windows-recovery-discovery-20261016-r49d/`.

The diagnostics command now unwraps the agent response before checking the
selected profile. Native GTK save-dialog export passed selected-profile field
allowlisting, connected/mounted status, private file permissions and refusal to
overwrite an existing synthetic file. The exact Linux package also passed mounted
write journaling, ancestor rename refusal, no cloud MOVE, and body-hash retention
after graceful shutdown. All scoped Linux services were closed.

Windows recovery metadata discovery uses the exact authenticated account,
registered root, generation and current-user protected journal. Its native test
verified read-only listing preserves the saved edit and performs no PUT. Testing
found and fixed registered Cloud Files roots being rejected by ordinary-directory
repinning; only the exact final registered root may have Cloud Files state,
ancestors remain ordinary directories, and OS registration is verified while
handles remain held. Wrong identity still returns the established changed-root
error. Windows normal-provider activation remains disabled and recovery GUI
wiring remains outstanding. Listing responses are bounded; aggregate journal
scan work is not yet bounded and remains an activation gate.

The UI skips unsupported Windows provider reads while preserving reachable
account status and existing recovery views. Filename warnings cover components
exceeding 255 UTF-16 units without renaming or rejecting cloud files. Host format,
strict clippy, 730 Rust tests (13 ignored), 53 UI tests and three focused Tauri
diagnostics tests passed. Windows strict check/clippy, 47 agent unit + two native,
74 Cloud Files unit + eight native, 28 provider/range and 59 cache tests passed.
The synthetic Windows account was removed and temporary Developer Mode restored.

Failed R48/R49/R49b/R49c attempts remain recorded. Native dialog harness fixes
used a unique focused editable filename field and native EditableText with
readback; this proves export behavior, not keyboard/IME or spoken output.
Prior feature acceptance below remains historical evidence, not a claim that all
those flows were rerun against R49d. Explorer, real desktop login, IME and spoken
screen-reader acceptance remain outstanding.

## R47 native busy-dialog acceptance — 16 October 2026 JST

The isolated Linux VM verified busy Escape preserves the dialog and exposes its
known explanation, cleared prior password-error state before the new attempt,
then exposed a new invalid-input notification and allowed idle Escape closure.
Tab and Shift-Tab stayed inside the dialog. R45 package executables were tested;
the installed R46 executable hashes are identical. No product rebuild was needed.
All scoped services were closed, synthetic recovery retained, and no real
credentials or remembered vault secrets were used. Evidence:
`../outputs/vm-lab/locked-location-busy-escape-20261016-r47/`.

Failed harness attempts are retained. Corrections included GTK interface method
dispatch, AT-SPI string entry instead of hardware-key codes, rearming delay just
before submission, current dialog references and a cleared-error baseline.
Earlier R44 input fallback does not prove exact entered bytes; its focus/containment
and error-state observations remain scoped evidence. R47 uses string entry.
This does not establish actual spoken screen-reader output or IME behavior.

## Installed R46 concurrent-startup acceptance — 16 October 2026 JST

R46 was installed at 23:33 JST and left closed; R45 is preserved at
`../outputs/install-backups/20261016T143332Z/`. Package SHA-256:
`3915a53df8aea877ebd087f1db5264aff013ee1f99d8b1ba93386b5c10a53b2a`.
Evidence: `../outputs/vm-lab/windows-concurrent-initialization-20261016-r46/`.

Two native threads independently pinned the same empty synthetic root before
racing initialization. Exactly one connected; the loser left its registration
and Personal/Spaces namespace intact. The winning registration then reconnected
successfully. All eight native Cloud Files tests, 74 unit tests and the remaining
ordinary-user agent/provider/cache suites passed. Host formatting, strict clippy,
728 Rust tests and supported Windows check/clippy passed. This is one observed
native race execution, not an exhaustive scheduling proof. Failure paths in the
test use bounded worker waits. Production provider activation remains disabled.

Linux exact archive/payload hashes were verified inside the VM. Executables match
R44/R45, so prior native UI evidence is reused without another runtime test.
Interactive Windows Explorer, screen-reader speech, IME and login gates remain.

## Installed R45 partial-initialization acceptance — 16 October 2026 JST

R45 was installed at 23:27 JST and left closed; R44 is preserved at
`../outputs/install-backups/20261016T142710Z/`. Package SHA-256:
`97954c951f991ee11dbd01330fc69c4e49f4a89085a7aa1d0473ea92aecc20a3`.
Evidence: `../outputs/vm-lab/windows-partial-initialization-20261016-r45/`.

A test-only, thread-local fault stops initialization after the first native
placeholder creation succeeds and before readiness. The ordinary-user Windows
VM test verified the exact registration and Personal child survive; reconnect
refuses the missing Spaces child and preserves both the namespace and
registration. All seven native Cloud Files tests, 74 unit tests, agent recovery,
provider/cache tests and Windows strict workspace checks passed. Host formatting,
strict clippy and 728 Rust tests passed. The fault is absent from production
builds; independent review found no required change.

The exact Linux archive and all payload hashes were verified inside the VM.
Executable and icon hashes are identical to R44, so its native UI evidence is
reused without repeating runtime tests. Concurrent startup and interactive
Windows acceptance remain open; production Windows activation remains disabled.

## Installed R44 locked-location accessibility — 16 October 2026 JST

R44 was installed at 23:18 JST and left closed. Exact package:
`94e3a9aac64bd008168351b5380fa11acf8dd7487f16fc1c669460a1e18c7968`.
Previous R43 binaries and launcher are preserved at
`../outputs/install-backups/20261016T141818Z/`. Evidence:
`../outputs/vm-lab/locked-location-ui-20261016-r44/`.

The unlock dialog explains why Escape cannot close a busy operation, associates
known password/integrity errors with the password input, and keeps transport
failures as general alerts. Saved-key unlock clears the field without reading
its value. All 51 UI tests and the Linux build passed. Rust sources and native
adapter sources match the verified R43 manifest; their R43 gates were reused.

The exact package passed isolated native WebKit/AT-SPI checks through a synthetic
locked-location deep link: initial password focus, 12 Tab transitions confined
to the dialog, error notification and invalid-input state, and idle Escape
closure. The probe needed API and role-mapping corrections; failed attempts
remain in the evidence. All scoped UI/agent/fixture/keyring/display services
were closed and synthetic recovery retained. This does not establish spoken
screen-reader announcements, IME behavior, focus return to a file-manager
opener, or Windows UI acceptance. No new Windows UI package was tested.

## Installed R43 initialization safeguards — 16 October 2026 JST

R43 was installed at 23:05 JST and left closed. Exact package:
`b3141234a3a5b8774387a609cbe59c37bb1d5a795c17e5351ede9733d02699ff`.
R41f rollback binaries and launcher are retained at
`../outputs/install-backups/20261016T140508Z/`. Evidence:
`../outputs/vm-lab/windows-initial-readiness-20261016-r43/`.

Windows fetch/enumeration admission now stays closed until initial namespace
verification finishes, without blocking close recovery or cancellation callbacks.
The close transition and fetch admission share a mutex. Exact child handles remain
pinned through readiness publication; reconnect checks the complete immediate
name set, opaque provider identities, volume and coherent Cloud Files state.
Unknown or missing entries fail closed without overwrite, deletion or registration
removal. A native reconnect test preserved an injected unknown root file and the
original registration. Initial and closing fetch refusal, terminal failure and
retained dirty blockers have focused unit coverage.

Formatting, strict workspace clippy and 728 Rust tests passed. Supported Windows
workspace check/clippy, 74 Cloud Files unit tests, all six native Cloud Files
tests, the native agent recovery test, 44 agent unit tests, 28 provider/cache
integration tests and 59 cache tests passed under an ordinary synthetic user.
Exact Linux package journal handoff, ancestor-rename refusal, retained recovery
and scoped-process cleanup passed. A staging-only port assertion caught a test
harness substitution before runtime start; the corrected fresh run is retained
separately as `r43b-data`.

Production Windows provider activation remains disabled. Forced partial-setup /
concurrent-startup fault injection and interactive Explorer/assistive-technology
acceptance remain gates. Earlier Linux native media, encrypted offline and
remembered-keyring evidence applies to the identical agent payload hash; it does
not establish interactive UI behavior for this package.

## Native optional remembered-vault unlock — 16 October 2026 JST

The exact packaged R41f Linux agent passed the real Secret Service/keyring flow
in a fresh isolated VM profile: ordinary unlock with remembering off did not save
a password; explicit opt-in saved only the selected synthetic vault; a distinct
vault could not use it. After an agent restart, inspection reported unknown
status until explicit saved unlock, which restored the mounted canary bytes.
Lock and forget then prevented saved unlock. No real vault, user password or
credential store was used. The private keyring, synthetic fixture and display
were closed, and synthetic data was retained. Evidence:
`../outputs/vm-lab/vault-keyring-native-20261016-r42/`.
This closes the packaged Linux credential-store/control gate, not interactive
unlock-dialog or Windows credential-store acceptance.

## Installed R41f and native recovery gates — 16 October 2026 JST

R41f was installed at 22:44 JST and left closed. The exact verified package is
`8ac5dc37e5d10b86189b7c4ce04adbd028990095b7655cbe7dbc020d337478b1`;
R37 binaries and launcher are retained at
`../outputs/install-backups/20261016T134451Z/`. Evidence:
`../outputs/vm-lab/windows-root-lifecycle-20261016-r41f/`.

Formatting, strict workspace clippy and 728 Rust tests passed (13 ignored on
Linux). The frozen source passed supported Windows workspace check/clippy,
73 Cloud Files unit tests, all six isolated native Cloud Files tests, the native
agent recovery test, 44 agent unit tests, 28 provider/cache integration tests and
59 cache tests under an ordinary synthetic user. Native tests cover actual
child-directory population/hydration, DPAPI journal capture across processes,
dirty-byte retention and destructive-operation refusal. Exact-package Linux
journal handoff, ancestor-rename guard, post-shutdown recovery retention and
scoped-process cleanup also passed. Temporary Windows Developer Mode was
restored and synthetic test accounts were removed; recovery was retained.

Windows verified read-through caching is wired into the trusted backend, bounded
to complete versions/listings and exact account/Space/root identities. Offline
classification never overrides authentication or stale-version denial. Windows
production provider activation remains disabled. Registered/disconnected roots
may have either plain or cloud form, but require exact OS registration and held /
path identity verification. Eager immediate-root population now uses the documented
root-only population flag; child directories remain lazy. Initial callback exposure
before namespace setup finishes remains a production-enablement gate, along with
interactive Explorer, real IME/WebView and login acceptance.

## Synthetic media recovery acceptance — 16 October 2026 JST

The exact R41c Linux package passed fresh synthetic sign-in/private-keyring,
verified media upload/readback, unchanged-file deduplication, commit-then-lost-response
recovery, removal refusal and restart retention. Source byte/size/mtime manifests
were unchanged; the fixture recorded two PUTs total and zero DELETE/MOVE calls.
The ambiguous item's staged copy survived restart without another PUT. All owned
processes and the control socket closed, with recovery preserved. Evidence:
`../outputs/vm-lab/media-native-20261016-r40/`. This used packaged agent SHA-256
`c0a21b1f675994cc599b380eed2d7a6b562723a934d44f34f506fd327d2a7a3b`,
which is also the current R41f Linux agent payload. It does not establish
interactive media UI or broader media organization choices.

## R37 encrypted offline native acceptance — 16 October 2026 JST

The exact installed R37 agent passed a fresh isolated Linux VM sequence:
synthetic vault creation, mounted file write/read, a complete encrypted pin,
loopback server outage, graceful restart, explicit password unlock of the saved
pin, offline listing and an exact mounted-byte comparison. No remembered secret
was enabled. The running executable hash matched the installed package; the
agent was gracefully closed afterward. Evidence:
`../outputs/vm-lab/encrypted-offline-20261016-r38c/result.json`.

An earlier harness attempt retained generation 1 while automatic online refresh
advanced the pin to generation 2; offline unlock refused the stale generation.
The harness must reconfirm the current Ready generation after a long wait, as
required by the unlock protocol. This result covers control and real FUSE
filesystem behavior;
interactive server UI, Windows Explorer and actual login/IME gates remain open.

## Installed R37 Windows cache library — 16 October 2026 JST

R37 was installed at 21:09 JST and left closed after exact-package Linux VM
verification. R36 binaries and launcher are preserved at
`../outputs/install-backups/20261016T120915Z/`. The archive SHA-256 is
`df8e6cc1a4934055912412f35f6455ad1d7fd0424fcc5a8684591bd88711fb61`.

Windows `Cache::open` now uses the pinned rollback SQLite owner and mandatory
handle-bound content storage. It refuses legacy WAL/SHM sidecars without
modifying them, preserves unknown recovery objects, and cannot select the
portable database owner on Windows. This enables the cache library only;
Windows agent cache integration and the production provider remain unfinished.

Formatting, strict workspace clippy and 720 Rust tests passed (13 native tests
ignored on Linux). Supported Windows workspace check/clippy and all 59 cache
tests passed under an ordinary synthetic user, including public-constructor
reopen, unsafe root, hard-linked database and legacy sidecar refusal. Earlier
attempts caught obsolete test field references and an overly specific error
assertion; final tests verify refusal and unchanged database bytes. The exact
Linux package passed running-agent hash, journal handoff/ancestor rename guard,
post-shutdown recovery retention and scoped-process cleanup checks.

Evidence: `../outputs/vm-lab/windows-cache-constructor-20261016-r37d/`.
Encrypted pinned outage/restart acceptance continues separately; interactive
Windows Explorer, real IME/login and broader upload-retry gates remain open.

## Installed R36 cache reference protection — 16 October 2026 JST

R36 was installed at 20:42 JST after exact-package Linux VM checks and supported
Windows source/native checks. Installed hashes match the verified archive; the
app is closed. R27 payloads and launcher are preserved at
`../outputs/install-backups/20261016T114228Z/`.

Cloud-only changes now independently protect pending write and encrypted pin
references even when content is marked Recent. Windows test-only cache coverage
now includes publication, eviction, journals, encrypted batch moves and locks,
policy changes, scope invalidation, cancellation cleanup, folder-pin readback,
and recovery-preserving startup inventory. Unknown blobs/stages remain protected
and count toward physical capacity; eviction accounts for them before selecting
eligible Recent content. Windows production cache/provider remain disabled.

Final source gates passed: 720 Rust tests, formatting and strict clippy; 13 native
tests were ignored on the host. The Windows VM passed workspace check/clippy and
56 cache tests as an ordinary synthetic user. A test-helper borrow error in R35
was corrected and covered by R36. Linux release/frontend builds passed. The exact
package's running agent hash, durable journal handoff/ancestor rename guard,
post-shutdown recovery bytes and scoped-service cleanup passed in the isolated
Linux VM. The initial readiness probe ran as root and could not inspect the
user-only FUSE mount; the subsequent ordinary-user control and filesystem test
passed. Full native suites and interactive acceptance were not rerun here.
Exact-package encrypted pinned outage/restart, interactive Windows Explorer,
real IME/login and broader upload-retry acceptance remain open.

Evidence: `../outputs/vm-lab/windows-cache-inventory-20261016-r36/`.
Package SHA-256: `c695ab23798f18a50b86615b2ec361cf6c38207d555f3f5881ac6d93f8e18af2`.

## Installed R27 root-delete guards and composing Escape fix — 16 October 2026 JST

R27 was installed at 19:48:36 JST and left closed; installed payload and manifest
hashes match the exact VM-tested package. R22 binaries and launcher are preserved
in `outputs/install-backups/20261016T104835Z/`. R23 ordinary-delete recovery
coverage, R24/R25 Engine/backend root-delete guards and R26 composing-Escape
handling are now included in the installed build.

Frozen source gates passed: 719 Rust tests, 13 native tests ignored on host,
formatting and strict Clippy; 46 frontend tests and frontend/package builds passed.
The Windows VM passed supported workspace check and strict Clippy with all 179
source hashes unchanged. Its existing R22 compilation cache was reused; the R22
source and evidence were preserved. Windows production caching remains disabled.

The isolated Linux VM verified the archive and all payload hashes, ordinary-user
CLI startup, and the running agent hash. The exact package passed durable-journal
handoff/ancestor-rename protection with no MOVE, retained blob hashes after
shutdown, and cleanup with no scoped services left. A fresh synthetic profile was
used; real accounts and cloud data were untouched. Full native test suites were
not rerun in this pass; real IME/WebView, tray/login/TLS and recovery-upload-retry
acceptance remain gaps. Runtime launch commands retained QGA capture pipes until
cleanup; their final exits were zero. One premature inspection could not yet read
those exit files; it did not affect the product checks.

Evidence: `outputs/vm-lab/root-delete-ime-20261016-r27/`, including
`status.json`, `laptop-install.json`, `evidence-linux/`, and `evidence-windows/`.
Package SHA-256: `4f75d2ce9cb524d56e5e994202bb7a543a359eb2c2a830edf8a07a848bad85d9`.

## Previously installed R22 journal-aware rename and consent fix — 16 October 2026 JST

Engine rename inspects non-verified writes in the exact authenticated cache
scope under its execution and metadata locks before cache invalidation or remote
MOVE. Overlapping source/destination subtrees with pending or conflicted edits
return a conflict; verified rows and sibling prefixes do not block. This closes
the R20 gap after FUSE transfers recovery ownership to the durable cache journal.
R22 also includes the R21 remembered-key consent correction and R20 subtree guards.

Source gates pass (716 tests, formatting, strict Clippy); build and 179 post-build
source hashes pass. Windows workspace check/Clippy evidence was verified;
frontend 46 tests/build passed on the host. Earlier Linux focused journal and
native 8 FUSE/5 agent checks passed as the ordinary synthetic user. The final
exact-package runtime passed after restoring the Linux VM: provider spool empty,
pending journal retained, ancestor rename rejected with no MOVE, and actual
41-byte blob/path/hash unchanged before/after and after graceful cleanup.

A delegated staging command accidentally changed ownership across the isolated
Linux guest. Its affected system disk, both test disks and firmware state were
preserved; the working OS was restored from the verified 9 October disk. The
post-restore runtime and root ownership checks passed. This incident and failed
harness attempts remain recorded in `outputs/vm-lab/journal-rename-consent-20261016-r22/evidence-linux/result.md`.

Installed at 19:24:31 JST; all installed payload/manifest hashes match the VM-tested
package, and the app was left closed. R19 is backed up at
`outputs/install-backups/20261016T070530Z/`. Evidence and installation record:
`outputs/vm-lab/journal-rename-consent-20261016-r22/`. Later R23–R26 changes were excluded from R22 and are now installed in R27. Native tray/login/TLS and real IME
acceptance gaps remain.


## Ordinary delete recovery audit — follow-up coverage

Review and a new ordinary-delete regression on 16 October confirm that deletion
preserves pending/conflicted journal bytes after cache reopen. A subsequent
listing keeps the recovery copy visible locally; repeated reconciliation reports
conflict with zero uploads and the remote item remains absent. Both pending and
already-conflicted states pass. This is source-level synthetic coverage, not a
native VM acceptance result. No production behavior changed and no new package
was built. Required source gates pass: 717 tests, 13 native tests ignored,
formatting and strict all-target Clippy. Raw logs and exits are retained in
`outputs/vm-lab/ordinary-delete-recovery-20261016-r23/`.

## Root-delete boundary hardening — included in R27

The ordinary Engine delete entry point now rejects empty and slash-only root
aliases before acquiring mutation locks, invalidating cache state or invoking
its backend. The focused regression checks `/`, `//`, `///` and empty input,
unchanged root/child content, zero backend discovery/list/delete calls and a
successful ordinary conditional child deletion. The mounted namespace already
rejects synthetic-root deletion; this adds protection for direct Engine callers.
The lower-level OpenCloud backend now applies the same guard before discovery
or DAV requests. Its direct-call regression verifies that no TCP connection is
made for root aliases. Combined source gates pass: 719 tests, 13 native tests
ignored, formatting and strict all-target Clippy. Evidence is retained in
`outputs/vm-lab/backend-root-delete-20261016-r25/`. Earlier Engine-only evidence
is retained in `outputs/vm-lab/root-delete-guard-20261016-r24/`. Root listing and
permission discovery remain available. These changes passed subsequent R27 package acceptance and are installed.


## Vault input-method Escape correction — included in R27

The vault dialog no longer dismisses on Escape while a keyboard input method is
composing text. Ordinary Escape still closes it under the existing busy-state
rules. All 46 frontend tests and the TypeScript/Vite build pass; an extracted
production-handler simulation confirms both Escape cases. Actual IME/WebView
behavior remains a native acceptance gap. Evidence is retained in
`outputs/vm-lab/vault-ime-escape-20261016-r26/`. This change is included in installed R27; the historical R22 package remains unchanged.

## R21 remembered-key consent correction — included in installed R22

The dialog now clears `rememberOnDevice` after confirmed, current-scope
`vault_forget` success. Previously the old checked state survived forget and
lock, allowing a later password unlock to resend `remember: true` without a
fresh opt-in. Failed or stale forget responses do not clear a different flow.
Behavioral tests exercise the production handlers for forget/lock/unlock,
explicit re-opt-in, failure and stale completion. Frontend tests (46) and the
TypeScript/Vite build pass; strengthened success-path assertions also pass
(3 focused tests), confirming successful unlock as well as outbound consent. This source change was excluded from R20 and is installed as part of R22. Evidence:
`outputs/vm-lab/vault-forget-consent-20261016-r21/`.


## R20 ordinary subtree rename safety — superseded before installation

Ordinary rename now publishes source/destination subtree reservations before
waiting for existing writers to release, excluding new descendants and ancestor
renames during that wait. Sibling prefixes and other Spaces remain independent.
Timeout retires only the rename's own markers. After writers retire, a bounded
read-only recovery scan rejects overlapping or unidentifiable saved edits,
unrecognized files, temporary manifests and incomplete scans. The separately
managed real vault-spool directory is explicitly excluded; its symlink/file
substitutes remain unknown. No recovery bytes are renamed or discarded.

Independent review found no blocker after correcting the unknown-entry scan gap.
Final source gates passed: 715 tests, 13 native tests ignored on host, formatting
and strict workspace Clippy. The package built and all 178 frozen source hashes
remained unchanged. Linux VM source/native checks passed as the isolated ordinary user. The exact
package blocked an active-writer ancestor rename, but allowed a rename after an
edit transferred to the SQLite journal. Its bytes survived in a conflict row;
the provider-spool-only check missed that recovery owner. R20 was not installed;
R19 remained installed until the verified R22 replacement. Evidence is in
`outputs/vm-lab/ordinary-subtree-rename-20261016-r20/`. Package SHA-256:
`ea1a9cb4843ed7e2022c39df116731dd5a0d8576d421873181da6b66d80fbd2f`.


## Windows ordinary journal integration — test-only R30 verified

Conditional writes and replacements now retain exact Windows blob handles and
the publication lease through the database commit. Failed writes preserve partial
stages and existing pending edits. Replacements retain the original condition and
journal ID; superseded bodies remain indexed as Recovery and count toward quota.
No Windows pathname orphan cleanup runs. All 35 native cache tests passed as an
ordinary synthetic user; supported Windows workspace check and strict Clippy,
plus host 719 tests (13 native ignored), formatting and strict Clippy passed.
Evidence: outputs/vm-lab/windows-cache-journal-20261016-r30/. Public Windows cache
initialization remains disabled; R27 remains installed and closed.

## Windows eviction integration — test-only R29 verified

Eviction now holds the Windows publication lease and obtains an exact-identity
delete handle before retiring metadata. Live readers cause a skip with accounting
and bytes intact; pending journals, pins and Dirty/Recovery retention remain
protected. Native Windows workspace check/Clippy passed and all 32 cache tests
passed as an ordinary synthetic user. Host formatting/Clippy and 719 tests passed
(13 native ignored). Evidence: outputs/vm-lab/windows-cache-eviction-20261016-r29/.
Other unported cleanup paths and public Windows cache initialization remain closed.
R27 is still the installed build; this is an internal test-only integration.

## Windows central publish/open integration — test-only R28 verified

The central cache publication and read paths now have an internal Windows fixture
backed by retained private directories and the pinned rollback SQLite owner.
One handle-pinned lease spans publication through metadata commit; the immutable
receipt survives the commit and failures preserve blob bytes. Readers retain their
validated handle. Unported deletion and orphan paths reject the fixture rather
than falling into the portable pathname lock domain. Public Windows Cache::open
remains disabled.

Windows workspace check and strict Clippy passed. All 28 native cache tests passed
under a fresh ordinary synthetic account, including the six central integration
checks and foreign-lease rejection. A prior SYSTEM run passed 26 and rejected two
legacy stock-SQLite sidecar ownership checks; those passed under the ordinary user
without relaxing ACL/owner validation. Host gates passed 719 tests (13 native
ignored), formatting and strict Clippy. Evidence: outputs/vm-lab/windows-cache-central-20261016-r28/.
R27 remains installed and closed; this storage seam is test-only and not delivered
as enabled Windows caching.

Next: integrate identity-bound eviction and orphan recovery, batch retarget and
journal writes, generation locks, and production database/storage initialization.
The publication/read slice alone does not justify production enablement.

### 16 October — Windows encrypted cache batch integration (R31)

The test-only central cache adapter now retains a validated root handle for exact
account/vault generation locks. Encrypted subtree retarget publication keeps every
published blob handle and the publication lease through the database commit and
acknowledgement. Failed or uncertain commits preserve recovery bytes.

The frozen R31 source passed Windows workspace check and strict clippy, and all
39 native cache tests passed as an ordinary synthetic VM user. New coverage checks
lock contention and identity across reopen, ciphertext pin readback, atomic
root-and-file retarget, and lost acknowledgement preserving old and new bodies.
Linux source gates passed (719 tests; 13 native tests ignored). Evidence is in
`../outputs/vm-lab/windows-cache-encrypted-batch-20261016-r31/`.
Windows production cache remains disabled; R27 remains installed and closed.

### 16 October — Cloud-only cleanup and reference protection (R32)

Cloud-only transitions in the test-only Windows adapter now acquire exact file
deletion handles before committing metadata changes. A live reader rolls back
the entire transition, including all versions of the resource. Pending ordinary
writes, encrypted writes and encrypted pin references now independently prevent
cloud-only eviction on every platform, regardless of a Recent retention label.

All 42 ordinary-user Windows cache tests passed, along with supported workspace
check and strict clippy. Linux source gates passed with 720 tests and 13 native
checks ignored. The added Linux regression proves a pending write survives a
cloud-only request even if its content is labelled Recent. Evidence is in
`../outputs/vm-lab/windows-cache-cloud-only-20261016-r32/`. R27 remains installed
and closed; this increment has not been packaged for laptop installation.

### 16 October — Windows encrypted invalidation and cancellation cleanup (R33–R34)

Encrypted scope invalidation now prepares all exact deletion handles before
committing the new epoch. Busy readers roll back epoch, pin state and index
changes. Dirty/recovery and pinned bodies survive, and unrelated account/root
scopes remain unchanged. R33 passed 44 ordinary-user native cache tests.

Cancellation cleanup now uses the same publication lease and identity-bound
handles for indexed bodies and deterministic orphan retries after metadata
removal. Pending references and Dirty/Recovery retention prevent removal; an
open reader preserves the row until retry. R34 passed 48 ordinary-user native
cache tests. Both snapshots passed supported Windows workspace check/clippy and
Linux source gates (720 passed; 13 native ignored). Evidence is in the R33
`windows-cache-invalidation-20261016-r33` and R34
`windows-cache-cancellation-20261016-r34` directories beneath `../outputs/vm-lab/`.
These adapters remain test-only. R27 is still installed and closed.

## Windows duplicate restart evidence — R118

The single R118 native duplicate-edit restart run failed: the ordinary OS write
produced one authenticated dirty snapshot, while the duplicate-success test
required at least two. Phase two reopened the same dirty record and reached
the post-dispatch snapshot-count assertion; conditional upload/readback totals
were not collected, so duplicate dispatch is not accepted. The wrapper also
failed on a post-run journal-path assumption. No retry, cleanup, unregister or
logout was performed. The synthetic profile remains loaded, no pinned test
process remains, and Developer Mode was unchanged. R121 corrects the test
fixture by explicitly making a second ordinary same-content write; it does not
weaken the duplicate checks or establish production acceptance.

See preserved native result (maintainer-local evidence: `../../outputs/vm-lab/windows-dirty-duplicate-restart-20261017-r118/windows/R118-native-result-summary.txt`)
and source diagnosis (maintainer-local evidence: `../../outputs/vm-lab/windows-dirty-duplicate-restart-20261017-r118/windows/R118-duplicate-failure-diagnosis.md`).

## Windows duplicate dirty-edit restart accepted — R121

The corrected test fixture explicitly creates a second ordinary OS same-content
write-close before disconnect. Its frozen 110-file Windows build passed check,
strict Clippy and all five test-binary builds. One exact native run then exited
0 (one test passed) and authenticated the same four 36-byte dirty snapshots
before and after two sequential fresh phase processes. Prepare dispatched
nothing; recovery verified duplicate reconciliation with exactly one conditional
PUT and no DELETE/MOVE. Local bytes, the exact synthetic Cloud Files root and
private journal scope remained retained. The existing synthetic WTS profile stayed
loaded, all scoped test/wrapper processes exited naturally, and Developer Mode
was unchanged. Individual child PIDs were not captured; the phase sequence is
proven by the test source, raw phase traces and acceptance marker. This closes
the duplicate-restart gate, not Explorer, packaged GUI, policy UI or production
provider activation. Earlier R118 failure evidence remains intact.

See parent native acceptance (maintainer-local evidence: `../../outputs/vm-lab/windows-dirty-duplicate-restart-20261017-r121/parent-native-acceptance.json`).

R122 source adds a worker-owned read-only cache-status RPC fenced by current
account generation, exact registered-root identity, active binding and scope
token. It exposes non-atomic last-observed metadata only. Linux host gates pass;
Windows compilation and four focused Windows-only tests are pending the R124
source snapshot. It adds no pin/download job, policy mutation or Windows UI.

## Current source follow-ups — R123 and R125

R123 adds exact saved-edit local export when ordinary directory metadata is
unavailable. Pending/conflicted plaintext Dirty bytes must pass scope, length and
hash checks; the page's auth generation and opaque account fingerprint survive
the native Save dialog and must still match before export. A stale generation
or changed account in the same profile is refused before opening the cache.
The journal remains unresolved and no cloud request or namespace restoration
occurs. Host gates pass (779 tests, 13 ignored), six cache security tests and
22 Tauri tests pass; the exact Linux R123 archive passed isolated native validation and was installed.
It has since been replaced by the verified R130 package, with the laptop closed.

R125 source adds catalog-bound Recent/CloudOnly local retention changes under an
exclusive backend lease, with one exact six-field listed-file binding retained
through the cache commit. It preserves dirty writes and catalog identities and
does not dehydrate OS placeholders or delete cloud files. AlwaysOffline remains
refused until a verified download workflow exists. Eight focused binding tests
and host gates pass (782 tests, 13 ignored). Native Windows validation, policy
RPC/UI and full availability workflow remain open; production activation is false.

## 17 October continuation — exact Linux R130 accepted

R130 combines the R127 final cache-listing publication fence and R129 local-copy
completion waiting. Its exact package passed the isolated installer and native
48 MiB pending-edit export, normal owned-tray Quit, and independent post-Quit
process/socket/mount closure checks. Dirty bytes and journal remained intact;
the fixture recorded no successful PUT, DELETE or MOVE. The copy completed in
0.604 seconds, so this is not a greater-than-ten-second timing stress result.
The original UI helper lost its wait handle after a preserved pre-Save selector
failure; shell numeric exit is unavailable, with closure independently verified.
The exact package is installed on the laptop, R123 binaries and launcher are
backed up, and the app remains closed. Canonical evidence is
`../outputs/vm-lab/linux-cache-publication-fence-20261017-r130/native-acceptance.json`.

Windows R128 passed all fifteen native cache-listing/publication tests with
numeric child and wrapper exits. R132 compiled and passed one exact connected-worker native test, with two
positive cache-status dispatches and twelve stale-row refusals after implicit OS
file hydration. The wrapper exited 1 from an incorrect registration-identity
expectation; a separate read-only query verified the retained normal configured
root, profile and closed processes. The original failure remains recorded. This
does not verify the outer control pipe or packaged GUI. R133 configured Recent
cache quota enforcement passed host gates and independent review. R134 passed
all nine focused native quota tests; its summary wrapper failed afterward and
independent process/profile postflight passed. R136 passed all six native
reservation-format/inventory tests with numeric child and wrapper exits.
R137 adds atomic schema-v6 policy intent counters and passed host gates
(804 tests, 13 ignored). R138 Windows check, clippy, build and test listing
passed; its first native wrapper failed before launching tests because its
manifest nesting differed from the script expectation. That failure is preserved.
The corrected R138c runner passed all ten policy-intent native cases.
R139 is an unintegrated two-phase plaintext download prototype, initially capped
at 16 MiB. It is not an active AlwaysOffline worker or a completed availability
feature; large files, guarded adapter publication and packaged acceptance remain open. Windows
AlwaysOffline download/policy UI and final package/native acceptance remain open;
production provider activation remains false.


R142 subsequently passed eight native two-phase download-stage tests and four
reservation-inventory tests, with all child and wrapper exits zero. R143b passed
five cached-promotion tests (including Dirty and Recovery retention) and eight
stage tests, also with numeric zero exits. Earlier pre-test runner failures are
preserved separately; they are not successful native tests.

R144/R145 adds a guarded ordinary-file offline operation, bounded to 16 MiB,
with 1 MiB conditional requests, explicit identity-bound unfinished-stage abort,
and final root/auth-generation plus durable policy-intent fences. It has no
IPC/UI or implicit callback route; Windows provider activation remains false.
R148 passed Windows check, strict Clippy, both test builds and exact test lists.
R148b then passed all seventeen new abort, live-admission and HTTP integration
tests (6 + 7 + 4), with numeric child and wrapper exits zero. Parent verification
checked exact names, summaries, suspended identity gates and process/profile
postflight. Evidence is `../outputs/vm-lab/windows-offline-job-20261017-r148/parent-native-acceptance.json`. Crash-time reservation reconciliation, larger
files, folder workflows and OS residency controls remain acceptance gaps. The
laptop has no new installation beyond the previously verified, closed R130.

The R145 Windows check found a sibling-module visibility error before any tests
ran. R147 contains only that visibility repair over the frozen R145 source; Clippy
then rejected an unused test helper. R148 removes that helper. Its first native
wrapper refused to launch because a missing-test count was compared with 17
instead of zero; R148b repairs that predicate without rebuilding. All original
compiler, lint and prelaunch failures are retained. No product package or laptop
installation was produced for this component validation.


R149 source now adds explicit Windows offline-file start/status/cancel control
requests. The provider worker checks the active binding before dispatching a
single bounded background job; downloads do not block the connection owner.
Status and cancellation require the current account/root scope and random job
identity. Generation invalidation and admission share a slot lock. Cancellation
keeps that slot occupied until the operation exits, and retained reservations or
panics report recovery required. Five manager tests are added; independent
review found no blocking scope or lock-order issue. Required host format, Clippy
and workspace tests pass. R149 Windows check, strict Clippy and agent build passed, followed by all
seven targeted native tests (five job-manager and two cache-status cases), with
zero child and wrapper exits. R150 then passed the extended native lifecycle fixture: two exact cached
versions completed explicit offline jobs through the real connected worker and
public request dispatch, with stale-row and mismatched job/scope/generation
requests refused. Both Personal and Projects used implicit OS hydration. The
exact test and wrapper exited zero; the standard WTS identity was verified before
resume, and the synthetic normal RaiunCF1 root/profile were retained with test
processes closed. Evidence is `../outputs/vm-lab/windows-offline-job-20261017-r150/parent-native-acceptance.json`.
The initial read-only artifact-path preflight failure is preserved; it launched
no test. This does not verify the outer control pipe or packaged GUI. Shutdown cancels and revokes work but
does not drain the detached job thread. Provider activation remains disabled;
there is no new package or laptop installation.


R151 adds cancellation-aware immutable readback in 64 KiB slices, including EOF
checks. Cancellation preserves existing indexed bytes and intent state; errors
while finishing a new private download report retained bytes. Final commit
admission is the documented cooperative cancellation boundary: a later cancel
may lose to the short durable transaction, while account/root/auth/intent fences
remain held. Required host gates and Windows check/strict Clippy/two test builds
pass. The native batch subsequently passed all five cache-verification, eight binding,
and four HTTP cases with exact test names and numeric zero child/wrapper exits.
Parent acceptance is `../outputs/vm-lab/windows-offline-job-20261017-r151/parent-native-acceptance.json`;
all processes closed and the synthetic profile remained loaded. The temporary 16 MiB cap and
all package/GUI acceptance gaps remain. No unknown-stage cleanup is introduced.


R154/R155 lift the explicit private-download staging limit to the existing
1 TiB object limit, still subject to configured quota and physical reservations.
Offline jobs have a one-hour total budget; individual network requests retain a
30-second bound. Cached reads verify the whole immutable object with cancellation
checks in 64 KiB slices, then return at most 16 MiB per range. This enables bounded
private-cache reads from larger objects; the native CFAPI request limit is still
16 MiB and large-file OS acceptance remains open. Existing native cached hashing
retains its backend read lease; revocation sets the flag before draining readers.

Required host checks and R155 Windows check/strict Clippy/cache test build pass.
R154b native verification passed four cancellation/content-reader cases, then a
test fixture incorrectly inserted metadata above the hard object limit into a
valid listing. Its failure and zero-process postflight are preserved. R155 changes
only that fixture: oversized metadata is tested directly and rejected before
allocation or intent. R155 subsequently passed all ten native cases (4 + 1 + 1 + 4), with
zero numeric child/wrapper exits, identities verified while suspended, no
remaining test processes, and the profile retained. Parent raw acceptance is
`../outputs/vm-lab/windows-large-download-20261017-r155/parent-native-acceptance.json`.
The accepted R154 CloudFiles executable was reused with explicit provenance. Evidence is under
`../outputs/vm-lab/windows-large-download-20261017-r155/`. No new package or laptop
installation occurred, and provider activation remains disabled.


R156 source now splits large native fetch requests into staging windows of at
most 16 MiB and publication slices of at most 64 KiB. A session holds one exact
file binding and root lease across all windows. Each window is validated before
publication, with the existing authorization and request permits held through
accepted transfers; failure stops at the unsent offset. Unsupported session
backends refuse large requests. Total requests remain bounded to 1 TiB and the
existing callback deadline; close-edit recovery still has its separate 16 MiB
whole-buffer limit. Three portable session tests and required host gates pass;
R156b Windows check, strict Clippy and test-binary build pass. R156c
subsequently passed eleven exact native cases (three sessions, four streaming,
four range checks), with numeric zero child/wrapper exits and suspended identity
verification. Raw parent acceptance is under
`../outputs/vm-lab/windows-native-windowing-20261017-r156c-native/native-runner-r156c/parent-native-acceptance.json`.
The tests call the same streaming helper as the callback, but do not establish
real CfExecute or packaged-file-manager acceptance. R157 prepares a 17 MiB + 7
byte extension of the existing isolated localhost/native hydration fixture; its
Windows build and real OS run remain pending.


R158 passed the real isolated Windows Cloud Files hydration fixture with a
17 MiB + 7 byte file. The OS requested the full 17,825,799-byte range; the backend
served bounded 16 MiB and 1,048,583-byte windows. Full byte equality, explicit
shutdown, numeric zero test/wrapper exits, suspended WTS identity and empty
post-test synthetic-root observations were independently checked. Parent evidence:
`../outputs/vm-lab/windows-large-os-fixture-20261017-r158-native/native-runner-r158/parent-native-acceptance.json`.
The earlier R157 fixture failure/root remains preserved. Its readback helper had
a separate 16 MiB ceiling; R158 bounds synthetic whole-file comparisons to 32 MiB
and isolates the large test size so DPAPI edit fixtures retain their 16 MiB
baseline. Required host and Windows source gates pass. This establishes native
large-file read behavior, not packaged GUI acceptance or large-file edit recovery.
No new package was installed; Linux R130 remains closed.


R159 source adds bounded read-only discovery of already-listed ordinary Windows
files, using the current backend catalog and the same account/session/root and
generation fences as offline jobs. Pages contain at most eight candidates and
128 KiB of JSON, exact unmodified file-version tuples, and scope echoes. Invalid
or unavailable rows are excluded without policy or cloud changes. UI controls
now use these rows for per-file status/start/poll/cancel, fence stale replies,
and retain the admitted job identity while loading or running. Page memory is
bounded, and selection cannot be replaced while admission is uncertain.
The panel requires an identity-bound registered root and an actually mounted
provider; it does not enable the currently disabled Windows provider. Required
host Rust gates, frontend build and sixteen focused controller/recovery tests
pass. Windows source/native verification is pending, as are packaged GUI and
outer-control-pipe acceptance. Folder pin/restart reconciliation remains open.

R160 bounds discovery work with a five-second token created when the request is
admitted, cancellation on caller return, and cancellation checks during both
catalog scans. Independent review accepted these read-only cancellation fences.
The required host Rust gates pass. Windows workspace checking, strict Clippy,
and both test-target builds pass; the agent target required correcting the
build harness from a library to its binary target. Exact artifact inventory and
native acceptance remain pending. No new package has been installed.

R160 Windows verification now passes all ten exact native cases: eight listing
helpers/backend cases, one worker refusal case, and the normal connected-worker
lifecycle. Parent checked raw test names, zero child/wrapper exits, suspended
WTS identity/image hashes, scoped rows and stale-scope refusals without network
requests. The normal RaiunCF1 registration and profile were retained; scoped
processes exited. Prelaunch harness failures remain preserved. Directory
enumeration diagnostics still differ from successful child lookup and implicit
OS file reads. Packaged GUI/outer-pipe acceptance and folder/restart
reconciliation remain open; provider activation and installed Linux R130 are
unchanged, and the laptop app remains closed.

The next restart-reconciliation foundation is a read-only cache query for
unfinished ordinary-file offline intents. It returns at most eight exact-scope
records per resource-ID cursor and validates persisted path, version, revision
and target state. A restart/account-isolation/pagination test passes, as do
required workspace formatting, strict Clippy and tests. Independent review
identified an unknown-state hardening gap, repaired with the existing decoder.
This API is not yet connected to Windows RPC/UI or verified in Windows; it
does not resume partial bytes, start network work or reclaim retained stages.

R161 adds an exact-resource lookup for unfinished ordinary-file offline intents
and exposes a pending-intent flag through the existing Windows file status RPC.
The backend matches the saved path and version to the current authenticated
file binding; the UI strictly validates the flag and offers a fresh explicit
download while preserving recovery data. Intent status remains last observed
and non-atomic, independent of whether a complete saved version is recorded.
A cache-reopen test verifies matching and changed path/version refusal. Required
host Rust gates, frontend build and focused controller tests pass. Windows
build/native verification is pending; no automatic partial-stage replay, folder
reconciliation, provider activation or packaged-app acceptance is claimed.

R161 Windows acceptance now passes the three targeted native cases: persisted
intent paging/scope isolation, exact-version pending status after cache reopen,
and the normal connected-worker lifecycle. Parent checked raw names, numeric
child/wrapper exits, suspended WTS identity/image hashes and retained RaiunCF1
registration. Processes exited and the profile stayed loaded. No package was
installed. The UI also refreshes saved status after a terminal download result.

R162 adds pin-bound Windows cache downloads and cached-content promotion.
Admission and publication check the exact live folder manifest, root, scope and
version; content remains Recent and is retained by the pin rather than creating
independent per-file offline policies. Seven exact Windows native cases pass,
including removal/staling refusal, policy-supersession regressions and clean
eviction after unpinning while dirty content remains protected. Parent checked
raw results, artifact and suspended-user identity proofs; the profile and
existing registrations were preserved. This is a cache foundation, not a
completed folder workflow or packaged-app acceptance.

R163 adds cancellable pin-readiness verification, probing during content hashing
and immediately before status publication. Observed cancellation preserves the
prior pin state, manifest and content. Required host Rust gates and independent
review pass; exact Windows verification is pending. The existing noncancellable
API retains its behavior, and folder-job integration remains open.

R164 separates complete-manifest admission from content verification for future
folder jobs. The new API returns a durable Building pin without hashing cached
bytes; cancellation before commit rolls back all inserted pin rows. Once commit
wins, the caller receives the durable ID for reconciliation. The existing
synchronous API still verifies readiness before returning. Focused rollback,
deferred-readiness and compatibility checks, required host Rust gates and
independent review pass; Windows native verification remains pending.

R163 Windows verification now passes all four selected cases: cancellation before
lookup, cancellation during verified-content hashing, pin retention through
clean eviction, and cached pin promotion. Parent verified exact test names, raw
numeric exits, the pinned image and ordinary-user identity before resume, and
process/profile postflight. No cloud root or registry change occurred; no new
package was installed.

A fresh 18 October host process check supersedes the earlier closed snapshot:
the installed R130 UI and agent are running, with executable hashes matching
the verified R130 build. They were left untouched. No later package has been
installed or accepted for delivery.

R164 Windows verification passes three exact native cases, including admission
rollback and deferred readiness, with numeric child/wrapper exits and identity
proofs checked by the parent. The preserved start record has stale expected
counts of four; the pinned sequence, actual child records and final results
consistently show three. This evidence-label discrepancy did not require a
rerun. No package or installation acceptance is implied.

R165 adds one bounded native diagnostic to the existing connected-worker test.
The exact Windows test passes, including both implicit OS reads and the file
status/list/job checks. Across Personal, Spaces and Projects, the first Rust
listing remains empty; after successful child enumeration, a fresh Rust read
sees all expected names without another accepted callback. Parent checked raw
results, pinned source/image, suspended-user identity and preserved synthetic
registration/profile. This narrows the initial-enumerator/population timing gap
without proving a fix or packaged Explorer acceptance.

R166 pin-bound file transport passed five exact Windows component cases. R167
fresh-only recursive folder admission/download passed five further exact cases,
including unavailable-server refusal, cancellation preserving a durable Building
pin, and wrong-identity/encrypted-child refusal. Independent review checked all
132 frozen source members and actual suspended-user image/identity proofs,
numeric child/wrapper exits and preserved profile. The R167 build-list wrapper
had an overstrict total-count guard (nine module tests, five selected); raw
check/Clippy/build/list exits were zero, but its postflight is missing. An optional
wrapper-error-file collection also failed; actual run exit evidence is present.
These are component results, not folder controls, packaged Explorer acceptance
or an installation.

R168 moves pin byte verification outside the metadata mutex and compares full
snapshots inside an immediate transaction before publishing readiness or replacing
a manifest. Staging is verified before replacement; cancellation preserves both
manifests and Dirty bytes. Exact size and scope protection are checked, retaining
legacy ciphertext-pin invalidation behavior. All 108 cache tests pass, including
four new snapshot/replacement cases; source formatting and strict workspace
Clippy and the complete workspace test suite pass. Windows verification remains
pending.

R168 Windows component verification is accepted: six exact native cache tests
passed once, including cancellation, concurrent snapshot changes, replacement
preserving Dirty bytes, and the Windows ciphertext invalidation regression.
Parent checked all 134 frozen source members and actual suspended identity/image
proofs, numeric child/wrapper exits, and final process/profile evidence. A Unix-only
selector and a missing local evidence directory caused preserved prelaunch
harness failures; neither required repeating native tests. No root/registry
claim is inferred from hardcoded harness flags. No package was installed.

R169 adds an explicit unchanged-manifest retry for an existing Building folder
pin. It retains the exact durable ID and checks account/root/path, all stored
manifest fields and fresh complete listings without mutating pins or bytes.
Changed, Ready or Stale snapshots are refused; changed-tree reconciliation
remains separate work. All 112 cache tests pass, and independent review found
no blocker. Full source gates and Windows backend/native verification are pending.

R169b exact interrupted-folder retry passed six native Windows cases (four cache
and two backend cases). Independent review verified the 136-member frozen source,
artifact pins, exact single-test logs and numeric exits, pre-resume identity and
image checks, and profile/process postflight. All required host and Windows source
gates pass. Preserved failures include a Windows-only unused-mut warning, an
inventory module-prefix mismatch, and a prelaunch checker-name mismatch. Literal
root/registry flags are not independent preservation proof. No package/install
acceptance follows from these component results.

R170 adds changed-folder refresh using a separately retained staging pin and an
opaque observation of the active snapshot captured before network work. A newer
manifest cannot be overwritten by an older refresh. Fresh listing admission may
mark Ready as Stale only when every identity, manifest field and content record
remains unchanged; final transactional validation still compares state exactly.
Cancellation before replacement preserves both pins; successful replacement keeps
the active ID and Dirty content. Final auth/root validation can fail after local
commit, in which case that active ID remains the reconciliation target. All 115
cache tests pass; independent review found no blocker. Full source checks and
Windows verification are underway. This does not complete folder controls or
restart/reconnection acceptance.

R170 native Windows verification exposed a staging-retry bug after four passing
cases: readiness inspection promoted an already cached staging pin from Building
to Ready, while the retry path accepted only Building. The fifth test failed and
the sixth was not run; raw evidence and the runtime are preserved. R170 is not
accepted as a complete native batch. R171 adds an exact staging-only retry that
also accepts Ready, without changing ordinary Building-only retry semantics or
skipping fresh manifest, per-file version and final byte/CAS verification. Its
117 cache tests pass; Windows retesting remains pending.

R171 also integrates bounded authenticated folder listing and folder job RPCs,
including prepare/start/resume/refresh/status/cancel. Folder jobs share the one
active offline-job slot and preserve pin progress; legacy file-job replies retain
the exact existing shape. Review caught a lost-start-reply race. Folder admission
now requires a reservation ID returned before any work can start, so lost replies
can be queried/cancelled and duplicate deliveries do not repeat work. Reservations
are bounded in-memory state and do not constitute restart recovery. Source gates
and native verification are still being completed. The isolated UI controller
passes eight focused tests and the UI build, but is not wired into the app yet.

R171's first Windows compile caught a test helper shadowed by a local binding;
the test-only correction is in R171b, with passing required host gates and a
fresh immutable Windows verification run underway. No native result is inferred
from compilation. R172 connects the folder controller/panel to Windows Transfers
with live mounted-drive action checks and known-job polling/cancellation. It also
adds atomic initial-pin admission: an existing same-scope root identity or path
refuses another initial save, including across independent cache handles, while
explicit staging remains available. All 120 cache tests pass, including reopen,
Dirty-byte preservation, cancellation and a two-handle admission race; independent
review found no blocker. UI integration checks and platform/package acceptance
remain pending. Persisted pin-role reconciliation after restart remains open.

R171b subsequently passed sixteen exact Windows native cases with independent
raw-evidence review. R172 integration review then found a missing outer prepare
dispatcher arm; it is now wired and has an actual dispatch/account-guard test,
whose Windows execution is still pending. R172's 29 focused UI tests, UI build,
and required Rust formatting, lint and workspace tests pass. Its unsigned Linux
package is frozen with all thirteen packaged file hashes independently checked;
isolated exact-package VM acceptance is underway. No new laptop installation or
Windows GUI/package acceptance is claimed.

The C02 enumeration audit also found an evidence limitation: R165 replaced its
first Rust-read callback counters after the child PowerShell enumeration. Those
final counters cannot identify which query triggered population. A test-only
follow-up will retain separate phase measurements and try a second Rust query
before the child query; first Explorer listing remains unverified.

R173 implements that diagnostic without changing provider behavior and adds a
backend regression for refusing a repeated initial folder save after a cancelled
admission. Its required host gates pass. R174 fixes a concrete folder-picker
ambiguity: Personal and Space roots previously shared the label “Drive root.”
Folder pages now include a display-only location label from authenticated
namespace discovery. Identity-only restored rows are omitted until a name is
available; labels never enter folder admission identities or requests. The UI
retains the original job's label when selection changes. Its 21 focused tests
and UI build pass; independent backend review found no blocker. These Windows
changes still require Windows compilation/native verification and do not change
the already frozen R172 Linux package.

R174's Windows check/lint, three test builds/listings and nine exact native cases
subsequently passed. Parent review checked actual suspended child identity,
session, image and hash before resume, individual numeric exits and wrapper exit
0. The C02 diagnostic found zero callbacks during both first and immediate second
Rust reads; a child query then populated the directories. The next bounded test
uses a Rust child before PowerShell to separate process behavior from API behavior.
This still does not establish first Explorer listing or Windows GUI acceptance.

R176 corrects a separate folder-control usability issue: terminal jobs hid the
already known refresh/resume action until users selected another folder and back.
Completed, cancelled and failed jobs now expose only their existing same-folder
role action. Active/uncertain jobs retain their guards, recovery-required jobs
offer no new mutation control, and terminal jobs no longer show a no-op status
button. All 24 focused UI tests and the UI build pass. This is source/UI-test
evidence; it is not part of the installed R172 Linux artifact or Windows native
GUI/package acceptance.

R175's early Windows compile caught a Unix-only temporary-directory dependency
in the diagnostic smoke test, before any native run. That failed source and log
are preserved; the corrected test uses a fresh standard-library directory and
removes it only after child success. R177 batches that correction with a cache
restart fix: new ordinary pin IDs use random bytes in the existing 64-hex format,
replacing a process-local counter and seconds clock that could repeat in another
process. Existing IDs, schema and scope checks are unchanged. A three-process
persistent-cache regression passes on Linux, including unchanged Dirty content;
R177 required source checks and Windows compile/lint/test-build gates passed.
The native cache regression failed before ID generation because a child could
not open the private cache in a test that kept the parent and sibling owners open;
that failure is preserved and unaccepted. R177b changes only the regression to
model fully closed sequential owners, retaining all storage protections and
Dirty-content assertions. Its focused Linux tests pass; Windows recheck follows
fresh source gates.

The independent, previously unattempted R177 lifecycle diagnostic passed with
numeric child/wrapper exits 0 and no remaining test processes. For Personal,
Spaces and the Projects Space, a Rust child of the same test executable obtained
the expected entries and one accepted callback, while both preceding parent
reads were empty with zero callbacks. PowerShell and post-child parent reads
also matched. This narrows the diagnostic to process behavior; it is not an
Explorer fix or full Windows acceptance. Parent raw-evidence review is in
`outputs/pin-id-process-20261018-r177/windows/native-runner-r177-lifecycle-continuation/native-evidence-r177lifecycle/parent-native-acceptance-r177-lifecycle.json`.


R177b's corrected sequential-owner restart regression subsequently passed the
Windows native gate with three distinct persisted pin IDs and unchanged Dirty
content. Parent review verified the frozen source delta, four Windows build/list
exits, actual suspended process identity and image hash before resume, child and
wrapper exits 0, and no remaining test process. The earlier concurrent-owner
failure remains preserved; concurrent Windows private-cache ownership is not
claimed by this result.

R178 adds durable ordinary-folder role intent under cache schema v7. Initial
admission, verified initial promotion and staged replacement update role records
in the same transaction as the pin change. Roles bind exact account/Space/root
and folder ID/path; legacy pins are never assigned roles by inference. Deleting
an active pin preserves its separate refresh stage as recovery-only: a durable
initial-stage flag prevents later readiness inspection from reactivating that
orphan. Review caught and corrected this cancellation edge before acceptance.
The v6 migration preserves saved pins and Dirty bytes and continues rejecting a
missing v6 policy-intent fence. Older binaries refuse schema v7 after migration;
this source upgrade is not installed on the laptop.

R178's eight focused journal regressions, required Linux source gates, Windows
workspace check/lint, and cache/CloudFiles test compilation/listing pass. Eleven
exact Windows native cache/backend cases are in progress. R179 then connects
read-only durable role discovery to folder pages and the UI. It separates known
intent from unknown, unavailable and orphaned state, retains the four-field
folder admission identity, and refuses automatic role guesses. Nine focused
cache tests and 28 focused UI tests pass; the UI build passes. Linux cannot run
the Windows-only folder-page tests (the attempted filter selected zero tests),
so those require the following Windows delta. Full R179 source gates remain in
progress. Neither revision establishes package, native GUI or whole-C03
completion; the laptop remains on the exact R172 package and closed.


Parent review has now accepted all eleven R178 Windows native component cases:
the exact eight journal regressions plus three affected folder start/refresh/
resume flows. It verified 95 collected raw files, the complete selector set,
actual suspended identity/image/hash gates, individual and wrapper exits 0 and
closure. A timed-out collection was recovered by recollecting evidence, without
rerunning tests. R179's final required source gates pass; its four-case Windows
discovery delta is underway.

The R180 Linux package has been built from 209 stable public source inputs and
verified against its thirteen-member manifest (archive SHA-256
`a8bdbee0d005c29641bfd78a1b1cc75979858a8a4e5ecc8756dc19d2acff0be6`).
Its isolated native check is specifically exercising genuine v6 synthetic Dirty
state through the v7 upgrade before recovery export and normal Quit. It is not
installed yet. The installed R172 public binaries and launcher have another
preserved backup; no user profile, credentials or recovery data were copied.
A filtered 212-file R181 Windows package source bundle is ready for unsigned
NSIS build and package acceptance after the R179 component delta. These are
pre-release validation steps, not publication or whole-checklist completion.

### Current Linux acceptance update — 21 October 2026

R200 adds an explicit accessible name to the complete media-preview status and
includes the installer guard requiring Zenity before destination writes. Its
166 UI tests, type check and standard package build pass; unchanged Rust source
gates are recorded and reused. Isolated native evidence verifies the local
preview and exact source preservation with zero preview PUT attempts. The full
media workflow still stops at backup destination selected-value observation;
upload, duplicate avoidance and restart recovery remain open. All four isolated
installer cases pass: missing-Zenity refusal and preservation, followed by
genuine-Zenity fresh installation and replacement of a previous synthetic
installation with unrelated state preserved. Agent database migration is a
separate acceptance gap. The laptop still has R180, not R200.

See the [bounded R200 acceptance](MVP-ACCEPTANCE.md#linux-r200-bounded-acceptance--21-october-2026)
and current continuation state (maintainer-local evidence: `../../outputs/desktop-continuation-state-20261017.json`).
No whole completion-checklist category is promoted by these results.


### 21 October 2026, 08:50 UTC — laptop test candidate R200

The exact R200 archive (`bd7df5c8c1e0a5f58e50748b65ed4401ba2164f150052ee685739f8670b5d6f4`) is now installed on the laptop after source gates, isolated exact-package installer qualification and bounded native VM checks. Installed app, agent, CLI, icon and manifest hashes match the approved archive. Previous R180 binaries, icon, manifest and desktop entry are preserved under `outputs/install-candidates/r200/20261021T085000Z/previous-R180/`. The app was not launched; no matching product process was observed before or after installation. Six same-UID executable links were unreadable, so the process-image scan was not exhaustive. No accounts, credentials, cache contents or cloud files were changed by this installation. This is an installed test candidate, not a claim of complete beta or C01–C10 acceptance. Receipt: `outputs/install-candidates/r200/20261021T085000Z/installed-state.json`.

### Windows bandwidth controls (local next-release work, 24 October)

Windows now implements the existing upload/download limits editor and account-bound
control requests. Content clients for the drive, folder/media work and recovery
share one transfer budget; sign-in and metadata requests remain outside that
budget. Preferences use a separate protected record with exact account-scope and
revision checks. A newly signed-out or not-yet-verified account shows unlimited
defaults and cannot save limits. Already verified offline accounts may edit their
own retained preferences.

Source checks and the focused portable service test pass. Native Windows
preferences persistence, effective aggregate throttling and installed-package
acceptance are still pending; this source work has not been released.

### Windows proxy settings (local next-release work, 24 October)

The Windows settings page now supports a proxy choice while signed out. Save a
system, direct or credential-free HTTP(S) proxy route before the next sign-in.
An existing session keeps its immutable route through token refresh and content
requests; changing the preference requires signing out first. Drive, folder/media,
recovery and Personal verification clients now consistently use that session route.

Preferences have a separate protected, revision-checked record. A pending choice
binds only after verified account metadata. A previous account's bound preference
is preserved but remains inactive for a new sign-in until an explicit signed-out
settings change replaces it. This does not import Windows proxy policy beyond the
existing HTTP client's system-proxy behavior.

Source checks and two focused portable preference tests pass. The Windows agent
RPC test compiles but has not run natively. Native routing, protected persistence
and installed-package acceptance remain pending; this work is unpublished.

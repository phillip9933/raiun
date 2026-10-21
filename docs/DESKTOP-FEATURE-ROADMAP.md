# Desktop feature roadmap and interoperability

The owner-approved [Linux and Windows completion checklist](COMPLETION-CHECKLIST.md)
fixes the scope and completion criteria. Historical notes and optional ideas
below do not automatically add release blockers.

## Current installation: R123, closed — 17 October 2026 JST

The exact R123 Linux package is installed and left closed. Its isolated native
Transfers flow exported a 53-byte pending saved edit while a fresh complete
listing was unavailable, preserved the dirty journal and cache bytes, and made
no additional PUT or destructive request. The exported file was private and
byte-exact. Normal owned tray Quit and independent process/socket/mount closure
passed. The previous R119c binaries and launcher are backed up; real profiles
and recovery data were not changed. The original UI selector failures are
preserved, and no numeric shell exit code is claimed because its original
parent had exited; separate closure proof passed.

Evidence: [parent acceptance](../../outputs/vm-lab/linux-saved-edit-export-20261017-r123/native-acceptance.json),
[installed state](../../outputs/vm-lab/linux-saved-edit-export-20261017-r123/laptop-install-r123.json),
and [native details](../../outputs/vm-lab/linux-saved-edit-export-20261017-r123b/R123b-acceptance-status.md).
R126 now has 12 individually verified native Windows filter passes: four
account/root-fenced cache-status tests and eight exact-binding cache tests.
The first harness stopped after two passes; a fresh continuation ran only the
remaining ten. Raw numeric exits, stdout and pre-resume identity/hash checks
passed, and scoped processes were closed afterward. Final wrapper summary/exit
records are unavailable and are not claimed as a clean aggregate wrapper run.
[Parent native review](../../outputs/vm-lab/windows-cache-policy-binding-20261017-r126/parent-native-acceptance.json).
R127 cache-publication hardening passed 784 host tests (13 ignored), formatting
and strict Clippy. Its exact R128 Windows cache artifact passed all 15 serial
native policy/invalidation tests, including final metadata revalidation and
preserved dirty bytes; native process and wrapper exits were both zero and
postflight found no scoped process. [Parent native review](../../outputs/vm-lab/windows-cache-publication-fence-20261017-r128/parent-native-acceptance.json).
The combined R130 Linux package has passed its fresh-home VM installer check;
its native runtime/export acceptance is pending, so R123 remains installed.
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
See [parent acceptance](../../outputs/vm-lab/linux-offline-recovery-identity-20261017-r119c/native-acceptance.json)
and [installed hashes](../../outputs/vm-lab/linux-offline-recovery-identity-20261017-r119c/laptop-install-r119c.json).


## Earlier installation: R116a, closed — 17 October 2026 JST

R116a is installed and hash-verified after native ordinary-file policy and warm
agent-process offline restart acceptance, followed by an exact corrected-package
VM installer check. Dirty data and recovery stayed intact; no successful cloud
PUT/DELETE/MOVE occurred. R112 is backed up. The first R116 install was safely
refused for invalid timestamp metadata; R116a changes only that manifest field.
See [current implementation](IMPLEMENTATION.md) and
[installed state](../../outputs/vm-lab/linux-failed-upload-listing-refresh-20261017-r116a/laptop-install-r116a.json).
Cold-login restoration, metadata-unavailable recovery enumeration, recursive
folder native acceptance and Windows native/provider gates remain open.
The R112/R108 checkpoints below are historical.

## Earlier Linux installation: R112 — 17 October 2026 JST

R112 is installed, hash-verified and closed. Native UI AlwaysOffline readback,
clean CloudOnly eviction and dirty-edit refusal/durable retention passed in the
isolated Linux VM; the remote snapshot stayed unchanged. Normal tray Quit closed
the app and agent; its helper's redundant shutdown RPC failed after the socket
was already gone, so that harness failure and unavailable attached-shell exit
code remain explicit. See [current implementation](IMPLEMENTATION.md) and
[R112 evidence](../../outputs/vm-lab/linux-offline-policy-commit-20261017-r112/native-acceptance.json).
R113b also passed native copy into an existing nested encrypted destination on
the exact installed R112 package, including plaintext verification, unchanged
source, journal retirement and normal tray Quit. Folder creation/moves and live
interoperability remain open. R108 is backed up. R115 confirmed that an offline process restart can leave
Personal empty after listing invalidation despite retained pinned/dirty bytes;
this remains an open Linux gap. R116 is an uninstalled narrow source repair for
failed uploads with reachable metadata, not full offline-restart completion.
Windows duplicate-edit restart acceptance remains blocked at
composite-root preflight; R114 is a diagnostic, with provider activation disabled.
The dated checkpoints below retain their historical installation statements.

## Earlier R108 Linux package and R109 Windows follow-up — 17 October 2026 JST

The current laptop installation is **R108**, hash-verified and left closed.
Its archive SHA-256 is
`3222fb7f2b1768696eefcd43fb972f33d75b13529f77465cd67feee9916823f8`.
The prior R107 installation is preserved. Native UI copy to a different unlocked
vault root, exact plaintext readback, unchanged source, journal retirement, and
normal tray Quit passed on that package. See the
[current implementation record](IMPLEMENTATION.md) for the installed-file hashes,
backup and acceptance evidence.

R109 adds recovered same-process Windows WTS lifecycle acceptance with implicit
OS reads in Personal and Projects Space. It does not enable the production
provider or establish Explorer/package acceptance. R110's metadata-conditional
cache-policy APIs pass the host gates (760 tests, 13 ignored); nine cache and one range checks have passed on Windows. Windows policy RPC/UI, AlwaysOffline downloads,
and OS dehydration remain open.

R111 adds the atomic verified-content guard for existing AlwaysOffline admission;
all eleven Windows cache checks pass. Its separate duplicate-edit process-restart
native test failed at composite-root preflight before registration; diagnosis
continues. R112 Linux cache-policy native UI checks are in progress and that
candidate is not installed. R108 remains installed and closed.

### Earlier verified checkpoints

The dated checkpoints below preserve history; their installed-version statements
are historical. The current installation and source status above take precedence.

R92 is installed on the Linux laptop, hashes verified and left closed at
00:38 UTC (09:38 JST). R79b binaries and launcher are preserved in
`../outputs/install-backups/r92-before-install-20261017T003818Z/`.
The exact accepted archive is
`f3628a8a5dad0d212197a9d1e743de7f3b6800ae42323101169cb94f6864613c`.
Recovery and profile data were untouched. Agent and CLI hashes still match R79b.

Native Linux UI checks confirm readable media selector labels, exact synthetic
Camera selection, local preview, one account-bound Personal `/Photos` backup,
verified upload/readback, and an unchanged **Check now** with no second PUT.
The source stayed unchanged; DELETE and MOVE counts stayed zero. The UI driver
misclassified accessible text as a missing name after completion; screenshots
and independent fixture counts establish the result. The scoped runtime closed
gracefully and synthetic source, job and recovery state remain preserved.
Host gates pass (736 workspace tests, 13 ignored; 66 UI tests and UI build).

Windows R69a passes 20 empty-probe/status cycles, a held-client response test,
and reply-dropped shutdown with native exit code zero. The test-only R70 fixture
correction passes Windows recovery 7, cache 59, CloudFiles unit 80 and native 8;
check and strict Clippy pass. R72 unsigned Windows 0.1.3 builds successfully;
R74 verifies 0.1.2 install → 0.1.3 upgrade → uninstall with state sentinels and
prior packages preserved. R73 verifies actual Settings saved-edit status and
native tray reopen/quit; the scoped shell and agent exited. R76 builds unsigned
Windows 0.1.4 with Windows-only CREATE_NO_WINDOW agent startup and passes Windows
shell format, strict Clippy and 19 tests. R78b installs that exact package with
exit code zero and matching agent/CLI hashes; R78b native GUI acceptance passes Settings saved-edit status,
no visible agent console, close/tray reopen and confirmed normal Quit. The exact
shell and agent exit with no installed-path processes or control pipe remaining. A conhost child process alone does not establish a visible
console or a failed headless startup check. Provider activation remains disabled.
R77b passes host gates and Windows check/strict Clippy, but the native test fails
before hydration: ordinary OS enumeration of Personal returns no fixture child.
Hydration and final mutation-counter assertions were not reached; diagnosis is
ongoing and production activation remains disabled. R79b passes exact Linux
bundle acceptance: native version survives navigation/status refresh and required
Settings actions fit the default 1000×720 window. Its isolated shell and agent
closed gracefully. R79b laptop installation is complete and left closed. Windows
0.1.4 still displays footer 0.1.0. R81b builds Windows 0.1.5 with the accepted UI
fixes and no experimental native test changes; 19 shell tests and package build
gates pass. Exact GUI acceptance initially stopped before launch because the installed
shell hash differs from the raw staged release shell. Parent byte comparison
proves the sole difference is Tauri's unique bundle marker UNK → NSS (three bytes),
corroborated by the NSIS build log. The derived embedded-shell hash is pinned
separately. R79d/R79f completes exact Windows 0.1.5 GUI acceptance without
reinstall: version 0.1.5 survives navigation/status refresh; Settings actions fit
the unchanged default window; no visible agent console; native tray reopen and
screenshot-gated normal Quit pass. Exact shell/agent processes exit and the control
pipe refuses connections. The synthetic VM installation is retained, app closed.
Earlier harness failures remain preserved; no hash check was relaxed.
R80d child-process OS enumeration triggers accepted callbacks for Personal,
Spaces and Projects. Projects publishes two entries, matching the fixture's
RecoveryRoot plus native-read.bin; its test incorrectly expected only the file.
R84 confirms both names are present; the remaining comparison failure was a
culture-aware PowerShell sort versus Rust lexical ordering. R85 uses explicit
ordinal ordering and passes the full focused native lifecycle test under a
standard non-admin synthetic user: exact Personal/Spaces/Projects enumeration,
implicit OS-read hydration in Personal and Projects, exact bytes and ETag binding,
zero read-phase mutation attempts and zero PUTs. No timeout; profile unloaded and
Developer Mode restored exactly. This is test-only per-instance provider activation,
not production enablement. Safe agent APIs do not expose exact placeholder-state
bits; that diagnostic limit remains explicit. Native write/offline/recovery and
actual authenticated recovery-row GUI acceptance remain open.
R90 additionally passes a native post-reconnect ordinary edit/close and durable
conflict check: a changed synthetic remote version triggers no extra PUT, exact
local dirty and external remote bytes remain intact, and unregister is refused.
This is a test-only milestone; whether a still-pending edit is dispatched across
an intervening restart is being audited separately. Production activation stays
disabled. A real-agent named-pipe test bridge is being prepared for the recovery
row GUI gap, with no production fixture switch or fabricated RPC.
R83 passes the actual synthetic Linux remember-off → explicit opt-in → lock →
saved-key UI unlock/canary → forget → lock/refused saved unlock sequence, with
private keyring and graceful shutdown. Its visible no-key hint was not exposed
as matching AT-SPI text. R92 names the saved-key status live region and passes UI build/66 tests plus
exact-package Linux AT-SPI acceptance: one status node exposes the exact no-key
name and text after real saved-unlock refusal, vault remains locked, zero fixture
PUTs, graceful agent/UI exit. Its synthetic vault is preserved. R92 is installed on the laptop with verified
payloads and a full R79b binary/launcher backup, and is left closed.
R90 does not establish pending dirty recovery across a process restart: its
conflict edit is created after reconnect. That acceptance gap remains open.
R91l displays the real synthetic saved-edit row in Windows Settings and preserves
it through one Refresh, using the actual framed agent/DPAPI fixture. The fixture
timed out before final post-Quit journal/zero-PUT assertions, so GUI evidence is
partial and no native fixture pass is claimed; the shell later quit normally.
R96 reopens the exact pending dirty snapshot set across two processes. Two
byte-identical immutable records already existed before the first process exited;
conflict dispatch is not yet accepted. Fresh acceptance will require the entire
bounded record set to survive unchanged and every record to resolve safely.
R98 passes that two-process set-aware recovery test: both exact immutable records
survive restart, both become durable conflicts, local/remote bytes remain intact,
and PUT/DELETE/MOVE stay zero. Unregister is refused. Explicit test-only CFAPI
hydration was needed before the ordinary read/write open, so implicit hydration
for that access mode remains an acceptance gap. Recovery state is preserved.
R99 completes the real-agent Windows recovery-row GUI test: Check + one Refresh
show the exact saved-edit row, normal tray Quit stops shell and fixture, native
test exit is 0, encrypted journal bytes/metadata remain unchanged, and fixture PUT
count stays zero. No packaged sidecar was spawned. Earlier harness failures are
preserved and the successful continuation ran on the same pinned processes.
R102 also passes the Windows-native cache boundary test under a fresh non-admin
SID: CloudOnly evicts clean Recent content, refuses a real journal-referenced
Dirty blob even after its label is demoted to Recent, and preserves exact pending
write metadata/base/bytes through refusal and eviction. Native exit is 0 with one
test passed; a collector regex initially misread the Rust summary and is corrected
without rerunning the test. This covers cache storage only, not Windows policy/
pin RPC, UI, recursive pinning, or production provider enablement.
Source hardening now guards both copy attempt claim and successful completion
with both token generations and both unlocked vault scopes. A session-bound cache
claim authenticates the exact journal revision without recursively acquiring its
coordinator lease. Cancellation/locked-source preclaim tests retain NeverAttempted;
completion revocation tests retain recovery. Host format, strict Clippy, focused
copy tests and full workspace tests pass (737 passed, 13 ignored). An initial
unrelated pause-cancellation timing test failed once, then passed focused and full
reruns; its failure log is retained. The later R102 Windows source gate below
includes this hardening.
The producer backend now exposes cancellable source/readback and guarded
admission/completion. Pre-read cancellation issues no requests and creates no
sealed journal. Final focused tests, strict Clippy and full workspace tests pass
(739 passed, 13 ignored). Active PUT now passes the caller cancellation predicate
to the existing body watchdog, which drops the request/body future on cancellation
without cancelling unrelated transfer budgets. A deterministic stalled partial-PUT
test aborts promptly, retains an Uncertain nonretryable copy journal, and records
no complete fixture PUT. R102 Windows exact-source check, strict Clippy and agent/
cache test-binary builds pass; producer RPC/UI is still absent and these changes
are not yet packaged.


Copy producer preparation now publishes the real durable journal ID/revision
immediately after queueing. Prequeue cancellation publishes nothing; cancellation
before attempt admission retains NeverAttempted, and interrupted PUT retains
Uncertain. The bounded producer job registry starts with no placeholder IDs,
retains an exact validated binding through cancellation/failure, and invalidates
on either vault scope/Space. Guarded successful completion wins a later cancel.
Host format, strict Clippy and workspace tests pass (744 passed, 13 ignored).
This is source-only preparation: no producer RPC/UI is exposed, the new registry
has not yet passed Windows compilation, and installed R92 remains closed.


R103d passes Windows check, strict Clippy and both exact-source test-binary builds
(108 frozen source hashes verified). Its read-only file cache metadata test passes
under a fresh non-admin SID: unknown/stale bindings fail, cache metadata queries
add no network requests, and cancellation/revocation are refused. Native exit is
0 with one test passed; an outer collector initially mishandled CRLF and reported
a false failure, so its correction does not rerun the test. Policy/content are
independently observed metadata, not an atomic snapshot or a promise of future
offline readability. No cache initialization or cached-byte reads occur in this
query. Windows policy/pin RPC, UI and OS placeholder dehydration remain pending.


Encrypted edit cancellation now checks the job operation class before mutating its
cancellation flag. Runtime IPC regression covers both wrong-action directions:
each refuses the request without cancelling the running job, while the matching
action cancels and joins normally. Host format, strict Clippy and full workspace
tests pass (745 passed, 13 ignored). This Unix control-path fix is source-only;
the installed package has not changed.


R103f's corrected four-leaf diagnostic proves all four leaves existed with exact
sizes and partial Cloud Files state 57 before ordinary reads. Every read failed
with error 395, with zero admitted callbacks or backend GET/range traffic; the
launcher, provider/test host and observed child processes all ran in Session 0.
This narrows the investigation to caller session context, but does not establish
causality. Its restart/conflict checks still require the labeled explicit CFAPI
fallback. R106c's same-SID session comparison remained inconclusive: the target-session
launcher returned Win32 error 3 before creating a child, including with verified
physical C: paths and an explicit default desktop. No implicit hydration or
WTS/Explorer acceptance is established; production provider activation remains off.
R105 separately passes all four exact shared copy-backend tests on Windows:
prequeue cancellation has no binding, postqueue cancellation retains the exact
NeverAttempted binding, active PUT cancellation retains Uncertain recovery, and
successful copy is conditional with verified decrypted readback. All native
exits are 0 under a fresh non-admin SID; the profile unloaded. An initial local
collector failure was repaired by collecting preserved logs, without rerunning.
R107 now verifies the Linux copy RPC in the isolated CachyOS VM: a real job
reported copied with its actual durable binding, retired the journal only after
verified decrypted readback, and preserved source bytes, identity, version and
its complete ciphertext tree. All three GNU mv refusal cases passed without
cloud DELETE/MOVE or destination creation. The exact package
`de8cc256f5a42c72b4bbce37f502c81c94e75073a0914d57ce1b947ba7804fe3`
is installed on the laptop, with R92 backed up and the app left closed. This
covers a destination vault root; nested-parent acceptance remains open because
the online route intentionally does not create directories. R108 adds user copy controls and current root/version metadata. Its exact
package `3222fb7f2b1768696eefcd43fb972f33d75b13529f77465cd67feee9916823f8`
passed actual AT-SPI source selection and destination-root copy, decrypted
readback/source preservation, journal retirement and conditional-request checks.
A separate shutdown-only check invoked the exact shell-owned native tray Quit:
shell and agent exited 0 with no additional remote mutations. The initial
window-destroy harness failure is retained. R108 is installed on the laptop,
R107 is backed up, and the app remains closed. Windows copy UI is hidden;
nested-parent copy acceptance and durable moves remain open.

R109 adds a Windows native lifecycle result from the pre-existing synthetic
`raiunGuiR66a` console session (WTS session 1): the exact `native_normal_lifecycle_restores_and_reconnects_registered_namespace` test passed once (1 passed, 0 failed) and reported implicit OS-read hydration for Personal and Projects Space. The same suspended process was verified by PID, image hash, SID, session and command line, then resumed once and exited naturally with code 0. The initial wrapper attempt stopped because CIM returned a null executable path; that failure is preserved, so this is not a clean wrapper pass. Developer Mode was restored exactly. The synthetic root/profile remain; no registration enumeration or cleanup was performed, and a protected cache path was not inspectable from SYSTEM. This is native test evidence only, not Explorer acceptance, packaged GUI acceptance, RecoveryRoot hydration acceptance, or production provider enablement. Evidence: [`native-acceptance.json`](../../outputs/vm-lab/windows-wts-isolated-native-20261017-r109/evidence/native-acceptance.json) and [`status.md`](../../outputs/vm-lab/windows-wts-isolated-native-20261017-r109/evidence/status.md).

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
and closed. See the [R110 native acceptance record](../../outputs/vm-lab/windows-cache-policy-fence-20261017-r110/evidence/native-acceptance.json) and [gate status](../../outputs/vm-lab/windows-cache-policy-fence-20261017-r110/STATUS.txt).


A source audit found unsupported cross-vault/root moves returning EXDEV, which
can invite a client such as GNU mv to copy and then unlink the source before
cloud destination verification. These cases now return EPERM; unsupported
same-route rename flags return EOPNOTSUPP. Same-route unflagged renames retain
their existing leased path. Independent review and host format/strict Clippy/
workspace tests pass (751 passed, 13 ignored). Exact-package isolated VM tests
must still prove GNU mv refuses with no source/destination mutation. This is
source-only and does not implement cross-vault moves. See the
[GNU mv fallback contract](https://www.gnu.org/s/coreutils/manual/html_node/mv-invocation.html).

These are test milestones; the broader feature roadmap remains incomplete.

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

## Initial public beta 0.7 gates — status 17 October 2026 JST

Linux and Windows readiness are independent. Source tests, packaged builds,
installed packages and native user acceptance are separate evidence; passing
one does not establish the others. No release or publication is authorized by
this roadmap.

- Linux: R56 is installed, hash-verified and closed; R55 is backed up. Its exact
  executables match R49d, which passed mounted write journaling, ancestor rename
  refusal, retained recovery bytes and native diagnostics save/export with private permissions,
  strict allowlisting and no overwrite. Host strict gates, 736 Rust tests,
  53 UI tests and three focused Tauri diagnostics tests passed. R44/R47 locked
  dialog acceptance remains prior feature evidence. R50 verified keyboard Escape
  and bottom Close restore focus to the exact picker opener. Spoken output, IME
  and real desktop-login acceptance remain unverified.
- Windows: R109 passes one exact native lifecycle test under the pre-existing
  synthetic WTS console identity; implicit OS-read hydration is observed for
  Personal and Projects Space. The first launcher attempt failed on null CIM image
  metadata, then the same verified suspended process was resumed once and exited 0;
  this is not a clean wrapper pass. The synthetic root/profile remain and Developer
  Mode was restored. Explorer, packaged GUI, RecoveryRoot hydration and production
  provider activation remain unaccepted. Earlier recovery discovery/cache tests are
  test-only evidence; unsupported UI operations remain gated without hiding a
  reachable agent.
- Linux encrypted offline access: the exact R37 package passed synthetic vault
  creation, encrypted pin, server outage, restart, explicit unlock and mounted
  byte comparison (R38c). No remembered secret was enabled by that test.
- Media: the exact R41c agent passed synthetic upload/readback, unchanged-file
  deduplication, ambiguous-response recovery, removal refusal and restart
  retention (R40); this is prior packaged-agent evidence, not an R51b rerun.
- Linux remembered unlock: exact packaged-agent testing with a private real
  Secret Service passed opt-out, explicit per-vault opt-in, cross-vault refusal,
  restart saved unlock, mounted bytes and lock/forget refusal (R42).
- Windows: the unsigned per-user NSIS package passed synthetic standard-user
  install, bounded process launch, upgrade and uninstall-preservation checks in
  a noninteractive session. This is not interactive Explorer acceptance.
- Windows provider: R46 passes 74 unit, eight native Cloud Files, native agent,
  28 provider/cache integration and 59 cache tests under an ordinary user.
  Read-through caching and exact registered-root lifecycle are verified.
  Callback readiness and exact reconnect namespace verification are fenced.
  Partial-setup and concurrent-startup fault injection passed. Interactive
  Explorer acceptance and production integration remain; activation stays disabled.
- Before release: finish blocked native gates, set consistent 0.7 version
  metadata, run exact-source/package checks for each platform, preserve rollback
  data, and document limits. Do not infer release readiness from host tests.

## Current delivery and backlog — 17 October 2026 JST

Current installed Linux package is R123, closed; it includes exact-root saved-edit disclosure and account-fenced local saved-edit export accepted in its isolated VM. Native ordinary-file policy
and warm agent-process offline restart passed, and the corrected archive passed
the exact-package VM installer gate. Windows R117a passed the DPAPI/cache
checks but failed the actual agent preflight at the public path validator.
R117b preserved that validator and passed control/cache tests, then failed
the SQLite long-path open in the agent diagnostic. R117d addresses lower SQLite path and filename-allocation ownership;
R117d passed host/Windows build and 33 native tests, including catalog/cache preflight. R121 actual duplicate-edit restart passed (see later acceptance); production activation remains disabled.

The following R46 installation paragraph is historical. Its archive: `3915a53df8aea877ebd087f1db5264aff013ee1f99d8b1ba93386b5c10a53b2a`.
Installed at `/home/phil/.local/share/raiun-desktop`, hashes verified and left
closed; R45 backup: `../outputs/install-backups/20261016T143332Z/`.
R47 native busy-dialog checks used the same executable hashes and left all
isolated test services closed. Source/native/package evidence and limitations
are recorded in [MVP acceptance](MVP-ACCEPTANCE.md). Windows production activation,
interactive UI/login/IME, live interoperability, broader uncertain recovery and
unfinished feature integration remain; this is not public-beta readiness.

The earlier bandwidth R3 and proxy-only package records below are historical
snapshots superseded by the integrated package. Their dated evidence remains
available at `/home/phil/Projects/raiun-desktop/outputs/vm-lab/async-bandwidth-20261015-r3/gates.md`
and `/home/phil/Projects/raiun-desktop/outputs/vm-lab/linux-proxy-20261015-r1/result.md`.

The Windows R5 application source archive is
`6eb77c1661ebb81a354f0f6047728dfd449c1d820c6b947d6e111652af78d7ca`; the
Git-absent packaging-helper overlay was separately hashed. The unsigned
per-user NSIS installers passed synthetic standard-user install, v0.1.0 to
v0.1.1 upgrade and uninstall checks. Account, cache, recovery and OpenCloud
sentinels retained their hashes; app files and Start Menu shortcut were
removed. The shell process launched from the user install path, but the VM run
was noninteractive and stopped that exact idle process after a bounded check.
It does not establish interactive GUI or Explorer behavior. The packages are
unsigned and unpublished. Evidence:
`/home/phil/Projects/raiun/outputs/windows-installer-acceptance-20261015-r5/result.md`.

Implemented Linux capabilities include account-scoped roots; persistent bounded
cache and offline availability policies; offline startup from a saved namespace;
explicit encrypted-folder and non-personal encrypted-Space unlock/browse/edit;
opt-in remembered unlock and lock/forget controls; durable offline encrypted
file operations; and bounded never-attempted folder-subtree rename with restart
recovery. These implementation claims do not imply native acceptance for every
flow or live cross-client interoperability.

| Remaining work | Current state / next evidence needed |
| --- | --- |
| Interrupted encrypted upload recovery | **Implemented and installed on Linux:** explicit user-triggered file-create retry and durable monotonic attempt fencing pass source tests and the installed package gate. Broader uncertain-operation recovery remains. |
| Remote encrypted directory deletion | **Not implemented by design:** ordinary recursive DAV DELETE cannot prove another client added no descendants. Keep this guard. Local cancellation of an empty never-attempted queued folder is supported. |
| Cross-vault copy and moves | **Linux single-file copy UI accepted:** R108 verified destination-root copy; R113b verified an existing nested destination on the exact R112 package, with plaintext readback, unchanged source, retired destination journal and normal Quit. Windows copy UI remains hidden. Moves remain unimplemented and require durable two-phase destination verification plus conditional source deletion; uncertain results must preserve both copies. |
| Ordinary offline restart and folder availability | **Open native gates:** R115 actual restart mounted an empty Personal after listing invalidation, while pinned and dirty content remained safe. R116 narrowly refreshes metadata after rejected uploads and preserves unrelated offline policy state; its exact-binary UI/restart test passed and corrected package R116a is installed. R118 recursive-folder pin, three nested offline reads after warm restart, dirty-child CloudOnly refusal and state-aware unpin with dirty-journal preservation passed on the same R116a binaries. R119c exact-root recovery disclosure is installed; R123 adds local export from the saved-write journal when a fresh listing is unavailable, with native acceptance still pending. Cold-login restoration remains open. |
| Native Linux acceptance | Exact R37 package passed synthetic encrypted vault creation, mounted write/read, complete pin, server outage, agent restart, explicit offline unlock and exact mounted-byte read in the isolated VM. A stale pin generation was safely refused in an earlier harness attempt; reconfirm current Ready generations after delays. Interactive authenticated server UI, display-manager login/logout, real IME and production Wayland behavior remain open. Earlier X11/tint2 and Plasma acceptance remains scoped to its dated package. |
| Live encrypted interoperability | **Validation outstanding:** controlled Desktop/Android/Web round trips on isolated test data. Synthetic codec fixtures are not a substitute. |
| Windows provider and durable identities | **Partial native acceptance; activation disabled:** R109 native reconnect and implicit OS reads passed. R110/R111 conditional cache-policy primitives passed focused Windows tests, but R120 adds an authenticated catalog-backed read-only six-field cache-status lookup with five focused portable tests and host gates (773 passed, 13 ignored). R122 adds a generation/account/root-fenced read-only worker RPC; R126 native evidence covers its four filters and all eight R120/R125 exact-binding backend filters, with preserved harness failures and no final aggregate wrapper status. R125 adds exact-binding Recent/CloudOnly retention; the later R127 publication fence has 784 host tests passing and R128 Windows validation remains pending. Mutation RPC/UI, verified AlwaysOffline download, Explorer, packaged GUI and RecoveryRoot hydration remain open. R111 duplicate-edit restart failed before registration. R114d localized a long-path protection/catalog failure; its wrapper false-pass record is invalid. R117a passed long-path DPAPI/cache checks but the agent rejected its public verbatim root. R117b passed control/cache checks but the agent failed SQLite long-path open. R117d keeps public DOS paths and uses owned SQLite filename metadata with extended aliases only at the locking lower open; host/Windows build and 33 native tests passed, including the actual catalog/cache preflight. R121 duplicate-edit restart passed with four retained snapshots and one conditional PUT; policy RPC/UI, Explorer and packaged GUI gates remain. |
| Selective sync and Space policy | **Implemented in source; native validation outstanding:** folder-pair exclusions, atomic policy publication, per-Space pause/resume and targeted Sync now passed the exact-source Linux gate. Native control acceptance, mounted-drive policy and per-Space disconnect remain. Preserve both copies, baselines and pending recovery. See [selective-sync contract](SELECTIVE-SYNC-DESIGN.md). |
| Media import | **Implemented; native engine acceptance passed (R40):** durable upload-only jobs, receipts, stable-file admission, account-bound UI, overlap/scheduler fixes and read-only recovery listings are implemented. Exact packaged-agent synthetic upload/readback, unchanged-file deduplication, ambiguous-response recovery, removal refusal and restart retention passed; R72 native media UI acceptance also passed. Richer date/name options and conflict/recovery controls remain. Preserve sources. See [media design](MEDIA-SYNC-DESIGN.md). |
| Diagnostics and compatibility | **Partly installed:** the redacted CLI summary and selected-profile export dialog are in the installed Linux package, and the exact-source Linux gate passed. Native export-flow acceptance and cross-platform filename/path validation remain. The report exports configuration summary and status counts, not runtime logs. |
| Network controls | **Proxy and bandwidth controls implemented and installed** in the integrated Linux `cc77c34b…e07fa6` package. The exact source/package gate and 8 FUSE + 5 agent live-FUSE CachyOS checks passed. Proxy changes apply on the next sign-in and credentials in proxy URLs are rejected. |
| Windows installer | **Built and lifecycle-tested:** the R5 unsigned per-user NSIS package passed standard-user install/upgrade/uninstall sentinel checks in a noninteractive VM session. Interactive setup, Explorer and GUI launch acceptance remain; do not describe the test as a release or signed package. |
| Release validation | **Blocked by native gates:** complete the remaining interactive Linux UI and Windows Explorer recovery paths and final default-feature gates; then run the exact final source/package checks, confirm 0.7 version metadata, and document rollback/support limits. Keep installed and source-only capabilities distinct. |
| macOS | Explicitly excluded from the current backlog-completion request. |

Vault administration, membership/sharing management and password rotation remain
outside the lightweight access/sync parity scope agreed with the owner. Do not
call the backlog complete while a required implementation, validation or
blocked acceptance gate remains outstanding.

## Historical research and implementation notes — 10 October 2026

The following is retained as the dated research/design record. Its statements
about Raiun implementation status are historical; use the current table above.

Research snapshot: 10 October 2026 (Asia/Tokyo). This compares Raiun Desktop's
repository state with OpenCloud Desktop 7.2 and ownCloud Desktop App 7.1 using
their official documentation and release notes. The ownCloud 7.1 app supports
ownCloud Infinite Scale (oCIS) only; ownCloud Classic Server users must remain
on the 6.x desktop-app line. The OpenCloud Linux sync-settings page cited below
is rolling documentation, so its details are identified as such. Feature
comparisons guide Raiun priorities; they are not commitments or claims of
platform parity.

Raiun's current verified platform is Linux. The agent and shell now contain
multi-account profile support in the integration branch, but the latest
implementation notes say multiple real accounts and the newly built installed
package still require acceptance. Windows and macOS filesystem adapters and
packages are not implemented. See [implementation status](IMPLEMENTATION.md)
and [MVP acceptance](MVP-ACCEPTANCE.md).

## Owner scope clarification — 10 October 2026

Encryption parity uses Raiun Android and OpenCloud Web as compatibility
references, while Desktop remains a lightweight sync and file-access client.
Prioritize explicit unlock/lock, encrypted folder and Space browsing, opening
files, mounted saving and ordinary create-folder/rename/move/delete operations,
plus safe folder sync and recovery. Vault administration, membership/sharing
management and password rotation are outside this requested parity pass.
Cross-vault moves must re-encrypt through the correct source/destination scopes;
a server-side ciphertext MOVE is valid only within the same verified vault.
Completed increments and remaining validation are tracked in IMPLEMENTATION.md.

## What the official desktop apps provide

OpenCloud Desktop 7.2 and ownCloud Desktop App 7.1 both document multiple
accounts, account-level management, and conflict handling. OpenCloud documents
separate local folders for accounts from different servers and separate
settings per account. ownCloud explicitly
rejects reusing a sync folder across accounts or sync connections. Raiun's
profile model follows the same isolation principle with one separate cloud root
per account; this does not mean cross-platform acceptance is complete.
[OpenCloud multiple accounts](https://docs.opencloud.eu/docs/user/desktop-client/common-functionality/multiple-accounts/),
[ownCloud multiple-account FAQ](https://doc.owncloud.com/desktop/7.1/faq.html)

| Area | Official desktop behavior | Raiun status and actionable gap |
| --- | --- | --- |
| Accounts and roots | OpenCloud 7.2 keeps each account in its own local folder. ownCloud 7.1 supports multiple accounts and disallows sharing the same sync folder between accounts/connections. | Profile-isolated roots, state, and scoped credentials are implemented in the agent integration. Complete Linux acceptance with two live accounts, account switching, per-account state/recovery, conflict paths, and restart. Keep canonical/ancestor-overlap rejection. Windows/macOS account UI and providers remain future work. |
| Windows files-on-demand | OpenCloud 7.2 integrates Windows VFS placeholders with Explorer; opening a placeholder downloads it, while pin/free-space controls distinguish durable offline content from online-only content. ownCloud documents VFS as Windows-only in the 7.1 app. [OpenCloud Windows VFS](https://docs.opencloud.eu/docs/user/desktop-client/windows/sync-settings-win/), [ownCloud VFS](https://doc.owncloud.com/desktop/7.1/vfs.html) | No Windows provider exists. Prioritize a separately reviewed Cloud Files adapter: placeholder enumeration, hydration, pin/unpin, cancellation, restart, and dirty-write recovery. Validate NTFS behavior and real Explorer workflows on Windows before describing support. |
| macOS and Linux sync scope | OpenCloud's macOS 7.2 docs describe downloaded local files and per-Space pause/resume, force sync, remove-connection while preserving local files, and choose-what-to-sync. The Linux sync-settings page documents similar controls but is rolling, not 7.2. [OpenCloud macOS settings](https://docs.opencloud.eu/docs/user/desktop-client/macos/sync-settings-mac/), [OpenCloud Linux settings (rolling)](https://docs.opencloud.eu/docs/next/user/desktop-client/linux/sync-settings-linux/) | Raiun exposes one mounted Personal/Spaces root, folder pairs, global pause/status, per-Space folder-pair pause/resume and targeted Sync now, plus pair-level selective exclusions. Per-Space disconnect and mounted-drive policy remain open product work; macOS needs a File Provider prototype and lifecycle/sandbox validation before roadmap promises. |
| Status and support | OpenCloud 7.2 documents common status states, logs, conflicts, filename compatibility rules, and Linux proxy/bandwidth settings. [Common functionality](https://docs.opencloud.eu/docs/user/desktop-client/common-functionality/), [OpenCloud Linux settings](https://docs.opencloud.eu/docs/user/desktop-client/linux/settings/), [OpenCloud filename rules](https://docs.opencloud.eu/docs/user/desktop-client/common-functionality/file-names/) | Raiun has actionable status, transfers, saved-copy recovery, explicit conflict choices, a redacted configuration summary, and advisory Windows filename/path warnings. A user-selected redacted log bundle and proxy/bandwidth controls remain open work; no general proxy or bandwidth setting is implemented today. |
| Conflicts | OpenCloud keeps the local conflicted copy and remote original for user comparison. ownCloud 7.1 release notes remove the capability to upload conflict files, so avoid treating that old behavior as a current baseline. [OpenCloud conflict handling](https://docs.opencloud.eu/docs/user/desktop-client/common-functionality/file-conflicts/), [ownCloud 7.1 release notes](https://doc.owncloud.com/desktop_release_notes.html) | Raiun requires an explicit Keep local/Keep cloud choice and preserves the displaced copy. Live Linux conflict choices have passed, but complete multi-account UI and installed-package acceptance. Preserve both versions on ambiguity. |

## Encryption: safe boundary and prerequisites

Raiun's ordinary protocol and provider paths retain their fail-closed encrypted
area guards. Explicit vault-bound folder pairs now use a separate verified
backend and dedicated create/unlock/lock UI. This includes encrypted names,
streaming content writes, conditional revisions, and the existing conflict
engine. Local synced files remain plaintext. The new Linux candidate adds
read-only mounted browsing for explicitly unlocked folder vaults; CachyOS synthetic VM checks
have passed; native/live-server acceptance remains pending. Whole encrypted Spaces and mounted encrypted writes remain
unavailable. See [encrypted sync](ENCRYPTED-SYNC.md) and
[implementation status](IMPLEMENTATION.md) for scope and validation.

OpenCloud Server 7.5.0 (released 25 August 2026) announced browser-side,
end-to-end encrypted vault folders and Spaces, with encrypted names and
rclone-crypt compatibility. The current OpenCloud rolling user guide says the
Desktop and Mobile Clients do not support that E2EE workflow and should not
access or modify encrypted folders; it warns that files written by those
clients are not end-to-end encrypted and may be unusable in the web client.
These statements describe different layers: the server release provides the
vault feature, while the desktop guide does not document a desktop unlock/write
workflow. Raiun must continue blocking vault access until it has an explicit,
tested interoperability implementation.
[OpenCloud 7.5.0 release notes](https://github.com/opencloud-eu/opencloud/releases),
[OpenCloud E2EE folder guide (rolling)](https://docs.opencloud.eu/docs/next/user/files-and-folders/e2ee-folders/)

OpenCloud's announcement says vaults interoperate with rclone crypt. That
identifies a format family, not enough configuration to safely decrypt any
particular vault. Rclone crypt encrypts file contents in authenticated 64 KiB
chunks and encrypts names segment-by-segment; key derivation uses scrypt and
may use a user-supplied second password/salt. Filename mode, directory-name
encryption, and filename encoding affect interpretation. Raiun now has pinned
Web/rclone synthetic fixtures and a streaming read/write implementation of the
Web v8 profile; see [interoperability scope](ENCRYPTION-INTEROP.md). This does not
support arbitrary rclone configurations or establish live encrypted-write
compatibility. Synthetic conditional-write and recovery checks complement the
codec fixtures; live deployment and native UX acceptance remain separate.
[rclone crypt format and options](https://rclone.org/crypt/)

The ownCloud Server 11 encryption manual describes a separate server-side
feature: the server encrypts/decrypts file contents, while names and directory
structure remain unencrypted; it does not protect against a compromised
server or administrator. This is not the OpenCloud client-side vault format,
and the cited ownCloud Classic Server version is distinct from the ownCloud
7.1 desktop app, which supports oCIS only. Raiun must not conflate these
formats or advertise one as interoperability for the other.
[ownCloud Server 11 encryption documentation](https://doc.owncloud.com/server/11.0/admin_manual/configuration/files/encryption/encryption_configuration.html),
[ownCloud Desktop 7.1 release notes](https://doc.owncloud.com/desktop_release_notes.html)

Encryption integration now includes explicit configuration binding, shared
account-scoped sessions, bounded password derivation, directory collision
checks, conditional ciphertext operations and creation readback. Keys remain
in memory only and account transitions reject new vault work. Remaining
roadmap work includes writable mounts and recovery, whole-Space browsing, password rotation,
key sharing, expiry policies and native acceptance. None is implied by the
folder-pair implementation.

## Prioritized work

| Priority | Work | Exit evidence |
| --- | --- | --- |
| P0 — now | Preserve existing fail-closed vault guards and their fixtures; maintain regression coverage for encrypted Space metadata, vault markers, ancestor checks, and ordinary read/write admission as integration evolves. | Tests show no encrypted content is served or uploaded through ordinary paths, with clear user-visible errors. Keep desktop acceptance docs aligned. |
| P1 — release gate | Finish Linux multi-account acceptance, including two real accounts, distinct roots and state, switching, recovery isolation, collision rejection, restart, and orderly all-account shutdown. | Repeatable installed-package report on a disposable test account/server setup; no account token or transfer state crosses profile boundaries. Existing synthetic smoke tests alone do not satisfy this gate. |
| P1 — next platform | Prototype and implement Windows Cloud Files support, prioritizing correct on-demand hydration, pin/free-space, cancellation, and dirty-write recovery. | Windows VM/device tests with Explorer save/rename patterns, offline placeholders, restart/unmount, and recovery verification. The native adapter receives separate review. |
| P2 — account scope | Per-Space folder-pair pause/resume, targeted Sync now, and pair-level selective exclusions are implemented in the current candidate; exact-source VM checks passed; native controls still need acceptance. Mounted-drive policy and per-Space disconnect remain future work. | Product decisions for local-data preservation and deletion policy, then Linux UX and reconciliation tests. |
| P2 — diagnostics and compatibility | A redacted local CLI diagnostics summary is implemented in source (version/platform and configuration counts only). Advisory Windows filename/path compatibility warnings are implemented without renaming or rejecting existing names. Log export and user-requested proxy/bandwidth controls remain future work. | Cross-platform fixtures and UI tests; any exported diagnostics must omit tokens, vault secrets, and file bodies. |
| P2 — macOS feasibility | Spike the per-account File Provider-domain architecture and agent communication. | Signed local prototype proves extension lifecycle, sandbox access, relaunch/recovery, and independent account domains before any support claim. |
| Integration gate — encryption | Validate the explicit encrypted folder-pair workflow in the native app; validate the new read-only folder-vault mount and revocation lifecycle, then design writable mount recovery. | Synthetic end-to-end checks plus installed acceptance proving account isolation, revocation, no ordinary-path bypass and preserved recovery. Mount support requires its own tests before enabling. |

## Sources and version scope

Sources were checked on 10 October 2026. Versioned OpenCloud desktop pages
refer to 7.2; the OpenCloud Linux sync-settings and E2EE user pages are rolling
(`next`) and may change. The OpenCloud 7.5.0 release notes are for the server,
not the desktop client. ownCloud desktop documentation refers to app 7.1;
ownCloud Server 11 encryption is a separate, older server product/version.

- OpenCloud Desktop 7.2: [supported platforms and common features](https://docs.opencloud.eu/docs/user/desktop-client/), [multiple accounts](https://docs.opencloud.eu/docs/user/desktop-client/common-functionality/multiple-accounts/), [Windows VFS](https://docs.opencloud.eu/docs/user/desktop-client/windows/sync-settings-win/), [macOS settings](https://docs.opencloud.eu/docs/user/desktop-client/macos/sync-settings-mac/), [Linux settings](https://docs.opencloud.eu/docs/user/desktop-client/linux/settings/), [conflicts](https://docs.opencloud.eu/docs/user/desktop-client/common-functionality/file-conflicts/), [filename rules](https://docs.opencloud.eu/docs/user/desktop-client/common-functionality/file-names/).
- OpenCloud rolling docs and server: [Linux sync settings](https://docs.opencloud.eu/docs/next/user/desktop-client/linux/sync-settings-linux/), [E2EE folders](https://docs.opencloud.eu/docs/next/user/files-and-folders/e2ee-folders/), [7.5.0 release notes](https://github.com/opencloud-eu/opencloud/releases).
- ownCloud Desktop App 7.1: [usage and accounts](https://doc.owncloud.com/desktop/7.1/using.html), [multiple-account FAQ](https://doc.owncloud.com/desktop/7.1/faq.html), [VFS](https://doc.owncloud.com/desktop/7.1/vfs.html), [release notes and supported server scope](https://doc.owncloud.com/desktop_release_notes.html).
- Format references: [rclone crypt](https://rclone.org/crypt/), [ownCloud Server 11 encryption](https://doc.owncloud.com/server/11.0/admin_manual/configuration/files/encryption/encryption_configuration.html).


## Next encrypted-browsing increment: whole project Spaces

The 10 October follow-up architecture review keeps this feature disabled until
its separate implementation and VM gate. Start with encrypted non-personal
Spaces; the fixed Personal projection needs its own design if the server marks
it encrypted.

- Preserve ordinary encrypted-Space guards. Do not expose encrypted roots as
  ordinary Space nodes: those call the ordinary list and writable path helpers.
  Keep display metadata separately and project an active, verified root route
  under the existing Spaces container as a generation-tagged vault node.
- Bind the route to the inspected DAV root resource ID, account, origin and
  Space ID. Space ID is not a substitute for root resource ID. Verify root
  directory identity through the vault backend before publishing the node.
- Extend the agent's three deliberate `/` exclusions (saved route configuration,
  unlock publication and readiness) only after provider coverage exists. Keep
  root-versus-folder overlap rejection within a Space.
- Retire the root inode and descendants on lock. Audit parent directory snapshots
  that contain the projected root: revocation must also prevent stale snapshot
  exposure, with parent-entry and inode invalidation. Re-unlock creates a fresh
  inode and never restores old handles.
- Gate with identity/token mismatch, ordinary-backend non-use, route overlap,
  mutation denial, held parent-directory reads, old root/file handles across
  lock/re-unlock, and fresh-lookup tests. Repeat isolated live FUSE tests in the
  CachyOS VM before packaging. Mounted writes remain a separate recovery design.


### Parent directory revocation prerequisite — source follow-up

Directory snapshots now track every vault route they contain, including vault
children beneath an ordinary parent. Publishing a snapshot and returning its
entries hold generation-checked leases through the reply. Revocation removes
those snapshots; a copied snapshot cannot regain access after re-unlock.
Routes are acquired in stable order, and an already-leased vault parent cannot
acquire a different child route. This prepares whole-Space projection without
enabling it. Regression coverage includes multiple routes, unrelated ordinary
snapshots, stale generations, and lock waiting for an in-flight reply.
This follow-up is included in the later account-setup-r2 candidate, but not the
earlier vault-browse-r2 archive or installed app. Its CachyOS VM gate
passed 242 workspace tests and all three live FUSE tests, including unconsumed
parent directory handles across lock/re-unlock.


The next root-route prerequisite now also has a registry regression: a whole-Space
root conflicts with a folder route in either registration order, distinct Spaces
remain independent, and a revoked root continues reserving its scope until the
registry is explicitly cleared. Workspace formatting, strict Clippy and tests
passed (244 total, including 26 FUSE tests; three live FUSE tests ignored).
This test-only follow-up changes no runtime behavior, enables no whole-Space
browsing, and does not alter the already verified account-setup-r2 package.

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

See [preserved native result](../../outputs/vm-lab/windows-dirty-duplicate-restart-20261017-r118/windows/R118-native-result-summary.txt)
and [source diagnosis](../../outputs/vm-lab/windows-dirty-duplicate-restart-20261017-r118/windows/R118-duplicate-failure-diagnosis.md).

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

See [parent native acceptance](../../outputs/vm-lab/windows-dirty-duplicate-restart-20261017-r121/parent-native-acceptance.json).

R122 source adds a worker-owned read-only cache-status RPC fenced by current
account generation, exact registered-root identity, active binding and scope
token. It exposes non-atomic last-observed metadata only. Linux host gates pass;
Windows compilation and four focused Windows-only tests are pending the R124
source snapshot. It adds no pin/download job, policy mutation or Windows UI.

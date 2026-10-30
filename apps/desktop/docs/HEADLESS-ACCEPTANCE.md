# Headless MVP acceptance

Sync remains disabled until the mount-only MVP has completed its practical
acceptance checks. Host tests and cross-compilation do not substitute for
filesystem, installed-process or startup evidence on the target platform.

## Verified baseline

The unpublished Windows candidate 6 was privately transferred through the owner's
OpenCloud instance. The Windows test chat verified the ZIP, its source manifest
and all bundled hashes. Its disconnected batch passed 14 unique selected cases
and nine batch checks, including synthetic app-token/current-user DPAPI
restore, configuration mismatch and logout. The native mount case was initially
ignored in that batch and subsequently executed separately.

With corrected runner r2, the separately opted-in native test passed both login
and fresh-process restart phases. Ordinary filesystem reads returned exact
Personal and Projects Space bytes. The synthetic server observed one GET for
each file and zero ETag mismatches. Its legacy unhandled-mutation counter was
zero, but that counter excluded the server's handled ordinary-file PUT route;
it is not comprehensive evidence that no write was attempted. The next fixture
uses a global pre-handler mutation counter. Safe unmount, refusal of late
automatic remount, normal shutdown, saved-session restoration and configured
automount passed. The task-owned root, registration, state and logs remain
retained and disconnected. This is a Windows-agent-reported result; the exact raw
Windows receipt/log mirror is tracked separately in project outputs.

The first native attempt failed before mounting because PowerShell 7.6 retained
empty environment entries when passed `$null`. The runner now actually removes
unset routing variables and preserves the caller's original presence and values.
All original mount admission and result checks remain. A harmless launcher
regression passed locally with inherited absent, empty and nonempty variables,
and separately on Windows. The original failed evidence remains preserved.

Linux candidate 4 passed the actual synthetic Ubuntu 24.04 VM fixture: 13
checks cover default private-state creation under umask 0002, ordinary kernel
FUSE reads/writes, one conditional remote PUT with independent readback, busy
unmount refusal while a file is open, graceful unmount, saved-session restart
and automount. Five production startup checks also passed. A separate actual
reboot produced a nonce-bound serial receipt before the first post-reboot SSH
connection: the normal user service had mounted and read three exact synthetic
files with no interactive login sessions. The observer did not start the user
manager. Normal disable detached the mount and preserved saved credentials.
This accepts the synthetic Ubuntu deployment, not a real server or IdP.

Windows candidate 7 passed direct installed production-CLI login and restart,
named-pipe transport, stdin token completion, ordinary Personal/Spaces reads,
saved-session restore and safe shutdown. Its global server mutation count was
zero for these read phases. The optional logon phase failed before registration
in the independent task-observation helper; its cause is not established. A
separate product startup-status check proved that Windows PowerShell's
Restricted policy blocked the generated script. The next candidate uses native
Task Scheduler APIs without changing execution policy.

Candidate 7's first ordinary-write case failed after OS write/flush/close:
recovery-store inspection returned ProtectionFailed before any remote PUT. The
journal had rewritten an admitted session root's inheritable ACL into a policy
rejected by later admission. Candidate 8 preserves and verifies that strict root
policy. Its native regressions and all three ordinary Space write scenarios
passed: one conditional PUT with two exact readbacks and native/journal local
completion; a 403 refusal retaining dirty bytes and protected journal without
marking clean; and transport loss before dispatch with zero PUTs, retaining the
same evidence. Each disconnected and stopped normally with sync disabled.

Candidate 8's explicit recovery fixture also passed: pending status after 403,
stale account/root rejection before remote I/O, wrong local path retaining the
record, and exact-path native plus journal completion with one successful PUT
and no replay. This uses the broker request path, not installed CLI transport
for `edits`, a daemon restart or a different provider token generation. Personal
writes and busy/drain unmount acceptance remain separate.

The corrected disconnected runner passed 21 unique native cases and 11 batch
checks with four intentional native fixture ignores. Its original log filename
used `startup::`, which NTFS rejected; only diagnostic filenames are now
sanitized. Original failures and package bytes remain retained.

Candidate 8 repeated direct installed CLI login/read/restart/safe stop, but the
full fixture still failed optional logon acceptance before registration. The
fixed observation identified `Get-ExecutionPolicy` telemetry failing with
HRESULT 0x80131501. Separate installed native startup status succeeded and
confirmed the task absent. The query's root cause remains undetermined. The
next fixture retains this query failure as bounded optional telemetry while
keeping every independent task binding, runtime and cleanup check mandatory;
no execution-policy change or bypass is used.

Candidate 9 passed two same-user task registration/manual-run, saved-session
automount and normal disable rounds. These did not exercise an actual logon
trigger or the noninteractive boot session. Candidate 11 passed Personal writes
and retained an open writer's dirty bytes, root and registration through normal
disconnect, explicit remount and a separate-process DPAPI restore. Refused
writes remained dirty. Disconnect is not an upload-completion barrier.

Candidate 13 passed the focused synthetic Personal streamed-file case with
17 MiB + 7 bytes: one conditional PUT, one independent full conditioned GET,
native in-sync completion and durable v2 acknowledgement. A separate-process
restart retained the same file identity, record, commitment, generation and
digest. Normal unmount/stop and retained state passed; all fixture processes
exited. Its original PowerShell runner then failed during reporting because
`$case` shadowed the validated `$Case` parameter. Separate read-only validation
accepted the original native receipts without repeating the test. The reporting
loop now uses `$caseResult`; the original error remains preserved. The same
verified binary with that corrected runner subsequently passed the Space save
and both streamed 403 cases on fresh roots. Refused writes made one attempt,
left the original remote content unchanged and retained dirty local bytes with
no native in-sync state or v2 acknowledgement through restart, without replay.
Together these are four scoped cases and eight save/restart roles across
separate focused runs; each reports `full_matrix_passed=false`. Production
streamed activation, namespace operations and full MVP acceptance do not follow
from these diagnostic results.

Further native Ubuntu VM checks on frozen Linux candidate 4 cover Personal and
Spaces large-file create/readback, ordinary directory/file operations, editor
replacement saves, populated-directory moves and saved-session readback.
Eleven scoped positive gates were joined across retained runs. Earlier aggregate
harness timeouts remain failures; the final bounded run passed and the VM shut
down normally. These synthetic results do not establish real-server race
semantics, cross-Space copy/move or crash-atomic remote replacement.

## Remaining checks

| Requirement | Evidence needed beyond the baseline |
| --- | --- |
| Installed Windows CLI | Candidate 7 passed the direct synthetic installed-CLI login/read/restart/stop phases. Preserve this evidence and rerun affected phases after startup/recovery changes. |
| Ordinary mounted edits | Personal and Space bounded edits passed; candidate 13 adds streamed success and 403 save/restart cases in both. Production activation, full Windows create/rename/move/delete/replacement, installed-CLI `edits` transport and GUI parity remain separate gates. Folder-pair sync stays disabled. |
| Failure behavior | Candidate 8 passed synthetic 403 refusal and unavailable transport before dispatch; candidate 11 passed open-writer dirty retention through disconnect/remount/restart. Candidate 13 adds streamed 403 dirty retention/no replay through restart. Different-generation recovery remains separate. Never force termination or treat a failed/skipped case as a pass. |
| Browser login | Verify the actual server/IdP browser flow and documented remote callback forwarding. A printed authorization URL or synthetic callback test alone is insufficient. |
| Real server | Verify authentication, accessible Personal/Space listings and file I/O against a scoped test account. Synthetic loopback results do not establish server deployment acceptance. |
| Windows logon startup | Candidate 9 passed exact same-user task registration/manual Run, saved-session mount/read and normal disable. Actual logon-trigger delivery remains unverified. |
| Windows boot startup | Verify current-user password-task DPAPI, networking and Cloud Files in the noninteractive boot session before interactive sign-in. Registration or interactive restart does not establish this. |
| Linux FUSE and boot | Candidate 4 passed synthetic Ubuntu VM mount I/O, graceful shutdown and actual before-login reboot acceptance. Other distributions and real-server deployment remain separate. |

Windows Server Core and coexistence with an actively mounted GUI provider remain explicit
platform/deployment limitations unless separately tested. Candidate 7 kept an idle, unmounted Desktop instance unchanged; that is limited idle coexistence evidence. Do not turn an
interactive laptop result into a general server-platform support claim.

## Evidence and test coordination

Run native fixtures only on the owner's explicitly authorized disposable Windows
laptop, after coordinating the provider slot with the Desktop test work. Use
new task-owned directories and retain both failed and successful receipts.
Additional candidates and runners use private OpenCloud hosting; verify exact
hashes before execution and retain normal endpoint security protections.

Google Drive classified the older candidate 4 as malware or spam before its
Windows download. The cause remains unresolved. The owner subsequently selected
private OpenCloud hosting. A clean local Defender scan of candidate 6 and a
bounded source/build review do not explain or clear the older classification.

Use [HEADLESS-MOUNT-TEST.md](HEADLESS-MOUNT-TEST.md) for the broker fixture and
[HEADLESS-STARTUP.md](HEADLESS-STARTUP.md) for startup prerequisites. Current
machine-specific reports, hashes and resumable checkpoints belong in project
`outputs/`, outside Git; do not store credentials in documentation or logs.

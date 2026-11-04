# Opt-in installed Windows CLI fixture

This fixture uses the package's checksum-verified installer to create a new
installation prefix. It runs the installed production CLI and agent, using their
normal named pipe, app-token stdin and current-user DPAPI paths. A separate
diagnostic executable supplies only a synthetic loopback server and observations;
it does not replace production provider activation or authentication checks.

Run only on the explicitly authorized disposable Windows test machine, after
coordinating a provider slot with Desktop testing. In PowerShell 7, invoke the
hash-verified runner from a verified candidate bundle:

```powershell
.\test-headless-cli-windows.ps1 `
  -PackageZip 'C:\ABS\raiun-headless-windows-x86_64-test.zip' `
  -ExpectedSha256 'EXACT_ZIP_SHA256_FROM_HANDOFF' `
  -RunInstalledCliNativeReadFixture `
  -OutputParent 'C:\ABS\existing-NTFS-evidence-parent'
```

The runner verifies the archive and each manifest member, installs into a fresh
prefix, and verifies installed executable hashes before running the exact ignored
test. It removes inherited routing environment entries in the child process;
assigning `$null` is not used to mean absence. It does not modify PATH, replace
the GUI installation or use real credentials. The fixed synthetic credential is
sent only through stdin, never a command-line argument.

The first production process must report completed app-token authentication,
expose Personal and Projects through the normal configured mount, list both
drives through the CLI and return exact file bytes through ordinary OS reads.
After CLI unmount, delayed checks must remain unmounted. CLI stop must allow the
foreground process to exit normally. A fresh process must restore the saved
session and automount without another login, then repeat reads and safe shutdown.
Folder-pair sync stays disabled throughout.

The install, root, native registration, protected state, configuration and all
evidence remain retained, including on failure. A timeout reports a PID and does
not force termination. Follow the retained configuration/state with the normal
CLI unmount/stop commands for investigation; do not unregister or delete a root
whose callbacks or dirty data may still be active.

To additionally exercise actual same-user Task Scheduler registration and manual
start, add `-RunLogonStartup` only when the handoff authorizes that phase. After
the two direct phases have stopped normally, the fixture registers the exact
state-bound `InteractiveToken` logon task, checks its SID, action, arguments,
working directory and source marker, waits for the running task and restored
mount, and performs ordinary reads. Normal startup disable must stop the agent
and remove that exact task. Two successful rounds are required. No Windows
password, elevation, boot trigger or reboot is used.

`LOGON-STARTUP.json` records task observations, optional script-policy telemetry
and cleanup results separately. `TASK-OBSERVATIONS.jsonl` retains bounded fixed
stages, numeric HRESULTs and child exit information without raw error text or
task XML. Policy telemetry is either a known policy with state `available` and
no HRESULT, or a null policy with state `unavailable` and a failed signed HRESULT.
A failed policy query does not bypass any SID, source, action, trigger, settings,
runtime or normal-cleanup check. It never overrides or changes execution policy.

Candidate 8's observer failed before registration while querying execution
policy (HRESULT `-2146233087`); the query's underlying failure remains
undetermined. That observation is separate from the earlier generated `-File`
helper's confirmed Restricted-policy refusal. Production startup now uses the
native Task Scheduler adapter. Neither record establishes a successful logon
registration or boot acceptance.

On failure or timeout, the runner records that a
startup change is possible rather than falsely reporting no task changes. An
unconfirmed or foreign task is retained; it is never force-stopped. A normal
running-task result such as `0x41301` is not treated as failure or as proof that
the drive works. Actual connected/mounted state and file reads are required.

Direct phases alone do not register startup. Manual task start does not establish
delivery of an actual logon trigger or boot-before-login acceptance.

Results here are synthetic account and loopback-server acceptance. They do not
prove live server/browser/IdP integration, ordinary writes, Windows boot-session
DPAPI/Cloud Files, Server Core, or coexistence with an active GUI provider. See
[HEADLESS-ACCEPTANCE.md](HEADLESS-ACCEPTANCE.md) for remaining gates.

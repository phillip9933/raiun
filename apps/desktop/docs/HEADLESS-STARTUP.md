# Headless CLI startup

The CLI can register its isolated foreground drive process for system boot or
user logon. Install the headless CLI and agent together in a permanent directory,
create and validate its configuration, and establish remembered login before
registering startup. Safely stop any foreground agent using the same state before
enabling startup, so the service can claim the isolated instance. The config controls `auto_mount`, `remember_login`, the
account/profile, server and mount path. Startup does not create credentials or
convert an interactive Desktop account into a headless account.

After establishing remembered login in a foreground agent, stop that isolated
agent with `drive stop` before enabling startup. Then let the service/task own
the process. A foreground agent and a startup agent cannot run concurrently
against the same state directory. Keep the same config and state arguments for
stop and startup commands; do not stop the separate GUI agent.

Use absolute paths for the installed CLI, configuration and separate state. The
service/task runs this same command, so it uses the configuration's normal
restoration, reconnection and automount policy:

```text
raiun --config /ABS/config.json drive --state-dir /ABS/state serve
```

Registration and immediate start happen only through `startup enable`. Installing
or building a bundle and `--dry-run` do not activate anything. The Desktop GUI
installation, its autostart entry and its state stay separate.

## Linux

Run as the account that owns the headless state, without `sudo`:

```sh
/path/to/raiun --config /ABS/config.json drive --state-dir /ABS/state startup enable --dry-run
/path/to/raiun --config /ABS/config.json drive --state-dir /ABS/state startup enable
/path/to/raiun --config /ABS/config.json drive --state-dir /ABS/state startup status
/path/to/raiun --config /ABS/config.json drive --state-dir /ABS/state startup disable
```

`boot` is the default mode. Enable queries `loginctl show-user <effective-uid>
--property=Linger --value` for the numeric effective OS account. A successful,
exact `yes` avoids an unnecessary policy authorization, including from a
noninteractive user service. Otherwise enable explicitly runs `loginctl
enable-linger <effective-uid>` and requires success before writing a unit or
enabling the service. Failed or ambiguous queries do not count as confirmation.
The UID comes from the OS, never `USER`, `LOGNAME` or a login session. Status also
queries that explicit UID. If local policy denies enabling lingering, ask an
administrator to run `sudo loginctl enable-linger <effective-uid>`, then repeat
enable as the original account. A user manager must still be reachable from the
registering context; this does not start or impersonate another account's manager.
After admission, enable writes one user service and runs
`systemctl --user enable --now`. The systemd documentation states that lingering starts a user manager at boot and
keeps it alive after logout. [loginctl](https://www.freedesktop.org/software/systemd/man/latest/loginctl.html)

The executable, config, state and mount path must be available before login for
boot startup; a home directory unlocked only at interactive login cannot meet
that condition. The unit lives under `$XDG_CONFIG_HOME/systemd/user`, or
`$HOME/.config/systemd/user`, and has a state-specific `raiun-headless-*.service`
name. It runs the absolute CLI directly, with quoted config/state arguments,
private creation permissions and on-failure restart. Service stops send SIGTERM
through the agent's normal guarded shutdown handler. There is no second broker
stop hook after a clean agent exit. The unit retains its 330-second shutdown
window and disables the final forced SIGKILL. A refused or timed-out stop is not
successful shutdown; inspect the retained process/mount, release busy handles
and request a normal stop again. Existing units with different content are
preserved. Executable command
arguments escape systemd's own `$` and `%` expansion; they are not shell code.
[systemd.service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)

Earlier test builds generated a different stop hook. Their units are also
preserved when they differ from the current definition. Disable an old instance
with its matching earlier CLI, then inspect the exact disabled unit before
replacing it and enabling the current definition. No automatic migration
overwrites an old or edited unit, and configuration, credentials and local
files must be retained.

`startup enable --mode logon` enables the same user service without changing
lingering. If lingering was already enabled for other services, this service may
also start at boot. Disable stops/disables the exact service and retains its
unit, config, saved credentials and local files. It does not disable lingering,
which may support unrelated services. Check `journalctl --user -u UNIT` and the
normal `drive status` if restoration or a mount fails. Network availability is
handled by the configured reconnect loop; unit registration is not a network or
mount acceptance test.

## Windows

Use the installed `raiun.exe` and absolute config/state paths, for example:

```powershell
& 'C:\RaiunCli\bin\raiun.exe' --config 'C:\RaiunCli\config.json' drive --state-dir 'C:\RaiunCli\state' startup enable --dry-run
& 'C:\RaiunCli\bin\raiun.exe' --config 'C:\RaiunCli\config.json' drive --state-dir 'C:\RaiunCli\state' startup enable
& 'C:\RaiunCli\bin\raiun.exe' --config 'C:\RaiunCli\config.json' drive --state-dir 'C:\RaiunCli\state' startup status
& 'C:\RaiunCli\bin\raiun.exe' --config 'C:\RaiunCli\config.json' drive --state-dir 'C:\RaiunCli\state' startup disable
```

Boot mode uses a Task Scheduler boot trigger and the same Windows user's
password logon with least-privilege execution. Registration requires a terminal
elevated under that same account: Microsoft restricts boot-trigger registration
to Administrators. The native CLI does not elevate itself or switch to LocalSystem.
[BootTrigger](https://learn.microsoft.com/en-us/windows/win32/taskschd/boottrigger)

The CLI uses the native local Task Scheduler API; it no longer generates or
runs a PowerShell helper. `startup enable/disable/status --dry-run` prints a pure
JSON plan before any COM connection, account lookup, credential prompt or
startup-state change. The plan keeps path arguments as data, shows the exact
foreground action, and identifies password input without including a password.

For a **new boot task**, the CLI checks elevation under the current Windows
account before requesting its Windows password through the existing hidden
console prompt. Enter the account password, not a Windows Hello PIN or OpenCloud
app token. No alternate username or password flag, stdin-password mode, file,
log or environment credential input is supported. A matching existing owned
boot task reuses Task Scheduler's stored credential without prompting again;
change startup mode only after explicitly disabling/removing the previous task.

The Rust password buffer uses `Zeroizing`, and the native adapter wipes its
owned UTF-16/BSTR copies after registration. COM/RPC and Task Scheduler copies
remain outside that guarantee; Task Scheduler retains the credential for
password logon. Registration failures report bounded stages/numeric HRESULTs,
not arbitrary COM description text. Changing the Windows account password can
require explicit task removal and registration again. A policy allowing
**Log on as a batch job** is required for password tasks.
[Task security contexts](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)

`startup enable --mode logon` instead uses a current-user logon trigger and
`InteractiveToken`, with no stored Windows password and no boot-before-login
claim. S4U is deliberately not used: Microsoft documents its lack of access to
network and encrypted files. Password tasks take the credential at registration;
interactive-token tasks require an existing interactive session.
[Principal.LogonType](https://learn.microsoft.com/en-us/windows/win32/taskschd/principal-logontype)

The state-specific task has a 30-second boot delay, unlimited normal runtime,
one active instance and bounded on-failure restart. Enable also requests an
immediate task run. The native adapter verifies the current SID, Raiun source
marker, exact executable/config/state arguments, working directory, action,
trigger, logon type and safety settings before inspecting or changing an
existing entry. It preserves a foreign or differently bound task. XML and
Windows command-line quoting are separate adapter/CLI responsibilities.

`startup status` now prints JSON from the native API: task presence, enabled
state, numeric Task Scheduler state/result, active-instance count, actual mode
and current-account SID. `agent_status_included=false` makes clear that this is
a task observation; use `drive status --json` separately to assess the account,
mount and retained-edit state. Running tasks can legitimately have numeric
`last_task_result=0x41301`; it is not a completed-execution receipt. The task's
own state is returned even if the command's default requested mode is boot.

The historical `startup.ps1` source can remain for prior evidence, but the CLI
has no runtime dependency on it, PowerShell, a generated helper file or machine
PowerShell execution policy. No execution-policy override is used or needed.

Disable first closes task startup/restart admission, requests the normal
isolated CLI stop, waits up to 330 seconds for the exact disabled task to become
inactive, and then rechecks its binding/inactivity before removal. The normal
CLI stop process has its own bounded 330-second observation window.
It never calls forced task/process termination. If shutdown cannot be confirmed,
including when the agent may already be offline, the task remains **disabled**
and its registration and all state remain for inspection. Inspect `drive status`
and Task Scheduler before another explicit action. A timed-out normal-stop PID
is reported and retained; failure does not silently remove the task.

### Native startup and boot acceptance still required

Portable plan/binding tests and Windows crosschecking do not execute the native
startup API on the target machine. This native integration requires separate
logon/start/stop/status and boot registration acceptance.

Registering and launching the task does not prove that current-user DPAPI and
the Cloud Files provider work in the noninteractive boot session on the target
Windows installation. That Session 0/current-user acceptance is pending; this
candidate does not promise either success or a blanket lack of platform support.
The explicit logon mode remains available when an interactive-session startup
is desired.

Before treating boot startup as accepted, reboot the target Windows test machine
without signing in, inspect the task result and agent state from an authorized
session, and verify the configured Personal/Spaces drive, file hydration, safe
unmount and recovery. A synthetic task registration check, source cross-check,
or later interactive sign-in alone does not establish those results.

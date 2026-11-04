# Opt-in Windows headless native read fixture

This fixture is prepared for the explicitly authorized disposable Windows test
laptop. It registers a real task-owned Cloud Files root; it must not run as part
of normal tests or on an unrelated machine. The Rust test has `#[ignore]`, uses
only its per-instance test activation field, and adds no production activation
flag. The runner requires an explicit native opt-in and the exact candidate test
executable SHA256 from the authorized candidate manifest.

From the hash-verified candidate bundle, run:

```powershell
.\test-headless-mount-windows.ps1 -AgentTestExecutable .\tests\agent-tests.exe -ExpectedSha256 'EXACT_AGENT_TEST_EXE_SHA256_FROM_MANIFEST' -RunNativeReadFixture
```

Use a current-user, interactive PowerShell terminal on the disposable Windows
machine. A new ordinary directory on a fixed local NTFS volume is required;
the default evidence parent is `%TEMP%`. The runner does not install anything,
change LocalAppData routing, modify the GUI installation, use a real account,
enable startup, change firewall/OS settings, force-stop a process, or recursively
delete a root. The headless child receives an admitted private state directory
under its unique fixture root; its DPAPI/cache/recovery writes remain there.

The runner removes inherited phase/context/config/state environment entries
before launching the supervisor, then restores the caller's original presence
and values. Setting an entry to `$null` is insufficient on recent PowerShell:
it can leave a present empty string, which the strict Rust configuration loader
correctly rejects. Launcher changes can be checked without mounting by running
`pwsh -NoProfile -File scripts/test-headless-mount-runner.ps1` from the source
checkout. This regression checks actual child inheritance and parent restoration;
it does not execute the native fixture.

The parent test holds the established synthetic loopback Personal/Projects
server and launches two fresh headless broker processes against the same exact
state/root. It does not launch the production CLI or named-pipe daemon, so this
is broker-to-provider acceptance rather than installed CLI transport acceptance.

1. The first child performs app-token login using a fixed synthetic credential,
   verifies Graph identity/drive and DAV metadata, then handles the ordinary
   configured automount request through `WindowsProfiles`. A separate normal
   PowerShell process enumerates the native namespace and reads the Personal
   and Projects `native-read.bin` files. Their exact bytes must match, and the
   synthetic server must observe both file GET paths with no ETag mismatch or
   remote mutation.
2. The first child explicitly unmounts, confirms its root metadata remains,
   rejects a queued stale automatic mount, checks the normal refresh tick cannot
   reconnect it, then performs normal broker shutdown.
3. The second child restores the exact synthetic DPAPI session/root, verifies
   the same server again and uses the regular refresh/automount loop without a
   new login or explicit mount request. It repeats ordinary OS reads and safe
   unmount. Restart may serve already hydrated/cache bytes; its receipt does not
   imply a second remote hydration occurred.

There is no explicit `CfHydratePlaceholder` fallback. If ordinary file access
fails, the fixture fails and retains its logs rather than upgrading another
hydration mechanism into an ordinary-read success claim.

The task-owned registration, root, protected state and logs are retained on
success as well as failure. Successful unmount/shutdown leaves the registration
disconnected. This initial runner deliberately does not unregister or delete
it. Do not use arbitrary cleanup tools, forced recursive deletion, or reparse
point manipulation; any later cleanup must verify this exact fixture's pinned
root identity and use the native safe unregister path after safe disconnect.

`RESULTS.json` records per-phase completion, remote read/mutation counters and
scope exclusions. `stages.log` contains fixed lifecycle markers. Each child and
ordinary read process has separate logs. Passwords/tokens and raw authorization
headers are not logged. The synthetic credential is test-only and config files
contain no token.

A timeout preserves the process and prints its PID/evidence directory. It does
not force termination while a provider may own callbacks. Inspect the stage
record and perform safe disconnect investigation before disposing of the
machine or attempting cleanup. A timeout, missing result receipt, skipped test,
or failure does not count as acceptance.

No result from this test establishes real-server authentication, remote writes,
folder sync, startup/service registration, boot Session 0, Server Core, physical
Windows reboot acceptance, or coexistence with an installed GUI provider.
Preparation, cross-compilation and parser checks on Linux do not establish that
this native fixture has run successfully on Windows.

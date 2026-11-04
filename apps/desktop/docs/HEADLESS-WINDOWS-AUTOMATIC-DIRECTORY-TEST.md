# Automatic ordinary directory diagnostic

This is an inert, test-only C16 candidate fixture. Production automatic directory
publication remains disabled. Compiling the fixture or passing its host contract
tests does not establish native discovery, conversion, or real OpenCloud 9
semantics. Preserve the failed C14 observer result and separately scoped explicit
native-directory results; they are not automatic producer acceptance.

Use the separately supplied, exact-hash Windows **agent test executable** only on
the explicitly authorized disposable Windows machine. Start with one selector:

```powershell
.\scripts\test-headless-directory-windows.ps1 `
  -AgentTestExecutable C:\owned\raiun-agent-tests.exe `
  -ExpectedSha256 <exact candidate SHA256> `
  -RunNativeDirectoryFixture -Case personal-success
```

The runner creates a fresh GUID evidence directory on fixed local NTFS. Its
supervisor serves a strict synthetic loopback DAV contract; a child opens the
actual headless broker with isolated DPAPI state, submits the fixed synthetic
app-token request, mounts its configured Cloud Files root and enables only that
manager's private diagnostic producer flag. A separate OS child enumerates the
namespace with entry-error checks and calls `create_dir`. The test never calls
native prepare or reconciliation to perform creation. The dedicated provider
owner thread discovers candidates and runs the existing typed producer.

Each selector is independent. Stop after the first failure and preserve all
receipts before trying another:

| Selector | Required evidence |
| --- | --- |
| `personal-success` | One Personal OS mkdir, one MKCOL, authenticated LocalCompleted, same native FileID, Cloud Files identity, no IN_SYNC, retained child bytes. |
| `space-success` | Same evidence through `Spaces\Projects` in the same configured root. Missing Projects or any enumeration error fails before OS mutation. |
| `personal-nested` | Parent and nested directory both created before the first producer tick. Two ordered MKCOLs and two exact completions; a plain parent is never traversed as managed authority. |
| `personal-bootstrap` | OS directory exists before any producer tick/observer attachment, then bounded bootstrap scan publishes it. |
| `personal-losthint` | At least one actual observed hint deliberately discarded, continuity remains unknown, bounded rescan still completes the same candidate. |
| `personal-lostresponse` | Server creates once and closes before its MKCOL response. Durable Submitted/Uncertain remains plain, without LocalCompleted or replay across later scans and an independent process restart. |

The contract authenticates every mutation through the existing app-token gate,
accepts only the two exact synthetic DAV roots and planned directory paths,
returns stable IDs and ETags, independently lists/stat-checks created entries,
refuses collisions and other mutation verbs, and counts every mutation. This
models a deliberately narrow synthetic contract, not an audit or proof of real
OC9 collision/race behavior. No real account, mail, public sharing or server
configuration is used.

Each runtime normally unmounts and stops its broker. Registrations, directories,
child bytes, private state and logs remain; nothing is unregistered or deleted.
A registered-root pin and separate OS child verify registration and retained
child bytes again after normal stop.
A 180-second child observation cap or 60-second cleanup observation cap permanently
fails that run but keeps waiting for natural completion. Any child wait error
also remains a permanent acceptance failure. The fixture retains the exact
server/broker/child owner. The outer runner's timeout reports the surviving PID
and does not terminate it. No process kill, forced unmount, service/startup change
or cleanup of earlier fixture data is performed. Inspect `*.pending.json`, child
PIDs and retained logs when an operation remains pending. A later natural exit
does not convert a timed-out run into acceptance.

The root `RESULTS.json`, per-runtime `save.RESULTS.json` (plus
`restart.RESULTS.json` for the lost-response selector), process receipts and runner
hash checks are required. A focused success applies only to its exact selector,
source and candidate executable. The fixture must not be described as a full
namespace implementation: automatic DELETE, MOVE and replacement are not wired.

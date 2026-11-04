# Opt-in Windows saved-edit recovery acceptance

This diagnostic runs the frozen ignored native test
`agent_windows::windows_profiles::windows_headless_edits_native_test::ordinary_403_recovery_requires_current_scope_and_exact_local_file`.
Use it only on the owner's explicitly authorized disposable Windows laptop. It
registers one new Cloud Files root and uses a fixed synthetic loopback app-token
account, ordinary OS writes and current-user DPAPI recovery metadata. Folder sync
stays disabled. It changes no installed application, real account or startup task.

Run the packaged runner with the **agent test executable** SHA256 from the exact
candidate handoff. The package archive, production agent and test executable have
different hashes.

```powershell
.\test-headless-edits-windows.ps1 `
  -AgentTestExecutable .\tests\agent-tests.exe `
  -ExpectedSha256 'EXACT_AGENT_TEST_EXE_SHA256_FROM_HANDOFF' `
  -RunNativeEditsFixture `
  -OutputParent 'C:\ABS\existing-NTFS-evidence-parent'
```

`AgentTestExecutable`, `ExpectedSha256` and the explicit `RunNativeEditsFixture`
switch are required. `OutputParent` defaults to the process's `TEMP` directory;
it must already exist on a fixed local NTFS volume. Paths and their existing
ancestors must be ordinary files/directories without reparse points. The runner
creates a fresh `raiun-headless-edits-<GUID>` directory and writes exactly
`raiun-headless-edits-native-v1` followed by a newline to `OWNER.txt`. Never reuse
an earlier fixture directory or hand-create a marker over existing data.

`TimeoutSeconds` defaults to 420 and accepts 60–1800. This bounds the outer
supervisor wait; the fixture separately bounds its runtime child to 240 seconds
and ordinary OS I/O child to 45 seconds. Choosing a shorter outer timeout can
return before the fixture finishes normal disconnect. A timeout never kills or
joins a stalled child. Preserve the recorded supervisor and child PIDs, root,
state and logs for investigation; a timed-out process can still be running.

The runner temporarily sets `RAIUN_HEADLESS_EDITS_FIXTURE_DIR` and actually removes
`RAIUN_HEADLESS_EDITS_FIXTURE_CHILD`, `RAIUN_HEADLESS_CONTEXT`,
`RAIUN_HEADLESS_CONFIG` and `RAIUN_STATE_DIR` from the supervisor environment. It
restores each original process variable's presence and value immediately after
launch, including launch failure. The fixture itself supplies its fresh isolated
state/config and role variables to its runtime and OS children. An empty CHILD
value is not an absent CHILD key and is deliberately refused by the fixture.

## Required acceptance

The native assertions and exact receipts must establish all of these:

1. An ordinary OS handle hydrates `Spaces/Projects/RecoveryRoot/document.bin`,
   changes one synthetic byte, flushes and closes. The initial conditional PUT
   receives an explicit synthetic HTTP 403. Status exposes one pending ordinary
   edit with `not_completed`, and recovery listing contains its protected record.
2. Explicit retry with a stale agent generation or wrong recovery-scope token is
   refused before any remote HTTP request. A test-only global request counter
   verifies this, independently of the mutation counter.
3. After the synthetic server resumes accepting PUT, retry with the wrong local
   components can verify the remote edit but cannot complete or retire the local
   record. The protected record remains listed.
4. Retry of that same immutable record with the exact local components obtains
   fresh remote verification and succeeds through guarded native acknowledgement
   and durable journal completion. Status becomes known with zero pending edits;
   the recovery list becomes empty. Remote verification alone is insufficient.
5. Exactly two PUT attempts occur: one refused and one successfully applied. The
   later completion retry does not upload again. The global pre-handler mutation
   count is also two, and folder-worker generation remains zero.
6. The runtime reports successful normal unmount and stop. Root, registration,
   edited file and private state are retained; no unregister, deletion or forced
   termination is part of this fixture.

The wrapper requires a zero supervisor exit code, the exact fixture identity,
`RESULTS.json` with `passed: true`, all child assertion receipts, normal
unmount/stop flags and the exact mutation counts. A missing receipt, nonzero exit,
timeout or any failed assertion is a failed/incomplete run. Do not infer success
from a clean-looking status snapshot, remote PUT alone or logs without receipts.

Keep the complete fresh directory, especially `runner.json`, `RESULTS.json`,
`CHILD-RESULTS.json`, `runtime.process.json`, `os.process.json`, supervisor/runtime/
OS logs, `cloud-root` and `state`. The two child process receipts record running,
exited, timed-out-retained or wait-failed-retained states. On an exercise failure
the runtime attempts normal unmount and stop before reporting failure. If the
native operation or shutdown itself stalls, retain the processes and evidence;
the wrapper performs no forced cleanup.

## Scope and limitations

This exercises production broker handlers and native completion inside the
diagnostic executable, with existing per-instance test-only lifecycle/save
activation. It does not exercise installed CLI subprocess/named-pipe transport.
It is separate from the retained read/restart and three-scenario write fixtures.
The 403 is a remote PUT refusal, not a local ACL-denial test.

Recovery runs against the same live backend. Existing strict fresh-publication
generation checks remain intact. This does not establish completion of an edit
whose immutable record generation differs from the current provider token
generation, daemon-restart recovery, automatic journal replay, transport-outage
recovery, changed-local-file/reparse rejection, busy-unmount draining, Personal
writes, real-server permission behavior, encrypted writes, startup or GUI
coexistence. Those need separate evidence. Native compilation, PowerShell parsing
and host checks do not establish that this native scenario has passed.

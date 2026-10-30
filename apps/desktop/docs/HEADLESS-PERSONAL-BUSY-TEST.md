# Opt-in Windows Personal save and open-writer acceptance

This new diagnostic is independent of the accepted C8 read/write/recovery
fixtures. Run it only on the owner's authorized disposable Windows laptop, from
an exact hash-verified candidate containing the new test. It uses two fresh
registered Cloud Files roots, isolated state and fixed synthetic loopback
app-token credentials. It does not install an application, use a real account,
enable folder sync or change startup settings.

```powershell
.\test-headless-personal-busy-windows.ps1 `
  -AgentTestExecutable .\tests\agent-tests.exe `
  -ExpectedSha256 'EXACT_AGENT_TEST_EXE_SHA256_FROM_HANDOFF' `
  -RunNativePersonalBusyFixture `
  -OutputParent 'C:\ABS\existing-NTFS-evidence-parent'
```

`AgentTestExecutable`, `ExpectedSha256` and the explicit
`RunNativePersonalBusyFixture` switch are required. Use the diagnostic executable
hash, which differs from the archive and production agent hashes. `OutputParent`
defaults to `TEMP` and must already exist on a fixed local NTFS volume. The runner
rejects reparse points in that path and its ancestors. It creates a fresh GUID
folder with `OWNER.txt` containing `raiun-headless-personal-busy-native-v1` and a
newline. Never reuse an old fixture directory or put a marker over existing data.

`TimeoutSeconds` defaults to 900, range 120–1800. Each of the three runtime phases
has a 240-second supervisor bound. Ordinary OS children have bounded process
waits and retained output/PID receipts; no stream read/flush/close runs inline in
the runtime supervisor. The open writer is released by an external marker even
when unmount is still waiting; its own 100-second release deadline closes the
handle normally before reporting failure. Timeouts never kill a process, force
unregister, delete a root/state directory or join a stalled child. Preserve the
PIDs and evidence; a timed-out process can still be running.

A lifecycle observer records failure after 60 seconds. It writes the runtime PID,
operation and pending state to `<role>.lifecycle-pending.json` and a failed phase
receipt, then keeps that process/owner alive waiting for the **same** outstanding
call. It never queues another unmount behind a stalled one. The supervisor can
report its independent timeout while the runtime remains retained. If the call
later returns, the recorded timeout remains a failure; normal cleanup can then
proceed. The production lifecycle API is not cancellable by this test wrapper.

The runner sets `RAIUN_HEADLESS_BUSY_FIXTURE_DIR` and actually removes
`RAIUN_HEADLESS_BUSY_FIXTURE_CHILD`, `RAIUN_HEADLESS_CONTEXT`,
`RAIUN_HEADLESS_CONFIG` and `RAIUN_STATE_DIR` from the supervisor environment. It
restores the original process-variable presence and values in `finally`, also
when launch fails. The fixture supplies the fresh config/state to its children.
An absent CHILD key is required; an empty value is not equivalent to absence.

## Acceptance cases

The `success` root tests an existing ordinary `Personal/ordinary-save.bin` file.
A separate ordinary OS process enumerates Personal, hydrates the baseline, edits
one synthetic byte, flushes and closes. Acceptance requires exactly one
conditional PUT, matching remote bytes, at least two verified remote readbacks,
native IN_SYNC and durable journal completion. Normal unmount/stop must retain
the file, exact root identity and registration.

The independent `busy` root keeps the synthetic remote PUT-403 gate armed:

1. A separate OS writer hydrates the baseline, writes and flushes the changed
   bytes, and reports readiness while retaining the ordinary read/write handle.
2. The runtime starts actual broker unmount and records the observed outcome:
   successful retained disconnect while open, explicit refusal while open, or a
   wait that continues until writer release. There is no required EBUSY result.
3. The writer is always released independently, closes normally, and verifies its
   handle still contains the edited bytes. The runtime explicitly retries normal
   unmount after closing, including after a refusal, and verifies automount stays
   disabled and the exact root/registration is retained.
4. A direct ordinary read of the already-hydrated file while disconnected checks
   the exact local bytes without requiring an on-demand directory enumeration. An explicit
   remount then performs ordinary Personal enumeration/read, verifies the same
   bytes and root identity, and checks the file remains outside native IN_SYNC.
5. After normal unmount/stop, a fresh independent runtime process restores the
   saved DPAPI session without submitting a token again, mounts the same root,
   and repeats ordinary enumeration/read, exact byte/root and native dirty checks.
6. No remote PUT is successfully applied in this case. Any attempted PUT must
   have received the synthetic 403; exact attempt/denial counts are retained.
   The test deliberately does not require zero attempts or a fixed journal record
   count, because close timing may permit capture before or after disconnect.
   Every available protected edit record must authenticate and contain the exact
   edited bytes. The test does not create an empty journal before capture.

Both cases require folder-worker generation zero and normal final unmount/stop.
Global pre-handler mutation counts must equal the dedicated ordinary PUT attempt
counts, excluding hidden mutation routes. A zero supervisor exit, exact fixture
identity and all `RESULTS.json`/phase receipts are required. Missing receipts,
timeout, nonzero exit, wrong bytes, unexpected mutations, false native clean
state or failed normal lifecycle make the run incomplete/failed.

## Retained evidence and limits

Keep the complete output directory: runner receipt/logs; both fresh case folders;
all `*.process.json`, `*.RESULTS.json` and stdout/stderr logs; `ROOT.json`;
`UNMOUNT-WHILE-OPEN.json`; any `*.lifecycle-pending.json`; writer ready/release
markers; `cloud-root`; config and
private DPAPI state. Normal operations preserve the registrations and local data
on success and failure. No cleanup, forced termination or recursive deletion is
provided by this runner.

Unmount is a retained disconnect, not an upload/flush barrier. The pending status
annotation counts captured closed edits; it is not a claim about an application's
still-open buffers. This fixture tests flushed ordinary bytes with one explicit
sharing mode and observes the OS outcome. It does not prove all sharing modes,
unflushed buffers, in-flight PUT cancellation, blocked callback drain, automatic
replay, different-record-generation completion, encryption, live-server
permissions, installed CLI transport, startup, GUI coexistence or Server Core.
It tests remount/restart byte preservation directly and does not presume an
unproven overwrite defect. Native compilation, parsing and host checks alone do
not establish native acceptance.

# Opt-in Windows headless write acceptance

This fixture is separate from the accepted native read/restart case. It is an
explicitly opted-in diagnostic for the owner's disposable Windows
laptop, using synthetic loopback accounts, task-owned roots and current-user
DPAPI recovery state. It must not run in ordinary test batches.

The required successful-save case uses ordinary OS file writes, flush and close,
then proves the conditional PUT, exact remote bytes and ETag-bound readback,
native clean state and durable verified recovery state. It must keep folder-pair
sync disabled. Existing test-only provider activation is per instance; production
authentication, mount admission and recovery RPC policy must not be broadened.

Separate denial and unavailable-transport cases require unchanged remote bytes,
retained local dirty content and journal evidence, no false clean/completed state
and normal disconnect. Do not assume an unavailable server causes automatic
replay of an already consumed initial-save request. Explicit headless recovery
RPCs remain outside the delivered CLI policy.

Run from a hash-verified diagnostic bundle using the exact test-executable hash
from the candidate handoff:

```powershell
.\test-headless-write-windows.ps1 `
  -AgentTestExecutable .\tests\agent-tests.exe `
  -ExpectedSha256 'EXACT_AGENT_TEST_EXE_SHA256_FROM_HANDOFF' `
  -RunNativeWriteFixture `
  -OutputParent 'C:\ABS\existing-NTFS-evidence-parent'
```

Verify hashes first and use a new ordinary fixed-local NTFS evidence directory.
Native roots, registrations, state and logs stay retained on success
and failure; no recursive cleanup, unregister or forced process termination is
part of this acceptance fixture.

The three scenarios use fresh state/root pairs. Permission refusal means an
explicit synthetic remote PUT 403; it does not prove every local ACL or UI
permission behavior. The unavailable case drops project DAV transport after the
ordinary file handle has hydrated its baseline, before write dispatch. It does
not change the machine's network settings. Each ordinary I/O child has retained
output/PID evidence and a 45-second polling bound. A timeout returns failure into
the normal disconnect/shutdown attempt without killing or joining a stalled
client. The outer runner also preserves a still-running supervisor on timeout.

The older server's legacy `read_counts` mutation field counted only unhandled
mutation routes. New acceptance must use the global pre-handler mutation counter
and dedicated ordinary-file PUT attempt/success/readback observations. A zero
legacy counter alone does not prove that no handled write was attempted.

This synthetic write fixture does not establish live server writes, installed
CLI transport, busy callback draining, actual boot, Server Core or GUI coexistence.
Those scopes remain separate in [HEADLESS-ACCEPTANCE.md](HEADLESS-ACCEPTANCE.md).

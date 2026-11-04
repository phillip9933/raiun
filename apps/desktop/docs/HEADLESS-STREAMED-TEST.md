# Windows streamed existing-file diagnostic

This ignored diagnostic exercises the shared ordinary Windows Cloud Files path
with files of **17 MiB + 7 bytes**, plus a focused **2 MiB + 7 byte** policy case.
It is outside normal test execution and does
not enable production large-file capture. Use only on the owner-authorized
Windows test laptop after the Desktop coordinator releases the native testing
slot. Preserve earlier candidates and all task state.

The test uses fresh isolated headless configurations, synthetic loopback app-token
login, actual broker mounting, ordinary OS reads/writes, protected streamed
capture, original-ETag conditional upload, independent revision-conditioned full
GET, native in-sync completion and a durable v2 ACK. Each case then starts a
separate process to restore its saved current-user DPAPI session and mount via
normal refresh ticks. Personal and Projects Space each have success and explicit
403 cases. Refused writes must retain exact dirty bytes and the same protected
recovery commitment across restart, without another automatic PUT.

## Run

Verify the candidate archive and source manifest using its exact handoff. Run the
adapter and policy tests listed in the handoff separately first; they are
synthetic checks, not mount acceptance. The handoff supplies the actual test
executable path and SHA-256; do not substitute a different installed agent.

```powershell
.\test-headless-streamed-windows.ps1 `
  -AgentTestExecutable .\tests\agent-tests.exe `
  -ExpectedSha256 '<exact test executable SHA-256 from the handoff>' `
  -RunNativeStreamedFixture `
  -OutputParent '<existing fixed local NTFS evidence directory>'
```

Add `-Case personal-success` to run only that exact save
and restart case. The other allowed selections are `space-success`,
`personal-forbidden` and `space-forbidden`. Omit `-Case` for the full four-case
matrix. A focused pass is labeled separately and does not establish the matrix.
Always use a fresh evidence directory; preserve the original failed run.

Two additional focused selections test the configured transfer policy:

| Selection | File size | Independent full GET rate |
| --- | --- | --- |
| `personal-paced` | 17 MiB + 7 bytes | 512 KiB/s |
| `personal-small-paced` | 2 MiB + 7 bytes | 64 KiB/s |

Each writes `windows_recovery.total_timeout_seconds=120` in its isolated config
and uses the same policy mapping as the prepared production factory through the
existing diagnostic guard. The production activation switch stays off. Only the
post-upload full GET is paced; initial Cloud Files hydration retains its normal
callback budget. The response must deliver every expected byte and last more
than 30 seconds, and save/restart receipts must retain the configured allowance,
exact file identity/digest, native in-sync state and durable v2 acknowledgement.
The smaller case checks new ordinary v2 captures below the old 16 MiB boundary.
Neither paced selection is added to the default four-case matrix.

The later `personal-paced-expired` selection uses 17 MiB + 7 bytes at 64 KiB/s
and a 60-second total allowance. Its expected result is different: one successful
conditional PUT, an interrupted partial independent GET lasting over 30 seconds,
retained deferred recovery and edited bytes, no native in-sync acknowledgement
or durable v2 ACK, and the same pending record across separate-process restart
without another PUT. The save runtime must last at least 60 seconds. This is an
opt-in expiry fixture, not a user-cancellation fixture. It is newer than frozen
candidate14; it requires a new pinned candidate and separate native acceptance.
The default four-case matrix remains unchanged.

`-RunNativeStreamedFixture` is mandatory. The runner verifies the executable hash,
creates one fresh owned evidence directory and restores inherited process
environment values, including absent versus empty values. It does not install
anything, change startup, use real account credentials, alter antivirus or
execution-policy settings, unregister roots, delete state or force-stop a process.
The default supervisor observation timeout is 900 seconds. A timeout is failure
and retains the running owner, server, roots and evidence for investigation.
Never start a second lifecycle operation behind a pending owner.

## Evidence and acceptance scope

For full matrix acceptance, root `RESULTS.json` must report exactly four distinct cases:
`personal-success`, `space-success`, `personal-forbidden`, `space-forbidden`.
Each case retains `save.RESULTS.json`, `restart.RESULTS.json`, `ROOT.json`,
`RECORD.json`, role process receipts and logs. Successful cases require one
conditional PUT, independent full conditioned readback, exact local/remote length
and digest, native in-sync state and durable v2 acknowledgement. The v2 upload
path performs its independent GET before releasing/joining its source worker;
there is no extra second GET requirement copied from the legacy dispatcher.
403 cases require the original remote bytes, one refused PUT, pending dirty
recovery state and retained edited local bytes. Restart must preserve the exact
record identity, generation, commitment and content digest. All cases require
normal unmount/stop, retained registration and disabled folder sync.

Application capture, completion digest and transport use bounded chunks. The
synthetic supervisor server deliberately holds the selected bounded body and accepts a full
request body; it is outside that application-side algorithm claim. This test is
not a process-wide memory measurement.

Compilation, static analysis and synthetic adapter tests do not establish native
acceptance. Even a full native pass here does not establish production activation,
new-file creation, directory creation, rename, move, delete, editor replacement,
real-server login/I/O, Windows boot before interactive login, GUI parity or sync.
Paced success alone does not establish native expiry/cancellation retention.
Those remain separately scoped MVP gates. Do not discard the accepted mount-only
candidates or start sync before the MVP is fully tested.

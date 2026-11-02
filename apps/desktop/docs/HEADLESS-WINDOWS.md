# Windows headless CLI candidate

Local, unpublished test candidate, 28 October 2026, based on Desktop 0.7.4.
The package contains the Rust CLI and agent, with no graphical shell, tray,
WebView or sync scheduler. Explicit startup commands are a separate opt-in.
Native acceptance is recorded
separately; a cross-build alone does not establish Windows runtime support.

One configured root per account exposes the existing Personal/Spaces hierarchy,
including accessible project/shared Spaces. This does not add a guest-link
recipient client or claim support for every sharing type. Folder-pair sync,
media jobs and vault management remain unavailable in this mode. Desktop
autostart settings are refused; `drive startup` manages headless startup explicitly.

## Use the local candidate

Extract the ZIP to a new directory. Keep `raiun.exe` and `raiun-agent.exe`
together. Run from an ordinary Windows user session on a local NTFS volume.
The candidate uses Windows Cloud Files APIs; it does not install a filesystem
or kernel driver. Do not infer Windows Server Core or service-account support
from ordinary-user laptop tests.

Optional installation copies only the CLI, agent, documentation and notices to
a **new** directory. It verifies the binary checksums and preserves an existing
installation. It does not register a service, enable autostart, change PATH,
start the agent, sign in or mount anything:

```powershell
./install.ps1
# Or: ./install.ps1 -Destination 'C:\Users\you\Apps\RaiunHeadlessCLI-Test'
```

In one PowerShell terminal, run the agent in the foreground:

```powershell
.\raiun.exe drive serve
```

In another terminal in the same directory:

```powershell
.\raiun.exe drive login --server https://cloud.example.test
.\raiun.exe drive status --json
# After status reports connected=true, create a separate empty local NTFS folder:
New-Item -ItemType Directory -Path 'C:\Users\you\RaiunCloudFiles'
.\raiun.exe drive mount --path 'C:\Users\you\RaiunCloudFiles'
.\raiun.exe drive spaces
.\raiun.exe drive unmount
.\raiun.exe drive logout
.\raiun.exe drive stop
```

The CLI prints the existing PKCE authorization URL for manual browser sign-in.
It does not open a browser or accept passwords/tokens as arguments. Browser `login`
means the flow started; `status` establishes completion or failure. Remote
browser use needs the loopback SSH forwarding shown by the command before
opening the URL. Actual server/IdP/SSH acceptance remains a separate check.

Without a configuration file, tokens live only in the running agent's memory and
restart requires fresh sign-in and an explicit mount. The new configured MVP
supports remembered login through current-user DPAPI, automatic mount and
reconnect. Configuration itself never contains a token or password; see the
[configuration and app-token guide](HEADLESS.md#configured-operation-and-app-tokens).
Protected root/registry/cache and recovery metadata can persist in either mode.
An unmount disconnects the provider
and prevents refresh/auth completion from reconnecting it; it retains the root
registration and local/recovery data. It does not delete local placeholders or
promise removal of bytes already downloaded. Use `drive stop` for controlled
shutdown rather than terminating the process.
Close file writers first. A successful retained disconnect does not establish
remote delivery of an open file. Pending-edit status covers captured closed
edits; it does not count another process's open buffers. Keep local bytes and
recovery evidence until remote delivery and native completion are verified.

## State and account isolation

The default state directory is `%LOCALAPPDATA%\RaiunHeadless`. `--state-dir`
overrides `RAIUN_STATE_DIR`; pass the same absolute local path to `serve` and
all client commands. Its parent must exist. The final private state directory
may be created by the client. Reparse/unsafe paths, system directories and
Desktop's `%LOCALAPPDATA%\Raiun` tree are refused. Mount roots cannot overlap
private application state or another configured account root.

An immutable process context binds the admitted physical state directory to a
separate user-scoped named pipe, protected metadata storage and Cloud Files
registration identity. Case/drive aliases resolve to the same admitted object.
Desktop retains its existing default pipe, storage and registration domain.
The CLI also checks agent mode before mutations, protecting against older
agents that ignore unknown request fields. No `LOCALAPPDATA` redirection is used.

```powershell
.\raiun.exe drive accounts list
.\raiun.exe drive accounts add --label Work
# Use the returned ID, not its label:
.\raiun.exe drive --profile PROFILE_ID login --server https://work.example.test
.\raiun.exe drive --profile PROFILE_ID mount --path 'C:\Users\you\RaiunWork'
```

Windows account creation takes a label only. Select its mount path after sign-in
with `mount --path`. Each profile has its own session and root. Commands target
`default` explicitly unless a config selects a profile or `--profile ID` is supplied.
An explicit profile must match the selected config. `stop` shuts down all
profiles in that state directory. Errors exit nonzero. After a timeout, inspect
status before retrying a mutation; the agent may still be working.

## Candidate build and verification

A native Rust/MSVC build can build only the two headless binaries from
`apps/desktop` using `cargo build --release --locked -p raiun-agent -p raiun-cli`.
The local Linux cross-build uses the verified LLVM-MinGW toolchain and Rust's
`x86_64-pc-windows-gnullvm` target:

```sh
python3 scripts/build-headless-windows-cross.py \
  --llvm-root /absolute/verified/llvm-mingw \
  --output /absolute/new/candidate-directory --include-tests
```

The cross-builder does not download tools, sign binaries, push commits or
publish. It generates a CldApi import library from the app's existing declared
Windows API names; no replacement DLL or mocked implementation is bundled.
Manifest hashes detect corruption and identify the local build; they do not
authenticate a publisher. The workspace version remains 0.7.4.

On the designated test laptop, use PowerShell 7 in an approved ordinary-user
context; a low-integrity sandbox may prevent native private-directory access:

```powershell
./test-headless-windows.ps1 -BinDir . -OutputDir 'C:\path\to\new\evidence'
```

This runs only named synthetic native fixtures and disconnected CLI/agent
checks. It checks context/ACL admission, credential nonpersistence, recovery and
registration-domain isolation, two independent agents, account isolation,
mode/sync refusals, logout and shutdown. It never signs in, registers or mounts
a live drive and does not touch installed Desktop state. Task-owned state and
logs remain available as evidence.

Positive acceptance still needs a dedicated test account and root: browser
sign-in, Personal/shared-Space enumeration and verified file I/O, permission
loss, interrupted saves, busy unmount, reconnect and crash recovery. Existing
Desktop or Linux test results do not establish this candidate's acceptance.
Sync is intentionally reserved for a later feature and acceptance phase.

## Scoped native verification — 28 October 2026

The exact candidate2 archive and source manifest were verified on the designated
Windows x64 laptop, build26200, ordinary-user Medium integrity/session1.
Fifteen unique native cases passed with zero failures or skips; recovery
subprocess/parent reports were counted once. The real disconnected CLI/agent
batch also passed two independent agents, account/state isolation, command
refusals, logout and safe shutdown without forced cleanup.

This is disconnected acceptance only. Positive sign-in/IdP, Cloud Files
registration/mount and Personal/Spaces I/O remain pending. Installer execution
is tracked separately. The archive is unsigned and unpublished.

The subsequent configured MVP adds `drive login --app-token` with a hidden
prompt, or bounded `--token-stdin`. Secret JSON travels only over sibling-agent
stdin, never arguments, config or environment. This new path, remembered-login
restart, automatic mount/reconnect and explicit startup are not covered by the
earlier disconnected candidate2 acceptance above; target-machine acceptance is
tracked separately.

## Configured MVP quickstart

Use an absolute config path and a new empty mount folder. For example:

```powershell
$config = Join-Path $env:USERPROFILE 'raiun-headless-config.json'
$mount = Join-Path $env:USERPROFILE 'RaiunCloudFiles'
New-Item -ItemType Directory -Path $mount
.\raiun.exe --config $config drive config init --server https://cloud.example.test --auth app_token --username you --mount-path $mount
.\raiun.exe --config $config drive config check
.\raiun.exe --config $config drive serve
# In another terminal, using the same absolute config:
.\raiun.exe --config $config drive login --app-token
.\raiun.exe --config $config drive status --json
```

The app token is requested without echo. `--token-stdin` accepts a private input
stream instead, with the same 16 KiB token limit. App-token `login` now waits for
the exact submitted authentication generation to become connected and prints one
final result. Invalid/revoked tokens, disconnects, account replacement, status
failure and deadline expiry exit nonzero. Its single 75-second deadline covers
submission and status polling after token input; credentials are never replayed.
`--json` returns the final connection result for scripts. Login completion does
not claim that the Cloud Files mount succeeded. To use browser PKCE, initialize
a separate nonsecret file with `--auth browser` and run `login` without
`--app-token`. The [option/schema reference](HEADLESS.md#configured-operation-and-app-tokens)
documents every field, default, range and precedence rule.

Once foreground behavior is verified, stop it before enabling startup:

```powershell
.\raiun.exe --config $config drive stop
.\raiun.exe --config $config drive startup enable --dry-run
.\raiun.exe --config $config drive startup enable
.\raiun.exe --config $config drive startup status
# Preserve configuration, remembered login and local files when disabling:
.\raiun.exe --config $config drive startup disable
```

`boot` is the default startup mode; `--mode logon` is explicit. Read the
[startup guide](HEADLESS-STARTUP.md) for Windows account credentials, permissions,
session limitations and the required real reboot/provider acceptance. The token
store uses the same Windows user's DPAPI identity. Expired/revoked app tokens
require manual replacement through `login`. Network readiness may be retried at
boot, but a credential rejection cannot be repaired by waiting. Config changes
take effect after agent restart. This remains an unpublished MVP with unchanged
application version; no new release or target-machine acceptance is implied.

## Inspect and explicitly retry ordinary saved edits

Authentication and mount status do not establish that every local edit is saved.
`drive status --json` now exposes `ordinary_edits.state` and a bounded
`pending_count` when known. `state=unknown` is not zero pending work. Ordinary
file recovery remains separate from folder sync and encrypted vault recovery.

Use `drive edits list --limit 50 --json` (range 1..100) and pass an optional
`--after` value exactly as returned in `next_after`. An explicit retry is:

```powershell
.\raiun.exe --config $config drive edits retry --id HEX_FROM_LIST --generation 7 --local-relative-path 'Spaces/Projects/path.bin' --json
```

This invocation is approval for one immutable record generation. It does not
prompt again, auto-replay after a stale-context error, or infer a disk name from
the remote path. The selected path is relative to this drive root, with `/` or
`\` separators and bounded ordinary filename components. Fresh profile status
supplies the authentication generation and registered-root scope token; native
identity and retained-content hash checks still decide whether local completion
is safe. Desktop's selected account is not silently substituted.

The result distinguishes `remote_verified` from `local_completion`. Only
`local_completion=completed` confirms the verified native completion step;
`unavailable`, `uncertain`, or `not_requested` must not be presented as a clean
placeholder. Read the existing `state`/`retained` fields as delivery and evidence
information, not a blanket saved-state signal. See the
[command and result contract](HEADLESS.md#windows-ordinary-saved-edits).
This new local candidate path needs its own native acceptance; existing tests of
other Windows candidates do not cover it. Folder sync stays disabled.

For `edits retry`, successful RPC handling alone does not produce exit status 0.
The CLI exits successfully only when `remote_verified=true` and
`local_completion=completed`. Conflicts, deferred/unknown outcomes and verified
remote delivery with unavailable/uncertain local completion exit nonzero. The
structured outcome remains on stdout (JSON with `--json`), with a bounded
nonsecret explanation on stderr; scripts must inspect both fields before acting.

## Windows recovery policy candidate

The optional schema-1 `windows_recovery` object now configures normal headless
ordinary existing-file streamed saves and explicit recovery contexts in source.
The configured limits replace the legacy whole-body 16-MiB capture ceiling for
that pipeline. File/folder namespace operations and encrypted-vault limits remain
separate. Desktop uses its own defaults and does not read the headless config.
Linux rejects this Windows-only section. Configuration changes require restart.

```json
"windows_recovery": {
  "max_file_bytes": 1073741824,
  "max_state_bytes": 8589934592,
  "max_state_entries": 20000,
  "max_scan_metadata_bytes": 67108864,
  "total_timeout_seconds": 21600
}
```

Omitting the section or individual fields uses the defaults above. Unknown fields
are errors. All values are integers; the object contains no credentials.

| Field | Meaning and accepted range |
| --- | --- |
| `max_file_bytes` | Inclusive plaintext admission limit for one ordinary file: 1–1,099,511,627,776 bytes (1 TiB); default 1 GiB. Encrypted-vault limits are separate. |
| `max_state_bytes` | Aggregate logical recovery budget: 16,777,216–17,592,186,044,416 bytes (16 MiB–16 TiB), at least `max_file_bytes`; default 8 GiB. Retained v1/v2 records, ciphertext stages, reservations and namespace metadata count. |
| `max_state_entries` | Retained-entry scan/admission limit: 64–20,000; default 20,000. The separate 256-scope/2,000-record discovery ceilings remain. |
| `max_scan_metadata_bytes` | Authenticated metadata work per scan: 524,288–67,108,864 bytes (512 KiB–64 MiB); default 64 MiB. |
| `total_timeout_seconds` | One total allowance per new ordinary save: 60–86,400 seconds; default 21,600 (6 hours). |

Fresh-file admission can conservatively need roughly four times its plaintext
size plus metadata. The state budget does not reserve free disk space. Lowering
it below retained usage refuses new admissions and preserves existing evidence.
Unknown or incomplete state fails closed. V2 listing does not read snapshot
bodies; legacy v1 discovery can still decrypt a bounded record containing up to
16 MiB of file content within its separate scan limits. A small scan budget can
refuse discovery even when disk space is available.

The single save allowance starts before capture and includes staging, queueing,
upload, independent full download/digest verification, worker joining and native
completion. New small and large ordinary saves share it when the new pipeline is
admitted. Old stored v1 recovery keeps its legacy decoder and deadlines. Queue,
retry and readback phases do not reset the allowance. Metadata requests use the
smaller of 30 seconds and remaining job time; payloads use remaining job time
and existing connection/inactivity bounds. OS cancellation/drain and worker joins
can outlast the logical deadline while owners and buffers remain retained.

At 128 KiB/s in each direction, a 1 GiB upload plus full verification takes about
4.6 hours before other work; at 64 KiB/s, about 9.1 hours. Configure the total for
the link. Permission loss, revocation,
cancellation or timeout must preserve edited bytes and recovery evidence without
a clean acknowledgement. The finished Windows candidate's basic large-save check
remains pending; source activation alone is not native acceptance.


## Current ordinary namespace source — 3 November 2026

The shared GUI/CLI runtime at `3e912d9` now wires new files, new folders, clean-file
deletion and same-folder ASCII file rename in Personal and writable, unencrypted
Spaces. Fresh Space/root qualification stays separate from the Personal account
anchor. Root and encrypted operations, directory rename/delete, cross-parent moves
and atomic replacement saves are not implied by these file capabilities. These
newer Spaces changes are source-checked, not yet packaged or natively exercised.
The earlier `d8233c1` installer passed basic install/upgrade/startup checks; a fresh
laptop test account's unavailable browser route leaves its sign-in/file workflow
unverified. Existing-headless state, memory-only credentials, explicit mount and
folder-sync/autostart restrictions are unchanged.

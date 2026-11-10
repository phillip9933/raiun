# Raiun headless CLI candidate

Local development candidate, 28 October 2026, based on published Desktop 0.7.4.
This is not a new public release. The first package targets Linux and reuses
Desktop's Rust agent, OpenCloud protocol client and FUSE adapter. Windows has a separate [Cloud Files headless test candidate](HEADLESS-WINDOWS.md)
with native acceptance tracked independently. macOS remains follow-up work.

One on-demand filesystem root per account contains `Personal/` and `Spaces/`,
including accessible project/shared Spaces discovered by the existing engine.
This does not add a guest-link recipient client or claim every share type.
Existing on-demand reads/writes are reused. Mount-only mode refuses folder sync,
media jobs, vault unlock, Desktop autostart settings and other desktop settings
operations. Explicit `drive startup` registration is separate.

On Linux, ordinary new-file copies use the same durable local acceptance and
shared four-worker upload pool as Desktop when the private cache is available.
The existing cache quota bounds pending bytes; fresh account, Space-root, parent
and encryption checks still apply before delivery. Uncertain uploads retain
their recovery copies and are not automatically resent. Normal stop and unmount
cancel and join the owned upload workers, retaining pending recovery. Without
usable cache storage, the established synchronous upload path remains available.

## Build and install

From `apps/desktop`, use Rust and its existing native build dependencies (C
toolchain and pkg-config). No Node/npm, Tauri, GTK, WebKit, display server or
Secret Service is needed for this package. Mounting needs Linux FUSE support,
access to `/dev/fuse` and `fusermount3`. The client does not configure container
mount permissions or change system permissions.

```sh
bash scripts/build-headless-linux.sh
tar -xzf target/raiun-headless-linux-x86_64.tar.gz
cd raiun-headless-linux
bash install.sh
# Alternative: bash install.sh --prefix /absolute/new/install-directory
```

The installer checks binary checksums and installs to a new directory, normally
`~/.local/lib/raiun-headless`. Existing installations are preserved; choose a new
prefix for replacements. It does not change PATH, register a service or start
anything. Keep both executables together. These unsigned checksums detect
corruption; they do not authenticate a publisher. The version string remains
the workspace's 0.7.4; no app version was bumped.

## Sign in and mount

Keep the foreground agent running in one terminal:

```sh
~/.local/lib/raiun-headless/raiun drive serve
```

In another terminal, use the full installed path or add its directory to PATH:

```sh
raiun drive login --server https://cloud.example.test
raiun drive status
# After status reports connected=true:
raiun drive mount --path "$HOME/RaiunHeadless"
raiun drive spaces
```

Browser `login` prints the authorization URL and expiry; open it manually. It retains
Desktop's authorization-code/PKCE flow, loopback callback, state and issuer
validation, verified TLS and token refresh. No browser is launched on the
headless host. Tokens/passwords are never CLI arguments. Successful browser `login`
means the flow started; `status` establishes completion or failure.

For a remote agent, the CLI prints the callback port and forwarding guidance:

```sh
# Run on the browser machine, replacing PORT with the reported callback port:
ssh -N -L PORT:127.0.0.1:PORT USER@AGENT_HOST
```

Forward before opening the URL and keep the tunnel running until sign-in
completes. OAuth client/IdP policy and available local ports must permit the
flow. Browser/SSH sign-in remains live acceptance work. This is not a device-code
grant implementation.

Without a configuration file, login stays in the running agent's memory and
every agent restart requires fresh sign-in. The configured MVP described below
adds remembered login and automatic mount/reconnect. Namespace metadata,
cache/staging and recovery data can still be written by either mode.

## Configured operation and app tokens

Create a nonsecret config using an absolute path. Existing files are preserved:

```sh
raiun --config "$HOME/.config/raiun-headless/config.json" drive config init \
  --server https://cloud.example.test --auth app_token --username you \
  --mount-path "$HOME/RaiunHeadless"
raiun --config "$HOME/.config/raiun-headless/config.json" drive config check
raiun --config "$HOME/.config/raiun-headless/config.json" drive serve
# In a second terminal: prompts for the app token without echoing it.
raiun --config "$HOME/.config/raiun-headless/config.json" drive login --app-token
```

For automated input, add `--token-stdin` and feed a private input stream. Tokens
are never accepted in arguments, environment variables or config. The CLI bounds
stdin to 16 KiB, wipes its token buffers and sends secret JSON to the sibling
agent through stdin. App tokens must be supported by the configured OpenCloud
server; this is not an OAuth password grant. Browser PKCE remains available with
`--auth browser` in the config.

App-token `login` waits for authentication completion on both platforms. The
single 75-second deadline starts after token input and covers submission plus
all status checks; each sibling-agent request shares the remaining budget. The
token is submitted once. Exit zero requires `connected=true` for the exact
authentication generation returned by that submission, with no authentication,
refresh or cleanup transition still pending. A concurrent account change,
rejection, disconnect, unavailable status or deadline expiry exits nonzero.
The command prints one final connection result, and `--json` makes it suitable
for scripts. This result confirms login, not successful mounting; inspect its
optional `mounted` field or run `status` for mount state. Error output uses
generic diagnostics rather than remote text that might echo a token. Browser
PKCE remains asynchronous: open its URL and use `status` to confirm completion.

The JSON schema is strict and rejects unknown fields, including token/password
fields. `drive config show` displays only the validated nonsecret config.

| JSON field | Default | Accepted value / matching init option |
| --- | --- | --- |
| `schema_version` | Required | Exactly `1`; written by `config init` |
| `server` | Required | Absolute HTTPS URL, without credentials/query/fragment; loopback HTTP allowed; `--server URL` |
| `auth` | Required (`init`: `browser`) | `browser` or `app_token`; `--auth browser\|app_token` |
| `username` | Absent | Required for `app_token`, 1–512 bytes, no colon/control characters or surrounding whitespace; `--username NAME` |
| `client_id` | Absent | Optional nonempty browser OAuth client ID, at most 4096 bytes; agent default `OpenCloudDesktop`; `--client-id ID` |
| `mount_path` | Required | Absolute directory path without `..`, excluding filesystem root; `--mount-path ABS` |
| `auto_mount` | `true` | Boolean; `--no-auto-mount` writes false |
| `remember_login` | `true` | Boolean; `--no-remember-login` writes false |
| `reconnect_interval_seconds` | `30` | Integer 1–86400; `--reconnect-interval-seconds N` |
| `profile` | `default` | `default` or `profile-` plus 32 lowercase hex digits; global `--profile ID` during init |
| `windows_recovery` | Absent | Optional Windows-only ordinary-file recovery limits; see the [candidate policy reference](HEADLESS-WINDOWS.md#windows-recovery-policy-candidate). Production activation remains disabled; no `config init` option enables it. Linux rejects this section. |

For example, this file contains deployment settings only:

```json
{
  "schema_version": 1,
  "server": "https://cloud.example.test",
  "auth": "app_token",
  "username": "you",
  "mount_path": "/home/you/RaiunHeadless",
  "auto_mount": true,
  "remember_login": true,
  "reconnect_interval_seconds": 30,
  "profile": "default"
}
```

On Windows use a local drive-absolute path such as
`"C:\\Users\\you\\RaiunCloudFiles"`; the first Cloud Files mount requires a
separate empty local NTFS directory. The path must be outside private state,
system directories and other configured roots. Existing retained registrations
are reopened only after the existing physical/account ownership checks.

`--config` selects an absolute file, then `RAIUN_HEADLESS_CONFIG` if exported;
otherwise the CLI tries `STATE_DIR/config.json`. A missing default keeps the older ephemeral behavior;
an explicitly selected missing or invalid file fails before contacting an agent.
`serve` passes the validated file path as `RAIUN_HEADLESS_CONFIG`. Use the same
state/config choices for every command. The config supplies the profile and
default mount path; an explicit `--profile` must match it. `login --server`,
`--username` and `--client-id` fill the corresponding request fields when given,
otherwise the config supplies them. Login must match the agent's configured
server/authentication identity. `--app-token` cannot override a browser config;
edit the config and restart the agent to change its authentication method.
Configuration is read once by an agent process; edits take effect after restart.

| CLI option / environment | Selection and default |
| --- | --- |
| `--config ABS` / `RAIUN_HEADLESS_CONFIG` | Explicit CLI path, then environment, then `STATE_DIR/config.json`; explicit files must exist |
| `drive --state-dir ABS` / `RAIUN_STATE_DIR` | Explicit CLI path overrides environment; Linux default `$XDG_STATE_HOME/raiun-headless` or `$HOME/.local/state/raiun-headless`; Windows `%LOCALAPPDATA%\RaiunHeadless` |
| `drive --profile ID` | Config profile when configured; otherwise supplied ID or `default`; a supplied ID must match config |
| `drive --json` | False; successful RPC data as JSON when set; errors remain on stderr |
| `login --app-token` | Selects app-token login; configured `auth=app_token` also selects it; no token-valued argument exists |
| `login --token-stdin` | False; requires `--app-token`; reads one UTF-8 token line, 1–16384 bytes excluding one optional final LF/CRLF |
| `mount --path ABS` | Configured `mount_path` when omitted; legacy unconfigured mode uses the agent's previously configured root |
| `startup --mode boot\|logon` | `boot`; explicit platform startup registration choice |
| `startup --dry-run` | False; prints a registration/removal/status plan without applying it |

`RAIUN_HEADLESS_CONTEXT=1` is an internal Windows routing opt-in set by the CLI;
it is not a credential setting. `HOME`, `XDG_STATE_HOME`, `LOCALAPPDATA` and the
startup helper's `XDG_CONFIG_HOME` retain their platform path meanings. Never put
an app token or login password into any environment variable for this client.

The command set is `serve`, `status`, `spaces`, `mount`, `unmount`, `login`,
`logout`, `stop`, `accounts list`, `accounts add --label LABEL` (Linux also needs
`--path ABS`), Windows-only `edits list/retry`, `config init/show/check` and
`startup enable/disable/status`.
Config commands run locally. Startup commands require an existing valid config.

Remembered Linux login uses private local files under
`STATE_DIR/sessions/PROFILE.json`: directories are owned by the effective user
with mode 0700 and session files are mode 0600, regular and singly linked.
This MVP filesystem store is not encrypted and does not use a keyring. Unsafe
existing permissions or links cause refusal without repair. Replacement is
atomic with file and directory sync. Keep the state directory on a private local
filesystem and protect backups. Windows uses current-user DPAPI in its isolated
state root. Disabling `remember_login` uses memory-only login.

After restart, configured remembered sessions are checked against the selected
server, profile and authentication identity before use. With `auto_mount=true`,
the agent attempts the configured mount after account verification and retries
network-related readiness according to the reconnect interval, including when
boot starts before the network is usable. `unmount` prevents background reconnect
from remounting during that agent run. `logout` removes remembered login so a
later restart cannot restore it; local and recovery files remain. An expired or
revoked app token needs a new token entered through `login`; the client does not
renew app tokens by sending them to an OAuth token endpoint. Browser credentials
retain the existing refresh rules and may require manual sign-in after rejection.

For browser login, use another config file and keep the foreground agent running:

```sh
raiun --config "$HOME/.config/raiun-headless/browser.json" drive config init \
  --server https://cloud.example.test --auth browser \
  --mount-path "$HOME/RaiunHeadless"
raiun --config "$HOME/.config/raiun-headless/browser.json" drive serve
# In the other terminal: open the printed URL manually, then inspect status.
raiun --config "$HOME/.config/raiun-headless/browser.json" drive login
raiun --config "$HOME/.config/raiun-headless/browser.json" drive status
```

Explicit background startup is available through `drive startup`; see its help
and the [startup guide](HEADLESS-STARTUP.md) for platform boot/logon choices and
permissions. First stop the foreground agent, then review and apply startup:

```sh
raiun --config "$HOME/.config/raiun-headless/config.json" drive stop
raiun --config "$HOME/.config/raiun-headless/config.json" drive startup enable --dry-run
raiun --config "$HOME/.config/raiun-headless/config.json" drive startup enable
raiun --config "$HOME/.config/raiun-headless/config.json" drive startup status
# To stop automatic startup while preserving state:
raiun --config "$HOME/.config/raiun-headless/config.json" drive startup disable
```

Startup requires a valid config
and remains an explicit action separate from package installation. Real login,
reboot, mount and reconnect acceptance must be measured on the target machine.

```sh
raiun drive unmount
raiun drive logout
raiun drive stop
```

Unmount and shutdown retain existing safe detach behavior; logout preserves
local/recovery files. `stop` affects all profiles in this isolated agent.
On Windows, disconnect retains the root, placeholders and local bytes. Close
writers before unmounting: a successful disconnect is not an upload barrier for
an open file, and retained-edit counts cover captured closed edits, not buffers
still held by another process. Inspect delivery/recovery separately before
treating an edit as saved remotely.
SIGINT/SIGTERM use the existing agent shutdown path. Failed requests exit
nonzero; after a timeout an operation may still be running, so inspect status
before retrying a mutation.

## State and accounts

State defaults to `$XDG_STATE_HOME/raiun-headless`, otherwise
`~/.local/state/raiun-headless`. `--state-dir /absolute/path` overrides
`RAIUN_STATE_DIR`. Use the same choice for `serve` and every client command.
Desktop state defaults stay separate. The client checks the agent mode before
mutations, including when an older desktop agent ignores the requested mode.
Profile RPCs target the selected config profile, or `default` without a config,
unless an allowed `--profile ID` is supplied.

```sh
raiun drive accounts list
raiun drive accounts add --label Work --path "$HOME/RaiunWork"
# Use the returned ID, not its label:
raiun drive --profile PROFILE_ID login --server https://work.example.test
raiun drive --profile PROFILE_ID status --json
raiun drive --profile PROFILE_ID mount
```

Roots must not overlap. Each profile has separate account and session state.
In legacy mode, adding a profile enables its mount preference, allowing automatic
mount after successful sign-in. The default profile initially requires explicit
`mount`; previously enabled roots remount on a later successful sign-in.
Configured mode follows its explicit `auto_mount` and `remember_login` values.
`--json` emits successful agent data; errors remain on stderr. Status may contain
server names, paths and account metadata; review before sharing it.

## Windows ordinary saved edits

`connected=true` reports an authenticated session. It does not mean every local
edit was delivered or that every placeholder is in sync. Windows status includes
`ordinary_edits`: `state=known` has a bounded `pending_count`; `state=unknown`
has no trustworthy count and must not be interpreted as zero. This status covers
ordinary retained edits, independently of folder sync and encrypted vault edits.

```powershell
# Read one bounded page; default limit is 50, permitted range is 1..100.
.\raiun.exe --config $config drive edits list --limit 50 --json
# Pass a returned next_after string unchanged with --after for the next page.
# Select the immutable record ID/generation and the exact local file explicitly:
.\raiun.exe --config $config drive edits retry --id HEX_FROM_LIST --generation 7 --local-relative-path 'Spaces/Projects/path.bin' --json
```

The retry invocation approves that one ordinary edit; there is no additional
confirmation prompt and no automatic replay. `--generation` is the immutable
record generation from `edits list`, not the current authentication generation.
The CLI obtains fresh status for the selected profile and includes its current
authentication generation and registered-root scope token internally. A changed
account/root or stale page is rejected rather than retried against newer state.

`--local-relative-path` identifies the file relative to the selected drive root;
`/` and `\` separate components. It is not an absolute path or a remote DAV
path. Empty/traversal/device/control/stream names and excessive lengths are
rejected. The CLI does not infer a local name from a remote path. The provider
still pins native file identity and verifies the exact retained-content hash;
path components alone do not grant write or completion authority. Local
completion currently requires the retained record's provider token generation
to match the active provider. A genuinely older generation can have verified
remote delivery while local completion remains unavailable; retain its pending
evidence. Ordinary app-token restarts reconstruct the current client generation,
which does not establish support for every older OAuth/token generation.

Retry output keeps `state` (`verified_applied`, `conflict`, `outcome_unknown`, or
`not_completed`) and separately reports `remote_verified` and
`local_completion` (`completed`, `not_requested`, `unavailable`, or `uncertain`).
A verified remote delivery with uncertain/unavailable local completion is not a
clean-placeholder claim. Retain the local file and recovery evidence and inspect
the result before another explicit request. `retained=true` means evidence was
preserved; it does not mean the remote delivery failed. These commands do not
enable sync, vault recovery, force overwrite, or generic agent requests. Linux
reports that `drive edits` is unsupported. Native acceptance of this new command
path is tracked separately from portable CLI/schema tests.

## Validation and next work

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python3 scripts/test-headless-linux.py --binaries target/release
```

Disconnected smoke uses disposable synthetic home/state directories, no display
or D-Bus session, a keyring-call detector and the real CLI/agent. It checks
status, account isolation, refused desktop/sync commands, failures, logout and
shutdown. Installer tests cover checksum failure and existing-file preservation.
CLI fixtures do not sign in, contact a server or mount.

The configured MVP and schema do not bump the application version or authorize
a release. Source checks and synthetic lifecycle tests do not establish physical
boot, positive server login or live mount acceptance on either platform.

Remaining acceptance: browser/SSH PKCE with a dedicated test account, actual
Personal/shared-Space FUSE reads/writes, permission loss, offline/crash recovery,
busy unmount and resource measurements. Windows needs native headless provider,
installation and account-isolation validation. Later folder sync should reuse
Desktop's reconciler behind an explicit command and separate acceptance gates;
it must not be enabled implicitly in this mount-only service.

For `edits retry`, successful RPC handling alone does not produce exit status 0.
The CLI exits successfully only when `remote_verified=true` and
`local_completion=completed`. Conflicts, deferred/unknown outcomes and verified
remote delivery with unavailable/uncertain local completion exit nonzero. The
structured outcome remains on stdout (JSON with `--json`), with a bounded
nonsecret explanation on stderr; scripts must inspect both fields before acting.

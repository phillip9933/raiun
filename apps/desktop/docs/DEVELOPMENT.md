# Desktop development and verification

Use the repository root as the working directory. Install Rust through the [official toolchain installer](https://rust-lang.org/tools/install/), including rustfmt and Clippy. CI uses stable Rust; the manifest's older language baseline is not an independently tested minimum compiler guarantee.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --release --locked
```

Cargo.lock pins application dependencies. The commands above operate on the main Rust workspace; tests use temporary directories and synthetic data and do not contact OpenCloud or write production configuration. The opt-in FUSE test is described below. The release CLI is `target/release/raiun` on Linux/macOS and `target/release/raiun.exe` on Windows.

CI runs portable crate tests (`raiun-core`, `raiun-cli`, `raiun-opencloud`, and `raiun-engine`) on Linux, Windows, and macOS. Its Linux job additionally runs formatting, Clippy, the full workspace tests, and the Linux package build. This does not establish Windows or macOS provider support: those native adapters and packages remain future work and require their own platform acceptance.

## Configuration recovery

The CLI uses a sidecar `.json.lock` file and refuses a concurrent writer. If a process crashes, inspect the lock and confirm no writer is running before removing the stale lock manually. A reader may see the preceding or following complete config during an atomic replacement; it should never see partial JSON. External editors do not honor this cooperative lock.

Config reads are limited to 1 MiB and reject unknown schema versions and fields. Symlink config files are refused. New config files use mode 0600 and newly created config directories use 0700 on Unix; existing directory permissions are not changed. Windows uses inherited ACLs at this stage and needs native security acceptance before storing sensitive material. The config contains no credentials.

Missing local folders invalidate operational checks but must not prevent viewing the config or removing stale pairs. Configuration path checks are preflight validation, not protection against every concurrent filesystem mutation. Provider and sync paths still need identity checks and platform-native handle discipline.

## Remaining validation priorities

Validate crash consistency and baseline advancement before throughput tuning. Exercise incomplete/failed directory listings, remote revision changes, local disk exhaustion, disappeared volumes, simultaneous edits, and cancellation with dirty bytes. Include large-directory and large-inventory fixtures that do not require building the entire dataset in memory.

Resource tests should report engine RSS, native helper memory, tray host memory, webview children, idle CPU, disk work, and server request volume. UI and engine must be measured both separately and together. Performance budgets in the architecture are provisional acceptance targets, not measurements of the current build.

## Linux integration checks

The ordinary workspace suite uses synthetic data and does not mount a filesystem.
The opt-in host check creates and removes its own temporary mount and backend:

```
cargo test -p raiun-fuse live_fuse_roundtrip_when_device_is_available -- --ignored --nocapture
```

Run it only when explicitly testing native filesystem integration, with access
to `/dev/fuse`. A missing device fails this opt-in check rather than reporting a
successful mount test.

The shell has a separate Cargo workspace, so the root Cargo commands do not
check its Rust package or frontend. Run `npm ci && npm run build` inside
`desktop-shell`. To test its Rust package, run:

```sh
cargo test --manifest-path desktop-shell/src-tauri/Cargo.toml --locked
```

The normal shell launch opens its window. Launch it with `--background` to
create the tray without an initial webview when the desktop session supports a
tray; if tray creation fails, the shell opens a window so it remains visible.
Linux autostart entries use this background argument. A process-level check
confirmed the latest background process had 56,316 KiB RSS and no WebKit child
processes, then confirmed a normal second launch reused that process and opened
the webview. Closing the window with its X and reopening it from the tray,
opening/paging the recovery panel, and launching at actual desktop-session login
still need manual acceptance.

The Linux package script builds the shell in release mode. Its Vite development
port is 1420, matching Tauri configuration. A browser-only preview cannot
control the agent; use the native shell for IPC and account tests.

## Linux sign-in troubleshooting

Raiun signs in as a native public OIDC client using authorization code with
PKCE S256; it has no client secret. Leaving the OAuth client ID field blank
requests WebFinger discovery for the public client ID and scopes; entering an
ID supplies a manual override. Tests and an anonymous live check confirmed
blank discovery returns `opencloud` with `openid profile email`, without
`offline_access`; the parser accepts the server's space-separated scope format.
Manual `OpenCloudDesktop` sign-in, session refresh, and restoration passed on
the target deployment. Automatic-client callback compatibility remains
unverified because the discovered client does not advertise the scope needed
by that deployment, and is not an MVP gate. The client uses a temporary loopback
callback, so an
authentik provider configured with regex matching should allow exactly
`^http://127\.0\.0\.1:[0-9]+/?$` (including the optional trailing slash). Keep
OpenCloud's configured issuer, signing-key verification, and accepted audience
aligned with the existing deployment; do not broaden audience checks to work
around a client registration problem.
OpenCloud documents the public-client/PKCE requirement and the default desktop
client ID in its [external OIDC setup guide](https://docs.opencloud.eu/docs/admin/configuration/authentication-and-user-management/external-idp/).
authentik documents public clients, PKCE, and redirect URI matching in its
[OAuth 2.0 provider guide](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/).

A successful browser callback and token exchange only confirm the OAuth step.
If the next status reports HTTP 500 from Graph discovery, treat that as a
separate API failure: ask the OpenCloud administrator to correlate the
`GET /graph/v1.0/me/drives` request with its request ID in the server logs and
inspect the Graph/proxy-side error. A client-side 500 alone does not establish
the cause. See OpenCloud's [Spaces API](https://docs.opencloud.eu/docs/dev/server/apis/http/graph/spaces/)
and [Graph service configuration](https://docs.opencloud.eu/docs/dev/server/services/graph/).

## Provider recovery

Provider recovery copies are under the current account's private
`provider-spool` directory. Settings provides an on-demand saved-copy index and
an Open folder action; listing is available while disconnected if the agent is
running and a saved account is configured. The installed endpoint returned a
valid empty page for the saved account; the recovery-panel click and pagination
flow still need manual UI acceptance. The index is bounded, reads only metadata,
and never replays or deletes uploads. Copy saved content elsewhere before
editing it; leave its metadata intact for recovery.
Folder-pair replacements may also preserve a displaced version in a local
`.raiun-preserve-*` directory. That prefix is reserved and excluded from sync.

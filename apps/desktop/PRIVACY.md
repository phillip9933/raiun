# Raiun Desktop privacy

Raiun Desktop is a client for the OpenCloud servers and accounts you choose.
This notice describes the Linux beta. It does not promise that every feature or
recovery case has completed acceptance testing; see the release limitations.

## Accounts, credentials and network access

Raiun stores account configuration and identifiers locally and contacts the
configured server for sign-in, account/Space discovery, file metadata, downloads,
uploads and synchronization. Your server and identity provider receive requests,
file names, file contents and other data required by the operations you enable;
their own privacy policies apply. Browser sign-in opens the configured login
service. Raiun also uses local control sockets and loopback communication for
its UI, agent and sign-in flow. These local interfaces are not a cloud service.

The Linux client uses the desktop Secret Service/keyring through `secret-tool`
for persistent credentials. The service must be available and unlocked. Saved
vault credentials require explicit consent and are scoped to the selected
account and encrypted location. Raiun does not promise physical erasure from an
unavailable or locked keyring: revoking Raiun's saved-key authority and deleting
an OS keyring entry are distinct operations. Protect your OS account and keyring.
Do not include tokens, passwords, vault keys or private server URLs in reports.

## Headless CLI candidate

The headless package uses separate state and account routes. It does not launch a
browser: PKCE sign-in prints a URL for manual opening, with loopback SSH forwarding
for a remote browser. App-token sign-in accepts hidden terminal input or private
stdin; credentials are not configuration fields or CLI arguments. These choices
do not change how the GUI saves sign-in or uses its OS credential store.

Without a headless config, credentials stay in the running agent's memory and
restart needs fresh sign-in. Selecting a config opts into configured operation,
where `remember_login` and `auto_mount` default to `true`; set them to `false` or
create the config with `--no-remember-login` and `--no-auto-mount` to disable them.
When remembered login is enabled, Linux stores credentials as plaintext in owned
private 0700 directories and 0600 files, separately from nonsecret configuration.
This is not encryption at rest. Windows uses isolated current-user DPAPI storage.
Use OS disk protection, and treat headless state as sensitive when making backups.
Either mode can retain cache, namespace metadata, staging files and recovery data.

Startup registration is explicit. Windows boot startup can ask Task Scheduler to
store the same user's Windows account credential after a hidden prompt; Raiun's
configuration does not contain that password. Windows logon startup does not need
a stored Windows password. Linux boot startup enables user lingering, which is
retained when Raiun startup is disabled. Disabling startup, logout, unmount and
uninstall do not erase cached files or recovery evidence. See [headless setup](docs/HEADLESS.md)
and [startup](docs/HEADLESS-STARTUP.md) for platform policy and acceptance limits.

## Local files, cache and recovery

Each account has its own configuration and storage scope. The client retains
local databases and metadata for sync pairs, inventories, transfer history,
offline policies and recovery. This account separation is not an OS security
boundary against other software running as the same user or an administrator.

Ordinary cached files, pending edits, recovery copies and exported files can
contain plaintext names and contents. Encrypted remote vaults can also require
private local plaintext working or staging copies while unlocked, edited or
exported. Remote encryption is not local disk encryption. Use OS disk protection
and independent backups appropriate for your data.

Network outages, app exit, logout, removing a sync pair, disabling a cache policy
and deleting local data have different effects. Raiun preserves pending work and
recovery data in several failure cases; do not assume logout or uninstall erases
all local files, logs, caches, exported copies, server data or backups. Review
retained data before discarding it. Uninstalling a user-scoped binary installation
is not a secure erase operation.

## Logs and support

The client and OS can retain local diagnostic logs and error information.
Diagnostics may expose paths, names, account identifiers, server addresses,
request metadata or error responses. Do not assume all diagnostics are free of
sensitive information. Inspect and redact material before choosing to submit an
issue or share a support archive. A public GitHub issue is public. This notice
is not consent for automatic log publication or sharing your credentials.

Raiun depends on the OS browser, WebKitGTK, keyring, desktop portals and other
system components. Their processing and crash-reporting behavior is governed by
your system configuration and their policies. Server-side retention and deletion
must be addressed with your server operator. Review the release source, feature
documentation and release notes for the version you install.

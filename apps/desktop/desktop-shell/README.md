# Raiun Desktop shell

This is the Linux-first Tauri 2 settings and tray client for the Raiun agent. The UI talks to the agent through a single Tauri `request` command; it does not run synchronization itself.

## Run locally

Install Node.js, Rust, and the Linux Tauri prerequisites, including WebKitGTK 4.1 and Ayatana AppIndicator. Then run:

```sh
npm install
npm run tauri dev
```

The Rust host connects to `control.sock` under `$XDG_STATE_HOME/raiun-desktop`, or `$HOME/.local/state/raiun-desktop` when `XDG_STATE_HOME` is unset. Set `RAIUN_STATE_DIR` to override that state directory. The shell currently supports this control socket on Linux; other platforms return an explicit unsupported-platform error.

The first-run window opens visibly. On Linux, the shell starts the sibling `raiun-agent serve` executable when it cannot connect to the per-user control socket; it never searches `PATH`. Tauri's single-instance handler brings the existing window forward when the launcher is opened again. Closing the main window destroys that webview while the tray keeps the shell alive, and selecting Open recreates it. The tray menu's Quit item exits the shell only; the agent continues. If the desktop session cannot create a tray icon, closing the window exits the shell so it cannot become hidden and inaccessible; the agent process continues and the launcher can open the shell again.

## Agent message shape

The frontend invokes `request` with `{ "message": { "action": "...", ... } }`. The host writes one newline-terminated JSON request to the agent socket and reads one newline-terminated response, capped at 1 MiB. The write timeout is 10 seconds; responses allow 65 seconds for sign-in discovery and 10 seconds for other actions. Successful responses return their `data` to the frontend. Agent rejections are surfaced as UI errors.

Authentication URL opening is owned by the Rust host: only a successful `auth_begin` response with an HTTPS URL and a host is opened in the system browser. Tokens remain in the agent. The host also exposes a narrowly scoped cloud-folder opener that obtains the path from agent status instead of accepting an arbitrary frontend path.

`--background` starts the tray without a webview when a tray is available. Tray status refreshes at startup and every 15 seconds. Settings can list saved upload copies through the bounded, read-only `recoveries` action, including while disconnected. Manual close/reopen and actual desktop-login startup acceptance are tracked in [MVP acceptance](../docs/MVP-ACCEPTANCE.md).

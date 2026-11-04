# Server document apps

Android 1.3.3 connects the ordinary file menu's **Open in web app** action to the existing server-provider chooser ([issue #21](https://github.com/phillip9933/raiun/issues/21)). **Open with** still prepares a local copy for another Android app. The chooser explains that distinction.

The server advertises providers and compatible MIME types. Raiun lists matching choices, requests a fresh server grant for browser opening, or uses the existing embedded viewer/editor on supported Android profiles. An empty provider list and a failed/denied discovery have distinct messages. This action does not add a third-party native Office connector or guarantee simultaneous editing for every provider/edition.

Account availability, app lock, credential-session leases, current resource identity and Space availability are checked by the existing service before and after network preparation. Known encrypted paths are denied, including stale ordinary catalog rows. The vault browser does not offer this server action. Account switching discards the chooser; embedded sessions and pending browser handoffs retain their lifecycle/screen-lock cleanup.

The browser path uses a new server-origin handoff grant, never an embedded launch token or a local file URI. The embedded path retains its origin/TLS/cookie isolation and browser fallback. See [server connections](SERVER-CONNECTIONS.md) for editor client-certificate limits. Opening a local snapshot through another app is not evidence of a live collaborative server session.

To test a supported deployment, open an ordinary Office file's action menu, select **Open in web app** and choose the configured provider. Confirm that edits save to the same server file. Two-user co-editing, mobile edition/licensing and provider-specific browser behavior require their own live acceptance. No encrypted file is implicitly decrypted for an Office server.

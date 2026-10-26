# Raiun Android 1.2.0

- Show a popup when an app update is available, with clearer update settings and release links.
- Improve browsing and backup selection in large folders.
- Add optional local server routing on selected Wi-Fi and Android-managed client certificates for supported server setups.
- Update the scanner and updater libraries, and tidy up settings buttons and language selection.

Install over your existing Raiun app to keep your accounts and files.

The new server connection settings have deployment limits: local routing keeps the public HTTPS hostname, and client certificates do not add OAuth certificate-bound token support. Real Wi-Fi/server and browser/identity-provider/KeyChain acceptance is still pending. See [server connections](SERVER-CONNECTIONS.md), [known limitations](../README.md#known-limitations) and [testing](TESTING.md).

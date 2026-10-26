# Server connections

Android 1.2.0 adds these optional connection settings. Real Wi-Fi/server and browser/identity-provider/KeyChain acceptance remains pending; see the verification scope below. Open **Server connection** from sign-in before Continue, or from Settings for the current account.

Connection preferences apply to the canonical server address and are shared by accounts using that address. They do not change account IDs, authentication issuers, file URLs, encrypted-location identities or existing backup destinations. Removing the final account for a server removes its local connection preferences; it does not delete a system certificate.

## A local address on selected Wi-Fi

Enable Wi-Fi routing, enter the local HTTPS address and the exact Wi-Fi name, then save. **Use current Wi-Fi** requests Android's permission to read the connected network name. Android requires precise location permission and enabled Location services for that information. Raiun does not request background location or bind the entire app process to a network. If Android withholds the Wi-Fi name, or a VPN or another network is active, Raiun uses the public route.

The local address is an alternate connection address for the same server. It must expose the same HTTPS port and base path, accept the public hostname and present a certificate valid for that hostname. For example, `https://drive.example.org` can connect to `https://192.168.1.20` on selected Wi-Fi when that local server serves `drive.example.org` with its valid certificate. A different port/path or a certificate valid only for the local IP is unsupported. Split DNS is another way to provide the same deployment arrangement without this app preference.

Request URLs, HTTPS hostname verification, certificate pins and the HTTP Host header remain canonical. Only the canonical server hostname receives the local DNS substitution; a separate identity provider retains its own public DNS name. A same-host request using a different port is refused while local routing is active because DNS cannot distinguish ports. The local route binds connections to the selected active Wi-Fi and uses direct connections rather than a system HTTP proxy. The Public preference disables local routing. No fallback to HTTP, ignored certificate errors or silent retry against a second endpoint is introduced.

A network or preference change refuses the next request made by a stale client before sending it. Refresh or retry creates a new connection; transfers use bounded recovery for that unsent refusal. An already transmitted request can still have an uncertain outcome and follows the existing transfer reconciliation and conditional-write rules. A local endpoint that cannot be reached reports an error; Raiun does not replay a write against the public endpoint automatically.

## TLS client certificates for OIDC deployments

Select a certificate using Android's system certificate picker and explicitly list the HTTPS origins that may receive it, one per line, such as `https://login.example.org`. An origin contains the scheme, hostname and optional port, with no path. Include the cloud origin only when that endpoint also needs the same identity. Android must already have a suitable client certificate/private key installed or provisioned; Raiun does not import or export private keys.

Raiun stores only the selected alias, certificate fingerprint and origin bindings in app-private storage excluded from Android backup. Private-key operations use Android KeyChain. Expired, replaced or unavailable identities require the user to review the preference. Removing the preference stops new requests through an old configured client. Normal server certificate/hostname validation and existing pins remain enabled. Certificate-configured clients use HTTP/1.1 to prevent HTTP/2 connection coalescing from carrying an authenticated connection to a different origin. Other origins, including the public app updater, do not receive this client certificate.

This supports TLS client-certificate requirements at a configured server or identity-provider boundary. OIDC remains authorization code with PKCE and public-client registration. It does **not** implement OAuth `tls_client_auth`, `self_signed_tls_client_auth`, mTLS endpoint aliases or certificate-bound access tokens. Such deployments need separate protocol and registration support; successful TLS login is not proof those modes are supported.

The authorization page opens in a separate browser, which controls its own client-certificate permission and selection. Granting Raiun access does not grant the browser access or guarantee both use the same certificate. Embedded office-editor WebViews still reject client-certificate requests; this feature does not add editor mTLS support.

## Verification before release

Use synthetic identities and a test deployment. Check selected versus other Wi-Fi, unavailable location permission, VPN, public override, wrong TLS identity, disconnected local endpoint, foreground/background changes, transfers and process recreation. Check certificate selection/cancellation, expiry/replacement/removal, unrelated origins and OIDC discovery/code exchange/refresh. Existing non-mTLS authentication and ordinary/encrypted data must remain usable.

Automated host tests are useful but do not establish Android KeyChain provisioning or a real browser/IdP combination. Record API 26/current Android and physical-phone results separately before release. Never include keys, token values, SSIDs, internal addresses or certificate subject details in public reports.

## Platform and protocol references

- [Android KeyChain](https://developer.android.com/reference/android/security/KeyChain)
- [Android WifiInfo and location-sensitive fields](https://developer.android.com/reference/android/net/wifi/WifiInfo)
- [Network-specific sockets and DNS](https://developer.android.com/reference/android/net/Network)
- [NetworkCallback location-information flag](https://developer.android.com/reference/android/net/ConnectivityManager.NetworkCallback)
- [OAuth mTLS: RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html)
- [OAuth for native apps: RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html)

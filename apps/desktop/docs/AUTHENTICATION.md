# Desktop authentication and compatibility

The new validation described here is an unpublished Desktop candidate. It is
not a claim that installed Desktop 0.7.4 binaries contain these changes.

Desktop is a public native OAuth authorization-code client using an external
browser, S256 PKCE and a temporary loopback listener. The cloud server's
authenticated APIs determine cloud identity and access. Unverified token issuer
hints may improve an error message; they do not authenticate an account.

This profile maps the relevant fixes from Android 1.3.0 (`c45ea07`) and the
[Android 1.3.1 authentication review](https://github.com/phillip9933/raiun/blob/6c60f787a7e116aea47932d3e9ca66296f22bf7b/apps/android/docs/AUTHENTICATION.md)
to Desktop's own contract. It is not a universal shared specification or an OIDC
relying-party conformance certification. Source validation is separate from
packaged and live-provider acceptance.

## Discovery and browser return

- WebFinger requests `platform=desktop`. An explicit Desktop client-ID override
  is retained; otherwise an advertised ID is used, followed by the existing
  `OpenCloudDesktop` fallback. Android's client ID and redirect URI are not used.
- Advertised scope arrays support individual tokens and ASCII-space-grouped
  strings, including custom tokens containing commas. Tabs, newlines and other
  controls are rejected rather than silently rewritten. Existing Desktop manual
  client behavior can add `offline_access`; this differs from Android's selection
  policy and does not change server-side permissions.
- Issuer identifiers retain their exact spelling. URL transport validation does
  not normalize the identifier used for comparison. Query strings, fragments,
  surrounding whitespace and controls are rejected in issuer identifiers.
- Missing optional flow-capability lists preserve legacy discovery. Present
  lists must support code responses, authorization-code grants and S256. An
  authorization endpoint cannot prepopulate the OAuth parameters that Desktop
  appends; unrelated query parameters remain intact.
- State and PKCE verifier values are generated independently. Pending flows stay
  in memory, expire after ten minutes and are consumed by the waiting flow.
  Restarting the agent does not restore a pending browser sign-in. Cancellation
  and expiry are checked again after callback reading and before exchange.

The callback rejects duplicate state, code, error or issuer parameters, malformed
percent/UTF-8 encoding, unexpected paths and fragments. Request-line decoding is
strict: malformed bytes are not transformed into another authorization code.

### Response issuer support

Desktop requires one exact matching callback `iss` when discovery advertises the
boolean `authorization_response_iss_parameter_supported: true`. Any supplied
issuer must match, even when that flag is absent or false. These checks precede
code exchange and also apply to error responses. See
[RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4).

Legacy providers that omit this optional extension can still return a callback
without `iss`. This preserves existing deployments, but is not complete mix-up
protection for a client interacting with multiple authorization servers. State,
PKCE and remembered endpoint URLs must not be presented as an equivalent proof.
Registered redirects are not silently changed by this work.

## Tokens, refresh and saved accounts

Token responses are validated before constructing a replacement session:

- Access tokens must fit the bounded Bearer-token grammar. `token_type` must be a
  string equal to `Bearer` without regard to case. Token bytes remain opaque and
  unchanged. Authorization headers already use canonical `Bearer`; Desktop's
  saved-session format has no token-type field to migrate.
- An omitted lifetime uses 3,600 seconds. Present integer or integer-string
  lifetimes must be positive and at most one year. Desktop retains this bound;
  Android's zero-lifetime acceptance and upper clamping are not copied.
- Missing or null refresh-token/scope metadata is absent. Malformed present
  metadata is rejected. Refresh retains an omitted replacement refresh token.
  Scope text is validated, but is not saved as a local permission grant or used
  to bypass a server access decision; no scope snapshot or session schema is added.
- Only explicit `invalid_grant` is a terminal rejected refresh grant. An opaque
  HTTP 401, proxy error or `invalid_client` preserves the saved user grant.
  Client-registration problems do not establish that the user's grant was revoked.
  Existing account, generation, cancellation and credential-write fences remain.

This does not add a new Unix startup retry policy: a non-transport refresh error
can still require attention. It does not relax Graph/DAV authorization failures.
Linux Secret Service and Windows CurrentUser DPAPI locations and formats remain
unchanged. Headless memory-only OAuth and its separate Basic/app-token route keep
their own admission and persistence rules; Bearer response parsing is not applied
to that Basic route.

## Verification boundaries

Synthetic tests cover initial exchange, callback refusal before token exchange,
legacy issuer omission, required/mismatched/duplicate issuer handling, cancellation
and expiry at the callback boundary, strict token metadata, refresh rotation and
preservation after nonterminal errors. HTTP fixtures explicitly declare their
Bearer token type. Tests and cross-compilation do not establish successful
Authelia/Authentik sign-in on a real deployment, final package upgrade behavior,
or complete OIDC/RFC 9700 conformance. Existing native and release evidence keeps
its original source scope.

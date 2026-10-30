# Authentication and interoperability

This guide describes Raiun's supported authentication profile and the
authentication review for Android 1.3.1. A source review and automated checks are not a conformance certification
or a guarantee for every identity-provider configuration.

## Supported profile

Raiun is a public native OAuth client using the authorization-code flow with S256
PKCE and an external browser. It uses OIDC discovery to find the provider and
OpenCloud's authenticated OCS current-user endpoint to identify the cloud account.
The account remains bound to the canonical OpenCloud server and its OCS user ID.

Raiun does not consume an ID token as its identity assertion or implement a generic
OIDC relying party. It therefore does not claim complete OIDC Core relying-party
conformance. Access tokens stay opaque; Raiun does not decode their JWT claims to
decide which cloud user has signed in. The configured server validates resource
access. See [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html).

The public-client registration must permit `app.raiun.cloud://oauth`. Dynamic
registration requests authentication method `none`; static registrations must be
configured appropriately by the administrator. Client secrets, implicit grants,
OAuth certificate-bound tokens and DPoP are outside this profile. Existing scoped
TLS client certificates remain separate; see [Server connections](SERVER-CONNECTIONS.md).

## Discovery and browser return

- OpenCloud WebFinger uses `platform=android`. Advertised client IDs and scopes
  take precedence, including custom scope names and OpenCloud's grouped scope
  strings. Without advertised scopes, the existing legacy provider-scope fallback
  remains; this is not a substitute for an administrator's client-specific scope
  policy. Configure the Android WebFinger scopes explicitly where custom claims
  control access or group membership.
- HTTPS endpoint validation is separate from exact issuer-identifier comparison.
  Issuer spelling is preserved rather than treating URL normalization as identity.
- The request uses independent random state and PKCE verifier values, with a
  SHA-256 challenge. Existing provider query parameters are retained, but may not
  duplicate parameters owned by the OAuth request builder. Advertised flow
  capabilities must support code, authorization-code grants and S256 when present.
- Pending state is encrypted, expires after ten minutes and is consumed once.
  The return URI, state and code are validated before exchange. No code or verifier
  is sent on a rejected issuer response.

### Issuer response support

The `iss` parameter in a browser authorization response is an extension defined by
[RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4). It is distinct
from the issuer claim inside an OIDC ID token.

Raiun requires a unique matching callback `iss` when the provider advertises
`authorization_response_iss_parameter_supported: true`. Any supplied `iss` is
validated exactly, even when support was not advertised. A provider that omits
that advertisement may return a response without `iss`; this preserves existing
Authentik-style deployments. Malformed metadata flags and duplicate, blank or
mismatched supplied issuers are rejected with a fixed error.

This capability-aware behavior does **not** establish complete mix-up protection
for legacy providers that supply no response issuer. [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4.2)
requires a countermeasure for clients interacting with multiple authorization
servers. A provider-supported response proof or separately registered
issuer-specific redirect is needed to close that legacy gap. State, PKCE and
remembered endpoint URLs alone must not be presented as equivalent protection.
Raiun does not silently change existing registered redirect URIs or require this
optional extension from every provider.

## Tokens, refresh and stored accounts

Token responses are validated before persistence. Access tokens and token types
must be nonempty strings, and the token type must be Bearer, matched without case
sensitivity. HTTP authorization always uses canonical `Bearer`; the opaque token
itself is never lowercased or trimmed. This also applies to previously saved
lowercase token types. Malformed header values cannot escape through an HTTP
builder's diagnostic message. See [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1).

Present invalid expiry, refresh-token or scope metadata is rejected instead of
silently replacing a usable grant. An omitted lifetime retains the existing
one-hour fallback, and a supplied lifetime remains bounded to one year. Integer
strings are accepted for provider interoperability; negative, fractional and
otherwise malformed values are rejected. Optional null refresh/scope values are
treated as absent. These compatibility choices are explicit; providers should
return the types defined by [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749#section-5.1).

Refresh is serialized per account. An omitted replacement refresh token or scope
retains the previous value; a valid replacement is committed together with its
access-token metadata. An explicit `invalid_grant` requires reauthentication, and
an explicit `invalid_client` invalidates the client binding. An unexplained
token-endpoint HTTP 401, proxy response or temporary failure preserves the stored
grant. Account removal waits for an active refresh and prevents its result from
resurrecting the removed credentials.

Credential encryption, aliases, account IDs and offline data formats are unchanged
by these fixes. New pending-login records retain the issuer-support flag; older
pending records remain readable. Restoring existing saved accounts does not start
a new browser login or require this optional response extension.

## Verification boundaries

Regression coverage targets stored lowercase token types, initial authorization
headers, malformed token responses, non-destructive refresh failures, token
rotation, exact issuer comparisons, callback rejection before exchange, legacy
issuer compatibility and pending-state restoration. See the executed local results
in [Testing](TESTING.md); earlier release results retain their own source scope.

No live provider settings, group memberships or production credentials were changed
for this review. Unauthenticated public metadata reads are not a successful live
sign-in, and existing provider-version differences remain deployment-specific.

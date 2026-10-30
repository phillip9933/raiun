# Raiun Android 1.3.1

### Bug fixes

- Fix sign-in with Authelia where login succeeded but Personal files, Spaces or shared files then failed to load. This also fixes affected accounts already saved on the phone.
- Stop unexplained login-server or proxy errors from unnecessarily clearing saved sign-in credentials. Raiun now distinguishes these failures from a provider explicitly rejecting the saved grant.

### Improvements

- Check login settings and token responses more carefully before sending credentials or replacing a saved session. Refreshes retain the existing refresh token and permissions when the provider omits replacement values.
- Improve login-provider identity checks while keeping compatibility with Authentik and other providers that do not implement the optional browser-response issuer extension.

Install over your existing Raiun app to keep its data. These fixes have automated regression coverage; the reporter's live Authelia deployment has not been retested. See the [authentication guide](AUTHENTICATION.md) for the supported profile and remaining security boundaries.

# Raiun 0.1.0-beta.3

Raiun is an independent Android client for OpenCloud. This beta introduces the Cloud crest identity while retaining the existing file, sharing, offline, backup and scanning features.

## Changes

- Raiun name, original launcher/themed icon and light/dark branding throughout the app.
- Android application ID `app.raiun.cloud`; OAuth redirect `app.raiun.cloud://oauth`. Administrators using a static OIDC client must allow this exact redirect. The client ID remains the value configured by the administrator.
- Correcting a manually supplied client ID now replaces a previously cached static ID.
- Recycle-bin overview with separate personal and project-space bins.
- Space menus for opening, viewing details and permitted management actions. Advanced actions can open the server's web interface.

## Installation and limitations

Android 8.0/API 26 or newer; arm64-v8a and x86_64. This remains a personal-project beta, not an official OpenCloud GmbH release.

Raiun has a new Android package identity and installs separately from the former app. This release keeps the existing signing certificate.

Large transfers during mobile/Wi-Fi changes can restart or require retry. Server and reverse-proxy HTTP 502/timeouts remain environment-dependent. Space management depends on account permissions and server support. Physical-device acceptance does not cover every server, Android version or OEM.

The APK is signed locally. The attached checksums, public signing certificate, license and corresponding source archive support verification. Private signing material is never included.

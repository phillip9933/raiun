# Credential storage

This describes Android 1.3.3 credential storage for [issue #54](https://github.com/phillip9933/raiun/issues/54). Publication and executed validation are recorded separately in [Testing](TESTING.md).

## Stored records

Raiun uses private `secure_credentials` preferences and AES-GCM with the original Android Keystore alias `opencloud.next.credentials.v1`. Records include Basic usernames/passwords, OAuth tokens, client registrations and pending browser-login state. This store is distinct from vault unlock keys and biometric/device-remember preferences.

New records use `v2:<base64 IV>:<base64 ciphertext and authentication tag>`. Authenticated associated data contains length-delimited UTF-8 fields for the application/store domain, envelope version and exact full preference key. An account identifier is part of each account-owned key; pending login uses its dedicated key. Moving a v2 ciphertext to a different account or credential slot fails authentication. Unknown versions and malformed or unauthenticated records are unavailable; a failed v2 read never falls back to legacy interpretation.

## Legacy migration

The original `IV:ciphertext` format remains readable with the same Keystore key. A read authenticates the ciphertext and validates the decoded record against its expected type before replacing the envelope in one checked preference commit. Token validation follows the existing supported Bearer/scope profile, including expired but structurally valid tokens that can still be refreshed. Malformed records are not rewritten. Pending state retains its lifetime/state checks; a matching callback consumes the record after checked removal rather than rewriting it first.

One process-wide state lock serializes reads, migrations, writes, invalidation and removal across store instances. Migration cannot publish a stale snapshot after a concurrent refresh or removal. Credential replacement/removal retains the existing vault-ledger revocation order: ledger, credential state, then key initialization. Network-refresh/account lifetime fences remain responsible for rejecting stale network results.

An unavailable or missing key never causes a read or migration to generate a replacement. A failed migration returns no usable record and emits only a fixed diagnostic category. It does not delete the old entry. Android preference commits can update the process-visible map before reporting a disk failure: this is not rollback or a crash-proof exactly-once transaction. Pending login is returned only after successful removal; persistent storage failure is not a durable replay-prevention guarantee across process restarts.

## Boundaries

AAD protects v2 record substitution by someone able to manipulate stored app data without using the protected key. It cannot recover historical account binding from legacy ciphertext, prevent replay of an entire valid old snapshot, or protect against a fully compromised application/OS. Legacy migration is a compatibility path, not retroactive proof of origin.

No key alias, account ID or vault encryption format changes. Older Raiun builds cannot read v2 records; downgrade is unsupported after writes/migration. A failed read preserves the stored record for investigation or explicit sign-in recovery. Diagnostic output must never contain credential values, plaintext, slot/account identifiers or exception payloads.

# Vault directory-name batches

`VaultSessionCoordinator::decode_directory_names` decodes one directory listing
through the verified session for the complete account, server-origin, Space,
and DAV-resource scope. The coordinator holds its registry lock for the whole
bounded operation, so a concurrent lock or account logout cannot interleave
with the batch.

Before decoding, the API rejects more than 10,000 entries, more than 2 MiB of
encrypted-name input, names longer than the codec's 3,277-byte limit, path
separators, and duplicate ciphertext strings. It then validates every decoded
component for portable filesystem use and rejects duplicate decoded names under
Unicode compatibility caseless matching. The complete vector is returned only
after every entry passes. Errors do not include names. Failed batches do not
publish partial results, but temporary plaintext strings are not promised to
be securely erased. Normalized collision keys are bounded to 4 KiB each and
4 MiB total; this bounds compatibility-decomposition expansion during a batch.

Collision keys use the compatibility-caseless sequence from Unicode's default
case algorithms: NFD, full default case folding, NFKD, full default case
folding, then NFKD. The implementation uses `caseless` 0.2.2 and the exact
`unicode-normalization` 0.1.24 pin; both provide Unicode 16.0.0 data. Their
Unicode data versions are exposed as `UNICODE_VERSION` and are covered by the
locked dependency versions.
This conservative policy rejects compatibility and case-fold-equivalent names
even when a particular filesystem might distinguish them. The output keeps the
original decoded spelling; no name is silently rewritten. This policy does not
claim exact equivalence with every platform filesystem.

Batch success establishes only that the supplied names are bounded, portable,
and unambiguous under this selected collision policy. It does not authenticate
the names or prove that the listing is complete. The vault's authenticated root
token verifies key compatibility, while EME-encrypted names do not carry an
independent authentication tag. Listing metadata and server honesty remain
outside this codec's guarantees.

References: [`caseless` API and Unicode version](https://docs.rs/caseless/0.2.2/caseless/),
[`unicode-normalization` 0.1.24 API and Unicode version](https://docs.rs/unicode-normalization/0.1.24/unicode_normalization/),
and [Unicode 16.0 Core Specification, Default Case Algorithms](https://unicode.org/versions/Unicode16.0.0/core-spec/chapter-3/).

## Encoding new names

`encode_directory_names` validates proposed names against the complete supplied
remote sibling list with the same bounds and compatibility-collision policy.
The write adapter reads siblings before creating/renaming an item, excludes
only the exact resource being replaced, and still sends conditional HTTP
headers. This preflight cannot guarantee a malicious or concurrently changed
server listing is complete. No partial encoded batch is returned on failure.

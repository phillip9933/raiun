# Read-only vault metadata discovery

`raiun_opencloud::vault::VaultMetadataClient` is a separate, read-only surface
for discovering folder vaults in a selected, non-encrypted Graph Space. It
resolves the Space by its configured ID through `OpenCloudClient::spaces()`;
callers cannot provide a DAV root URL. Requests are authenticated by the
existing client, remain on the configured origin, use `Depth: 1`, and parse at
most 2 MiB of XML, 10,000 responses, 32 nested elements, and 4 KiB per field.
Redirects are not followed. The implementation does not GET file contents or
perform any server mutations.

Discovery considers only immediate directory children. A collection is
reported as a candidate when its raw name ends with `.vault` (case-insensitive),
it has a nonempty `ocrclone:integrity-id`, or its content type is
`application/vnd.opencloud.vault`. These are server-provided hints, not
authentication. Discovery rejects a selected parent that itself has vault
signals, so it does not promise traversal inside an encrypted folder.

The returned `VaultRootListing` includes raw IDs, paths, sizes, ETag hints,
the optional root integrity token, and the untrusted evidence that selected
the folder. Resource IDs are not globally unique: key them by server/account,
Space ID, and resource ID. ETags are revision hints and do not authenticate
metadata. A `raiun-vault` verified session authenticates the vault token and
content blocks; it does not authenticate DAV lengths, IDs, names, ETags, or root
hints. Those values remain untrusted. An expected content length must come from
an independently trusted source before it can be used to detect complete-block
truncation. The integrity token remains opaque until a verified session
validates it against the user-supplied password. No password or derived key
enters this API. UI code must not treat raw metadata as verified plaintext.

`inspect_vault` also accepts `/` for a Graph-marked encrypted Space and binds
it to the stable DAV root resource ID returned by PROPFIND. An ordinary Space
root is rejected. The explicitly named folder-vault API retains its original
restriction to non-encrypted Spaces. The crate-private raw inspector supports
Depth 0 file metadata and Depth 1 directories for the verified write adapter;
raw metadata never authorizes plaintext access by itself.

The XML reader rejects DTDs and undeclared entities, requires same-origin,
Space-scoped hrefs, direct-child listings, unique resource IDs and paths, a
collection root, and a valid HTTP status line for every DAV propstat. Valid
non-200 propstats are ignored; missing or malformed statuses fail closed.
Conflicting DAV `getcontentlength` and OpenCloud `oc:size` values are rejected.
These checks protect request scope and parser resource use; they do not prove
the server is honest. A malicious server can truncate a ciphertext at a
complete cipher-block boundary without a cryptographic failure unless an
independent trusted source supplies the expected length.

Integration must use the scoped batch validator described in
[VAULT-DIRECTORIES.md](VAULT-DIRECTORIES.md) for decoded-name collisions and
portable component checks. Safe host-path joining remains an integration
responsibility. This module
preserves server names and does not rewrite them. It is not a synchronization
backend and must not bypass the ordinary encrypted-path guard in
`CloudBackend`.

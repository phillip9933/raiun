# OpenCloud Web vault write contract

Research date: 2026-10-10. This is a source audit, not a live-server test. The Web source is pinned to OpenCloud Web v8.0.0, commit `11e699ac82fda4dd113ac3ceb2ecb2dd74574045`; the server mapping is pinned to OpenCloud Server v7.5.0, commit `cd9095833af0ba1dc7449194e62799931d38a7b1`. The contract below describes that Web implementation and its generic WebDAV client. It does not claim that every server deployment accepts every request identically.

## Creating a vault root

A folder vault has a cleartext root folder whose name ends in `.vault`; only descendants have encrypted names. Web creates that root with ordinary WebDAV `MKCOL` at its cleartext path. Afterward, the setup component creates an integrity token and sends a separate `PROPPATCH` to the root. The property key is `ocrclone:integrity-id`. Web explicitly supplies it as an extra property so the client emits the `ocrclone` namespace, whose URI is the literal string `ocrclone`:

```http
MKCOL /<space-webdav-path>/<parent>/Project.vault
```

```http
PROPPATCH /<space-webdav-path>/<parent>/Project.vault
Content-Type: application/xml; charset=utf-8

<d:propertyupdate xmlns:d="DAV:" xmlns:ocrclone="ocrclone">
  <d:set><d:prop>
    <ocrclone:integrity-id>BASE64_RCLONE_CIPHERTEXT</ocrclone:integrity-id>
  </d:prop></d:set>
</d:propertyupdate>
```

The token is a random UUID encrypted using the vault's rclone-crypt content cipher, with a fresh nonce, then base64 encoded for the XML text value. Web validates it by attempting authenticated content decryption; it does not require the decrypted UUID to have a particular shape. The property is arbitrary custom metadata in this Web implementation; Server's Graph code maps the separate Space `contentType` field but has no `ocrclone:integrity-id` special case in the audited source.

The two writes are not atomic. Web's setup flow reports that the folder was created but its password was not saved if the token `PROPPATCH` fails; it leaves the root in place. A client implementing creation should represent this partial state and provide a retry path rather than claiming that creation failed wholly or silently pretending unlock will work.

A vault Space uses a different root marker. Web sends an authenticated Graph request:

```http
POST /v1.0/drives?template=none
Content-Type: application/json

{"name":"Project archive","@libre.graph.contentType":"application/vnd.opencloud.vault"}
```

`template=none` prevents the normal `.space` folder template from being created. Server v7.5 stores the Graph `LibreGraphContentType` value as opaque Space metadata `contentType` and maps that value back into the Graph drive response. Once the Space exists, Web writes the same integrity property with `PROPPATCH` at the Space root path `/`. The Graph creation and root property write are separate requests, so the same partial-creation handling applies.

The folder suffix and Space content type are discovery markers, not cryptographic proof. The integrity token's successful decryption is the password check. Neither marker hides the root's cleartext name.

## Writing descendants

Web's vault DAV wrapper encrypts every descendant path relative to the root and leaves the root path itself unchanged. Its `Cipher('base32')` engine applies rclone-crypt EME filename encryption per path segment. Content uploads through the wrapper encrypt the file bytes as an rclone-crypt content blob before the request; the inspected Web v8 engine buffers the whole plaintext file and emits one encrypted blob, so this implementation is not streaming.

| Operation | WebDAV behavior in Web v8 |
| --- | --- |
| File `PUT` through `VaultWebDav.putFileContents` | Encrypts both content and descendant path, then delegates to `PUT`. The lower-level DAV helper sends `If-Match: <etag>` when `previousEntityTag` is supplied. Otherwise it sends `If-None-Match: *` when `overwrite` is false or omitted (the default); with `overwrite: true` and no etag it sends neither condition. |
| Child folder `MKCOL` | Encrypts the descendant path, then sends normal `MKCOL`; the folder root itself remains cleartext. No automatic conditional header is added. |
| `MOVE` | Encrypts source and destination paths and sends `MOVE` with `Destination: <absolute DAV URL>` and `Overwrite: T` or `F` (default `F`). No automatic ETag precondition is added. Same-vault moves leave ciphertext bytes on the server. Do not use this as a cross-vault or plaintext/vault re-encryption operation. |
| `DELETE` | Encrypts a descendant path and sends normal `DELETE`; the root path is not encrypted. No automatic ETag precondition is added. |
| Integrity-token `PROPPATCH` | Targets the cleartext vault root and writes the custom property above. No automatic conditional header is added. |

There is an important upload-path distinction: the direct `VaultWebDav.putFileContents` API has the conditional `PUT` behavior in the table, but the normal file-upload UI uses Uppy. `HandleUpload` prepares encrypted path endpoints and encrypted file data; with Tus enabled, the request goes through TUS, while the XHR fallback uses `PUT`. The inspected Uppy configuration does not add `If-Match` or `If-None-Match` for either route. Do not claim conditional conflict protection for the normal UI upload path based only on the direct DAV helper.

The Web DAV request builder's default content-type is `application/xml; charset=utf-8`, including its generic requests; the encrypted upload body itself is produced as ciphertext bytes. A production client should verify how its HTTP stack sets content type for file `PUT` and upload/TUS requests instead of copying that generic default blindly.

## Sources

All code links below are pinned to the audited commit. Server links are pinned separately.

- [Vault extension markers and root lookup](https://github.com/opencloud-eu/web/blob/11e699ac82fda4dd113ac3ceb2ecb2dd74574045/packages/web-app-rclone-crypt/src/vaultLocation.ts)
- [Vault setup and post-create finalization](https://github.com/opencloud-eu/web/blob/11e699ac82fda4dd113ac3ceb2ecb2dd74574045/packages/web-app-rclone-crypt/src/components/VaultSetup.vue)
- [Integrity property name, namespace opt-in, and storage call](https://github.com/opencloud-eu/web/blob/11e699ac82fda4dd113ac3ceb2ecb2dd74574045/packages/web-app-rclone-crypt/src/integrity.ts)
- [Rclone cipher, filename/content encryption, and token format](https://github.com/opencloud-eu/web/blob/11e699ac82fda4dd113ac3ceb2ecb2dd74574045/packages/web-app-rclone-crypt/src/crypto/engine.ts)
- [Space Graph creation, `template=none`, and root finalization](https://github.com/opencloud-eu/web/blob/11e699ac82fda4dd113ac3ceb2ecb2dd74574045/packages/web-pkg/src/composables/spaces/useCreateSpace.ts)
- [Vault path/content transforms for DAV calls](https://github.com/opencloud-eu/web/blob/11e699ac82fda4dd113ac3ceb2ecb2dd74574045/packages/web-pkg/src/services/client/vaultWebDav.ts)
- [DAV request headers for PUT, MOVE, and PROPPATCH](https://github.com/opencloud-eu/web/blob/11e699ac82fda4dd113ac3ceb2ecb2dd74574045/packages/web-client/src/webdav/client/dav.ts)
- [DAV XML namespace and PROPPATCH body builder](https://github.com/opencloud-eu/web/blob/11e699ac82fda4dd113ac3ceb2ecb2dd74574045/packages/web-client/src/webdav/client/builders.ts)
- [Uppy upload endpoints and cleartext path metadata handling](https://github.com/opencloud-eu/web/blob/11e699ac82fda4dd113ac3ceb2ecb2dd74574045/packages/web-app-files/src/HandleUpload.ts)
- [TUS/XHR setup](https://github.com/opencloud-eu/web/blob/11e699ac82fda4dd113ac3ceb2ecb2dd74574045/packages/web-pkg/src/services/uppy/uppyService.ts)
- [Generated Graph `createDrive` endpoint and request shape](https://github.com/opencloud-eu/web/blob/11e699ac82fda4dd113ac3ceb2ecb2dd74574045/packages/web-client/src/graph/generated/api.ts)
- [OpenCloud Server Graph mapping of drive content type](https://github.com/opencloud-eu/opencloud/blob/cd9095833af0ba1dc7449194e62799931d38a7b1/services/graph/pkg/service/v0/drives.go#L362-L438)

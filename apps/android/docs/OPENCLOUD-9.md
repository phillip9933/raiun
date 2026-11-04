# OpenCloud 9 compatibility

Reviewed against the published [OpenCloud 9.0.0 rolling release](https://github.com/opencloud-eu/opencloud/releases/tag/v9.0.0), released 27 October 2026, and its bundled Web 8.2.0. This is a source/protocol review; it is not acceptance against a running 9.0 deployment. The production 9.1 release remains a separate compatibility target.

## Existing accounts and encrypted locations

No change to Raiun's application identity, saved account formats, signing identity or existing encrypted data is required by the reviewed release. Web 8.0.0 and 8.2.0 use byte-identical `engine.ts`, `integrity.ts` and `resolveVault.ts` implementations and the same pinned rclone-crypt dependency. This supports continued interoperability; it does not replace cross-client read/write testing on a 9.0 server. Password-policy and navigation changes are not a new encryption format. The proposed server-side S3 SSE-C work is distinct from client-side vault encryption.

## Thumbnails and server upgrades

The [new thumbnail pipeline](https://github.com/opencloud-eu/opencloud/pull/3397) changes server configuration and processing, while retaining the DAV preview request contract used by Raiun (`preview=1`, explicit x/y and aspect handling). Raiun requests 128×128 previews, bounds response bytes and decoded dimensions, and does not download full cloud files as a preview fallback. Verify images, videos, shared resources and unavailable formats after upgrading; generator configuration can change which formats have previews. Encrypted previews remain local after unlocking.

Operators must follow the server's [9.x upgrade instructions](https://docs.opencloud.eu/docs/next/admin/maintenance/upgrade/upgrade-9.x.x). Guest links are disabled by default and require `OC_ENABLE_GUEST_LINKS=true`, the auth-guest service and correctly configured signing secrets/mail delivery. Raiun does not activate or change server configuration.

## Guest links

The server protocol is documented in the tagged [auth-guest README](https://github.com/opencloud-eu/opencloud/blob/v9.0.0/services/auth-guest/README.md). Raiun supports the sender workflow: signed-in users create and manage file/folder guest invitations. Recipients open the emailed invitation in the server’s web client using their browser.

Guest availability follows the explicit `capabilities.files_sharing.guest_links.enabled` boolean together with ordinary sharing support. OpenCloud deliberately reports OCS `version.string` as legacy compatibility `0.1.0`; it cannot identify the actual product release or gate guest invitations. Missing or malformed guest advertisement disables guest support without breaking ordinary capabilities. This is feature discovery, not a permission grant: the server still checks the user and resource for every operation.

An item with no existing permissions has a valid Graph response containing role/action annotations without a `value` key. Raiun treats absent `value` as an empty list only for permission discovery, after validating the server role metadata. Explicit null/wrong types remain errors. Invitation responses still require a present singleton permission collection; an empty or missing mutation result is not accepted as success. See the tagged [collection schema](https://github.com/opencloud-eu/opencloud/blob/v9.0.0/vendor/github.com/opencloud-eu/libre-graph-api-go/model_collection_of_permissions_with_allowed_values.go).

Sender operations use item-scoped Graph permissions and email invitations. They are separate from OCS user/group shares and public links; numeric OCS share types do not reliably identify guests. Role choices come from the server's allowed values, and mutations refresh those permissions. A server's guest invitation policy can still deny an invitation even when ordinary sharing is allowed. No mutation is used to detect support. File/folder guest sharing is the initial scope; Web 8.2.0 also disables guest invitations to Space roots.

Received guest invitations are handled in the browser. Raiun does not provide native invitation opening, URL paste/share receiving, guest browsing/downloads or guest-session renewal. Use the latest invitation email and the web client for recipient access and renewal. Raiun does not register a wildcard HTTPS guest-link handler.

## Encrypted upload continuation

The exact server 9.0.0 source still does not establish safe conditional byte-offset uploads for Raiun. Its pinned Reva v2.52.1 public TUS initiation route checks `If-Match` against an initial destination lookup, but does not pass that condition into the upload session. It does not read `If-None-Match` to preserve create-only intent. A destination can change between that initial check and upload finalization. See the [pinned dependency](https://github.com/opencloud-eu/opencloud/blob/v9.0.0/go.mod) and [public upload handler](https://github.com/opencloud-eu/reva/blob/v2.52.1/internal/http/services/owncloud/ocdav/tus.go).

Backend finalization checks and a best-effort final ETag do not repair missing conditions in the public route. Raiun therefore retains conditional whole-object encrypted-upload recovery and complete committed-ciphertext verification. Issue [#11](https://github.com/phillip9933/raiun/issues/11) stays open. A future resumable implementation needs an end-to-end conditional commit contract plus race, interruption and completion tests; generic TUS advertisement or server version alone is insufficient. This source assessment is not a live mutation test and does not rule out every alternative server API or storage driver.

The ordinary [PUT handler](https://github.com/opencloud-eu/reva/blob/v2.52.1/internal/http/services/owncloud/ocdav/put.go) does forward expected-ETag `If-Match`, unlike the reviewed TUS initiation route. Create-only `If-None-Match` propagation was not found in those handlers. The examined decomposedfs backend does atomically reject a competing name created after a new-file session is initialized; it does not fall back to overwriting that file. The remaining source-derived concern is a competing creation between the client's absent-destination check and backend session initialization. This bounded review has not established deployed unsafe behavior or exhausted global proxy middleware, so it cannot certify end-to-end create-only semantics. A fresh client preflight alone cannot prove atomicity across that interval.

## Acceptance still required

Use synthetic data on an isolated server with invitation mail under the tester's control:

- Ordinary 8.x accounts still browse, transfer, share and work offline; guest-only controls fail clearly on unsupported/disabled servers.
- Create guest invitations for files and folders; verify server roles, optional expiry, update and revocation. Confirm unrelated user/group/public shares are unchanged.
- Open a fresh Raiun-created invitation from its email in the server’s web client. Verify recipient access and the effects of expiry, permission changes and revocation there. Creating an invitation must remain an explicit sender action; opening management must not send email.
- Compare Web-created and Raiun-created encrypted folders/Spaces on 9.0, including old 8.x data, non-ASCII passwords, rename, offline access and interrupted transfers.
- Check thumbnails, permission-denied moves/deletes, same-name conflicts, eventual upload verification and full-text search only when enabled by server capabilities.

Mock protocol tests and emulator UI checks cannot establish mail delivery, deployed proxy configuration, physical biometrics or live 9.0 compatibility. Record those results separately before publication.


### Live readiness update — 28 October 2026

The owner reports successful web guest-link tests on their installed server 9.0.0 with SMTP. Earlier scoped native invalid-link endpoint checks passed on API 26/API 35 with normal DNS and verified TLS; those historical checks did not establish invitation creation, mail delivery or positive recipient access. The authenticated native probe was skipped because its dedicated development login was not configured.

The owner subsequently removed native recipient access from the candidate’s scope. Phone acceptance now covers invitation creation and management in Raiun, followed by recipient access in the browser. Previous signed phone-test APKs and their evidence remain historical artifacts; they do not establish acceptance of this sender-only candidate. No new release was published.


### Sender-only phone acceptance update — 28 October 2026

The owner tested the production-signed guest test 4 sender-only APK and reported “looks like it works fine.” This is general owner-reported acceptance of that phone candidate. Earlier test 3 acceptance separately established invitation sending and browser recipient browsing/downloading. Neither report establishes an exhaustive file/folder role, expiry, update or revocation matrix; those scoped scenarios above remain to be recorded. Native recipient access remains outside scope. Earlier pending-phone statements are historical; this update supersedes them for test 4 only. This does not clear the separately recorded native CI lock/window failures or establish a new release.

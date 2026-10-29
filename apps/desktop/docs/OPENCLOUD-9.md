# OpenCloud 9 guest invitation management — local Desktop candidate

This unpublished candidate adds native guest invitation creation and management
for Linux and Windows. Desktop's published version and Android source are
unchanged. Received-link redemption and native guest browsing are deferred at
the owner's request; they are not part of this candidate.

## Sharing workspace and automatic lists

The sidebar entry is **Sharing**. Its inventory tabs follow Android:

- **Shared with me** automatically loads the authenticated account's Graph
  shared-item inventory, including files and folders.
- **Shared by me** automatically loads outgoing OCS user/group/guest grants.
- **Public links** automatically loads outgoing OCS link grants.

Lists load when their tab opens. No item picker or query is required to discover
shares; the optional filter narrows the already-loaded list. Incoming rows
prioritize the item and who shared it. Outgoing desktop rows have explicit
column headers and reflow into labelled cards on compact windows.

**New share** is below the Shared by me list. It opens a compact method choice
(People & groups, Share links or Guest invitations), then the file/folder chooser
and access review. Creation remains bound to fresh ordinary-item metadata and
server-provided roles. Guest invitations send email only on the final explicit
action; received guest-link redemption and native guest accounts remain deferred.

People/group creation uses bounded server identity lookup and verifies the
selected identity. Public-link creation respects actual supported file/folder
link types and declared password/expiration policy. Known disabled expiration
permits a non-expiring link. Public-link creation accepts a transient password;
it is required when the server's global or per-role policy requires one. The
client treats any stricter write-category policy as requiring a password for
write links. Unknown/malformed policy blocks creation. OpenCloud 9's unsupported
`blocksDownload` creation type is not offered.

The password is sent only in the authenticated create request, never in a URL
or local settings. It is excluded from rendered HTML, draft fingerprints and
error details, and cleared from the form on submission or context changes.
Recipients need the password separately. Passwords may contain up to 72 UTF-8
bytes; server complexity/banned-password rules remain authoritative.

## Inventory identity and management boundaries

Incoming Graph shared-item IDs, target IDs, OCS grant IDs, OCS resource/Space
IDs and Graph permission IDs remain distinct. OCS IDs are never passed to a
Graph permission mutation. Incoming rows are read-only. Owned records with a
known grant type and stable resource ID can explicitly remove access through
OCS: immediately before DELETE, the agent reloads the owned category and checks
the exact grant and resource identity under the current account generation.
Unknown types/missing bindings remain visible but cannot be revoked. Editing
uses a dedicated OCS settings operation, never a guessed Graph crosswalk.

Public URLs are held in memory, excluded from rendered markup and redacted in
Debug output; Copy link is explicit. Account/server or sign-in generation changes
clear the lists, drafts and URLs. An uncertain mutation blocks repeat submission
until refresh. Removing access never deletes the item, removes independent
other grants or retracts copies already downloaded.

The inventory uses the server's account-level feeds instead of crawling files
or substituting Raiun-created history. A complete response means all returned
server-visible rows passed validation, not administrator-wide visibility.
OCS currently returns an unpaged array; incoming Graph continuation, if present,
must stay on the same origin and endpoint. Byte/item/page limits fail explicitly,
and the local reply limit rejects a serialized snapshot above 900 KiB rather
than displaying a truncated complete list. Failed refresh preserves the previous
snapshot with an error and disables its editing/removal actions until a
complete refresh succeeds. These bounds may need local IPC paging for unusually
large inventories; no unsupported server paging parameters are invented.

## Edit an existing share

Open **More actions → Edit access** on an outgoing row, or **Edit access** from
its details. The editor reloads that exact OCS grant before showing settings.
User/group grants with known file/folder and recipient identities can change
access and expiration. Public links can change name, supported access and
expiration where the server capability policy permits it. Existing public URLs
and passwords are preserved; this editor does not set or clear passwords.
Public edits remain disabled if password policy is unknown. Editing submits no
password field, including when the existing link is password-protected.
Incoming items and unrecognized/missing identities remain read-only.

Only changed fields are submitted. Leaving an expiration unchanged preserves
its exact server timestamp; explicitly emptying the field clears it where
allowed. Before PUT the agent re-reads the owned feed and compares the complete
baseline (grant, resource, Space, owner, recipient, type, target and settings).
This is optimistic checking, not an atomic server-side compare-and-swap. It
then sends one bounded request without retry and reads back identity, requested
values and untouched fields before confirming success. A lost acknowledgement
or mismatched readback blocks resubmission until **Refresh** reloads settings.
Changing tabs or cancelling a dirty editor asks before discarding changes.
Account/server/sign-in-generation changes invalidate the editor.

Synthetic tests cover OCS form semantics, field preservation, uncertain
outcomes, stale baselines and account changes. No live shares were edited in
this increment; native Windows interaction remains pending.

## Existing sender protocol

Guest creation and item-scoped role/expiration management retain the original
Graph validation described below. Those item permission operations are separate
from the new aggregate OCS inventory and revocation path. The server's actual
PATCH permission route is used; a conflicting documentation-page POST label is
stale. Synthetic protocol tests do not imply live permission-change acceptance.

## Protocol and safety

Guest sender operations use Graph item permissions and `/invite`, not an OCS
share type. Aggregate owned-share revocation uses its separately validated OCS
route. Availability requires actual JSON `true` for both
`capabilities.files_sharing.api_enabled` and
`capabilities.files_sharing.guest_links.enabled`. Never compare the compatibility
`version.string` against product major 9: official OpenCloud 9 can advertise
`0.1.0` there. Missing/malformed flags disable guest access without changing
ordinary account functionality. Feature unavailability and a genuine server
403 denial have different messages.

Allowed roles come from fresh item metadata. A permission-list GET may omit
`value` when no permissions exist, after valid role annotations. Explicit null,
malformed rows and malformed roles remain invalid. An invitation POST must
return its singleton permission collection. Only permissions explicitly marked
`grantedToV2.user[@libre.graph.userType] == Guest` are editable here.

Both agents require the explicit account/auth generation. Mutations also compare
the selected resource ID against freshly resolved ordinary metadata. Account
changes and in-flight sign-out are fenced; stale confirmations do not send.
Transport retries are disabled, requests have bounded deadlines, and an uncertain
mutation result asks users to refresh rather than automatically resend email.
Successful mutations acknowledge submission separately from the next refresh.

## Observed acceptance and remaining checks

The exact staged Linux agent restored the existing selected account and created
an owner-authorized empty Personal-space test folder. It loaded the server's
actual roles, accepted one explicit email invitation, and read back its Can view
role and 24-hour expiry. The folder remained empty and the saved account list
was preserved. This verifies the production broker/protocol path, not a
physically clicked invitation button. A later explicit renewal request returned
HTTP 200 and preserved the permission. Mail delivery is not independently
certified here.

The owner reports that opening a fresh received link in the native preview
still failed. The cause was not established. Native recipient support was
removed because the owner deferred that feature; removal is not a fix or
acceptance of the failed recipient flow. Its source and failure evidence remain
preserved outside Git under `outputs/desktop-opencloud9-guests-20261028/`.

Before release, verify the exact Linux and Windows packages and sender UI,
role/expiry edit and revoke, server denials, and preservation of ordinary
account/encrypted workflows. Windows source cross-checks and packaging failures
are recorded separately; a cross-check is not installed/native acceptance.
Additional invitations or renewal emails require an explicitly authorized test
recipient and action. No server configuration change or publication is implied.

Protocol references: [tagged auth-guest service](https://github.com/opencloud-eu/opencloud/blob/v9.0.0/services/auth-guest/README.md),
tagged capability/permission models, and independently maintained Android guest
invitation clients. Android remains read-only reference in this Desktop task.


## Latest read-only native observation

The local Linux preview reconnected the same selected account and enumerated
all three feeds with exact account/generation/server validation. Incoming
returned one item; outgoing people/group grants and public links returned
successful empty lists for that selected account. No invitation, new link,
permission change or revoke was performed. Actual Windows package interaction
and comprehensive keyboard/accessibility acceptance remain separate work.

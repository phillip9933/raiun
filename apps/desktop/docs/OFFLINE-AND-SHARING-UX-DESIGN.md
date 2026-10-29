# Desktop Offline files and Sharing redesign

**Design proposal · 28 October 2026 · implementation handoff**

This document specifies the next Linux and Windows Desktop iteration following
owner review of the local 0.7.4 preview. It is a proposal, not implemented
behavior or release acceptance. No application code, settings, account data or
shares were changed to create it.

Follow the [Raiun shared design reference](../../../design/raiun/DESIGN-SYSTEM.md)
and its [review template](../../../design/raiun/REVIEW-TEMPLATE.md). This document
defines screen structure and behavior; it does not introduce another palette.

## Owner amendment: Android-style sharing inventories

The owner's subsequent review supersedes the method-based sharing tabs and
item-lookup landing pages in the original proposal below. The implemented main
navigation is **Sharing → Shared with me / Shared by me / Public links**, using
a single continuous tab row. Each tab loads its server-wide, account-visible
inventory automatically. Filtering is optional and operates on loaded rows.

**New share** belongs below the Shared by me list. People & groups, Share links
and Guest invitations are creation methods inside that flow, not inventory tabs.
Incoming rows show the item and who shared it; unsupported access/expiry fields
are omitted. Owned lists use explicit desktop columns and compact labelled rows.

Supported account-level Graph and OCS feeds replace the original per-item
fallback. They retain separate identity/permission models. Exact OCS grant and
resource revalidation enables explicit owned-share revocation without guessing
Graph IDs; incoming rows remain read-only. See [current behavior](OPENCLOUD-9.md)
for limits and evidence. The following original design remains historical
context where this amendment supersedes it.

## 1. Decisions at a glance

| Area | Proposed decision |
| --- | --- |
| Offline row Options | Keep the control in the same row and position when opened. Insert its panel underneath the entire row. |
| Offline storage | Make the automatic cache allowance configurable. Clearly distinguish it from files explicitly kept offline and protected edits. |
| Sharing navigation | One **Sharing** sidebar destination, with **People & groups**, **Share links**, and **Guest invitations** sections. |
| Sharing landing pages | Show existing shares first. Creation forms appear only after **New share**. |
| Item selection | A separate, clearly labelled **Choose file or folder** step, followed by access settings and review. |
| Guest management | List invitations first; editing is an explicit action. Remove the permanently displayed creation form and empty Guest access panel. |
| Other sharing methods | Implement actual capability-backed People & groups and Share links operations; do not ship enabled placeholder controls. |
| Received guest links | Remain deferred. This work does not add guest-link accounts, redemption or a recipient browser. |

## 2. What the current preview establishes

The Offline page already separates Files & folders from Storage & help. The
expanded `.offline-row-options` element currently spans the full grid width,
moving its own summary out of the action column. That explains the reported
button movement; a panel must span the row without relocating its trigger.

The existing cache documentation describes a default **1 GiB automatic cache
allowance**. Kept-offline content and protected edits can exceed it. Presenting
total usage as “used of 1 GB” incorrectly suggests a hard total-storage cap.
Linux currently reports selected-account storage; Windows reports a device
budget shared by accounts. Preserve and label these scopes until the engine
deliberately supports a common model.

Sharing currently implements sender-side guest invitations for a selected
ordinary file/folder. People/internal sharing and other external sharing are
placeholders. The current guest API surface lists permissions for one selected
item; an account-wide list of all shared items is **additional backend work**,
not a frontend rearrangement. Existing guest roles and availability are
server-derived. No new protocol support is established by this design.

## 3. Offline files: stable rows and progressive detail

Keep the two existing views. In Files & folders, prioritize browsing, current
availability and the next action. Use short labels and neutral surfaces.

```text
Offline files
Copies stored on this computer.
2.4 GiB stored · This account                     Storage settings

[ Files & folders ]   [ Storage & help ]

Location  [ Personal                          v ]
Personal / Documents                         Keep folder offline

  Project notes.pdf     Available offline             Options ▾
  ------------------------------------------------------------
  Availability  [ Keep offline                        v ]
  This copy stays available when you are disconnected.
  ------------------------------------------------------------
  Budget.xlsx          Not kept offline    Keep offline  Options ▸
```

### Expansion contract

- Put filename/status/actions in a stable row wrapper. Put the associated
  options panel in a separate full-width region immediately after that row.
- Keep **Options** as the label in both states; only the chevron and
  `aria-expanded` change. Use `aria-controls` to identify the panel. Give each
  button an accessible name including its filename.
- Opening or closing a panel must not change the trigger's x/y position,
  move focus, scroll the page to its contents, or change the height of its
  own header row. Rows below naturally move down. Background refresh must not
  collapse it or steal focus.
- At narrow widths, wrap the action strip below the filename in **both**
  states. Do not switch layout simply because Options is open.
- Tab reaches the newly revealed controls in document order. Closing returns
  focus to Options if focus was inside the panel. Account/Space changes clear
  the panel and its drafts; no settings may carry into another scope.
- Keep error, stale-copy, pending-edit and uncertain-download status visible
  in the row or page activity area even when options are closed.
- Avoid decorative panels inside panels. Use a subtle separator, regular
  spacing and a neutral inset surface only when it improves grouping.

Apply the same behavior to Folder options. Preserve all current policy,
encryption, authentication and account/root checks.

## 4. Offline storage: configurable and accurately named

### Storage & help layout

```text
Storage on this computer
Scope: This account                 [Linux]
   or: All Raiun accounts on this device      [Windows]

Total stored                                        2.4 GiB
Automatic cache                                     0.8 GiB
Kept offline                                        1.6 GiB
Protected edits                                     Included above

Automatic cache limit        [ 1       ] [ GiB v ]
Temporary copies of files you open. Raiun can remove older copies
to stay within this limit. Files you keep offline and unsent edits
are protected separately.
                                               Cancel   Save limit

How storage works ▸
```

Numbers above are illustrative. Never fabricate a category total or subtract
overlapping counters to obtain “automatic cache.” The engine must supply an
accurate evictable-content measurement, or the UI must say **Not available**.
Avoid a stacked chart until categories are proven disjoint. File browser sizes
remain cloud sizes, not measured local disk usage.

### Setting behavior

- Default remains **1 GiB** (1,073,741,824 bytes). Display consistent IEC units;
  do not silently relabel the existing quota as decimal GB.
- Use a numeric amount plus MiB/GiB unit selector, with optional quick values
  **1 GiB**, **5 GiB**, **10 GiB**, **Custom**. Proposed supported minimum is
  256 MiB; validate exact byte conversion and engine-supported upper bounds.
  No Unlimited or zero/off interpretation in this increment.
- Save is explicit and enabled only for a valid changed value. Show inline
  validation and preserve a rejected draft. A successful save acknowledges
  the persisted value returned by the agent; a restart retains it.
- Scope is always visible beside the control. On Linux change only the
  selected account's allowance. On Windows explicitly state that the change
  affects all accounts on this device; never label it an account preference.
- Raising the allowance does not pre-download files. Lowering it may remove
  only eligible temporary copies through the existing safe eviction path.
  Explain that effect beside Save when reducing the value. It never removes
  kept-offline copies, pending edits, recovery data or cloud content.
- If protected content exceeds the allowance, show **Kept-offline files and
  edits use additional space**. Do not call this a failed quota setting or
  offer automatic unpinning. Disk-full conditions remain distinct errors.
- Read-only usage refresh must not trigger cleanup. Save-limit configuration
  and any subsequent eviction must report their outcomes separately: a saved
  allowance does not mean space has already been freed.
- Changes may be saved while disconnected if the agent can securely resolve
  the existing local scope. Reject unknown/stale scopes; do not require a new
  cloud sign-in merely to change a local preference.

**Deliberately excluded:** a hard cap on all offline files. Enforcing one would
need separate admission behavior for pins and edits. Do not pretend the
automatic cache setting provides that cap. No clear-all button, automatic
removal of protected copies or permanent account cleanup is added here.

## 5. Sharing: existing access first

Use the existing **Sharing** sidebar entry. Do not add a separate permanent
Guest access block below the main workspace.

| Section | One-line explanation | Primary creation action |
| --- | --- | --- |
| People & groups | Give people or groups on this server access to a file or folder. | New share |
| Share links | Create a link to a file or folder. Anyone with the link may gain the access you allow. | New share |
| Guest invitations | Invite someone by email to open a file or folder in their browser. | New share |

These names replace ambiguous Internal/External categories. Guest invitations
are identity/email-oriented access; Share links are link-based access. Neither
is received guest-link sign-in. Descriptions must not promise recipient
verification, restricted forwarding or features the server does not provide.

```text
Sharing                                              + New share
Manage access to files and folders in this account.

[ People & groups ]   [ Share links ]   [ Guest invitations ]

Invite someone by email to open a file or folder in their browser.
Search shares…                Location [ All locations v ]

Item                  Shared with          Access     Expiration
Trip photos           alex@example.test    Can view   12 Nov    ⋯
Personal / Photos
Project brief.pdf     pat@example.test     Can view   None      ⋯
Team / Documents
```

### List rules

- Each section opens on a compact list of its existing shares, including
  shares created outside Raiun when the server can enumerate them. Scope is
  the selected account and permissions the user can actually manage.
- One row represents one access grant/link/invitation. Repeat the item label
  when it has multiple grants; do not hide recipients behind an unexplained
  count. Use filename, location, recipient or link label, role and expiration.
- File/folder names open **Share details**, not file navigation. A labelled
  **More actions** menu offers contextual edit/revoke or delete-link actions.
  Link rows can expose a quiet **Copy link** action. Guest rows must not invent
  a reusable link when the server only supports invitation email.
- Show expired status when established by the expiration time. Only show
  Accepted, Pending or Email delivered when the server supplies reliable
  evidence; an HTTP success is not evidence of mail delivery.
- No inline edit forms in every row. Details has a readable summary followed
  by **Edit access** and a clearly named destructive action.
- Empty means a successfully loaded empty result: **No guest invitations yet**
  with **New share**. Loading, permission denied, unavailable capability and
  failed/partial enumeration are distinct states. Retain loaded rows during
  refresh and report failures without flashing the whole screen.
- Do not include raw share URLs, invitation tokens or recipient email
  addresses in diagnostic logs. Copy links only after an explicit action.

### Enumeration is a prerequisite, not an assumption

Before promising “All shared items,” establish supported enumeration APIs,
pagination, permissions and roles for each sharing type. Do not recursively
scan every file on startup. Do not present a local history of Raiun-created
shares as the complete server inventory.

If the server supports only item-scoped lookup for a category, the honest
fallback is **Shares for a file or folder**, with **Choose file or folder**
above its list. Remembered items may be offered as **Recently managed**, with
fresh permission checks and explicit coverage wording. This is a fallback,
not completion of the owner's account-wide list requirement. Record the API
gap before implementation scope is accepted; never hide it behind a zero count.

## 6. New share and edit flows

**New share** opens a dedicated creation subpage in the main content area. The
selected section supplies the sharing method; show it in the title. Keep the
account header visible. Avoid a long always-open form or nested modals.

### Step 1 — Choose file or folder

- Heading: **New guest invitation**, **New share link**, or **Share with people**.
- Use a persistent **Location** label above the Space selector. Place the
  selector and browse area on separate rows, not a squeezed heading/action
  grid. Single-line native options use concise names; a wrapping text line
  below the selector shows the full selected name when needed.
- Browse with a breadcrumb, folder-navigation actions and a single selected
  item state. Clicking a folder opens it; a separate radio/selection control
  chooses the item. File rows select rather than attempting directory browsing.
- Replace repeated **Select** buttons with one footer action:
  **Use this file** or **Use this folder**. It remains disabled until a valid
  item is selected. A selection summary makes the exact item unmistakable.
- Keep **Cancel** and **Continue**/the contextual Use action visible in normal
  document flow or a non-obscuring sticky footer. No content under the footer.
- Guest Space roots and encrypted locations remain excluded. Other methods
  must use verified capability and encryption rules; no inference that an
  ordinary share makes an encrypted item safely readable.

### Step 2 — Access settings and review

Show a compact **item + location** summary with **Change item**. Changing the
item clears recipient/permission drafts and reloads its permitted roles.

| Method | Main fields | Optional fields, only when supported | Final action |
| --- | --- | --- | --- |
| People & groups | Server user/group search; access role | Expiration; notification preference | Share |
| Share links | Link name; access role | Password; expiration; other server-enforced restrictions | Create link |
| Guest invitations | Recipient email; access role | Expiration | Send invitation |

Use the server's actual role names plus a short capability-derived explanation.
Do not hardcode an Editor role if it is unavailable. Choose the least-privileged
appropriate supported default. Show required server-policy fields directly;
do not hide required passwords or expiry inside Advanced.

Place a brief consequence statement above the final action. For guests:
**This gives [email] [role] access to [item] and sends an invitation email.**
This final review is the deliberate confirmation; implementation may reuse the
existing native confirmation initially, but must not require two identical
confirmations in the finished flow. No mutation occurs during browsing.

On success return to that section's list, highlight the new row once, and show
a concise dismissible notice. After Create link, offer **Copy link**; do not
write to the clipboard automatically. Preserve list filter/scroll position,
but reveal or link to a newly created item hidden by a filter.

Edit opens details with **Save changes** and **Cancel**. Revoke confirmation
names the recipient/link and item: **This removes this access. It does not
delete the file or folder.** Do not claim it removes other grants, inherited
access or copies already downloaded.

### Safe interaction states

- Account, authentication generation, Space, item identity and permission
  revision must remain valid across creation, confirmation and edit.
- Account switch closes the flow and clears sensitive drafts; stale replies
  must never render another account's recipients. Changing category with
  unsaved edits asks to discard; ordinary untouched navigation does not.
- Disable duplicate submission while pending. A timeout with unknown outcome
  shows **Could not confirm the result. Refresh before trying again.** Never
  automatically resend invitations or create duplicate links.
- Disconnection preserves a current draft but disables submission. A changed
  authorization/role list must be re-reviewed before sending.
- Server capability absence gets a concise explanation. A supported feature
  denied to this user gets a permission message. An unimplemented client
  adapter must not masquerade as server unavailability.

## 7. Style, layout and accessibility contract

- Use canonical canvas/surface/inset, text/muted, border/controlBorder and
  focus tokens. No per-feature purple, amber or green background panels.
- Account accent belongs to the persistent header and selected account card.
  Status uses text plus icon and, if useful, a narrow rule. Success and errors
  do not recolor the whole form.
- One primary action per active view. Quiet tabs, secondary buttons and
  ordinary rows remain neutral. Standard icons accompany familiar labels.
- Label fields above controls; never overlay a label, hint and select in one
  grid cell. Use the shared spacing scale, flexible widths and min-width:0.
  Long locations/emails wrap in summaries; keep complete names accessible.
- Typical desktop widths use table-like rows; compact widths use stacked
  rows retaining every action. At 700 CSS px and at 200% zoom, fields stack,
  action groups wrap and there is no horizontal page overflow.
- Native keyboard semantics, visible focus, 4.5:1 normal text and 3:1 essential
  control boundaries. Information tooltips must also open on focus/click;
  essential consequences remain visible without a tooltip.
- Lists and forms preserve focus during refresh. Creation navigates focus to
  its heading; Cancel returns to New share; details returns to its originating
  row. Loading announcements use a restrained live region. Respect reduced
  motion; no full-panel flashing or repeated success animation.

## 8. Implementation sequence for Sol

1. **Stable Offline Options:** restructure row/panel markup and scoped focus
   handling. Verify both folder and file rows before touching storage logic.
2. **Configurable allowance:** inspect both agents' actual quota ownership;
   implement validated durable configuration, usage reporting and UI. Preserve
   separate platform scope rather than inventing equivalent behavior.
3. **Sharing capability/aggregation assessment:** identify supported list,
   create, edit and revoke APIs for all three methods. Record missing aggregate
   enumeration and server-policy requirements. No real invitations needed.
4. **Shared Sharing shell:** list-first pages, details, creation steps and
   accessible item chooser. Reuse current guest sender validation; remove the
   old persistent form. Extract focused view/state modules instead of further
   expanding the main renderer.
5. **People & groups and Share links adapters:** implement actual server-backed
   behavior and rights checks. Keep type-specific permissions distinct; the
   guest permission filter must never mutate ordinary grants accidentally.
6. **Native acceptance:** run focused Linux and Windows checks against exact
   candidate packages. Document supported server capabilities and gaps before
   release. Android adoption is separately owned; do not change its code here.

Implementation entry points: `desktop-shell/src/main.ts`, `style.css`,
`guest-sharing.ts`, Windows offline view/controller modules, and the agents'
profile/cache and `guest_sharing_wire` paths. Extend current abstractions after
inspection; this document deliberately does not invent endpoint names or IPC
schemas. Read existing dirty-work/continuation records before editing.

## 9. Done when

- [ ] Opening/closing Options leaves its trigger stationary at normal and
  compact widths, with focus and keyboard behavior verified.
- [ ] Limit edits persist after restart, preserve account/device scope, reject
  invalid input and leave protected copies, edits and cloud files untouched.
- [ ] Storage labels distinguish total disk usage from automatic-cache budget;
  unknown and overlapping measurements remain honest.
- [ ] Each implemented sharing method starts with an accurately scoped list,
  with explicit coverage limits if account-wide enumeration is unavailable.
- [ ] New-share fields are absent until requested. Item selection, changing
  item, cancelling, successful creation and returning to the list are clear.
- [ ] People/group shares, links and guest invitations have working supported
  operations; no enabled placeholder tabs or imaginary server features.
- [ ] Long Space names, paths and emails do not overlap controls in light,
  dark and system themes, 700/1100/1400 widths and 200% zoom.
- [ ] Account switching, stale confirmations, network loss, unknown mutation
  outcome and unavailable/denied capabilities preserve safe behavior.
- [ ] Guest recipient access remains removed. No regression in encryption,
  ordinary account sign-in, cache safety or recovery handling.
- [ ] Synthetic tests and exact-package Linux/Windows interactions have
  separate evidence using the shared design scorecard; absent evidence stays
  unverified. New live email/access tests require an explicitly authorized
  recipient, item and action; earlier test permission is not reusable consent.

## Local implementation status — 28 October 2026

The local candidate implements stationary file/folder Options, a persisted
256 MiB–1 TiB cache allowance, and a list-first Sharing workspace with guest,
people/group and public-link adapters. Inspection corrected the proposal's
Windows premise: the shared device allowance also gates explicit download
admission. Saving it never deletes content, and protected data can exceed it.

Account-wide sharing enumeration now uses separate Graph incoming and OCS
outgoing feeds. Direct owned shares have a fresh-settings editor for supported
access/expiration and public-link names. Password setup remains unsupported;
public creation/editing is disabled when server password policy requires an
unsupported operation or cannot be confirmed. Incoming and inherited grants
remain read-only. See the behavior
documents below for current details. These are uncommitted candidate changes;
the unchecked acceptance items above are not automatically passed by source
implementation or synthetic tests.

## Source references

- [Offline behavior and safety](OFFLINE-CACHE.md)
- [Current guest sender scope](OPENCLOUD-9.md)
- [Shared design tokens](../../../design/raiun/tokens.json)
- [Desktop follow-up backlog](../../../docs/PRODUCT-BACKLOG.md)

The existing local preview remains unchanged. This proposal does not authorize
publication, new invitations, changes to real shares or cleanup of user files.

# Product backlog

Owner-requested improvements, recorded 23 October 2026. These are queued product
work, not additions to the current Desktop beta completion baseline.

## Desktop: make Transfers easier to understand

Public work item: [#41](https://github.com/phillip9933/raiun/issues/41).

- Improve the Transfers tab and its sub-tabs so users can tell what each view
  contains, what is happening now, and what needs their attention.
- Use clear labels, short explanations and useful empty states. Distinguish
  active/queued work, completed transfers, failures and saved edits/recovery
  according to the actual categories available.
- Make progress and the next useful action understandable without technical
  knowledge; preserve existing recovery and verification semantics.

Local progress (28 October): the next Desktop candidate adds human-readable
transfer states, counts and explanations for Current & paused, Needs attention
and History. Unknown states remain visible for review; unknown directions do
not appear as downloads. Offline edits and recovery stay separate. This is local
implementation, pending focused Linux/Windows review and publication.

## Raiun: consistent design across apps

Public work item: [#42](https://github.com/phillip9933/raiun/issues/42).

Use the [shared design reference](../design/raiun/DESIGN-SYSTEM.md) and its
component catalog and review scorecard. Keep information panels neutral, reserve
status color for labels/icons/narrow indicators, and preserve the full account
card/header accent. Desktop maps the shared light/dark tokens into its theme;
Android adoption and each platform's interaction/scaling review remain pending.
The scorecard records evidence and unverified states rather than assuming parity.

## Android and Desktop: explain Photos only / Videos only presets

- Explain what each preset includes and excludes when configuring a sync folder,
  and make that explanation available when reviewing an existing configuration.
- Describe the actual supported photo/video types, how subfolders are treated,
  and what happens to other files, including mixed photo/video folders.
- Keep the wording consistent across apps while reflecting any actual platform
  differences. Verify descriptions against the implemented filters; this item
  does not change filtering behavior or add new formats.

Desktop progress (23 October): the media preview, recurring-backup setup and
saved backup cards now explain the Include filter, recursive subfolders and
skipped symbolic links. Types are recognized from contents rather than filename
extensions. This copy does not change filtering. Android wording remains queued.

## Desktop: GitHub release updates — completed for beta.2

Owner request (24 October 2026):

- Add an optional update checker that checks the official Raiun GitHub releases
  and offers to download the latest compatible Desktop version for Linux or
  Windows. Include a manual “Check for updates” action.
- Show the available version and release notes, distinguish stable and beta
  releases, and select the correct platform/package asset.
- Verify downloaded packages against published integrity information. Explain
  how to install the update and preserve settings, accounts and recovery data;
  do not install or restart without the user's agreement.
- The owner promoted this into the beta scope on 26 October. Implementation,
  signed packages and focused Linux/Windows upgrade acceptance are complete for
  Desktop 0.7.0-beta.2. See [Desktop updates](../apps/desktop/docs/DESKTOP-UPDATES.md)
  for the release contract and supported behavior. Public issue #7 tracks the
  delivered work; this historical request is not a second live task list.

## Desktop: simpler Offline files workspace

Public work item: [#43](https://github.com/phillip9933/raiun/issues/43). The local
next candidate separates Files & folders from Storage & help, adds direct
Keep offline file actions and native Options disclosures, and preserves visible
download/recovery warnings. Windows uses one Files/Folders picker at a time;
device-wide storage remains clearly labeled. Shared guide color and wrapping
fixes accompany the redesign. Local checks and Linux preview pass; actual
Windows UI and owner review remain. No new release is published.


### Desktop Offline and Sharing follow-up — local 28 October candidate

The owner approved the [Offline and Sharing design](../apps/desktop/docs/OFFLINE-AND-SHARING-UX-DESIGN.md)
for implementation. Current source adds stationary Options, configurable scoped
cache allowance, and list-first People & groups / Share links / Guest invitations
with a separate New share flow. Item-scoped list coverage is explicit;
account-wide inventory and public-link editing/password setup remain gaps.
Source, visual and native-package acceptance are tracked separately; no release
or live invitation mutation is implied by the implementation. This extends the
Offline work in #43 and the shared design work in #42.


### Desktop Sharing inventory amendment — 28 October (#44)

The owner replaced method-based tabs with **Shared with me**, **Shared by me**
and **Public links**, matching Android's organization. The local candidate now
loads each account-visible server inventory automatically, with an optional
local filter. New share is below Shared by me and opens method/item/access steps.
Incoming items remain read-only; supported owned grants can be revoked through
a fresh resource-bound OCS path. Source/native-preview evidence is in
`outputs/desktop-sharing-inventory-20261028/`; exact Windows package acceptance
and full accessibility review remain pending. Earlier per-item-only inventory
limitations are superseded by the new aggregate feeds, subject to explicit
whole-response and local-message bounds. No publication is implied.

### Desktop sharing amendment — editable existing settings (28 October)

[#44](https://github.com/phillip9933/raiun/issues/44) also tracks the owner's
request to edit shares after creation. The local candidate now opens a fresh,
account-bound editor for supported outgoing OCS grants, with access/expiration
and public-link name changes. It preserves the existing link/password and
untouched fields, checks a fresh baseline before PUT, and verifies the result.
Incoming/unknown grants remain read-only; public policy limitations, actual
Windows interaction and live mutation acceptance remain explicit. This is
uncommitted local work, not a published feature. See
[the behavior contract](../apps/desktop/docs/OPENCLOUD-9.md).

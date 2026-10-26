# Product backlog

Owner-requested improvements, recorded 23 October 2026. These are queued product
work, not additions to the current Desktop beta completion baseline.

## Desktop: make Transfers easier to understand

- Improve the Transfers tab and its sub-tabs so users can tell what each view
  contains, what is happening now, and what needs their attention.
- Use clear labels, short explanations and useful empty states. Distinguish
  active/queued work, completed transfers, failures and saved edits/recovery
  according to the actual categories available.
- Make progress and the next useful action understandable without technical
  knowledge; preserve existing recovery and verification semantics.

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

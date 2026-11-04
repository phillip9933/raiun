# Raiun UI review record

Use the [shared design reference](DESIGN-SYSTEM.md) and [component catalog](reference.html).
Create a separate record for each candidate/platform. Keep screenshots and recordings
with the review evidence; remove private account names, addresses and filenames.

- App and exact candidate/commit or artifact hash:
- Platform and OS version:
- Device, window/viewport size and display scale:
- Appearance: light / dark / system (record the resolved appearance)
- Font scaling / zoom and reduced-motion setting:
- Screens and states reviewed:
- Reviewer and date:
- Evidence location and related issue/PR:

| Criterion | Score (0 / 1 / 2 / unverified) | Evidence, interaction steps and remaining finding |
| --- | --- | --- |
| Semantic color and neutral panels | unverified | |
| Text contrast | unverified | |
| Controls and boundaries | unverified | |
| Focus and keyboard | unverified | |
| Status is not color-only | unverified | |
| Account and privacy context | unverified | |
| Destructive actions | unverified | |
| Font scaling and reflow | unverified | |
| Screen-size adaptation | unverified | |
| Motion and loading | unverified | |

- Critical privacy, destructive-action or accessibility failure / unverified state:
- Total: record only after every criterion has evidence; do not score unverified as passed.
- Outcome: ready / needs work / redesign / incomplete evidence.
- Follow-up issues, exact owner and next action:

Review the ordinary, loading, empty, failure and disconnected states that the
candidate changes. Include account switching and any affected confirmations.
Token contrast and synthetic component snapshots are supporting evidence; they
do not replace real platform interaction or certify the whole application.

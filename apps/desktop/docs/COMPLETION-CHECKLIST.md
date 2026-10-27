# Linux and Windows completion checklist

Owner-approved baseline: 17 October 2026. This fixes the product scope agreed
in the conversation. It governs completion reporting for Linux and Windows;
historical roadmap entries and optional ideas do not automatically enlarge it.

## Definition of completion

Each item below requires implementation, relevant source checks, native
platform acceptance, and verification of the actual packaged application.
Linux evidence does not establish Windows acceptance. A build or unit-test pass
alone does not complete an item. Preserve evidence of failures and limitations.

For each acceptance record, identify the source/package, expected and observed
behavior, result, and installed versus running state. Use synthetic isolated
tests and preserve credentials, user data, dirty edits, and recovery. Existing
test and installation authorizations retain their limits.

The boxes represent whole-category completion, not absence of working features.
They remain unchecked while required flows or verification within that category
are outstanding. Detailed evidence lives in [implementation status](IMPLEMENTATION.md)
and [acceptance records](MVP-ACCEPTANCE.md).

## Linux beta milestone — owner update, 21 October 2026

Owner priority update, 23 October: the Linux beta is published. Put the larger
share of next-release implementation effort into Windows feature parity while
continuing focused Linux beta improvements. The practical acceptance rules below
and fixed capability scope still apply.

The immediate delivery target is a usable Linux beta. The owner explicitly
prioritized normal everyday workflows over exhaustive testing of every possible
failure. The fixed capabilities below remain the product scope; whole-category
certification is a later milestone and is not the beta release gate.

For beta, resolve observed security, account-isolation and data-loss blockers,
run the relevant source checks and focused exact-package native checks, and
publish honest known limitations with the candidate. Reuse valid unchanged
evidence. Missing exhaustive edge-case coverage, media restart verification or
full advanced-control acceptance alone must not hold the beta indefinitely.
Do not add test frameworks or new feature scope to satisfy hypothetical issues.
This does not authorize publication or unsafe operations.

## Fixed feature checklist

| ID | Capability and acceptance boundary | Linux complete | Windows complete |
| --- | --- | --- | --- |
| C01 | **Accounts:** sign-in, session refresh, account switching, and separate credentials, roots, caches, transfer state, and recovery; verify isolation and restart behavior. | ☐ | ☐ |
| C02 | **Cloud drive:** one root per account containing Personal and Spaces; native file-manager access, on-demand opening, and safe saving back to the cloud. | ☐ | ☐ |
| C03 | **Offline availability:** persistent bounded caching; cloud-only and always-available-offline files and folders; safe restart/reconnection and reconciliation. Eviction must never mean cloud deletion, and dirty edits must survive. | ☐ | ☐ |
| C04 | **Folder sync and Space controls:** configured local/cloud folder pairs, selective exclusions, pause/resume, targeted sync, and the agreed per-Space controls, including disconnect while preserving local data. | ☐ | ☐ |
| C05 | **Encrypted file access:** explicit unlock/lock; encrypted folder and Space browsing, opening, editing, ordinary create-folder/rename/move/delete flows, safe folder sync and recovery; compatibility with the supported Raiun Android/OpenCloud Web format. Preserve fail-closed restrictions where an operation cannot be made safe. | ☐ | ☐ |
| C06 | **Remembered unlock:** optional OS-protected storage with explicit per-vault opt-in, correct account/vault binding, restart behavior, and lock/forget controls; accessible locked-location unlock flow. | ☐ | ☐ |
| C07 | **Conflicts and recovery:** preserve local edits and competing versions; clear recovery choices, local-copy export, and safe explicit retries. Uncertain results must not cause destructive replay or loss of either copy. | ☐ | ☐ |
| C08 | **Media backup:** the agreed upload-only workflow, duplicate avoidance, restart recovery, and preservation of source files. | ☐ | ☐ |
| C09 | **Everyday controls:** clear status and transfers, tray operation, startup settings, proxy/bandwidth controls, useful redacted diagnostics, and filename/path compatibility warnings. | ☐ | ☐ |
| C10 | **Delivery:** working platform packages, safe installation/upgrade and preserved rollback/recovery, verified installed-app and native file-manager workflows, and documented support limits. | ☐ | ☐ |

Normal file-operation acceptance includes the already-agreed cross-vault copy
and move behavior: re-encrypt through the correct source/destination scopes,
verify the destination before any conditional source removal, and preserve both
copies on uncertainty. A ciphertext MOVE is allowed only inside the same
verified vault. This does not authorize unsafe recursive encrypted deletion.

## Explicit exclusions

- macOS is outside this completion pass.
- Vault administration, membership/sharing management, and password rotation.
- Arbitrary encryption formats or arbitrary rclone configurations.
- Automatic publication or release authorization.
- Unsafe operations that cannot preserve data, including blanket recursive
  encrypted-directory deletion without sufficient safeguards.
- Optional enhancements such as richer media date/naming options, expanded
  administration, or other later ideas unless the owner explicitly adds them.

## Scope and progress rules

1. New product capabilities require explicit owner approval before becoming
   completion blockers. Keep proposals separate from this baseline.
2. Security and correctness repairs necessary for these agreed capabilities
   remain implementation work within scope; they are not extra features.
3. Required platform acceptance is part of completion. Do not inflate progress
   from test counts, build counts, or repeated checkpoints.
4. Report implementation and verification separately. Any percentage must name
   its denominator and weighting. The earlier approximate 65% overall estimate
   was provisional, not a measured score against this checklist.
5. Do not add rows, split rows to change the denominator, or expand acceptance
   boundaries merely to accommodate new ideas. Record owner-approved changes
   explicitly with their date and effect on completion reporting.

Owner update, 21 October 2026: resume the next Linux and Windows release at a
token-frugal pace. Stop work and delegated agents when less than 10% of the
weekly allowance remains (weekly usedPercent > 90), until explicit owner resume.
This supersedes the earlier spending thresholds without expanding feature scope.

## Desktop updater — owner addition, 26 October 2026

Before the next beta, both Windows and Linux must detect newer compatible
Desktop releases on GitHub, download and install verified updates, and show
dismissible update notices, following the Android client's update workflow.
Provide automatic checks and a manual App updates screen. Later dismisses that
release without hiding the manual update controls; a newer release can notify
again. Download and installation require explicit user actions.

Keep Desktop and Android release selection separate in the shared repository.
Preserve account settings, credentials, dirty edits and recovery during upgrade;
verify safe agent shutdown before replacing a running installation. Validate
platform/package/version and update signatures before installation, with focused
Windows and Linux package-upgrade acceptance. Missing release trust metadata
must fail closed. Signing-key setup and publication remain separately authorized
operations. This addition belongs to C10 delivery and adds no whole-category
completion claim. Source implementation and focused source checks pass. Both
beta.2 update artifacts are signed; isolated Linux signed-package upgrade and
retention checks pass. The Windows signed-package native checks, exact installed
payload/version verification, synthetic settings/document/DPAPI retention,
signed-out App updates UI and normal app closure now pass. The passive installer
UI was not captured; its exact process and normal exit 0 were verified. Receipt
preservation and normal ordinary-process exit 0 are recorded. The final ordinary test session exited normally with numeric 0; its installed
app and synthetic data are retained. Windows sustained-save acceptance
completed all 129 saves, rollover, Lock read refusal and recovery listing
(100+29 items). The original complete case remains failed at its final Save Copy.
The registered cloud-root pin repair now passes focused native Save Copy on the
preserved locked 129-edit custody: exact 65,553-byte content, no-clobber refusal,
unchanged custody, and both root/destination negative tests. The continuation
uses the production Save Copy path; the earlier public RPC listing/Lock evidence
is paired separately. The corrected signed Windows package now also passes its
exact-package native upgrade: installed shell/Agent/CLI hashes and beta.2 version,
settings/document/DPAPI retention, visible App updates and normal Quit. Harness
and NSIS installer exits are both numeric 0 with retained handles; the passive
installer finish UI was not observed. The Linux and Windows practical beta
acceptance gates are met. Final signed candidate packaging, exact metadata checks and parent evidence
review are complete. Both beta.2 candidates were published on 27 October 2026. Offline release-fixture checks
do not establish a live GitHub update offer.


## Urgent post-beta fixes — owner update, 27 October 2026

Ship the Linux saved-sign-in startup recovery, Windows retained-session/retry and
duplicate-sign-in repairs, and encrypted Space metadata correction separately
from the broader UI/CLI feedback. The intended patch is Desktop 0.7.0-beta.3 on
both Linux and Windows. Existing update verification, safe shutdown, account/root
binding and recovery gates still apply. New navigation, appearance, sync/media
workspace and CLI changes are explicitly outside this patch.


Owner numbering clarification, 27 October 2026: keep the current
`0.7.0-beta.3` compatibility bridge so installed beta.2 clients can discover it.
Its updater must recognize numeric `0.x.y` releases as Beta; future releases use
that cleaner format. GitHub prerelease metadata and Stable-channel exclusion
must follow the same classification. The bridge remains available for old clients.


### Published hotfix evidence — 27 October 2026

[Desktop 0.7.0-beta.3](https://github.com/phillip9933/raiun/releases/tag/desktop-v0.7.0-beta.3)
is published for Linux and Windows x86_64. [PR #24](https://github.com/phillip9933/raiun/pull/24)
merged the urgent fixes and numeric-version bridge. Both [Desktop checks](https://github.com/phillip9933/raiun/actions/runs/40440925658)
and the [full Windows native suite and build](https://github.com/phillip9933/raiun/actions/runs/40440920902)
passed on final source `632c96b`. Packages were built from `d88645f`; final changes
are test formatting, a bounded integration-test wait and a CI timeout only.
Published build provenance records exact production-source equivalence.

Both exact signed beta.2-to-beta.3 package upgrades passed signature tamper/version
negatives, installed-file checks, synthetic data/settings retention, visible new
version and App updates, and normal new-app exit code zero. Windows additionally
retained a CurrentUser DPAPI canary. Its installer exit was zero; the installer
finish page was not visually captured. The initial invalid synthetic release-list
fixture was correctly rejected before updater construction, preserved and
corrected before the successful continuation. All nine public assets were
downloaded without authentication and matched the approved sizes and SHA256.
Task VMs were normally shut down; original accounts/recovery fixtures remain.

These checks use synthetic fixtures and do not establish organization-specific
browser/IdP sign-in, a live GitHub offer/download from the installed GUI, or
completion of the broader UI/CLI work. Android source is unchanged: its quality
checks passed; a later emulator run had lock-screen/UI failures, retained and
reported separately rather than treated as a passing run. Existing C01–C10 gaps
remain open. Subsequent Desktop releases use numeric Beta versions, beginning
with planned `0.7.4`; this bridge remains available to older updaters.


### Owner-approved 0.7.4 candidate scope — 27 October 2026

Prepare items 1–7 from the agreed prioritization: Windows in-place upgrades
([#25](https://github.com/phillip9933/raiun/issues/25)), storage/encrypted-file UI
([#26](https://github.com/phillip9933/raiun/issues/26)), combined sync/media
workspace ([#27](https://github.com/phillip9933/raiun/issues/27)), stable refresh
([#28](https://github.com/phillip9933/raiun/issues/28)), safe account removal and
same-ID restoration ([#29](https://github.com/phillip9933/raiun/issues/29)), and
appearance/navigation ([#30](https://github.com/phillip9933/raiun/issues/30)).
Headless/CLI and MSI packaging are excluded. The owner requested ready-for-publication
candidates; this instruction does not publish 0.7.4.

Source implementation and synthetic frontend/removal checks are in place. Linux
and Windows exact-package build/upgrade, affected UI, retention and normal-quit
checks remain required. The local browser preview was denied by automatic review;
its unfinished interactive checks remain unverified and the preview was stopped.
Existing unrelated completion gaps remain open; do not reinterpret whole-category
checkboxes as a count of missing features or re-run unchanged acceptance matrices.


### Windows beta withdrawal — owner request, 27 October 2026

Windows beta.2 and beta.3 installers, updater archives and sidecar signatures were
withdrawn from both public Desktop releases. Their update manifests/inventories
now contain Linux only; checksums and distribution notes were refreshed. Linux
AppImages and signatures are unchanged. Original Windows artifacts and release
metadata remain preserved in maintainer-local evidence. The owner reports the
same reconnecting-saved-sign-in failure on a newly added account, and diagnostics
export fails. The connection cause is not yet confirmed. Do not claim Windows
public beta readiness from the earlier synthetic acceptance or restore these
downloads without verified resolution and owner authorization.

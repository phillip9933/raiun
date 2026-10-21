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

The owner explicitly resumed development on 17 October 2026 and replaced the
previous rolling-spend stop rule with a 500-credit minimum available balance.
This changes the work budget, not the fixed feature scope above.

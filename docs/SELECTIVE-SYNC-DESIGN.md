# Selective folder sync implementation contract

Status: core/engine filtering, profile persistence/dispatch fencing, and native
folder controls are implemented in the current source candidate, 13 October
2026 JST. The controls let users add or remove exact relative paths, including
while cloud sync is offline. They keep both existing copies and do not free
disk space. Package-level native UI acceptance is still pending.
This policy applies to configured folder pairs; mounted cloud-only/offline
availability remains a separate policy. Excluding a path never deletes either
copy and never evicts a dirty working file.

## First supported policy

Add a bounded list of exact pair-relative excluded paths. A directory excludes
its descendants at component boundaries. Use forward slashes, reject absolute
paths, dot segments, empty components and control characters, and keep the
existing account/root overlap checks. Do not introduce arbitrary regular
expressions or platform-dependent glob interpretation in the first slice.
An absent list preserves current behavior. Reject excessive entries/bytes.
The current `FolderPair::excluded_paths` field accepts at most 256 paths and
32 KiB total, with a 4 KiB per-path limit. The engine filters matching entries
from both inventory scans before descending into excluded directories or
planning reconciliation. Excluded baselines are not advanced or deleted.

The UI describes this as stopping synchronization while keeping existing local
and cloud files. It must not describe exclusions as freeing disk space. A
remote browser can select folders, and users can review/remove exclusions even
when offline. Encrypted paths are relative to the explicitly bound vault;
credentials and encryption keys never enter pair configuration.

## Reconciliation invariants

- Apply the same policy to both inventories and the comparison/planning phase.
  An excluded object is not a missing object; it cannot generate a deletion.
- Preserve excluded baselines and durable transfer/recovery records. Skip
  excluded queued work at dispatch, including jobs created before a policy
  change. Do not mark these jobs completed or silently discard dirty data.
- Serialize policy publication with dispatch admission. Already-dispatched
  remote writes may finish; report that fact and preserve their receipts.
  Publication must not start new excluded work.
- Unexcluding a path triggers a fresh scan against its preserved baseline.
  Edits on both sides use normal conflict handling. A stale scan cannot publish
  work under a different policy revision.
- Existing pin/unpin, encryption lock, account isolation and recovery retention
  rules remain in force. A folder-pair exclusion does not hide a mounted path.

The engine has no durable folder-sync upload queue: `sync_pair` performs
operations directly from the supplied immutable `FolderPair`. Its execution
guard serializes sync calls within one Engine. The profile action
`pair_exclusions_set` validates and durably saves one exact pair while holding
the Runtime sync gate and Engine admission fence, then publishes the new policy
before another scheduler pass can dispatch. A failed settings write leaves the
old Engine policy in place. Delayed calls carrying an older pair snapshot are
rejected, as are calls for retired pair IDs. Conflict listing/resolution uses
the same policy fence, so a stale conflict action cannot force an excluded
upload. Already-dispatched writes may finish before publication acquires the
fence. This is separate from encrypted-operation journals, which retain their
existing retry and recovery semantics.

## Required evidence before enabling

Tests must exercise exclusion of an existing synchronized folder without any
DELETE, local/remote changes while excluded followed by a conflict on inclusion,
restart with pending uploads, a policy change during queued/active work, path
boundary and traversal cases, and encrypted pair scope isolation. Test both
ordinary and encrypted fixtures. Complete the normal source gates and exact
package VM test; then verify the native selection and status UI separately.

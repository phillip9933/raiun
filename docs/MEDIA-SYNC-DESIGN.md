# Desktop photo and video import design

Updated 9 October 2026. This is a bounded design proposal for a future desktop
media-import feature. It does not claim that media import exists in Raiun
Desktop, and it does not change the Android implementation.

## What exists today

Raiun Desktop currently models configured local-to-cloud folder pairs with
`two_way`, `upload_only`, and `download_only` modes. The Linux agent and engine
already own scheduling, transfer records, persistent inventory, conditional
provider writes, and explicit conflict review. The shell exposes transfers and
requires a deliberate Keep local or Keep cloud choice for a conflict. There is
no media-specific source model, file-type filter, date-based destination
organization, or metadata-based rename feature in the desktop UI or engine.

The Android app has a separate folder-backup flow in `feature/files`. It selects
a source folder, lets a user choose Photos, Videos, or All files, chooses a
remote destination, and can organize files into UTC year/month folders. Android
backup queues uploads and leaves source files in place; it is not a
bidirectional mirror. Its receipt key includes the destination, date
organization, relative source parent, file name, and source URI. Consequently,
a source rename is observed as a different receipt; Android does not reconcile
that event as a remote rename. A destination collision can require explicit
conflict resolution. Android's source stability check waits ten seconds before
enqueueing a file, uses size and modification time when both are available, and
hashes content as a fallback when those attributes are unknown. These behaviors
are visible in `BackupSettingsRoute`/`FileBrowserScreen`,
`BackupOrganization`, `BackupInventory`, and `DiscoveryAndBackupWorkers` in the
Android repository. The Android project README also states that changed
destination names can require conflict resolution.

The existing desktop architecture already says future media jobs should use
the shared transfer queue and that metadata extraction/date-based naming should
be separated from transport. It leaves date-source precedence, timezone,
collision behavior, repeat-run identity, sidecars, and rename scope open. This
proposal stays within those boundaries.

## Bounded implementation proposal

Treat media import as a separately configured, upload-only job, not as a new
folder-pair mode. Keep the first implementation to one selected local source
folder, a Photos/Videos/All filter, one Personal or Spaces destination folder,
and an optional UTC year/month destination layout. Preserve source files and
their names. Reuse the agent scheduler, transfer history, provider upload
pipeline, durable recovery behavior, and conflict APIs. Do not add a second
transfer queue or allow media import to delete cloud or local files.

The initial scanner should have an explicit bounded contract: enumerate the
selected source, filter by MIME type, wait for a file to be stable before
queueing it, and record an accepted receipt only according to the existing
transfer-success semantics. A queued or failed upload must not be mistaken for
a completed import. Use content hashes where size/mtime cannot establish a
reliable signature, and persist scan progress so restarts can resume safely.
The Linux engine has a conservative local hash cache covered by tests. It uses
device/inode/size/mtime/ctime fingerprints on ext4, Btrfs, XFS, and tmpfs, and
does not reuse a hash when ctime nanoseconds are zero. The tmpfs content test
showed 554 µs average warm scans versus a 242 ms forced full-hash audit across
117 scans, with no warm-scan transfer bytes. The cache also adds metadata and
SQLite work: a one-million-empty-file warm run took 19,722 ms with cache
versus 14,004 ms before cache, with no new RSS sample. Installed end-to-end
acceptance is pending; this media proposal does not depend on that optimization.

The current reviewable slice is an offline CLI preview, not an importer. Pass
an already classified source manifest and existing destination file paths to
`raiun media-preview --input ./media-preview.json`:

```json
{
  "options": {
    "destination_root": "/Personal/Photos",
    "filter": "photos",
    "organization": "utc_year_month"
  },
  "sources": [
    {
      "relative_path": "Camera/IMG_0001.jpg",
      "kind": "photo",
      "utc_date": { "year": 2026, "month": 7 }
    }
  ],
  "existing_destinations": []
}
```

The command prints sorted JSON plan rows. It reads at most a 1 MiB request and
performs no source scan, timestamp extraction, network request, or file write.
Unsafe paths and path collisions are reported; the planner never resolves a
collision by overwriting or inventing a renamed destination.

For rename behavior, the closest safe Android-parity starting point is to keep
the original filename and treat a renamed source as a new candidate. Do not
infer that the old remote file belongs to the renamed local file, and do not
automatically rename or delete either copy. If the resulting destination
already exists, route it through the current conflict workflow, which checks
fresh local and remote preconditions and preserves the displaced version. This
means that users may see a conflict after renaming a file; it avoids silently
overwriting unrelated content. A stable identity-based rename tracker would be
a separate feature with additional platform and provider assumptions.

Keep extraction/renaming of EXIF or video metadata out of the first increment.
That defers questions about unavailable or contradictory timestamps, timezone
interpretation, privacy-sensitive metadata, sidecar files, and destination
collisions. It also avoids adding a metadata library until the desired behavior
is settled.

## Decisions for the product owner

These choices affect user-visible behavior and should be settled before the
implementation grows beyond the bounded proposal:

- **Scope:** Should the first version provide a one-time import, recurring
  backup, or both? Android's existing behavior is recurring backup.
- **Source selection:** Is one user-selected folder enough, or are named
  libraries such as Pictures/DCIM needed? Should removable volumes be allowed?
- **Filtering:** Should the choices be Photos, Videos, and All files as on
  Android? Which MIME types should count as photos/videos, and should RAW or
  animated image formats be included?
- **Destination organization:** Should the desktop match Android's optional UTC
  `year/month` folders, use the original relative subfolders, or offer both?
  Should the default be no date folders, matching Android's current default?
- **Rename matching:** Is Android parity acceptable (renamed source is a new
  candidate and the previous remote copy remains untouched), or is true
  source-identity-based remote rename tracking required? If the latter, what
  stable identity is acceptable across file moves, removable drives, and
  metadata rewrites?
- **Duplicate and collision policy:** When two source files map to the same
  remote path, should import stop for explicit resolution, offer a preview, or
  use another deterministic naming scheme? Should repeated identical content
  at a new source path be imported again?
- **Metadata and privacy:** Should date-based organization use filesystem
  modified time only, embedded capture time, or a defined precedence? Should
  original metadata remain untouched, be stripped, or be editable?
- **Scheduling and resource use:** What scan interval and maximum parallel
  uploads are appropriate, and should background import pause on metered
  networks or battery/power conditions on supported desktops?

The recommended first cut is recurring, opt-in folder backup with the Android
Photos/Videos/All filter, original filenames, optional UTC year/month
organization, source preservation, and explicit collision handling. This
recommendation adopts Android's observable behavior and avoids guessing at
rename identity. It does not settle the owner decisions above.

## Delivery and acceptance boundary

Before adding UI, define a media-job configuration and receipt schema in the
core/agent contract, with migration and validation tests. Then implement a
synthetic-filesystem scanner and queue integration. Acceptance should cover
stable-file delay, unsupported MIME types, edits after an earlier upload,
restart/retry behavior, repeated identical scans, renamed and moved source
files, destination collisions, unavailable permissions/volumes, and recovery
of the displaced copy. Run server-backed tests before exposing controls in the
shell. Add a small configuration form only after those semantics and the owner
choices are settled. Do not present a configured or queued item as uploaded;
the existing transfer state remains the source of truth.

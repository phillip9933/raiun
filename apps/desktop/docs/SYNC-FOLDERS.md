# Sync Folders

Sync Folders brings your folder connections into one list, grouped by OpenCloud
location. Add a folder by choosing its local folder, cloud location and direction.

- **Two-way:** synchronize supported changes in both directions.
- **One-way to cloud:** send local changes to the selected cloud folder.
- **One-way from cloud:** receive cloud changes into the local folder.

Existing files are not automatically deleted when a connection is removed.
A file disappearing from a previous sync is reported for attention; these modes
are not promises of automatic deletion mirroring.

## Files to include

Advanced settings offers All files, Photos or Videos. For ordinary folder sync,
Photos and Videos match the supported filename extensions without regard to
letter case. The help beside each option lists the extensions. Directories remain
traversable so matching files in subfolders are included.

Connections that review existing cloud copies keep their previous upload-only
behavior. Their photo/video filter examines file contents, rather than the name.
Their help identifies the supported content formats. Optional date grouping uses
the filesystem modification date in UTC, not the photograph's capture date.

## Exclusions

Add as many rules as needed within the displayed limits, then save the settings.
Cancel discards the draft. Rules apply to this connection and keep existing local
and cloud files in place; an exclusion does not free disk space or delete a cloud
copy.

- **File type:** enter an extension such as `.tmp` or `.tar.gz`.
- **Folder or file path:** enter a name or source-relative path pattern.

Patterns use the Android client's case-sensitive matching rules:

| Example | Meaning |
| --- | --- |
| `*.tmp` | Matching names at any depth |
| `Cache/` | The named directory and its descendants; not a file named `Cache` |
| `Camera/*.tmp` | Matching files directly under `Camera` |
| `Drafts/**/note?.txt` | Matching paths under `Drafts`, with any number of intermediate directories |

`*` matches within a name, `?` matches one UTF-16 unit, and `**` can cross folders.
A pattern without `/` matches names anywhere. A path containing `/` starts at the
selected local folder. A trailing `/` restricts a rule to directories. Rules are
limited to 100 entries, 255 UTF-16 units per rule and 8,192 units overall.
Previously saved exact-path exclusions remain literal paths, including names
containing wildcard characters. Use the trash icon to remove a rule.

## Change a connection

Use the edit icon beside the trash icon to change direction, included files and
exclusions. Settings are saved together; if the account or connection changed
while the editor was open, refresh and review the change again. Local and cloud
locations remain fixed for an existing connection to preserve its sync history
and recovery binding. Add another connection to use different locations.

For existing upload-only connections that review cloud copies, the editor also
provides their schedule and destination organization options. Their saved
identity, account binding and conflict behavior are preserved.

## Accounts and Settings

Settings groups appearance, accounts, sync and storage, network, security,
diagnostics and update controls. Account colors apply independently to the
selected account's card and header.
Avatars, when available, come only from that account's authenticated OpenCloud
server. Unsupported or unavailable photos use a local fallback.

Removed accounts appear at the bottom. Removing an account retains local files
and recovery; restoring it requires signing in again. Permanent local cleanup is
separate backlog work and is not available in this update.

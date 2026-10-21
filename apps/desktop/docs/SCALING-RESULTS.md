# Synthetic inventory scaling

`raiun-engine/examples/inventory_scale.rs` exercises the engine's local scan,
remote listing, staged inventory, and reconciliation using empty files and a
generated fake backend. All fixture files and engine state are created in a
temporary directory. The generated backend streams entries on demand; it does
not keep the full remote inventory in memory. The example performs no network
access and makes no cloud mutations. A matching warm baseline means the run
measures inventory work, not transfers or first-sync hashing.

Measurements below are from the optimized release example. Sync time is the
example's `engine.sync_pair` duration; setup time is reported separately.

| Files | Directories | Inventory entries | Engine sync | Example-process peak RSS |
|---:|---:|---:|---:|---:|
| 10,000 | 79 | 10,079 | 133 ms | 11,328 KiB |
| 100,000 | 782 | 100,782 | 1,363 ms | 12,192 KiB |
| 1,000,000 | 7,813 | 1,007,813 | 14,004 ms | 12,132 KiB |

The million-file run generated its local fixture in 1,285 ms and seeded
baselines in 3,113 ms. Sync completed in 14,004 ms, with all 1,007,813 entries
unchanged and no uploads, downloads, conflicts, or attention items.

After the local content-hash cache was added, the same million-empty-file
shape (1,000,000 files and 7,813 directories) took 19,722 ms. This is slower
than the earlier 14,004 ms pre-cache result: avoiding file-content reads adds
stat and SQLite metadata work, which can dominate when files are empty and the
scan is listing-bound. No new RSS sample was collected for this run.

The first measurements exposed a benchmark-fixture bug: seeded local mtimes
were stored in seconds while the engine records them in milliseconds. Those
early 10k/100k results (327/9,614 ms before staging batches; 255/8,900 ms
after staging batches) were therefore metadata-refresh stress runs, not
warm-baseline inventory measurements. The first 1m run reached staged
reconciliation but exceeded its 600-second wall bound; phase timestamps had
not yet been added, so setup and sync time could not be separated. A second 1m
run with corrected baselines was stopped after both inventories had staged,
when query-plan inspection found per-page temporary sorting; it did not produce
a completion time. After correcting the fixture and before the query-plan fix,
corrected warm-baseline sync took 193 ms at 10k and 8,309 ms at 100k.

Bundled SQLite 3.46's plan for the original paginated `UNION` query used a
temporary B-tree for the union and another for ordering each page. The engine
now reads up to 256 keys from each side through the `(pair_id, rel_path)` index,
then merges, deduplicates, and truncates the bounded results in memory. Staged
local and remote writes are also committed in batches of 256 rows, with local
file hashing and provider listing outside database transactions. The 100k
warm-baseline run fell from 8,309 ms to 1,363 ms after those changes.

Peak RSS is for the standalone synthetic example process, measured with
Python's `resource.getrusage` because `/usr/bin/time` is not installed in this
environment. These figures do not represent the full Raiun application: they
exclude the desktop UI, agent, FUSE mount, authentication, live provider, and
real network activity. The empty-file warm-baseline fixture also does not
measure content hashing, transfers, or real-world directory-name distributions.

## Persistent local content-hash cache

The Linux engine now reuses a stored SHA-256 only when a safe `statfs` result
identifies ext4, btrfs, XFS, or tmpfs and the complete local fingerprint still
matches: device, inode, size, modification time (seconds and nanoseconds), and
change time (seconds and nanoseconds). Cache reuse is disabled when ctime
nanoseconds are zero, avoiding coarse ext2/3 timestamps. Unknown, network,
FUSE, overlay, and non-Linux filesystems continue to hash every file. Cache
hits are re-statted; conflict scans and pre-write guards still hash content
independently. A full
hash audit runs every 120 completed pair scans, and failed local scans do not
prune cache rows.

A source-only harness at
`outputs/mvp-2026-10-09/hash-cache-benchmark/` (maintainer-local evidence: `../../outputs/mvp-2026-10-09/hash-cache-benchmark/`)
exercised the public engine API on tmpfs with 32 synthetic 16 MiB files (512
MiB total). The first sync took 1,748 ms and uploaded 512 MiB; the fake backend
observed 1,024 MiB of verification downloads. One unchanged scan took 723 µs,
and 117 warm scans averaged 554 µs. Warm scans transferred zero bytes and
reported all 32 files unchanged. Scan 120 forced a complete content-hash audit
and took 242 ms. The warm/audit comparison shows the local scan savings on this
host; the cold first-sync number includes upload and verification work and is
not directly comparable.

This is a synthetic tmpfs CPU/cache result, not a disk-backed or live-provider
benchmark. It shows fewer content reads for unchanged nonempty files, but the
cache still adds metadata and SQLite work; it was not faster in the
million-empty-file listing benchmark above. The harness fake backend stores
remote bodies in memory, the process is already warm, and the content benchmark
does not represent network latency, cache size growth at million-file scale,
power loss, or real photo/video metadata extraction. The measurements are
single runs and should not be generalized as a production throughput
guarantee.

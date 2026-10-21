//! Linux FUSE projection for one account's Personal and Spaces namespace.
//!
//! Remote work is dispatched to a small worker pool. Provider writes land in a
//! durable local spool and are uploaded with an ETag precondition on flush,
//! fsync, and release. Failed uploads leave their spool and manifest in place.
//! Cached namespace state is intentionally bounded: at most 100,000 inodes,
//! 10,000 visible entries per directory, 512 open directory snapshots, and
//! 2,048 open file handles. The inode cache is released by unmounting; this
//! adapter is an MVP and has not been tuned for very large tenants.
//!
//! Replacement file renames preserve the old target under a temporary recovery
//! name before publishing the new file. Encrypted roots use a separate
//! route-bound working copy and conditional backend; ordinary provider
//! recovery files are never used for vault plaintext.

use std::{
    collections::{BTreeMap, HashMap},
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Condvar, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, SyncSender},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(test)]
use std::sync::atomic::AtomicUsize;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

#[cfg(target_os = "linux")]
use nix::sys::statvfs::fstatvfs;

use fuser::{
    Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    InitFlags, KernelConfig, MountOption, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request,
    TimeOrNow,
};
use raiun_cache::CacheScope;
use raiun_core::{
    Space,
    backend::{CloudError, CloudSpace, ErrorKind, RemoteEntry, WriteCondition},
    space_entries,
};
use raiun_engine::{Engine, FetchSnapshot};
use vault_routes::{
    VaultCancelledCreateReceiptState, VaultDirectoryCreateOutcome, VaultInstallHook,
    VaultPendingCreateResolution, VaultPendingDirectoryRetargetState,
    VaultPendingDirectorySubtreeRenameOutcome, VaultReadHandle, VaultRevokeHook, VaultRouteControl,
    VaultRouteLease, VaultUploadOutcome,
};
use vault_write::{
    MAX_VAULT_WORKING_COPY_BYTES, PendingVaultDirectoryRetarget, PendingVaultRetargetOperation,
    PendingVaultRetargetRow, VaultWorkingCopy, VaultWriteBinding,
};

mod pin_recovery;
pub mod recovery;
use pin_recovery::RecoveryNode;
pub mod vault_routes;
pub mod vault_write;
pub use recovery::{RecoveryConditionKind, RecoveryItem, RecoveryPage, RecoveryWarning};
pub use vault_write::{
    PendingVaultCreateCancellation, VaultParentRef, VaultWriteLifecycle, VaultWriteSpool,
    VaultWriteWarning,
};

const ROOT: u64 = 1;

#[cfg(debug_assertions)]
fn trace_vault_file_create_stage(stage: &str) {
    if std::env::var_os("RAIUN_TRACE_VAULT_CREATE").is_some() {
        eprintln!("raiun_vault_file_create_stage={stage}");
    }
}

#[cfg(debug_assertions)]
fn trace_fuse_namespace_error(stage: &str, error: &CloudError) {
    if std::env::var_os("RAIUN_TRACE_FUSE_NAMESPACE").is_some() {
        eprintln!(
            "raiun_fuse_namespace_stage={stage} error_kind={:?}",
            error.kind
        );
    }
}

#[cfg(not(debug_assertions))]
fn trace_fuse_namespace_error(_stage: &str, _error: &CloudError) {}

const PERSONAL: u64 = 2;
const SPACES: u64 = 3;
const TTL: Duration = Duration::from_secs(1);
const MAX_READ: u32 = 1024 * 1024;
const MAX_NODES: usize = 100_000;
const MAX_DIRECTORY_ENTRIES: usize = 10_000;
const MAX_DIRECTORY_HANDLES: usize = 512;
const MAX_FILE_HANDLES: usize = 2_048;
const MAX_VAULT_ROUTES: usize = 16;
// Keep local metadata and recovery work from filling the volume that backs
// the durable upload spool. The advertised writable budget is also capped at
// the largest single working copy accepted by the spool.
const SPOOL_STATFS_HEADROOM_RESERVE_BYTES: u64 = 64 * 1024 * 1024;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SpoolStatfs {
    blocks: u64,
    files: u64,
    files_free: u64,
    block_size: u32,
}

#[cfg(target_os = "linux")]
fn spool_statfs_from_available(
    available_blocks: u64,
    block_size: u64,
    files: u64,
    files_free: u64,
) -> Option<SpoolStatfs> {
    let block_size_u32 = u32::try_from(block_size).ok().filter(|size| *size > 0)?;
    let available_bytes = available_blocks.saturating_mul(block_size);
    let writable_bytes = available_bytes
        .saturating_sub(SPOOL_STATFS_HEADROOM_RESERVE_BYTES)
        .min(MAX_VAULT_WORKING_COPY_BYTES);
    let blocks = writable_bytes / block_size;
    Some(SpoolStatfs {
        // Report the remaining local spool budget as this mount's usable
        // capacity. Remote quota is not known or implied by these values.
        blocks,
        files,
        files_free: files_free.min(files),
        block_size: block_size_u32,
    })
}

#[cfg(target_os = "linux")]
fn spool_statfs(fd: &File) -> std::io::Result<SpoolStatfs> {
    let stats = fstatvfs(fd)?;
    let block_size = stats.fragment_size();
    let snapshot = spool_statfs_from_available(
        stats.blocks_available() as u64,
        block_size as u64,
        stats.files() as u64,
        stats.files_available() as u64,
    )
    .ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "local spool filesystem capacity is unavailable",
        )
    })?;
    Ok(snapshot)
}

#[cfg(target_os = "linux")]
fn open_spool_capacity_dir(path: &Path) -> std::io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "local spool capacity handle is not a directory",
        ));
    }
    Ok(file)
}
const LOCKED_VAULT_README: &str = "This encrypted location is locked.\n\
Raiun hides its contents while locked. Open Raiun, select this location, and unlock it to browse files.\n\
This notice is local and does not change cloud data.\n";
// Linux FUSE passes the kernel's raw O_LARGEFILE bit in `CREATE` flags even on
// 64-bit libc targets where libc::O_LARGEFILE is zero.
#[cfg(target_os = "linux")]
const LINUX_KERNEL_O_LARGEFILE: i32 = 0x8000;
#[cfg(not(target_os = "linux"))]
const LINUX_KERNEL_O_LARGEFILE: i32 = 0;
static MANIFEST_TEMP_ID: AtomicU64 = AtomicU64::new(1);
type VaultRouteKey = (String, String, String);
type VaultRouteMap = BTreeMap<VaultRouteKey, VaultMountRoute>;

fn vault_open_flags_supported(flags: i32) -> bool {
    let supported = libc::O_ACCMODE
        | libc::O_APPEND
        | libc::O_TRUNC
        | libc::O_CREAT
        | libc::O_EXCL
        | libc::O_CLOEXEC
        | libc::O_LARGEFILE
        | LINUX_KERNEL_O_LARGEFILE
        | libc::O_NOCTTY
        | libc::O_NONBLOCK
        | libc::O_SYNC
        | libc::O_DSYNC
        | libc::O_NOFOLLOW;
    flags & !supported == 0
}

type Job = Box<dyn FnOnce() + Send + 'static>;

#[derive(Clone)]
struct RemotePool {
    tx: SyncSender<Job>,
}

impl RemotePool {
    fn new(worker_count: usize) -> Self {
        let (tx, rx) = mpsc::sync_channel::<Job>(64);
        let rx = Arc::new(Mutex::new(rx));
        for _ in 0..worker_count.max(1) {
            let receiver = Arc::clone(&rx);
            thread::spawn(move || {
                loop {
                    let job = receiver.lock().ok().and_then(|guard| guard.recv().ok());
                    match job {
                        Some(job) => job(),
                        None => break,
                    }
                }
            });
        }
        Self { tx }
    }

    fn call<T: Send + 'static>(
        &self,
        operation: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, CloudError> {
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        self.tx
            .send(Box::new(move || {
                let _ = result_tx.send(operation());
            }))
            .map_err(|_| {
                CloudError::new(ErrorKind::Offline, "provider worker pool is unavailable")
            })?;
        result_rx.recv().map_err(|_| {
            CloudError::new(
                ErrorKind::Offline,
                "provider operation stopped unexpectedly",
            )
        })
    }
}

#[derive(Clone)]
enum NodeKind {
    Recovery(RecoveryNode),
    Root,
    Personal {
        space: String,
    },
    Spaces,
    Space {
        space: String,
    },
    Remote {
        space: String,
        entry: RemoteEntry,
    },
    Vault {
        route: VaultMountRoute,
        generation: u64,
        entry: RemoteEntry,
    },
    LockedVault {
        profile_id: String,
        space: String,
        resource_id: Option<String>,
        remote_path: String,
    },
    LockedReadme {
        parent: u64,
    },
}

#[derive(Clone)]
struct Node {
    ino: u64,
    parent: u64,
    name: String,
    kind: NodeKind,
    metadata_expires_at: Instant,
}

enum OpenFile {
    Read(ReadHandle),
    Write(Box<WriteHandle>),
    Vault {
        route: VaultRouteControl,
        generation: u64,
        ino: u64,
        path: String,
        handle: Option<VaultReadHandle>,
    },
    VaultWrite(Box<VaultWriteHandle>),
}

enum ReadHandle {
    Recovery(raiun_cache::CacheContentReader),
    Local(File),
    Snapshot(FetchSnapshot),
    Static(Cursor<Vec<u8>>),
}

trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

struct WriteHandle {
    file: File,
    spool: PathBuf,
    manifest: PathBuf,
    space: String,
    path: String,
    condition: WriteCondition,
    scope: CacheScope,
    resource_id: Option<String>,
    dirty: bool,
    ino: u64,
    cleanup_on_release: bool,
}

struct VaultWriteHandle {
    route: VaultRouteControl,
    generation: u64,
    binding: VaultWriteBinding,
    working: VaultWorkingCopy,
    path: String,
    entry_id: String,
    condition: WriteCondition,
    dirty: bool,
    closing: bool,
    ino: u64,
    flags: i32,
    active_key: String,
}

struct VaultRouteReader<'a, 'b> {
    lease: &'a VaultRouteLease<'b>,
    handle: &'a VaultReadHandle,
    offset: u64,
}

impl Read for VaultRouteReader<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let bytes = self
            .lease
            .read(self.handle, self.offset, output.len())
            .map_err(|error| std::io::Error::other(error.message))?;
        output[..bytes.len()].copy_from_slice(&bytes);
        self.offset = self.offset.saturating_add(bytes.len() as u64);
        Ok(bytes.len())
    }
}

impl Seek for VaultRouteReader<'_, '_> {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        let next = match position {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::Current(delta) => i128::from(self.offset) + i128::from(delta),
            SeekFrom::End(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "vault source does not support end-relative seeks",
                ));
            }
        };
        if !(0..=i128::from(u64::MAX)).contains(&next) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "vault source seek is out of range",
            ));
        }
        self.offset = next as u64;
        Ok(self.offset)
    }
}

struct State {
    nodes: HashMap<u64, Node>,
    children: HashMap<(u64, String), u64>,
    // Emitted historical names remain mutation-denied for this mount session,
    // even if an already admitted cloud operation later replaces the mapping.
    recovery_aliases: std::collections::HashSet<(u64, String)>,
    file_handles: HashMap<u64, Arc<Mutex<OpenFile>>>,
    vault_file_handles: HashMap<u64, VaultFileHandleMeta>,
    directory_handles: HashMap<u64, DirectoryHandle>,
    pending_parent_refs: HashMap<u64, (u64, VaultParentRef)>,
    active_writers: std::collections::HashSet<String>,
}

/// Immutable metadata used to fence namespace moves against already-open
/// vault files. Keep it outside the OpenFile mutex: revocation and rename
/// both hold State while changing these indexes, and must never acquire a
/// handle mutex in the opposite lock order.
#[derive(Clone, Debug, PartialEq, Eq)]
struct VaultFileHandleMeta {
    route_id: u64,
    ino: u64,
    path: String,
    writable: bool,
}

#[derive(Clone)]
struct DirectoryHandle {
    entries: Vec<(String, u64, FileType)>,
    routes: Vec<(VaultRouteControl, u64)>,
    locked_vaults: Vec<u64>,
    owner_vault: Option<(u64, u64, u64, String)>,
}

struct RegisteredVaultHooks {
    _revoke: VaultRevokeHook,
    _install: VaultInstallHook,
}

fn directory_vault_routes(parent: &Node, children: &[Node]) -> Vec<(VaultRouteControl, u64)> {
    let mut routes = BTreeMap::new();
    let mut add = |node: &Node| {
        if let NodeKind::Vault {
            route, generation, ..
        } = &node.kind
        {
            routes
                .entry(route.control.route_id())
                .or_insert_with(|| (route.control.clone(), *generation));
        }
    };
    add(parent);
    for child in children {
        add(child);
    }
    routes.into_values().collect()
}

fn with_vault_route_leases<T, F>(
    routes: &[(VaultRouteControl, u64)],
    index: usize,
    operation: F,
) -> Result<T, CloudError>
where
    F: FnOnce() -> Result<T, CloudError>,
{
    let Some((route, generation)) = routes.get(index) else {
        return operation();
    };
    route.with_read_lease(*generation, |_| {
        with_vault_route_leases(routes, index + 1, operation)
    })
}

fn purge_vault_route_state(
    shared_state: &Arc<Mutex<State>>,
    route_id: u64,
) -> Result<Vec<(u64, String, u64)>, CloudError> {
    let mut state = shared_state
        .lock()
        .map_err(|_| io_error("provider state is unavailable"))?;
    let removed: std::collections::HashSet<u64> = state
        .nodes
        .iter()
        .filter_map(|(ino, node)| match &node.kind {
            NodeKind::Vault { route, .. } if route.control.route_id() == route_id => Some(*ino),
            _ => None,
        })
        .collect();
    let invalidations = removed
        .iter()
        .filter_map(|ino| {
            state
                .nodes
                .get(ino)
                .map(|node| (node.parent, node.name.clone(), *ino))
        })
        .collect();
    state.nodes.retain(|ino, _| !removed.contains(ino));
    state
        .pending_parent_refs
        .retain(|ino, _| !removed.contains(ino));
    state
        .children
        .retain(|_, child_ino| !removed.contains(child_ino));
    state.directory_handles.retain(|_, handle| {
        !handle
            .routes
            .iter()
            .any(|(route, _)| route.route_id() == route_id)
    });
    let vault_handles: Vec<u64> = state
        .vault_file_handles
        .iter()
        .filter_map(|(handle, owner)| (owner.route_id == route_id).then_some(*handle))
        .collect();
    for handle in vault_handles {
        state.vault_file_handles.remove(&handle);
        state.file_handles.remove(&handle);
    }
    state.active_writers.retain(|key| {
        !key.starts_with(&format!("vault-write:{route_id}:\0"))
            && !key.starts_with(&format!("vault-subtree:{route_id}:\0"))
    });
    Ok(invalidations)
}

fn trace_vault_install_hook_stage(stage: &'static str) {
    #[cfg(debug_assertions)]
    if std::env::var_os("RAIUN_TRACE_VAULT_CREATE").is_some() {
        eprintln!("raiun_vault_install_hook_stage={stage}");
    }
    #[cfg(not(debug_assertions))]
    let _ = stage;
}

fn purge_locked_vault_state(
    shared_state: &Arc<Mutex<State>>,
    profile_id: &str,
    space: &str,
    root_path: &str,
    resource_id: &str,
    root_name: &str,
) -> Result<Vec<(u64, String, u64)>, CloudError> {
    let mut state = shared_state
        .lock()
        .map_err(|_| io_error("provider state is unavailable"))?;
    let removed: std::collections::HashSet<u64> = state
        .nodes
        .iter()
        .filter_map(|(ino, node)| match &node.kind {
            NodeKind::LockedVault {
                profile_id: current_profile,
                space: current_space,
                resource_id: Some(current_id),
                remote_path: current_path,
            } if current_profile == profile_id
                && current_space == space
                && current_path == root_path
                && current_id == resource_id =>
            {
                Some(*ino)
            }
            _ => None,
        })
        .collect();
    let mut all_removed = removed.clone();
    all_removed.extend(state.nodes.iter().filter_map(|(ino, node)| {
        matches!(&node.kind, NodeKind::LockedReadme { parent } if removed.contains(parent))
            .then_some(*ino)
    }));
    let mut invalidations = all_removed
        .iter()
        .filter_map(|ino| {
            state
                .nodes
                .get(ino)
                .map(|node| (node.parent, node.name.clone(), *ino))
        })
        .collect::<Vec<_>>();
    let parent_path = root_path
        .rsplit_once('/')
        .map(|(parent, _)| if parent.is_empty() { "/" } else { parent });
    let parent_ino = if root_path == "/" {
        // Whole-Space roots are children of the synthetic Spaces container.
        state.nodes.get(&SPACES).map(|node| node.ino)
    } else {
        let parent_path = parent_path.unwrap_or("/");
        state.nodes.values().find_map(|node| match &node.kind {
            NodeKind::Personal { space: current } | NodeKind::Space { space: current }
                if current == space && parent_path == "/" =>
            {
                Some(node.ino)
            }
            NodeKind::Remote {
                space: current,
                entry,
            } if current == space && entry.path == parent_path && entry.directory => Some(node.ino),
            _ => None,
        })
    };
    if let Some(parent_ino) = parent_ino
        && !invalidations
            .iter()
            .any(|(parent, name, _)| *parent == parent_ino && name == root_name)
    {
        // Also invalidate the entry even when no LockedVault node was
        // materialized. A cached negative dentry for a newly registered root
        // is still possible in the kernel.
        invalidations.push((parent_ino, root_name.to_owned(), 0));
    }
    state.nodes.retain(|ino, _| !all_removed.contains(ino));
    state
        .children
        .retain(|_, child_ino| !all_removed.contains(child_ino));
    state
        .directory_handles
        .retain(|_, handle| !handle.locked_vaults.iter().any(|ino| removed.contains(ino)));
    Ok(invalidations)
}

struct PathReservation<'a> {
    state: &'a Mutex<State>,
    changed: &'a Condvar,
    key: String,
    active: bool,
}

impl PathReservation<'_> {
    fn disarm(mut self) {
        self.active = false;
    }
}

impl Drop for PathReservation<'_> {
    fn drop(&mut self) {
        if self.active {
            if let Ok(mut state) = self.state.lock() {
                state.active_writers.remove(&self.key);
                self.changed.notify_all();
            }
        }
    }
}

fn vault_reservation_path(key: &str, route_id: u64) -> Option<(bool, &str)> {
    let writer_prefix = format!("vault-write:{route_id}:\0");
    if let Some(path) = key.strip_prefix(&writer_prefix) {
        return Some((false, path));
    }
    let cancellation_prefix = format!("vault-cancel-file:{route_id}:\0");
    if let Some(path) = key.strip_prefix(&cancellation_prefix) {
        return Some((false, path));
    }
    let subtree_prefix = format!("vault-subtree:{route_id}:\0");
    key.strip_prefix(&subtree_prefix).map(|path| (true, path))
}

fn persist_subtree_retarget_wal(
    spool: &VaultWriteSpool,
    outcome: &VaultPendingDirectorySubtreeRenameOutcome,
    source_path: &str,
    destination_path: &str,
) -> Result<PendingVaultDirectoryRetarget, CloudError> {
    let (records, truncated) = spool.list_pending().map_err(vault_write_error)?;
    if truncated {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "queued subtree rename could not verify the complete local spool",
        ));
    }
    let operation_ids: std::collections::HashSet<&str> = outcome
        .rows
        .iter()
        .map(|row| row.write_id.as_str())
        .collect();
    let mut rows = Vec::with_capacity(outcome.rows.len());
    let mut local_write_ids = std::collections::HashSet::new();
    for row in &outcome.rows {
        if row.previous_revision.checked_add(1) != Some(row.revision) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "queued subtree contains a changed or unresolved operation",
            ));
        }
        let (record_id, old_target, bytes, sha256) = match row.operation {
            vault_routes::VaultPendingSubtreeOperation::CreateFile => {
                let mut matching = records.iter().filter(|record| {
                    record.scope.as_ref() == Some(&outcome.scope)
                        && matches!(record.lifecycle.as_ref(),
                            Some(VaultWriteLifecycle::Queued { write_id, revision, uncertain: false, .. })
                                if write_id == &row.write_id && *revision == row.previous_revision)
                });
                let record = matching.next().ok_or_else(|| {
                    CloudError::new(
                        ErrorKind::Conflict,
                        "queued subtree file has no exact clean local copy",
                    )
                })?;
                if matching.next().is_some() {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "queued subtree file has duplicate local copies",
                    ));
                }
                let old_target = record.target.clone().ok_or_else(|| {
                    CloudError::new(ErrorKind::Conflict, "queued file binding is unavailable")
                })?;
                let (bytes, sha256, write_id, revision) = match record.lifecycle.as_ref() {
                    Some(VaultWriteLifecycle::Queued {
                        bytes,
                        sha256,
                        write_id,
                        revision,
                        uncertain: false,
                    }) => (*bytes, sha256.clone(), write_id, *revision),
                    _ => unreachable!("filtered lifecycle changed"),
                };
                if write_id != &row.write_id
                    || revision != row.previous_revision
                    || bytes != row.plaintext_len
                    || sha256 != row.plaintext_sha256
                    || old_target.condition() != &WriteCondition::Absent
                    || row.target.condition() != &WriteCondition::Absent
                    || row.target.parent_ref() != Some(&row.parent_ref)
                {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "queued subtree file does not match its journal identity",
                    ));
                }
                local_write_ids.insert(row.write_id.as_str());
                (
                    Some(record.record_id.clone()),
                    Some(old_target),
                    bytes,
                    sha256,
                )
            }
            vault_routes::VaultPendingSubtreeOperation::CreateDirectory => {
                if row.plaintext_len != 0 || !row.plaintext_sha256.is_empty() {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "queued directory unexpectedly has content",
                    ));
                }
                let old_target = row.old_target.clone().ok_or_else(|| {
                    CloudError::new(
                        ErrorKind::Conflict,
                        "queued directory has no authenticated old target",
                    )
                })?;
                if old_target.condition() != &WriteCondition::Absent
                    || row.target.condition() != &WriteCondition::Absent
                    || old_target.parent_ref().is_none()
                    || row.target.parent_ref() != Some(&row.parent_ref)
                {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "queued directory binding does not match its journal identity",
                    ));
                }
                (None, Some(old_target), 0, String::new())
            }
        };
        rows.push(PendingVaultRetargetRow {
            write_id: row.write_id.clone(),
            previous_revision: row.previous_revision,
            revision: row.revision,
            operation: match row.operation {
                vault_routes::VaultPendingSubtreeOperation::CreateFile => {
                    PendingVaultRetargetOperation::CreateFile
                }
                vault_routes::VaultPendingSubtreeOperation::CreateDirectory => {
                    PendingVaultRetargetOperation::CreateDirectory
                }
            },
            old_path: row.old_path.clone(),
            path: row.path.clone(),
            record_id,
            old_target,
            target: row.target.clone(),
            bytes,
            sha256,
        });
    }
    // A local spool row whose authenticated pending-parent reference names a
    // member of this closure must itself occur in the exact backend closure.
    for record in records {
        if record.scope.as_ref() != Some(&outcome.scope) {
            continue;
        }
        let Some(target) = record.target else {
            continue;
        };
        let Some(
            VaultWriteLifecycle::Queued { write_id, .. }
            | VaultWriteLifecycle::DirtyQueued { write_id, .. }
            | VaultWriteLifecycle::BuildingCreate { write_id, .. }
            | VaultWriteLifecycle::DirtyBuildingCreate { write_id, .. },
        ) = record.lifecycle
        else {
            continue;
        };
        if target.parent_ref().is_some_and(|parent| {
            matches!(parent, crate::vault_write::VaultParentRef::PendingCreate { write_id, .. }
                if operation_ids.contains(write_id.as_str()))
        }) && !local_write_ids.contains(write_id.as_str())
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "queued subtree has a dirty or unsupported local descendant",
            ));
        }
    }
    let wal = PendingVaultDirectoryRetarget {
        scope: outcome.scope.clone(),
        root_write_id: outcome.root_write_id.clone(),
        root_previous_revision: outcome.root_previous_revision,
        root_revision: outcome.root_revision,
        source_path: source_path.to_owned(),
        destination_path: destination_path.to_owned(),
        rows,
    };
    spool
        .begin_directory_subtree_retarget(&wal)
        .map_err(vault_write_error)?;
    Ok(wal)
}

struct RaiunFilesystem {
    engine: Engine,
    pool: RemotePool,
    project_spaces: Vec<(String, CloudSpace)>,
    mounted_spaces: HashMap<String, CloudSpace>,
    spool_dir: PathBuf,
    #[cfg(target_os = "linux")]
    spool_capacity_dir: Option<File>,
    vault_write_spool: Option<VaultWriteSpool>,
    vault_write_spool_error: Option<String>,
    owner_uid: u32,
    owner_gid: u32,
    state: Arc<Mutex<State>>,
    active_writer_changed: Arc<Condvar>,
    vault_retarget_recovery: Mutex<std::collections::HashSet<(u64, u64)>>,
    vault_subtree_recovery: Mutex<std::collections::HashSet<(u64, u64)>>,
    vault_cancel_recovery: Mutex<std::collections::HashSet<(u64, u64)>>,
    next_handle: AtomicU64,
    vault_registry: VaultMountRegistry,
    registered_route_hooks: Mutex<HashMap<u64, RegisteredVaultHooks>>,
    notifier: Arc<Mutex<Option<fuser::Notifier>>>,
    local_profile_id: String,
}

fn verify_subtree_retarget_proof(
    wal: &PendingVaultDirectoryRetarget,
    proof: &vault_routes::VaultPendingDirectoryRetargetResolution,
) -> Result<(), CloudError> {
    if proof.scope != wal.scope
        || proof.root_write_id != wal.root_write_id
        || proof.root_previous_revision != wal.root_previous_revision
        || proof.root_revision
            != match proof.state {
                VaultPendingDirectoryRetargetState::AllOld => wal.root_previous_revision,
                VaultPendingDirectoryRetargetState::AllNew => wal.root_revision,
            }
        || proof.rows.len() != wal.rows.len()
    {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "queued subtree recovery proof does not match its durable intent",
        ));
    }

    let mut seen = std::collections::HashSet::with_capacity(proof.rows.len());
    for row in &proof.rows {
        if !seen.insert(row.write_id.as_str()) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "queued subtree recovery proof repeats an operation",
            ));
        }
        let expected = wal
            .rows
            .iter()
            .find(|expected| expected.write_id == row.write_id)
            .ok_or_else(|| {
                CloudError::new(
                    ErrorKind::Conflict,
                    "queued subtree recovery proof contains an unknown row",
                )
            })?;
        let expected_path = match proof.state {
            VaultPendingDirectoryRetargetState::AllOld => &expected.old_path,
            VaultPendingDirectoryRetargetState::AllNew => &expected.path,
        };
        let expected_operation = match expected.operation {
            PendingVaultRetargetOperation::CreateFile => {
                crate::vault_routes::VaultPendingSubtreeOperation::CreateFile
            }
            PendingVaultRetargetOperation::CreateDirectory => {
                crate::vault_routes::VaultPendingSubtreeOperation::CreateDirectory
            }
        };
        if row.previous_revision != expected.previous_revision
            || row.revision != expected.revision
            || row.operation != expected_operation
            || row.old_path != expected.old_path
            || row.path != *expected_path
            || row.plaintext_len != expected.bytes
            || row.plaintext_sha256 != expected.sha256
            || row.target.parent_ref() != Some(&row.parent_ref)
            || match proof.state {
                VaultPendingDirectoryRetargetState::AllOld => expected
                    .old_target
                    .as_ref()
                    .is_none_or(|target| target != &row.target),
                VaultPendingDirectoryRetargetState::AllNew => row.target != expected.target,
            }
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "queued subtree recovery proof differs from its durable row",
            ));
        }
    }
    if seen.len() != wal.rows.len()
        || wal
            .rows
            .iter()
            .any(|row| !seen.contains(row.write_id.as_str()))
    {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "queued subtree recovery proof omits a durable operation",
        ));
    }
    Ok(())
}

/// An explicitly configured folder-vault overlay. The route remains live
/// across lock/unlock; individual FUSE nodes capture a specific generation.
#[derive(Clone)]
pub struct VaultMountRoute {
    space_id: String,
    root_path: String,
    root_resource_id: String,
    control: VaultRouteControl,
}

/// Dynamic set of explicitly configured folder-vault roots shared by the
/// runtime and FUSE mount. The registry stores no unlocked generation.
#[derive(Clone, Default)]
pub struct VaultMountRegistry {
    routes: Arc<RwLock<VaultRouteMap>>,
}

impl VaultMountRoute {
    pub fn new(
        space_id: String,
        root_path: String,
        root_resource_id: String,
        control: VaultRouteControl,
    ) -> Result<Self, CloudError> {
        if space_id.is_empty() || root_resource_id.is_empty() {
            return Err(invalid("vault route identity is incomplete"));
        }
        let root_path = normalize_vault_root(&root_path)?;
        Ok(Self {
            space_id,
            root_path,
            root_resource_id,
            control,
        })
    }

    pub fn generation(&self) -> Result<u64, CloudError> {
        self.control.generation()
    }

    pub fn control(&self) -> &VaultRouteControl {
        &self.control
    }

    pub fn space_id(&self) -> &str {
        &self.space_id
    }

    pub fn root_path(&self) -> &str {
        &self.root_path
    }

    pub fn root_resource_id(&self) -> &str {
        &self.root_resource_id
    }

    fn matches(&self, space: &str, entry: &RemoteEntry) -> bool {
        self.space_id == space
            && normalize_entry_path(&entry.path).as_deref() == Some(self.root_path.as_str())
            && entry.id == self.root_resource_id
            && entry.encrypted
            && entry.directory
    }
}

impl VaultMountRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, route: VaultMountRoute) -> Result<(), CloudError> {
        let key = (
            route.space_id.clone(),
            route.root_path.clone(),
            route.root_resource_id.clone(),
        );
        let mut routes = self
            .routes
            .write()
            .map_err(|_| io_error("vault route registry is unavailable"))?;
        if routes.contains_key(&key) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "vault route is already registered",
            ));
        }
        if routes.len() >= MAX_VAULT_ROUTES {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "vault route registry limit reached",
            ));
        }
        if routes.iter().any(|((space, path, resource), _)| {
            space == &route.space_id
                && (resource == &route.root_resource_id || paths_overlap(path, &route.root_path))
        }) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "overlapping vault roots are not supported",
            ));
        }
        routes.insert(key, route);
        Ok(())
    }

    pub fn remove(
        &self,
        space_id: &str,
        root_path: &str,
        root_resource_id: &str,
    ) -> Result<Option<VaultMountRoute>, CloudError> {
        let key = (
            space_id.to_owned(),
            normalize_vault_root(root_path)?,
            root_resource_id.to_owned(),
        );
        let mut routes = self
            .routes
            .write()
            .map_err(|_| io_error("vault route registry is unavailable"))?;
        if let Some(route) = routes.get(&key)
            && route.control.is_active()?
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "vault route must be revoked before it is removed",
            ));
        }
        Ok(routes.remove(&key))
    }

    pub fn get(
        &self,
        space_id: &str,
        root_path: &str,
        root_resource_id: &str,
    ) -> Result<Option<VaultMountRoute>, CloudError> {
        let key = (
            space_id.to_owned(),
            normalize_vault_root(root_path)?,
            root_resource_id.to_owned(),
        );
        self.routes
            .read()
            .map(|routes| routes.get(&key).cloned())
            .map_err(|_| io_error("vault route registry is unavailable"))
    }

    /// Find the single route bound to an encrypted Space root. The Space ID
    /// scopes `/`; folder routes in other Spaces cannot alias this root.
    pub fn get_space_root(&self, space_id: &str) -> Result<Option<VaultMountRoute>, CloudError> {
        self.routes
            .read()
            .map(|routes| {
                routes
                    .values()
                    .find(|route| route.space_id == space_id && route.root_path == "/")
                    .cloned()
            })
            .map_err(|_| io_error("vault route registry is unavailable"))
    }

    pub fn routes(&self) -> Result<Vec<VaultMountRoute>, CloudError> {
        self.routes
            .read()
            .map(|routes| routes.values().cloned().collect())
            .map_err(|_| io_error("vault route registry is unavailable"))
    }

    pub fn clear_revoked(&self) -> Result<(), CloudError> {
        let mut routes = self
            .routes
            .write()
            .map_err(|_| io_error("vault route registry is unavailable"))?;
        if routes
            .values()
            .any(|route| route.control.is_active().unwrap_or(true))
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "all vault routes must be revoked before clearing the registry",
            ));
        }
        routes.clear();
        Ok(())
    }
}

/// A live FUSE mount. Dropping the handle unmounts and joins the FUSE session.
pub struct MountHandle {
    session: Option<fuser::BackgroundSession>,
    root: PathBuf,
    source: String,
}

impl MountHandle {
    /// Whether this process still sees the FUSE mount at its configured root.
    /// If mountinfo cannot be read, keep the conservative answer that a live
    /// session may still be mounted.
    pub fn is_mounted(&self) -> bool {
        mountpoint_has_source(&self.root, &self.source).unwrap_or(self.session.is_some())
    }

    /// Unmount through fusermount3 while retaining the background session until
    /// the mount has actually disappeared. This lets callers retry a busy or
    /// otherwise failed unmount instead of losing fuser's only session handle.
    pub fn unmount(&mut self) -> Result<(), String> {
        if self.session.is_none() {
            return Ok(());
        }

        let owned_mount_present =
            mountpoint_has_source(&self.root, &self.source).map_err(|error| {
                format!("could not verify cloud mount ownership; leaving it mounted: {error}")
            })?;
        if owned_mount_present {
            let result = Command::new("fusermount3")
                .arg("-u")
                .arg(&self.root)
                .output()
                .map_err(|error| format!("could not run fusermount3: {error}"))?;
            let still_owned = mountpoint_has_source(&self.root, &self.source).map_err(|error| {
                format!("could not verify whether the cloud root detached: {error}")
            })?;
            if still_owned {
                let message = String::from_utf8_lossy(&result.stderr);
                let detail = message.trim();
                return Err(if detail.is_empty() {
                    format!("fusermount3 exited with {}", result.status)
                } else {
                    format!("fusermount3 could not unmount the cloud root: {detail}")
                });
            }
        }

        let Some(session) = self.session.take() else {
            return Ok(());
        };
        session.join().map_err(|error| {
            format!("cloud root is unmounted, but its FUSE session did not stop cleanly: {error}")
        })
    }
}

impl Drop for MountHandle {
    fn drop(&mut self) {
        let _ = self.unmount();
    }
}

fn mountpoint_has_source(root: &Path, source: &str) -> std::io::Result<bool> {
    let mountinfo = fs::read("/proc/self/mountinfo")?;
    Ok(mountinfo_has_fuse_source(
        &mountinfo,
        root,
        source.as_bytes(),
    ))
}

#[cfg(test)]
fn mountinfo_contains_mountpoint(mountinfo: &[u8], root: &Path) -> bool {
    let expected = mountinfo_escape(root);
    mountinfo.split(|byte| *byte == b'\n').any(|line| {
        let Some(separator) = line.windows(3).position(|window| window == b" - ") else {
            return false;
        };
        let before = &line[..separator];
        let after = &line[separator + 3..];
        let mountpoint = before
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty())
            .nth(4);
        let filesystem = after
            .split(u8::is_ascii_whitespace)
            .find(|field| !field.is_empty());
        mountpoint == Some(expected.as_slice())
            && filesystem.is_some_and(|kind| kind.starts_with(b"fuse"))
    })
}

#[cfg(unix)]
fn mountinfo_escape(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    let mut escaped = Vec::new();
    for byte in path.as_os_str().as_bytes() {
        match byte {
            b' ' => escaped.extend_from_slice(b"\\040"),
            b'\t' => escaped.extend_from_slice(b"\\011"),
            b'\n' => escaped.extend_from_slice(b"\\012"),
            b'\\' => escaped.extend_from_slice(b"\\134"),
            byte => escaped.push(*byte),
        }
    }
    escaped
}

#[cfg(not(unix))]
fn mountinfo_escape(path: &Path) -> Vec<u8> {
    path.to_string_lossy().as_bytes().to_vec()
}

/// Attempt recovery only for a disconnected Raiun mount created for this state directory.
/// Legacy `OpenCloud` mounts have no ownership identity and are intentionally left alone.
pub fn recover_stale_mount(root: &Path, state_dir: &Path) -> Result<bool, String> {
    let root = normalize_mount_path(root)?;
    let read_error = match fs::read_dir(&root) {
        Ok(mut entries) => match entries.next() {
            Some(Err(error)) if error.raw_os_error() == Some(libc::ENOTCONN) => error,
            Some(Err(_)) | Some(Ok(_)) | None => return Ok(false),
        },
        Err(error) if error.raw_os_error() == Some(libc::ENOTCONN) => error,
        Err(_) => return Ok(false),
    };
    let state_dir = fs::canonicalize(state_dir)
        .map_err(|error| format!("provider state directory is unavailable: {error}"))?;
    let expected_source = mount_source(&state_dir);
    let mountinfo = fs::read("/proc/self/mountinfo")
        .map_err(|error| format!("could not inspect mount ownership: {error}"))?;
    let Some(actual_source) = mountinfo_fuse_source_at(&mountinfo, &root) else {
        return Ok(false);
    };
    if actual_source != expected_source.as_bytes() {
        return if actual_source == b"OpenCloud" {
            Err("Cloud root has a disconnected legacy OpenCloud FUSE mount without ownership metadata; eject it in the file manager, then retry mounting".into())
        } else {
            Err("Cloud root has a disconnected FUSE mount owned by another provider; eject it in the file manager, then retry mounting".into())
        };
    }

    let result = Command::new("fusermount3")
        .arg("-u")
        .arg(&root)
        .output()
        .map_err(|error| {
            format!("could not run fusermount3 for disconnected Raiun mount: {error}")
        })?;
    let still_owned = fs::read("/proc/self/mountinfo")
        .map(|data| mountinfo_has_fuse_source(&data, &root, expected_source.as_bytes()))
        .unwrap_or(true);
    if still_owned {
        let detail = String::from_utf8_lossy(&result.stderr);
        let detail = detail.trim();
        return Err(if detail.is_empty() {
            format!("could not detach disconnected Raiun mount: {read_error}")
        } else {
            format!("could not detach disconnected Raiun mount: {detail}")
        });
    }
    Ok(true)
}

/// Unmount an exact profile-owned FUSE mount when its process handle was lost.
/// Any other FUSE provider at the configured path is left mounted and reported.
pub fn unmount_profile_mount(root: &Path, state_dir: &Path) -> Result<bool, String> {
    let root = normalize_mount_path(root)?;
    let mountinfo = fs::read("/proc/self/mountinfo")
        .map_err(|error| format!("could not inspect cloud mount: {error}"))?;
    let Some(actual_source) = mountinfo_fuse_source_at(&mountinfo, &root) else {
        return Ok(false);
    };
    let state_dir = fs::canonicalize(state_dir)
        .map_err(|error| format!("provider state directory is unavailable: {error}"))?;
    let expected_source = mount_source(&state_dir);
    if actual_source != expected_source.as_bytes() {
        return Err(if actual_source == b"OpenCloud" {
            "Cloud root is mounted by a legacy OpenCloud provider whose ownership cannot be verified; eject it in the file manager before signing out".into()
        } else {
            "Cloud root is mounted by another FUSE provider; eject it in the file manager before signing out".into()
        });
    }
    let result = Command::new("fusermount3")
        .arg("-u")
        .arg(&root)
        .output()
        .map_err(|error| format!("could not run fusermount3: {error}"))?;
    let still_owned = fs::read("/proc/self/mountinfo")
        .map(|data| mountinfo_has_fuse_source(&data, &root, expected_source.as_bytes()))
        .unwrap_or(true);
    if still_owned {
        let detail = String::from_utf8_lossy(&result.stderr);
        let detail = detail.trim();
        return Err(if detail.is_empty() {
            format!(
                "could not unmount the Raiun cloud root: fusermount3 exited with {}",
                result.status
            )
        } else {
            format!("could not unmount the Raiun cloud root: {detail}")
        });
    }
    Ok(true)
}

/// Mount the account namespace at an existing empty directory.
pub fn mount(engine: Engine, root: &Path, state_dir: &Path) -> Result<MountHandle, String> {
    mount_with_vault_registry(engine, root, state_dir, VaultMountRegistry::new())
}

/// Mount with an explicit shared registry of folder-vault overlays.
pub fn mount_with_vault_registry(
    engine: Engine,
    root: &Path,
    state_dir: &Path,
    vault_registry: VaultMountRegistry,
) -> Result<MountHandle, String> {
    mount_with_vault_registry_for_profile(engine, root, state_dir, "default", vault_registry)
}

/// Mount the namespace with immutable local profile identity for scoped
/// encrypted-location navigation. This ID is never a server account claim.
pub fn mount_with_vault_registry_for_profile(
    engine: Engine,
    root: &Path,
    state_dir: &Path,
    profile_id: &str,
    vault_registry: VaultMountRegistry,
) -> Result<MountHandle, String> {
    if !valid_profile_id(profile_id) {
        return Err("local profile identifier is invalid".into());
    }
    let root = normalize_mount_path(root)?;
    fs::create_dir_all(state_dir)
        .map_err(|error| format!("could not create provider state directory: {error}"))?;
    let state_dir = fs::canonicalize(state_dir)
        .map_err(|error| format!("provider state directory is unavailable: {error}"))?;
    let _ = recover_stale_mount(&root, &state_dir)?;
    let root =
        fs::canonicalize(root).map_err(|error| format!("mount root is unavailable: {error}"))?;
    if !root.is_dir() {
        return Err("mount root must be a directory".into());
    }
    if fs::read_dir(&root)
        .map_err(|error| format!("could not inspect mount root: {error}"))?
        .next()
        .is_some()
    {
        return Err("mount root must be empty so existing files are not hidden".into());
    }
    if state_dir == root || state_dir.starts_with(&root) {
        return Err("provider state directory must be outside the mounted cloud root".into());
    }
    let spool_dir = state_dir.join("provider-spool");
    prepare_spool_dir(&spool_dir).map_err(|error| error.to_string())?;
    let mount_owner = fs::metadata(&root)
        .map_err(|error| format!("could not read cloud root ownership: {error}"))?;
    let notifier = Arc::new(Mutex::new(None));
    let filesystem = RaiunFilesystem::new(
        engine,
        spool_dir,
        mount_owner.uid(),
        mount_owner.gid(),
        profile_id.to_owned(),
        vault_registry,
        Arc::clone(&notifier),
    )
    .map_err(|error| error.to_string())?;
    let source = mount_source(&state_dir);
    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::FSName(source.clone()),
        MountOption::DefaultPermissions,
        MountOption::NoDev,
        MountOption::NoSuid,
        MountOption::RW,
    ];
    config.n_threads = Some(4);
    let session = fuser::spawn_mount(filesystem, &root, &config)
        .map_err(|error| format!("could not mount OpenCloud: {error}"))?;
    *notifier
        .lock()
        .map_err(|_| "FUSE notifier state is unavailable")? = Some(session.notifier());
    Ok(MountHandle {
        session: Some(session),
        root,
        source,
    })
}

fn mount_source(state_dir: &Path) -> String {
    format!(
        "RaiunDesktop-{:016x}",
        stable_hash(&state_dir.to_string_lossy())
    )
}

fn normalize_mount_path(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| part == std::path::Component::ParentDir)
    {
        return Err("mount root must be an absolute path without '..'".into());
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        if component != std::path::Component::CurDir {
            normalized.push(component.as_os_str());
        }
    }
    Ok(normalized)
}

fn mountinfo_has_fuse_source(mountinfo: &[u8], root: &Path, source: &[u8]) -> bool {
    mountinfo_fuse_source_at(mountinfo, root).as_deref() == Some(source)
}

fn mountinfo_fuse_source_at(mountinfo: &[u8], root: &Path) -> Option<Vec<u8>> {
    let expected = mountinfo_escape(root);
    mountinfo.split(|byte| *byte == b'\n').find_map(|line| {
        let separator = line.windows(3).position(|window| window == b" - ")?;
        let before = &line[..separator];
        let after = &line[separator + 3..];
        let mountpoint = before
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty())
            .nth(4);
        let mut fields = after
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty());
        let filesystem = fields.next()?;
        let source = fields.next()?;
        if mountpoint == Some(expected.as_slice()) && filesystem.starts_with(b"fuse") {
            Some(source.to_vec())
        } else {
            None
        }
    })
}

impl RaiunFilesystem {
    fn reserve_vault_write(&self, route_id: u64, path: &str) -> Result<String, CloudError> {
        let key = format!("vault-write:{route_id}:\0{path}");
        let cancellation_key = format!("vault-cancel-file:{route_id}:\0{path}");
        let mut state = self
            .state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?;
        if state.active_writers.contains(&key)
            || state.active_writers.contains(&cancellation_key)
            || state.active_writers.iter().any(|active| {
                let Some((is_subtree, active_path)) = vault_reservation_path(active, route_id)
                else {
                    return false;
                };
                is_subtree && paths_overlap(path, active_path)
            })
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "active writer or encrypted directory move overlaps this path",
            ));
        }
        state.active_writers.insert(key.clone());
        Ok(key)
    }

    fn reserve_vault_rename_paths(
        &self,
        route_id: u64,
        source: &str,
        destination: &str,
        allow_read_only_source_handle: bool,
    ) -> Result<Vec<PathReservation<'_>>, CloudError> {
        let source_key = format!("vault-subtree:{route_id}:\0{source}");
        let destination_key = format!("vault-write:{route_id}:\0{destination}");
        let mut state = self
            .state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?;
        let conflicts = state.active_writers.iter().any(|active| {
            let Some((_, active_path)) = vault_reservation_path(active, route_id) else {
                return false;
            };
            paths_overlap(source, active_path) || paths_overlap(destination, active_path)
        });
        let open_file_conflict = state.vault_file_handles.values().any(|handle| {
            let current_path = state.nodes.get(&handle.ino).and_then(|node| {
                let NodeKind::Vault { entry, .. } = &node.kind else {
                    return None;
                };
                Some(entry.path.as_str())
            });
            if handle.route_id != route_id {
                return false;
            }
            let overlaps = paths_overlap(source, &handle.path)
                || paths_overlap(destination, &handle.path)
                || current_path.is_some_and(|path| {
                    paths_overlap(source, path) || paths_overlap(destination, path)
                });
            let is_stable_source_reader =
                allow_read_only_source_handle && !handle.writable && current_path == Some(source);
            overlaps && !is_stable_source_reader
        });
        let open_directory_conflict = state.directory_handles.values().any(|handle| {
            handle
                .owner_vault
                .as_ref()
                .is_some_and(|(owner_route, _, _, path)| {
                    *owner_route == route_id && path_is_within(path, source)
                })
        });
        if conflicts || open_file_conflict || open_directory_conflict {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "open handle or active operation overlaps encrypted rename",
            ));
        }
        state.active_writers.insert(source_key.clone());
        state.active_writers.insert(destination_key.clone());
        drop(state);
        Ok(vec![
            PathReservation {
                state: &self.state,
                changed: &self.active_writer_changed,
                key: source_key,
                active: true,
            },
            PathReservation {
                state: &self.state,
                changed: &self.active_writer_changed,
                key: destination_key,
                active: true,
            },
        ])
    }

    fn reserve_vault_path(
        &self,
        route_id: u64,
        path: &str,
    ) -> Result<PathReservation<'_>, CloudError> {
        let key = self.reserve_vault_write(route_id, path)?;
        Ok(PathReservation {
            state: &self.state,
            changed: &self.active_writer_changed,
            key,
            active: true,
        })
    }

    /// Reserve one pending directory subtree against new open directory
    /// handles and mutations while the backend CAS-cancels its NeverAttempted
    /// journal row. The shared state mutex serializes this with opendir's
    /// owner registration and all mutation reservations.
    fn reserve_pending_directory_cancel(
        &self,
        route_id: u64,
        path: &str,
    ) -> Result<PathReservation<'_>, CloudError> {
        let key = format!("vault-subtree:{route_id}:\0{path}");
        let mut state = self
            .state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?;
        let writer_conflict = state.active_writers.iter().any(|active| {
            vault_reservation_path(active, route_id)
                .is_some_and(|(_, active_path)| paths_overlap(path, active_path))
        });
        let directory_conflict = state.directory_handles.values().any(|handle| {
            handle
                .owner_vault
                .as_ref()
                .is_some_and(|(owner_route, _, _, owner_path)| {
                    *owner_route == route_id && path_is_within(owner_path, path)
                })
        });
        if writer_conflict || directory_conflict {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "queued directory has an open handle or active descendant operation",
            ));
        }
        if !state.active_writers.insert(key.clone()) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "queued directory cancellation is already in progress",
            ));
        }
        Ok(PathReservation {
            state: &self.state,
            changed: &self.active_writer_changed,
            key,
            active: true,
        })
    }

    /// Atomically exclude every open file handle for one queued create, its
    /// containing directory snapshots, and concurrent opens/mutations while
    /// the journal cancellation receipt is committed. Unlike a subtree move,
    /// this reservation covers only the exact file path.
    fn reserve_pending_file_create_cancel(
        &self,
        route_id: u64,
        path: &str,
        ino: u64,
    ) -> Result<PathReservation<'_>, CloudError> {
        let key = format!("vault-cancel-file:{route_id}:\0{path}");
        let mut state = self
            .state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?;
        let operation_conflict = state.active_writers.iter().any(|active| {
            vault_reservation_path(active, route_id).is_some_and(|(subtree, active_path)| {
                if subtree {
                    paths_overlap(path, active_path)
                } else {
                    active_path == path
                }
            })
        });
        let open_file_conflict = state.vault_file_handles.values().any(|handle| {
            if handle.route_id != route_id {
                return false;
            }
            handle.path == path
                || state.nodes.get(&handle.ino).is_some_and(|node| {
                    matches!(&node.kind, NodeKind::Vault { route, entry, .. }
                        if route.control.route_id() == route_id && entry.path == path)
                })
        });
        let open_directory_conflict = state.directory_handles.values().any(|handle| {
            handle
                .entries
                .iter()
                .any(|(_, entry_ino, _)| *entry_ino == ino)
        });
        if operation_conflict {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "queued file cancellation overlaps an active operation",
            ));
        }
        if open_file_conflict {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "queued file has an open file handle",
            ));
        }
        if open_directory_conflict {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "queued file appears in an open directory snapshot",
            ));
        }
        if !state.active_writers.insert(key.clone()) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "queued file cancellation is already in progress",
            ));
        }
        Ok(PathReservation {
            state: &self.state,
            changed: &self.active_writer_changed,
            key,
            active: true,
        })
    }

    fn register_directory_handle(
        &self,
        fh: u64,
        handle: DirectoryHandle,
    ) -> Result<(), CloudError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?;
        if state.directory_handles.len() >= MAX_DIRECTORY_HANDLES {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "provider directory handle limit reached",
            ));
        }
        if let Some((route_id, _, _, owner_path)) = &handle.owner_vault {
            let blocked = state.active_writers.iter().any(|active| {
                vault_reservation_path(active, *route_id).is_some_and(|(subtree, reserved_path)| {
                    subtree && path_is_within(owner_path, reserved_path)
                })
            });
            if blocked {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "encrypted directory is being cancelled or moved",
                ));
            }
        }
        let listed_cancelled_file = handle.entries.iter().any(|(_, ino, _)| {
            state.nodes.get(ino).is_some_and(|node| {
                let NodeKind::Vault { route, entry, .. } = &node.kind else {
                    return false;
                };
                let key = format!(
                    "vault-cancel-file:{}:\0{}",
                    route.control.route_id(),
                    entry.path
                );
                state.active_writers.contains(&key)
            })
        });
        if listed_cancelled_file {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "encrypted directory listing overlaps a file cancellation",
            ));
        }
        state.directory_handles.insert(fh, handle);
        Ok(())
    }

    fn release_write_key(&self, key: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.active_writers.remove(key);
            self.active_writer_changed.notify_all();
        }
    }

    /// Wait for close/flush to retire writers before taking a route read lease
    /// for rename. The condition variable releases provider state while
    /// sleeping, and this method is always called before acquiring a route
    /// lease so lock revocation cannot deadlock behind the wait.
    fn wait_for_vault_writers(
        &self,
        route_id: u64,
        source: &str,
        destination: &str,
        timeout: Duration,
    ) -> Result<(), CloudError> {
        self.wait_for_vault_writers_with_hook(route_id, source, destination, timeout, || {})
    }

    /// Wait for a prior FUSE writer's asynchronous `release` before opening or
    /// mutating this path. Callers must invoke this before taking a route
    /// lease; the condition variable releases provider state while waiting,
    /// so route revocation can purge reservations and wake this operation.
    fn wait_for_vault_path(
        &self,
        route: &VaultMountRoute,
        generation: u64,
        path: &str,
        timeout: Duration,
    ) -> Result<(), CloudError> {
        self.wait_for_vault_path_with_hook(route, generation, path, timeout, || {})
    }

    fn wait_for_vault_path_with_hook(
        &self,
        route: &VaultMountRoute,
        generation: u64,
        path: &str,
        timeout: Duration,
        mut before_wait: impl FnMut(),
    ) -> Result<(), CloudError> {
        let route_id = route.control.route_id();
        let deadline = Instant::now() + timeout;
        loop {
            // Never take the route lock while holding provider state. Revoke
            // runs its purge hook under the exclusive route lock.
            if route.control.generation()? != generation {
                return Err(CloudError::new(
                    ErrorKind::Unauthorized,
                    "vault route was locked while waiting for a writer",
                ));
            }
            let state = self
                .state
                .lock()
                .map_err(|_| io_error("provider state is unavailable"))?;
            let active = state.active_writers.iter().any(|candidate| {
                let Some((_, active_path)) = vault_reservation_path(candidate, route_id) else {
                    return false;
                };
                paths_overlap(path, active_path)
            });
            if !active {
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "active encrypted writer did not close before the operation",
                ));
            }
            before_wait();
            let (state, wait) = self
                .active_writer_changed
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .map_err(|_| io_error("provider state is unavailable"))?;
            drop(state);
            if wait.timed_out() {
                // Prefer revocation over a stale-writer timeout when lock
                // invalidated this route while the condition variable slept.
                if route.control.generation()? != generation {
                    return Err(CloudError::new(
                        ErrorKind::Unauthorized,
                        "vault route was locked while waiting for a writer",
                    ));
                }
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "active encrypted writer did not close before the operation",
                ));
            }
        }
    }

    fn wait_for_vault_writers_with_hook(
        &self,
        route_id: u64,
        source: &str,
        destination: &str,
        timeout: Duration,
        mut before_wait: impl FnMut(),
    ) -> Result<(), CloudError> {
        let source_key = format!("vault-write:{route_id}:\0{source}");
        let destination_key = format!("vault-write:{route_id}:\0{destination}");
        let deadline = Instant::now() + timeout;
        let mut state = self
            .state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?;
        loop {
            let active = state.active_writers.iter().any(|key| {
                if key == &source_key || key == &destination_key {
                    return true;
                }
                let Some((_, active_path)) = vault_reservation_path(key, route_id) else {
                    return false;
                };
                paths_overlap(source, active_path) || paths_overlap(destination, active_path)
            });
            if !active {
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "active writer did not close before encrypted rename",
                ));
            }
            before_wait();
            let (next, wait) = self
                .active_writer_changed
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .map_err(|_| io_error("provider state is unavailable"))?;
            state = next;
            if wait.timed_out() {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "active writer did not close before encrypted rename",
                ));
            }
        }
    }

    fn prepare_vault_working_copy(
        &self,
        route: &VaultMountRoute,
        generation: u64,
        entry: &RemoteEntry,
        request: (WriteCondition, Option<&VaultParentRef>),
        truncate: bool,
        lease: &VaultRouteLease<'_>,
    ) -> Result<(VaultWriteBinding, VaultWorkingCopy), CloudError> {
        let (condition, parent_ref) = request;
        if !lease.supports_writes() && !lease.supports_existing_file_overwrites() {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "encrypted route is read-only",
            ));
        }
        let spool = self.vault_write_spool.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Forbidden,
                self.vault_write_spool_error
                    .as_deref()
                    .unwrap_or("encrypted working copy is unavailable"),
            )
        })?;
        let (scope, target) = match &condition {
            WriteCondition::Match(base_etag) => {
                lease.prepare_existing_target(&entry.path, &entry.id, base_etag)?
            }
            WriteCondition::Absent if lease.supports_file_creates() => {
                let parent_ref = parent_ref.ok_or_else(|| {
                    CloudError::new(
                        ErrorKind::Conflict,
                        "encrypted create has no verified parent reference",
                    )
                })?;
                lease.prepare_file_create_under_parent(&entry.path, parent_ref, None)?
            }
            WriteCondition::Absent => {
                return Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "offline encrypted routes cannot create files",
                ));
            }
        };
        if scope.space_id() != route.space_id()
            || scope.root_resource_id() != route.root_resource_id()
            || target.condition() != &condition
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "encrypted write target does not match its mounted route",
            ));
        }
        let binding = VaultWriteBinding::new(scope, target, generation)
            .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "invalid vault binding"))?;

        let working = if truncate || matches!(condition, WriteCondition::Absent) {
            let mut empty = std::io::Cursor::new(Vec::<u8>::new());
            spool
                .begin(binding.clone(), &mut empty, generation)
                .map_err(vault_write_error)?
        } else {
            let opened = lease.open(&entry.path)?;
            let copied = {
                let mut reader = VaultRouteReader {
                    lease,
                    handle: &opened,
                    offset: 0,
                };
                spool.begin(binding.clone(), &mut reader, generation)
            };
            let closed = lease.close(opened);
            let working = copied.map_err(vault_write_error)?;
            closed?;
            working
        };
        Ok((binding, working))
    }

    fn recover_never_attempted_create_for_rename(
        &self,
        route: &VaultMountRoute,
        generation: u64,
        write_id: &str,
        revision: u64,
    ) -> Result<VaultWorkingCopy, CloudError> {
        let spool = self.vault_write_spool.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Conflict,
                "pending encrypted create has no local recovery copy",
            )
        })?;
        let (records, truncated) = spool.list_pending().map_err(vault_write_error)?;
        if truncated {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "pending encrypted create recovery scan was incomplete",
            ));
        }
        let mut matched = None;
        for record in records {
            let (
                Some(scope),
                Some(target),
                Some(VaultWriteLifecycle::Queued {
                    write_id: candidate_id,
                    revision: candidate_revision,
                    uncertain: false,
                    ..
                }),
            ) = (record.scope, record.target, record.lifecycle)
            else {
                continue;
            };
            if candidate_id != write_id || candidate_revision != revision {
                continue;
            }
            if scope.space_id() != route.space_id()
                || scope.root_resource_id() != route.root_resource_id()
                || !matches!(target.condition(), WriteCondition::Absent)
                || target.parent_ref().is_none()
            {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "pending encrypted create recovery binding does not match the route",
                ));
            }
            if matched.is_some() {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "pending encrypted create recovery identity is ambiguous",
                ));
            }
            matched = Some((record.record_id, scope, target));
        }
        let (record_id, scope, target) = matched.ok_or_else(|| {
            CloudError::new(
                ErrorKind::Conflict,
                "pending encrypted create recovery copy was not found",
            )
        })?;
        let binding =
            VaultWriteBinding::new(scope, target, generation).map_err(vault_write_error)?;
        spool
            .recover(&record_id, binding, generation)
            .map_err(vault_write_error)
    }

    fn open_vault_for_write(
        &self,
        ino: u64,
        flags: i32,
        route: &VaultMountRoute,
        generation: u64,
        entry: &RemoteEntry,
        lease: &VaultRouteLease<'_>,
    ) -> Result<u64, CloudError> {
        if flags & libc::O_ACCMODE == libc::O_RDONLY {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault file was not opened for writing",
            ));
        }
        if !vault_open_flags_supported(flags) {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "vault open flags are not supported",
            ));
        }
        if entry.directory || !entry.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "encrypted item is read-only",
            ));
        }
        let current = lease.stat(&entry.path)?;
        if current.id != entry.id || current.directory || !current.writable {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "vault item identity or write permission changed",
            ));
        }
        if current.etag.is_empty() {
            return Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "vault file has no conditional version",
            ));
        }
        let active_key = self.reserve_vault_write(route.control.route_id(), &entry.path)?;
        let result = (|| {
            let condition = WriteCondition::Match(current.etag.clone());
            let (binding, working) = self.prepare_vault_working_copy(
                route,
                generation,
                &current,
                (condition.clone(), None),
                flags & libc::O_TRUNC != 0,
                lease,
            )?;
            let mut working = working;
            if flags & libc::O_TRUNC != 0 {
                working.mark_dirty(generation).map_err(vault_write_error)?;
            }
            self.register_handle(OpenFile::VaultWrite(Box::new(VaultWriteHandle {
                route: route.control.clone(),
                generation,
                binding,
                working,
                path: current.path,
                entry_id: current.id,
                condition,
                dirty: flags & libc::O_TRUNC != 0,
                closing: false,
                ino,
                flags,
                active_key: active_key.clone(),
            })))
        })();
        if result.is_err() {
            self.release_write_key(&active_key);
        }
        result
    }

    fn create_vault_file(
        &self,
        parent_ino: u64,
        name: &str,
        flags: i32,
        lease: &VaultRouteLease<'_>,
    ) -> Result<(Node, u64), CloudError> {
        #[cfg(debug_assertions)]
        trace_vault_file_create_stage("entry");
        if !vault_open_flags_supported(flags)
            || (flags & libc::O_ACCMODE == libc::O_RDONLY && flags & libc::O_TRUNC != 0)
        {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted create flags are not supported",
            ));
        }
        let parent = self.node(parent_ino)?;
        let NodeKind::Vault {
            route,
            generation,
            entry: parent_entry,
        } = parent.kind
        else {
            return Err(invalid("vault parent changed"));
        };
        let full_writer = lease.supports_writes();
        let can_create = lease.supports_file_creates();
        if lease.generation() != generation
            || (!full_writer && !lease.supports_existing_file_overwrites() && !can_create)
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "encrypted route is read-only",
            ));
        }
        let current_parent = lease.stat(&parent_entry.path)?;
        let parent_ref = self.vault_parent_ref(parent_ino, generation, &current_parent, lease)?;
        #[cfg(debug_assertions)]
        trace_vault_file_create_stage("parent_verified");
        let pending_parent = matches!(parent_ref, VaultParentRef::PendingCreate { .. });
        if current_parent.id != parent_entry.id
            || !current_parent.directory
            || (can_create && !current_parent.writable && !pending_parent)
            || (pending_parent && !lease.supports_pending_parent_operations())
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "encrypted directory is read-only or stale",
            ));
        }
        let (_, path) = self.child_path(
            &Node {
                kind: NodeKind::Vault {
                    route: route.clone(),
                    generation,
                    entry: current_parent,
                },
                ..parent
            },
            name,
        )?;
        let existing = match lease.stat(&path) {
            Ok(entry) => Some(entry),
            Err(error) if error.kind == ErrorKind::NotFound => None,
            Err(error) => {
                trace_fuse_namespace_error("vault_create_parent_stat", &error);
                return Err(error);
            }
        };
        #[cfg(debug_assertions)]
        trace_vault_file_create_stage("destination_checked");
        if let Some(existing) = existing {
            if flags & libc::O_EXCL != 0 {
                return Err(CloudError::new(ErrorKind::Conflict, "destination exists"));
            }
            if existing.directory {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "cannot create a file over an encrypted directory",
                ));
            }
            let ino = self.add_node(
                parent_ino,
                name.to_owned(),
                NodeKind::Vault {
                    route: route.clone(),
                    generation,
                    entry: existing.clone(),
                },
            )?;
            let fh = if flags & libc::O_ACCMODE == libc::O_RDONLY {
                let _open_reservation =
                    self.reserve_vault_path(route.control.route_id(), &existing.path)?;
                self.ensure_vault_hook(&route)?;
                let handle = lease.open(&existing.path)?;
                self.register_handle(OpenFile::Vault {
                    route: route.control.clone(),
                    generation,
                    ino,
                    path: existing.path.clone(),
                    handle: Some(handle),
                })?
            } else {
                self.open_vault_for_write(ino, flags, &route, generation, &existing, lease)?
            };
            return Ok((self.node(ino)?, fh));
        }

        if !can_create {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "encrypted route does not permit file creation",
            ));
        }

        let active_key = self.reserve_vault_write(route.control.route_id(), &path)?;
        #[cfg(debug_assertions)]
        trace_vault_file_create_stage("write_reserved");
        let result = (|| {
            #[cfg(debug_assertions)]
            trace_vault_file_create_stage("working_copy_start");
            let (mut binding, mut working) = self.prepare_vault_working_copy(
                &route,
                generation,
                &RemoteEntry {
                    id: "new-file".into(),
                    path: path.clone(),
                    directory: false,
                    size: 0,
                    etag: String::new(),
                    modified_unix: 0,
                    writable: true,
                    encrypted: false,
                },
                (WriteCondition::Absent, Some(&parent_ref)),
                true,
                lease,
            )?;
            #[cfg(debug_assertions)]
            trace_vault_file_create_stage("working_copy_ready");
            let (scope, target) =
                lease.prepare_file_create_under_parent(&path, &parent_ref, None)?;
            #[cfg(debug_assertions)]
            trace_vault_file_create_stage("target_prepared");
            if scope != *binding.scope() || target != *binding.target() {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "encrypted create target changed before publication",
                ));
            }
            let outcome = lease.begin_file_create(&target)?;
            #[cfg(debug_assertions)]
            trace_vault_file_create_stage("backend_create_started");
            let VaultUploadOutcome::BuildingCreate {
                entry: created,
                write_id,
                revision,
            } = outcome
            else {
                return Err(CloudError::new(
                    ErrorKind::InvalidResponse,
                    "encrypted create did not return a durable building operation",
                ));
            };
            if created.path != path
                || created.directory
                || created.size != 0
                || created.etag.is_empty()
                || created.id.is_empty()
            {
                return Err(CloudError::new(
                    ErrorKind::InvalidResponse,
                    "encrypted create returned an invalid building entry",
                ));
            }
            working
                .record_building_create(generation, &write_id, revision)
                .map_err(vault_write_error)?;
            #[cfg(debug_assertions)]
            trace_vault_file_create_stage("building_recorded");
            let condition = WriteCondition::Absent;
            binding = working.binding().clone();
            let ino = self.add_node(
                parent_ino,
                name.to_owned(),
                NodeKind::Vault {
                    route: route.clone(),
                    generation,
                    entry: created.clone(),
                },
            )?;
            let fh = self.register_handle(OpenFile::VaultWrite(Box::new(VaultWriteHandle {
                route: route.control.clone(),
                generation,
                binding,
                working,
                path: path.clone(),
                entry_id: created.id,
                condition,
                // Even an empty file needs its first content revision published
                // on flush/release; the backend Building row is not retryable.
                dirty: true,
                closing: false,
                ino,
                flags,
                active_key: active_key.clone(),
            })))?;
            #[cfg(debug_assertions)]
            trace_vault_file_create_stage("handle_registered");
            Ok((self.node(ino)?, fh))
        })();
        if result.is_err() {
            #[cfg(debug_assertions)]
            trace_vault_file_create_stage("failed_after_reservation");
            self.release_write_key(&active_key);
        }
        result
    }

    fn new(
        engine: Engine,
        spool_dir: PathBuf,
        owner_uid: u32,
        owner_gid: u32,
        local_profile_id: String,
        vault_registry: VaultMountRegistry,
        notifier: Arc<Mutex<Option<fuser::Notifier>>>,
    ) -> Result<Self, CloudError> {
        let spaces = engine.spaces()?;
        let personal_space = spaces
            .iter()
            .find(|space| space.personal && !space.encrypted)
            .cloned()
            .ok_or_else(|| {
                CloudError::new(ErrorKind::Unsupported, "personal drive is unavailable")
            })?;
        let projects: Vec<_> = spaces
            .iter()
            .filter(|space| !space.personal)
            .map(|space| Space {
                id: space.id.clone(),
                name: space.name.clone(),
            })
            .collect();
        let names = space_entries(&projects).map_err(|_| {
            CloudError::new(
                ErrorKind::InvalidResponse,
                "OpenCloud returned invalid Space names",
            )
        })?;
        let project_spaces = names
            .into_iter()
            .filter_map(|entry| {
                let label = entry.relative_path.file_name()?.to_str()?.to_owned();
                spaces
                    .iter()
                    .find(|space| space.id == entry.space_id)
                    .cloned()
                    .map(|space| (label, space))
            })
            .collect();
        let mounted_spaces = spaces
            .iter()
            .map(|space| (space.id.clone(), space.clone()))
            .collect();
        // If this profile cannot safely open a durable private vault spool,
        // its encrypted routes remain browseable but read-only.
        let (vault_write_spool, vault_write_spool_error) = match VaultWriteSpool::open(&spool_dir) {
            Ok(spool) => (Some(spool), None),
            Err(error) => (None, Some(error.to_string())),
        };
        #[cfg(target_os = "linux")]
        let spool_capacity_dir = open_spool_capacity_dir(&spool_dir).ok();
        let root = Node {
            ino: ROOT,
            parent: ROOT,
            name: String::new(),
            kind: NodeKind::Root,
            metadata_expires_at: Instant::now(),
        };
        let personal = Node {
            ino: PERSONAL,
            parent: ROOT,
            name: "Personal".into(),
            kind: NodeKind::Personal {
                space: personal_space.id.clone(),
            },
            metadata_expires_at: Instant::now(),
        };
        let spaces_node = Node {
            ino: SPACES,
            parent: ROOT,
            name: "Spaces".into(),
            kind: NodeKind::Spaces,
            metadata_expires_at: Instant::now(),
        };
        let mut nodes = HashMap::new();
        nodes.insert(ROOT, root);
        nodes.insert(PERSONAL, personal);
        nodes.insert(SPACES, spaces_node);
        let filesystem = Self {
            engine,
            pool: RemotePool::new(4),
            project_spaces,
            mounted_spaces,
            spool_dir,
            #[cfg(target_os = "linux")]
            spool_capacity_dir,
            vault_write_spool,
            vault_write_spool_error,
            owner_uid,
            owner_gid,
            local_profile_id,
            state: Arc::new(Mutex::new(State {
                nodes,
                children: HashMap::from([
                    ((ROOT, "Personal".into()), PERSONAL),
                    ((ROOT, "Spaces".into()), SPACES),
                ]),
                recovery_aliases: std::collections::HashSet::new(),
                file_handles: HashMap::new(),
                vault_file_handles: HashMap::new(),
                directory_handles: HashMap::new(),
                pending_parent_refs: HashMap::new(),
                active_writers: std::collections::HashSet::new(),
            })),
            active_writer_changed: Arc::new(Condvar::new()),
            vault_retarget_recovery: Mutex::new(std::collections::HashSet::new()),
            vault_subtree_recovery: Mutex::new(std::collections::HashSet::new()),
            vault_cancel_recovery: Mutex::new(std::collections::HashSet::new()),
            next_handle: AtomicU64::new(1),
            vault_registry,
            registered_route_hooks: Mutex::new(HashMap::new()),
            notifier,
        };
        for route in filesystem.vault_registry.routes()? {
            filesystem.ensure_vault_hook(&route)?;
        }
        Ok(filesystem)
    }

    fn ensure_vault_hook(&self, route: &VaultMountRoute) -> Result<(), CloudError> {
        let route_id = route.control.route_id();
        let mut registered = self
            .registered_route_hooks
            .lock()
            .map_err(|_| io_error("vault route hook state is unavailable"))?;
        if registered.contains_key(&route_id) {
            return Ok(());
        }
        let state = Arc::downgrade(&self.state);
        let notifier = Arc::clone(&self.notifier);
        let active_writer_changed = Arc::clone(&self.active_writer_changed);
        let revoke_hook = route.control.register_revoke_hook(Arc::new(move || {
            let Some(state) = state.upgrade() else {
                return Ok(());
            };
            let invalidations = purge_vault_route_state(&state, route_id)?;
            active_writer_changed.notify_all();
            let notifier = notifier
                .lock()
                .map_err(|_| io_error("FUSE notifier state is unavailable"))?
                .clone()
                .ok_or_else(|| io_error("FUSE notifier is not available"))?;
            for (parent, name, ino) in invalidations {
                ignore_missing_invalidation(
                    notifier.inval_entry(INodeNo(parent), OsStr::new(&name)),
                    "could not invalidate a locked vault entry",
                )?;
                ignore_missing_invalidation(
                    notifier.inval_inode(INodeNo(ino), 0, -1),
                    "could not invalidate a locked vault inode",
                )?;
            }
            Ok(())
        }))?;
        let install_state = Arc::downgrade(&self.state);
        let install_notifier = Arc::clone(&self.notifier);
        let profile_id = self.local_profile_id.clone();
        let space_id = route.space_id().to_owned();
        let root_path = route.root_path().to_owned();
        let root_resource_id = route.root_resource_id().to_owned();
        let root_name = if root_path == "/" {
            self.project_spaces
                .iter()
                .find(|(_, space)| space.id == space_id)
                .map(|(label, _)| label.clone())
                .unwrap_or_else(|| space_id.clone())
        } else {
            root_path
                .rsplit('/')
                .next()
                .filter(|name| !name.is_empty())
                .unwrap_or_default()
                .to_owned()
        };
        let install_hook = route.control.register_install_hook(Arc::new(move || {
            trace_vault_install_hook_stage("entered");
            let Some(state) = install_state.upgrade() else {
                trace_vault_install_hook_stage("state_unavailable");
                return Ok(());
            };
            trace_vault_install_hook_stage("purge_start");
            let invalidations = purge_locked_vault_state(
                &state,
                &profile_id,
                &space_id,
                &root_path,
                &root_resource_id,
                &root_name,
            )?;
            trace_vault_install_hook_stage("purge_complete");
            let notifier = install_notifier
                .lock()
                .map_err(|_| io_error("FUSE notifier state is unavailable"))?
                .clone();
            // Before the FUSE session has initialized there is no kernel cache
            // to invalidate. Once initialized, missing notifier state is a
            // fail-closed installation error.
            let Some(notifier) = notifier else {
                trace_vault_install_hook_stage("no_notifier");
                return Ok(());
            };
            trace_vault_install_hook_stage("notifier_ready");
            for (parent, name, ino) in invalidations {
                trace_vault_install_hook_stage("entry_invalidation_start");
                ignore_missing_invalidation(
                    notifier.inval_entry(INodeNo(parent), OsStr::new(&name)),
                    "could not invalidate a newly unlocked vault entry",
                )?;
                trace_vault_install_hook_stage("entry_invalidation_complete");
                trace_vault_install_hook_stage("parent_invalidation_start");
                ignore_missing_invalidation(
                    notifier.inval_inode(INodeNo(parent), 0, -1),
                    "could not invalidate a parent listing before vault unlock",
                )?;
                trace_vault_install_hook_stage("parent_invalidation_complete");
                if ino != 0 {
                    trace_vault_install_hook_stage("inode_invalidation_start");
                    ignore_missing_invalidation(
                        notifier.inval_inode(INodeNo(ino), 0, -1),
                        "could not invalidate a locked vault inode before unlock",
                    )?;
                    trace_vault_install_hook_stage("inode_invalidation_complete");
                }
            }
            trace_vault_install_hook_stage("complete");
            Ok(())
        }))?;
        registered.insert(
            route_id,
            RegisteredVaultHooks {
                _revoke: revoke_hook,
                _install: install_hook,
            },
        );
        Ok(())
    }

    fn node(&self, ino: u64) -> Result<Node, CloudError> {
        self.state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?
            .nodes
            .get(&ino)
            .cloned()
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "cloud item was not found"))
    }

    fn add_vault_root(
        &self,
        parent: u64,
        space: &str,
        name: &str,
        raw_entry: &RemoteEntry,
    ) -> Result<Option<Node>, CloudError> {
        let route = self
            .vault_registry
            .get(space, &raw_entry.path, &raw_entry.id)?;
        let Some(route) = route.filter(|route| route.matches(space, raw_entry)) else {
            return self
                .add_locked_vault_root(parent, name, space, &raw_entry.path, Some(&raw_entry.id))
                .map(Some);
        };
        self.ensure_vault_hook(&route)?;
        if !route.control.is_active()? {
            return self
                .add_locked_vault_root(parent, name, space, &raw_entry.path, Some(&raw_entry.id))
                .map(Some);
        }
        let generation = route.generation()?;
        let root = match route.control.with_read_lease(generation, |lease| {
            let root = lease.stat("/")?;
            if root.id != route.root_resource_id || !root.directory || root.encrypted {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "vault root no longer matches its configured route",
                ));
            }
            Ok(root)
        }) {
            Ok(root) => root,
            Err(error) if matches!(error.kind, ErrorKind::Unauthorized | ErrorKind::Forbidden) => {
                return self
                    .add_locked_vault_root(
                        parent,
                        name,
                        space,
                        &raw_entry.path,
                        Some(&raw_entry.id),
                    )
                    .map(Some);
            }
            Err(error) => {
                trace_fuse_namespace_error("active_vault_root_stat", &error);
                return Err(error);
            }
        };
        let ino = self.add_node(
            parent,
            name.to_owned(),
            NodeKind::Vault {
                route,
                generation,
                entry: root,
            },
        )?;
        self.node(ino).map(Some)
    }

    /// Overlay only live, identity-bound routes when the ordinary listing
    /// cache cannot expose encrypted entries. The encrypted entry itself is
    /// revalidated through the route's authenticated snapshot in
    /// `add_vault_root`; this metadata is only a discovery hint.
    fn append_active_vault_routes(
        &self,
        space: &str,
        parent_path: &str,
        entries: &mut Vec<RemoteEntry>,
    ) -> Result<(), CloudError> {
        let parent_path = normalize_entry_path(parent_path)
            .ok_or_else(|| invalid("vault route parent path is invalid"))?;
        for route in self.vault_registry.routes()? {
            if route.space_id != space || route.root_path == "/" {
                continue;
            }
            let Some((route_parent, _)) = route.root_path.rsplit_once('/') else {
                continue;
            };
            let route_parent = if route_parent.is_empty() {
                "/"
            } else {
                route_parent
            };
            if route_parent != parent_path || !route.control.is_active()? {
                continue;
            }
            if entries
                .iter()
                .any(|entry| entry.path == route.root_path && entry.id == route.root_resource_id)
            {
                continue;
            }
            entries.push(RemoteEntry {
                id: route.root_resource_id,
                path: route.root_path,
                directory: true,
                size: 0,
                etag: String::new(),
                modified_unix: 0,
                writable: false,
                encrypted: true,
            });
        }
        Ok(())
    }

    fn add_whole_space_vault_root(
        &self,
        parent: u64,
        label: &str,
        space: &CloudSpace,
    ) -> Result<Option<Node>, CloudError> {
        let route = self.vault_registry.get_space_root(&space.id)?;
        let Some(route) = route else {
            return self
                .add_locked_vault_root(parent, label, &space.id, "/", None)
                .map(Some);
        };
        self.ensure_vault_hook(&route)?;
        if !route.control.is_active()? {
            return self
                .add_locked_vault_root(parent, label, &space.id, "/", Some(&route.root_resource_id))
                .map(Some);
        }
        let generation = route.generation()?;
        let root = match route.control.with_read_lease(generation, |lease| {
            let root = lease.stat("/")?;
            if root.id != route.root_resource_id || !root.directory || root.encrypted {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "encrypted Space root no longer matches its configured route",
                ));
            }
            Ok(root)
        }) {
            Ok(root) => root,
            Err(error) if matches!(error.kind, ErrorKind::Unauthorized | ErrorKind::Forbidden) => {
                return self
                    .add_locked_vault_root(
                        parent,
                        label,
                        &space.id,
                        "/",
                        Some(&route.root_resource_id),
                    )
                    .map(Some);
            }
            Err(error) => return Err(error),
        };
        let ino = self.add_node(
            parent,
            label.to_owned(),
            NodeKind::Vault {
                route,
                generation,
                entry: root,
            },
        )?;
        self.node(ino).map(Some)
    }

    fn add_locked_vault_root(
        &self,
        parent: u64,
        name: &str,
        space: &str,
        remote_path: &str,
        resource_id: Option<&str>,
    ) -> Result<Node, CloudError> {
        let ino = self.add_node(
            parent,
            name.to_owned(),
            NodeKind::LockedVault {
                profile_id: self.local_profile_id.clone(),
                space: space.to_owned(),
                resource_id: resource_id.map(str::to_owned),
                remote_path: remote_path.to_owned(),
            },
        )?;
        self.node(ino)
    }

    fn with_node_lease<T>(
        &self,
        ino: u64,
        operation: impl FnOnce(Option<&VaultRouteLease<'_>>) -> Result<T, CloudError>,
    ) -> Result<T, CloudError> {
        let node = self.node(ino)?;
        if let NodeKind::Vault {
            route, generation, ..
        } = node.kind
        {
            self.ensure_vault_hook(&route)?;
            route
                .control
                .with_read_lease(generation, |lease| operation(Some(lease)))
        } else {
            operation(None)
        }
    }

    fn add_node(&self, parent: u64, name: String, kind: NodeKind) -> Result<u64, CloudError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?;
        if let Some(ino) = state.children.get(&(parent, name.clone())).copied() {
            if let Some(current) = state.nodes.get_mut(&ino) {
                if same_identity(&current.kind, &kind) {
                    if matches!(&kind, NodeKind::Remote { .. }) {
                        current.kind = kind;
                        current.metadata_expires_at = Instant::now() + TTL;
                    }
                    return Ok(ino);
                }
            }
        }
        if state.nodes.len() >= MAX_NODES {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "provider node limit reached; unmount and remount to release cached namespace state",
            ));
        }
        let key = match &kind {
            NodeKind::Recovery(view) => {
                format!("recovery:{}:{}", self.local_profile_id, view.key())
            }
            NodeKind::Space { space } => format!("space:{space}"),
            NodeKind::Remote { space, entry } => format!("remote:{space}:{}", entry.id),
            NodeKind::Vault {
                route,
                generation,
                entry,
            } => format!(
                "vault:{}:{generation}:{}",
                route.control.route_id(),
                entry.id
            ),
            NodeKind::LockedVault {
                profile_id,
                space,
                resource_id,
                remote_path,
            } => format!(
                "locked-vault:{profile_id}:{space}:{}",
                resource_id.as_deref().unwrap_or(remote_path)
            ),
            NodeKind::LockedReadme { parent } => format!("locked-readme:{parent}"),
            NodeKind::Personal { space } => format!("personal:{space}"),
            NodeKind::Spaces => "synthetic:spaces".into(),
            NodeKind::Root => "synthetic:root".into(),
        };
        let mut ino = stable_inode(&key);
        while state
            .nodes
            .get(&ino)
            .is_some_and(|node| !same_identity(&node.kind, &kind))
        {
            ino = ino.wrapping_add(1).max(4);
        }
        if matches!(kind, NodeKind::Recovery(_)) {
            let alias = (parent, name.clone());
            if !state.recovery_aliases.contains(&alias) && state.recovery_aliases.len() >= MAX_NODES
            {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "saved namespace limit reached; remount to release retained names",
                ));
            }
            // Publish the deny fence and the visible name under the same lock.
            state.recovery_aliases.insert(alias);
        }
        state.children.insert((parent, name.clone()), ino);
        state.nodes.insert(
            ino,
            Node {
                ino,
                parent,
                name,
                kind,
                metadata_expires_at: Instant::now() + TTL,
            },
        );
        Ok(ino)
    }

    fn complete_pending_create_cancellation(
        &self,
        route: &VaultMountRoute,
        generation: u64,
        lease: &VaultRouteLease<'_>,
        spool: &VaultWriteSpool,
        cancellation: PendingVaultCreateCancellation,
    ) -> Result<bool, CloudError> {
        spool
            .ensure_create_cancellation_tombstone(&cancellation)
            .map_err(vault_write_error)?;
        let binding = VaultWriteBinding::new(
            cancellation.scope.clone(),
            cancellation.target.clone(),
            generation,
        )
        .map_err(vault_write_error)?;
        let mut working = match spool.recover(&cancellation.record_id, binding, generation) {
            Ok(working) => Some(working),
            // The exact backend receipt is still required below. If local
            // retirement completed just before a crash, this lets recovery
            // finish the same WAL without treating record absence alone as
            // cancellation authority.
            Err(crate::vault_write::VaultWriteError::RecordNotFound) => None,
            Err(error) => return Err(vault_write_error(error)),
        };
        if let Some(working) = working.as_mut() {
            match working.lifecycle() {
                VaultWriteLifecycle::Queued {
                    write_id,
                    revision,
                    uncertain: false,
                    ..
                } if write_id == &cancellation.write_id && *revision == cancellation.revision => {
                    working
                        .begin_never_attempted_create_cancel(
                            generation,
                            &cancellation.write_id,
                            cancellation.revision,
                            &cancellation.path,
                        )
                        .map_err(vault_write_error)?;
                }
                VaultWriteLifecycle::CancelPendingCreate { .. } => {}
                _ => {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "local queued-file cancellation state changed",
                    ));
                }
            }
            let expected = VaultWriteLifecycle::CancelPendingCreate {
                write_id: cancellation.write_id.clone(),
                revision: cancellation.revision,
                bytes: cancellation.bytes,
                sha256: cancellation.sha256.clone(),
            };
            if working.binding().scope() != &cancellation.scope
                || working.binding().target() != &cancellation.target
                || working.lifecycle() != &expected
            {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "queued file cancellation no longer matches its local record",
                ));
            }
        }

        let receipt = match lease
            .resolve_cancelled_file_create(&cancellation.write_id, cancellation.revision)
        {
            Ok(Some(receipt)) => receipt,
            Ok(None) if working.is_some() => match lease.cancel_never_attempted_file_create(
                &cancellation.path,
                &cancellation.write_id,
                cancellation.revision,
                &format!("raiun-pending-create:{}", cancellation.write_id),
                &format!(
                    "raiun-pending-v1:{}:{}",
                    cancellation.write_id, cancellation.revision
                ),
            ) {
                Ok(receipt) => receipt,
                Err(_) => return Ok(false),
            },
            // The durable local-retirement phase authorizes acknowledging only
            // a receipt that still resolves above. Absence remains unresolved.
            Ok(None) => return Ok(false),
            Err(_) => return Ok(false),
        };
        if receipt.scope != cancellation.scope
            || receipt.target != cancellation.target
            || receipt.path != cancellation.path
            || receipt.write_id != cancellation.write_id
            || receipt.original_revision != cancellation.revision
            || receipt.current_revision < receipt.original_revision
            || receipt.content.bytes != cancellation.bytes
            || receipt.content.sha256 != cancellation.sha256
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "backend cancellation receipt does not match the durable local intent",
            ));
        }
        let mut cancellation = cancellation;
        match receipt.state {
            VaultCancelledCreateReceiptState::Cancelled => {
                if let Some(working) = working {
                    if !working
                        .retire_cancelled_create_if_unchanged(
                            generation,
                            &cancellation.write_id,
                            cancellation.revision,
                            &receipt.content,
                        )
                        .map_err(vault_write_error)?
                    {
                        return Err(CloudError::new(
                            ErrorKind::Conflict,
                            "queued file bytes changed during cancellation",
                        ));
                    }
                    cancellation = spool
                        .mark_create_cancellation_local_retired(&cancellation)
                        .map_err(vault_write_error)?;
                } else if !cancellation.local_retired {
                    // An exact Cancelled receipt still pins the body, so this
                    // recovers a crash after spool retirement but before the
                    // local WAL phase was advanced.
                    cancellation = spool
                        .mark_create_cancellation_local_retired(&cancellation)
                        .map_err(vault_write_error)?;
                }
                if !cancellation.local_retired {
                    return Ok(false);
                }
                if lease
                    .acknowledge_cancelled_file_create(
                        &cancellation.write_id,
                        cancellation.revision,
                        &receipt.target,
                        &receipt.content,
                    )
                    .is_err()
                {
                    return Ok(false);
                }
            }
            VaultCancelledCreateReceiptState::Acknowledged => {
                // Acknowledgement is only possible after local retirement.
                // Never erase a remaining spool record or accept a missing
                // local-retirement phase as proof of that ordering.
                if working.is_some() || !cancellation.local_retired {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "acknowledged cancellation does not match local retirement state",
                    ));
                }
            }
        }

        // Close the crash window between backend acknowledgement and WAL
        // removal: resolve again and require the exact compact terminal proof.
        // A missing row is never treated as successful acknowledgement.
        let acknowledged = match lease
            .resolve_cancelled_file_create(&cancellation.write_id, cancellation.revision)
        {
            Ok(Some(receipt)) => receipt,
            Ok(None) | Err(_) => return Ok(false),
        };
        if acknowledged.state != VaultCancelledCreateReceiptState::Acknowledged
            || acknowledged.scope != cancellation.scope
            || acknowledged.target != cancellation.target
            || acknowledged.path != cancellation.path
            || acknowledged.write_id != cancellation.write_id
            || acknowledged.original_revision != cancellation.revision
            || acknowledged.content.bytes != cancellation.bytes
            || acknowledged.content.sha256 != cancellation.sha256
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "acknowledged cancellation receipt does not match the durable local intent",
            ));
        }
        spool
            .remove_create_cancellation_tombstone(&cancellation)
            .map_err(vault_write_error)?;
        // Finalization is garbage collection of the small proof row. The WAL
        // is already durably gone; a failure leaves only bounded backend
        // metadata and must not recreate the local WAL.
        let _ = lease.finalize_cancelled_file_create_ack(&acknowledged);
        self.remove_vault_path_projection(route.control.route_id(), &cancellation.path);
        Ok(true)
    }

    fn reconcile_pending_create_cancellations(
        &self,
        route: &VaultMountRoute,
        generation: u64,
        lease: &VaultRouteLease<'_>,
    ) -> Result<(), CloudError> {
        let route_key = (route.control.route_id(), generation);
        let mut completed = self
            .vault_cancel_recovery
            .lock()
            .map_err(|_| io_error("encrypted cancellation recovery is unavailable"))?;
        if completed.contains(&route_key) {
            return Ok(());
        }
        completed.retain(|(route_id, _)| *route_id != route.control.route_id());
        let Some(spool) = &self.vault_write_spool else {
            completed.insert(route_key);
            return Ok(());
        };
        let cancellations = spool
            .list_create_cancellations()
            .map_err(vault_write_error)?;
        let mut all_complete = true;
        for cancellation in cancellations {
            if cancellation.scope.space_id() != route.space_id()
                || cancellation.scope.root_resource_id() != route.root_resource_id()
            {
                continue;
            }
            if !self.complete_pending_create_cancellation(
                route,
                generation,
                lease,
                spool,
                cancellation,
            )? {
                all_complete = false;
            }
        }
        if all_complete {
            completed.insert(route_key);
        }
        Ok(())
    }

    fn remove_vault_path_projection(&self, route_id: u64, path: &str) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let removed: std::collections::HashSet<u64> = state
            .nodes
            .iter()
            .filter_map(|(ino, node)| match &node.kind {
                NodeKind::Vault { route, entry, .. }
                    if route.control.route_id() == route_id && entry.path == path =>
                {
                    Some(*ino)
                }
                _ => None,
            })
            .collect();
        state.children.retain(|_, child| !removed.contains(child));
        state
            .pending_parent_refs
            .retain(|ino, _| !removed.contains(ino));
        state.nodes.retain(|ino, _| !removed.contains(ino));
    }

    fn reconcile_pending_create_retargets(
        &self,
        route: &VaultMountRoute,
        generation: u64,
        lease: &VaultRouteLease<'_>,
    ) -> Result<(), CloudError> {
        let mut completed = self
            .vault_retarget_recovery
            .lock()
            .map_err(|_| io_error("encrypted create recovery is unavailable"))?;
        let route_key = (route.control.route_id(), generation);
        if completed.contains(&route_key) {
            return Ok(());
        }
        completed.retain(|(route_id, _)| *route_id != route.control.route_id());
        let Some(spool) = &self.vault_write_spool else {
            completed.insert(route_key);
            return Ok(());
        };
        let (records, truncated) = spool.list_pending().map_err(vault_write_error)?;
        if truncated {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "encrypted create recovery scan was incomplete",
            ));
        }
        let mut resolver_failed = false;
        for record in records {
            let (
                Some(scope),
                Some(old_target),
                Some(VaultWriteLifecycle::RetargetingCreate {
                    write_id,
                    previous_revision,
                    destination_path,
                    destination,
                    bytes,
                    sha256,
                }),
            ) = (record.scope, record.target, record.lifecycle)
            else {
                continue;
            };
            if scope.space_id() != route.space_id()
                || scope.root_resource_id() != route.root_resource_id()
            {
                continue;
            }
            if !matches!(old_target.condition(), WriteCondition::Absent)
                || old_target.parent_ref().is_none()
            {
                continue;
            }
            let binding = VaultWriteBinding::new(scope.clone(), old_target.clone(), generation)
                .map_err(vault_write_error)?;
            let mut working = spool
                .recover(&record.record_id, binding, generation)
                .map_err(vault_write_error)?;
            let Some(resolved): Option<VaultPendingCreateResolution> =
                (match lease.resolve_pending_create(&write_id) {
                    Ok(resolved) => resolved,
                    Err(_) => {
                        // Keep the route eligible for another scan. A transient
                        // resolver failure must not make this generation appear
                        // fully reconciled until remount.
                        resolver_failed = true;
                        continue;
                    }
                })
            else {
                continue;
            };
            if resolved.scope != scope
                || resolved.write_id != write_id
                || !resolved.never_attempted
                || resolved.plaintext_bytes != bytes
                || resolved.plaintext_sha256.as_deref() != Some(&sha256)
                || resolved.target.condition() != &WriteCondition::Absent
                || resolved.target.parent_ref().is_none()
            {
                continue;
            }
            if resolved.revision == previous_revision && resolved.target == old_target {
                working
                    .restore_original_create_binding(generation, &write_id, previous_revision)
                    .map_err(vault_write_error)?;
            } else if resolved.revision > previous_revision
                && resolved.path == destination_path
                && resolved.target == destination
            {
                working
                    .finish_verified_create_retarget(
                        generation,
                        &write_id,
                        previous_revision,
                        resolved.revision,
                        resolved.target,
                        crate::vault_write::VerifiedCreateContent {
                            bytes: resolved.plaintext_bytes,
                            sha256: resolved
                                .plaintext_sha256
                                .as_deref()
                                .unwrap_or_default()
                                .to_owned(),
                        },
                    )
                    .map_err(vault_write_error)?;
            }
            // Any other current row is retained unchanged for explicit review.
        }
        if !resolver_failed {
            completed.insert(route_key);
        }
        Ok(())
    }

    fn reconcile_pending_directory_subtree_retargets(
        &self,
        route: &VaultMountRoute,
        generation: u64,
        lease: &VaultRouteLease<'_>,
    ) -> Result<(), CloudError> {
        let mut completed = self
            .vault_subtree_recovery
            .lock()
            .map_err(|_| io_error("encrypted subtree recovery is unavailable"))?;
        let route_key = (route.control.route_id(), generation);
        if completed.contains(&route_key) {
            return Ok(());
        }
        completed.retain(|(route_id, _)| *route_id != route.control.route_id());
        let Some(spool) = &self.vault_write_spool else {
            completed.insert(route_key);
            return Ok(());
        };
        let retargets = spool
            .list_directory_subtree_retargets()
            .map_err(vault_write_error)?;
        for wal in retargets {
            if wal.scope.space_id() != route.space_id()
                || wal.scope.root_resource_id() != route.root_resource_id()
            {
                continue;
            }
            let proof = lease.resolve_pending_directory_subtree_retarget(&wal)?;
            verify_subtree_retarget_proof(&wal, &proof)?;
            match proof.state {
                VaultPendingDirectoryRetargetState::AllOld => spool
                    .discard_directory_subtree_retarget_if_unchanged(&wal)
                    .map_err(vault_write_error)?,
                VaultPendingDirectoryRetargetState::AllNew => {
                    spool
                        .apply_directory_subtree_retarget(&wal, generation)
                        .map_err(vault_write_error)?;
                    spool
                        .finish_directory_subtree_retarget(&wal)
                        .map_err(vault_write_error)?;
                }
            }
        }
        completed.insert(route_key);
        Ok(())
    }

    fn children(&self, parent_ino: u64) -> Result<Vec<Node>, CloudError> {
        self.with_node_lease(parent_ino, |lease| {
            self.children_with_lease(parent_ino, lease)
        })
    }

    fn children_with_lease(
        &self,
        parent_ino: u64,
        held_lease: Option<&VaultRouteLease<'_>>,
    ) -> Result<Vec<Node>, CloudError> {
        let parent = self.node(parent_ino)?;
        let mut result = Vec::new();
        match parent.kind {
            NodeKind::Recovery(view) => result.extend(self.recovery_children(parent_ino, &view)?),
            NodeKind::Root => result.extend([self.node(PERSONAL)?, self.node(SPACES)?]),
            NodeKind::Spaces => {
                for (label, space) in &self.project_spaces {
                    if space.encrypted {
                        // Whole-Space vaults are visible only through an
                        // explicitly unlocked, identity-bound route. Never
                        // ask the ordinary engine to list this Space.
                        if let Some(node) =
                            self.add_whole_space_vault_root(parent_ino, label, space)?
                        {
                            result.push(node);
                        }
                    } else {
                        let ino = self.add_node(
                            parent_ino,
                            label.clone(),
                            NodeKind::Space {
                                space: space.id.clone(),
                            },
                        )?;
                        result.push(self.node(ino)?);
                    }
                }
            }
            NodeKind::Personal { space } | NodeKind::Space { space } => {
                let engine = self.engine.clone();
                let request_space = space.clone();
                let listing = self.pool.call(move || engine.list(&request_space, "/"))?;
                let (mut entries, unavailable) = match listing {
                    Ok(entries) => (entries, None),
                    Err(error) if error.kind == ErrorKind::Offline => (Vec::new(), Some(error)),
                    Err(error) => {
                        trace_fuse_namespace_error("personal_listing", &error);
                        return Err(error);
                    }
                };
                if let Err(error) = self.append_active_vault_routes(&space, "/", &mut entries) {
                    trace_fuse_namespace_error("personal_route_overlay", &error);
                    return Err(error);
                }
                self.append_recovery_catalog(parent_ino, &space, &entries, &mut result)?;
                // A missing offline listing is not proof of an empty directory.
                // Authenticated active vault routes can still provide a bounded
                // offline view; never invent ordinary entries from stale rows.
                if entries.is_empty()
                    && result.is_empty()
                    && let Some(error) = unavailable
                {
                    return Err(error);
                }
                if entries.len() > MAX_DIRECTORY_ENTRIES {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "directory exceeds the provider listing limit",
                    ));
                }
                for mut entry in entries {
                    let name = entry.path.rsplit('/').next().unwrap_or_default().to_owned();
                    if !safe_component(&name) {
                        continue;
                    }
                    if entry.encrypted {
                        let route_root = self.add_vault_root(parent_ino, &space, &name, &entry);
                        if let Err(error) = &route_root {
                            trace_fuse_namespace_error("personal_vault_root", error);
                        }
                        if let Some(node) = route_root? {
                            result.push(node);
                        }
                        continue;
                    }
                    entry.writable &= self.space_is_writable(&space);
                    let ino = self.add_node(
                        parent_ino,
                        name.clone(),
                        NodeKind::Remote {
                            space: space.clone(),
                            entry,
                        },
                    )?;
                    result.push(self.node(ino)?);
                }
            }
            NodeKind::Remote { space, entry } if entry.directory && !entry.encrypted => {
                let path = entry.path.clone();
                let engine = self.engine.clone();
                let request_space = space.clone();
                let request_path = path.clone();
                let (mut entries, unavailable) = match self
                    .pool
                    .call(move || engine.list(&request_space, &request_path))?
                {
                    Ok(entries) => (entries, None),
                    Err(error) if error.kind == ErrorKind::Offline => (Vec::new(), Some(error)),
                    Err(error) => return Err(error),
                };
                self.append_active_vault_routes(&space, &path, &mut entries)?;
                if entries.is_empty()
                    && let Some(error) = unavailable
                {
                    return Err(error);
                }
                if entries.len() > MAX_DIRECTORY_ENTRIES {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "directory exceeds the provider listing limit",
                    ));
                }
                for mut entry in entries {
                    let name = entry.path.rsplit('/').next().unwrap_or_default().to_owned();
                    if !safe_component(&name) {
                        continue;
                    }
                    if entry.encrypted {
                        if let Some(node) =
                            self.add_vault_root(parent_ino, &space, &name, &entry)?
                        {
                            result.push(node);
                        }
                        continue;
                    }
                    entry.writable &= self.space_is_writable(&space);
                    let ino = self.add_node(
                        parent_ino,
                        name.clone(),
                        NodeKind::Remote {
                            space: space.clone(),
                            entry,
                        },
                    )?;
                    result.push(self.node(ino)?);
                }
            }
            NodeKind::Vault {
                route,
                generation,
                entry,
            } if entry.directory => {
                self.ensure_vault_hook(&route)?;
                let add_entries = |lease: &VaultRouteLease<'_>, result: &mut Vec<Node>| {
                    self.reconcile_pending_create_cancellations(&route, generation, lease)?;
                    self.reconcile_pending_directory_subtree_retargets(&route, generation, lease)?;
                    self.reconcile_pending_create_retargets(&route, generation, lease)?;
                    let entries = lease.list(&entry.path)?;
                    for entry in entries.into_iter().filter(|entry| {
                        !entry.encrypted
                            && safe_component(entry.path.rsplit('/').next().unwrap_or_default())
                    }) {
                        let name = entry.path.rsplit('/').next().unwrap_or_default().to_owned();
                        let ino = self.add_node(
                            parent_ino,
                            name,
                            NodeKind::Vault {
                                route: route.clone(),
                                generation,
                                entry,
                            },
                        )?;
                        let child = self.node(ino)?;
                        if let NodeKind::Vault { entry, .. } = &child.kind
                            && entry.directory
                        {
                            let parent_ref = lease.parent_ref_for_directory(
                                &entry.path,
                                &entry.id,
                                &entry.etag,
                            )?;
                            if matches!(parent_ref, VaultParentRef::PendingCreate { .. }) {
                                self.remember_pending_parent_ref(ino, generation, parent_ref)?;
                            }
                        }
                        result.push(child);
                    }
                    Ok::<(), CloudError>(())
                };
                if let Some(lease) = held_lease {
                    if lease.generation() != generation {
                        return Err(CloudError::new(
                            ErrorKind::Unauthorized,
                            "vault route is locked or stale",
                        ));
                    }
                    add_entries(lease, &mut result)?;
                } else {
                    route
                        .control
                        .with_read_lease(generation, |lease| add_entries(lease, &mut result))?;
                }
            }
            NodeKind::LockedVault { .. } => {
                let ino = self.add_node(
                    parent_ino,
                    "README.txt".into(),
                    NodeKind::LockedReadme { parent: parent_ino },
                )?;
                result.push(self.node(ino)?);
            }
            _ => {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "item is not a directory",
                ));
            }
        }
        if result.len() > MAX_DIRECTORY_ENTRIES {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "directory exceeds the provider listing limit",
            ));
        }
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    fn lookup_child_with_lease(
        &self,
        parent: u64,
        name: &str,
        held_lease: Option<&VaultRouteLease<'_>>,
    ) -> Result<Node, CloudError> {
        self.lookup_child_with_lease_at(parent, name, held_lease, Instant::now())
    }

    fn lookup_child_with_lease_at(
        &self,
        parent: u64,
        name: &str,
        held_lease: Option<&VaultRouteLease<'_>>,
        now: Instant,
    ) -> Result<Node, CloudError> {
        let parent_is_vault = matches!(self.node(parent)?.kind, NodeKind::Vault { .. });
        let cached_ino = {
            self.state
                .lock()
                .map_err(|_| io_error("provider state is unavailable"))?
                .children
                .get(&(parent, name.to_owned()))
                .copied()
        };
        if let Some(ino) = cached_ino {
            let cached = self.node(ino)?;
            let safe_to_reuse = match &cached.kind {
                NodeKind::Remote { entry, .. } => {
                    !parent_is_vault && !entry.encrypted && now < cached.metadata_expires_at
                }
                NodeKind::Root
                | NodeKind::Personal { .. }
                | NodeKind::Spaces
                | NodeKind::Space { .. } => true,
                // Vault roots must be revalidated against the provider before
                // lookup; their route authorization alone does not prove that
                // the configured remote root still has the same identity.
                NodeKind::Vault { .. } => false,
                // Locked placeholders are synthetic and must be rebuilt from
                // the current Space/parent listing so unlock transitions can
                // replace them with route-bound nodes.
                NodeKind::LockedVault { .. }
                | NodeKind::LockedReadme { .. }
                | NodeKind::Recovery(_) => false,
            };
            if safe_to_reuse {
                return Ok(cached);
            }
        }
        self.children_with_lease(parent, held_lease)?
            .into_iter()
            .find(|child| child.name == name)
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "cloud item was not found"))
    }

    fn space_is_writable(&self, space: &str) -> bool {
        self.mounted_spaces.get(space).is_some_and(|mounted| {
            self.engine
                .published_mount_permission(mounted)
                .unwrap_or(mounted.writable)
        })
    }

    fn reject_recovery_alias(&self, parent: u64, name: &str) -> Result<(), CloudError> {
        let state = self
            .state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?;
        if state.recovery_aliases.contains(&(parent, name.to_owned())) {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "saved offline copies are read-only",
            ));
        }
        Ok(())
    }

    fn child_path(&self, parent: &Node, name: &str) -> Result<(String, String), CloudError> {
        if !safe_component(name) {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "file name is not supported",
            ));
        }
        self.reject_recovery_alias(parent.ino, name)?;
        let (space, base) = match &parent.kind {
            NodeKind::Personal { space } | NodeKind::Space { space } => {
                (space.clone(), "/".to_owned())
            }
            NodeKind::Remote { space, entry } if entry.directory && !entry.encrypted => {
                (space.clone(), entry.path.clone())
            }
            NodeKind::Vault {
                route,
                generation,
                entry,
            } if entry.directory
                && (entry.writable || self.has_pending_parent_ref(parent.ino, *generation)?) =>
            {
                (route.space_id.clone(), entry.path.clone())
            }
            _ => {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "destination is not a writable cloud directory",
                ));
            }
        };
        if !self.space_is_writable(&space) {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "cloud Space is read-only",
            ));
        }
        let base = base.trim_end_matches('/');
        Ok((space, format!("{base}/{name}")))
    }

    fn has_pending_parent_ref(&self, ino: u64, generation: u64) -> Result<bool, CloudError> {
        let state = self
            .state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?;
        Ok(state
            .pending_parent_refs
            .get(&ino)
            .is_some_and(|(found_generation, reference)| {
                *found_generation == generation
                    && matches!(reference, VaultParentRef::PendingCreate { .. })
            }))
    }

    fn vault_parent_ref(
        &self,
        ino: u64,
        generation: u64,
        entry: &RemoteEntry,
        lease: &VaultRouteLease<'_>,
    ) -> Result<VaultParentRef, CloudError> {
        let cached = {
            self.state
                .lock()
                .map_err(|_| io_error("provider state is unavailable"))?
                .pending_parent_refs
                .get(&ino)
                .cloned()
        };
        if let Some((found_generation, reference)) = cached {
            if found_generation == generation {
                // A queued directory reference is bound to the exact synthetic
                // entry shown to FUSE. Never reuse it after that inode starts
                // resolving to a different remote/synthetic identity.
                let matches_entry = match &reference {
                    VaultParentRef::PendingCreate { write_id, revision } => {
                        entry.id == format!("raiun-pending-directory:{write_id}")
                            && entry.etag == format!("raiun-pending-v1:{write_id}:{revision}")
                    }
                    VaultParentRef::Stable { resource_id } => entry.id == *resource_id,
                };
                if matches_entry {
                    return Ok(reference);
                }
                self.state
                    .lock()
                    .map_err(|_| io_error("provider state is unavailable"))?
                    .pending_parent_refs
                    .remove(&ino);
            }
        }
        let reference = lease.parent_ref_for_directory(&entry.path, &entry.id, &entry.etag)?;
        if matches!(reference, VaultParentRef::PendingCreate { .. }) {
            self.state
                .lock()
                .map_err(|_| io_error("provider state is unavailable"))?
                .pending_parent_refs
                .insert(ino, (generation, reference.clone()));
        }
        Ok(reference)
    }

    fn remember_pending_parent_ref(
        &self,
        ino: u64,
        generation: u64,
        reference: VaultParentRef,
    ) -> Result<(), CloudError> {
        if !matches!(reference, VaultParentRef::PendingCreate { .. }) {
            return Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "queued encrypted directory lacks a pending-operation reference",
            ));
        }
        self.state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?
            .pending_parent_refs
            .insert(ino, (generation, reference));
        Ok(())
    }

    fn register_handle(&self, file: OpenFile) -> Result<u64, CloudError> {
        let vault_metadata = match &file {
            OpenFile::Vault {
                route, ino, path, ..
            } => Some(VaultFileHandleMeta {
                route_id: route.route_id(),
                ino: *ino,
                path: path.clone(),
                writable: false,
            }),
            OpenFile::VaultWrite(write) => Some(VaultFileHandleMeta {
                route_id: write.route.route_id(),
                ino: write.ino,
                path: write.path.clone(),
                writable: true,
            }),
            _ => None,
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?;
        if state.file_handles.len() >= MAX_FILE_HANDLES {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "provider file handle limit reached",
            ));
        }
        let id = self.next_handle.fetch_add(1, Ordering::Relaxed).max(1);
        state.file_handles.insert(id, Arc::new(Mutex::new(file)));
        if let Some(metadata) = vault_metadata {
            state.vault_file_handles.insert(id, metadata);
        }
        Ok(id)
    }

    fn file_handle(&self, id: u64) -> Result<Arc<Mutex<OpenFile>>, CloudError> {
        self.state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?
            .file_handles
            .get(&id)
            .cloned()
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "open file handle was not found"))
    }

    /// CREATE publishes a local BuildingCreate placeholder before its first
    /// content revision. FUSE immediately asks for attributes, while remote
    /// stat intentionally cannot see that non-retryable reservation yet.
    /// Preserve the placeholder only when an active handle for this exact
    /// inode and route generation still owns that BuildingCreate copy.
    fn building_create_size(&self, ino: u64, generation: u64) -> Result<Option<u64>, CloudError> {
        let handles = self
            .state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?
            .file_handles
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for handle in handles {
            let open = handle
                .lock()
                .map_err(|_| io_error("open file state is unavailable"))?;
            let OpenFile::VaultWrite(write) = &*open else {
                continue;
            };
            if write.ino != ino
                || write.generation != generation
                || !matches!(write.condition, WriteCondition::Absent)
                || !matches!(
                    write.working.lifecycle(),
                    VaultWriteLifecycle::BuildingCreate { .. }
                        | VaultWriteLifecycle::DirtyBuildingCreate { .. }
                )
            {
                continue;
            }
            return write
                .working
                .len(generation)
                .map(Some)
                .map_err(vault_write_error);
        }
        Ok(None)
    }

    fn prepare_write(
        &self,
        ino: u64,
        space: &str,
        path: &str,
        existing: Option<&RemoteEntry>,
        truncate: bool,
    ) -> Result<WriteHandle, CloudError> {
        let (spool, manifest) = self.spool_paths(space, path);
        let engine = self.engine.clone();
        let scope_space = space.to_owned();
        let scope = self
            .pool
            .call(move || engine.ordinary_write_scope(&scope_space))??;
        let resource_id = existing.map(|entry| entry.id.clone());
        let mut condition = existing
            .map(|entry| WriteCondition::Match(entry.etag.clone()))
            .unwrap_or(WriteCondition::Absent);
        let pending = manifest.exists() && spool.exists();
        if pending && truncate {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "a failed cloud write is pending; refusing to truncate its recovery copy",
            ));
        }
        let mut file = if pending {
            condition = read_manifest(&manifest, &scope, resource_id.as_deref(), path)?
                .ok_or_else(|| invalid("provider spool manifest disappeared"))?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&spool)
                .map_err(io_cloud)?
        } else {
            if existing.is_some() && !truncate {
                let engine = self.engine.clone();
                let space = space.to_owned();
                let path = path.to_owned();
                let mut snapshot = self
                    .pool
                    .call(move || engine.fetch_snapshot(&space, &path))??;
                let mut destination = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&spool)
                    .map_err(io_cloud)?;
                std::io::copy(&mut snapshot, &mut destination).map_err(io_cloud)?;
                destination.sync_all().map_err(io_cloud)?;
            }
            OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(truncate || existing.is_none())
                .open(&spool)
                .map_err(io_cloud)?
        };
        if truncate {
            file.set_len(0).map_err(io_cloud)?;
        }
        file.seek(SeekFrom::End(0)).map_err(io_cloud)?;
        write_manifest(&manifest, &scope, resource_id.as_deref(), path, &condition)?;
        Ok(WriteHandle {
            file,
            spool,
            manifest,
            space: space.into(),
            path: path.into(),
            condition,
            scope,
            resource_id,
            dirty: pending || truncate || existing.is_none(),
            ino,
            cleanup_on_release: false,
        })
    }

    fn spool_paths(&self, space: &str, path: &str) -> (PathBuf, PathBuf) {
        let hash = stable_hash(&format!("{space}\0{path}"));
        let stem = format!("{hash:016x}");
        (
            self.spool_dir.join(format!("{stem}.data")),
            self.spool_dir.join(format!("{stem}.meta")),
        )
    }

    fn refresh_remote_node(&self, ino: u64) -> Result<Node, CloudError> {
        let node = self.node(ino)?;
        if let NodeKind::Recovery(view) = &node.kind {
            self.validate_recovery_node(view)?;
        }
        let NodeKind::Remote { space, entry } = &node.kind else {
            return Ok(node);
        };
        let (spool, manifest) = self.spool_paths(space, &entry.path);
        if spool.exists() && manifest.exists() {
            return Ok(node);
        }
        let engine = self.engine.clone();
        let request_space = space.clone();
        let path = entry.path.clone();
        let mut refreshed = self
            .pool
            .call(move || engine.stat(&request_space, &path))??;
        refreshed.writable &= self.space_is_writable(space);
        if refreshed.id != entry.id {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "cloud item identity changed; refusing to reuse a stale inode",
            ));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?;
        let current = state
            .nodes
            .get_mut(&ino)
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "cloud item was removed"))?;
        current.kind = NodeKind::Remote {
            space: space.clone(),
            entry: refreshed,
        };
        current.metadata_expires_at = Instant::now() + TTL;
        Ok(current.clone())
    }

    fn getattr_node(&self, ino: u64) -> Result<Node, CloudError> {
        self.getattr_node_at(ino, Instant::now())
    }

    fn getattr_node_at(&self, ino: u64, now: Instant) -> Result<Node, CloudError> {
        let node = self.node(ino)?;
        if matches!(node.kind, NodeKind::Remote { .. }) && now < node.metadata_expires_at {
            // Directory listing already supplied bounded metadata and the
            // kernel caches this attribute for TTL. A later listing refreshes
            // the same inode's metadata when it sees it again. Actual opens and
            // mutations still refresh identity and permissions.
            Ok(node)
        } else if matches!(
            node.kind,
            NodeKind::Root
                | NodeKind::Personal { .. }
                | NodeKind::Spaces
                | NodeKind::Space { .. }
                | NodeKind::LockedVault { .. }
                | NodeKind::LockedReadme { .. }
        ) {
            Ok(node)
        } else {
            self.refresh_remote_node(ino)
        }
    }

    // Publish subtree intent before waiting for RELEASE so no new child
    // mutation can enter. The same markers also exclude ancestor renames.
    fn reserve_ordinary_rename_paths(
        &self,
        source: (&str, &str),
        destination: (&str, &str),
        timeout: Duration,
        mut before_wait: impl FnMut(),
    ) -> Result<Vec<PathReservation<'_>>, CloudError> {
        if source == destination {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "rename paths are identical",
            ));
        }
        let paths = [source, destination];
        let keys = paths.map(|(space, path)| format!("\0ordinary-subtree\0{space}\0{path}"));
        let deadline = Instant::now() + timeout;
        let mut state = self
            .state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?;
        if state.active_writers.iter().any(|key| {
            ordinary_subtree_path(key).is_some_and(|(space, path)| {
                paths.iter().any(|(target_space, target)| {
                    space == *target_space && paths_overlap(path, target)
                })
            })
        }) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "overlapping rename is active",
            ));
        }
        for key in &keys {
            state.active_writers.insert(key.clone());
        }
        while state.active_writers.iter().any(|key| {
            key.split_once('\0').is_some_and(|(space, path)| {
                paths.iter().any(|(target_space, target)| {
                    space == *target_space && paths_overlap(path, target)
                })
            })
        }) {
            let now = Instant::now();
            if now >= deadline {
                for key in &keys {
                    state.active_writers.remove(key);
                }
                self.active_writer_changed.notify_all();
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "active writer did not close before rename",
                ));
            }
            before_wait();
            (state, _) = self
                .active_writer_changed
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .map_err(|_| io_error("provider state is unavailable"))?;
        }
        drop(state);
        let guards = keys
            .into_iter()
            .map(|key| PathReservation {
                state: &self.state,
                changed: &self.active_writer_changed,
                key,
                active: true,
            })
            .collect::<Vec<_>>();
        // Failed RELEASE retires the writer reservation but retains its data.
        // Never move an ancestor while such recovery records still refer to it.
        self.ensure_ordinary_rename_has_no_recovery(&paths)?;
        Ok(guards)
    }

    fn ensure_ordinary_rename_has_no_recovery(
        &self,
        paths: &[(&str, &str)],
    ) -> Result<(), CloudError> {
        let mut after = None;
        loop {
            let page = recovery::list_recoveries(
                &self.spool_dir,
                after.as_deref(),
                recovery::MAX_RECOVERY_PAGE_SIZE,
            )
            .map_err(|_| io_error("could not inspect pending local data before rename"))?;
            if page.truncated || page.unrecognized_entries != 0 {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "pending local data scan is incomplete",
                ));
            }
            for item in page.items {
                let (Some(space), Some(path)) =
                    (item.space_id.as_deref(), item.remote_path.as_deref())
                else {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "unidentified local recovery data prevents rename",
                    ));
                };
                if paths.iter().any(|(target_space, target)| {
                    space == *target_space && paths_overlap(path, target)
                }) {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "rename subtree has pending local data",
                    ));
                }
            }
            match page.next_after {
                Some(cursor) => after = Some(cursor),
                None => return Ok(()),
            }
        }
    }

    fn reserve_path(&self, space: &str, path: &str) -> Result<PathReservation<'_>, CloudError> {
        let key = format!("{space}\0{path}");
        let mut state = self
            .state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?;
        if state.active_writers.iter().any(|active| {
            ordinary_subtree_path(active).is_some_and(|(active_space, active_path)| {
                active_space == space && paths_overlap(active_path, path)
            })
        }) || !state.active_writers.insert(key.clone())
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "cloud path already has an active operation",
            ));
        }
        drop(state);
        Ok(PathReservation {
            state: &self.state,
            changed: &self.active_writer_changed,
            key,
            active: true,
        })
    }

    fn commit(&self, handle: &Arc<Mutex<OpenFile>>) -> Result<(), CloudError> {
        let mut open = handle
            .lock()
            .map_err(|_| io_error("open file state is unavailable"))?;
        let OpenFile::Write(write) = &mut *open else {
            return Ok(());
        };
        write.file.flush().map_err(io_cloud)?;
        write.file.sync_all().map_err(io_cloud)?;
        if !write.dirty {
            return Ok(());
        }
        let engine = self.engine.clone();
        let source = write.spool.clone();
        let space = write.space.clone();
        let path = write.path.clone();
        let condition = write.condition.clone();
        let scope = write.scope.clone();
        let resource_id = write.resource_id.clone();
        let outcome = self.pool.call(move || {
            engine.commit_file_write_scoped(
                &space,
                &path,
                &source,
                condition,
                &scope,
                resource_id.as_deref(),
            )
        })??;
        match outcome {
            raiun_engine::FileWriteOutcome::Uploaded(entry) => {
                if let Ok(mut state) = self.state.lock() {
                    if let Some(node) = state.nodes.get_mut(&write.ino) {
                        if let NodeKind::Remote { entry: current, .. } = &mut node.kind {
                            *current = entry.clone();
                        }
                    }
                }
                let next_condition = WriteCondition::Match(entry.etag.clone());
                write.resource_id = Some(entry.id.clone());
                write_manifest(
                    &write.manifest,
                    &write.scope,
                    write.resource_id.as_deref(),
                    &write.path,
                    &next_condition,
                )?;
                write.condition = next_condition;
                write.dirty = false;
                write.cleanup_on_release = true;
            }
            raiun_engine::FileWriteOutcome::Queued(entry) => {
                if let Ok(mut state) = self.state.lock() {
                    if let Some(node) = state.nodes.get_mut(&write.ino) {
                        if let NodeKind::Remote { entry: current, .. } = &mut node.kind {
                            current.size = entry.size;
                        }
                    }
                }
                // The cache journal now owns the durable pending bytes. Keep
                // the original base condition so a later flush cannot rebase.
                write.dirty = false;
                write.cleanup_on_release = true;
            }
        }
        Ok(())
    }

    fn commit_vault(
        &self,
        handle: &Arc<Mutex<OpenFile>>,
        lease: &VaultRouteLease<'_>,
        expected_generation: u64,
    ) -> Result<bool, CloudError> {
        let mut open = handle
            .lock()
            .map_err(|_| io_error("open file state is unavailable"))?;
        let OpenFile::VaultWrite(write) = &mut *open else {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "file handle is not an encrypted writer",
            ));
        };
        if write.generation != expected_generation || lease.generation() != expected_generation {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "encrypted write handle is stale",
            ));
        }
        if write.closing {
            return Err(CloudError::new(
                ErrorKind::NotFound,
                "encrypted file handle is closing",
            ));
        }
        write
            .working
            .sync(write.generation)
            .map_err(vault_write_error)?;
        if !write.dirty {
            return Ok(false);
        }
        let (scope, target) = match &write.condition {
            WriteCondition::Match(base_etag) => {
                lease.prepare_existing_target(&write.path, &write.entry_id, base_etag)?
            }
            WriteCondition::Absent => {
                let existing = match write.working.lifecycle() {
                    VaultWriteLifecycle::Queued {
                        write_id, revision, ..
                    }
                    | VaultWriteLifecycle::DirtyQueued {
                        write_id, revision, ..
                    }
                    | VaultWriteLifecycle::BuildingCreate { write_id, revision }
                    | VaultWriteLifecycle::DirtyBuildingCreate { write_id, revision } => {
                        Some((write_id.as_str(), *revision))
                    }
                    _ => None,
                };
                let parent_ref = write.binding.target().parent_ref().ok_or_else(|| {
                    CloudError::new(
                        ErrorKind::Conflict,
                        "encrypted create lost its verified parent reference",
                    )
                })?;
                lease.prepare_file_create_under_parent(&write.path, parent_ref, existing)?
            }
        };
        if scope != *write.binding.scope()
            || target.condition() != &write.condition
            || target != *write.binding.target()
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "encrypted write target changed; refusing to publish stale data",
            ));
        }
        let path = write.path.clone();
        let existing_create = match write.working.lifecycle() {
            VaultWriteLifecycle::Queued {
                write_id, revision, ..
            }
            | VaultWriteLifecycle::DirtyQueued {
                write_id, revision, ..
            }
            | VaultWriteLifecycle::BuildingCreate { write_id, revision }
            | VaultWriteLifecycle::DirtyBuildingCreate { write_id, revision }
                if matches!(write.condition, WriteCondition::Absent) =>
            {
                Some((write_id.clone(), *revision))
            }
            _ => None,
        };
        let outcome = write
            .working
            .commit_snapshot_outcome(write.generation, |source, length| {
                let outcome = match &write.condition {
                    WriteCondition::Match(_) => {
                        lease.overwrite_existing(&target, source, length)?
                    }
                    WriteCondition::Absent => lease.create_file(
                        &target,
                        source,
                        length,
                        existing_create
                            .as_ref()
                            .map(|(id, revision)| (id.as_str(), *revision)),
                    )?,
                };
                let entry = match &outcome {
                    VaultUploadOutcome::Committed(entry)
                    | VaultUploadOutcome::Queued { entry, .. }
                    | VaultUploadOutcome::QueuedCreate { entry, .. }
                    | VaultUploadOutcome::BuildingCreate { entry, .. } => entry,
                };
                if entry.path != path
                    || entry.directory
                    || entry.size != length
                    || entry.etag.is_empty()
                {
                    return Err(CloudError::new(
                        ErrorKind::InvalidResponse,
                        "encrypted upload returned an invalid file version",
                    ));
                }
                Ok(outcome)
            })
            .map_err(vault_write_error)?;
        let entry = match outcome {
            VaultUploadOutcome::Committed(entry) | VaultUploadOutcome::Queued { entry, .. } => {
                entry
            }
            VaultUploadOutcome::QueuedCreate { entry, .. }
            | VaultUploadOutcome::BuildingCreate { entry, .. } => entry,
        };
        let next_condition = match write.working.lifecycle() {
            VaultWriteLifecycle::Queued { .. } | VaultWriteLifecycle::BuildingCreate { .. }
                if matches!(write.binding.target().condition(), WriteCondition::Absent) =>
            {
                // Queued creates retain the original Absent condition; their
                // operation ID/revision live in the durable lifecycle.
                WriteCondition::Absent
            }
            _ => WriteCondition::Match(entry.etag.clone()),
        };
        write.entry_id = entry.id.clone();
        write.condition = next_condition;
        write.binding = write.working.binding().clone();
        write.dirty = false;
        if let Ok(mut state) = self.state.lock() {
            if let Some(node) = state.nodes.get_mut(&write.ino) {
                if let NodeKind::Vault { entry: current, .. } = &mut node.kind {
                    *current = entry;
                }
            }
        }
        Ok(true)
    }
}

fn ignore_missing_invalidation(
    result: std::io::Result<()>,
    message: &str,
) -> Result<(), CloudError> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(io_error(message)),
    }
}

impl Filesystem for RaiunFilesystem {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        config
            .add_capabilities(InitFlags::FUSE_ATOMIC_O_TRUNC)
            .map_err(|unsupported| {
                std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!("kernel does not support atomic O_TRUNC: {unsupported:?}"),
                )
            })
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        #[cfg(target_os = "linux")]
        {
            let capacity = self
                .spool_capacity_dir
                .as_ref()
                .ok_or_else(|| std::io::Error::other("local write spool capacity is unavailable"))
                .and_then(spool_statfs);
            match capacity {
                Ok(capacity) => reply.statfs(
                    capacity.blocks,
                    capacity.blocks,
                    capacity.blocks,
                    capacity.files,
                    capacity.files_free,
                    capacity.block_size,
                    255,
                    capacity.block_size,
                ),
                Err(error) => reply.error(error.into()),
            }
        }
        #[cfg(not(target_os = "linux"))]
        reply.error(Errno::ENOSYS);
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let mut reply = Some(reply);
        let outcome = self.with_node_lease(parent.0, |lease| {
            let result = name
                .to_str()
                .ok_or_else(|| CloudError::new(ErrorKind::Unsupported, "file name is not UTF-8"))
                .and_then(|name| self.lookup_child_with_lease(parent.0, name, lease));
            match result {
                Ok(node) => {
                    let mut send_entry = || {
                        let ttl = if matches!(node.kind, NodeKind::Vault { .. }) {
                            &Duration::ZERO
                        } else {
                            &TTL
                        };
                        reply.take().expect("FUSE reply is used once").entry(
                            ttl,
                            &self.attr(&node),
                            Generation(0),
                        );
                        Ok::<(), CloudError>(())
                    };
                    let sent = match (&node.kind, lease) {
                        (
                            NodeKind::Vault {
                                route: child_route,
                                generation: child_generation,
                                ..
                            },
                            Some(parent_lease),
                        ) => {
                            let parent_node = self.node(parent.0);
                            match parent_node {
                                Ok(Node {
                                    kind:
                                        NodeKind::Vault {
                                            route: parent_route,
                                            generation: parent_generation,
                                            ..
                                        },
                                    ..
                                }) if parent_route.control.route_id()
                                    == child_route.control.route_id()
                                    && parent_generation == *child_generation
                                    && parent_lease.generation() == *child_generation =>
                                {
                                    // A child in a vault directory uses the
                                    // owner's existing lease; taking a second
                                    // read lock can deadlock behind a waiting
                                    // revoker.
                                    send_entry()
                                }
                                Ok(Node {
                                    kind: NodeKind::Vault { .. },
                                    ..
                                }) => Err(CloudError::new(
                                    ErrorKind::Conflict,
                                    "a vault directory cannot contain a different vault route",
                                )),
                                Ok(_) => self.with_node_lease(node.ino, |_| send_entry()),
                                Err(error) => Err(error),
                            }
                        }
                        (NodeKind::Vault { .. }, None) => {
                            self.with_node_lease(node.ino, |_| send_entry())
                        }
                        (_, Some(_)) => Err(CloudError::new(
                            ErrorKind::Conflict,
                            "a vault directory cannot contain an ordinary cloud entry",
                        )),
                        (_, None) => send_entry(),
                    };
                    if let Err(error) = sent {
                        reply
                            .take()
                            .expect("FUSE reply is used once")
                            .error(errno(&error));
                    }
                }
                Err(error) => reply
                    .take()
                    .expect("FUSE reply is used once")
                    .error(errno(&error)),
            }
            Ok(())
        });
        if let Err(error) = outcome {
            if let Some(reply) = reply {
                reply.error(errno(&error));
            }
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        let mut reply = Some(reply);
        let outcome = self.with_node_lease(ino.0, |lease| {
            let result = (|| {
                let mut node = self.getattr_node(ino.0)?;
                if let NodeKind::Vault {
                    route,
                    generation,
                    entry,
                } = &node.kind
                {
                    let lease = lease.ok_or_else(|| {
                        CloudError::new(ErrorKind::Unauthorized, "vault route is locked or stale")
                    })?;
                    if lease.generation() != *generation {
                        return Err(CloudError::new(
                            ErrorKind::Unauthorized,
                            "vault route is locked or stale",
                        ));
                    }
                    match lease.stat(&entry.path) {
                        Ok(refreshed) => {
                            if refreshed.id != entry.id {
                                return Err(CloudError::new(
                                    ErrorKind::Conflict,
                                    "vault item identity changed",
                                ));
                            }
                            node.kind = NodeKind::Vault {
                                route: route.clone(),
                                generation: *generation,
                                entry: refreshed,
                            };
                        }
                        Err(error) if error.kind == ErrorKind::NotFound => {
                            if let Some(size) = self.building_create_size(ino.0, *generation)? {
                                if let NodeKind::Vault { entry, .. } = &mut node.kind {
                                    entry.size = size;
                                }
                            } else {
                                return Err(error);
                            }
                        }
                        Err(error) => return Err(error),
                    }
                }
                if let Some(fh) = fh {
                    let handle = self.file_handle(fh.0)?;
                    let open = handle
                        .lock()
                        .map_err(|_| io_error("open file state is unavailable"))?;
                    if let OpenFile::VaultWrite(write) = &*open {
                        if write.ino != ino.0
                            || lease.is_none_or(|lease| lease.generation() != write.generation)
                        {
                            return Err(CloudError::new(
                                ErrorKind::Unauthorized,
                                "encrypted file handle is stale",
                            ));
                        }
                        if let NodeKind::Vault { entry, .. } = &mut node.kind {
                            entry.size = write
                                .working
                                .len(write.generation)
                                .map_err(vault_write_error)?;
                        }
                    }
                }
                Ok(node)
            })();
            match result {
                Ok(node) => {
                    let ttl = if matches!(node.kind, NodeKind::Vault { .. }) {
                        &Duration::ZERO
                    } else {
                        &TTL
                    };
                    reply
                        .take()
                        .expect("FUSE reply is used once")
                        .attr(ttl, &self.attr(&node));
                }
                Err(error) => reply
                    .take()
                    .expect("FUSE reply is used once")
                    .error(errno(&error)),
            }
            Ok(())
        });
        if let Err(error) = outcome {
            if let Some(reply) = reply {
                reply.error(errno(&error));
            }
        }
    }

    fn opendir(&self, req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let mut reply = Some(reply);
        let outcome = self.with_node_lease(ino.0, |held_lease| {
            let result = (|| {
                let children = self.children_with_lease(ino.0, held_lease)?;
                if children.len() > MAX_DIRECTORY_ENTRIES {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "directory exceeds the provider listing limit",
                    ));
                }
                let mut snapshot = vec![(".".into(), ino.0, FileType::Directory)];
                if let Ok(parent) = self.node(ino.0) {
                    snapshot.push(("..".into(), parent.parent, FileType::Directory));
                }
                snapshot.extend(
                    children
                        .iter()
                        .map(|node| (node.name.clone(), node.ino, self.file_type(node))),
                );
                let parent = self.node(ino.0)?;
                let owner_vault = match &parent.kind {
                    NodeKind::Vault {
                        route,
                        generation,
                        entry,
                    } => Some((
                        route.control.route_id(),
                        *generation,
                        parent.ino,
                        entry.path.clone(),
                    )),
                    _ => None,
                };
                let routes = directory_vault_routes(&parent, &children);
                let mut locked_vaults = children
                    .iter()
                    .filter_map(|node| {
                        matches!(node.kind, NodeKind::LockedVault { .. }).then_some(node.ino)
                    })
                    .collect::<Vec<_>>();
                if matches!(parent.kind, NodeKind::LockedVault { .. }) {
                    locked_vaults.push(parent.ino);
                }
                let parent_route_id = match &parent.kind {
                    NodeKind::Vault { route, .. } => Some(route.control.route_id()),
                    _ => None,
                };
                let routes_to_acquire: Vec<_> = routes
                    .iter()
                    .filter(|(route, _)| Some(route.route_id()) != parent_route_id)
                    .cloned()
                    .collect();
                if held_lease.is_some() && !routes_to_acquire.is_empty() {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "a vault directory cannot contain a different vault route",
                    ));
                }
                let fh = self.next_handle.fetch_add(1, Ordering::Relaxed).max(1);
                with_vault_route_leases(&routes_to_acquire, 0, || {
                    self.register_directory_handle(
                        fh,
                        DirectoryHandle {
                            entries: snapshot,
                            routes,
                            locked_vaults,
                            owner_vault,
                        },
                    )?;
                    reply
                        .take()
                        .expect("FUSE reply is used once")
                        .opened(FileHandle(fh), FopenFlags::empty());
                    Ok(())
                })
            })();
            if let Err(error) = result {
                reply
                    .take()
                    .expect("FUSE reply is used once")
                    .error(errno(&error));
            }
            Ok(())
        });
        if let Err(error) = outcome {
            if let Some(reply) = reply {
                reply.error(errno(&error));
            }
        }
        let _ = req;
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        reply: ReplyDirectory,
    ) {
        let snapshot = self
            .state
            .lock()
            .ok()
            .and_then(|state| state.directory_handles.get(&fh.0).cloned());
        let Some(snapshot) = snapshot else {
            reply.error(Errno::EBADF);
            return;
        };
        let mut reply = Some(reply);
        let emit = |reply: ReplyDirectory| {
            let mut reply = reply;
            for (index, (name, child, kind)) in
                snapshot.entries.iter().enumerate().skip(offset as usize)
            {
                if reply.add(INodeNo(*child), (index + 1) as u64, *kind, name) {
                    break;
                }
            }
            reply.ok();
        };
        match with_vault_route_leases(&snapshot.routes, 0, || {
            emit(reply.take().expect("FUSE reply is used once"));
            Ok(())
        }) {
            Ok(()) => {}
            Err(error) => {
                if let Some(reply) = reply.take() {
                    reply.error(errno(&error));
                }
            }
        }
        let _ = ino;
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        if let Ok(mut state) = self.state.lock() {
            state.directory_handles.remove(&fh.0);
        }
        reply.ok();
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let initial = self.node(ino.0);
        if let Ok(node) = &initial
            && let NodeKind::Vault {
                route,
                generation,
                entry,
            } = &node.kind
            && let Err(error) =
                self.wait_for_vault_path(route, *generation, &entry.path, Duration::from_secs(5))
        {
            reply.error(errno(&error));
            return;
        }
        if let Ok(Node {
            kind: NodeKind::Vault { .. },
            ..
        }) = initial
        {
            let mut reply = Some(reply);
            let outcome = self.with_node_lease(ino.0, |lease| {
                let result = (|| {
                    let node = self.node(ino.0)?;
                    let NodeKind::Vault {
                        route,
                        generation,
                        entry,
                    } = node.kind
                    else {
                        return Err(CloudError::new(
                            ErrorKind::Unauthorized,
                            "vault route is locked or stale",
                        ));
                    };
                    if entry.directory {
                        return Err(CloudError::new(
                            ErrorKind::Unsupported,
                            "vault directory cannot be opened as a file",
                        ));
                    }
                    let lease = lease.ok_or_else(|| {
                        CloudError::new(ErrorKind::Unauthorized, "vault route is locked or stale")
                    })?;
                    if lease.generation() != generation {
                        return Err(CloudError::new(
                            ErrorKind::Unauthorized,
                            "vault route is locked or stale",
                        ));
                    }
                    if flags.0 & libc::O_ACCMODE != libc::O_RDONLY {
                        let fh = self.open_vault_for_write(
                            ino.0, flags.0, &route, generation, &entry, lease,
                        )?;
                        return Ok(fh);
                    }
                    if flags.0 & (libc::O_TRUNC | libc::O_APPEND) != 0 {
                        return Err(CloudError::new(
                            ErrorKind::Forbidden,
                            "read-only vault open flags are invalid",
                        ));
                    }
                    let _open_reservation =
                        self.reserve_vault_path(route.control.route_id(), &entry.path)?;
                    let current = lease.stat(&entry.path)?;
                    if current.id != entry.id || current.directory {
                        return Err(CloudError::new(
                            ErrorKind::Conflict,
                            "vault item identity changed",
                        ));
                    }
                    let handle = lease.open(&entry.path)?;
                    self.register_handle(OpenFile::Vault {
                        route: route.control.clone(),
                        generation,
                        ino: ino.0,
                        path: entry.path.clone(),
                        handle: Some(handle),
                    })
                })();
                match result {
                    Ok(fh) => reply
                        .take()
                        .expect("FUSE reply is used once")
                        .opened(FileHandle(fh), FopenFlags::FOPEN_DIRECT_IO),
                    Err(error) => reply
                        .take()
                        .expect("FUSE reply is used once")
                        .error(errno(&error)),
                }
                Ok(())
            });
            if let Err(error) = outcome {
                if let Some(reply) = reply {
                    reply.error(errno(&error));
                }
            }
        } else {
            match initial.and_then(|_| self.open_node(ino.0, flags.0)) {
                Ok(fh) => reply.opened(FileHandle(fh), FopenFlags::empty()),
                Err(error) => reply.error(errno(&error)),
            }
        }
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        if size > MAX_READ {
            reply.error(Errno::EINVAL);
            return;
        }
        let file_handle = self.file_handle(fh.0);
        let vault_access = file_handle.as_ref().ok().and_then(|handle| {
            handle.lock().ok().and_then(|open| match &*open {
                OpenFile::Vault {
                    route, generation, ..
                } => Some((route.clone(), *generation)),
                OpenFile::VaultWrite(write) => Some((write.route.clone(), write.generation)),
                _ => None,
            })
        });
        if let Some((route, generation)) = vault_access {
            let mut reply = Some(reply);
            let outcome = route.with_read_lease(generation, |lease| {
                let result = (|| {
                    let mut open = file_handle
                        .as_ref()
                        .map_err(Clone::clone)?
                        .lock()
                        .map_err(|_| io_error("open file state is unavailable"))?;
                    match &mut *open {
                        OpenFile::Vault {
                            handle: Some(vault_handle),
                            ..
                        } => lease.read(vault_handle, offset, size as usize),
                        OpenFile::VaultWrite(write) => {
                            if write.closing {
                                return Err(CloudError::new(
                                    ErrorKind::NotFound,
                                    "encrypted file handle is closing",
                                ));
                            }
                            if write.flags & libc::O_ACCMODE == libc::O_WRONLY {
                                return Err(CloudError::new(
                                    ErrorKind::Forbidden,
                                    "file was opened write-only",
                                ));
                            }
                            let mut data = vec![0; size as usize];
                            let count = write
                                .working
                                .read_at(offset, &mut data, write.generation)
                                .map_err(vault_write_error)?;
                            data.truncate(count);
                            Ok(data)
                        }
                        _ => Err(CloudError::new(
                            ErrorKind::NotFound,
                            "vault file handle was released",
                        )),
                    }
                })();
                match result {
                    Ok(data) => reply.take().expect("FUSE reply is used once").data(&data),
                    Err(error) => reply
                        .take()
                        .expect("FUSE reply is used once")
                        .error(errno(&error)),
                }
                Ok(())
            });
            if let Err(error) = outcome {
                if let Some(reply) = reply {
                    reply.error(errno(&error));
                }
            }
            return;
        }
        let result = file_handle.and_then(|handle| {
            let mut open = handle
                .lock()
                .map_err(|_| io_error("open file state is unavailable"))?;
            let file: &mut dyn ReadSeek = match &mut *open {
                OpenFile::Read(ReadHandle::Recovery(file)) => file,
                OpenFile::Read(ReadHandle::Local(file)) => file,
                OpenFile::Read(ReadHandle::Snapshot(file)) => file,
                OpenFile::Read(ReadHandle::Static(file)) => file,
                OpenFile::Write(write) => &mut write.file,
                OpenFile::Vault { .. } | OpenFile::VaultWrite(_) => {
                    unreachable!("vault reads are handled above")
                }
            };
            file.seek(SeekFrom::Start(offset)).map_err(io_cloud)?;
            let mut data = vec![0; size as usize];
            let read = file.read(&mut data).map_err(io_cloud)?;
            data.truncate(read);
            Ok(data)
        });
        match result {
            Ok(data) => reply.data(&data),
            Err(error) => reply.error(errno(&error)),
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: fuser::WriteFlags,
        flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyWrite,
    ) {
        let handle = self.file_handle(fh.0);
        let vault_access = handle.as_ref().ok().and_then(|handle| {
            handle.lock().ok().and_then(|open| match &*open {
                OpenFile::VaultWrite(write) => Some((write.route.clone(), write.generation)),
                _ => None,
            })
        });
        if let Some((route, generation)) = vault_access {
            let mut reply = Some(reply);
            let outcome = route.with_read_lease(generation, |lease| {
                let result = (|| {
                    let handle = handle.as_ref().map_err(Clone::clone)?;
                    let mut open = handle
                        .lock()
                        .map_err(|_| io_error("open file state is unavailable"))?;
                    let OpenFile::VaultWrite(write) = &mut *open else {
                        return Err(CloudError::new(
                            ErrorKind::Forbidden,
                            "file was not opened for encrypted writing",
                        ));
                    };
                    if write.ino != ino.0 || lease.generation() != write.generation {
                        return Err(CloudError::new(
                            ErrorKind::Unauthorized,
                            "encrypted file handle is stale",
                        ));
                    }
                    if write.closing {
                        return Err(CloudError::new(
                            ErrorKind::NotFound,
                            "encrypted file handle is closing",
                        ));
                    }
                    if write.flags & libc::O_ACCMODE == libc::O_RDONLY {
                        return Err(CloudError::new(
                            ErrorKind::Forbidden,
                            "file was opened read-only",
                        ));
                    }
                    let offset =
                        if flags.0 & libc::O_APPEND != 0 || write.flags & libc::O_APPEND != 0 {
                            write
                                .working
                                .len(write.generation)
                                .map_err(vault_write_error)?
                        } else {
                            offset
                        };
                    let count = write
                        .working
                        .write_at(offset, data, write.generation)
                        .map_err(vault_write_error)?;
                    write.dirty = true;
                    let size = write
                        .working
                        .len(write.generation)
                        .map_err(vault_write_error)?;
                    Ok((u32::try_from(count).unwrap_or(u32::MAX), size))
                })();
                match result {
                    Ok((count, size)) => {
                        self.update_vault_size(ino.0, size);
                        reply
                            .take()
                            .expect("FUSE reply is used once")
                            .written(count);
                    }
                    Err(error) => reply
                        .take()
                        .expect("FUSE reply is used once")
                        .error(errno(&error)),
                }
                Ok(())
            });
            if let Err(error) = outcome {
                if let Some(reply) = reply {
                    reply.error(errno(&error));
                }
            }
            return;
        }
        let result = self.file_handle(fh.0).and_then(|handle| {
            let mut open = handle
                .lock()
                .map_err(|_| io_error("open file state is unavailable"))?;
            let OpenFile::Write(write) = &mut *open else {
                return Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "file was not opened for writing",
                ));
            };
            let offset = if flags.0 & libc::O_APPEND != 0 {
                write.file.metadata().map_err(io_cloud)?.len()
            } else {
                offset
            };
            write.file.seek(SeekFrom::Start(offset)).map_err(io_cloud)?;
            write.file.write_all(data).map_err(io_cloud)?;
            write.dirty = true;
            let count = u32::try_from(data.len()).map_err(|_| {
                CloudError::new(ErrorKind::Unsupported, "write request is too large")
            })?;
            Ok((count, offset.saturating_add(u64::from(count))))
        });
        match result {
            Ok((count, size)) => {
                self.update_size_after_write(ino.0, size);
                reply.written(count);
            }
            Err(error) => reply.error(errno(&error)),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: fuser::LockOwner,
        reply: ReplyEmpty,
    ) {
        let handle = self.file_handle(fh.0);
        let vault = handle.as_ref().ok().and_then(|handle| {
            handle.lock().ok().and_then(|open| match &*open {
                OpenFile::VaultWrite(write) => Some((write.route.clone(), write.generation)),
                _ => None,
            })
        });
        if let (Ok(handle), Some((route, generation))) = (&handle, vault) {
            let handle = handle.clone();
            let mut reply = Some(reply);
            let outcome = route.with_read_lease(generation, |lease| {
                let result = self.commit_vault(&handle, lease, generation).map(|_| ());
                match result {
                    Ok(()) => reply.take().expect("FUSE reply is used once").ok(),
                    Err(error) => reply
                        .take()
                        .expect("FUSE reply is used once")
                        .error(errno(&error)),
                }
                Ok(())
            });
            if let Err(error) = outcome {
                if let Some(reply) = reply {
                    reply.error(errno(&error));
                }
            }
            return;
        }
        match handle.and_then(|handle| self.commit(&handle)) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(errno(&error)),
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let handle = self.file_handle(fh.0);
        let vault = handle.as_ref().ok().and_then(|handle| {
            handle.lock().ok().and_then(|open| match &*open {
                OpenFile::VaultWrite(write) => Some((write.route.clone(), write.generation)),
                _ => None,
            })
        });
        if let (Ok(handle), Some((route, generation))) = (&handle, vault) {
            let handle = handle.clone();
            let mut reply = Some(reply);
            let outcome = route.with_read_lease(generation, |lease| {
                let result = self.commit_vault(&handle, lease, generation).map(|_| ());
                match result {
                    Ok(()) => reply.take().expect("FUSE reply is used once").ok(),
                    Err(error) => reply
                        .take()
                        .expect("FUSE reply is used once")
                        .error(errno(&error)),
                }
                Ok(())
            });
            if let Err(error) = outcome {
                if let Some(reply) = reply {
                    reply.error(errno(&error));
                }
            }
            return;
        }
        match handle.and_then(|handle| self.commit(&handle)) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(errno(&error)),
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let handle = self.state.lock().ok().and_then(|mut state| {
            state.vault_file_handles.remove(&fh.0);
            state.file_handles.remove(&fh.0)
        });
        match handle {
            Some(handle)
                if matches!(handle.lock().ok().as_deref(), Some(OpenFile::VaultWrite(_))) =>
            {
                let info = handle
                    .lock()
                    .map_err(|_| io_error("open file state is unavailable"))
                    .and_then(|open| match &*open {
                        OpenFile::VaultWrite(write) => Ok((
                            write.route.clone(),
                            write.generation,
                            write.active_key.clone(),
                        )),
                        _ => Err(io_error("encrypted writer changed unexpectedly")),
                    });
                match info {
                    Ok((route, generation, active_key)) => {
                        let handle_for_lease = handle.clone();
                        drop(handle);
                        let result = route.with_read_lease(generation, move |lease| {
                            self.commit_vault(&handle_for_lease, lease, generation)?;
                            {
                                let mut open = handle_for_lease
                                    .lock()
                                    .map_err(|_| io_error("open file state is unavailable"))?;
                                let OpenFile::VaultWrite(write) = &mut *open else {
                                    return Err(io_error("encrypted writer changed unexpectedly"));
                                };
                                write.closing = true;
                            }
                            match Arc::try_unwrap(handle_for_lease) {
                                Ok(mutex) => {
                                    let open = mutex
                                        .into_inner()
                                        .map_err(|_| io_error("open file state is unavailable"))?;
                                    match open {
                                        OpenFile::VaultWrite(write) => write
                                            .working
                                            .retire_if_unchanged(generation)
                                            .map(|_| ())
                                            .map_err(vault_write_error),
                                        _ => Err(io_error("encrypted writer changed unexpectedly")),
                                    }
                                }
                                Err(_still_open) => Ok(()),
                            }
                        });
                        self.release_write_key(&active_key);
                        match result {
                            Ok(()) => reply.ok(),
                            Err(error) => reply.error(errno(&error)),
                        }
                    }
                    Err(error) => reply.error(errno(&error)),
                }
            }
            Some(handle)
                if matches!(handle.lock().ok().as_deref(), Some(OpenFile::Vault { .. })) =>
            {
                let token = handle
                    .lock()
                    .map_err(|_| io_error("open file state is unavailable"))
                    .and_then(|mut open| match &mut *open {
                        OpenFile::Vault {
                            route,
                            handle: vault_handle,
                            ..
                        } => vault_handle
                            .take()
                            .map(|token| (route.clone(), token))
                            .ok_or_else(|| io_error("vault file handle was already released")),
                        _ => Err(io_error("vault file handle changed unexpectedly")),
                    });
                let result = token.and_then(|(route, token)| match route.release_handle(&token) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind == ErrorKind::Unauthorized => Ok(()),
                    Err(error) => Err(error),
                });
                match result {
                    Ok(()) => reply.ok(),
                    Err(error) if error.kind == ErrorKind::Unauthorized => reply.ok(),
                    Err(error) => reply.error(errno(&error)),
                }
            }
            Some(handle) => match self.commit(&handle) {
                Ok(()) => {
                    let mut key = None;
                    if let Ok(open) = handle.lock() {
                        if let OpenFile::Write(write) = &*open {
                            if write.cleanup_on_release {
                                let _ = fs::remove_file(&write.manifest);
                                let _ = fs::remove_file(&write.spool);
                            }
                            key = Some(format!("{}\0{}", write.space, write.path));
                        }
                    }
                    if let Some(key) = key {
                        self.release_write_key(&key);
                    }
                    reply.ok()
                }
                Err(error) => {
                    if let Ok(open) = handle.lock() {
                        if let OpenFile::Write(write) = &*open {
                            self.release_write_key(&format!("{}\0{}", write.space, write.path));
                        }
                    }
                    reply.error(errno(&error))
                }
            },
            None => reply.error(Errno::EBADF),
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent_ino: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        if matches!(
            self.node(parent_ino.0),
            Ok(Node {
                kind: NodeKind::Vault { .. },
                ..
            })
        ) {
            let wait = (|| {
                let parent = self.node(parent_ino.0)?;
                let NodeKind::Vault {
                    route, generation, ..
                } = &parent.kind
                else {
                    return Err(invalid("vault directory changed"));
                };
                let name = name
                    .to_str()
                    .ok_or_else(|| invalid("directory name is not UTF-8"))?;
                let (_, path) = self.child_path(&parent, name)?;
                self.wait_for_vault_path(route, *generation, &path, Duration::from_secs(5))
            })();
            if let Err(error) = wait {
                reply.error(errno(&error));
                return;
            }
            let mut reply = Some(reply);
            let outcome = self.with_node_lease(parent_ino.0, |lease| {
                let result = (|| {
                    let name = name
                        .to_str()
                        .ok_or_else(|| invalid("directory name is not UTF-8"))?;
                    let parent = self.node(parent_ino.0)?;
                    let NodeKind::Vault {
                        route,
                        generation,
                        entry: parent_entry,
                    } = parent.kind.clone()
                    else {
                        return Err(invalid("vault directory changed"));
                    };
                    let lease = lease.ok_or_else(|| {
                        CloudError::new(ErrorKind::Unauthorized, "vault route is locked or stale")
                    })?;
                    if lease.generation() != generation
                        || (!lease.supports_writes() && !lease.supports_directory_creates())
                    {
                        return Err(CloudError::new(
                            ErrorKind::Forbidden,
                            "encrypted route does not permit directory creation",
                        ));
                    }
                    let current_parent = lease.stat(&parent_entry.path)?;
                    let parent_ref =
                        self.vault_parent_ref(parent_ino.0, generation, &current_parent, lease)?;
                    let pending_parent = matches!(parent_ref, VaultParentRef::PendingCreate { .. });
                    if current_parent.id != parent_entry.id
                        || !current_parent.directory
                        || (!current_parent.writable && !pending_parent)
                        || (pending_parent && !lease.supports_pending_parent_operations())
                    {
                        return Err(CloudError::new(
                            ErrorKind::Forbidden,
                            "encrypted directory is read-only or stale",
                        ));
                    }
                    let (_, path) = self.child_path(
                        &Node {
                            kind: NodeKind::Vault {
                                route: route.clone(),
                                generation,
                                entry: current_parent,
                            },
                            ..parent.clone()
                        },
                        name,
                    )?;
                    let _path_reservation =
                        self.reserve_vault_path(route.control.route_id(), &path)?;
                    let (entry, child_parent_ref) =
                        match lease.create_directory_under_parent(&path, &parent_ref)? {
                            VaultDirectoryCreateOutcome::Committed(entry) => {
                                if !entry.directory || entry.path != path || !entry.writable {
                                    return Err(CloudError::new(
                                        ErrorKind::InvalidResponse,
                                        "encrypted directory creation returned an invalid entry",
                                    ));
                                }
                                let child_ref =
                                    VaultParentRef::stable(entry.id.clone()).map_err(|_| {
                                        CloudError::new(
                                            ErrorKind::InvalidResponse,
                                            "encrypted directory returned an invalid identity",
                                        )
                                    })?;
                                (entry, child_ref)
                            }
                            VaultDirectoryCreateOutcome::Queued {
                                entry,
                                write_id,
                                revision,
                                ..
                            } => {
                                if !entry.directory
                                    || entry.path != path
                                    || entry.writable
                                    || !entry.id.starts_with("raiun-pending-directory:")
                                    || entry.etag.is_empty()
                                {
                                    return Err(CloudError::new(
                                        ErrorKind::InvalidResponse,
                                        "queued encrypted directory has invalid local identity",
                                    ));
                                }
                                let child_ref = VaultParentRef::pending_create(write_id, revision)
                                    .map_err(|_| {
                                        CloudError::new(
                                            ErrorKind::InvalidResponse,
                                            "queued encrypted directory reference is invalid",
                                        )
                                    })?;
                                (entry, child_ref)
                            }
                        };
                    let ino = self.add_node(
                        parent_ino.0,
                        name.to_owned(),
                        NodeKind::Vault {
                            route: route.clone(),
                            generation,
                            entry: entry.clone(),
                        },
                    )?;
                    if matches!(child_parent_ref, VaultParentRef::PendingCreate { .. }) {
                        self.remember_pending_parent_ref(ino, generation, child_parent_ref)?;
                    }
                    let node = self.node(ino)?;
                    Ok(node)
                })();
                match result {
                    Ok(node) => reply.take().expect("FUSE reply is used once").entry(
                        &Duration::ZERO,
                        &self.attr(&node),
                        Generation(0),
                    ),
                    Err(error) => reply
                        .take()
                        .expect("FUSE reply is used once")
                        .error(errno(&error)),
                }
                Ok(())
            });
            if let Err(error) = outcome {
                if let Some(reply) = reply {
                    reply.error(errno(&error));
                }
            }
            return;
        }
        let result = (|| {
            let name = name
                .to_str()
                .ok_or_else(|| invalid("directory name is not UTF-8"))?;
            let parent = self.node(parent_ino.0)?;
            let (space, path) = self.child_path(&parent, name)?;
            let _reservation = self.reserve_path(&space, &path)?;
            let engine = self.engine.clone();
            let operation_space = space.clone();
            let operation_path = path.clone();
            let entry = self
                .pool
                .call(move || engine.mkdir(&operation_space, &operation_path))??;
            self.add_node(
                parent_ino.0,
                name.to_owned(),
                NodeKind::Remote {
                    space,
                    entry: entry.clone(),
                },
            )?;
            Ok(entry)
        })();
        match result {
            Ok(entry) => {
                let node = self.child(
                    parent_ino.0,
                    entry.path.rsplit('/').next().unwrap_or_default(),
                );
                match node {
                    Ok(node) => reply.entry(&TTL, &self.attr(&node), Generation(0)),
                    Err(error) => reply.error(errno(&error)),
                }
            }
            Err(error) => reply.error(errno(&error)),
        }
    }

    fn unlink(&self, _req: &Request, parent_ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if matches!(
            self.node(parent_ino.0),
            Ok(Node {
                kind: NodeKind::Vault { .. },
                ..
            })
        ) {
            let result = (|| {
                let name = name
                    .to_str()
                    .ok_or_else(|| invalid("file name is not UTF-8"))?;
                let parent = self.node(parent_ino.0)?;
                let NodeKind::Vault {
                    route, generation, ..
                } = &parent.kind
                else {
                    return Err(invalid("encrypted parent directory changed"));
                };
                let (_, path) = self.child_path(&parent, name)?;
                for attempt in 0..2 {
                    self.wait_for_vault_path(route, *generation, &path, Duration::from_secs(5))?;
                    let result = self.with_node_lease(parent_ino.0, |lease| {
                        let lease = lease.ok_or_else(|| {
                            CloudError::new(
                                ErrorKind::Unauthorized,
                                "vault route is locked or stale",
                            )
                        })?;
                        self.delete_vault_child_with_lease(parent_ino.0, name, false, lease)
                    });
                    let raced_with_release = result.as_ref().is_err_and(|error| {
                        error.kind == ErrorKind::Conflict && error.message.contains("active writer")
                    });
                    if raced_with_release && attempt == 0 {
                        continue;
                    }
                    return result;
                }
                unreachable!("bounded retry loop always returns")
            })();
            match result {
                Ok(()) => reply.ok(),
                Err(error) => reply.error(errno(&error)),
            }
            return;
        }
        let result = self.delete_child(parent_ino.0, name, false);
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(errno(&error)),
        }
    }

    fn rmdir(&self, _req: &Request, parent_ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if matches!(
            self.node(parent_ino.0),
            Ok(Node {
                kind: NodeKind::Vault { .. },
                ..
            })
        ) {
            let result = (|| {
                let name = name
                    .to_str()
                    .ok_or_else(|| invalid("directory name is not UTF-8"))?;
                let parent = self.node(parent_ino.0)?;
                let NodeKind::Vault {
                    route, generation, ..
                } = &parent.kind
                else {
                    return Err(invalid("encrypted parent directory changed"));
                };
                let (_, path) = self.child_path(&parent, name)?;
                for attempt in 0..2 {
                    self.wait_for_vault_path(route, *generation, &path, Duration::from_secs(5))?;
                    let result = self.with_node_lease(parent_ino.0, |lease| {
                        let lease = lease.ok_or_else(|| {
                            CloudError::new(
                                ErrorKind::Unauthorized,
                                "vault route is locked or stale",
                            )
                        })?;
                        self.delete_vault_child_with_lease(parent_ino.0, name, true, lease)
                    });
                    let raced_with_release = result.as_ref().is_err_and(|error| {
                        error.kind == ErrorKind::Conflict && error.message.contains("active writer")
                    });
                    if raced_with_release && attempt == 0 {
                        continue;
                    }
                    return result;
                }
                unreachable!("bounded retry loop always returns")
            })();
            match result {
                Ok(()) => reply.ok(),
                Err(error) => reply.error(errno(&error)),
            }
            return;
        }
        let result = self.delete_child(parent_ino.0, name, true);
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(errno(&error)),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let source_parent_node = self.node(parent.0);
        let destination_parent_node = self.node(newparent.0);
        let source_parent_route =
            source_parent_node
                .as_ref()
                .ok()
                .and_then(|node| match &node.kind {
                    NodeKind::Vault {
                        route, generation, ..
                    } => Some((route.clone(), *generation)),
                    _ => None,
                });
        let destination_parent_route =
            destination_parent_node
                .as_ref()
                .ok()
                .and_then(|node| match &node.kind {
                    NodeKind::Vault {
                        route, generation, ..
                    } => Some((route.clone(), *generation)),
                    _ => None,
                });
        if source_parent_route.is_some() || destination_parent_route.is_some() {
            let same_route = matches!(
                (&source_parent_route, &destination_parent_route),
                (Some((source, source_generation)), Some((destination, destination_generation)))
                    if source.control.route_id() == destination.control.route_id()
                        && source_generation == destination_generation
            );
            if !same_route {
                // EXDEV invites clients such as mv to copy and then unlink
                // the source. Cross-vault moves need verified destination
                // completion before source deletion; that protocol is not
                // implemented, so refuse without suggesting a copy fallback.
                reply.error(Errno::EPERM);
                return;
            }
            if flags.bits() != 0 {
                reply.error(Errno::EOPNOTSUPP);
                return;
            }
            let source_name = match name.to_str() {
                Some(name) => name,
                None => {
                    reply.error(Errno::EINVAL);
                    return;
                }
            };
            let destination_name = match newname.to_str() {
                Some(name) => name,
                None => {
                    reply.error(Errno::EINVAL);
                    return;
                }
            };
            let result = (|| {
                let (route, _) = source_parent_route.as_ref().expect("same-route check");
                let source_parent = source_parent_node.as_ref().map_err(Clone::clone)?;
                let destination_parent = destination_parent_node.as_ref().map_err(Clone::clone)?;
                let (_, source_path) = self.child_path(source_parent, source_name)?;
                let (_, destination_path) =
                    self.child_path(destination_parent, destination_name)?;
                for attempt in 0..2 {
                    self.wait_for_vault_writers(
                        route.control.route_id(),
                        &source_path,
                        &destination_path,
                        Duration::from_secs(5),
                    )?;
                    let result = self.with_node_lease(parent.0, |lease| {
                        let lease = lease.ok_or_else(|| {
                            CloudError::new(
                                ErrorKind::Unauthorized,
                                "vault route is locked or stale",
                            )
                        })?;
                        self.rename_vault_with_lease(
                            parent.0,
                            source_name,
                            newparent.0,
                            destination_name,
                            lease,
                        )
                    });
                    let raced_with_release = result.as_ref().is_err_and(|error| {
                        error.kind == ErrorKind::Conflict
                            && (error.message.contains("active writer")
                                || error.message.contains("open writable descendant"))
                    });
                    if raced_with_release && attempt == 0 {
                        continue;
                    }
                    return result;
                }
                unreachable!("bounded retry loop always returns")
            })();
            match result {
                Ok(()) => reply.ok(),
                Err(error) => reply.error(errno(&error)),
            }
            return;
        }
        if let Ok(source) = self.child(parent.0, name.to_str().unwrap_or_default()) {
            if matches!(source.kind, NodeKind::Vault { .. }) {
                // An unlocked vault root is bound to its registered route.
                // Do not turn an unsupported root move into copy-and-delete.
                reply.error(Errno::EPERM);
                return;
            }
        }
        let result = (|| {
            if flags.bits() != 0 {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "rename flags are not supported",
                ));
            }
            let source_parent = self.node(parent.0)?;
            let destination_parent = self.node(newparent.0)?;
            let source_name = name
                .to_str()
                .ok_or_else(|| invalid("file name is not UTF-8"))?;
            let destination_name = newname
                .to_str()
                .ok_or_else(|| invalid("file name is not UTF-8"))?;
            let (source_space, source_path) = self.child_path(&source_parent, source_name)?;
            let (destination_space, destination_path) =
                self.child_path(&destination_parent, destination_name)?;
            let _reservations = self.reserve_ordinary_rename_paths(
                (&source_space, &source_path),
                (&destination_space, &destination_path),
                Duration::from_secs(5),
                || {},
            )?;
            // RELEASE may have refreshed the source ETag while we waited.
            let source = self.child(parent.0, source_name)?;
            let source_remote = match &source.kind {
                NodeKind::Remote { space, entry } => (space.clone(), entry.clone()),
                _ => return Err(invalid("synthetic folders cannot be renamed")),
            };
            // An ancestor can move while the condition variable releases
            // provider state. Never mutate paths different from those reserved.
            let current_source = self.child_path(&self.node(parent.0)?, source_name)?;
            let current_destination =
                self.child_path(&self.node(newparent.0)?, destination_name)?;
            if current_source != (source_space.clone(), source_path.clone())
                || current_destination != (destination_space.clone(), destination_path.clone())
                || source_remote.0 != source_space
                || source_remote.1.path != source_path
            {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "rename paths changed while waiting for release",
                ));
            }
            let (source_spool, source_manifest) =
                self.spool_paths(&source_remote.0, &source_remote.1.path);
            if source_spool.exists() && source_manifest.exists() {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "file has pending local data",
                ));
            }
            if source_remote.0 != destination_space {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "cross-Space move is not supported",
                ));
            }
            let destination_entry = {
                let engine = self.engine.clone();
                let space = destination_space.clone();
                let path = destination_path.clone();
                match self.pool.call(move || engine.stat(&space, &path))? {
                    Ok(entry) => Some(entry),
                    Err(error) if error.kind == ErrorKind::NotFound => None,
                    Err(error) => return Err(error),
                }
            };
            let space = source_remote.0.clone();
            let from = source_remote.1.path.clone();
            let etag = source_remote.1.etag.clone();
            let entry = if let Some(previous) = destination_entry {
                if previous.directory || previous.encrypted || !previous.writable {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "rename cannot replace a directory, encrypted item, or read-only item",
                    ));
                }
                let (previous_spool, previous_manifest) =
                    self.spool_paths(&destination_space, &destination_path);
                if previous_spool.exists() && previous_manifest.exists() {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "destination has pending local data",
                    ));
                }
                let (parent_path, _) = destination_path
                    .rsplit_once('/')
                    .ok_or_else(|| invalid("destination path is malformed"))?;
                let mut backup_path = String::new();
                let mut backup_reservation = None;
                for _ in 0..8 {
                    let id = MANIFEST_TEMP_ID.fetch_add(1, Ordering::Relaxed);
                    backup_path = format!("{parent_path}/.raiun-recovery-{id:016x}");
                    match self.reserve_path(&destination_space, &backup_path) {
                        Ok(reservation) => {
                            let engine = self.engine.clone();
                            let request_space = destination_space.clone();
                            let request_path = backup_path.clone();
                            match self
                                .pool
                                .call(move || engine.stat(&request_space, &request_path))?
                            {
                                Err(error) if error.kind == ErrorKind::NotFound => {
                                    backup_reservation = Some(reservation);
                                    break;
                                }
                                Ok(_) => drop(reservation),
                                Err(error) => return Err(error),
                            }
                        }
                        Err(error) if error.kind == ErrorKind::Conflict => continue,
                        Err(error) => return Err(error),
                    }
                }
                let Some(_backup_reservation) = backup_reservation else {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "could not reserve a recovery name for replacement",
                    ));
                };
                let engine = self.engine.clone();
                let request_space = destination_space.clone();
                let request_path = destination_path.clone();
                let backup_target = backup_path.clone();
                let backup = self.pool.call(move || {
                    engine.rename(
                        &request_space,
                        &request_path,
                        &backup_target,
                        &previous.etag,
                    )
                })??;
                let engine = self.engine.clone();
                let request_space = space.clone();
                let request_from = from.clone();
                let request_to = destination_path.clone();
                let replacement = self.pool.call(move || {
                    engine.rename(&request_space, &request_from, &request_to, &etag)
                })?;
                match replacement {
                    Ok(replacement) => {
                        let engine = self.engine.clone();
                        let request_space = destination_space.clone();
                        let request_path = backup_path;
                        let backup_etag = backup.etag;
                        let _ = self.pool.call(move || {
                            engine.delete(&request_space, &request_path, &backup_etag)
                        });
                        replacement
                    }
                    Err(error) => {
                        let engine = self.engine.clone();
                        let request_space = destination_space.clone();
                        let request_backup = backup_path.clone();
                        let request_destination = destination_path.clone();
                        match self.pool.call(move || {
                            engine.rename(
                                &request_space,
                                &request_backup,
                                &request_destination,
                                &backup.etag,
                            )
                        })? {
                            Ok(_) => return Err(error),
                            Err(restore_error) => {
                                return Err(CloudError::new(
                                    ErrorKind::Conflict,
                                    format!(
                                        "replacement failed and the prior file remains at {backup_path}: {restore_error}"
                                    ),
                                ));
                            }
                        }
                    }
                }
            } else {
                let engine = self.engine.clone();
                self.pool
                    .call(move || engine.rename(&space, &from, &destination_path, &etag))??
            };
            if let Ok(mut state) = self.state.lock() {
                state.children.remove(&(parent.0, source.name.clone()));
                if let Some(existing) = state
                    .children
                    .remove(&(newparent.0, destination_name.into()))
                {
                    state.nodes.remove(&existing);
                }
                state
                    .children
                    .insert((newparent.0, destination_name.into()), source.ino);
                state.nodes.insert(
                    source.ino,
                    Node {
                        ino: source.ino,
                        parent: newparent.0,
                        name: destination_name.into(),
                        kind: NodeKind::Remote {
                            space: destination_space,
                            entry,
                        },
                        metadata_expires_at: Instant::now() + TTL,
                    },
                );
            }
            Ok(())
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(errno(&error)),
        }
    }

    fn create(
        &self,
        _req: &Request,
        parent_ino: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        if matches!(
            self.node(parent_ino.0),
            Ok(Node {
                kind: NodeKind::Vault { .. },
                ..
            })
        ) {
            let wait = (|| {
                let parent = self.node(parent_ino.0)?;
                let NodeKind::Vault {
                    route, generation, ..
                } = &parent.kind
                else {
                    return Err(invalid("encrypted parent directory changed"));
                };
                let name = name
                    .to_str()
                    .ok_or_else(|| invalid("file name is not UTF-8"))?;
                let (_, path) = self.child_path(&parent, name)?;
                self.wait_for_vault_path(route, *generation, &path, Duration::from_secs(5))
            })();
            if let Err(error) = wait {
                reply.error(errno(&error));
                return;
            }
            let mut reply = Some(reply);
            let outcome = self.with_node_lease(parent_ino.0, |lease| {
                let result = (|| {
                    let name = name
                        .to_str()
                        .ok_or_else(|| invalid("file name is not UTF-8"))?;
                    let lease = lease.ok_or_else(|| {
                        CloudError::new(ErrorKind::Unauthorized, "vault route is locked or stale")
                    })?;
                    self.create_vault_file(parent_ino.0, name, flags, lease)
                })();
                match result {
                    Ok((node, fh)) => reply.take().expect("FUSE reply is used once").created(
                        &Duration::ZERO,
                        &self.attr(&node),
                        Generation(0),
                        FileHandle(fh),
                        FopenFlags::FOPEN_DIRECT_IO,
                    ),
                    Err(error) => reply
                        .take()
                        .expect("FUSE reply is used once")
                        .error(errno(&error)),
                }
                Ok(())
            });
            if let Err(error) = outcome {
                if let Some(reply) = reply {
                    reply.error(errno(&error));
                }
            }
            return;
        }
        let result = (|| {
            let name = name
                .to_str()
                .ok_or_else(|| invalid("file name is not UTF-8"))?;
            let parent = self.node(parent_ino.0)?;
            let (space, path) = self.child_path(&parent, name)?;
            let reservation = self.reserve_path(&space, &path)?;
            let engine = self.engine.clone();
            let check_space = space.clone();
            let check_path = path.clone();
            match self
                .pool
                .call(move || engine.stat(&check_space, &check_path))?
            {
                Ok(entry) => {
                    if flags & libc::O_EXCL != 0 {
                        return Err(CloudError::new(
                            ErrorKind::Conflict,
                            "destination already exists",
                        ));
                    }
                    // FUSE CREATE may be used for open(O_CREAT) even when the
                    // path already exists. Without O_EXCL, POSIX semantics
                    // require opening that file; open_node refreshes its
                    // metadata and preserves the current ETag write condition.
                    let ino = self.add_node(
                        parent_ino.0,
                        name.into(),
                        NodeKind::Remote {
                            space: space.clone(),
                            entry,
                        },
                    )?;
                    drop(reservation);
                    let fh = self.open_node(ino, flags)?;
                    return Ok((self.node(ino)?, fh, flags));
                }
                Err(error) if error.kind == ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            let entry = RemoteEntry {
                id: format!("pending:{}", stable_hash(&format!("{space}:{path}"))),
                path: path.clone(),
                directory: false,
                size: 0,
                etag: String::new(),
                modified_unix: 0,
                writable: true,
                encrypted: false,
            };
            let ino = self.add_node(
                parent_ino.0,
                name.into(),
                NodeKind::Remote {
                    space: space.clone(),
                    entry,
                },
            )?;
            let write = self.prepare_write(ino, &space, &path, None, true)?;
            let fh = self.register_handle(OpenFile::Write(Box::new(write)))?;
            let node = self.node(ino)?;
            reservation.disarm();
            Ok((node, fh, flags))
        })();
        match result {
            Ok((node, fh, _)) => reply.created(
                &TTL,
                &self.attr(&node),
                Generation(0),
                FileHandle(fh),
                FopenFlags::empty(),
            ),
            Err(error) => reply.error(errno(&error)),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        crtime: Option<SystemTime>,
        chgtime: Option<SystemTime>,
        bkuptime: Option<SystemTime>,
        flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let mut reply = Some(reply);
        let outcome = self.with_node_lease(ino.0, |lease| {
            let result = (|| {
                if mode.is_some()
                    || uid.is_some()
                    || gid.is_some()
                    || atime.is_some()
                    || mtime.is_some()
                    || ctime.is_some()
                    || crtime.is_some()
                    || chgtime.is_some()
                    || bkuptime.is_some()
                    || flags.is_some()
                {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "cloud metadata updates are not supported",
                    ));
                }
                if let Some(size) = size {
                    let fh = fh.ok_or_else(|| {
                        CloudError::new(
                            ErrorKind::Unsupported,
                            "truncate requires an open writable handle",
                        )
                    })?;
                    let handle = self.file_handle(fh.0)?;
                    let mut open = handle
                        .lock()
                        .map_err(|_| io_error("open file state is unavailable"))?;
                    let vault_lease = lease;
                    let updated_size = match &mut *open {
                        OpenFile::Write(write) => {
                            write.file.set_len(size).map_err(io_cloud)?;
                            write.dirty = true;
                            size
                        }
                        OpenFile::VaultWrite(write) => {
                            let lease = vault_lease.ok_or_else(|| {
                                CloudError::new(
                                    ErrorKind::Unauthorized,
                                    "encrypted route is locked or stale",
                                )
                            })?;
                            if write.ino != ino.0 || lease.generation() != write.generation {
                                return Err(CloudError::new(
                                    ErrorKind::Unauthorized,
                                    "encrypted file handle is stale",
                                ));
                            }
                            if write.closing || write.flags & libc::O_ACCMODE == libc::O_RDONLY {
                                return Err(CloudError::new(
                                    ErrorKind::Forbidden,
                                    "file handle does not permit encrypted truncation",
                                ));
                            }
                            write
                                .working
                                .truncate(size, write.generation)
                                .map_err(vault_write_error)?;
                            write.dirty = true;
                            write
                                .working
                                .len(write.generation)
                                .map_err(vault_write_error)?
                        }
                        _ => {
                            return Err(CloudError::new(
                                ErrorKind::Forbidden,
                                "file was not opened for writing",
                            ));
                        }
                    };
                    drop(open);
                    if matches!(self.node(ino.0)?.kind, NodeKind::Vault { .. }) {
                        self.update_vault_size(ino.0, updated_size);
                    } else {
                        self.update_size(ino.0, updated_size);
                    }
                }
                self.node(ino.0)
            })();
            match result {
                Ok(node) => {
                    let ttl = if matches!(node.kind, NodeKind::Vault { .. }) {
                        &Duration::ZERO
                    } else {
                        &TTL
                    };
                    reply
                        .take()
                        .expect("FUSE reply is used once")
                        .attr(ttl, &self.attr(&node));
                }
                Err(error) => reply
                    .take()
                    .expect("FUSE reply is used once")
                    .error(errno(&error)),
            }
            Ok(())
        });
        if let Err(error) = outcome {
            if let Some(reply) = reply {
                reply.error(errno(&error));
            }
        }
    }
}

impl RaiunFilesystem {
    fn locked_readme_contents(&self, parent_ino: u64) -> Vec<u8> {
        let mut contents = LOCKED_VAULT_README.as_bytes().to_vec();
        let Ok(parent) = self.node(parent_ino) else {
            return contents;
        };
        let NodeKind::LockedVault {
            profile_id,
            space,
            resource_id: Some(resource_id),
            remote_path,
        } = parent.kind
        else {
            return contents;
        };
        if !safe_unlock_hint(&profile_id)
            || !safe_unlock_hint(&space)
            || !safe_unlock_hint(&resource_id)
        {
            return contents;
        }
        let registered = self
            .vault_registry
            .get(&space, &remote_path, &resource_id)
            .ok()
            .flatten()
            .is_some();
        if !registered {
            return contents;
        }
        let uri = format!(
            "raiun://unlock?v=1&profile_id={}&space_id={}&root_resource_id={}",
            encode_uri_component(&profile_id),
            encode_uri_component(&space),
            encode_uri_component(&resource_id),
        );
        contents.extend_from_slice(b"\nOpen this location in Raiun:\n");
        contents.extend_from_slice(uri.as_bytes());
        contents.push(b'\n');
        contents
    }

    fn open_node(&self, ino: u64, flags: i32) -> Result<u64, CloudError> {
        let initial_node = self.node(ino)?;
        if flags & libc::O_ACCMODE != libc::O_RDONLY
            || flags & (libc::O_TRUNC | libc::O_APPEND | libc::O_CREAT | libc::O_EXCL) != 0
        {
            self.reject_recovery_alias(initial_node.parent, &initial_node.name)?;
        }
        if let NodeKind::Recovery(ref view) = initial_node.kind {
            return self.open_recovery_node(view, flags);
        }
        if let NodeKind::LockedReadme { parent } = initial_node.kind {
            if flags & libc::O_ACCMODE != libc::O_RDONLY
                || flags & (libc::O_TRUNC | libc::O_APPEND | libc::O_CREAT | libc::O_EXCL) != 0
            {
                return Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "locked-location notice is read-only",
                ));
            }
            return self.register_handle(OpenFile::Read(ReadHandle::Static(Cursor::new(
                self.locked_readme_contents(parent),
            ))));
        }
        if matches!(initial_node.kind, NodeKind::LockedVault { .. }) {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "locked encrypted location is a directory",
            ));
        }
        let writing = flags & libc::O_ACCMODE != libc::O_RDONLY;
        let reservation = if writing {
            match &initial_node.kind {
                NodeKind::Remote { space, entry } => Some(self.reserve_path(space, &entry.path)?),
                _ => None,
            }
        } else {
            None
        };
        let node = self.refresh_remote_node(ino)?;
        let NodeKind::Remote { space, entry } = node.kind else {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "synthetic folders cannot be opened as files",
            ));
        };
        if entry.directory || entry.encrypted {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "directory or encrypted item cannot be opened as a file",
            ));
        }
        if writing {
            if !entry.writable {
                return Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "cloud item is read-only",
                ));
            }
            let write = self.prepare_write(
                ino,
                &space,
                &entry.path,
                (!entry.etag.is_empty()).then_some(&entry),
                flags & libc::O_TRUNC != 0,
            )?;
            let handle = self.register_handle(OpenFile::Write(Box::new(write)))?;
            if let Some(reservation) = reservation {
                reservation.disarm();
            }
            Ok(handle)
        } else {
            let (spool, manifest) = self.spool_paths(&space, &entry.path);
            let read_handle = if spool.exists() && manifest.exists() {
                ReadHandle::Local(File::open(spool).map_err(io_cloud)?)
            } else {
                let engine = self.engine.clone();
                let fetch_space = space.clone();
                let path = entry.path.clone();
                ReadHandle::Snapshot(
                    self.pool
                        .call(move || engine.fetch_snapshot(&fetch_space, &path))??,
                )
            };
            self.register_handle(OpenFile::Read(read_handle))
        }
    }

    fn child(&self, parent: u64, name: &str) -> Result<Node, CloudError> {
        let ino = self
            .state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?
            .children
            .get(&(parent, name.into()))
            .copied();
        if let Some(ino) = ino {
            return self.node(ino);
        }
        self.children(parent)?
            .into_iter()
            .find(|child| child.name == name)
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "cloud item was not found"))
    }

    fn delete_child(
        &self,
        parent_ino: u64,
        name: &OsStr,
        directory: bool,
    ) -> Result<(), CloudError> {
        let name = name
            .to_str()
            .ok_or_else(|| invalid("file name is not UTF-8"))?;
        self.reject_recovery_alias(parent_ino, name)?;
        let node = self.child(parent_ino, name)?;
        let NodeKind::Remote { space, entry } = node.kind else {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "synthetic folders cannot be deleted",
            ));
        };
        if directory != entry.directory {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "file and directory operation do not match",
            ));
        }
        if entry.encrypted || !entry.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "cloud item is read-only or encrypted",
            ));
        }
        let _reservation = self.reserve_path(&space, &entry.path)?;
        let (spool, manifest) = self.spool_paths(&space, &entry.path);
        if spool.exists() && manifest.exists() {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "file has pending local data",
            ));
        }
        if directory && !self.children(node.ino)?.is_empty() {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "directory is not empty",
            ));
        }
        let engine = self.engine.clone();
        let path = entry.path;
        let etag = entry.etag;
        self.pool
            .call(move || engine.delete(&space, &path, &etag))??;
        if let Ok(mut state) = self.state.lock() {
            state.children.remove(&(parent_ino, name.to_owned()));
            state.nodes.remove(&node.ino);
        }
        Ok(())
    }

    fn rename_vault_with_lease(
        &self,
        source_parent_ino: u64,
        source_name: &str,
        destination_parent_ino: u64,
        destination_name: &str,
        lease: &VaultRouteLease<'_>,
    ) -> Result<(), CloudError> {
        let source_parent = self.node(source_parent_ino)?;
        let destination_parent = self.node(destination_parent_ino)?;
        let (
            NodeKind::Vault {
                route: source_route,
                generation: source_generation,
                entry: source_parent_entry,
            },
            NodeKind::Vault {
                route: destination_route,
                generation: destination_generation,
                entry: destination_parent_entry,
            },
        ) = (&source_parent.kind, &destination_parent.kind)
        else {
            return Err(invalid("encrypted rename requires vault directories"));
        };
        if source_route.control.route_id() != destination_route.control.route_id()
            || source_generation != destination_generation
            || lease.generation() != *source_generation
            || (!lease.supports_writes()
                && !lease.supports_file_renames()
                && !lease.supports_pending_create_renames()
                && !lease.supports_pending_directory_renames())
        {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cross-route encrypted rename is not supported",
            ));
        }
        let (_, source_path) = self.child_path(&source_parent, source_name)?;
        let (_, destination_path) = self.child_path(&destination_parent, destination_name)?;
        if source_path == "/" || destination_path == "/" {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault root cannot be renamed",
            ));
        }
        if destination_path.starts_with(&format!("{}/", source_path.trim_end_matches('/'))) {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "encrypted directory cannot be moved inside itself",
            ));
        }
        if source_parent_ino == destination_parent_ino && source_name == destination_name {
            return Ok(());
        }
        let source_node =
            self.lookup_child_with_lease(source_parent_ino, source_name, Some(lease))?;
        let NodeKind::Vault {
            entry: expected_source,
            ..
        } = &source_node.kind
        else {
            return Err(invalid("encrypted rename source changed"));
        };
        let allow_read_only_source_handle = !expected_source.directory
            && !expected_source.id.starts_with("raiun-pending-")
            && (lease.supports_writes() || lease.supports_file_renames());
        let _rename_reservations = self.reserve_vault_rename_paths(
            source_route.control.route_id(),
            &source_path,
            &destination_path,
            allow_read_only_source_handle,
        )?;
        (|| {
            let current_source_parent = lease.stat(&source_parent_entry.path)?;
            let current_destination_parent = lease.stat(&destination_parent_entry.path)?;
            let current_source_parent_ref = lease.parent_ref_for_directory(
                &source_parent_entry.path,
                &current_source_parent.id,
                &current_source_parent.etag,
            )?;
            let current_destination_parent_ref = lease.parent_ref_for_directory(
                &destination_parent_entry.path,
                &current_destination_parent.id,
                &current_destination_parent.etag,
            )?;
            let pending_parent_writable = |entry: &RemoteEntry, parent_ref: &VaultParentRef| {
                entry.writable
                    || (matches!(parent_ref, VaultParentRef::PendingCreate { .. })
                        && lease.supports_pending_parent_operations())
            };
            let source = lease.stat(&source_path)?;
            if current_source_parent.id != source_parent_entry.id
                || current_destination_parent.id != destination_parent_entry.id
                || !current_source_parent.directory
                || !current_destination_parent.directory
                || !pending_parent_writable(&current_source_parent, &current_source_parent_ref)
                || !pending_parent_writable(
                    &current_destination_parent,
                    &current_destination_parent_ref,
                )
                || source.id != expected_source.id
                || source.directory != expected_source.directory
                || (!source.writable
                    && !(source.directory
                        && source.id.starts_with("raiun-pending-directory:")
                        && lease.supports_pending_directory_renames()))
                || source.etag.is_empty()
            {
                return Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "encrypted source or parent is read-only, stale, or unsupported",
                ));
            }
            let previous = match lease.stat(&destination_path) {
                Ok(entry) => Some(entry),
                Err(error) if error.kind == ErrorKind::NotFound => None,
                Err(error) => return Err(error),
            };
            let moved = if source.id.starts_with("raiun-pending-directory:") {
                if !source.directory || previous.is_some() {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "queued directory cannot replace or move a non-directory",
                    ));
                }
                if !lease.supports_pending_directory_renames() {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "this encrypted route cannot rename a queued directory",
                    ));
                }
                let (write_id, revision) =
                    pending_directory_identity(&source).ok_or_else(|| {
                        CloudError::new(
                            ErrorKind::Conflict,
                            "queued directory identity is stale or malformed",
                        )
                    })?;
                if source.etag != expected_source.etag {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "queued directory revision changed before rename",
                    ));
                }
                let listed_children = lease.list(&source_path)?;
                let has_materialized_children = !self.children(source_node.ino)?.is_empty();
                if has_materialized_children && listed_children.is_empty() {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "queued directory view changed before retarget",
                    ));
                }
                if listed_children.is_empty() {
                    let outcome = lease.rename_pending_directory_create(
                        &source_path,
                        &destination_path,
                        &source.id,
                        &source.etag,
                        &current_destination_parent_ref,
                    )?;
                    if outcome.write_id != write_id
                        || outcome.previous_revision != revision
                        || outcome.revision != revision + 1
                        || outcome.entry.id != source.id
                        || outcome.entry.path != destination_path
                        || !outcome.entry.directory
                        || outcome.entry.etag
                            != format!("raiun-pending-v1:{write_id}:{}", outcome.revision)
                        || outcome.parent_ref != current_destination_parent_ref
                    {
                        return Err(CloudError::new(
                            ErrorKind::Conflict,
                            "retargeted queued directory does not match its source",
                        ));
                    }
                    outcome.entry
                } else {
                    if !lease.supports_pending_directory_subtree_renames() {
                        return Err(CloudError::new(
                            ErrorKind::Unsupported,
                            "this encrypted route cannot retarget a populated queued directory",
                        ));
                    }
                    let spool = self.vault_write_spool.as_ref().ok_or_else(|| {
                        CloudError::new(
                            ErrorKind::Conflict,
                            "queued subtree local recovery store is unavailable",
                        )
                    })?;
                    let mut wal = None;
                    let mut before_publish =
                        |candidate: &VaultPendingDirectorySubtreeRenameOutcome| {
                            self.vault_subtree_recovery
                                .lock()
                                .map_err(|_| {
                                    io_error("encrypted subtree recovery state is unavailable")
                                })?
                                .remove(&(source_route.control.route_id(), *source_generation));
                            let prepared = persist_subtree_retarget_wal(
                                spool,
                                candidate,
                                &source_path,
                                &destination_path,
                            )?;
                            wal = Some(prepared);
                            Ok(())
                        };
                    let outcome = lease.rename_pending_directory_subtree(
                        &source_path,
                        &destination_path,
                        &source.id,
                        &source.etag,
                        &current_destination_parent_ref,
                        &mut before_publish,
                    )?;
                    drop(before_publish);
                    let wal = wal.ok_or_else(|| {
                        CloudError::new(
                            ErrorKind::Conflict,
                            "queued subtree backend omitted its precommit proof",
                        )
                    })?;
                    if outcome.root_write_id != write_id
                        || outcome.root_previous_revision != revision
                        || outcome.root_revision != revision + 1
                        || outcome.root_entry.id != source.id
                        || outcome.root_entry.path != destination_path
                        || outcome.root_entry.etag
                            != format!("raiun-pending-v1:{write_id}:{}", outcome.root_revision)
                    {
                        return Err(CloudError::new(
                            ErrorKind::Conflict,
                            "retargeted queued subtree root changed",
                        ));
                    }
                    spool
                        .apply_directory_subtree_retarget(&wal, *source_generation)
                        .map_err(vault_write_error)?;
                    spool
                        .finish_directory_subtree_retarget(&wal)
                        .map_err(vault_write_error)?;
                    outcome.root_entry
                }
            } else if source.id.starts_with("raiun-pending-create:") {
                if source.directory || previous.is_some() || !source.writable {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "pending encrypted create cannot replace or move a directory",
                    ));
                }
                if !lease.supports_pending_create_renames() {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "this encrypted route cannot rename a pending file create",
                    ));
                }
                let write_id = source
                    .id
                    .strip_prefix("raiun-pending-create:")
                    .ok_or_else(|| invalid("pending encrypted create ID is invalid"))?;
                let revision = source
                    .etag
                    .strip_prefix("raiun-pending-v1:")
                    .and_then(|value| value.strip_prefix(&format!("{write_id}:")))
                    .and_then(|value| value.parse::<u64>().ok())
                    .filter(|revision| *revision > 0)
                    .ok_or_else(|| {
                        CloudError::new(
                            ErrorKind::Conflict,
                            "pending encrypted create version is stale",
                        )
                    })?;
                let mut working = self.recover_never_attempted_create_for_rename(
                    source_route,
                    *source_generation,
                    write_id,
                    revision,
                )?;
                let destination_parent_ref = current_destination_parent_ref;
                let (marker_scope, marker_target) = lease.prepare_file_create_under_parent(
                    &destination_path,
                    &destination_parent_ref,
                    None,
                )?;
                if marker_scope != *working.binding().scope()
                    || !matches!(marker_target.condition(), WriteCondition::Absent)
                {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "pending create destination binding changed",
                    ));
                }
                working
                    .begin_never_attempted_create_retarget(
                        *source_generation,
                        write_id,
                        revision,
                        &destination_path,
                        marker_target,
                    )
                    .map_err(vault_write_error)?;
                if matches!(destination_parent_ref, VaultParentRef::PendingCreate { .. })
                    && !lease.supports_pending_parent_operations()
                {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "encrypted route cannot retarget into an uncommitted parent",
                    ));
                }
                let outcome = lease.rename_pending_create(
                    &source_path,
                    &destination_path,
                    &source.id,
                    &source.etag,
                    &destination_parent_ref,
                )?;
                if outcome.write_id != write_id
                    || outcome.previous_revision != revision
                    || outcome.revision <= revision
                    || outcome.entry.id != source.id
                    || outcome.entry.path != destination_path
                    || outcome.entry.directory
                    || !outcome.entry.writable
                    || outcome.entry.etag
                        != format!("raiun-pending-v1:{write_id}:{}", outcome.revision)
                    || outcome.scope != *working.binding().scope()
                    || outcome.target.parent_ref() != Some(&destination_parent_ref)
                    || !matches!(outcome.target.condition(), WriteCondition::Absent)
                {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "retargeted encrypted create does not match its recovery copy",
                    ));
                }
                let (verified_bytes, verified_sha256) = match working.lifecycle() {
                    VaultWriteLifecycle::RetargetingCreate { bytes, sha256, .. } => {
                        (*bytes, sha256.clone())
                    }
                    _ => {
                        return Err(CloudError::new(
                            ErrorKind::Conflict,
                            "pending create retarget marker was lost",
                        ));
                    }
                };
                working
                    .finish_verified_create_retarget(
                        *source_generation,
                        write_id,
                        revision,
                        outcome.revision,
                        outcome.target,
                        crate::vault_write::VerifiedCreateContent {
                            bytes: verified_bytes,
                            sha256: verified_sha256,
                        },
                    )
                    .map_err(vault_write_error)?;
                outcome.entry
            } else if !lease.supports_writes() {
                if source.directory {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "offline encrypted rename supports regular files only",
                    ));
                }
                if previous.is_some() {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "offline encrypted rename destination already exists",
                    ));
                }
                let outcome =
                    lease.rename_file(&source_path, &destination_path, &source.id, &source.etag)?;
                let entry = match outcome {
                    crate::vault_routes::VaultRenameOutcome::Committed(entry)
                    | crate::vault_routes::VaultRenameOutcome::Queued { entry, .. } => entry,
                };
                if entry.path != destination_path
                    || entry.directory
                    || entry.etag.is_empty()
                    || (entry.id != source.id && !entry.id.starts_with("raiun-pending-rename:"))
                {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "queued encrypted rename projection does not match its source",
                    ));
                }
                entry
            } else {
                let target_condition = previous
                    .as_ref()
                    .map(|entry| WriteCondition::Match(entry.etag.clone()))
                    .unwrap_or(WriteCondition::Absent);
                let (scope, target) =
                    lease.prepare_target(&destination_path, target_condition.clone())?;
                if scope.space_id() != source_route.space_id()
                    || scope.root_resource_id() != source_route.root_resource_id()
                    || target.condition() != &target_condition
                {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "encrypted rename target does not match its mounted route",
                    ));
                }
                if let Some(previous) = previous {
                    if source.directory
                        || previous.directory
                        || !previous.writable
                        || previous.etag.is_empty()
                    {
                        return Err(CloudError::new(
                            ErrorKind::Unsupported,
                            "encrypted rename cannot replace a directory or read-only item",
                        ));
                    }
                    let (parent_path, _) = destination_path
                        .rsplit_once('/')
                        .ok_or_else(|| invalid("encrypted destination path is malformed"))?;
                    let mut backup = None;
                    for _ in 0..8 {
                        let id = MANIFEST_TEMP_ID.fetch_add(1, Ordering::Relaxed);
                        let candidate = format!("{parent_path}/.raiun-recovery-{id:016x}");
                        let (backup_scope, _) =
                            lease.prepare_target(&candidate, WriteCondition::Absent)?;
                        if backup_scope.space_id() != source_route.space_id()
                            || backup_scope.root_resource_id() != source_route.root_resource_id()
                        {
                            return Err(CloudError::new(
                                ErrorKind::Conflict,
                                "encrypted recovery target does not match its mounted route",
                            ));
                        }
                        match lease.stat(&candidate) {
                            Err(error) if error.kind == ErrorKind::NotFound => {
                                let moved_backup =
                                    lease.rename(&destination_path, &candidate, &previous.etag)?;
                                if moved_backup.path != candidate
                                    || moved_backup.directory
                                    || moved_backup.etag.is_empty()
                                {
                                    return Err(CloudError::new(
                                        ErrorKind::InvalidResponse,
                                        "encrypted replacement backup could not be verified",
                                    ));
                                }
                                backup = Some((candidate, moved_backup));
                                break;
                            }
                            Ok(_) => continue,
                            Err(error) => return Err(error),
                        }
                    }
                    let Some((backup_path, backup_entry)) = backup else {
                        return Err(CloudError::new(
                            ErrorKind::Conflict,
                            "could not reserve an encrypted replacement recovery name",
                        ));
                    };
                    match lease.rename(&source_path, &destination_path, &source.etag) {
                        Ok(entry)
                            if entry.path == destination_path
                                && !entry.directory
                                && entry.id == source.id
                                && !entry.etag.is_empty() =>
                        {
                            // Removing the exact backup is part of the requested
                            // successful replacement. If that cleanup is refused,
                            // keep the old copy under its recovery name.
                            let _ = lease.delete(&backup_path, &backup_entry.etag);
                            entry
                        }
                        Ok(_) => {
                            return Err(CloudError::new(
                                ErrorKind::Conflict,
                                "encrypted replacement result could not be verified; recovery copy retained",
                            ));
                        }
                        Err(move_error) => match lease.stat(&destination_path) {
                            Err(error) if error.kind == ErrorKind::NotFound => {
                                match lease.rename(
                                    &backup_path,
                                    &destination_path,
                                    &backup_entry.etag,
                                ) {
                                    Ok(restored) if restored.path == destination_path => {
                                        return Err(move_error);
                                    }
                                    _ => {
                                        return Err(CloudError::new(
                                            ErrorKind::Conflict,
                                            "encrypted replacement failed; recovery copy was retained",
                                        ));
                                    }
                                }
                            }
                            _ => {
                                return Err(CloudError::new(
                                    ErrorKind::Conflict,
                                    "encrypted replacement result is uncertain; recovery copy retained",
                                ));
                            }
                        },
                    }
                } else {
                    let entry = lease.rename(&source_path, &destination_path, &source.etag)?;
                    if entry.path != destination_path
                        || entry.directory != source.directory
                        || entry.id != source.id
                        || entry.etag.is_empty()
                    {
                        return Err(CloudError::new(
                            ErrorKind::InvalidResponse,
                            "encrypted rename returned an invalid file version",
                        ));
                    }
                    entry
                }
            };
            let moved_pending_parent_ref = if moved.directory {
                pending_directory_identity(&moved)
                    .map(|(write_id, revision)| VaultParentRef::pending_create(write_id, revision))
                    .transpose()
                    .map_err(|_| invalid("retargeted directory reference is invalid"))?
            } else {
                None
            };
            let moved_is_directory = moved.directory;
            if let Ok(mut state) = self.state.lock() {
                if moved.directory {
                    let mut descendants = std::collections::HashSet::new();
                    let mut pending = vec![source_node.ino];
                    while let Some(parent) = pending.pop() {
                        for ((candidate_parent, _), child_ino) in &state.children {
                            if *candidate_parent == parent && descendants.insert(*child_ino) {
                                pending.push(*child_ino);
                            }
                        }
                    }
                    descendants.remove(&source_node.ino);
                    state.children.retain(|(parent, _), child| {
                        !descendants.contains(parent) && !descendants.contains(child)
                    });
                    for ino in descendants {
                        state.nodes.remove(&ino);
                    }
                    let route_id = source_route.control.route_id();
                    state.directory_handles.retain(|_, handle| {
                        !handle
                            .routes
                            .iter()
                            .any(|(route, _)| route.route_id() == route_id)
                    });
                }
                state
                    .children
                    .remove(&(source_parent_ino, source_name.to_owned()));
                if let Some(previous_ino) = state
                    .children
                    .remove(&(destination_parent_ino, destination_name.to_owned()))
                {
                    state.nodes.remove(&previous_ino);
                }
                state.children.insert(
                    (destination_parent_ino, destination_name.to_owned()),
                    source_node.ino,
                );
                if let Some(node) = state.nodes.get_mut(&source_node.ino) {
                    node.parent = destination_parent_ino;
                    node.name = destination_name.to_owned();
                    node.kind = NodeKind::Vault {
                        route: source_route.clone(),
                        generation: *source_generation,
                        entry: moved,
                    };
                    node.metadata_expires_at = Instant::now();
                }
                if let Some(reference) = moved_pending_parent_ref {
                    state
                        .pending_parent_refs
                        .insert(source_node.ino, (*source_generation, reference));
                } else if moved_is_directory {
                    state.pending_parent_refs.remove(&source_node.ino);
                }
                state.directory_handles.retain(|_, handle| {
                    !handle
                        .routes
                        .iter()
                        .any(|(route, _)| route.route_id() == source_route.control.route_id())
                });
            }
            Ok(())
        })()
    }

    fn cancel_pending_file_create_with_lease(
        &self,
        child: &Node,
        route: &VaultMountRoute,
        generation: u64,
        lease: &VaultRouteLease<'_>,
    ) -> Result<(), CloudError> {
        let NodeKind::Vault { entry, .. } = &child.kind else {
            return Err(CloudError::new(
                ErrorKind::NotFound,
                "encrypted file was not found",
            ));
        };
        let (write_id, revision) = pending_file_create_identity(entry).ok_or_else(|| {
            CloudError::new(
                ErrorKind::Forbidden,
                "only an exact never-attempted encrypted file create can be cancelled",
            )
        })?;
        let spool = self.vault_write_spool.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Forbidden, "encrypted write spool is unavailable")
        })?;
        let _reservation = self.reserve_pending_file_create_cancel(
            route.control.route_id(),
            &entry.path,
            child.ino,
        )?;

        let cancellations = spool
            .list_create_cancellations()
            .map_err(vault_write_error)?;
        if let Some(cancellation) = cancellations.into_iter().find(|cancellation| {
            cancellation.scope.space_id() == route.space_id()
                && cancellation.scope.root_resource_id() == route.root_resource_id()
                && cancellation.path == entry.path
                && cancellation.write_id == write_id
                && cancellation.revision == revision
        }) {
            if !self.complete_pending_create_cancellation(
                route,
                generation,
                lease,
                spool,
                cancellation,
            )? {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "queued file cancellation remains unresolved; local bytes are retained",
                ));
            }
            return Ok(());
        }

        let (records, truncated) = spool.list_pending().map_err(vault_write_error)?;
        if truncated {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "queued file cancellation could not verify the complete local spool index",
            ));
        }
        let expected_write_id = write_id.clone();
        let expected_revision = revision;
        let mut matching = records.into_iter().filter(|record| {
            record.scope.as_ref().is_some_and(|scope| {
                scope.space_id() == route.space_id()
                    && scope.root_resource_id() == route.root_resource_id()
            }) && matches!(
                record.lifecycle,
                Some(VaultWriteLifecycle::Queued {
                    ref write_id,
                    revision: current_revision,
                    uncertain: false,
                    ..
                }) if write_id == &expected_write_id && current_revision == expected_revision
            )
        });
        let record = matching.next().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Conflict,
                "exact never-attempted local file body is unavailable",
            )
        })?;
        if matching.next().is_some() {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "multiple local records match the queued file operation",
            ));
        }
        let scope = record.scope.ok_or_else(|| {
            CloudError::new(ErrorKind::Conflict, "queued file scope is unavailable")
        })?;
        let target = record.target.ok_or_else(|| {
            CloudError::new(ErrorKind::Conflict, "queued file target is unavailable")
        })?;
        if !matches!(target.condition(), WriteCondition::Absent) || target.parent_ref().is_none() {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "queued file is not a new file under a verified parent",
            ));
        }
        let binding = VaultWriteBinding::new(scope.clone(), target.clone(), generation)
            .map_err(vault_write_error)?;
        let mut working = spool
            .recover(&record.record_id, binding, generation)
            .map_err(vault_write_error)?;
        let verified = working
            .begin_never_attempted_create_cancel(generation, &write_id, revision, &entry.path)
            .map_err(vault_write_error)?;
        let cancellation = PendingVaultCreateCancellation {
            record_id: record.record_id,
            scope,
            target,
            path: entry.path.clone(),
            write_id: write_id.clone(),
            revision,
            bytes: verified.bytes,
            sha256: verified.sha256,
            local_retired: false,
        };
        drop(working);
        if !self.complete_pending_create_cancellation(
            route,
            generation,
            lease,
            spool,
            cancellation,
        )? {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "queued file cancellation remains unresolved; local bytes are retained",
            ));
        }
        Ok(())
    }

    fn delete_vault_child_with_lease(
        &self,
        parent_ino: u64,
        name: &str,
        directory: bool,
        lease: &VaultRouteLease<'_>,
    ) -> Result<(), CloudError> {
        let parent = self.node(parent_ino)?;
        let NodeKind::Vault {
            route,
            generation,
            entry: parent_entry,
        } = parent.kind
        else {
            return Err(invalid("encrypted parent directory changed"));
        };
        if lease.generation() != generation
            || (!lease.supports_writes()
                && !directory
                && !lease.supports_file_deletes()
                && !lease.supports_cancel_file_create())
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "encrypted route is read-only, stale, or does not permit this deletion",
            ));
        }
        let child = self.lookup_child_with_lease(parent_ino, name, Some(lease))?;
        let NodeKind::Vault {
            route: child_route,
            generation: child_generation,
            entry,
        } = child.kind.clone()
        else {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "ordinary cloud items cannot be removed through an encrypted route",
            ));
        };
        if child_route.control.route_id() != route.control.route_id()
            || child_generation != generation
            || entry.path == "/"
            || directory != entry.directory
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "encrypted item cannot be removed from this route",
            ));
        }
        // A queued directory can be removed only by atomically cancelling its
        // exact never-attempted journal generation. This path never calls
        // WebDAV DELETE: ordinary, uncertain, committed, and legacy Pending
        // directories remain unsupported below.
        if directory && lease.supports_cancel_directory_create() {
            let Some((write_id, revision)) = pending_directory_identity(&entry) else {
                return Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "only an exact never-attempted encrypted directory can be cancelled",
                ));
            };
            let _reservation =
                self.reserve_pending_directory_cancel(route.control.route_id(), &entry.path)?;
            let has_materialized_children = self
                .state
                .lock()
                .map_err(|_| io_error("provider state is unavailable"))?
                .children
                .keys()
                .any(|(parent, _)| *parent == child.ino);
            if has_materialized_children {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "queued directory has dependent children",
                ));
            }
            lease.cancel_never_attempted_directory_create(
                &entry.path,
                &write_id,
                revision,
                &entry.id,
                &entry.etag,
            )?;
            let mut state = self
                .state
                .lock()
                .map_err(|_| io_error("provider state is unavailable"))?;
            state.children.remove(&(parent_ino, name.to_owned()));
            state.nodes.remove(&child.ino);
            state.pending_parent_refs.remove(&child.ino);
            state
                .directory_handles
                .retain(|_, handle| !handle.entries.iter().any(|(_, ino, _)| *ino == child.ino));
            return Ok(());
        }
        if !directory && pending_file_create_identity(&entry).is_some() {
            if !lease.supports_cancel_file_create() {
                return Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "queued encrypted file cancellation is unavailable",
                ));
            }
            return self.cancel_pending_file_create_with_lease(&child, &route, generation, lease);
        }
        if !entry.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "encrypted item is read-only",
            ));
        }
        let _reservation = self.reserve_vault_path(route.control.route_id(), &entry.path)?;
        let current_parent = lease.stat(&parent_entry.path)?;
        let current = lease.stat(&entry.path)?;
        if current_parent.id != parent_entry.id
            || !current_parent.directory
            || !current_parent.writable
            || current.id != entry.id
            || current.directory != directory
            || !current.writable
            || current.etag.is_empty()
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "encrypted item or parent changed before removal",
            ));
        }
        if directory {
            let children = lease.list(&current.path)?;
            if children.len() > MAX_DIRECTORY_ENTRIES {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "encrypted directory exceeds the provider listing limit",
                ));
            }
            if !children.is_empty() {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "encrypted directory is not empty",
                ));
            }
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted directory deletion is disabled until the server can condition it on membership",
            ));
        }
        if lease.supports_writes() {
            lease.delete(&current.path, &current.etag)?;
        } else {
            // Restricted offline routes expose only this exact-file tombstone
            // capability. The backend retains the encrypted source reference
            // and later revalidates root, parent, resource ID, and ETag before
            // issuing a conditional DELETE.
            let _outcome = lease.delete_file(&current.path, &current.id, &current.etag)?;
        }
        if let Ok(mut state) = self.state.lock() {
            state.children.remove(&(parent_ino, name.to_owned()));
            state.nodes.remove(&child.ino);
        }
        Ok(())
    }

    fn file_type(&self, node: &Node) -> FileType {
        match node.kind {
            NodeKind::Recovery(ref view) if view.directory() => FileType::Directory,
            NodeKind::Root
            | NodeKind::Personal { .. }
            | NodeKind::Spaces
            | NodeKind::Space { .. }
            | NodeKind::LockedVault { .. } => FileType::Directory,
            NodeKind::Remote { ref entry, .. } if entry.directory => FileType::Directory,
            NodeKind::Vault { ref entry, .. } if entry.directory => FileType::Directory,
            _ => FileType::RegularFile,
        }
    }

    fn attr(&self, node: &Node) -> FileAttr {
        let directory = self.file_type(node) == FileType::Directory;
        let (size, mtime, writable) = match &node.kind {
            NodeKind::Recovery(view) => (view.size(), UNIX_EPOCH, false),
            NodeKind::Remote { space, entry } => {
                let (spool, manifest) = self.spool_paths(space, &entry.path);
                let size = if spool.exists() && manifest.exists() {
                    fs::metadata(spool)
                        .map(|metadata| metadata.len())
                        .unwrap_or(entry.size)
                } else {
                    entry.size
                };
                (
                    size,
                    timestamp(entry.modified_unix),
                    entry.writable && !entry.encrypted && self.space_is_writable(space),
                )
            }
            NodeKind::Vault {
                route,
                generation,
                entry,
            } => {
                let pending_directory = entry.directory
                    && self
                        .has_pending_parent_ref(node.ino, *generation)
                        .unwrap_or(false)
                    && route
                        .control
                        .supports_pending_parent_operations()
                        .unwrap_or(false);
                (
                    entry.size,
                    timestamp(entry.modified_unix),
                    (entry.writable || pending_directory)
                        && self.vault_write_spool.is_some()
                        && if entry.directory {
                            route.control.supports_writes().unwrap_or(false)
                                || route.control.supports_file_creates().unwrap_or(false)
                        } else {
                            route.control.supports_writes().unwrap_or(false)
                                || route
                                    .control
                                    .supports_existing_file_overwrites()
                                    .unwrap_or(false)
                        },
                )
            }
            NodeKind::LockedReadme { parent } => (
                self.locked_readme_contents(*parent).len() as u64,
                UNIX_EPOCH,
                false,
            ),
            NodeKind::Personal { space } | NodeKind::Space { space } => {
                (0, UNIX_EPOCH, self.space_is_writable(space))
            }
            _ => (0, UNIX_EPOCH, false),
        };
        FileAttr {
            ino: INodeNo(node.ino),
            size,
            blocks: size.div_ceil(512),
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime: mtime,
            kind: self.file_type(node),
            perm: if directory {
                if writable { 0o755 } else { 0o555 }
            } else if writable {
                0o644
            } else {
                0o444
            },
            nlink: if directory { 2 } else { 1 },
            uid: self.owner_uid,
            gid: self.owner_gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn update_size(&self, ino: u64, size: u64) {
        if let Ok(mut state) = self.state.lock() {
            if let Some(node) = state.nodes.get_mut(&ino) {
                if let NodeKind::Remote { entry, .. } = &mut node.kind {
                    entry.size = size;
                }
            }
        }
    }

    fn update_size_after_write(&self, ino: u64, size: u64) {
        if let Ok(mut state) = self.state.lock() {
            if let Some(Node {
                kind: NodeKind::Remote { entry, .. },
                ..
            }) = state.nodes.get_mut(&ino)
            {
                entry.size = entry.size.max(size);
            }
        }
    }

    fn update_vault_size(&self, ino: u64, size: u64) {
        if let Ok(mut state) = self.state.lock() {
            if let Some(Node {
                kind: NodeKind::Vault { entry, .. },
                metadata_expires_at,
                ..
            }) = state.nodes.get_mut(&ino)
            {
                entry.size = size;
                *metadata_expires_at = Instant::now();
            }
        }
    }
}

fn pending_directory_identity(entry: &RemoteEntry) -> Option<(String, u64)> {
    if !entry.directory || entry.writable || entry.path == "/" {
        return None;
    }
    let write_id = entry.id.strip_prefix("raiun-pending-directory:")?;
    if write_id.len() != 32 || !write_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let revision = entry
        .etag
        .strip_prefix(&format!("raiun-pending-v1:{write_id}:"))?
        .parse::<u64>()
        .ok()?;
    (revision > 0).then(|| (write_id.to_owned(), revision))
}

fn pending_file_create_identity(entry: &RemoteEntry) -> Option<(String, u64)> {
    if entry.directory || entry.path == "/" {
        return None;
    }
    let write_id = entry.id.strip_prefix("raiun-pending-create:")?;
    if write_id.len() != 32 || !write_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let revision = entry
        .etag
        .strip_prefix(&format!("raiun-pending-v1:{write_id}:"))?
        .parse::<u64>()
        .ok()?;
    (revision > 0).then(|| (write_id.to_owned(), revision))
}

fn same_identity(a: &NodeKind, b: &NodeKind) -> bool {
    match (a, b) {
        (NodeKind::Recovery(a), NodeKind::Recovery(b)) => a.key() == b.key(),
        (NodeKind::Space { space: a }, NodeKind::Space { space: b }) => a == b,
        (
            NodeKind::LockedVault {
                profile_id: profile_a,
                space: space_a,
                resource_id: id_a,
                remote_path: path_a,
            },
            NodeKind::LockedVault {
                profile_id: profile_b,
                space: space_b,
                resource_id: id_b,
                remote_path: path_b,
            },
        ) => profile_a == profile_b && space_a == space_b && id_a == id_b && path_a == path_b,
        (NodeKind::LockedReadme { parent: a }, NodeKind::LockedReadme { parent: b }) => a == b,
        (
            NodeKind::Remote {
                space: a,
                entry: ea,
            },
            NodeKind::Remote {
                space: b,
                entry: eb,
            },
        ) => a == b && ea.id == eb.id,
        (
            NodeKind::Vault {
                route: route_a,
                generation: generation_a,
                entry: entry_a,
            },
            NodeKind::Vault {
                route: route_b,
                generation: generation_b,
                entry: entry_b,
            },
        ) => {
            route_a.control.route_id() == route_b.control.route_id()
                && generation_a == generation_b
                && entry_a.id == entry_b.id
        }
        _ => false,
    }
}
fn stable_inode(value: &str) -> u64 {
    stable_hash(value).max(4)
}
fn stable_hash(value: &str) -> u64 {
    value
        .as_bytes()
        .iter()
        .fold(0xcbf29ce484222325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        })
}
fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
}
fn valid_profile_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
fn safe_unlock_hint(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}
fn encode_uri_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(b"0123456789ABCDEF"[usize::from(byte >> 4)]));
            encoded.push(char::from(b"0123456789ABCDEF"[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}
fn normalize_vault_root(path: &str) -> Result<String, CloudError> {
    if path == "/" {
        return Ok("/".into());
    }
    if !path.starts_with('/') || path.contains('\\') || path.chars().any(char::is_control) {
        return Err(invalid("vault root path is invalid"));
    }
    let trimmed = path.trim_end_matches('/');
    let components: Vec<_> = trimmed[1..].split('/').collect();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !safe_component(component))
    {
        return Err(invalid("vault root path is invalid"));
    }
    Ok(format!("/{}", components.join("/")))
}
fn normalize_entry_path(path: &str) -> Option<String> {
    normalize_vault_root(path).ok()
}
fn ordinary_subtree_path(key: &str) -> Option<(&str, &str)> {
    key.strip_prefix("\0ordinary-subtree\0")?.split_once('\0')
}

fn paths_overlap(left: &str, right: &str) -> bool {
    left == right
        || left == "/"
        || right == "/"
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
}
fn path_is_within(path: &str, directory: &str) -> bool {
    directory == "/"
        || path == directory
        || path
            .strip_prefix(directory)
            .is_some_and(|suffix| suffix.starts_with('/'))
}
fn timestamp(value: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(value.max(0) as u64)
}
fn invalid(message: &str) -> CloudError {
    CloudError::new(ErrorKind::InvalidResponse, message)
}
fn io_error(message: &str) -> CloudError {
    CloudError::new(ErrorKind::Io, message)
}
fn io_cloud(error: std::io::Error) -> CloudError {
    CloudError::new(
        ErrorKind::Io,
        format!("local file operation failed: {error}"),
    )
}
fn vault_write_error(error: vault_write::VaultWriteError) -> CloudError {
    use vault_write::VaultWriteError as VaultError;
    match error {
        VaultError::StaleGeneration => {
            CloudError::new(ErrorKind::Unauthorized, "encrypted write handle is stale")
        }
        VaultError::SizeLimit => CloudError::new(
            ErrorKind::Unsupported,
            "encrypted working copy exceeds its limit",
        ),
        VaultError::RecordNotFound => {
            CloudError::new(ErrorKind::NotFound, "encrypted working copy was not found")
        }
        VaultError::InvalidBinding
        | VaultError::InvalidTarget
        | VaultError::InvalidCondition
        | VaultError::InvalidRecordId
        | VaultError::ScanLimit
        | VaultError::RecordMismatch
        | VaultError::CorruptRecord => {
            CloudError::new(ErrorKind::Conflict, "encrypted working copy is invalid")
        }
        VaultError::UnsafeDirectory | VaultError::Io => {
            CloudError::new(ErrorKind::Io, "encrypted working copy is unavailable")
        }
        VaultError::Backend(error) => error,
        VaultError::ChangedDuringUpload => CloudError::new(
            ErrorKind::Conflict,
            "encrypted working copy changed during upload",
        ),
    }
}
fn errno(error: &CloudError) -> Errno {
    match error.kind {
        ErrorKind::Unauthorized => Errno::EACCES,
        ErrorKind::Forbidden => Errno::EACCES,
        ErrorKind::NotFound => Errno::ENOENT,
        ErrorKind::Conflict if error.message.contains("active writer") => Errno::EAGAIN,
        ErrorKind::Conflict => Errno::EEXIST,
        ErrorKind::Offline => Errno::EHOSTUNREACH,
        ErrorKind::Unsupported if error.message.contains("handle limit") => Errno::ENOMEM,
        ErrorKind::Unsupported if error.message.contains("node limit") => Errno::ENOMEM,
        ErrorKind::Unsupported if error.message.contains("listing limit") => Errno::EOVERFLOW,
        ErrorKind::Unsupported => Errno::EOPNOTSUPP,
        ErrorKind::Io | ErrorKind::InvalidResponse => Errno::EIO,
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OrdinaryWriteManifest {
    version: u8,
    origin: String,
    account_id: String,
    space_id: String,
    root_resource_id: String,
    resource_id: Option<String>,
    path: String,
    condition: String,
    etag: String,
}

fn write_manifest(
    path: &Path,
    scope: &CacheScope,
    resource_id: Option<&str>,
    remote: &str,
    condition: &WriteCondition,
) -> Result<(), CloudError> {
    let (kind, etag) = match condition {
        WriteCondition::Absent => ("absent", ""),
        WriteCondition::Match(etag) => ("match", etag.as_str()),
    };
    let parent = path
        .parent()
        .ok_or_else(|| invalid("provider spool path has no parent"))?;
    let (temp, mut file) = loop {
        let id = MANIFEST_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".provider-manifest-{}-{id}.tmp",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => break (candidate, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io_cloud(error)),
        }
    };
    let encoded = serde_json::to_vec(&OrdinaryWriteManifest {
        version: 2,
        origin: scope.origin().to_owned(),
        account_id: scope.account_id().to_owned(),
        space_id: scope.space_id().to_owned(),
        root_resource_id: scope.root_resource_id().to_owned(),
        resource_id: resource_id.map(str::to_owned),
        path: remote.to_owned(),
        condition: kind.to_owned(),
        etag: etag.to_owned(),
    })
    .map_err(|_| invalid("could not encode provider spool manifest"))?;
    let result = (|| {
        file.write_all(&encoded).map_err(io_cloud)?;
        file.sync_all().map_err(io_cloud)?;
        drop(file);
        fs::rename(&temp, path).map_err(io_cloud)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(io_cloud)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result?;
    Ok(())
}

fn prepare_spool_dir(path: &Path) -> Result<(), CloudError> {
    fs::create_dir_all(path).map_err(io_cloud)?;
    let metadata = fs::symlink_metadata(path).map_err(io_cloud)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("provider spool must be a real directory"));
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_cloud)?;
    Ok(())
}

fn read_manifest(
    path: &Path,
    expected_scope: &CacheScope,
    expected_resource_id: Option<&str>,
    expected_path: &str,
) -> Result<Option<WriteCondition>, CloudError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_cloud(error)),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 16 * 1024 {
        return Err(invalid("provider spool manifest is unsafe or too large"));
    }
    let bytes = recovery::read_manifest_bytes(path)
        .map_err(|_| invalid("provider spool manifest is unsafe or too large"))?;
    let body =
        std::str::from_utf8(&bytes).map_err(|_| invalid("provider spool manifest is malformed"))?;
    if body.trim_start().starts_with('[') {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "legacy unscoped provider spool is recovery-only and will not be auto-adopted",
        ));
    }
    let manifest: OrdinaryWriteManifest =
        serde_json::from_str(body).map_err(|_| invalid("provider spool manifest is malformed"))?;
    if manifest.version != 2
        || manifest.origin != expected_scope.origin()
        || manifest.account_id != expected_scope.account_id()
        || manifest.space_id != expected_scope.space_id()
        || manifest.root_resource_id != expected_scope.root_resource_id()
        || manifest.resource_id.as_deref() != expected_resource_id
        || manifest.path != expected_path
    {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "provider spool does not match the current account, Space root, or resource",
        ));
    }
    match (manifest.condition.as_str(), manifest.etag.as_str()) {
        ("absent", "") => Ok(Some(WriteCondition::Absent)),
        ("match", etag) if !etag.is_empty() && !etag.chars().any(char::is_control) => {
            Ok(Some(WriteCondition::Match(etag.into())))
        }
        _ => Err(invalid("provider spool manifest is malformed")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault_routes::{
        VaultCancelledCreateReceipt, VaultCancelledCreateReceiptState,
        VaultExistingFileOverwriteBackend, VaultReadBackend, VaultReadStream, VaultWriteBackend,
        VaultWriteSource,
    };
    use crate::vault_write::{VaultWriteScope, VaultWriteTarget};
    use sha2::{Digest, Sha256};
    use std::io::Cursor;

    #[cfg(target_os = "linux")]
    #[test]
    fn spool_statfs_reserves_headroom_and_caps_to_one_working_copy() {
        let block_size = 4096_u64;
        let reserve_blocks = SPOOL_STATFS_HEADROOM_RESERVE_BYTES / block_size;
        let small = spool_statfs_from_available(reserve_blocks, block_size, 100, 50).unwrap();
        assert_eq!(small.blocks, 0);
        assert_eq!(small.block_size, 4096);

        let extra_blocks = (8 * 1024 * 1024) / block_size;
        let available =
            spool_statfs_from_available(reserve_blocks + extra_blocks, block_size, 100, 150)
                .unwrap();
        assert_eq!(available.blocks * block_size, 8 * 1024 * 1024);
        assert_eq!(available.files_free, 100);

        let far_more_blocks = u64::MAX / block_size;
        let capped = spool_statfs_from_available(far_more_blocks, block_size, 100, 40).unwrap();
        assert!(capped.blocks * block_size <= MAX_VAULT_WORKING_COPY_BYTES);
        assert_eq!(capped.blocks * block_size, MAX_VAULT_WORKING_COPY_BYTES);
        assert_eq!(capped.files_free, 40);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn spool_statfs_rejects_unusable_block_sizes() {
        assert!(spool_statfs_from_available(10, 0, 1, 1).is_none());
        assert!(spool_statfs_from_available(10, u32::MAX as u64 + 1, 1, 1).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn spool_capacity_uses_a_held_nofollow_directory_descriptor() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("spool");
        fs::create_dir(&directory).unwrap();
        let descriptor = open_spool_capacity_dir(&directory).unwrap();
        let stats = spool_statfs(&descriptor).unwrap();
        assert!(stats.block_size > 0);
        assert!(stats.files_free <= stats.files);

        let link = temp.path().join("spool-link");
        std::os::unix::fs::symlink(&directory, &link).unwrap();
        assert!(open_spool_capacity_dir(&link).is_err());
    }

    #[test]
    fn mountinfo_match_is_exact_escaped_and_fuse_only() {
        let root = Path::new("/home/test/Open Cloud\\Box/クラウド");
        let expected = String::from_utf8(mountinfo_escape(root)).expect("UTF-8 fixture path");
        let fixture = format!(
            "40 25 0:32 / {expected} rw,nosuid - fuse.OpenCloud OpenCloud rw\n\
             41 25 0:33 / {expected}-other rw - fuse.OpenCloud OpenCloud rw\n\
             42 25 0:34 / {expected} rw - ext4 /dev/sda rw\n",
        );
        assert!(mountinfo_contains_mountpoint(fixture.as_bytes(), root));
        assert_eq!(
            mountinfo_fuse_source_at(fixture.as_bytes(), root).as_deref(),
            Some(b"OpenCloud".as_slice())
        );
        assert!(!mountinfo_has_fuse_source(
            fixture.as_bytes(),
            root,
            b"RaiunDesktop-expected"
        ));
        assert!(!mountinfo_contains_mountpoint(
            fixture.replace("fuse.OpenCloud", "ext4").as_bytes(),
            root
        ));
        assert!(expected.contains("\\040"));
        assert!(expected.contains("\\134"));
        assert!(expected.contains("クラウド"));
    }

    #[test]
    fn mixed_or_duplicate_subtree_proof_keeps_retarget_wal() {
        let temp = tempfile::tempdir().expect("temp dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
                .expect("restrict test state directory");
        }
        let spool = VaultWriteSpool::open(temp.path()).expect("open spool");
        let scope =
            VaultWriteScope::new("account-a", "https://example.invalid", "space-a", "root-a")
                .unwrap();
        let root_id = "a".repeat(32);
        let child_id = "b".repeat(32);
        let old_root_target = VaultWriteTarget::new_with_parent(
            "old",
            WriteCondition::Absent,
            crate::vault_write::VaultParentRef::stable("root-a").unwrap(),
        )
        .unwrap();
        let new_root_target = VaultWriteTarget::new_with_parent(
            "new",
            WriteCondition::Absent,
            crate::vault_write::VaultParentRef::stable("root-a").unwrap(),
        )
        .unwrap();
        let old_child_target = VaultWriteTarget::new_with_parent(
            "old/child",
            WriteCondition::Absent,
            crate::vault_write::VaultParentRef::pending_create(root_id.clone(), 1).unwrap(),
        )
        .unwrap();
        let new_child_target = VaultWriteTarget::new_with_parent(
            "new/child",
            WriteCondition::Absent,
            crate::vault_write::VaultParentRef::pending_create(root_id.clone(), 2).unwrap(),
        )
        .unwrap();
        let wal = PendingVaultDirectoryRetarget {
            scope: scope.clone(),
            root_write_id: root_id.clone(),
            root_previous_revision: 1,
            root_revision: 2,
            source_path: "/old".into(),
            destination_path: "/new".into(),
            rows: vec![
                PendingVaultRetargetRow {
                    write_id: root_id.clone(),
                    previous_revision: 1,
                    revision: 2,
                    operation: PendingVaultRetargetOperation::CreateDirectory,
                    old_path: "/old".into(),
                    path: "/new".into(),
                    record_id: None,
                    old_target: Some(old_root_target.clone()),
                    target: new_root_target.clone(),
                    bytes: 0,
                    sha256: String::new(),
                },
                PendingVaultRetargetRow {
                    write_id: child_id.clone(),
                    previous_revision: 3,
                    revision: 4,
                    operation: PendingVaultRetargetOperation::CreateDirectory,
                    old_path: "/old/child".into(),
                    path: "/new/child".into(),
                    record_id: None,
                    old_target: Some(old_child_target.clone()),
                    target: new_child_target.clone(),
                    bytes: 0,
                    sha256: String::new(),
                },
            ],
        };
        spool
            .begin_directory_subtree_retarget(&wal)
            .expect("durable intent is written before backend mutation");

        let new_row = |write_id: &str,
                       previous_revision: u64,
                       revision: u64,
                       old_path: &str,
                       path: &str,
                       old_target: VaultWriteTarget,
                       target: VaultWriteTarget| {
            let parent_ref = target.parent_ref().cloned().expect("target parent ref");
            crate::vault_routes::VaultPendingDirectorySubtreeRenameRow {
                write_id: write_id.into(),
                previous_revision,
                revision,
                operation: crate::vault_routes::VaultPendingSubtreeOperation::CreateDirectory,
                old_path: old_path.into(),
                path: path.into(),
                old_target: Some(old_target),
                target,
                plaintext_len: 0,
                plaintext_sha256: String::new(),
                parent_ref,
            }
        };
        let root_new = new_row(
            &root_id,
            1,
            2,
            "/old",
            "/new",
            old_root_target.clone(),
            new_root_target.clone(),
        );
        let child_new = new_row(
            &child_id,
            3,
            4,
            "/old/child",
            "/new/child",
            old_child_target,
            new_child_target,
        );
        let proof = |rows| crate::vault_routes::VaultPendingDirectoryRetargetResolution {
            scope: scope.clone(),
            state: VaultPendingDirectoryRetargetState::AllNew,
            root_write_id: root_id.clone(),
            root_previous_revision: 1,
            root_revision: 2,
            rows,
        };
        let mixed = proof(vec![root_new.clone(), {
            let mut stale = child_new.clone();
            stale.revision = 3;
            stale.path = "/old/child".into();
            stale.target = VaultWriteTarget::new_with_parent(
                "old/child",
                WriteCondition::Absent,
                crate::vault_write::VaultParentRef::pending_create(root_id.clone(), 1).unwrap(),
            )
            .unwrap();
            stale
        }]);
        assert!(verify_subtree_retarget_proof(&wal, &mixed).is_err());
        assert_eq!(
            spool.list_directory_subtree_retargets().unwrap(),
            vec![wal.clone()]
        );

        let duplicate = proof(vec![root_new.clone(), root_new]);
        assert!(verify_subtree_retarget_proof(&wal, &duplicate).is_err());
        assert_eq!(spool.list_directory_subtree_retargets().unwrap(), vec![wal]);
    }

    use raiun_core::backend::{CloudBackend, CloudSpace};
    use std::collections::HashMap;

    type FakeFiles = HashMap<(String, String), (RemoteEntry, Vec<u8>)>;

    fn test_sha256(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[derive(Default)]
    struct FakeBackend {
        files: Mutex<FakeFiles>,
        fail_upload: Mutex<bool>,
        spaces_override: Mutex<Option<Vec<CloudSpace>>>,
        network_error: Mutex<Option<ErrorKind>>,
        root_ids: Mutex<HashMap<String, String>>,
        list_calls: AtomicUsize,
        stat_calls: AtomicUsize,
    }

    struct FakeVaultReadBackend;

    struct MismatchedVaultRootReadBackend;

    impl VaultReadBackend for MismatchedVaultRootReadBackend {
        fn authorize(&self) -> Result<(), CloudError> {
            Ok(())
        }

        fn list(&self, path: &str) -> Result<Vec<RemoteEntry>, CloudError> {
            FakeVaultReadBackend.list(path)
        }

        fn stat(&self, path: &str) -> Result<RemoteEntry, CloudError> {
            let mut entry = FakeVaultReadBackend.stat(path)?;
            if path == "/" {
                entry.id = "replaced-root-id".into();
            }
            Ok(entry)
        }

        fn open(&self, path: &str) -> Result<Box<dyn VaultReadStream>, CloudError> {
            FakeVaultReadBackend.open(path)
        }
    }

    impl VaultReadBackend for FakeVaultReadBackend {
        fn authorize(&self) -> Result<(), CloudError> {
            Ok(())
        }

        fn list(&self, path: &str) -> Result<Vec<RemoteEntry>, CloudError> {
            if path == "/" {
                Ok(vec![RemoteEntry {
                    id: "vault-file-id".into(),
                    path: "/hello.txt".into(),
                    directory: false,
                    size: 12,
                    etag: "vault-file-etag".into(),
                    modified_unix: 1,
                    writable: false,
                    encrypted: false,
                }])
            } else {
                Ok(Vec::new())
            }
        }

        fn stat(&self, path: &str) -> Result<RemoteEntry, CloudError> {
            match path {
                "/" => Ok(RemoteEntry {
                    id: "vault-root-id".into(),
                    path: "/".into(),
                    directory: true,
                    size: 0,
                    etag: "vault-root-etag".into(),
                    modified_unix: 1,
                    writable: false,
                    encrypted: false,
                }),
                "/hello.txt" => Ok(RemoteEntry {
                    id: "vault-file-id".into(),
                    path: path.into(),
                    directory: false,
                    size: 12,
                    etag: "vault-file-etag".into(),
                    modified_unix: 1,
                    writable: false,
                    encrypted: false,
                }),
                _ => Err(CloudError::new(
                    ErrorKind::NotFound,
                    "missing vault fixture",
                )),
            }
        }

        fn open(&self, path: &str) -> Result<Box<dyn VaultReadStream>, CloudError> {
            if path != "/hello.txt" {
                return Err(CloudError::new(
                    ErrorKind::NotFound,
                    "missing vault fixture",
                ));
            }
            Ok(Box::new(Cursor::new(b"vault secret".to_vec())))
        }
    }

    type CancelledDirectory = (String, String, u64, String, String);

    #[derive(Default)]
    struct FakeVaultWriteBackend {
        files: Mutex<HashMap<String, (RemoteEntry, Vec<u8>)>>,
        fail_upload: Mutex<bool>,
        next_version: AtomicUsize,
        delete_calls: AtomicUsize,
        rename_calls: AtomicUsize,
        fail_rename_call: Mutex<Option<usize>>,
        queued_delete_sources: Mutex<HashMap<String, (RemoteEntry, Vec<u8>)>>,
        create_calls: Mutex<Vec<Option<(String, u64)>>>,
        directory_parent_refs: Mutex<Vec<VaultParentRef>>,
        cancelled_directories: Mutex<Vec<CancelledDirectory>>,
        queue_creates: bool,
        pending_create_rename_calls: AtomicUsize,
        pending_create_resolution_failures: AtomicUsize,
        pending_create_resolutions: Mutex<HashMap<String, VaultPendingCreateResolution>>,
        pending_create_bodies: Mutex<HashMap<String, Vec<u8>>>,
        pending_create_targets: Mutex<HashMap<String, VaultWriteTarget>>,
        cancelled_file_receipts: Mutex<HashMap<String, VaultCancelledCreateReceipt>>,
        file_cancel_calls: AtomicUsize,
        fail_file_cancel: Mutex<bool>,
        queue_directories: bool,
        queue_renames: bool,
        queue_deletes: bool,
    }

    impl FakeVaultWriteBackend {
        fn with_root() -> Self {
            let root = RemoteEntry {
                id: "vault-root-id".into(),
                path: "/".into(),
                directory: true,
                size: 0,
                etag: "root-v1".into(),
                modified_unix: 1,
                writable: true,
                encrypted: false,
            };
            Self {
                files: Mutex::new(HashMap::from([("/".into(), (root, Vec::new()))])),
                fail_upload: Mutex::new(false),
                next_version: AtomicUsize::new(1),
                delete_calls: AtomicUsize::new(0),
                rename_calls: AtomicUsize::new(0),
                fail_rename_call: Mutex::new(None),
                queued_delete_sources: Mutex::new(HashMap::new()),
                create_calls: Mutex::new(Vec::new()),
                directory_parent_refs: Mutex::new(Vec::new()),
                cancelled_directories: Mutex::new(Vec::new()),
                queue_creates: false,
                pending_create_rename_calls: AtomicUsize::new(0),
                pending_create_resolution_failures: AtomicUsize::new(0),
                pending_create_resolutions: Mutex::new(HashMap::new()),
                pending_create_bodies: Mutex::new(HashMap::new()),
                pending_create_targets: Mutex::new(HashMap::new()),
                cancelled_file_receipts: Mutex::new(HashMap::new()),
                file_cancel_calls: AtomicUsize::new(0),
                fail_file_cancel: Mutex::new(false),
                queue_directories: false,
                queue_renames: false,
                queue_deletes: false,
            }
        }

        fn with_queued_nested_creates() -> Self {
            Self {
                queue_creates: true,
                queue_directories: true,
                ..Self::with_root()
            }
        }

        fn with_queued_renames() -> Self {
            Self {
                queue_renames: true,
                ..Self::with_root()
            }
        }

        fn with_queued_deletes() -> Self {
            Self {
                queue_deletes: true,
                ..Self::with_root()
            }
        }

        fn recovered_delete(&self, path: &str) -> Option<Vec<u8>> {
            self.queued_delete_sources
                .lock()
                .unwrap()
                .get(path)
                .map(|(_, bytes)| bytes.clone())
        }

        fn seed_file(&self, path: &str, bytes: &[u8], etag: &str, writable: bool) {
            self.files.lock().unwrap().insert(
                path.into(),
                (
                    RemoteEntry {
                        id: format!("id:{path}"),
                        path: path.into(),
                        directory: false,
                        size: bytes.len() as u64,
                        etag: etag.into(),
                        modified_unix: 1,
                        writable,
                        encrypted: false,
                    },
                    bytes.to_vec(),
                ),
            );
        }

        fn seed_directory(&self, path: &str, etag: &str, writable: bool) {
            self.files.lock().unwrap().insert(
                path.into(),
                (
                    RemoteEntry {
                        id: format!("id:{path}"),
                        path: path.into(),
                        directory: true,
                        size: 0,
                        etag: etag.into(),
                        modified_unix: 1,
                        writable,
                        encrypted: false,
                    },
                    Vec::new(),
                ),
            );
        }

        fn parent(path: &str) -> &str {
            path.rsplit_once('/')
                .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
                .unwrap_or("/")
        }

        fn next_etag(&self) -> String {
            format!(
                "vault-v{}",
                self.next_version.fetch_add(1, Ordering::Relaxed) + 1
            )
        }

        fn queued_create(
            &self,
            target: &VaultWriteTarget,
            source: &mut dyn VaultWriteSource,
            plaintext_len: u64,
            existing: Option<(&str, u64)>,
        ) -> Result<VaultUploadOutcome, CloudError> {
            if !matches!(target.condition(), WriteCondition::Absent) {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "create fixture lost its original absence condition",
                ));
            }
            let operation_id = existing
                .map(|(id, _)| id.to_owned())
                .unwrap_or_else(|| "c".repeat(32));
            let revision = existing.map(|(_, revision)| revision + 1).unwrap_or(1);
            self.create_calls
                .lock()
                .unwrap()
                .push(existing.map(|(id, revision)| (id.to_owned(), revision)));
            let mut bytes = Vec::new();
            source.read_to_end(&mut bytes).map_err(io_cloud)?;
            if bytes.len() as u64 != plaintext_len {
                return Err(invalid("queued create fixture length mismatch"));
            }
            self.pending_create_bodies
                .lock()
                .unwrap()
                .insert(operation_id.clone(), bytes.clone());
            self.pending_create_targets
                .lock()
                .unwrap()
                .insert(operation_id.clone(), target.clone());
            let entry = RemoteEntry {
                id: format!("raiun-pending-create:{operation_id}"),
                path: format!("/{}", target.opaque_relative_target()),
                directory: false,
                size: plaintext_len,
                etag: format!("raiun-pending-v1:{operation_id}:{revision}"),
                modified_unix: 0,
                writable: true,
                encrypted: true,
            };
            self.files
                .lock()
                .unwrap()
                .insert(entry.path.clone(), (entry.clone(), bytes));
            Ok(VaultUploadOutcome::QueuedCreate {
                entry,
                write_id: operation_id,
                revision,
                uncertain: false,
            })
        }
    }

    impl VaultReadBackend for FakeVaultWriteBackend {
        fn authorize(&self) -> Result<(), CloudError> {
            Ok(())
        }

        fn list(&self, path: &str) -> Result<Vec<RemoteEntry>, CloudError> {
            let files = self.files.lock().unwrap();
            Ok(files
                .iter()
                .filter(|(candidate, _)| {
                    candidate.as_str() != path && Self::parent(candidate) == path
                })
                .map(|(_, (entry, _))| entry.clone())
                .collect())
        }

        fn stat(&self, path: &str) -> Result<RemoteEntry, CloudError> {
            self.files
                .lock()
                .unwrap()
                .get(path)
                .map(|(entry, _)| entry.clone())
                .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "missing fixture item"))
        }

        fn open(&self, path: &str) -> Result<Box<dyn VaultReadStream>, CloudError> {
            let bytes = self
                .files
                .lock()
                .unwrap()
                .get(path)
                .map(|(_, bytes)| bytes.clone())
                .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "missing fixture item"))?;
            Ok(Box::new(Cursor::new(bytes)))
        }

        fn resolve_pending_create(
            &self,
            write_id: &str,
        ) -> Result<Option<VaultPendingCreateResolution>, CloudError> {
            loop {
                let failures = self
                    .pending_create_resolution_failures
                    .load(Ordering::Relaxed);
                if failures == 0 {
                    break;
                }
                if self
                    .pending_create_resolution_failures
                    .compare_exchange(failures, failures - 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    return Err(CloudError::new(
                        ErrorKind::Offline,
                        "injected transient resolver failure",
                    ));
                }
            }
            Ok(self
                .pending_create_resolutions
                .lock()
                .unwrap()
                .get(write_id)
                .cloned())
        }

        fn parent_ref_for_directory(
            &self,
            path: &str,
            expected_entry_id: &str,
            expected_entry_etag: &str,
        ) -> Result<VaultParentRef, CloudError> {
            let current = VaultReadBackend::stat(self, path)?;
            if !current.directory
                || current.id != expected_entry_id
                || current.etag != expected_entry_etag
            {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "fixture parent identity changed",
                ));
            }
            if let Some(write_id) = current.id.strip_prefix("raiun-pending-directory:") {
                let etag = current
                    .etag
                    .strip_prefix(&format!("raiun-pending-v1:{write_id}:"))
                    .ok_or_else(|| invalid("fixture pending parent ETag is malformed"))?;
                let revision = etag
                    .parse::<u64>()
                    .map_err(|_| invalid("fixture pending parent revision is malformed"))?;
                return VaultParentRef::pending_create(write_id.to_owned(), revision)
                    .map_err(|_| invalid("fixture pending parent ID is malformed"));
            }
            VaultParentRef::stable(expected_entry_id)
                .map_err(|_| invalid("fixture stable parent ID is malformed"))
        }
    }

    impl VaultWriteBackend for FakeVaultWriteBackend {
        fn supports_pending_parent_operations(&self) -> bool {
            self.queue_directories
        }

        fn supports_file_create(&self) -> bool {
            true
        }

        fn prepare_target(
            &self,
            path: &str,
            condition: WriteCondition,
        ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
            let target = path.trim_start_matches('/');
            let scope = VaultWriteScope::new(
                "account-a",
                "https://example.invalid",
                "encrypted-space",
                "vault-root-id",
            )
            .map_err(|_| invalid("bad test scope"))?;
            let target =
                VaultWriteTarget::new(target, condition).map_err(|_| invalid("bad test target"))?;
            Ok((scope, target))
        }

        fn upload(
            &self,
            target: &VaultWriteTarget,
            source: &mut dyn VaultWriteSource,
            plaintext_len: u64,
        ) -> Result<VaultUploadOutcome, CloudError> {
            if *self.fail_upload.lock().unwrap() {
                return Err(CloudError::new(ErrorKind::Offline, "fixture offline"));
            }
            let path = format!("/{}", target.opaque_relative_target());
            let mut files = self.files.lock().unwrap();
            match (target.condition(), files.get(&path)) {
                (WriteCondition::Absent, Some(_)) => {
                    return Err(CloudError::new(ErrorKind::Conflict, "already exists"));
                }
                (WriteCondition::Match(expected), Some((current, _)))
                    if expected != &current.etag =>
                {
                    return Err(CloudError::new(ErrorKind::Conflict, "revision changed"));
                }
                (WriteCondition::Match(_), None) => {
                    return Err(CloudError::new(ErrorKind::Conflict, "missing"));
                }
                _ => {}
            }
            let mut bytes = Vec::new();
            source.read_to_end(&mut bytes).map_err(io_cloud)?;
            if bytes.len() as u64 != plaintext_len {
                return Err(invalid("test upload length mismatch"));
            }
            let etag = self.next_etag();
            let entry = RemoteEntry {
                id: files
                    .get(&path)
                    .map(|(entry, _)| entry.id.clone())
                    .unwrap_or_else(|| format!("id:{path}")),
                path: path.clone(),
                directory: false,
                size: plaintext_len,
                etag,
                modified_unix: 1,
                writable: true,
                encrypted: false,
            };
            files.insert(path, (entry.clone(), bytes));
            Ok(VaultUploadOutcome::Committed(entry))
        }

        fn create_file(
            &self,
            target: &VaultWriteTarget,
            source: &mut dyn VaultWriteSource,
            plaintext_len: u64,
            existing: Option<(&str, u64)>,
        ) -> Result<VaultUploadOutcome, CloudError> {
            if self.queue_creates {
                self.queued_create(target, source, plaintext_len, existing)
            } else {
                VaultWriteBackend::upload(self, target, source, plaintext_len)
            }
        }

        fn begin_file_create(
            &self,
            target: &VaultWriteTarget,
        ) -> Result<VaultUploadOutcome, CloudError> {
            if !matches!(target.condition(), WriteCondition::Absent) {
                return Err(CloudError::new(ErrorKind::Conflict, "create lost Absent"));
            }
            let write_id = "c".repeat(32);
            Ok(VaultUploadOutcome::BuildingCreate {
                entry: RemoteEntry {
                    id: format!("raiun-pending-create:{write_id}"),
                    path: format!("/{}", target.opaque_relative_target()),
                    directory: false,
                    size: 0,
                    etag: format!("raiun-pending-v1:{write_id}:1"),
                    modified_unix: 0,
                    writable: true,
                    encrypted: true,
                },
                write_id,
                revision: 1,
            })
        }

        fn mkdir(&self, path: &str) -> Result<RemoteEntry, CloudError> {
            let mut files = self.files.lock().unwrap();
            if files.contains_key(path) {
                return Err(CloudError::new(ErrorKind::Conflict, "already exists"));
            }
            let entry = RemoteEntry {
                id: format!("id:{path}"),
                path: path.into(),
                directory: true,
                size: 0,
                etag: self.next_etag(),
                modified_unix: 1,
                writable: true,
                encrypted: false,
            };
            files.insert(path.into(), (entry.clone(), Vec::new()));
            Ok(entry)
        }

        fn delete(&self, path: &str, expected_etag: &str) -> Result<(), CloudError> {
            self.delete_calls.fetch_add(1, Ordering::Relaxed);
            let mut files = self.files.lock().unwrap();
            match files.get(path) {
                Some((entry, _)) if entry.etag == expected_etag => {
                    files.remove(path);
                    Ok(())
                }
                Some(_) => Err(CloudError::new(ErrorKind::Conflict, "revision changed")),
                None => Err(CloudError::new(ErrorKind::NotFound, "missing")),
            }
        }

        fn rename(
            &self,
            from: &str,
            to: &str,
            expected_etag: &str,
        ) -> Result<RemoteEntry, CloudError> {
            let call = self.rename_calls.fetch_add(1, Ordering::Relaxed) + 1;
            if *self.fail_rename_call.lock().unwrap() == Some(call) {
                return Err(CloudError::new(
                    ErrorKind::Offline,
                    "injected rename failure",
                ));
            }
            let mut files = self.files.lock().unwrap();
            let (source, bytes) = files
                .get(from)
                .cloned()
                .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "missing"))?;
            if source.etag != expected_etag || files.contains_key(to) {
                return Err(CloudError::new(ErrorKind::Conflict, "revision changed"));
            }
            let mut moving = if source.directory {
                let prefix = format!("{}/", from.trim_end_matches('/'));
                files
                    .iter()
                    .filter(|(path, _)| path.as_str() == from || path.starts_with(&prefix))
                    .map(|(path, value)| (path.clone(), value.clone()))
                    .collect::<Vec<_>>()
            } else {
                vec![(from.to_owned(), (source, bytes))]
            };
            if moving.iter().any(|(old, _)| {
                let tail = old.strip_prefix(from).unwrap_or_default();
                files.contains_key(&format!("{to}{tail}"))
            }) {
                return Err(CloudError::new(ErrorKind::Conflict, "destination exists"));
            }
            for (old, _) in &moving {
                files.remove(old);
            }
            let mut moved_root = None;
            for (old, (mut entry, contents)) in moving.drain(..) {
                let tail = old.strip_prefix(from).unwrap_or_default();
                let new_path = format!("{to}{tail}");
                entry.path = new_path.clone();
                if old == from {
                    entry.etag = self.next_etag();
                    moved_root = Some(entry.clone());
                }
                files.insert(new_path, (entry, contents));
            }
            Ok(moved_root.expect("rename includes source root"))
        }
    }

    impl VaultExistingFileOverwriteBackend for FakeVaultWriteBackend {
        fn supports_pending_parent_operations(&self) -> bool {
            self.queue_directories
        }

        fn prepare_existing_target(
            &self,
            path: &str,
            base_resource_id: &str,
            base_etag: &str,
        ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
            let entry = VaultReadBackend::stat(self, path)?;
            if entry.directory || entry.id != base_resource_id || entry.etag != base_etag {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "fixture file identity or version changed",
                ));
            }
            VaultWriteBackend::prepare_target(
                self,
                path,
                WriteCondition::Match(base_etag.to_owned()),
            )
        }

        fn overwrite(
            &self,
            target: &VaultWriteTarget,
            source: &mut dyn VaultWriteSource,
            plaintext_len: u64,
        ) -> Result<VaultUploadOutcome, CloudError> {
            VaultWriteBackend::upload(self, target, source, plaintext_len)
        }

        fn supports_file_create(&self) -> bool {
            true
        }

        fn prepare_file_create(
            &self,
            path: &str,
            _existing: Option<(&str, u64)>,
        ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
            VaultWriteBackend::prepare_target(self, path, WriteCondition::Absent)
        }

        fn create_file(
            &self,
            target: &VaultWriteTarget,
            source: &mut dyn VaultWriteSource,
            plaintext_len: u64,
            existing: Option<(&str, u64)>,
        ) -> Result<VaultUploadOutcome, CloudError> {
            self.queued_create(target, source, plaintext_len, existing)
        }

        fn begin_file_create(
            &self,
            target: &VaultWriteTarget,
        ) -> Result<VaultUploadOutcome, CloudError> {
            VaultWriteBackend::begin_file_create(self, target)
        }

        fn supports_directory_create(&self) -> bool {
            self.queue_directories
        }

        fn supports_cancel_directory_create(&self) -> bool {
            self.queue_directories
        }

        fn cancel_never_attempted_directory_create(
            &self,
            path: &str,
            write_id: &str,
            revision: u64,
            expected_entry_id: &str,
            expected_entry_etag: &str,
        ) -> Result<(), CloudError> {
            let expected_id = format!("raiun-pending-directory:{write_id}");
            let expected_etag = format!("raiun-pending-v1:{write_id}:{revision}");
            if expected_entry_id != expected_id || expected_entry_etag != expected_etag {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "stale queued directory",
                ));
            }
            let mut files = self.files.lock().unwrap();
            if files.keys().any(|candidate| {
                candidate != path
                    && candidate
                        .strip_prefix(path.trim_end_matches('/'))
                        .is_some_and(|suffix| suffix.starts_with('/'))
            }) {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "directory has children",
                ));
            }
            match files.get(path) {
                Some((entry, _))
                    if entry.id == expected_id
                        && entry.etag == expected_etag
                        && entry.directory => {}
                _ => return Err(CloudError::new(ErrorKind::Conflict, "directory changed")),
            }
            files.remove(path);
            self.cancelled_directories.lock().unwrap().push((
                path.to_owned(),
                write_id.to_owned(),
                revision,
                expected_entry_id.to_owned(),
                expected_entry_etag.to_owned(),
            ));
            Ok(())
        }

        fn supports_cancel_file_create(&self) -> bool {
            self.queue_creates
        }

        fn cancel_never_attempted_file_create(
            &self,
            path: &str,
            write_id: &str,
            revision: u64,
            expected_entry_id: &str,
            expected_entry_etag: &str,
        ) -> Result<VaultCancelledCreateReceipt, CloudError> {
            self.file_cancel_calls.fetch_add(1, Ordering::Relaxed);
            let exact_id = format!("raiun-pending-create:{write_id}");
            let exact_etag = format!("raiun-pending-v1:{write_id}:{revision}");
            if expected_entry_id != exact_id || expected_entry_etag != exact_etag {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "stale create identity",
                ));
            }
            if *self.fail_file_cancel.lock().unwrap() {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "create was claimed by an upload attempt",
                ));
            }
            if let Some(receipt) = self.cancelled_file_receipts.lock().unwrap().get(write_id) {
                return Ok(receipt.clone());
            }
            let (entry, bytes) = self
                .files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "pending create missing"))?;
            if entry.id != exact_id || entry.etag != exact_etag || entry.directory {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "pending create changed",
                ));
            }
            let target = self
                .pending_create_targets
                .lock()
                .unwrap()
                .get(write_id)
                .cloned()
                .ok_or_else(|| CloudError::new(ErrorKind::Conflict, "target missing"))?;
            let scope = VaultWriteScope::new(
                "account-a",
                "https://example.invalid",
                "encrypted-space",
                "vault-root-id",
            )
            .map_err(|_| invalid("bad test scope"))?;
            let receipt = VaultCancelledCreateReceipt {
                state: VaultCancelledCreateReceiptState::Cancelled,
                scope,
                target,
                path: path.to_owned(),
                write_id: write_id.to_owned(),
                original_revision: revision,
                current_revision: revision,
                content: crate::vault_write::VerifiedCreateContent {
                    bytes: bytes.len() as u64,
                    sha256: test_sha256(&bytes),
                },
            };
            self.cancelled_file_receipts
                .lock()
                .unwrap()
                .insert(write_id.to_owned(), receipt.clone());
            Ok(receipt)
        }

        fn resolve_cancelled_file_create(
            &self,
            write_id: &str,
            revision: u64,
        ) -> Result<Option<VaultCancelledCreateReceipt>, CloudError> {
            Ok(self
                .cancelled_file_receipts
                .lock()
                .unwrap()
                .get(write_id)
                .filter(|receipt| receipt.original_revision == revision)
                .cloned())
        }

        fn acknowledge_cancelled_file_create(
            &self,
            write_id: &str,
            revision: u64,
            target: &VaultWriteTarget,
            content: &crate::vault_write::VerifiedCreateContent,
        ) -> Result<(), CloudError> {
            let mut receipts = self.cancelled_file_receipts.lock().unwrap();
            match receipts.get(write_id).cloned() {
                Some(receipt)
                    if receipt.original_revision == revision
                        && receipt.target == *target
                        && receipt.content == *content =>
                {
                    if receipt.state == VaultCancelledCreateReceiptState::Cancelled {
                        let mut acknowledged = receipt.clone();
                        acknowledged.state = VaultCancelledCreateReceiptState::Acknowledged;
                        acknowledged.current_revision = acknowledged
                            .current_revision
                            .checked_add(1)
                            .expect("test receipt revision should not overflow");
                        receipts.insert(write_id.to_owned(), acknowledged);
                        self.files.lock().unwrap().remove(&receipt.path);
                    }
                    Ok(())
                }
                _ => Err(CloudError::new(
                    ErrorKind::Conflict,
                    "cancellation receipt changed",
                )),
            }
        }

        fn finalize_cancelled_file_create_ack(
            &self,
            receipt: &VaultCancelledCreateReceipt,
        ) -> Result<(), CloudError> {
            let mut receipts = self.cancelled_file_receipts.lock().unwrap();
            match receipts.get(&receipt.write_id) {
                Some(current)
                    if current == receipt
                        && current.state == VaultCancelledCreateReceiptState::Acknowledged =>
                {
                    receipts.remove(&receipt.write_id);
                    Ok(())
                }
                _ => Err(CloudError::new(
                    ErrorKind::Conflict,
                    "acknowledged cancellation proof changed",
                )),
            }
        }

        fn create_directory_under_parent(
            &self,
            path: &str,
            parent_ref: &VaultParentRef,
        ) -> Result<VaultDirectoryCreateOutcome, CloudError> {
            if !self.queue_directories {
                return Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "fixture directory creation is disabled",
                ));
            }
            let parent_path = Self::parent(path);
            let parent = VaultReadBackend::stat(self, parent_path)?;
            match parent_ref {
                VaultParentRef::Stable { resource_id } if parent.id == *resource_id => {}
                VaultParentRef::PendingCreate { write_id, revision }
                    if parent.id == format!("raiun-pending-directory:{write_id}")
                        && parent.etag == format!("raiun-pending-v1:{write_id}:{revision}") => {}
                _ => {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "fixture parent reference does not match the directory",
                    ));
                }
            }
            let mut parent_refs = self.directory_parent_refs.lock().unwrap();
            parent_refs.push(parent_ref.clone());
            let write_id = format!("{:032x}", parent_refs.len());
            drop(parent_refs);
            let entry = RemoteEntry {
                id: format!("raiun-pending-directory:{write_id}"),
                path: path.to_owned(),
                directory: true,
                size: 0,
                etag: format!("raiun-pending-v1:{write_id}:1"),
                modified_unix: 0,
                writable: false,
                encrypted: false,
            };
            self.files
                .lock()
                .unwrap()
                .insert(path.to_owned(), (entry.clone(), Vec::new()));
            Ok(VaultDirectoryCreateOutcome::Queued {
                entry,
                write_id,
                revision: 1,
                uncertain: false,
            })
        }

        fn supports_pending_directory_rename(&self) -> bool {
            self.queue_directories
        }

        fn rename_pending_directory_create(
            &self,
            from: &str,
            to: &str,
            expected_entry_id: &str,
            expected_entry_etag: &str,
            destination_parent: &VaultParentRef,
        ) -> Result<crate::vault_routes::VaultPendingDirectoryRenameOutcome, CloudError> {
            let write_id = expected_entry_id
                .strip_prefix("raiun-pending-directory:")
                .ok_or_else(|| invalid("fixture pending directory ID is malformed"))?;
            let revision = expected_entry_etag
                .strip_prefix("raiun-pending-v1:")
                .and_then(|value| value.strip_prefix(&format!("{write_id}:")))
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| invalid("fixture pending directory ETag is malformed"))?;
            let mut files = self.files.lock().unwrap();
            let (mut entry, contents) = files
                .get(from)
                .cloned()
                .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "missing pending directory"))?;
            let has_children = files.keys().any(|candidate| {
                candidate != from
                    && candidate
                        .strip_prefix(from.trim_end_matches('/'))
                        .is_some_and(|suffix| suffix.starts_with('/'))
            });
            if !self.queue_directories
                || !entry.directory
                || entry.id != expected_entry_id
                || entry.etag != expected_entry_etag
                || has_children
                || files.contains_key(to)
            {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "fixture pending directory changed, has children, or destination exists",
                ));
            }
            let parent = files
                .get(Self::parent(to))
                .map(|(entry, _)| entry)
                .ok_or_else(|| {
                    CloudError::new(ErrorKind::NotFound, "missing destination parent")
                })?;
            let parent_matches = match destination_parent {
                VaultParentRef::Stable { resource_id } => parent.id == *resource_id,
                VaultParentRef::PendingCreate { write_id, revision } => {
                    parent.id == format!("raiun-pending-directory:{write_id}")
                        && parent.etag == format!("raiun-pending-v1:{write_id}:{revision}")
                }
            };
            if !parent_matches {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "fixture destination parent changed",
                ));
            }
            files.remove(from);
            entry.path = to.to_owned();
            entry.etag = format!("raiun-pending-v1:{write_id}:{}", revision + 1);
            files.insert(to.to_owned(), (entry.clone(), contents));
            self.directory_parent_refs
                .lock()
                .unwrap()
                .push(destination_parent.clone());
            Ok(crate::vault_routes::VaultPendingDirectoryRenameOutcome {
                entry,
                write_id: write_id.to_owned(),
                previous_revision: revision,
                revision: revision + 1,
                parent_ref: destination_parent.clone(),
            })
        }

        fn supports_file_rename(&self) -> bool {
            self.queue_renames
        }

        fn supports_pending_create_rename(&self) -> bool {
            self.queue_creates
        }

        fn rename_pending_create(
            &self,
            from: &str,
            to: &str,
            expected_source_id: &str,
            expected_source_etag: &str,
            destination_parent: &VaultParentRef,
        ) -> Result<crate::vault_routes::VaultPendingCreateRenameOutcome, CloudError> {
            if !self.queue_creates {
                return Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "fixture pending-create rename capability is disabled",
                ));
            }
            self.pending_create_rename_calls
                .fetch_add(1, Ordering::Relaxed);
            let id = expected_source_id
                .strip_prefix("raiun-pending-create:")
                .ok_or_else(|| invalid("fixture pending create ID is malformed"))?;
            let revision = expected_source_etag
                .strip_prefix("raiun-pending-v1:")
                .and_then(|tail| tail.strip_prefix(&format!("{id}:")))
                .and_then(|tail| tail.parse::<u64>().ok())
                .ok_or_else(|| invalid("fixture pending create ETag is malformed"))?;
            let mut files = self.files.lock().unwrap();
            let (mut entry, bytes) = files
                .remove(from)
                .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "missing pending source"))?;
            if entry.directory
                || entry.id != expected_source_id
                || entry.etag != expected_source_etag
                || files.contains_key(to)
            {
                files.insert(from.to_owned(), (entry, bytes));
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "fixture pending create changed or destination exists",
                ));
            }
            let (parent_path, _) = to.rsplit_once('/').unwrap_or(("", to));
            let parent_path = if parent_path.is_empty() {
                "/"
            } else {
                parent_path
            };
            let parent = files
                .get(parent_path)
                .map(|(entry, _)| entry)
                .ok_or_else(|| {
                    CloudError::new(ErrorKind::NotFound, "missing destination parent")
                })?;
            let parent_matches = match destination_parent {
                VaultParentRef::Stable { resource_id } => parent.id == *resource_id,
                VaultParentRef::PendingCreate { write_id, revision } => {
                    parent.id == format!("raiun-pending-directory:{write_id}")
                        && parent.etag == format!("raiun-pending-v1:{write_id}:{revision}")
                }
            };
            if !parent_matches {
                files.insert(from.to_owned(), (entry, bytes));
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "fixture destination parent changed",
                ));
            }
            entry.path = to.to_owned();
            entry.etag = format!("raiun-pending-v1:{id}:{}", revision + 1);
            let content_bytes = bytes.len() as u64;
            let content_sha256 = test_sha256(&bytes);
            files.insert(to.to_owned(), (entry.clone(), bytes));
            let scope = VaultWriteScope::new(
                "account-a",
                "https://example.invalid",
                "encrypted-space",
                "vault-root-id",
            )
            .map_err(|_| invalid("fixture scope is invalid"))?;
            let target = VaultWriteTarget::new_with_parent(
                to.trim_start_matches('/'),
                WriteCondition::Absent,
                destination_parent.clone(),
            )
            .map_err(|_| invalid("fixture destination target is invalid"))?;
            let resolution = VaultPendingCreateResolution {
                scope: scope.clone(),
                target: target.clone(),
                write_id: id.to_owned(),
                revision: revision + 1,
                path: to.to_owned(),
                plaintext_bytes: content_bytes,
                plaintext_sha256: Some(content_sha256),
                never_attempted: true,
            };
            self.pending_create_resolutions
                .lock()
                .unwrap()
                .insert(id.to_owned(), resolution);
            Ok(crate::vault_routes::VaultPendingCreateRenameOutcome {
                entry,
                write_id: id.to_owned(),
                previous_revision: revision,
                revision: revision + 1,
                scope,
                target,
            })
        }

        fn rename_file(
            &self,
            from: &str,
            to: &str,
            expected_source_id: &str,
            expected_source_etag: &str,
        ) -> Result<crate::vault_routes::VaultRenameOutcome, CloudError> {
            if !self.queue_renames {
                return Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "fixture rename capability is disabled",
                ));
            }
            let mut files = self.files.lock().unwrap();
            let (mut entry, bytes) = files
                .get(from)
                .cloned()
                .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "missing rename source"))?;
            if entry.directory
                || entry.id != expected_source_id
                || entry.etag != expected_source_etag
                || files.contains_key(to)
            {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "fixture rename identity or destination changed",
                ));
            }
            files.remove(from);
            entry.path = to.to_owned();
            entry.etag = format!("{}-queued-rename", entry.etag);
            files.insert(to.to_owned(), (entry.clone(), bytes));
            Ok(crate::vault_routes::VaultRenameOutcome::Queued {
                entry,
                write_id: "fixture-rename-id".into(),
                revision: 1,
                uncertain: false,
            })
        }

        fn supports_file_delete(&self) -> bool {
            self.queue_deletes
        }

        fn delete_file(
            &self,
            path: &str,
            expected_source_id: &str,
            expected_source_etag: &str,
        ) -> Result<crate::vault_routes::VaultDeleteOutcome, CloudError> {
            if !self.queue_deletes {
                return Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "fixture delete capability is disabled",
                ));
            }
            let mut files = self.files.lock().unwrap();
            let (entry, bytes) = files
                .get(path)
                .cloned()
                .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "missing delete source"))?;
            if entry.directory
                || entry.id != expected_source_id
                || entry.etag != expected_source_etag
            {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "fixture delete identity changed",
                ));
            }
            files.remove(path);
            self.queued_delete_sources
                .lock()
                .unwrap()
                .insert(path.to_owned(), (entry, bytes));
            Ok(crate::vault_routes::VaultDeleteOutcome::Queued {
                write_id: "fixture-delete-id".into(),
                revision: 1,
                uncertain: false,
            })
        }
    }

    impl FakeBackend {
        fn with_file(path: &str, body: &[u8]) -> Self {
            let mut files = HashMap::new();
            files.insert(
                ("personal".into(), path.into()),
                (entry(path, body.len() as u64, "v1"), body.into()),
            );
            Self {
                files: Mutex::new(files),
                fail_upload: Mutex::new(false),
                spaces_override: Mutex::new(None),
                network_error: Mutex::new(None),
                root_ids: Mutex::new(HashMap::new()),
                list_calls: AtomicUsize::new(0),
                stat_calls: AtomicUsize::new(0),
            }
        }

        fn set_network_error(&self, error: Option<ErrorKind>) {
            *self.network_error.lock().expect("fake network state") = error;
        }

        fn add_space_entry(
            &self,
            space: &str,
            path: &str,
            body: &[u8],
            directory: bool,
            etag: &str,
        ) {
            let mut item = entry(path, body.len() as u64, etag);
            item.id = format!("{space}:{path}");
            item.directory = directory;
            self.files
                .lock()
                .expect("fake files")
                .insert((space.to_owned(), path.to_owned()), (item, body.to_vec()));
        }

        fn replace_root_id(&self, space: &str, id: &str) {
            self.root_ids
                .lock()
                .expect("fake roots")
                .insert(space.to_owned(), id.to_owned());
        }

        fn remove_space_entry(&self, space: &str, path: &str) {
            self.files
                .lock()
                .expect("fake files")
                .remove(&(space.to_owned(), path.to_owned()));
        }

        fn network_error(&self) -> Option<CloudError> {
            self.network_error
                .lock()
                .expect("fake network state")
                .map(|kind| CloudError::new(kind, "synthetic backend failure"))
        }

        fn replace_for_test(&self, path: &str, body: &[u8], etag: &str) {
            self.files.lock().expect("fake lock").insert(
                ("personal".into(), path.into()),
                (entry(path, body.len() as u64, etag), body.into()),
            );
        }
    }

    fn entry(path: &str, size: u64, etag: &str) -> RemoteEntry {
        RemoteEntry {
            id: path.into(),
            path: path.into(),
            directory: false,
            size,
            etag: etag.into(),
            modified_unix: 1,
            writable: true,
            encrypted: false,
        }
    }

    impl CloudBackend for FakeBackend {
        fn server_origin(&self) -> Option<String> {
            Some("https://example.invalid".into())
        }

        fn spaces(&self) -> Result<Vec<CloudSpace>, CloudError> {
            if let Some(error) = self.network_error() {
                return Err(error);
            }
            if let Some(spaces) = self.spaces_override.lock().expect("fake spaces").clone() {
                return Ok(spaces);
            }
            Ok(vec![CloudSpace {
                id: "personal".into(),
                name: "Personal".into(),
                dav_url: "https://example.invalid/dav".into(),
                personal: true,
                writable: true,
                encrypted: false,
            }])
        }

        fn list(
            &self,
            space: &str,
            path: &str,
            visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
        ) -> Result<(), CloudError> {
            self.list_calls.fetch_add(1, Ordering::Relaxed);
            if let Some(error) = self.network_error() {
                return Err(error);
            }
            let files = self.files.lock().expect("fake lock");
            for ((candidate_space, candidate_path), (item, _)) in files.iter() {
                if candidate_path == "/" {
                    continue;
                }
                if candidate_space == space
                    && candidate_path
                        .rsplit_once('/')
                        .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
                        == Some(path)
                {
                    visit(item.clone())?;
                }
            }
            Ok(())
        }

        fn stat(&self, space: &str, path: &str) -> Result<RemoteEntry, CloudError> {
            self.stat_calls.fetch_add(1, Ordering::Relaxed);
            if let Some(error) = self.network_error() {
                return Err(error);
            }
            if path == "/" {
                let id = self
                    .root_ids
                    .lock()
                    .expect("fake roots")
                    .get(space)
                    .cloned()
                    .unwrap_or_else(|| format!("{space}:root"));
                return Ok(RemoteEntry {
                    id,
                    path: "/".into(),
                    directory: true,
                    size: 0,
                    etag: "root-v1".into(),
                    modified_unix: 1,
                    writable: true,
                    encrypted: false,
                });
            }
            self.files
                .lock()
                .expect("fake lock")
                .get(&(space.into(), path.into()))
                .map(|(item, _)| item.clone())
                .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "missing"))
        }

        fn download(
            &self,
            space: &str,
            path: &str,
            expected_etag: Option<&str>,
            destination: &Path,
        ) -> Result<RemoteEntry, CloudError> {
            if let Some(error) = self.network_error() {
                return Err(error);
            }
            let files = self.files.lock().expect("fake lock");
            let (item, body) = files
                .get(&(space.into(), path.into()))
                .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "missing"))?;
            if expected_etag.is_some_and(|etag| etag != item.etag) {
                return Err(CloudError::new(ErrorKind::Conflict, "revision changed"));
            }
            fs::write(destination, body).map_err(io_cloud)?;
            Ok(item.clone())
        }

        fn upload(
            &self,
            space: &str,
            path: &str,
            source: &Path,
            condition: WriteCondition,
        ) -> Result<RemoteEntry, CloudError> {
            if *self.fail_upload.lock().expect("fake lock") {
                return Err(CloudError::new(ErrorKind::Offline, "fixture offline"));
            }
            let mut files = self.files.lock().expect("fake lock");
            let key = (space.into(), path.into());
            match (&condition, files.get(&key)) {
                (WriteCondition::Absent, Some(_)) => {
                    return Err(CloudError::new(ErrorKind::Conflict, "already exists"));
                }
                (WriteCondition::Match(expected), Some((current, _)))
                    if expected != &current.etag =>
                {
                    return Err(CloudError::new(ErrorKind::Conflict, "revision changed"));
                }
                (WriteCondition::Match(_), None) => {
                    return Err(CloudError::new(ErrorKind::Conflict, "missing"));
                }
                _ => {}
            }
            let body = fs::read(source).map_err(io_cloud)?;
            let item = entry(path, body.len() as u64, "v2");
            files.insert(key, (item.clone(), body));
            Ok(item)
        }

        fn upload_in_root(
            &self,
            space: &str,
            path: &str,
            source: &Path,
            condition: WriteCondition,
            root: &str,
        ) -> Result<RemoteEntry, CloudError> {
            if self.stat(space, "/")?.id != root {
                return Err(CloudError::new(ErrorKind::Conflict, "fixture root changed"));
            }
            self.upload(space, path, source, condition)
        }
        fn download_in_root(
            &self,
            space: &str,
            path: &str,
            etag: Option<&str>,
            destination: &Path,
            root: &str,
        ) -> Result<RemoteEntry, CloudError> {
            if self.stat(space, "/")?.id != root {
                return Err(CloudError::new(ErrorKind::Conflict, "fixture root changed"));
            }
            self.download(space, path, etag, destination)
        }
        fn mkdir(&self, _space: &str, _path: &str) -> Result<RemoteEntry, CloudError> {
            Err(CloudError::new(ErrorKind::Unsupported, "not needed"))
        }
        fn delete(&self, space: &str, path: &str, etag: &str) -> Result<(), CloudError> {
            let mut files = self.files.lock().expect("fake lock");
            match files.get(&(space.into(), path.into())) {
                Some((item, _)) if item.etag == etag => {
                    files.remove(&(space.into(), path.into()));
                    Ok(())
                }
                Some(_) => Err(CloudError::new(ErrorKind::Conflict, "revision changed")),
                None => Err(CloudError::new(ErrorKind::NotFound, "missing")),
            }
        }
        fn rename(
            &self,
            space: &str,
            from: &str,
            to: &str,
            etag: &str,
        ) -> Result<RemoteEntry, CloudError> {
            let mut files = self.files.lock().expect("fake lock");
            let source = files
                .get(&(space.into(), from.into()))
                .cloned()
                .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "missing"))?;
            if source.0.etag != etag {
                return Err(CloudError::new(ErrorKind::Conflict, "revision changed"));
            }
            if files.contains_key(&(space.into(), to.into())) {
                return Err(CloudError::new(ErrorKind::Conflict, "destination exists"));
            }
            files.remove(&(space.into(), from.into()));
            let mut renamed = source.0;
            renamed.path = to.into();
            renamed.id = to.into();
            renamed.etag = format!("{etag}-moved");
            files.insert((space.into(), to.into()), (renamed.clone(), source.1));
            Ok(renamed)
        }
    }

    fn filesystem_with_registry(
        temp: &tempfile::TempDir,
        backend: Arc<FakeBackend>,
        vault_registry: VaultMountRegistry,
    ) -> RaiunFilesystem {
        let engine = Engine::open(&temp.path().join("engine"), backend)
            .expect("engine")
            .with_account_scope("fuse-test-account".into(), "https://example.invalid".into())
            .expect("bind synthetic account scope");
        let spool = temp.path().join("spool");
        fs::create_dir_all(&spool).expect("spool directory");
        #[cfg(unix)]
        fs::set_permissions(&spool, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private spool directory");
        let owner = fs::metadata(temp.path()).expect("mount owner");
        RaiunFilesystem::new(
            engine,
            spool,
            owner.uid(),
            owner.gid(),
            "fuse-test-profile".into(),
            vault_registry,
            Arc::new(Mutex::new(None)),
        )
        .expect("filesystem")
    }

    fn filesystem(temp: &tempfile::TempDir, backend: Arc<FakeBackend>) -> RaiunFilesystem {
        filesystem_with_registry(temp, backend, VaultMountRegistry::new())
    }

    fn writable_vault_filesystem(
        temp: &tempfile::TempDir,
        vault_backend: Arc<FakeVaultWriteBackend>,
    ) -> (RaiunFilesystem, VaultRouteControl, u64, Node) {
        let ordinary = Arc::new(FakeBackend::with_file("/ordinary.txt", b"ordinary"));
        *ordinary.spaces_override.lock().unwrap() = Some(vec![
            CloudSpace {
                id: "personal".into(),
                name: "Personal".into(),
                dav_url: "https://example.invalid/dav/personal".into(),
                personal: true,
                writable: true,
                encrypted: false,
            },
            CloudSpace {
                id: "encrypted-space".into(),
                name: "Encrypted Space".into(),
                dav_url: "https://example.invalid/dav/encrypted".into(),
                personal: false,
                writable: true,
                encrypted: true,
            },
        ]);
        let control = VaultRouteControl::new();
        let generation = control
            .install_writable_backend(vault_backend)
            .expect("install synthetic writable vault backend");
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    "encrypted-space".into(),
                    "/".into(),
                    "vault-root-id".into(),
                    control.clone(),
                )
                .unwrap(),
            )
            .unwrap();
        let filesystem = filesystem_with_registry(temp, ordinary, registry);
        let root = filesystem
            .children(SPACES)
            .expect("Spaces listing")
            .into_iter()
            .find(|node| node.name == "Encrypted Space")
            .expect("registered encrypted Space root");
        (filesystem, control, generation, root)
    }

    fn offline_creatable_vault_filesystem(
        temp: &tempfile::TempDir,
        vault_backend: Arc<FakeVaultWriteBackend>,
    ) -> (RaiunFilesystem, VaultRouteControl, u64, Node) {
        let ordinary = Arc::new(FakeBackend::with_file("/ordinary.txt", b"ordinary"));
        *ordinary.spaces_override.lock().unwrap() = Some(vec![
            CloudSpace {
                id: "personal".into(),
                name: "Personal".into(),
                dav_url: "https://example.invalid/dav/personal".into(),
                personal: true,
                writable: true,
                encrypted: false,
            },
            CloudSpace {
                id: "encrypted-space".into(),
                name: "Encrypted Space".into(),
                dav_url: "https://example.invalid/dav/encrypted".into(),
                personal: false,
                writable: true,
                encrypted: true,
            },
        ]);
        let control = VaultRouteControl::new();
        let generation = control
            .install_existing_file_overwrite_backend(vault_backend)
            .expect("install synthetic offline create/overwrite route");
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    "encrypted-space".into(),
                    "/".into(),
                    "vault-root-id".into(),
                    control.clone(),
                )
                .unwrap(),
            )
            .unwrap();
        let filesystem = filesystem_with_registry(temp, ordinary, registry);
        let root = filesystem
            .children(SPACES)
            .expect("Spaces listing")
            .into_iter()
            .find(|node| node.name == "Encrypted Space")
            .expect("registered encrypted Space root");
        (filesystem, control, generation, root)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn vault_create_accepts_raw_linux_largefile_flag_and_rejects_unknown_bits() {
        let temp = tempfile::tempdir().expect("temp directory");
        let backend = Arc::new(FakeVaultWriteBackend::with_root());
        let (filesystem, control, generation, root) =
            writable_vault_filesystem(&temp, backend.clone());
        control
            .with_read_lease(generation, |lease| {
                let flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | 0x8000;
                let (_, fh) = filesystem
                    .create_vault_file(root.ino, "largefile.txt", flags, lease)
                    .expect("raw kernel O_LARGEFILE is a supported harmless flag");
                let handle = filesystem.file_handle(fh).expect("create handle");
                filesystem.commit_vault(&handle, lease, generation)?;
                let error = match filesystem.create_vault_file(
                    root.ino,
                    "unsupported.txt",
                    libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | 0x4000_0000,
                    lease,
                ) {
                    Err(error) => error,
                    Ok(_) => panic!("unknown flag bits must be rejected"),
                };
                assert_eq!(error.kind, ErrorKind::Unsupported);
                Ok(())
            })
            .expect("route remains active");
        assert_eq!(backend.stat("/largefile.txt").unwrap().size, 0);
        assert!(backend.stat("/unsupported.txt").is_err());
    }

    #[test]
    fn vault_create_flush_updates_same_handle_condition_and_conflict_retains_dirty_copy() {
        let temp = tempfile::tempdir().expect("temp directory");
        let backend = Arc::new(FakeVaultWriteBackend::with_root());
        let (filesystem, control, generation, root) =
            writable_vault_filesystem(&temp, backend.clone());
        let (created, fh) = control
            .with_read_lease(generation, |lease| {
                filesystem.create_vault_file(
                    root.ino,
                    "notes.txt",
                    libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                    lease,
                )
            })
            .expect("verified empty create");
        assert_eq!(created.name, "notes.txt");
        assert!(backend.stat("/notes.txt").is_err());

        let handle = filesystem.file_handle(fh).expect("writer handle");
        control
            .with_read_lease(generation, |lease| {
                {
                    let mut open = handle.lock().unwrap();
                    let OpenFile::VaultWrite(write) = &mut *open else {
                        panic!("expected vault writer")
                    };
                    write
                        .working
                        .write_at(0, b"hello", generation)
                        .expect("first write");
                    write.dirty = true;
                }
                filesystem.commit_vault(&handle, lease, generation)?;
                assert_eq!(
                    backend.files.lock().unwrap().get("/notes.txt").unwrap().1,
                    b"hello"
                );

                {
                    let mut open = handle.lock().unwrap();
                    let OpenFile::VaultWrite(write) = &mut *open else {
                        panic!("expected vault writer")
                    };
                    let mut current = [0; 5];
                    assert_eq!(
                        write
                            .working
                            .read_at(0, &mut current, generation)
                            .expect("read local working copy"),
                        5
                    );
                    assert_eq!(&current, b"hello");
                    let append_at = write.working.len(generation).expect("working length");
                    write
                        .working
                        .write_at(append_at, b" world", generation)
                        .expect("append second write");
                    write.dirty = true;
                }
                filesystem.commit_vault(&handle, lease, generation)?;
                assert_eq!(
                    backend.files.lock().unwrap().get("/notes.txt").unwrap().1,
                    b"hello world"
                );

                {
                    let mut open = handle.lock().unwrap();
                    let OpenFile::VaultWrite(write) = &mut *open else {
                        panic!("expected vault writer")
                    };
                    write
                        .working
                        .truncate(5, generation)
                        .expect("truncate working copy");
                    write
                        .working
                        .write_at(10, b"!", generation)
                        .expect("extend with a sparse hole");
                    let mut extended = [1; 11];
                    assert_eq!(
                        write
                            .working
                            .read_at(0, &mut extended, generation)
                            .expect("read extended working copy"),
                        11
                    );
                    assert_eq!(&extended, b"hello\0\0\0\0\0!");
                    write.dirty = true;
                }
                filesystem.commit_vault(&handle, lease, generation)?;
                assert_eq!(
                    backend.files.lock().unwrap().get("/notes.txt").unwrap().1,
                    b"hello\0\0\0\0\0!"
                );

                {
                    let mut files = backend.files.lock().unwrap();
                    let (entry, bytes) = files.get_mut("/notes.txt").unwrap();
                    entry.etag = "concurrent-version".into();
                    *bytes = b"remote edit".to_vec();
                    entry.size = bytes.len() as u64;
                }
                {
                    let mut open = handle.lock().unwrap();
                    let OpenFile::VaultWrite(write) = &mut *open else {
                        panic!("expected vault writer")
                    };
                    write
                        .working
                        .write_at(0, b"local conflict", generation)
                        .expect("third write");
                    write.dirty = true;
                }
                let error = filesystem
                    .commit_vault(&handle, lease, generation)
                    .expect_err("stale ETag must reject upload");
                assert_eq!(error.kind, ErrorKind::Conflict);
                Ok(())
            })
            .expect("route remains active");
        assert_eq!(
            backend.files.lock().unwrap().get("/notes.txt").unwrap().1,
            b"remote edit"
        );
        let pending = filesystem
            .vault_write_spool
            .as_ref()
            .unwrap()
            .list_pending()
            .expect("read recovery metadata");
        assert_eq!(pending.0.len(), 1);
        assert!(matches!(
            pending.0[0].lifecycle,
            Some(VaultWriteLifecycle::Dirty)
        ));
    }

    #[test]
    fn nested_queued_directory_nodes_keep_exact_parent_refs_for_file_creates() {
        let temp = tempfile::tempdir().expect("temp directory");
        let backend = Arc::new(FakeVaultWriteBackend::with_queued_nested_creates());
        let (filesystem, control, generation, root) =
            offline_creatable_vault_filesystem(&temp, backend.clone());

        let first_outcome = control
            .with_read_lease(generation, |lease| {
                let root_entry = lease.stat("/")?;
                let root_ref =
                    filesystem.vault_parent_ref(root.ino, generation, &root_entry, lease)?;
                lease.create_directory_under_parent("/first", &root_ref)
            })
            .expect("first queued directory");
        assert!(matches!(
            first_outcome,
            VaultDirectoryCreateOutcome::Queued { .. }
        ));
        let first = filesystem
            .children(root.ino)
            .expect("first folder projection")
            .into_iter()
            .find(|node| node.name == "first")
            .expect("first queued directory is listed");

        let second_outcome = control
            .with_read_lease(generation, |lease| {
                let first_entry = lease.stat("/first")?;
                let first_ref =
                    filesystem.vault_parent_ref(first.ino, generation, &first_entry, lease)?;
                assert!(matches!(first_ref, VaultParentRef::PendingCreate { .. }));
                lease.create_directory_under_parent("/first/second", &first_ref)
            })
            .expect("nested queued directory");
        assert!(matches!(
            second_outcome,
            VaultDirectoryCreateOutcome::Queued { .. }
        ));
        let second = filesystem
            .children(first.ino)
            .expect("nested folder projection")
            .into_iter()
            .find(|node| node.name == "second")
            .expect("nested queued directory is listed");
        let NodeKind::Vault {
            entry: mut stale_entry,
            ..
        } = second.kind.clone()
        else {
            panic!("expected nested vault directory node");
        };
        stale_entry.etag = "raiun-pending-v1-stale".into();
        let stale_ref_result = control.with_read_lease(generation, |lease| {
            filesystem.vault_parent_ref(second.ino, generation, &stale_entry, lease)
        });
        assert!(
            stale_ref_result.is_err(),
            "stale pending revision must not bind children"
        );

        let (_, handle_id) = control
            .with_read_lease(generation, |lease| {
                filesystem.create_vault_file(
                    second.ino,
                    "note.txt",
                    libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                    lease,
                )
            })
            .expect("file create below nested queued parent");
        let handle = filesystem
            .file_handle(handle_id)
            .expect("created writer handle");
        let open = handle.lock().expect("open handle lock");
        let OpenFile::VaultWrite(write) = &*open else {
            panic!("expected vault write handle");
        };
        assert_eq!(
            write.binding.target().parent_ref(),
            Some(&VaultParentRef::pending_create(format!("{:032x}", 2), 1).unwrap()),
            "the file's durable binding must name the exact nested directory receipt dependency"
        );
        drop(open);

        let refs = backend.directory_parent_refs.lock().unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0], VaultParentRef::stable("vault-root-id").unwrap());
        assert_eq!(
            refs[1],
            VaultParentRef::pending_create(format!("{:032x}", 1), 1).unwrap()
        );
    }

    #[test]
    fn never_attempted_empty_directory_rename_retargets_exact_revision() {
        let temp = tempfile::tempdir().expect("temp directory");
        let backend = Arc::new(FakeVaultWriteBackend::with_queued_nested_creates());
        let (filesystem, control, generation, root) =
            offline_creatable_vault_filesystem(&temp, backend.clone());
        control
            .with_read_lease(generation, |lease| {
                let root_entry = lease.stat("/")?;
                let parent = VaultParentRef::stable(root_entry.id.clone())
                    .map_err(|_| invalid("bad fixture root reference"))?;
                lease.create_directory_under_parent("/before", &parent)?;
                Ok(())
            })
            .expect("queue an empty directory");
        let before = filesystem
            .children(root.ino)
            .expect("list queued directory")
            .into_iter()
            .find(|node| node.name == "before")
            .expect("queued directory is projected");
        let NodeKind::Vault {
            entry: previous_entry,
            ..
        } = before.kind.clone()
        else {
            panic!("expected queued directory node");
        };

        control
            .with_read_lease(generation, |lease| {
                filesystem.rename_vault_with_lease(root.ino, "before", root.ino, "after", lease)
            })
            .expect("retarget the never-attempted empty directory");

        assert!(filesystem.child(root.ino, "before").is_err());
        let after = filesystem
            .child(root.ino, "after")
            .expect("renamed directory remains projected");
        let NodeKind::Vault { entry, .. } = &after.kind else {
            panic!("expected renamed vault directory");
        };
        let (write_id, revision) = pending_directory_identity(entry).unwrap();
        assert_eq!(revision, 2);
        assert_eq!(entry.path, "/after");
        assert_eq!(entry.id, previous_entry.id);
        assert!(backend.stat("/before").is_err());
        assert_eq!(backend.stat("/after").unwrap().etag, entry.etag);
        assert_eq!(backend.rename_calls.load(Ordering::Relaxed), 0);
        assert_eq!(backend.delete_calls.load(Ordering::Relaxed), 0);

        control
            .with_read_lease(generation, |lease| {
                let current = lease.stat("/after")?;
                assert_eq!(
                    current.etag,
                    format!("raiun-pending-v1:{write_id}:{revision}")
                );
                let current_ref =
                    filesystem.vault_parent_ref(after.ino, generation, &current, lease)?;
                assert_eq!(
                    current_ref,
                    VaultParentRef::pending_create(write_id.clone(), revision)
                        .map_err(|_| invalid("bad renamed parent reference"))?
                );
                assert!(
                    filesystem
                        .vault_parent_ref(after.ino, generation, &previous_entry, lease)
                        .is_err(),
                    "the previous revision must not bind future children"
                );
                Ok(())
            })
            .expect("route remains active");
    }

    #[test]
    fn pending_directory_rename_rejects_children_and_open_subtrees() {
        let temp = tempfile::tempdir().expect("temp directory");
        let backend = Arc::new(FakeVaultWriteBackend::with_queued_nested_creates());
        let (filesystem, control, generation, root) =
            offline_creatable_vault_filesystem(&temp, backend.clone());
        control
            .with_read_lease(generation, |lease| {
                let root_entry = lease.stat("/")?;
                let root_ref = VaultParentRef::stable(root_entry.id.clone())
                    .map_err(|_| invalid("bad fixture root reference"))?;
                lease.create_directory_under_parent("/parent", &root_ref)?;
                Ok(())
            })
            .expect("queue parent directory");
        let parent = filesystem
            .children(root.ino)
            .expect("list root")
            .into_iter()
            .find(|node| node.name == "parent")
            .expect("queued parent");
        control
            .with_read_lease(generation, |lease| {
                let parent_entry = lease.stat("/parent")?;
                let parent_ref =
                    filesystem.vault_parent_ref(parent.ino, generation, &parent_entry, lease)?;
                lease.create_directory_under_parent("/parent/child", &parent_ref)?;
                Ok(())
            })
            .expect("queue dependent child");
        let error = control
            .with_read_lease(generation, |lease| {
                filesystem.rename_vault_with_lease(root.ino, "parent", root.ino, "moved", lease)
            })
            .expect_err("backend without subtree-retarget support must reject populated moves");
        assert_eq!(error.kind, ErrorKind::Unsupported);
        assert!(backend.stat("/parent").unwrap().directory);
        assert!(backend.stat("/parent/child").unwrap().directory);

        let empty_temp = tempfile::tempdir().expect("second temp directory");
        let empty_backend = Arc::new(FakeVaultWriteBackend::with_queued_nested_creates());
        let (empty_fs, empty_control, empty_generation, empty_root) =
            offline_creatable_vault_filesystem(&empty_temp, empty_backend);
        empty_control
            .with_read_lease(empty_generation, |lease| {
                let root_entry = lease.stat("/")?;
                let root_ref = VaultParentRef::stable(root_entry.id.clone())
                    .map_err(|_| invalid("bad fixture root reference"))?;
                lease.create_directory_under_parent("/empty", &root_ref)?;
                Ok(())
            })
            .expect("queue empty directory");
        let empty = empty_fs
            .children(empty_root.ino)
            .expect("list root")
            .into_iter()
            .find(|node| node.name == "empty")
            .expect("empty queued directory");
        let (empty_route, empty_path) = match &empty.kind {
            NodeKind::Vault { route, entry, .. } => (route.clone(), entry.path.clone()),
            _ => panic!("expected vault node"),
        };
        empty_fs
            .register_directory_handle(
                9901,
                DirectoryHandle {
                    entries: Vec::new(),
                    routes: vec![(empty_route.control.clone(), empty_generation)],
                    locked_vaults: Vec::new(),
                    owner_vault: Some((
                        empty_control.route_id(),
                        empty_generation,
                        empty.ino,
                        empty_path.clone(),
                    )),
                },
            )
            .expect("open the queued directory");
        let open_handle_blocked = empty_control
            .with_read_lease(empty_generation, |lease| {
                empty_fs.rename_vault_with_lease(
                    empty_root.ino,
                    "empty",
                    empty_root.ino,
                    "moved",
                    lease,
                )
            })
            .expect_err("an open directory handle blocks rename");
        assert_eq!(open_handle_blocked.kind, ErrorKind::Conflict);
        empty_fs
            .state
            .lock()
            .unwrap()
            .directory_handles
            .remove(&9901);
        let NodeKind::Vault { entry, .. } = &empty.kind else {
            panic!("expected vault node");
        };
        let reservation = empty_fs
            .reserve_pending_directory_cancel(empty_control.route_id(), &entry.path)
            .expect("reserve overlapping subtree");
        let blocked = empty_control
            .with_read_lease(empty_generation, |lease| {
                empty_fs.rename_vault_with_lease(
                    empty_root.ino,
                    "empty",
                    empty_root.ino,
                    "moved",
                    lease,
                )
            })
            .expect_err("an overlapping reservation blocks rename");
        assert_eq!(blocked.kind, ErrorKind::Conflict);
        drop(reservation);
        empty_control
            .with_read_lease(empty_generation, |lease| {
                empty_fs.rename_vault_with_lease(
                    empty_root.ino,
                    "empty",
                    empty_root.ino,
                    "moved",
                    lease,
                )
            })
            .expect("rename after reservation release");
    }

    #[test]
    fn never_attempted_directory_cancel_requires_closed_handle_and_exact_pending_identity() {
        let temp = tempfile::tempdir().expect("temp directory");
        let backend = Arc::new(FakeVaultWriteBackend::with_queued_nested_creates());
        let (filesystem, control, generation, root) =
            offline_creatable_vault_filesystem(&temp, backend.clone());
        let (directory, write_id, revision) = control
            .with_read_lease(generation, |lease| {
                let root_entry = lease.stat("/")?;
                let parent_ref = VaultParentRef::stable(root_entry.id.clone()).unwrap();
                let VaultDirectoryCreateOutcome::Queued {
                    entry,
                    write_id,
                    revision,
                    ..
                } = lease.create_directory_under_parent("/pending", &parent_ref)?
                else {
                    panic!("fixture should queue a local directory intent");
                };
                Ok((entry, write_id, revision))
            })
            .expect("queue local directory");
        assert_eq!(directory.id, format!("raiun-pending-directory:{write_id}"));
        assert_eq!(
            directory.etag,
            format!("raiun-pending-v1:{write_id}:{revision}")
        );
        let route = match &root.kind {
            NodeKind::Vault { route, .. } => route.clone(),
            _ => unreachable!(),
        };
        let dir_ino = filesystem
            .add_node(
                root.ino,
                "pending".into(),
                NodeKind::Vault {
                    route: route.clone(),
                    generation,
                    entry: directory.clone(),
                },
            )
            .expect("materialize pending directory");
        filesystem
            .remember_pending_parent_ref(
                dir_ino,
                generation,
                VaultParentRef::pending_create(write_id.clone(), revision).unwrap(),
            )
            .expect("bind exact parent operation");

        control
            .with_read_lease(generation, |lease| {
                let handle = DirectoryHandle {
                    entries: vec![(".".into(), dir_ino, FileType::Directory)],
                    routes: vec![(control.clone(), generation)],
                    locked_vaults: Vec::new(),
                    owner_vault: Some((
                        control.route_id(),
                        generation,
                        dir_ino,
                        directory.path.clone(),
                    )),
                };
                filesystem.register_directory_handle(700, handle)?;
                let open_error = filesystem
                    .delete_vault_child_with_lease(root.ino, "pending", true, lease)
                    .expect_err("an open directory handle blocks cancellation");
                assert_eq!(open_error.kind, ErrorKind::Conflict, "{open_error:?}");
                assert!(backend.cancelled_directories.lock().unwrap().is_empty());
                filesystem
                    .state
                    .lock()
                    .unwrap()
                    .directory_handles
                    .remove(&700);

                filesystem.delete_vault_child_with_lease(root.ino, "pending", true, lease)?;
                Ok(())
            })
            .expect("never-attempted intent cancels after final handle closes");
        assert_eq!(
            backend.cancelled_directories.lock().unwrap().as_slice(),
            &[(
                "/pending".into(),
                write_id,
                revision,
                directory.id,
                directory.etag,
            )]
        );
        assert_eq!(backend.delete_calls.load(Ordering::Relaxed), 0);
        assert!(filesystem.child(root.ino, "pending").is_err());
    }

    #[test]
    fn never_attempted_file_create_cancel_is_receipt_gated_and_retries_cas_safely() {
        let temp = tempfile::tempdir().expect("temp directory");
        let backend = Arc::new(FakeVaultWriteBackend::with_queued_nested_creates());
        let (filesystem, control, generation, root) =
            offline_creatable_vault_filesystem(&temp, backend.clone());
        let operation_id = "b".repeat(32);
        let contents = b"unsent local bytes";
        let (entry, record_id, child_ino) = control
            .with_read_lease(generation, |lease| {
                let root_entry = lease.stat("/")?;
                let parent = VaultParentRef::stable(root_entry.id.clone())
                    .map_err(|_| invalid("bad fixture parent"))?;
                let (scope, target) =
                    lease.prepare_file_create_under_parent("/cancel.txt", &parent, None)?;
                let binding = VaultWriteBinding::new(scope, target.clone(), generation)
                    .map_err(vault_write_error)?;
                let mut initial = Cursor::new(contents.to_vec());
                let spool = filesystem.vault_write_spool.as_ref().unwrap();
                let mut working = spool
                    .begin(binding, &mut initial, generation)
                    .map_err(vault_write_error)?;
                let record_id = working.record_id().to_owned();
                working
                    .record_building_create(generation, &operation_id, 1)
                    .map_err(vault_write_error)?;
                let outcome = working
                    .commit_snapshot_outcome(generation, |source, length| {
                        lease.create_file(&target, source, length, Some((&operation_id, 1)))
                    })
                    .map_err(vault_write_error)?;
                let VaultUploadOutcome::QueuedCreate {
                    entry,
                    write_id,
                    revision,
                    uncertain: false,
                } = outcome
                else {
                    panic!("fixture should publish a never-attempted queued create");
                };
                assert_eq!(write_id, operation_id);
                assert_eq!(revision, 2);
                drop(working);
                let child_ino = filesystem.add_node(
                    root.ino,
                    "cancel.txt".into(),
                    NodeKind::Vault {
                        route: match &root.kind {
                            NodeKind::Vault { route, .. } => route.clone(),
                            _ => unreachable!(),
                        },
                        generation,
                        entry: entry.clone(),
                    },
                )?;
                Ok((entry, record_id, child_ino))
            })
            .expect("seed exact queued local create");
        assert_eq!(entry.id, format!("raiun-pending-create:{operation_id}"));
        assert_eq!(entry.etag, format!("raiun-pending-v1:{operation_id}:2"));
        let route = match &root.kind {
            NodeKind::Vault { route, .. } => route.clone(),
            _ => unreachable!(),
        };

        let route_id = control.route_id();
        control
            .with_read_lease(generation, |lease| {
                filesystem.state.lock().unwrap().vault_file_handles.insert(
                    991,
                    VaultFileHandleMeta {
                        route_id,
                        ino: child_ino,
                        path: entry.path.clone(),
                        writable: false,
                    },
                );
                let child = filesystem.node(child_ino)?;
                let open_error = filesystem
                    .cancel_pending_file_create_with_lease(&child, &route, generation, lease)
                    .expect_err("an open reader or writer blocks cancellation");
                assert_eq!(open_error.kind, ErrorKind::Conflict, "{open_error:?}");
                assert_eq!(backend.file_cancel_calls.load(Ordering::Relaxed), 0);
                filesystem
                    .state
                    .lock()
                    .unwrap()
                    .vault_file_handles
                    .remove(&991);

                *backend.fail_file_cancel.lock().unwrap() = true;
                let cas_error = filesystem
                    .cancel_pending_file_create_with_lease(&child, &route, generation, lease)
                    .expect_err("attempt-claim CAS race must retain local data");
                assert_eq!(cas_error.kind, ErrorKind::Conflict);
                let (rows, _) = filesystem
                    .vault_write_spool
                    .as_ref()
                    .unwrap()
                    .list_pending()
                    .unwrap();
                assert!(rows.iter().any(|row| row.record_id == record_id));
                let cancellations = filesystem
                    .vault_write_spool
                    .as_ref()
                    .unwrap()
                    .list_create_cancellations()
                    .unwrap();
                let spool = filesystem.vault_write_spool.as_ref().unwrap();
                assert_eq!(cancellations.len(), 1);
                assert!(!cancellations[0].local_retired);
                assert_eq!(backend.delete_calls.load(Ordering::Relaxed), 0);

                *backend.fail_file_cancel.lock().unwrap() = false;
                let cancellation = cancellations.into_iter().next().unwrap();
                let receipt = lease.cancel_never_attempted_file_create(
                    &cancellation.path,
                    &cancellation.write_id,
                    cancellation.revision,
                    &format!("raiun-pending-create:{}", cancellation.write_id),
                    &format!(
                        "raiun-pending-v1:{}:{}",
                        cancellation.write_id, cancellation.revision
                    ),
                )?;
                let binding = VaultWriteBinding::new(
                    cancellation.scope.clone(),
                    cancellation.target.clone(),
                    generation,
                )
                .map_err(vault_write_error)?;
                let working = filesystem
                    .vault_write_spool
                    .as_ref()
                    .unwrap()
                    .recover(&record_id, binding, generation)
                    .map_err(vault_write_error)?;
                assert!(
                    working
                        .retire_cancelled_create_if_unchanged(
                            generation,
                            &cancellation.write_id,
                            cancellation.revision,
                            &receipt.content,
                        )
                        .map_err(vault_write_error)?
                );
                let cancellation = spool
                    .mark_create_cancellation_local_retired(&cancellation)
                    .map_err(vault_write_error)?;
                let wal = filesystem
                    .vault_write_spool
                    .as_ref()
                    .unwrap()
                    .list_create_cancellations()
                    .map_err(vault_write_error)?;
                assert_eq!(wal.len(), 1);
                assert!(wal[0].local_retired);
                lease.acknowledge_cancelled_file_create(
                    &cancellation.write_id,
                    cancellation.revision,
                    &receipt.target,
                    &receipt.content,
                )?;
                let acknowledged = lease
                    .resolve_cancelled_file_create(&cancellation.write_id, cancellation.revision)?
                    .expect("acknowledged receipt remains until the WAL is removed");
                assert_eq!(
                    acknowledged.state,
                    VaultCancelledCreateReceiptState::Acknowledged
                );
                lease.acknowledge_cancelled_file_create(
                    &cancellation.write_id,
                    cancellation.revision,
                    &receipt.target,
                    &receipt.content,
                )?;
                let repeated_ack = lease
                    .resolve_cancelled_file_create(&cancellation.write_id, cancellation.revision)?
                    .expect("repeated ack preserves the compact proof");
                assert_eq!(repeated_ack, acknowledged);

                let mut mismatched = acknowledged.clone();
                let replacement = if mismatched.content.sha256.starts_with('0') {
                    "1"
                } else {
                    "0"
                };
                mismatched.content.sha256.replace_range(0..1, replacement);
                backend
                    .cancelled_file_receipts
                    .lock()
                    .unwrap()
                    .insert(cancellation.write_id.clone(), mismatched);
                let mismatch_error = filesystem
                    .complete_pending_create_cancellation(
                        &route,
                        generation,
                        lease,
                        spool,
                        cancellation.clone(),
                    )
                    .expect_err("mismatched terminal proof must retain the WAL");
                assert_eq!(mismatch_error.kind, ErrorKind::Conflict);
                assert_eq!(
                    spool
                        .list_create_cancellations()
                        .map_err(vault_write_error)?
                        .len(),
                    1
                );
                backend
                    .cancelled_file_receipts
                    .lock()
                    .unwrap()
                    .insert(cancellation.write_id.clone(), acknowledged);
                let restarted_spool = VaultWriteSpool::open_existing(&temp.path().join("spool"))
                    .unwrap()
                    .expect("durable spool survives restart");
                assert!(filesystem.complete_pending_create_cancellation(
                    &route,
                    generation,
                    lease,
                    &restarted_spool,
                    cancellation,
                )?);
                Ok(())
            })
            .expect("exact cancellation receipt can complete after a CAS retry");
        assert_eq!(backend.file_cancel_calls.load(Ordering::Relaxed), 2);
        assert_eq!(backend.delete_calls.load(Ordering::Relaxed), 0);
        assert!(backend.cancelled_file_receipts.lock().unwrap().is_empty());
        assert!(filesystem.child(root.ino, "cancel.txt").is_err());
        let spool = filesystem.vault_write_spool.as_ref().unwrap();
        assert!(spool.list_pending().unwrap().0.is_empty());
        assert!(spool.list_create_cancellations().unwrap().is_empty());
        assert!(!spool.root().join(&record_id).exists());
    }

    #[test]
    fn cancel_reservation_and_opendir_registration_are_serialized() {
        let temp = tempfile::tempdir().expect("temp directory");
        let backend = Arc::new(FakeVaultWriteBackend::with_queued_nested_creates());
        let (filesystem, control, generation, _root) =
            offline_creatable_vault_filesystem(&temp, backend);
        let directory = RemoteEntry {
            id: "raiun-pending-directory:0123456789abcdef0123456789abcdef".into(),
            path: "/pending".into(),
            directory: true,
            size: 0,
            etag: "raiun-pending-v1:0123456789abcdef0123456789abcdef:1".into(),
            modified_unix: 0,
            writable: false,
            encrypted: true,
        };
        let handle = || DirectoryHandle {
            entries: vec![(".".into(), 999, FileType::Directory)],
            routes: vec![(control.clone(), generation)],
            locked_vaults: Vec::new(),
            owner_vault: Some((control.route_id(), generation, 999, directory.path.clone())),
        };

        let child_writer = filesystem
            .reserve_vault_path(control.route_id(), "/pending/note.txt")
            .expect("reserve descendant writer");
        assert!(
            filesystem
                .reserve_pending_directory_cancel(control.route_id(), &directory.path)
                .is_err()
        );
        drop(child_writer);

        // Cancellation wins first: its subtree marker prevents opendir from
        // registering a handle after the backend has checked open handles.
        let reservation = filesystem
            .reserve_pending_directory_cancel(control.route_id(), &directory.path)
            .expect("reserve empty subtree");
        let open_error = filesystem
            .register_directory_handle(701, handle())
            .expect_err("opendir cannot race past cancellation reservation");
        assert_eq!(open_error.kind, ErrorKind::Conflict);
        drop(reservation);

        // Opendir wins first: the registered owner blocks cancellation until
        // Releasedir removes the handle; no timing or sleeps are involved.
        filesystem
            .register_directory_handle(702, handle())
            .expect("register open directory handle");
        let cancel_error = match filesystem
            .reserve_pending_directory_cancel(control.route_id(), &directory.path)
        {
            Err(error) => error,
            Ok(reservation) => {
                drop(reservation);
                panic!("open directory handle blocks cancellation reservation");
            }
        };
        assert_eq!(cancel_error.kind, ErrorKind::Conflict);
        filesystem
            .state
            .lock()
            .unwrap()
            .directory_handles
            .remove(&702);
        let reservation = filesystem
            .reserve_pending_directory_cancel(control.route_id(), &directory.path)
            .expect("closed handle permits cancellation reservation");
        drop(reservation);
    }

    #[test]
    fn offline_vault_create_flush_preserves_absent_and_revises_same_operation() {
        let temp = tempfile::tempdir().expect("temp directory");
        let backend = Arc::new(FakeVaultWriteBackend::with_queued_nested_creates());
        let (filesystem, control, generation, root) =
            offline_creatable_vault_filesystem(&temp, backend.clone());
        let (created, fh) = control
            .with_read_lease(generation, |lease| {
                filesystem.create_vault_file(
                    root.ino,
                    "offline.txt",
                    libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                    lease,
                )
            })
            .expect("offline create intent is durable before reply");
        assert_eq!(created.name, "offline.txt");
        let NodeKind::Vault { entry, .. } = &created.kind else {
            panic!("expected encrypted created node")
        };
        assert_eq!(entry.path, "/offline.txt");
        assert_eq!(entry.size, 0);
        assert_eq!(
            filesystem
                .building_create_size(created.ino, generation)
                .expect("local BuildingCreate size remains available"),
            Some(0)
        );
        let handle = filesystem.file_handle(fh).expect("writer handle");
        control
            .with_read_lease(generation, |lease| {
                {
                    let mut open = handle.lock().unwrap();
                    let OpenFile::VaultWrite(write) = &mut *open else {
                        panic!("expected vault writer")
                    };
                    assert_eq!(write.condition, WriteCondition::Absent);
                    assert_eq!(write.binding.target().condition(), &WriteCondition::Absent);
                    assert!(matches!(
                        write.working.lifecycle(),
                        VaultWriteLifecycle::BuildingCreate { revision: 1, .. }
                    ));
                    write
                        .working
                        .write_at(0, b"offline bytes", generation)
                        .expect("write same handle");
                    write.dirty = true;
                }
                assert_eq!(
                    filesystem
                        .building_create_size(created.ino, generation)
                        .expect("dirty BuildingCreate size remains available"),
                    Some(b"offline bytes".len() as u64)
                );
                filesystem.commit_vault(&handle, lease, generation)?;
                assert_eq!(
                    filesystem
                        .building_create_size(created.ino, generation)
                        .expect("queued create is no longer a BuildingCreate placeholder"),
                    None
                );
                {
                    let mut open = handle.lock().unwrap();
                    let OpenFile::VaultWrite(write) = &mut *open else {
                        panic!("expected vault writer")
                    };
                    assert_eq!(write.condition, WriteCondition::Absent);
                    assert_eq!(write.binding.target().condition(), &WriteCondition::Absent);
                    assert!(matches!(
                        write.working.lifecycle(),
                        VaultWriteLifecycle::Queued { revision: 2, .. }
                    ));
                    write
                        .working
                        .write_at(0, b"offline final", generation)
                        .expect("revise same queued create");
                    write.dirty = true;
                }
                filesystem.commit_vault(&handle, lease, generation)?;
                let open = handle.lock().unwrap();
                let OpenFile::VaultWrite(write) = &*open else {
                    panic!("expected vault writer")
                };
                assert!(matches!(
                    write.working.lifecycle(),
                    VaultWriteLifecycle::Queued { revision: 3, .. }
                ));
                Ok(())
            })
            .expect("queued create remains mounted");
        let calls = backend.create_calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], Some(("c".repeat(32), 1)));
        assert_eq!(calls[1], Some(("c".repeat(32), 2)));
        let records = filesystem
            .vault_write_spool
            .as_ref()
            .unwrap()
            .list_pending()
            .expect("local recovery journal remains visible")
            .0;
        assert_eq!(records.len(), 1);
        assert!(matches!(
            records[0].lifecycle,
            Some(VaultWriteLifecycle::Queued { revision: 3, .. })
        ));
    }

    #[test]
    fn vault_rename_replacement_restores_backup_after_source_move_failure() {
        let temp = tempfile::tempdir().expect("temp directory");
        let backend = Arc::new(FakeVaultWriteBackend::with_root());
        backend.seed_file("/source.txt", b"new", "source-v1", true);
        backend.seed_file("/destination.txt", b"old", "destination-v1", true);
        *backend.fail_rename_call.lock().unwrap() = Some(2);
        let (filesystem, control, generation, root) =
            writable_vault_filesystem(&temp, backend.clone());
        filesystem.children(root.ino).expect("initial root listing");
        let error = control
            .with_read_lease(generation, |lease| {
                filesystem.rename_vault_with_lease(
                    root.ino,
                    "source.txt",
                    root.ino,
                    "destination.txt",
                    lease,
                )
            })
            .expect_err("injected source move should fail");
        assert_eq!(error.kind, ErrorKind::Offline);
        let files = backend.files.lock().unwrap();
        assert_eq!(files.get("/source.txt").unwrap().1, b"new");
        assert_eq!(files.get("/destination.txt").unwrap().1, b"old");
        assert!(!files.keys().any(|path| path.contains("raiun-recovery")));
    }

    #[test]
    fn vault_directory_rename_preserves_type_and_refreshes_cached_children() {
        let temp = tempfile::tempdir().expect("temp directory");
        let backend = Arc::new(FakeVaultWriteBackend::with_root());
        let (filesystem, control, generation, root) =
            writable_vault_filesystem(&temp, backend.clone());
        let route = match &root.kind {
            NodeKind::Vault { route, .. } => route.clone(),
            _ => unreachable!(),
        };
        control
            .with_read_lease(generation, |lease| {
                let directory = lease.mkdir("/old-directory")?;
                filesystem.add_node(
                    root.ino,
                    "old-directory".into(),
                    NodeKind::Vault {
                        route: route.clone(),
                        generation,
                        entry: directory,
                    },
                )?;
                let old_directory = filesystem.child(root.ino, "old-directory")?;
                let child = lease.mkdir("/old-directory/child")?;
                filesystem.add_node(
                    old_directory.ino,
                    "child".into(),
                    NodeKind::Vault {
                        route: route.clone(),
                        generation,
                        entry: child,
                    },
                )?;
                let cached_child = filesystem.child(old_directory.ino, "child")?;
                filesystem.rename_vault_with_lease(
                    root.ino,
                    "old-directory",
                    root.ino,
                    "new-directory",
                    lease,
                )?;
                assert!(backend.stat("/new-directory").unwrap().directory);
                assert!(backend.stat("/new-directory/child").unwrap().directory);
                assert!(filesystem.child(root.ino, "old-directory").is_err());
                assert!(filesystem.node(cached_child.ino).is_err());
                let new_directory = filesystem.child(root.ino, "new-directory")?;
                let refreshed = filesystem.children_with_lease(new_directory.ino, Some(lease))?;
                let refreshed_child = refreshed
                    .iter()
                    .find(|node| node.name == "child")
                    .expect("moved directory child is relisted");
                assert!(matches!(
                    &refreshed_child.kind,
                    NodeKind::Vault { entry, .. } if entry.path == "/new-directory/child"
                ));
                Ok(())
            })
            .expect("route remains active");
    }

    #[test]
    fn offline_vault_file_rename_updates_local_namespace_without_replacing_destination() {
        let temp = tempfile::tempdir().expect("temp directory");
        let backend = Arc::new(FakeVaultWriteBackend::with_queued_renames());
        backend.seed_file("/source.txt", b"source bytes", "source-v1", true);
        backend.seed_file("/occupied.txt", b"keep this", "occupied-v1", true);
        let (filesystem, control, generation, root) =
            offline_creatable_vault_filesystem(&temp, backend.clone());
        filesystem
            .children(root.ino)
            .expect("initial vault listing");

        control
            .with_read_lease(generation, |lease| {
                filesystem.rename_vault_with_lease(
                    root.ino,
                    "source.txt",
                    root.ino,
                    "renamed.txt",
                    lease,
                )?;
                assert!(filesystem.child(root.ino, "source.txt").is_err());
                let renamed = filesystem.child(root.ino, "renamed.txt")?;
                assert!(matches!(
                    &renamed.kind,
                    NodeKind::Vault { entry, .. }
                        if entry.path == "/renamed.txt" && entry.id == "id:/source.txt"
                ));
                assert_eq!(
                    backend.stat("/renamed.txt")?.size,
                    b"source bytes".len() as u64
                );

                let error = filesystem
                    .rename_vault_with_lease(
                        root.ino,
                        "renamed.txt",
                        root.ino,
                        "occupied.txt",
                        lease,
                    )
                    .expect_err("offline rename must never replace an existing target");
                assert_eq!(error.kind, ErrorKind::Conflict);
                assert_eq!(backend.stat("/renamed.txt")?.id, "id:/source.txt");
                assert_eq!(backend.stat("/occupied.txt")?.id, "id:/occupied.txt");
                Ok(())
            })
            .expect("route remains unlocked for local overlay assertions");
    }

    #[test]
    fn encrypted_stable_file_rename_keeps_an_open_reader_snapshot_usable() {
        let temp = tempfile::tempdir().expect("temp directory");
        let backend = Arc::new(FakeVaultWriteBackend::with_queued_renames());
        backend.seed_file("/source.txt", b"snapshot bytes", "source-v1", true);
        let (filesystem, control, generation, root) =
            offline_creatable_vault_filesystem(&temp, backend);
        filesystem.children(root.ino).expect("initial root listing");
        let source = filesystem
            .child(root.ino, "source.txt")
            .expect("source file");

        control
            .with_read_lease(generation, |lease| {
                let read = lease.open("/source.txt")?;
                let fh = filesystem.register_handle(OpenFile::Vault {
                    route: control.clone(),
                    generation,
                    ino: source.ino,
                    path: "/source.txt".into(),
                    handle: Some(read),
                })?;

                filesystem.rename_vault_with_lease(
                    root.ino,
                    "source.txt",
                    root.ino,
                    "renamed.txt",
                    lease,
                )?;

                let open = filesystem.file_handle(fh)?;
                let mut open = open
                    .lock()
                    .map_err(|_| io_error("open file state is unavailable"))?;
                let OpenFile::Vault {
                    handle: Some(read), ..
                } = &mut *open
                else {
                    return Err(invalid("reader handle disappeared after rename"));
                };
                assert_eq!(lease.read(read, 0, 64)?, b"snapshot bytes");
                Ok(())
            })
            .expect("stable-file rename should preserve an already-open reader");
    }

    #[test]
    fn never_attempted_queued_create_rename_rebinds_same_recovery_copy() {
        let temp = tempfile::tempdir().expect("temp directory");
        let backend = Arc::new(FakeVaultWriteBackend::with_queued_nested_creates());
        let operation_id = "e".repeat(32);
        let original_entry = RemoteEntry {
            id: format!("raiun-pending-create:{operation_id}"),
            path: "/source.txt".into(),
            directory: false,
            size: 11,
            etag: format!("raiun-pending-v1:{operation_id}:2"),
            modified_unix: 0,
            writable: true,
            encrypted: false,
        };
        backend.files.lock().unwrap().insert(
            "/source.txt".into(),
            (original_entry.clone(), b"local bytes".to_vec()),
        );
        let (filesystem, control, generation, root) =
            offline_creatable_vault_filesystem(&temp, backend.clone());
        control
            .with_read_lease(generation, |lease| {
                let root_entry = lease.stat("/")?;
                let parent =
                    filesystem.vault_parent_ref(root.ino, generation, &root_entry, lease)?;
                lease.create_directory_under_parent("/folder", &parent)?;
                Ok(())
            })
            .expect("queue destination directory");
        filesystem
            .children(root.ino)
            .expect("initial vault listing");
        let folder = filesystem
            .child(root.ino, "folder")
            .expect("pending destination directory");
        let source_node = filesystem
            .child(root.ino, "source.txt")
            .expect("pending create source inode");

        let spool = filesystem.vault_write_spool.as_ref().unwrap();
        let scope = VaultWriteScope::new(
            "account-a",
            "https://example.invalid",
            "encrypted-space",
            "vault-root-id",
        )
        .unwrap();
        let source_target = VaultWriteTarget::new_with_parent(
            "source.txt",
            WriteCondition::Absent,
            VaultParentRef::stable("vault-root-id").unwrap(),
        )
        .unwrap();
        let binding = VaultWriteBinding::new(scope, source_target, generation).unwrap();
        let mut empty = Cursor::new(Vec::<u8>::new());
        let mut working = spool.begin(binding, &mut empty, generation).unwrap();
        let record_id = working.record_id().to_owned();
        working
            .record_building_create(generation, &operation_id, 1)
            .unwrap();
        working.write_at(0, b"local bytes", generation).unwrap();
        working
            .commit_snapshot_outcome(generation, |_source, _length| {
                Ok(VaultUploadOutcome::QueuedCreate {
                    entry: original_entry.clone(),
                    write_id: operation_id.clone(),
                    revision: 2,
                    uncertain: false,
                })
            })
            .unwrap();
        drop(working);

        let reader = filesystem
            .register_handle(OpenFile::Vault {
                route: control.clone(),
                generation,
                ino: source_node.ino,
                path: "/source.txt".into(),
                handle: None,
            })
            .unwrap();
        let blocked = control
            .with_read_lease(generation, |lease| {
                filesystem.rename_vault_with_lease(
                    root.ino,
                    "source.txt",
                    folder.ino,
                    "renamed.txt",
                    lease,
                )
            })
            .expect_err("open readers fence pending-create retarget");
        assert_eq!(blocked.kind, ErrorKind::Conflict);
        assert_eq!(
            backend.pending_create_rename_calls.load(Ordering::Relaxed),
            0,
            "backend must not change the journal while a source reader is open"
        );
        filesystem
            .state
            .lock()
            .unwrap()
            .file_handles
            .remove(&reader);
        filesystem
            .state
            .lock()
            .unwrap()
            .vault_file_handles
            .remove(&reader);

        control
            .with_read_lease(generation, |lease| {
                filesystem.rename_vault_with_lease(
                    root.ino,
                    "source.txt",
                    folder.ino,
                    "renamed.txt",
                    lease,
                )?;
                assert!(filesystem.child(root.ino, "source.txt").is_err());
                let renamed = filesystem.child(folder.ino, "renamed.txt")?;
                assert!(matches!(
                    &renamed.kind,
                    NodeKind::Vault { entry, .. }
                        if entry.id == original_entry.id
                            && entry.path == "/folder/renamed.txt"
                            && entry.etag == format!("raiun-pending-v1:{operation_id}:3")
                ));
                Ok(())
            })
            .expect("never-attempted pending create can be safely retargeted");
        assert_eq!(
            backend.pending_create_rename_calls.load(Ordering::Relaxed),
            1
        );
        let (records, _) = spool.list_pending().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_id, record_id);
        assert_eq!(
            records[0].target.as_ref().unwrap().parent_ref(),
            Some(&VaultParentRef::pending_create(format!("{:032x}", 1), 1).unwrap())
        );
        assert!(matches!(
            records[0].lifecycle.as_ref(),
            Some(VaultWriteLifecycle::Queued { write_id, revision: 3, uncertain: false, bytes: 11, .. })
                if write_id == &operation_id
        ));
        let recovered_binding = VaultWriteBinding::new(
            records[0].scope.clone().unwrap(),
            records[0].target.clone().unwrap(),
            generation + 1,
        )
        .unwrap();
        let mut recovered = spool
            .recover(&record_id, recovered_binding, generation + 1)
            .unwrap();
        let mut bytes = vec![0; 11];
        recovered.read_at(0, &mut bytes, generation + 1).unwrap();
        assert_eq!(&bytes, b"local bytes");
    }

    #[test]
    fn queued_create_retarget_recovers_after_crash_between_backend_cas_and_manifest() {
        let temp = tempfile::tempdir().expect("temp directory");
        let backend = Arc::new(FakeVaultWriteBackend::with_queued_nested_creates());
        let operation_id = "f".repeat(32);
        let original_entry = RemoteEntry {
            id: format!("raiun-pending-create:{operation_id}"),
            path: "/source.txt".into(),
            directory: false,
            size: 11,
            etag: format!("raiun-pending-v1:{operation_id}:2"),
            modified_unix: 0,
            writable: true,
            encrypted: false,
        };
        backend.files.lock().unwrap().insert(
            "/source.txt".into(),
            (original_entry.clone(), b"local bytes".to_vec()),
        );
        let (filesystem, control, generation, root) =
            offline_creatable_vault_filesystem(&temp, backend.clone());
        let (_folder, destination_parent_ref) = control
            .with_read_lease(generation, |lease| {
                let root_entry = lease.stat("/")?;
                let parent =
                    filesystem.vault_parent_ref(root.ino, generation, &root_entry, lease)?;
                lease.create_directory_under_parent("/folder", &parent)?;
                let folder = filesystem.child(root.ino, "folder")?;
                let NodeKind::Vault { entry, .. } = &folder.kind else {
                    unreachable!()
                };
                let parent_ref =
                    lease.parent_ref_for_directory(&entry.path, &entry.id, &entry.etag)?;
                Ok((folder, parent_ref))
            })
            .expect("create pending parent");

        let spool = filesystem.vault_write_spool.as_ref().unwrap();
        let scope = VaultWriteScope::new(
            "account-a",
            "https://example.invalid",
            "encrypted-space",
            "vault-root-id",
        )
        .unwrap();
        let source_target = VaultWriteTarget::new_with_parent(
            "source.txt",
            WriteCondition::Absent,
            VaultParentRef::stable("vault-root-id").unwrap(),
        )
        .unwrap();
        let binding = VaultWriteBinding::new(scope, source_target, generation).unwrap();
        let mut empty = Cursor::new(Vec::<u8>::new());
        let mut working = spool.begin(binding, &mut empty, generation).unwrap();
        let record_id = working.record_id().to_owned();
        working
            .record_building_create(generation, &operation_id, 1)
            .unwrap();
        working.write_at(0, b"local bytes", generation).unwrap();
        working
            .commit_snapshot_outcome(generation, |_source, _length| {
                Ok(VaultUploadOutcome::QueuedCreate {
                    entry: original_entry.clone(),
                    write_id: operation_id.clone(),
                    revision: 2,
                    uncertain: false,
                })
            })
            .unwrap();
        let destination_path = "/folder/renamed.txt";
        let destination_target = VaultWriteTarget::new_with_parent(
            "folder/renamed.txt",
            WriteCondition::Absent,
            destination_parent_ref.clone(),
        )
        .unwrap();
        working
            .begin_never_attempted_create_retarget(
                generation,
                &operation_id,
                2,
                destination_path,
                destination_target,
            )
            .unwrap();

        // Deterministic crash point: the backend CAS succeeds, then the process
        // drops the working-copy handle before writing the new local manifest.
        control
            .with_read_lease(generation, |lease| {
                let outcome = lease.rename_pending_create(
                    "/source.txt",
                    destination_path,
                    &original_entry.id,
                    &original_entry.etag,
                    &destination_parent_ref,
                )?;
                assert_eq!(outcome.revision, 3);
                Ok(())
            })
            .expect("backend retarget CAS");
        drop(working);

        drop(filesystem);
        drop(control);
        backend
            .pending_create_resolution_failures
            .store(1, Ordering::Relaxed);
        let (filesystem, _control, next_generation, root_after_restart) =
            offline_creatable_vault_filesystem(&temp, backend.clone());
        filesystem
            .children(root_after_restart.ino)
            .expect("listing remains available after a transient resolver error");
        let spool = filesystem.vault_write_spool.as_ref().unwrap();
        let (records, truncated) = spool.list_pending().unwrap();
        assert!(!truncated);
        assert!(matches!(
            records
                .iter()
                .find(|record| record.record_id == record_id)
                .and_then(|record| record.lifecycle.as_ref()),
            Some(VaultWriteLifecycle::RetargetingCreate { .. })
        ));
        filesystem
            .children(root_after_restart.ino)
            .expect("the next listing retries exact-ID recovery");

        let (records, truncated) = spool.list_pending().unwrap();
        assert!(!truncated);
        let record = records
            .iter()
            .find(|record| record.record_id == record_id)
            .unwrap();
        assert_eq!(
            record.target.as_ref().unwrap().opaque_relative_target(),
            "folder/renamed.txt"
        );
        assert_eq!(
            record.target.as_ref().unwrap().parent_ref(),
            Some(&destination_parent_ref)
        );
        assert!(
            matches!(record.lifecycle, Some(VaultWriteLifecycle::Queued { ref write_id, revision: 3, uncertain: false, .. }) if write_id == &operation_id)
        );
        let binding = VaultWriteBinding::new(
            record.scope.clone().unwrap(),
            record.target.clone().unwrap(),
            next_generation,
        )
        .unwrap();
        let mut recovered = spool.recover(&record_id, binding, next_generation).unwrap();
        let mut content = vec![0; 11];
        recovered.read_at(0, &mut content, next_generation).unwrap();
        assert_eq!(&content, b"local bytes");
        drop(recovered);
        drop(filesystem);

        // A second restart starts from the already-finalized manifest. Recovery
        // must be idempotent and must not replay the backend retarget operation.
        let (filesystem, _control, final_generation, final_root) =
            offline_creatable_vault_filesystem(&temp, backend.clone());
        filesystem
            .children(final_root.ino)
            .expect("finalized manifest remains browsable after another restart");
        assert_eq!(
            backend.pending_create_rename_calls.load(Ordering::Relaxed),
            1,
            "a finalized manifest must not replay the backend CAS"
        );
        let final_folder = filesystem.child(final_root.ino, "folder").unwrap();
        let final_file = filesystem.child(final_folder.ino, "renamed.txt").unwrap();
        let NodeKind::Vault { entry, .. } = final_file.kind else {
            panic!("renamed queued file should remain a vault entry")
        };
        assert_eq!(entry.etag, format!("raiun-pending-v1:{operation_id}:3"));
        let final_records = filesystem
            .vault_write_spool
            .as_ref()
            .unwrap()
            .list_pending()
            .unwrap()
            .0;
        let final_record = final_records
            .iter()
            .find(|record| record.record_id == record_id)
            .unwrap();
        let final_binding = VaultWriteBinding::new(
            final_record.scope.clone().unwrap(),
            final_record.target.clone().unwrap(),
            final_generation,
        )
        .unwrap();
        let mut final_copy = filesystem
            .vault_write_spool
            .as_ref()
            .unwrap()
            .recover(&record_id, final_binding, final_generation)
            .unwrap();
        let mut final_bytes = vec![0; 11];
        final_copy
            .read_at(0, &mut final_bytes, final_generation)
            .unwrap();
        assert_eq!(&final_bytes, b"local bytes");
    }

    #[test]
    fn offline_vault_file_delete_hides_name_but_keeps_recovery_content() {
        let temp = tempfile::tempdir().expect("temp directory");
        let backend = Arc::new(FakeVaultWriteBackend::with_queued_deletes());
        backend.seed_file("/delete-me.txt", b"recoverable bytes", "source-v1", true);
        backend.seed_directory("/empty-directory", "directory-v1", true);
        let (filesystem, control, generation, root) =
            offline_creatable_vault_filesystem(&temp, backend.clone());
        filesystem
            .children(root.ino)
            .expect("initial vault listing");

        control
            .with_read_lease(generation, |lease| {
                filesystem.delete_vault_child_with_lease(
                    root.ino,
                    "delete-me.txt",
                    false,
                    lease,
                )?;
                assert!(filesystem.child(root.ino, "delete-me.txt").is_err());
                assert_eq!(
                    backend.recovered_delete("/delete-me.txt").as_deref(),
                    Some(&b"recoverable bytes"[..])
                );

                // The tombstone cannot remove a future same-path replacement.
                backend.seed_file(
                    "/delete-me.txt",
                    b"replacement bytes",
                    "replacement-v1",
                    true,
                );
                let replacement = filesystem.child(root.ino, "delete-me.txt")?;
                assert!(matches!(
                    &replacement.kind,
                    NodeKind::Vault { entry, .. }
                        if entry.id == "id:/delete-me.txt" && entry.etag == "replacement-v1"
                ));
                assert_eq!(
                    backend.recovered_delete("/delete-me.txt").as_deref(),
                    Some(&b"recoverable bytes"[..])
                );

                let error = filesystem
                    .delete_vault_child_with_lease(root.ino, "empty-directory", true, lease)
                    .expect_err("directory deletion is unsupported on every encrypted route");
                assert_eq!(error.kind, ErrorKind::Unsupported);
                Ok(())
            })
            .expect("route remains unlocked for tombstone assertions");
    }

    #[test]
    fn encrypted_directory_delete_is_unsupported_without_backend_requests() {
        let temp = tempfile::tempdir().expect("temp directory");
        let backend = Arc::new(FakeVaultWriteBackend::with_root());
        backend.seed_directory("/empty-directory", "directory-v1", true);
        let (filesystem, control, generation, root) =
            writable_vault_filesystem(&temp, backend.clone());
        filesystem
            .children(root.ino)
            .expect("initial vault listing");

        control
            .with_read_lease(generation, |lease| {
                let error = filesystem
                    .delete_vault_child_with_lease(root.ino, "empty-directory", true, lease)
                    .expect_err("directory deletion is not safe without membership preconditions");
                assert_eq!(error.kind, ErrorKind::Unsupported);
                assert_eq!(backend.delete_calls.load(Ordering::Relaxed), 0);
                assert_eq!(backend.stat("/empty-directory")?.id, "id:/empty-directory");
                Ok(())
            })
            .expect("route remains active after unsupported request");
    }

    #[test]
    fn directory_listing_metadata_avoids_per_file_stat_but_open_revalidates() {
        let temp = tempfile::tempdir().expect("temp dir");
        let backend = Arc::new(FakeBackend::with_file("/note.txt", b"old"));
        {
            let mut files = backend.files.lock().expect("fixture lock");
            for index in 0..10 {
                let path = format!("/other-{index:02}.txt");
                let body = format!("entry {index}").into_bytes();
                files.insert(
                    ("personal".into(), path.clone()),
                    (entry(&path, body.len() as u64, "v1"), body),
                );
            }
        }
        let filesystem = filesystem(&temp, backend.clone());
        let personal = filesystem.node(PERSONAL).expect("Personal node");
        let entries = filesystem.children(personal.ino).expect("list Personal");
        assert_eq!(backend.stat_calls.load(Ordering::Relaxed), 0);
        assert_eq!(backend.list_calls.load(Ordering::Relaxed), 1);
        assert_eq!(entries.len(), 11);
        let note = entries
            .iter()
            .find(|node| node.name == "note.txt")
            .expect("listed note");
        for listed in &entries {
            let found = filesystem
                .lookup_child_with_lease_at(listed.parent, &listed.name, None, Instant::now())
                .expect("lookup reuses a fresh ordinary child inode");
            assert_eq!(found.ino, listed.ino);
        }
        assert_eq!(
            backend.list_calls.load(Ordering::Relaxed),
            1,
            "fresh known child lookups should not repeat the parent listing"
        );

        backend.replace_for_test("/note.txt", b"new content", "v2");
        let cached = filesystem
            .getattr_node(note.ino)
            .expect("get attributes from listed metadata");
        assert_eq!(backend.stat_calls.load(Ordering::Relaxed), 0);
        assert!(matches!(
            &cached.kind,
            NodeKind::Remote { entry, .. } if entry.size == 3 && entry.etag == "v1"
        ));

        let refreshed_entries = filesystem
            .children(personal.ino)
            .expect("relist Personal to refresh cached metadata");
        assert_eq!(backend.list_calls.load(Ordering::Relaxed), 2);
        let refreshed = refreshed_entries
            .iter()
            .find(|node| node.name == "note.txt")
            .expect("note remains visible");
        assert_eq!(refreshed.ino, note.ino);
        assert!(matches!(
            &filesystem.node(note.ino).unwrap().kind,
            NodeKind::Remote { entry, .. } if entry.size == 11 && entry.etag == "v2"
        ));
        assert_eq!(backend.stat_calls.load(Ordering::Relaxed), 0);

        filesystem
            .lookup_child_with_lease_at(
                personal.ino,
                "note.txt",
                None,
                Instant::now() + TTL + Duration::from_millis(1),
            )
            .expect("expired lookup re-lists the parent");
        assert_eq!(backend.list_calls.load(Ordering::Relaxed), 3);

        let expired = filesystem
            .getattr_node_at(note.ino, Instant::now() + TTL + Duration::from_millis(1))
            .expect("expired attributes perform a fresh stat");
        assert_eq!(backend.stat_calls.load(Ordering::Relaxed), 1);
        assert!(matches!(
            &expired.kind,
            NodeKind::Remote { entry, .. } if entry.size == 11 && entry.etag == "v2"
        ));

        filesystem
            .open_node(note.ino, libc::O_RDONLY)
            .expect("open performs a fresh stat and download");
        // Opening performs its own fresh identity check; the engine snapshot
        // then checks the remote revision around the downloaded bytes.
        assert_eq!(backend.stat_calls.load(Ordering::Relaxed), 3);
        assert!(matches!(
            filesystem.node(note.ino).unwrap().kind,
            NodeKind::Remote { entry, .. } if entry.size == 11 && entry.etag == "v2"
        ));
    }

    #[test]
    fn whole_space_route_overlaps_folder_routes_only_within_its_space() {
        let root_route = |space: &str, resource: &str| {
            VaultMountRoute::new(
                space.into(),
                "/".into(),
                resource.into(),
                VaultRouteControl::new(),
            )
            .unwrap()
        };
        let folder_route = |space: &str, path: &str, resource: &str| {
            VaultMountRoute::new(
                space.into(),
                path.into(),
                resource.into(),
                VaultRouteControl::new(),
            )
            .unwrap()
        };

        let root_first = VaultMountRegistry::new();
        root_first
            .register(root_route("space-a", "space-a-root"))
            .unwrap();
        assert_eq!(
            root_first
                .register(folder_route("space-a", "/Folder.vault", "folder-root"))
                .unwrap_err()
                .kind,
            ErrorKind::Conflict
        );

        let folder_first = VaultMountRegistry::new();
        folder_first
            .register(folder_route("space-a", "/Folder.vault", "folder-root"))
            .unwrap();
        assert_eq!(
            folder_first
                .register(root_route("space-a", "space-a-root"))
                .unwrap_err()
                .kind,
            ErrorKind::Conflict
        );

        let separate_spaces = VaultMountRegistry::new();
        separate_spaces
            .register(root_route("space-a", "space-a-root"))
            .unwrap();
        separate_spaces
            .register(folder_route("space-b", "/Folder.vault", "folder-root"))
            .unwrap();
        assert_eq!(separate_spaces.routes().unwrap().len(), 2);

        let revoked_root = VaultMountRegistry::new();
        let control = VaultRouteControl::new();
        revoked_root
            .register(
                VaultMountRoute::new(
                    "space-a".into(),
                    "/".into(),
                    "space-a-root".into(),
                    control.clone(),
                )
                .unwrap(),
            )
            .unwrap();
        control.revoke(|| Ok(())).unwrap();
        assert_eq!(
            revoked_root
                .register(folder_route("space-a", "/Folder.vault", "folder-root"))
                .unwrap_err()
                .kind,
            ErrorKind::Conflict,
            "a revoked route remains reserved until the registry is cleared"
        );
        revoked_root.clear_revoked().unwrap();
        revoked_root
            .register(folder_route("space-a", "/Folder.vault", "folder-root"))
            .unwrap();
        assert_eq!(revoked_root.routes().unwrap().len(), 1);
    }

    #[test]
    fn configured_folder_vault_overlays_plaintext_names_and_revokes_old_nodes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let backend = Arc::new(FakeBackend::default());
        backend.files.lock().expect("fake lock").insert(
            ("personal".into(), "/Vault".into()),
            (
                RemoteEntry {
                    id: "vault-root-id".into(),
                    path: "/Vault".into(),
                    directory: true,
                    size: 0,
                    etag: "remote-vault-etag".into(),
                    modified_unix: 1,
                    writable: true,
                    encrypted: true,
                },
                Vec::new(),
            ),
        );
        let control = VaultRouteControl::new();
        let generation = control
            .install_backend(Arc::new(FakeVaultReadBackend))
            .expect("install route backend");
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    "personal".into(),
                    "/Vault".into(),
                    "vault-root-id".into(),
                    control.clone(),
                )
                .expect("route descriptor"),
            )
            .expect("register route");
        let filesystem = filesystem_with_registry(&temp, backend, registry.clone());
        let personal = filesystem.node(PERSONAL).expect("Personal node");
        let visible = filesystem.children(personal.ino).expect("Personal listing");
        let vault_root = visible
            .iter()
            .find(|node| node.name == "Vault")
            .expect("configured vault root shown");
        let children = filesystem.children(vault_root.ino).expect("vault listing");
        let file = children
            .iter()
            .find(|node| node.name == "hello.txt")
            .expect("decrypted name shown");
        assert_eq!(file_type_for(&filesystem, file), FileType::RegularFile);
        assert_eq!(filesystem.attr(file).perm, 0o444);
        assert!(filesystem.child_path(vault_root, "new.txt").is_err());
        assert!(matches!(
            filesystem.node(vault_root.ino).unwrap().kind,
            NodeKind::Vault {
                generation: found,
                ..
            } if found == generation
        ));

        // A non-mounted synthetic filesystem has no kernel notifier. Its hook
        // still purges route-owned plaintext names/handles and reports that
        // kernel invalidation could not be confirmed.
        assert!(control.revoke(|| Ok(())).is_err());
        assert!(filesystem.node(vault_root.ino).is_err());
        assert!(filesystem.children(vault_root.ino).is_err());
        let locked_root = filesystem
            .children(personal.ino)
            .expect("show locked folder placeholder")
            .into_iter()
            .find(|node| node.name == "Vault")
            .expect("locked folder placeholder");
        assert!(matches!(locked_root.kind, NodeKind::LockedVault { .. }));
        let readme = filesystem
            .children(locked_root.ino)
            .expect("locked placeholder contains notice")
            .into_iter()
            .next()
            .expect("README node");

        control
            .install_backend(Arc::new(FakeVaultReadBackend))
            .expect("reinstall after unlock");
        let visible = filesystem
            .children(personal.ino)
            .expect("relisted Personal");
        let new_root = visible
            .iter()
            .find(|node| node.name == "Vault")
            .expect("vault returns after unlock");
        assert_ne!(new_root.ino, vault_root.ino);
        assert!(filesystem.children(vault_root.ino).is_err());
        assert!(filesystem.node(locked_root.ino).is_err());
        assert!(filesystem.node(readme.ino).is_err());
    }

    #[test]
    fn personal_readdir_propagates_active_vault_root_identity_mismatch() {
        let temp = tempfile::tempdir().expect("temp dir");
        let backend = Arc::new(FakeBackend::default());
        let mut encrypted_root = entry("/Vault.vault", 0, "remote-etag");
        encrypted_root.id = "configured-root-id".into();
        encrypted_root.directory = true;
        encrypted_root.encrypted = true;
        backend.files.lock().expect("fake lock").insert(
            ("personal".into(), encrypted_root.path.clone()),
            (encrypted_root, Vec::new()),
        );

        let control = VaultRouteControl::new();
        control
            .install_backend(Arc::new(MismatchedVaultRootReadBackend))
            .expect("install synthetic route with replaced root");
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    "personal".into(),
                    "/Vault.vault".into(),
                    "configured-root-id".into(),
                    control,
                )
                .expect("route descriptor"),
            )
            .expect("register route");
        let filesystem = filesystem_with_registry(&temp, backend, registry);
        assert_eq!(
            filesystem
                .engine
                .list("personal", "/")
                .expect("synthetic Personal listing")
                .len(),
            1
        );
        let personal = filesystem.node(PERSONAL).expect("Personal node");

        let error = match filesystem.children(personal.ino) {
            Ok(_) => panic!("stale active route must not become an empty success"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Conflict);
    }

    #[test]
    fn locked_folder_vault_shows_only_local_readme_and_denies_mutations() {
        let temp = tempfile::tempdir().expect("temp dir");
        let backend = Arc::new(FakeBackend::default());
        let mut root = entry("/Vault", 0, "root-v1");
        root.id = "vault-root-id".into();
        root.directory = true;
        root.encrypted = true;
        backend
            .files
            .lock()
            .unwrap()
            .insert(("personal".into(), "/Vault".into()), (root, Vec::new()));
        backend.add_space_entry("personal", "/Vault/secret.txt", b"ciphertext", false, "v1");
        let filesystem = filesystem(&temp, Arc::clone(&backend));

        let personal = filesystem.node(PERSONAL).expect("Personal");
        let children = filesystem.children(personal.ino).expect("Personal listing");
        let locked = children
            .iter()
            .find(|node| node.name == "Vault")
            .expect("locked vault remains visible");
        assert!(matches!(locked.kind, NodeKind::LockedVault { .. }));
        assert_eq!(filesystem.file_type(locked), FileType::Directory);
        assert_eq!(filesystem.attr(locked).perm, 0o555);
        let before_placeholder = backend.list_calls.load(Ordering::Relaxed);

        let placeholder = filesystem
            .children(locked.ino)
            .expect("static locked notice listing");
        assert_eq!(placeholder.len(), 1);
        let readme = &placeholder[0];
        assert_eq!(readme.name, "README.txt");
        assert_eq!(filesystem.file_type(readme), FileType::RegularFile);
        assert_eq!(filesystem.attr(readme).perm, 0o444);
        let handle = filesystem
            .open_node(readme.ino, libc::O_RDONLY)
            .expect("read-only local notice");
        let contents = filesystem.file_handle(handle).unwrap();
        let mut open = contents.lock().unwrap();
        let OpenFile::Read(ReadHandle::Static(reader)) = &mut *open else {
            panic!("placeholder should use static local content")
        };
        let mut text = String::new();
        reader.read_to_string(&mut text).unwrap();
        assert!(text.contains("This encrypted location is locked"));
        assert!(text.contains("Open Raiun"));
        assert!(!text.contains("raiun://"));
        drop(open);
        assert!(filesystem.open_node(readme.ino, libc::O_WRONLY).is_err());
        assert!(filesystem.open_node(locked.ino, libc::O_RDONLY).is_err());
        assert!(filesystem.child_path(locked, "new.txt").is_err());
        assert_eq!(
            backend.list_calls.load(Ordering::Relaxed),
            before_placeholder,
            "opening/listing the placeholder must not ask the ordinary backend for vault contents"
        );
    }

    #[test]
    fn locked_readme_unlock_link_requires_exact_registered_stable_identity() {
        let temp = tempfile::tempdir().expect("temp dir");
        let backend = Arc::new(FakeBackend::default());
        let mut root = entry("/Vault", 0, "root-v1");
        root.id = "root/id %".into();
        root.directory = true;
        root.encrypted = true;
        backend
            .files
            .lock()
            .unwrap()
            .insert(("personal".into(), "/Vault".into()), (root, Vec::new()));

        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    "personal".into(),
                    "/Vault".into(),
                    "root/id %".into(),
                    VaultRouteControl::new(),
                )
                .unwrap(),
            )
            .unwrap();
        let filesystem = filesystem_with_registry(&temp, backend, registry);
        let personal = filesystem.node(PERSONAL).expect("Personal");
        let locked = filesystem
            .children(personal.ino)
            .expect("Personal listing")
            .into_iter()
            .find(|node| node.name == "Vault")
            .expect("locked root");
        assert!(matches!(locked.kind, NodeKind::LockedVault { .. }));

        let readme = filesystem
            .children(locked.ino)
            .expect("notice listing")
            .into_iter()
            .next()
            .expect("README");
        let size = filesystem.attr(&readme).size;
        let handle = filesystem
            .open_node(readme.ino, libc::O_RDONLY)
            .expect("read-only README");
        let contents = filesystem.file_handle(handle).unwrap();
        let mut open = contents.lock().unwrap();
        let OpenFile::Read(ReadHandle::Static(reader)) = &mut *open else {
            panic!("README should be a local static handle")
        };
        let mut text = String::new();
        reader.read_to_string(&mut text).unwrap();
        assert_eq!(text.len() as u64, size);
        assert!(text.contains(
            "raiun://unlock?v=1&profile_id=fuse-test-profile&space_id=personal&root_resource_id=root%2Fid%20%25"
        ));
        assert!(!text.contains("/Vault"), "URI must not expose a cloud path");
    }

    #[test]
    fn locked_whole_space_is_visible_without_ordinary_listing() {
        let temp = tempfile::tempdir().expect("temp dir");
        let backend = Arc::new(FakeBackend::default());
        *backend.spaces_override.lock().unwrap() = Some(vec![
            CloudSpace {
                id: "personal".into(),
                name: "Personal".into(),
                dav_url: "https://example.invalid/dav/personal".into(),
                personal: true,
                writable: true,
                encrypted: false,
            },
            CloudSpace {
                id: "encrypted-space".into(),
                name: "Encrypted Projects".into(),
                dav_url: "https://example.invalid/dav/encrypted".into(),
                personal: false,
                writable: true,
                encrypted: true,
            },
        ]);
        let filesystem = filesystem(&temp, Arc::clone(&backend));
        let spaces = filesystem.children(SPACES).expect("Spaces listing");
        let locked = spaces
            .iter()
            .find(|node| node.name == "Encrypted Projects")
            .expect("encrypted Space is visible while locked");
        assert!(matches!(locked.kind, NodeKind::LockedVault { .. }));
        assert_eq!(backend.list_calls.load(Ordering::Relaxed), 0);
        let children = filesystem.children(locked.ino).expect("notice listing");
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].name, "README.txt");
        assert_eq!(backend.list_calls.load(Ordering::Relaxed), 0);
        assert!(filesystem.child_path(locked, "new.txt").is_err());
    }

    #[test]
    fn unlocked_whole_space_vault_is_projected_without_ordinary_listing() {
        let temp = tempfile::tempdir().expect("temp dir");
        let backend = Arc::new(FakeBackend::with_file("/outside.txt", b"ordinary"));
        *backend.spaces_override.lock().unwrap() = Some(vec![
            CloudSpace {
                id: "personal".into(),
                name: "Personal".into(),
                dav_url: "https://example.invalid/dav/personal".into(),
                personal: true,
                writable: true,
                encrypted: false,
            },
            CloudSpace {
                id: "ordinary-space".into(),
                name: "Ordinary Projects".into(),
                dav_url: "https://example.invalid/dav/ordinary".into(),
                personal: false,
                writable: true,
                encrypted: false,
            },
            CloudSpace {
                id: "encrypted-space".into(),
                name: "Encrypted Projects".into(),
                dav_url: "https://example.invalid/dav/encrypted".into(),
                personal: false,
                writable: true,
                encrypted: true,
            },
        ]);

        let control = VaultRouteControl::new();
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    "encrypted-space".into(),
                    "/".into(),
                    "vault-root-id".into(),
                    control.clone(),
                )
                .expect("whole-Space route descriptor"),
            )
            .expect("register whole-Space route");
        let filesystem = filesystem_with_registry(&temp, backend.clone(), registry);
        let spaces = filesystem.node(SPACES).expect("Spaces container");

        let locked = filesystem.children(spaces.ino).expect("locked Space list");
        assert!(locked.iter().any(|node| node.name == "Ordinary Projects"));
        let placeholder = locked
            .iter()
            .find(|node| node.name == "Encrypted Projects")
            .expect("locked encrypted Space placeholder");
        assert!(matches!(placeholder.kind, NodeKind::LockedVault { .. }));
        assert_eq!(
            filesystem
                .children(placeholder.ino)
                .expect("locked Space notice")
                .first()
                .map(|node| node.name.as_str()),
            Some("README.txt")
        );
        assert_eq!(backend.list_calls.load(Ordering::Relaxed), 0);

        let first_generation = control
            .install_backend(Arc::new(FakeVaultReadBackend))
            .expect("install unlocked whole-Space backend");
        assert!(filesystem.node(placeholder.ino).is_err());
        let visible = filesystem
            .children(spaces.ino)
            .expect("unlocked Space list");
        let root = visible
            .iter()
            .find(|node| node.name == "Encrypted Projects")
            .expect("unlocked encrypted Space root");
        assert!(matches!(
            &root.kind,
            NodeKind::Vault {
                generation,
                entry,
                ..
            } if *generation == first_generation && entry.id == "vault-root-id" && entry.path == "/"
        ));
        let children = filesystem
            .children(root.ino)
            .expect("decrypted root listing");
        let file = children
            .iter()
            .find(|node| node.name == "hello.txt")
            .expect("decrypted name beneath whole Space");
        assert_eq!(file_type_for(&filesystem, file), FileType::RegularFile);
        assert_eq!(filesystem.attr(file).perm, 0o444);
        assert!(filesystem.child_path(root, "new.txt").is_err());
        assert_eq!(
            backend.list_calls.load(Ordering::Relaxed),
            0,
            "encrypted Space contents must never use the ordinary backend"
        );

        assert!(control.revoke(|| Ok(())).is_err());
        assert!(filesystem.node(root.ino).is_err());
        let locked_again = filesystem
            .children(spaces.ino)
            .expect("Space list after lock");
        let locked_placeholder = locked_again
            .iter()
            .find(|node| node.name == "Encrypted Projects")
            .expect("locked Space placeholder remains visible");
        assert!(matches!(
            locked_placeholder.kind,
            NodeKind::LockedVault { .. }
        ));

        let second_generation = control
            .install_backend(Arc::new(FakeVaultReadBackend))
            .expect("reinstall after unlock");
        assert!(second_generation > first_generation);
        let relisted = filesystem
            .children(spaces.ino)
            .expect("Space list after relock");
        let new_root = relisted
            .iter()
            .find(|node| node.name == "Encrypted Projects")
            .expect("new-generation Space root");
        assert_ne!(new_root.ino, root.ino);
        assert!(filesystem.children(root.ino).is_err());
    }

    #[test]
    fn whole_space_root_identity_mismatch_is_reported_not_hidden() {
        let temp = tempfile::tempdir().expect("temp dir");
        let backend = Arc::new(FakeBackend::with_file("/ordinary.txt", b"ordinary"));
        *backend.spaces_override.lock().unwrap() = Some(vec![
            CloudSpace {
                id: "personal".into(),
                name: "Personal".into(),
                dav_url: "https://example.invalid/dav/personal".into(),
                personal: true,
                writable: true,
                encrypted: false,
            },
            CloudSpace {
                id: "encrypted-space".into(),
                name: "Encrypted Projects".into(),
                dav_url: "https://example.invalid/dav/encrypted".into(),
                personal: false,
                writable: true,
                encrypted: true,
            },
        ]);
        let control = VaultRouteControl::new();
        control
            .install_backend(Arc::new(FakeVaultReadBackend))
            .expect("install mismatched fixture");
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    "encrypted-space".into(),
                    "/".into(),
                    "different-root-id".into(),
                    control,
                )
                .unwrap(),
            )
            .unwrap();
        let filesystem = filesystem_with_registry(&temp, backend, registry);
        let error = match filesystem.children(SPACES) {
            Err(error) => error,
            Ok(_) => panic!(
                "a stale route must surface identity conflict rather than appear as an empty Space"
            ),
        };
        assert_eq!(error.kind, ErrorKind::Conflict);
    }

    #[test]
    fn offline_missing_listing_is_not_reported_as_empty_directory() {
        let temp = tempfile::tempdir().expect("temp dir");
        let backend = Arc::new(FakeBackend::with_file("/ordinary.txt", b"ordinary"));
        let filesystem = filesystem(&temp, backend.clone());
        // A previously known directory must not become an apparent empty
        // directory merely because its listing cannot be fetched or restored.
        let nested = filesystem
            .add_node(
                PERSONAL,
                "Nested".into(),
                NodeKind::Remote {
                    space: "personal".into(),
                    entry: RemoteEntry {
                        id: "nested-id".into(),
                        modified_unix: 0,
                        path: "/Nested".into(),
                        etag: "nested-etag".into(),
                        size: 0,
                        directory: true,
                        writable: true,
                        encrypted: false,
                    },
                },
            )
            .expect("known directory");
        backend.set_network_error(Some(ErrorKind::Offline));
        for directory in [PERSONAL, nested] {
            let error = filesystem
                .children(directory)
                .err()
                .expect("listing unavailable");
            assert_eq!(error.kind, ErrorKind::Offline);
        }
    }

    #[test]
    fn active_pinned_folder_route_is_discoverable_without_server_listing() {
        let temp = tempfile::tempdir().expect("temp dir");
        let backend = Arc::new(FakeBackend::with_file("/ordinary.txt", b"ordinary"));
        let control = VaultRouteControl::new();
        control
            .install_backend(Arc::new(FakeVaultReadBackend))
            .expect("install authenticated pinned snapshot");
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    "personal".into(),
                    "/Pinned.vault".into(),
                    "vault-root-id".into(),
                    control,
                )
                .expect("valid pinned route"),
            )
            .expect("register pinned route");
        registry
            .register(
                VaultMountRoute::new(
                    "personal".into(),
                    "/Locked.vault".into(),
                    "locked-root-id".into(),
                    VaultRouteControl::new(),
                )
                .expect("valid inactive route"),
            )
            .expect("register inactive route");

        let filesystem = filesystem_with_registry(&temp, backend.clone(), registry);
        backend.set_network_error(Some(ErrorKind::Offline));
        let personal = filesystem
            .children(PERSONAL)
            .expect("offline Personal listing should expose authenticated pin");
        let root = personal
            .iter()
            .find(|node| node.name == "Pinned.vault")
            .expect("pinned encrypted root should be discoverable");
        assert!(matches!(root.kind, NodeKind::Vault { .. }));
        assert!(!personal.iter().any(|node| node.name == "Locked.vault"));

        let children = filesystem
            .children(root.ino)
            .expect("read decrypted snapshot without server listing");
        assert!(children.iter().any(|node| node.name == "hello.txt"));
    }

    #[test]
    fn parent_directory_snapshots_require_each_vault_route_and_stale_clones_stay_denied() {
        let first = VaultRouteControl::new();
        let first_generation = first
            .install_backend(Arc::new(FakeVaultReadBackend))
            .unwrap();
        let second = VaultRouteControl::new();
        let second_generation = second
            .install_backend(Arc::new(FakeVaultReadBackend))
            .unwrap();
        let parent = Node {
            ino: PERSONAL,
            parent: ROOT,
            name: "Personal".into(),
            kind: NodeKind::Personal {
                space: "personal".into(),
            },
            metadata_expires_at: Instant::now(),
        };
        let vault_child = |path: &str, id: &str, control: VaultRouteControl, generation| Node {
            ino: stable_inode(id),
            parent: PERSONAL,
            name: path.rsplit('/').next().unwrap().into(),
            kind: NodeKind::Vault {
                route: VaultMountRoute::new("personal".into(), path.into(), id.into(), control)
                    .unwrap(),
                generation,
                entry: RemoteEntry {
                    id: id.into(),
                    path: path.into(),
                    directory: true,
                    size: 0,
                    etag: "root-etag".into(),
                    modified_unix: 0,
                    writable: false,
                    encrypted: true,
                },
            },
            metadata_expires_at: Instant::now(),
        };
        let children = vec![
            vault_child(
                "/First.vault",
                "first-root",
                first.clone(),
                first_generation,
            ),
            vault_child(
                "/Second.vault",
                "second-root",
                second.clone(),
                second_generation,
            ),
        ];
        let routes = directory_vault_routes(&parent, &children);
        assert_eq!(routes.len(), 2);
        assert!(routes[0].0.route_id() < routes[1].0.route_id());
        let snapshot = DirectoryHandle {
            entries: children
                .iter()
                .map(|node| (node.name.clone(), node.ino, FileType::Directory))
                .collect(),
            routes: routes.clone(),
            locked_vaults: Vec::new(),
            owner_vault: None,
        };
        let unrelated_snapshot = DirectoryHandle {
            entries: vec![("ordinary".into(), 90, FileType::Directory)],
            routes: Vec::new(),
            locked_vaults: Vec::new(),
            owner_vault: None,
        };
        with_vault_route_leases(&snapshot.routes, 0, || Ok(()))
            .expect("all included routes are initially active");

        first.revoke(|| Ok(())).unwrap();
        let state = Arc::new(Mutex::new(State {
            nodes: HashMap::new(),
            children: HashMap::new(),
            recovery_aliases: std::collections::HashSet::new(),
            file_handles: HashMap::new(),
            vault_file_handles: HashMap::new(),
            directory_handles: HashMap::from([
                (1, snapshot.clone()),
                (2, unrelated_snapshot.clone()),
            ]),
            pending_parent_refs: HashMap::new(),
            active_writers: std::collections::HashSet::new(),
        }));
        purge_vault_route_state(&state, first.route_id()).unwrap();
        {
            let state = state.lock().unwrap();
            assert!(!state.directory_handles.contains_key(&1));
            assert!(state.directory_handles.contains_key(&2));
        }
        assert!(with_vault_route_leases(&snapshot.routes, 0, || Ok(())).is_err());

        let next_first_generation = first
            .install_backend(Arc::new(FakeVaultReadBackend))
            .unwrap();
        assert!(next_first_generation > first_generation);
        assert!(with_vault_route_leases(&snapshot.routes, 0, || Ok(())).is_err());
        let first_reunlocked_children = vec![
            vault_child(
                "/First.vault",
                "first-root",
                first.clone(),
                next_first_generation,
            ),
            vault_child(
                "/Second.vault",
                "second-root",
                second.clone(),
                second_generation,
            ),
        ];
        let first_reunlocked_routes = directory_vault_routes(&parent, &first_reunlocked_children);
        with_vault_route_leases(&first_reunlocked_routes, 0, || Ok(()))
            .expect("a fresh snapshot is valid while both included routes are active");
        second.revoke(|| Ok(())).unwrap();
        assert!(with_vault_route_leases(&snapshot.routes, 0, || Ok(())).is_err());

        let fresh_children = vec![
            vault_child(
                "/First.vault",
                "first-root",
                first.clone(),
                next_first_generation,
            ),
            vault_child(
                "/Second.vault",
                "second-root",
                second.clone(),
                second_generation,
            ),
        ];
        let fresh_routes = directory_vault_routes(&parent, &fresh_children);
        assert!(with_vault_route_leases(&fresh_routes, 0, || Ok(())).is_err());
        let next_second_generation = second
            .install_backend(Arc::new(FakeVaultReadBackend))
            .unwrap();
        let fresh_children = vec![
            vault_child(
                "/First.vault",
                "first-root",
                first.clone(),
                next_first_generation,
            ),
            vault_child(
                "/Second.vault",
                "second-root",
                second,
                next_second_generation,
            ),
        ];
        let fresh_routes = directory_vault_routes(&parent, &fresh_children);
        with_vault_route_leases(&fresh_routes, 0, || Ok(()))
            .expect("fresh snapshot is valid only after both routes are unlocked");
    }

    #[test]
    fn parent_snapshot_lease_keeps_revoke_waiting_through_reply() {
        use std::sync::mpsc;
        use std::time::Duration;

        let control = VaultRouteControl::new();
        let generation = control
            .install_backend(Arc::new(FakeVaultReadBackend))
            .unwrap();
        let parent = Node {
            ino: PERSONAL,
            parent: ROOT,
            name: "Personal".into(),
            kind: NodeKind::Personal {
                space: "personal".into(),
            },
            metadata_expires_at: Instant::now(),
        };
        let child = Node {
            ino: 88,
            parent: PERSONAL,
            name: "Vault".into(),
            kind: NodeKind::Vault {
                route: VaultMountRoute::new(
                    "personal".into(),
                    "/Vault".into(),
                    "root-id".into(),
                    control.clone(),
                )
                .unwrap(),
                generation,
                entry: RemoteEntry {
                    id: "root-id".into(),
                    path: "/Vault".into(),
                    directory: true,
                    size: 0,
                    etag: "root-etag".into(),
                    modified_unix: 0,
                    writable: false,
                    encrypted: true,
                },
            },
            metadata_expires_at: Instant::now(),
        };
        let routes = directory_vault_routes(&parent, &[child]);
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release_reply = Arc::new(std::sync::Barrier::new(2));
        let reader = {
            let routes = routes.clone();
            let entered = Arc::clone(&entered);
            let release_reply = Arc::clone(&release_reply);
            std::thread::spawn(move || {
                with_vault_route_leases(&routes, 0, || {
                    entered.wait();
                    release_reply.wait();
                    Ok(())
                })
            })
        };
        entered.wait();

        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let revoker = {
            let control = control.clone();
            std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                let result = control.revoke(|| Ok(()));
                finished_tx.send(result).unwrap();
            })
        };
        started_rx.recv().unwrap();
        assert!(
            finished_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "revoke must wait until the parent-directory reply releases its route lease"
        );
        release_reply.wait();
        reader.join().unwrap().unwrap();
        finished_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        revoker.join().unwrap();
        assert!(!control.is_active().unwrap());
    }

    #[test]
    fn route_purge_does_not_lock_open_files_while_holding_provider_state() {
        use std::sync::mpsc;
        use std::time::Duration;

        let control = VaultRouteControl::new();
        let route_id = control.route_id();
        let route = VaultMountRoute::new(
            "personal".into(),
            "/Vault".into(),
            "root-id".into(),
            control.clone(),
        )
        .unwrap();
        let handle = Arc::new(Mutex::new(OpenFile::Vault {
            route: control,
            generation: 1,
            ino: 99,
            path: "/secret.txt".into(),
            handle: None,
        }));
        let mut nodes = HashMap::new();
        nodes.insert(
            99,
            Node {
                ino: 99,
                parent: 10,
                name: "secret.txt".into(),
                kind: NodeKind::Vault {
                    route,
                    generation: 1,
                    entry: RemoteEntry {
                        id: "secret-id".into(),
                        path: "/secret.txt".into(),
                        directory: false,
                        size: 1,
                        etag: "v1".into(),
                        modified_unix: 0,
                        writable: false,
                        encrypted: false,
                    },
                },
                metadata_expires_at: Instant::now(),
            },
        );
        let state = Arc::new(Mutex::new(State {
            nodes,
            children: HashMap::new(),
            recovery_aliases: std::collections::HashSet::new(),
            file_handles: HashMap::from([(7, Arc::clone(&handle))]),
            vault_file_handles: HashMap::from([(
                7,
                VaultFileHandleMeta {
                    route_id,
                    ino: 99,
                    path: "/secret.txt".into(),
                    writable: false,
                },
            )]),
            directory_handles: HashMap::new(),
            pending_parent_refs: HashMap::new(),
            active_writers: std::collections::HashSet::new(),
        }));

        let (holding_tx, holding_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let ordinary = {
            let handle = Arc::clone(&handle);
            let state = Arc::clone(&state);
            std::thread::spawn(move || {
                let open = handle.lock().unwrap();
                holding_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                drop(open);
                state
                    .lock()
                    .unwrap()
                    .active_writers
                    .insert("finished".into());
            })
        };
        holding_rx.recv().unwrap();

        let (purged_tx, purged_rx) = mpsc::channel();
        let purger = {
            let state = Arc::clone(&state);
            std::thread::spawn(move || {
                let result = purge_vault_route_state(&state, route_id);
                purged_tx.send(result).unwrap();
            })
        };
        let result = purged_rx.recv_timeout(Duration::from_secs(1));
        if result.is_err() {
            release_tx.send(()).unwrap();
            ordinary.join().unwrap();
            purger.join().unwrap();
            panic!("route purge waited on an open-file mutex while holding State");
        }
        assert_eq!(
            result.unwrap().unwrap(),
            vec![(10, "secret.txt".into(), 99)]
        );
        release_tx.send(()).unwrap();
        ordinary.join().unwrap();
        purger.join().unwrap();
        let state = state.lock().unwrap();
        assert!(!state.file_handles.contains_key(&7));
        assert!(!state.vault_file_handles.contains_key(&7));
        assert!(state.active_writers.contains("finished"));
    }

    fn file_type_for(filesystem: &RaiunFilesystem, node: &Node) -> FileType {
        filesystem.file_type(node)
    }

    #[test]
    fn writable_directory_attributes_use_stable_mount_owner() {
        let temp = tempfile::tempdir().expect("temp dir");
        let backend = Arc::new(FakeBackend::with_file("/note.txt", b"old"));
        let filesystem = filesystem(&temp, backend.clone());
        let owner = fs::metadata(temp.path()).expect("mount owner");
        let personal = filesystem.node(PERSONAL).expect("personal root");
        let personal_attr = filesystem.attr(&personal);
        assert_eq!(personal_attr.uid, owner.uid());
        assert_eq!(personal_attr.gid, owner.gid());
        assert_eq!(personal_attr.perm, 0o755);

        let root = filesystem.node(ROOT).expect("namespace root");
        assert_eq!(filesystem.attr(&root).perm, 0o555);
        assert_eq!(filesystem.attr(&root).uid, owner.uid());

        let entry = backend.stat("personal", "/note.txt").expect("stat");
        let ino = filesystem
            .add_node(
                PERSONAL,
                "note.txt".into(),
                NodeKind::Remote {
                    space: "personal".into(),
                    entry,
                },
            )
            .expect("file node");
        let file = filesystem.node(ino).expect("file");
        assert_eq!(filesystem.attr(&file).perm, 0o644);
        assert_eq!(filesystem.attr(&file).uid, owner.uid());
        assert_eq!(filesystem.attr(&file).gid, owner.gid());
    }

    #[test]
    fn spool_commit_uses_revision_and_publishes_verified_bytes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let backend = Arc::new(FakeBackend::with_file("/note.txt", b"old"));
        let fs = filesystem(&temp, backend.clone());
        let original = backend.stat("personal", "/note.txt").expect("stat");
        let ino = fs
            .add_node(
                PERSONAL,
                "note.txt".into(),
                NodeKind::Remote {
                    space: "personal".into(),
                    entry: original.clone(),
                },
            )
            .expect("node");
        let mut handle = fs
            .prepare_write(ino, "personal", "/note.txt", Some(&original), false)
            .expect("write handle");
        handle.file.set_len(0).expect("truncate spool");
        handle.file.seek(SeekFrom::Start(0)).expect("rewind spool");
        handle.file.write_all(b"new body").expect("write spool");
        handle.dirty = true;
        let open = Arc::new(Mutex::new(OpenFile::Write(Box::new(handle))));
        fs.commit(&open).expect("conditional commit");
        let mut body = Vec::new();
        backend
            .download(
                "personal",
                "/note.txt",
                Some("v2"),
                &temp.path().join("verify"),
            )
            .expect("download");
        File::open(temp.path().join("verify"))
            .expect("open verified body")
            .read_to_end(&mut body)
            .expect("read verified body");
        assert_eq!(body, b"new body");
    }

    #[test]
    fn failed_upload_leaves_recoverable_spool() {
        let temp = tempfile::tempdir().expect("temp dir");
        let backend = Arc::new(FakeBackend::with_file("/note.txt", b"old"));
        *backend.fail_upload.lock().expect("fake lock") = true;
        let fs = filesystem(&temp, backend);
        let original = entry("/note.txt", 3, "v1");
        let ino = fs
            .add_node(
                PERSONAL,
                "note.txt".into(),
                NodeKind::Remote {
                    space: "personal".into(),
                    entry: original.clone(),
                },
            )
            .expect("node");
        let mut write = fs
            .prepare_write(ino, "personal", "/note.txt", Some(&original), false)
            .expect("write handle");
        write.file.set_len(0).expect("truncate spool");
        write.file.seek(SeekFrom::Start(0)).expect("rewind spool");
        write.file.write_all(b"pending").expect("write spool");
        write.dirty = true;
        let spool = write.spool.clone();
        let manifest = write.manifest.clone();
        let open = Arc::new(Mutex::new(OpenFile::Write(Box::new(write))));
        assert_eq!(
            fs.commit(&open).expect_err("offline upload").kind,
            ErrorKind::Offline
        );
        assert!(spool.is_file());
        assert!(manifest.is_file());
        assert_eq!(fs::read(&spool).expect("preserved spool"), b"pending");
        match fs.prepare_write(ino, "personal", "/note.txt", Some(&original), true) {
            Err(error) => assert_eq!(error.kind, ErrorKind::Conflict),
            Ok(_) => panic!("pending data was unexpectedly truncated"),
        }
        assert_eq!(fs::read(&spool).expect("still preserved"), b"pending");
    }

    #[test]
    fn path_mutations_reserve_against_concurrent_writers() {
        let temp = tempfile::tempdir().expect("temp dir");
        let fs = filesystem(&temp, Arc::new(FakeBackend::default()));
        let reservation = fs.reserve_path("personal", "/note.txt").expect("reserve");
        match fs.reserve_path("personal", "/note.txt") {
            Err(error) => assert_eq!(error.kind, ErrorKind::Conflict),
            Ok(_) => panic!("duplicate reservation unexpectedly succeeded"),
        }
        drop(reservation);
        assert!(fs.reserve_path("personal", "/note.txt").is_ok());
    }

    #[test]
    fn encrypted_directory_move_reservation_excludes_descendant_mutations() {
        let temp = tempfile::tempdir().unwrap();
        let (filesystem, _control, generation, _root) =
            writable_vault_filesystem(&temp, Arc::new(FakeVaultWriteBackend::with_root()));
        let filesystem = Arc::new(filesystem);
        let route = filesystem
            .vault_registry
            .get("encrypted-space", "/", "vault-root-id")
            .unwrap()
            .unwrap();
        let route_id = route.control.route_id();
        let reservations = filesystem
            .reserve_vault_rename_paths(route_id, "/d", "/moved", false)
            .expect("reserve directory subtree and destination atomically");

        for path in ["/d/new.txt", "/d/new-dir"] {
            assert_eq!(
                filesystem
                    .reserve_vault_write(route_id, path)
                    .expect_err("new descendant mutation must be fenced")
                    .kind,
                ErrorKind::Conflict
            );
        }
        let unrelated = filesystem
            .reserve_vault_write(route_id, "/d2/independent.txt")
            .expect("slash-boundary matching must leave sibling subtree alone");
        filesystem.release_write_key(&unrelated);

        let (waiting_tx, waiting_rx) = std::sync::mpsc::channel();
        let waiter = {
            let filesystem = Arc::clone(&filesystem);
            let route = route.clone();
            std::thread::spawn(move || {
                filesystem.wait_for_vault_path_with_hook(
                    &route,
                    generation,
                    "/d/new.txt",
                    Duration::from_secs(2),
                    || {
                        let _ = waiting_tx.send(());
                    },
                )
            })
        };
        waiting_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("descendant lookup reached the subtree reservation wait");
        drop(reservations);
        waiter
            .join()
            .unwrap()
            .expect("dropping directory reservation wakes descendant operation");

        let active_child = filesystem
            .reserve_vault_write(route_id, "/d/child.txt")
            .expect("child writer can start after move reservation releases");
        match filesystem.reserve_vault_rename_paths(route_id, "/d", "/moved", false) {
            Err(error) => assert_eq!(error.kind, ErrorKind::Conflict),
            Ok(guards) => {
                drop(guards);
                panic!("directory move passed an active child writer")
            }
        }
        filesystem.release_write_key(&active_child);
    }

    #[test]
    fn encrypted_rename_reservation_rejects_open_file_and_directory_handles() {
        let temp = tempfile::tempdir().unwrap();
        let (filesystem, control, generation, _root) =
            writable_vault_filesystem(&temp, Arc::new(FakeVaultWriteBackend::with_root()));
        let route_id = control.route_id();
        let file_handle = filesystem
            .register_handle(OpenFile::Vault {
                route: control.clone(),
                generation,
                ino: 91,
                path: "/folder/note.txt".into(),
                handle: None,
            })
            .unwrap();
        let open = filesystem.file_handle(file_handle).unwrap();
        // Rename checks the immutable side index and never locks OpenFile
        // while State is held (the same order used by revoke/purge).
        let _open_guard = open.lock().unwrap();
        match filesystem.reserve_vault_rename_paths(route_id, "/folder", "/moved", false) {
            Err(error) => assert_eq!(error.kind, ErrorKind::Conflict),
            Ok(guards) => {
                drop(guards);
                panic!("open descendant file did not fence its parent move")
            }
        }
        drop(_open_guard);
        {
            let mut state = filesystem.state.lock().unwrap();
            state.file_handles.remove(&file_handle);
            state.vault_file_handles.remove(&file_handle);
            state.directory_handles.insert(
                92,
                DirectoryHandle {
                    entries: Vec::new(),
                    routes: vec![(control.clone(), generation)],
                    locked_vaults: Vec::new(),
                    owner_vault: Some((route_id, generation, 93, "/folder/nested".into())),
                },
            );
        }
        match filesystem.reserve_vault_rename_paths(route_id, "/folder", "/moved", false) {
            Err(error) => assert_eq!(error.kind, ErrorKind::Conflict),
            Ok(guards) => {
                drop(guards);
                panic!("open descendant directory did not fence its parent move")
            }
        }
        assert!(
            filesystem
                .reserve_vault_rename_paths(route_id, "/other", "/renamed", false)
                .is_ok(),
            "unrelated open directory handles do not block a rename"
        );
    }

    #[test]
    fn encrypted_stable_file_rename_allows_only_open_readers_of_current_source() {
        let temp = tempfile::tempdir().unwrap();
        let (filesystem, control, _generation, root) =
            writable_vault_filesystem(&temp, Arc::new(FakeVaultWriteBackend::with_root()));
        let source_ino = filesystem
            .add_node(
                root.ino,
                "note.txt".into(),
                NodeKind::Vault {
                    route: match &root.kind {
                        NodeKind::Vault { route, .. } => route.clone(),
                        _ => unreachable!(),
                    },
                    generation: 1,
                    entry: entry("/note.txt", 4, "v1"),
                },
            )
            .unwrap();
        let route_id = control.route_id();
        filesystem.state.lock().unwrap().vault_file_handles.insert(
            901,
            VaultFileHandleMeta {
                route_id,
                ino: source_ino,
                path: "/note.txt".into(),
                writable: false,
            },
        );

        let reservation = filesystem
            .reserve_vault_rename_paths(route_id, "/note.txt", "/renamed.txt", true)
            .expect("stable source reader may retain its private snapshot across rename");
        assert_eq!(
            filesystem
                .reserve_vault_write(route_id, "/note.txt")
                .expect_err("rename reservation fences a new writer")
                .kind,
            ErrorKind::Conflict
        );
        drop(reservation);

        filesystem
            .state
            .lock()
            .unwrap()
            .vault_file_handles
            .get_mut(&901)
            .unwrap()
            .writable = true;
        let writer_error = match filesystem.reserve_vault_rename_paths(
            route_id,
            "/note.txt",
            "/renamed.txt",
            true,
        ) {
            Ok(_) => panic!("writer handles are never allowed across rename"),
            Err(error) => error,
        };
        assert_eq!(writer_error.kind, ErrorKind::Conflict);
        let pending_create_error = match filesystem.reserve_vault_rename_paths(
            route_id,
            "/note.txt",
            "/renamed.txt",
            false,
        ) {
            Ok(_) => panic!("pending-create retarget stays strict"),
            Err(error) => error,
        };
        assert_eq!(pending_create_error.kind, ErrorKind::Conflict);
    }

    #[test]
    fn encrypted_directory_move_and_descendant_writer_race_has_one_winner() {
        use std::sync::Barrier;

        let temp = tempfile::tempdir().unwrap();
        let filesystem = Arc::new(filesystem(&temp, Arc::new(FakeBackend::default())));
        let barrier = Arc::new(Barrier::new(3));
        let (writer_tx, writer_rx) = std::sync::mpsc::channel();
        let (move_tx, move_rx) = std::sync::mpsc::channel();
        let (release_writer_tx, release_writer_rx) = std::sync::mpsc::channel();
        let (release_move_tx, release_move_rx) = std::sync::mpsc::channel();

        let writer = {
            let filesystem = Arc::clone(&filesystem);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let reservation = filesystem.reserve_vault_write(81, "/d/child.txt");
                writer_tx.send(reservation.is_ok()).unwrap();
                if let Ok(key) = reservation {
                    let _ = release_writer_rx.recv();
                    filesystem.release_write_key(&key);
                }
            })
        };
        let mover = {
            let filesystem = Arc::clone(&filesystem);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let reservation = filesystem.reserve_vault_rename_paths(81, "/d", "/moved", false);
                move_tx.send(reservation.is_ok()).unwrap();
                if let Ok(guards) = reservation {
                    let _ = release_move_rx.recv();
                    drop(guards);
                }
            })
        };

        barrier.wait();
        let writer_won = writer_rx.recv().unwrap();
        let move_won = move_rx.recv().unwrap();
        assert_ne!(
            writer_won, move_won,
            "mutex-protected reservation must allow exactly one overlapping operation"
        );
        let _ = release_writer_tx.send(());
        let _ = release_move_tx.send(());
        writer.join().unwrap();
        mover.join().unwrap();
        assert!(filesystem.state.lock().unwrap().active_writers.is_empty());
    }

    #[test]
    fn reconnect_updates_existing_mount_root_permissions_and_write_gate() {
        let temp = tempfile::tempdir().unwrap();
        let backend = Arc::new(FakeBackend::with_file("/temp", b"new"));
        let mut filesystem = filesystem(&temp, backend);
        // Model the read-only namespace returned at an offline mount start.
        filesystem
            .mounted_spaces
            .get_mut("personal")
            .unwrap()
            .writable = false;
        let parent = Node {
            ino: PERSONAL,
            parent: ROOT,
            name: "Personal".into(),
            kind: NodeKind::Personal {
                space: "personal".into(),
            },
            metadata_expires_at: Instant::now(),
        };
        assert_eq!(filesystem.attr(&parent).perm, 0o555);
        assert!(filesystem.child_path(&parent, "new.txt").is_err());
        let proof = filesystem.engine.probe_live_namespace().unwrap();
        filesystem.engine.publish_live_namespace(proof).unwrap();
        assert_eq!(filesystem.attr(&parent).perm, 0o755);
        assert!(filesystem.child_path(&parent, "new.txt").is_ok());
    }

    #[test]
    fn ordinary_rename_waits_for_release_and_reserves_both_paths() {
        let temp = tempfile::tempdir().unwrap();
        let backend = Arc::new(FakeBackend::with_file("/temp", b"new"));
        let filesystem = Arc::new(filesystem(&temp, backend));
        let key = "personal\0/temp";
        filesystem
            .state
            .lock()
            .unwrap()
            .active_writers
            .insert(key.into());
        let (waiting_tx, waiting_rx) = std::sync::mpsc::channel();
        let waiter = {
            let filesystem = Arc::clone(&filesystem);
            std::thread::spawn(move || {
                let guards = filesystem
                    .reserve_ordinary_rename_paths(
                        ("personal", "/temp"),
                        ("personal", "/destination"),
                        Duration::from_secs(2),
                        || {
                            let _ = waiting_tx.send(());
                        },
                    )
                    .unwrap();
                assert!(filesystem.reserve_path("personal", "/temp").is_err());
                assert!(filesystem.reserve_path("personal", "/destination").is_err());
                drop(guards);
            })
        };
        waiting_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("wait entered with state mutex held");
        filesystem.release_write_key(key);
        waiter.join().unwrap();
        assert!(filesystem.state.lock().unwrap().active_writers.is_empty());
    }

    #[test]
    fn ordinary_rename_blocks_new_descendants_and_ancestors_while_waiting() {
        let temp = tempfile::tempdir().unwrap();
        let filesystem = Arc::new(filesystem(
            &temp,
            Arc::new(FakeBackend::with_file("/dir/child", b"data")),
        ));
        let writer = filesystem.reserve_path("personal", "/dir/child").unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|threads| {
            let fs = &filesystem;
            let waiter = threads.spawn(move || {
                let guards = fs
                    .reserve_ordinary_rename_paths(
                        ("personal", "/dir"),
                        ("personal", "/target"),
                        Duration::from_secs(2),
                        || {
                            let _ = tx.send(());
                        },
                    )
                    .unwrap();
                assert!(fs.reserve_path("personal", "/dir/new").is_err());
                assert!(fs.reserve_path("personal", "/target/new").is_err());
                drop(guards);
            });
            rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(filesystem.reserve_path("personal", "/dir/new").is_err());
            assert!(filesystem.reserve_path("personal", "/target/new").is_err());
            assert!(filesystem.reserve_path("personal", "/").is_err());
            assert!(filesystem.reserve_path("personal", "/dir2/new").is_ok());
            assert!(filesystem.reserve_path("other", "/dir/new").is_ok());
            assert!(
                filesystem
                    .reserve_ordinary_rename_paths(
                        ("personal", "/"),
                        ("personal", "/elsewhere"),
                        Duration::ZERO,
                        || {},
                    )
                    .is_err()
            );
            drop(writer);
            waiter.join().unwrap();
        });
        assert!(filesystem.state.lock().unwrap().active_writers.is_empty());
    }

    #[test]
    fn ordinary_rename_preserves_failed_descendant_release_recovery() {
        for path in ["/dir/child", "/target/child"] {
            let temp = tempfile::tempdir().unwrap();
            let filesystem = filesystem(
                &temp,
                Arc::new(FakeBackend::with_file("/dir/child", b"data")),
            );
            let writer = filesystem.reserve_path("personal", path).unwrap();
            let (data, metadata) = filesystem.spool_paths("personal", path);
            fs::write(&data, b"unsent descendant edit").unwrap();
            let manifest = serde_json::to_vec(&["personal", path, "absent", ""]).unwrap();
            fs::write(&metadata, &manifest).unwrap();
            drop(writer); // Model failed RELEASE: reservation retired, bytes retained.
            assert!(
                filesystem
                    .reserve_ordinary_rename_paths(
                        ("personal", "/dir"),
                        ("personal", "/target"),
                        Duration::ZERO,
                        || {},
                    )
                    .is_err()
            );
            assert_eq!(fs::read(&data).unwrap(), b"unsent descendant edit");
            assert_eq!(fs::read(&metadata).unwrap(), manifest);
            assert!(filesystem.state.lock().unwrap().active_writers.is_empty());
            assert!(
                filesystem
                    .reserve_ordinary_rename_paths(
                        ("personal", "/dir2"),
                        ("personal", "/independent"),
                        Duration::ZERO,
                        || {},
                    )
                    .is_ok()
            );
        }
    }

    #[test]
    fn ordinary_rename_rejects_unidentified_and_temporary_recovery() {
        for name in [
            "unknown.data",
            ".provider-manifest-1-1.tmp",
            "unknown-directory",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let filesystem = filesystem(
                &temp,
                Arc::new(FakeBackend::with_file("/dir/child", b"data")),
            );
            let path = filesystem.spool_dir.join(name);
            fs::write(&path, b"unidentified recovery").unwrap();
            assert!(
                filesystem
                    .reserve_ordinary_rename_paths(
                        ("personal", "/dir"),
                        ("personal", "/target"),
                        Duration::ZERO,
                        || {},
                    )
                    .is_err()
            );
            assert_eq!(fs::read(path).unwrap(), b"unidentified recovery");
            assert!(filesystem.state.lock().unwrap().active_writers.is_empty());
        }
    }

    #[test]
    fn ordinary_rename_descendant_timeout_releases_only_its_markers() {
        let temp = tempfile::tempdir().unwrap();
        let filesystem = filesystem(
            &temp,
            Arc::new(FakeBackend::with_file("/dir/child", b"data")),
        );
        let writer = filesystem
            .reserve_path("personal", "/target/child")
            .unwrap();
        assert!(
            filesystem
                .reserve_ordinary_rename_paths(
                    ("personal", "/dir"),
                    ("personal", "/target"),
                    Duration::ZERO,
                    || {},
                )
                .is_err()
        );
        assert!(
            filesystem
                .reserve_path("personal", "/target/child")
                .is_err()
        );
        assert!(filesystem.reserve_path("personal", "/dir/new").is_ok());
        assert_eq!(filesystem.state.lock().unwrap().active_writers.len(), 1);
        drop(writer);
    }

    #[test]
    fn ordinary_rename_timeout_preserves_writer_and_recovery_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let backend = Arc::new(FakeBackend::with_file("/temp", b"new"));
        let filesystem = filesystem(&temp, backend);
        let writer = filesystem.reserve_path("personal", "/temp").unwrap();
        let (spool, manifest) = filesystem.spool_paths("personal", "/temp");
        fs::create_dir_all(spool.parent().unwrap()).unwrap();
        fs::write(&spool, b"dirty").unwrap();
        fs::write(&manifest, b"recovery metadata").unwrap();
        let result = filesystem.reserve_ordinary_rename_paths(
            ("personal", "/temp"),
            ("personal", "/destination"),
            Duration::ZERO,
            || {},
        );
        assert!(matches!(
            result,
            Err(CloudError {
                kind: ErrorKind::Conflict,
                ..
            })
        ));
        assert!(filesystem.reserve_path("personal", "/temp").is_err());
        assert!(filesystem.reserve_path("personal", "/destination").is_ok());
        assert_eq!(fs::read(spool).unwrap(), b"dirty");
        assert_eq!(fs::read(manifest).unwrap(), b"recovery metadata");
        drop(writer);
    }

    #[test]
    fn encrypted_rename_wait_observes_close_release_without_timing_race() {
        let temp = tempfile::tempdir().unwrap();
        let backend = Arc::new(FakeBackend::with_file("/ordinary.txt", b"ordinary"));
        let filesystem = Arc::new(filesystem(&temp, backend));
        let route_id = 73;
        let key = format!("vault-write:{route_id}:\0/folder/file.txt");
        filesystem
            .state
            .lock()
            .unwrap()
            .active_writers
            .insert(key.clone());

        let (waiting_tx, waiting_rx) = std::sync::mpsc::channel();
        let waiter = {
            let filesystem = Arc::clone(&filesystem);
            std::thread::spawn(move || {
                filesystem.wait_for_vault_writers_with_hook(
                    route_id,
                    "/folder/file.txt",
                    "/folder/renamed.txt",
                    Duration::from_secs(2),
                    || waiting_tx.send(()).unwrap(),
                )
            })
        };
        // The hook runs with the provider state mutex held immediately before
        // Condvar::wait atomically releases it, so this notify cannot be lost.
        waiting_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("rename waiter reached the release wait");
        filesystem.release_write_key(&key);
        waiter
            .join()
            .unwrap()
            .expect("close release should wake the waiting rename");
        assert!(filesystem.state.lock().unwrap().active_writers.is_empty());
    }

    #[test]
    fn vault_reopen_waits_for_async_release_and_revoke_cancels_waiter() {
        use std::sync::mpsc;

        let temp = tempfile::tempdir().unwrap();
        let (filesystem, control, generation, _root) =
            writable_vault_filesystem(&temp, Arc::new(FakeVaultWriteBackend::with_root()));
        let filesystem = Arc::new(filesystem);
        let route = filesystem
            .vault_registry
            .get("encrypted-space", "/", "vault-root-id")
            .unwrap()
            .unwrap();
        let path = "/work/nested/reopened.txt";
        let key = format!("vault-write:{}:\0{path}", route.control.route_id());

        filesystem
            .state
            .lock()
            .unwrap()
            .active_writers
            .insert(key.clone());
        let (waiting_tx, waiting_rx) = mpsc::channel();
        let waiter = {
            let waiter_fs = Arc::clone(&filesystem);
            let route = route.clone();
            std::thread::spawn(move || {
                waiter_fs.wait_for_vault_path_with_hook(
                    &route,
                    generation,
                    path,
                    Duration::from_secs(2),
                    || waiting_tx.send(()).unwrap(),
                )
            })
        };
        waiting_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("immediate reopen reached the asynchronous release wait");
        // This is the same notification path used by VaultWriteHandle::drop
        // after its release callback finishes commit/retirement.
        filesystem.release_write_key(&key);
        waiter
            .join()
            .unwrap()
            .expect("immediate reopen should continue after close release");

        let path = "/work/nested/locked.txt";
        let key = format!("vault-write:{}:\0{path}", route.control.route_id());
        filesystem.state.lock().unwrap().active_writers.insert(key);
        let (waiting_tx, waiting_rx) = mpsc::channel();
        let fs_for_wait = Arc::clone(&filesystem);
        let route_for_wait = route.clone();
        let waiter = std::thread::spawn(move || {
            fs_for_wait.wait_for_vault_path_with_hook(
                &route_for_wait,
                generation,
                path,
                Duration::from_secs(2),
                || waiting_tx.send(()).unwrap(),
            )
        });
        waiting_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("second operation reached the wait");
        assert!(
            control.revoke(|| Ok(())).is_err(),
            "synthetic mount has no notifier, but revoke still purges route state"
        );
        assert_eq!(
            waiter.join().unwrap().unwrap_err().kind,
            ErrorKind::Unauthorized,
            "a waiter must cancel when lock advances the route generation"
        );
    }

    #[test]
    fn ordinary_manifest_rejects_malformed_conditions_without_modification() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("write.meta");
        let scope = CacheScope::new(
            "https://cloud.example.test/",
            "account",
            "space",
            "root",
            raiun_cache::ScopeProtection::PlaintextAllowed,
        )
        .unwrap();
        write_manifest(&path, &scope, None, "/file", &WriteCondition::Absent).unwrap();
        let valid = fs::read(&path).unwrap();
        assert_eq!(
            read_manifest(&path, &scope, None, "/file").unwrap(),
            Some(WriteCondition::Absent)
        );
        for (condition, etag, unknown) in [
            ("absent", "unexpected", false),
            ("match", "bad\nheader", false),
            ("match", "", false),
            ("absent", "", true),
        ] {
            let mut value: serde_json::Value = serde_json::from_slice(&valid).unwrap();
            value["condition"] = condition.into();
            value["etag"] = etag.into();
            if unknown {
                value["unknown"] = true.into();
            }
            let bytes = serde_json::to_vec(&value).unwrap();
            fs::write(&path, &bytes).unwrap();
            assert!(read_manifest(&path, &scope, None, "/file").is_err());
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
    }

    #[test]
    fn ordinary_write_manifest_binds_account_origin_root_and_resource() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = temp.path().join("write.meta");
        let scope = CacheScope::new(
            "https://cloud.example.test/",
            "account-a",
            "space-a",
            "root-a",
            raiun_cache::ScopeProtection::PlaintextAllowed,
        )
        .unwrap();
        write_manifest(
            &manifest,
            &scope,
            Some("resource-a"),
            "/folder/file.txt",
            &WriteCondition::Match("etag-a".into()),
        )
        .unwrap();
        assert_eq!(
            read_manifest(&manifest, &scope, Some("resource-a"), "/folder/file.txt").unwrap(),
            Some(WriteCondition::Match("etag-a".into()))
        );
        let replaced_root = CacheScope::new(
            "https://cloud.example.test/",
            "account-a",
            "space-a",
            "root-replaced",
            raiun_cache::ScopeProtection::PlaintextAllowed,
        )
        .unwrap();
        assert_eq!(
            read_manifest(
                &manifest,
                &replaced_root,
                Some("resource-a"),
                "/folder/file.txt"
            )
            .unwrap_err()
            .kind,
            ErrorKind::Conflict
        );
        for (origin, account, space, root) in [
            (
                "https://other.example.test/",
                "account-a",
                "space-a",
                "root-a",
            ),
            (
                "https://cloud.example.test/",
                "account-b",
                "space-a",
                "root-a",
            ),
            (
                "https://cloud.example.test/",
                "account-a",
                "space-b",
                "root-a",
            ),
        ] {
            let replaced_scope = CacheScope::new(
                origin,
                account,
                space,
                root,
                raiun_cache::ScopeProtection::PlaintextAllowed,
            )
            .unwrap();
            assert_eq!(
                read_manifest(
                    &manifest,
                    &replaced_scope,
                    Some("resource-a"),
                    "/folder/file.txt"
                )
                .unwrap_err()
                .kind,
                ErrorKind::Conflict
            );
        }
        assert_eq!(
            read_manifest(
                &manifest,
                &scope,
                Some("resource-replaced"),
                "/folder/file.txt"
            )
            .unwrap_err()
            .kind,
            ErrorKind::Conflict
        );
        assert_eq!(
            read_manifest(&manifest, &scope, Some("resource-a"), "/folder/other.txt")
                .unwrap_err()
                .kind,
            ErrorKind::Conflict
        );
        let mut old_version: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
        old_version["version"] = serde_json::json!(1);
        fs::write(&manifest, serde_json::to_vec(&old_version).unwrap()).unwrap();
        assert!(
            read_manifest(&manifest, &scope, Some("resource-a"), "/folder/file.txt")
                .unwrap_err()
                .message
                .contains("does not match")
        );
        fs::write(
            &manifest,
            serde_json::to_vec(&["space-a", "/folder/file.txt", "match", "etag-old"]).unwrap(),
        )
        .unwrap();
        let legacy =
            read_manifest(&manifest, &scope, Some("resource-a"), "/folder/file.txt").unwrap_err();
        assert!(legacy.message.contains("recovery-only"));
    }

    #[test]
    fn mount_refuses_nonempty_root_before_mounting() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("cloud 日本語");
        fs::create_dir(&root).expect("mount dir");
        fs::write(root.join("keep.txt"), b"keep").expect("marker");
        let engine = Engine::open(
            &temp.path().join("engine"),
            Arc::new(FakeBackend::default()),
        )
        .expect("engine");
        let error = match mount(engine, &root, &temp.path().join("state")) {
            Ok(_) => panic!("mount unexpectedly accepted a nonempty root"),
            Err(error) => error,
        };
        assert!(error.contains("must be empty"));
        assert_eq!(
            fs::read(root.join("keep.txt")).expect("marker preserved"),
            b"keep"
        );
    }

    #[test]
    #[ignore = "requires an explicitly requested isolated host FUSE mount"]
    fn live_fuse_roundtrip_when_device_is_available() {
        assert!(
            Path::new("/dev/fuse").exists(),
            "host FUSE device is required"
        );
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("cloud 日本語");
        let state = temp.path().join("state");
        fs::create_dir(&root).expect("mount directory");
        let backend = Arc::new(FakeBackend::with_file("/note.txt", b"hello"));
        backend.replace_for_test("/replace.txt", b"old", "r1");
        let engine = Engine::open(&state.join("engine"), backend.clone())
            .expect("engine")
            .with_account_scope("fuse-test-account".into(), "https://example.invalid".into())
            .expect("bind synthetic account scope");
        let mount_handle = mount(engine.clone(), &root, &state).expect("isolated FUSE mount");

        assert_eq!(
            fs::read(root.join("Personal/note.txt")).expect("read mounted file"),
            b"hello"
        );
        backend.replace_for_test("/note.txt", b"changed!", "v2");
        assert_eq!(
            fs::read(root.join("Personal/note.txt")).expect("read refreshed file"),
            b"changed!"
        );
        assert_eq!(
            fs::metadata(root.join("Personal/note.txt"))
                .expect("refreshed metadata")
                .len(),
            8
        );
        fs::write(root.join("Personal/new.txt"), b"from fuse")
            .expect("create and write through FUSE");
        assert_eq!(
            backend
                .stat("personal", "/new.txt")
                .expect("uploaded file")
                .size,
            9
        );
        fs::write(root.join("Personal/.temp-save"), b"replacement")
            .expect("write editor temporary file");
        fs::rename(
            root.join("Personal/.temp-save"),
            root.join("Personal/replace.txt"),
        )
        .expect("replace an existing file without overwriting it in place");
        let fetched = temp.path().join("replacement-check");
        backend
            .download("personal", "/replace.txt", None, &fetched)
            .expect("replacement downloaded");
        assert_eq!(
            fs::read(fetched).expect("replacement contents"),
            b"replacement"
        );

        fs::write(root.join("Personal/replace.txt"), b"in-place overwrite")
            .expect("truncate and write an existing remote file");
        assert_eq!(
            fs::read(root.join("Personal/replace.txt")).expect("read overwritten file"),
            b"in-place overwrite"
        );

        drop(mount_handle);

        // A fresh FUSE instance has no cached inode for this existing path.
        // `std::fs::write` opens with create+truncate and must route through
        // the existing-file branch while retaining a Match(etag) condition.
        let remounted = mount(engine, &root, &state).expect("remount with empty inode cache");
        fs::write(
            root.join("Personal/replace.txt"),
            b"overwrite after remount",
        )
        .expect("open and overwrite an uncached existing file");
        assert_eq!(
            fs::read(root.join("Personal/replace.txt")).expect("read remounted overwrite"),
            b"overwrite after remount"
        );
        drop(remounted);
    }

    #[test]
    #[ignore = "requires an explicitly requested isolated host FUSE mount"]
    fn live_fuse_dual_profile_mounts_are_isolated_and_owned_cleanup_is_exact() {
        assert!(
            Path::new("/dev/fuse").exists(),
            "host FUSE device is required"
        );
        let temp = tempfile::tempdir().expect("temp dir");
        let root_a = temp.path().join("profile-a-root");
        let root_b = temp.path().join("profile-b-root");
        let state_a = temp.path().join("profile-a-state");
        let state_b = temp.path().join("profile-b-state");
        fs::create_dir(&root_a).expect("profile A mount directory");
        fs::create_dir(&root_b).expect("profile B mount directory");

        let backend_a = Arc::new(FakeBackend::with_file("/note.txt", b"account-a"));
        let backend_b = Arc::new(FakeBackend::with_file("/note.txt", b"account-b"));
        let engine_a = Engine::open(&state_a.join("engine"), backend_a)
            .expect("engine A")
            .with_account_scope("account-a".into(), "https://example.invalid".into())
            .expect("bind account A scope");
        let engine_b = Engine::open(&state_b.join("engine"), backend_b)
            .expect("engine B")
            .with_account_scope("account-b".into(), "https://example.invalid".into())
            .expect("bind account B scope");
        let mount_a = mount(engine_a, &root_a, &state_a).expect("mount profile A");
        let mut mount_b = mount(engine_b, &root_b, &state_b).expect("mount profile B");
        let source_a = mount_a.source.clone();
        let source_b = mount_b.source.clone();

        let note_a = root_a.join("Personal/note.txt");
        let note_b = root_b.join("Personal/note.txt");
        assert_eq!(fs::read(&note_a).expect("read profile A"), b"account-a");
        assert_eq!(fs::read(&note_b).expect("read profile B"), b"account-b");
        assert!(mount_a.is_mounted());
        assert!(mount_b.is_mounted());
        assert!(mountpoint_has_source(&root_a, &mount_a.source).expect("A mount source"));
        assert!(mountpoint_has_source(&root_b, &mount_b.source).expect("B mount source"));

        assert!(
            unmount_profile_mount(&root_a, &state_b).is_err(),
            "another profile must not detach A's owned mount"
        );
        assert!(mount_a.is_mounted());
        assert!(mount_b.is_mounted());

        fs::write(&note_a, b"changed only in A").expect("write through profile A");
        assert_eq!(
            fs::read(&note_a).expect("read updated profile A"),
            b"changed only in A"
        );
        assert_eq!(
            fs::read(&note_b).expect("profile B stays unchanged"),
            b"account-b"
        );
        fs::write(root_a.join("Personal/a-only.txt"), b"only A").expect("create A-only file");
        assert!(!root_b.join("Personal/a-only.txt").exists());

        assert!(
            unmount_profile_mount(&root_a, &state_a).expect("unmount exact profile A owner"),
            "profile A owner must detach its mount"
        );
        assert!(!mount_a.is_mounted());
        assert!(mount_b.is_mounted(), "profile B mount remains attached");
        assert!(mountpoint_has_source(&root_b, &mount_b.source).expect("B mount source remains"));
        assert_eq!(
            fs::read(&note_b).expect("profile B remains readable"),
            b"account-b"
        );
        fs::write(root_b.join("Personal/b-still-live.txt"), b"still B")
            .expect("profile B remains writable");
        assert_eq!(
            fs::read(root_b.join("Personal/b-still-live.txt")).expect("read B write"),
            b"still B"
        );

        drop(mount_a);
        mount_b.unmount().expect("unmount profile B");
        assert!(!mount_b.is_mounted());
        drop(mount_b);
        assert!(!mountpoint_has_source(&root_a, &source_a).expect("profile A detached"));
        assert!(!mountpoint_has_source(&root_b, &source_b).expect("profile B detached"));
    }

    #[test]
    #[ignore = "requires an explicitly requested isolated host FUSE mount"]
    fn live_fuse_folder_vault_browses_read_only_and_revokes_open_handles() {
        assert!(
            Path::new("/dev/fuse").exists(),
            "host FUSE device is required"
        );
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("vault mount");
        let state_dir = temp.path().join("vault state");
        fs::create_dir(&root).expect("mount root");

        let backend = Arc::new(FakeBackend::with_file("/outside.txt", b"outside"));
        backend.files.lock().unwrap().insert(
            ("personal".into(), "/Vault".into()),
            (
                RemoteEntry {
                    id: "vault-root-id".into(),
                    path: "/Vault".into(),
                    directory: true,
                    size: 0,
                    etag: "remote-vault-etag".into(),
                    modified_unix: 1,
                    writable: true,
                    encrypted: true,
                },
                Vec::new(),
            ),
        );
        let control = VaultRouteControl::new();
        control
            .install_backend(Arc::new(FakeVaultReadBackend))
            .expect("unlock synthetic vault route");
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    "personal".into(),
                    "/Vault".into(),
                    "vault-root-id".into(),
                    control.clone(),
                )
                .expect("route descriptor"),
            )
            .expect("register route");
        let engine = Engine::open(&state_dir.join("engine"), backend).expect("engine");
        let mount = mount_with_vault_registry(engine, &root, &state_dir, registry)
            .expect("mount synthetic vault");

        let vault = root.join("Personal/Vault");
        let file_path = vault.join("hello.txt");
        assert_eq!(
            fs::read(&file_path).expect("read decrypted file"),
            b"vault secret"
        );
        assert!(fs::write(&file_path, b"must not write").is_err());
        assert!(fs::create_dir(vault.join("new-dir")).is_err());
        assert!(fs::remove_file(&file_path).is_err());
        assert!(fs::rename(&file_path, root.join("Personal/moved.txt")).is_err());
        assert!(
            fs::rename(
                root.join("Personal/outside.txt"),
                vault.join("moved-in.txt")
            )
            .is_err()
        );
        assert!(file_path.exists());
        assert!(!vault.join("new-dir").exists());
        assert!(!root.join("Personal/moved.txt").exists());
        assert!(!vault.join("moved-in.txt").exists());

        let mut stale_file = fs::File::open(&file_path).expect("open vault file handle");
        let mut prefix = [0; 5];
        stale_file
            .read_exact(&mut prefix)
            .expect("read initial plaintext");
        assert_eq!(&prefix, b"vault");
        let stale_directory = fs::read_dir(&vault).expect("open vault directory handle");
        let personal = root.join("Personal");
        // Open ordinary-parent snapshots before lock but deliberately do not
        // iterate them yet, so no userspace-buffered names can be mistaken for
        // a post-lock FUSE readdir response.
        let stale_personal_during_lock =
            fs::read_dir(&personal).expect("open Personal snapshot before lock");
        let stale_personal_after_unlock =
            fs::read_dir(&personal).expect("open second Personal snapshot before lock");

        control
            .revoke(|| Ok(()))
            .expect("revoke and purge encrypted route");
        stale_file
            .seek(SeekFrom::Start(0))
            .expect("rewind stale handle after lock");
        assert!(stale_file.read(&mut prefix).is_err());
        assert!(stale_directory.collect::<Result<Vec<_>, _>>().is_err());
        assert!(
            stale_personal_during_lock
                .collect::<Result<Vec<_>, _>>()
                .is_err()
        );
        let locked_personal_names: Vec<_> = fs::read_dir(&personal)
            .expect("open fresh Personal snapshot while locked")
            .map(|entry| entry.expect("locked parent entry").file_name())
            .collect();
        assert!(
            locked_personal_names
                .iter()
                .any(|name| name == OsStr::new("Vault"))
        );
        let stale_locked_personal =
            fs::read_dir(&personal).expect("open locked parent snapshot before unlock");
        let locked_vault_names: Vec<_> = fs::read_dir(&vault)
            .expect("open locked placeholder")
            .map(|entry| entry.expect("locked placeholder entry").file_name())
            .collect();
        assert_eq!(locked_vault_names, vec!["README.txt"]);
        let notice = fs::read_to_string(vault.join("README.txt")).expect("read lock notice");
        assert!(notice.contains("This encrypted location is locked"));
        assert!(notice.contains(
            "raiun://unlock?v=1&profile_id=default&space_id=personal&root_resource_id=vault-root-id"
        ));
        assert!(fs::read(&file_path).is_err());

        control
            .install_backend(Arc::new(FakeVaultReadBackend))
            .expect("unlock into a new route generation");
        assert!(
            stale_locked_personal
                .collect::<Result<Vec<_>, _>>()
                .is_err(),
            "a parent snapshot containing the locked placeholder must be revoked on unlock"
        );
        assert_eq!(
            fs::read(&file_path).expect("read after unlock"),
            b"vault secret"
        );
        stale_file
            .seek(SeekFrom::Start(0))
            .expect("rewind old-generation handle after unlock");
        assert!(stale_file.read(&mut prefix).is_err());
        assert!(
            stale_personal_after_unlock
                .collect::<Result<Vec<_>, _>>()
                .is_err()
        );
        let unlocked_personal_names: Vec<_> = fs::read_dir(&personal)
            .expect("open fresh Personal snapshot after unlock")
            .map(|entry| entry.expect("unlocked parent entry").file_name())
            .collect();
        assert!(
            unlocked_personal_names
                .iter()
                .any(|name| name == OsStr::new("Vault"))
        );

        drop(stale_file);
        drop(mount);
        assert!(
            fs::read_dir(&root)
                .expect("inspect detached mount")
                .next()
                .is_none()
        );
    }

    #[test]
    #[ignore = "requires an explicitly requested isolated host FUSE mount"]
    fn live_fuse_whole_space_vault_browses_read_only_and_revokes_parent_snapshots() {
        assert!(
            Path::new("/dev/fuse").exists(),
            "host FUSE device is required"
        );
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("whole-space vault mount");
        let state_dir = temp.path().join("whole-space vault state");
        fs::create_dir(&root).expect("mount root");

        let backend = Arc::new(FakeBackend::with_file("/outside.txt", b"outside"));
        *backend.spaces_override.lock().unwrap() = Some(vec![
            CloudSpace {
                id: "personal".into(),
                name: "Personal".into(),
                dav_url: "https://example.invalid/dav/personal".into(),
                personal: true,
                writable: true,
                encrypted: false,
            },
            CloudSpace {
                id: "encrypted-space".into(),
                name: "Encrypted Projects".into(),
                dav_url: "https://example.invalid/dav/encrypted".into(),
                personal: false,
                writable: true,
                encrypted: true,
            },
        ]);
        let control = VaultRouteControl::new();
        control
            .install_backend(Arc::new(FakeVaultReadBackend))
            .expect("unlock synthetic Space route");
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    "encrypted-space".into(),
                    "/".into(),
                    "vault-root-id".into(),
                    control.clone(),
                )
                .expect("whole-Space route descriptor"),
            )
            .expect("register whole-Space route");
        let engine = Engine::open(&state_dir.join("engine"), backend).expect("engine");
        let mount = mount_with_vault_registry(engine, &root, &state_dir, registry)
            .expect("mount synthetic whole-Space vault");

        let vault = root.join("Spaces/Encrypted Projects");
        let file_path = vault.join("hello.txt");
        assert_eq!(
            fs::read(&file_path).expect("read decrypted Space file"),
            b"vault secret"
        );
        assert!(fs::write(&file_path, b"must not write").is_err());
        assert!(fs::create_dir(vault.join("new-dir")).is_err());
        assert!(fs::remove_file(&file_path).is_err());
        assert!(fs::rename(&file_path, root.join("Personal/moved.txt")).is_err());
        assert!(
            fs::rename(
                root.join("Personal/outside.txt"),
                vault.join("moved-in.txt")
            )
            .is_err()
        );
        assert!(file_path.exists());
        assert!(!vault.join("new-dir").exists());
        assert!(!root.join("Personal/moved.txt").exists());
        assert!(!vault.join("moved-in.txt").exists());

        let mut stale_file = fs::File::open(&file_path).expect("open whole-Space file handle");
        let mut prefix = [0; 5];
        stale_file
            .read_exact(&mut prefix)
            .expect("read initial decrypted bytes");
        let spaces = root.join("Spaces");
        // Open parent snapshots but don't iterate them before lock, so the
        // assertion tests a FUSE readdir after revocation rather than bytes
        // already buffered by libc.
        let stale_spaces_during_lock = fs::read_dir(&spaces).expect("open Spaces snapshot");
        let stale_spaces_after_unlock = fs::read_dir(&spaces).expect("open second Spaces snapshot");

        control
            .revoke(|| Ok(()))
            .expect("revoke and purge Space route");
        stale_file
            .seek(SeekFrom::Start(0))
            .expect("rewind stale file");
        assert!(stale_file.read(&mut prefix).is_err());
        assert!(
            stale_spaces_during_lock
                .collect::<Result<Vec<_>, _>>()
                .is_err()
        );
        let locked_spaces: Vec<_> = fs::read_dir(&spaces)
            .expect("fresh Spaces listing while locked")
            .map(|entry| entry.expect("locked Space entry").file_name())
            .collect();
        assert!(
            locked_spaces
                .iter()
                .any(|name| name == OsStr::new("Encrypted Projects"))
        );
        let stale_locked_spaces =
            fs::read_dir(&spaces).expect("open locked Spaces snapshot before unlock");
        let locked_space_names: Vec<_> = fs::read_dir(&vault)
            .expect("open locked whole-Space placeholder")
            .map(|entry| entry.expect("locked Space placeholder entry").file_name())
            .collect();
        assert_eq!(locked_space_names, vec!["README.txt"]);
        let notice = fs::read_to_string(vault.join("README.txt")).expect("read lock notice");
        assert!(notice.contains("This encrypted location is locked"));
        assert!(notice.contains(
            "raiun://unlock?v=1&profile_id=default&space_id=encrypted-space&root_resource_id=vault-root-id"
        ));
        assert!(fs::read(&file_path).is_err());

        control
            .install_backend(Arc::new(FakeVaultReadBackend))
            .expect("unlock a new Space route generation");
        assert!(
            stale_locked_spaces.collect::<Result<Vec<_>, _>>().is_err(),
            "a Spaces snapshot containing the locked placeholder must be revoked on unlock"
        );
        assert_eq!(
            fs::read(&file_path).expect("read after unlock"),
            b"vault secret"
        );
        stale_file
            .seek(SeekFrom::Start(0))
            .expect("rewind old-generation file");
        assert!(stale_file.read(&mut prefix).is_err());
        assert!(
            stale_spaces_after_unlock
                .collect::<Result<Vec<_>, _>>()
                .is_err()
        );
        let unlocked_spaces: Vec<_> = fs::read_dir(&spaces)
            .expect("fresh Spaces listing after unlock")
            .map(|entry| entry.expect("unlocked Space entry").file_name())
            .collect();
        assert!(
            unlocked_spaces
                .iter()
                .any(|name| name == OsStr::new("Encrypted Projects"))
        );

        drop(stale_file);
        drop(mount);
        assert!(
            fs::read_dir(&root)
                .expect("inspect detached mount")
                .next()
                .is_none()
        );
    }

    #[test]
    #[ignore = "requires an explicitly requested isolated host FUSE mount"]
    fn live_fuse_writable_vault_supports_conditional_edits_and_revokes_stale_handles() {
        assert!(
            Path::new("/dev/fuse").exists(),
            "host FUSE device is required"
        );
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("writable vault mount");
        let state_dir = temp.path().join("writable vault state");
        fs::create_dir(&root).expect("mount root");

        let ordinary = Arc::new(FakeBackend::with_file("/outside.txt", b"outside"));
        *ordinary.spaces_override.lock().unwrap() = Some(vec![
            CloudSpace {
                id: "personal".into(),
                name: "Personal".into(),
                dav_url: "https://example.invalid/dav/personal".into(),
                personal: true,
                writable: true,
                encrypted: false,
            },
            CloudSpace {
                id: "encrypted-space".into(),
                name: "Encrypted Projects".into(),
                dav_url: "https://example.invalid/dav/encrypted".into(),
                personal: false,
                writable: true,
                encrypted: true,
            },
        ]);
        let vault = Arc::new(FakeVaultWriteBackend::with_root());
        let control = VaultRouteControl::new();
        control
            .install_writable_backend(vault.clone())
            .expect("install synthetic writable vault");
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    "encrypted-space".into(),
                    "/".into(),
                    "vault-root-id".into(),
                    control.clone(),
                )
                .expect("whole-Space route descriptor"),
            )
            .expect("register writable route");
        let engine = Engine::open(&state_dir.join("engine"), ordinary).expect("engine");
        let mount = mount_with_vault_registry(engine, &root, &state_dir, registry)
            .expect("mount synthetic writable vault");

        let vault_root = root.join("Spaces/Encrypted Projects");
        let folder = vault_root.join("work");
        fs::create_dir(&folder).expect("create encrypted folder");
        let file_path = folder.join("note.txt");
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&file_path)
            .expect("create encrypted file");
        file.write_all(b"first version")
            .expect("write encrypted file");
        file.sync_all().expect("commit first version");
        file.seek(SeekFrom::Start(0)).expect("rewind same handle");
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).expect("read same handle");
        assert_eq!(contents, b"first version");
        file.seek(SeekFrom::Start(0)).expect("rewind for update");
        file.write_all(b"second version")
            .expect("update through same handle");
        file.sync_all().expect("commit updated version");
        drop(file);
        assert_eq!(vault.stat("/work/note.txt").unwrap().size, 14);

        let renamed = folder.join("renamed.txt");
        fs::rename(&file_path, &renamed).expect("rename encrypted file");
        assert_eq!(vault.stat("/work/renamed.txt").unwrap().size, 14);
        fs::remove_file(&renamed).expect("delete encrypted file");
        assert!(vault.stat("/work/renamed.txt").is_err());

        let target = folder.join("document.txt");
        fs::write(&target, b"old document").expect("create target document");
        let temporary = folder.join(".document.txt.editor-tmp");
        fs::write(&temporary, b"saved document").expect("create editor temp file");
        fs::rename(&temporary, &target).expect("replace target with editor save");
        assert_eq!(fs::read(&target).unwrap(), b"saved document");

        let preserve_target = folder.join("preserve.txt");
        fs::write(&preserve_target, b"preserve this").expect("create preserved target");
        let failed_temp = folder.join(".preserve.txt.editor-tmp");
        fs::write(&failed_temp, b"replacement copy").expect("create replacement temp");
        let fail_source_move = vault.rename_calls.load(Ordering::Relaxed) + 2;
        *vault.fail_rename_call.lock().unwrap() = Some(fail_source_move);
        assert!(fs::rename(&failed_temp, &preserve_target).is_err());
        *vault.fail_rename_call.lock().unwrap() = None;
        assert_eq!(fs::read(&preserve_target).unwrap(), b"preserve this");
        assert_eq!(fs::read(&failed_temp).unwrap(), b"replacement copy");
        fs::rename(&failed_temp, &preserve_target).expect("retry editor replacement");
        assert_eq!(fs::read(&preserve_target).unwrap(), b"replacement copy");

        let nested_directory = folder.join("nested-directory");
        fs::create_dir(&nested_directory).expect("create nested encrypted directory");
        let nested_file = nested_directory.join("child.txt");
        fs::write(&nested_file, b"child data").expect("create and close nested file");
        assert_eq!(
            fs::read(&nested_file).expect("immediately reopen nested file"),
            b"child data",
            "a following read must wait for the asynchronous writer release"
        );
        fs::remove_file(&nested_file).expect("unlink the just-written nested file");
        let delete_calls_before_rmdir = vault.delete_calls.load(Ordering::Relaxed);
        assert!(
            fs::remove_dir(&nested_directory).is_err(),
            "directory deletion remains disabled without a membership precondition"
        );
        assert_eq!(
            vault.delete_calls.load(Ordering::Relaxed),
            delete_calls_before_rmdir,
            "directory removal must not send a destructive backend request"
        );
        assert!(nested_directory.is_dir());

        let movable_directory = folder.join("movable-directory");
        fs::create_dir(&movable_directory).expect("create directory-move fixture");
        let movable_child = movable_directory.join("nested-child.txt");
        fs::write(&movable_child, b"move with its descendant")
            .expect("create and close descendant before directory move");
        let moved_directory = folder.join("moved-directory");
        fs::rename(&movable_directory, &moved_directory)
            .expect("move a directory with a closed descendant writer");
        assert!(!movable_directory.exists());
        assert_eq!(
            fs::read(moved_directory.join("nested-child.txt"))
                .expect("read descendant at its moved path"),
            b"move with its descendant"
        );

        let conflict_path = folder.join("conflict.txt");
        fs::write(&conflict_path, b"base").expect("create initial conflict test file");
        let mut conflict = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&conflict_path)
            .expect("open conflict file");
        conflict
            .seek(SeekFrom::Start(0))
            .expect("rewind local conflict edit");
        conflict.write_all(b"local").expect("write local conflict");
        {
            let mut files = vault.files.lock().unwrap();
            let (entry, bytes) = files.get_mut("/work/conflict.txt").unwrap();
            entry.etag = "external-version".into();
            entry.size = 6;
            *bytes = b"remote".to_vec();
        }
        assert!(
            conflict.sync_all().is_err(),
            "stale ETag must reject upload"
        );
        assert_eq!(
            vault.files.lock().unwrap()["/work/conflict.txt"].1,
            b"remote"
        );
        conflict
            .seek(SeekFrom::Start(0))
            .expect("read retained local conflict");
        let mut local_copy = [0; 5];
        conflict
            .read_exact(&mut local_copy)
            .expect("local dirty copy remains readable");
        assert_eq!(&local_copy, b"local");
        let spool = VaultWriteSpool::open_existing(&state_dir.join("provider-spool"))
            .expect("open vault recovery spool")
            .expect("spool exists");
        assert!(
            spool
                .list_pending()
                .expect("list retained conflict")
                .0
                .iter()
                .any(|record| matches!(record.lifecycle, Some(VaultWriteLifecycle::Dirty)))
        );
        drop(conflict);

        let stale_path = folder.join("stale.txt");
        fs::write(&stale_path, b"generation data").expect("create stale-handle test file");
        let mut stale = fs::File::open(&stale_path).expect("open before lock");
        let mut prefix = [0; 4];
        stale.read_exact(&mut prefix).expect("read before lock");
        assert_eq!(&prefix, b"gene");
        control
            .revoke(|| Ok(()))
            .expect("lock and revoke encrypted route");
        stale.seek(SeekFrom::Start(0)).expect("rewind stale handle");
        assert!(stale.read(&mut prefix).is_err());
        control
            .install_writable_backend(vault.clone())
            .expect("unlock into a new route generation");
        stale
            .seek(SeekFrom::Start(0))
            .expect("rewind old generation after unlock");
        assert!(stale.read(&mut prefix).is_err());
        assert_eq!(fs::read(&stale_path).unwrap(), b"generation data");

        drop(stale);
        drop(mount);
        assert!(
            fs::read_dir(&root)
                .expect("inspect detached mount")
                .next()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires an explicitly requested isolated host FUSE mount"]
    fn live_fuse_open_reader_survives_stable_rename_and_lock_revokes_it() {
        use std::{
            fs,
            io::{Read, Seek, SeekFrom},
            os::unix::fs::PermissionsExt,
        };

        assert!(
            Path::new("/dev/fuse").exists(),
            "host FUSE device is required"
        );
        let temp = tempfile::tempdir().expect("temp dir");
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("private fixture directory");
        let root = temp.path().join("open-reader rename mount");
        let state_dir = temp.path().join("open-reader rename state");
        fs::create_dir(&root).expect("mount root");

        let ordinary = Arc::new(FakeBackend::with_file("/outside.txt", b"outside"));
        *ordinary.spaces_override.lock().unwrap() = Some(vec![
            CloudSpace {
                id: "personal".into(),
                name: "Personal".into(),
                dav_url: "https://example.invalid/dav/personal".into(),
                personal: true,
                writable: true,
                encrypted: false,
            },
            CloudSpace {
                id: "encrypted-space".into(),
                name: "Encrypted Projects".into(),
                dav_url: "https://example.invalid/dav/encrypted".into(),
                personal: false,
                writable: true,
                encrypted: true,
            },
        ]);
        let vault = Arc::new(FakeVaultWriteBackend::with_root());
        let plaintext = b"same bytes through the open handle";
        vault.seed_file("/before.txt", plaintext, "source-v1", true);
        let control = VaultRouteControl::new();
        control
            .install_writable_backend(vault)
            .expect("install synthetic writable vault");
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    "encrypted-space".into(),
                    "/".into(),
                    "vault-root-id".into(),
                    control.clone(),
                )
                .expect("whole-Space route descriptor"),
            )
            .expect("register writable route");
        let engine = Engine::open(&state_dir.join("engine"), ordinary).expect("engine");
        let mount = mount_with_vault_registry(engine, &root, &state_dir, registry)
            .expect("mount synthetic vault");

        let cloud_root = root.join("Spaces/Encrypted Projects");
        let original = cloud_root.join("before.txt");
        let renamed = cloud_root.join("after.txt");
        let mut reader = fs::File::open(&original).expect("open stable remote source");
        let mut contents = Vec::new();
        reader
            .read_to_end(&mut contents)
            .expect("read source bytes");
        assert_eq!(contents, plaintext);

        fs::rename(&original, &renamed)
            .expect("stable remote file rename may keep a read-only source handle open");
        assert!(!original.exists());
        assert_eq!(fs::read(&renamed).expect("read renamed path"), plaintext);
        reader
            .seek(SeekFrom::Start(0))
            .expect("rewind original open handle after rename");
        contents.clear();
        reader
            .read_to_end(&mut contents)
            .expect("open handle still reads the same file snapshot");
        assert_eq!(contents, plaintext);

        control
            .revoke(|| Ok(()))
            .expect("lock and revoke vault route");
        reader
            .seek(SeekFrom::Start(0))
            .expect("rewind stale handle after lock");
        assert!(
            reader.read(&mut [0; 1]).is_err(),
            "locking must revoke reads from the handle that survived rename"
        );
        assert!(fs::read(&renamed).is_err(), "locked path reads are denied");
        drop(reader);
        drop(mount);
        assert!(
            fs::read_dir(&root)
                .expect("inspect detached mount")
                .next()
                .is_none()
        );
    }

    #[test]
    #[ignore = "requires an explicitly requested isolated host FUSE mount"]
    fn live_fuse_offline_cache_reads_personal_and_spaces_without_crossing_scope() {
        assert!(
            Path::new("/dev/fuse").exists(),
            "host FUSE device is required"
        );
        let temp = tempfile::tempdir().expect("temporary fixture");
        let backend = Arc::new(FakeBackend::with_file("/placeholder", b"unused"));
        *backend.spaces_override.lock().expect("fake spaces") = Some(vec![
            CloudSpace {
                id: "personal".into(),
                name: "Personal".into(),
                dav_url: "https://example.invalid/dav/personal".into(),
                personal: true,
                writable: true,
                encrypted: false,
            },
            CloudSpace {
                id: "projects".into(),
                name: "Projects".into(),
                dav_url: "https://example.invalid/dav/projects".into(),
                personal: false,
                writable: true,
                encrypted: false,
            },
        ]);
        backend.add_space_entry("personal", "/", b"", true, "p-root-v1");
        backend.add_space_entry("personal", "/Documents", b"", true, "p-docs-v1");
        backend.add_space_entry(
            "personal",
            "/Documents/keep.txt",
            b"personal offline bytes",
            false,
            "p-file-v1",
        );
        backend.add_space_entry("projects", "/", b"", true, "team-root-v1");
        backend.add_space_entry("projects", "/Design", b"", true, "design-v1");
        backend.add_space_entry(
            "projects",
            "/Design/pinned.txt",
            b"pinned space bytes",
            false,
            "team-file-v1",
        );
        backend.add_space_entry(
            "projects",
            "/cloud-only.txt",
            b"must remain online",
            false,
            "cloud-only-v1",
        );

        let engine = Engine::open(&temp.path().join("engine"), backend.clone()).expect("engine");
        let cache_dir = temp.path().join("offline-cache");
        fs::create_dir(&cache_dir).expect("cache state directory");
        #[cfg(unix)]
        fs::set_permissions(
            &cache_dir,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private cache state directory");
        let cache = raiun_cache::Cache::open(&cache_dir, 64 * 1024 * 1024).expect("offline cache");
        let engine = engine
            .with_offline_cache(
                cache,
                "synthetic-account".into(),
                "https://example.invalid".into(),
            )
            .expect("bind cache to synthetic account/server");
        let namespace_snapshot = engine.spaces().expect("capture namespace snapshot");
        let engine = engine
            .with_offline_spaces(namespace_snapshot.clone())
            .expect("attach namespace snapshot");

        // Prime complete directory listings and recent file versions while the
        // synthetic server is online. Pin one nested project folder recursively.
        engine.list("personal", "/").expect("list Personal");
        engine
            .list("personal", "/Documents")
            .expect("list Personal/Documents");
        engine
            .fetch_snapshot("personal", "/Documents/keep.txt")
            .expect("cache Personal file");
        engine.list("projects", "/").expect("list Projects");
        engine
            .pin_offline_tree("projects", "/Design", |_| {})
            .expect("pin Projects/Design");
        // Cache this exact version first, then change only its policy. A later
        // offline read must honor CloudOnly even though old bytes still exist.
        engine
            .fetch_snapshot("projects", "/cloud-only.txt")
            .expect("cache recent cloud-only candidate");
        engine
            .set_availability_policy(
                "projects",
                "/cloud-only.txt",
                raiun_cache::AvailabilityPolicy::CloudOnly,
            )
            .expect("set cloud-only policy online");

        let root = temp.path().join("mounted cloud");
        let state_dir = temp.path().join("mount-state");
        fs::create_dir(&root).expect("mountpoint");
        let first_mount = mount(engine.clone(), &root, &state_dir).expect("mount synthetic FUSE");
        assert_eq!(
            fs::read(root.join("Personal/Documents/keep.txt")).expect("online Personal read"),
            b"personal offline bytes"
        );
        assert_eq!(
            fs::read(root.join("Spaces/Projects/Design/pinned.txt")).expect("online Spaces read"),
            b"pinned space bytes"
        );

        // Fail every protocol operation, including spaces(). Root namespace
        // projection was captured at mount; all per-Space listing/stat/content
        // requests must now use the verified cache fallback.
        backend.set_network_error(Some(ErrorKind::Offline));
        let root_names = fs::read_dir(&root)
            .expect("offline synthetic root")
            .map(|item| item.expect("root entry").file_name())
            .collect::<std::collections::HashSet<_>>();
        assert!(root_names.contains(OsStr::new("Personal")));
        assert!(root_names.contains(OsStr::new("Spaces")));
        let personal_names = fs::read_dir(root.join("Personal"))
            .expect("offline Personal listing")
            .map(|item| item.expect("Personal entry").file_name())
            .collect::<std::collections::HashSet<_>>();
        assert!(personal_names.contains(OsStr::new("Documents")));
        let document_names = fs::read_dir(root.join("Personal/Documents"))
            .expect("offline nested Personal listing")
            .map(|item| item.expect("document entry").file_name())
            .collect::<std::collections::HashSet<_>>();
        assert!(document_names.contains(OsStr::new("keep.txt")));
        let project_names = fs::read_dir(root.join("Spaces"))
            .expect("offline Spaces listing")
            .map(|item| item.expect("Space entry").file_name())
            .collect::<std::collections::HashSet<_>>();
        assert!(project_names.contains(OsStr::new("Projects")));
        let design_names = fs::read_dir(root.join("Spaces/Projects/Design"))
            .expect("offline nested Space listing")
            .map(|item| item.expect("Design entry").file_name())
            .collect::<std::collections::HashSet<_>>();
        assert!(design_names.contains(OsStr::new("pinned.txt")));

        // This is a fresh OS open while transport is offline, not an already
        // open/read-ahead descriptor retained from the online phase.
        assert_eq!(
            fs::read(root.join("Spaces/Projects/Design/pinned.txt"))
                .expect("fresh offline pinned read"),
            b"pinned space bytes"
        );
        assert!(fs::read(root.join("Spaces/Projects/cloud-only.txt")).is_err());

        // Authorization failures are not treated as connectivity loss and do
        // not fall back to cached file contents.
        backend.set_network_error(Some(ErrorKind::Forbidden));
        let permission = fs::read(root.join("Personal/Documents/keep.txt"))
            .expect_err("Forbidden must not use offline cache");
        assert_eq!(permission.kind(), std::io::ErrorKind::PermissionDenied);

        // Restart from the persisted Space snapshot and ciphertext/content
        // cache while the transport is already offline, then mount the
        // namespace from that restored Engine rather than an online Engine
        // which later lost connectivity.
        backend.set_network_error(Some(ErrorKind::Offline));
        drop(first_mount);
        assert!(
            fs::read_dir(&root)
                .expect("inspect first detached mount")
                .next()
                .is_none()
        );
        drop(engine);

        let cache = raiun_cache::Cache::open(&cache_dir, 64 * 1024 * 1024)
            .expect("reopen offline cache after restart");
        let restarted_engine = Engine::open(&temp.path().join("engine"), backend.clone())
            .expect("reopen engine after restart")
            .with_offline_cache(
                cache,
                "synthetic-account".into(),
                "https://example.invalid".into(),
            )
            .expect("restore account-bound cache")
            .with_offline_spaces(namespace_snapshot.clone())
            .expect("restore account-bound Space namespace");
        let root_after_restart = temp.path().join("mounted cloud after restart");
        let state_after_restart = temp.path().join("mount state after restart");
        fs::create_dir(&root_after_restart).expect("second mountpoint");
        let remount = mount(
            restarted_engine.clone(),
            &root_after_restart,
            &state_after_restart,
        )
        .expect("mount restored offline namespace");
        let restarted_names = fs::read_dir(&root_after_restart)
            .expect("restored offline root namespace")
            .map(|item| item.expect("restored root entry").file_name())
            .collect::<std::collections::HashSet<_>>();
        assert!(restarted_names.contains(OsStr::new("Personal")));
        assert!(restarted_names.contains(OsStr::new("Spaces")));
        assert_eq!(
            fs::read(root_after_restart.join("Personal/Documents/keep.txt"))
                .expect("restored cached Personal content"),
            b"personal offline bytes"
        );
        assert_eq!(
            fs::read(root_after_restart.join("Spaces/Projects/Design/pinned.txt"))
                .expect("restored pinned Space content"),
            b"pinned space bytes"
        );
        let engine = restarted_engine;

        // A successfully observed new server root gets a distinct cache scope.
        // Bytes and listings from the previous root must not appear after the
        // transport then drops again.
        assert!(engine.namespace_transport_unavailable());
        backend.set_network_error(None);
        let live_namespace = engine
            .probe_live_namespace()
            .expect("probe the recovered synthetic namespace");
        engine
            .publish_live_namespace(live_namespace)
            .expect("publish the validated recovered namespace");
        assert!(!engine.namespace_transport_unavailable());
        backend.replace_root_id("projects", "team-root-replaced");
        backend.remove_space_entry("projects", "/Design/pinned.txt");
        engine
            .list("projects", "/")
            .expect("publish listing under replacement root identity");
        backend.set_network_error(Some(ErrorKind::Offline));
        assert!(fs::read(root_after_restart.join("Spaces/Projects/Design/pinned.txt")).is_err());

        drop(remount);
        assert!(
            fs::read_dir(&root_after_restart)
                .expect("inspect detached mount")
                .next()
                .is_none()
        );
    }

    #[test]
    #[ignore = "requires an explicitly requested isolated host FUSE mount"]
    fn live_fuse_offline_edits_survive_restart_and_reconcile_without_overwrite() {
        assert!(
            Path::new("/dev/fuse").exists(),
            "host FUSE device is required"
        );
        let temp = tempfile::tempdir().expect("temporary fixture");
        let backend = Arc::new(FakeBackend::default());
        backend.add_space_entry("personal", "/", b"", true, "root-v1");
        backend.add_space_entry(
            "personal",
            "/queued.txt",
            b"server base",
            false,
            "queued-v1",
        );
        backend.add_space_entry(
            "personal",
            "/conflict.txt",
            b"conflict base",
            false,
            "conflict-v1",
        );

        let engine_dir = temp.path().join("engine");
        let cache_dir = temp.path().join("offline-cache");
        fs::create_dir(&cache_dir).expect("cache state directory");
        #[cfg(unix)]
        fs::set_permissions(
            &cache_dir,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private cache state directory");
        let make_engine = || {
            let cache =
                raiun_cache::Cache::open(&cache_dir, 64 * 1024 * 1024).expect("open durable cache");
            Engine::open(&engine_dir, backend.clone())
                .expect("open engine")
                .with_offline_cache(
                    cache,
                    "synthetic-account".into(),
                    "https://example.invalid".into(),
                )
                .expect("bind cache to synthetic account/server")
        };
        let engine = make_engine();
        engine.list("personal", "/").expect("prime root listing");
        engine
            .fetch_snapshot("personal", "/queued.txt")
            .expect("prime queued file version");
        engine
            .fetch_snapshot("personal", "/conflict.txt")
            .expect("prime conflict file version");

        let first_root = temp.path().join("first mount");
        let first_state = temp.path().join("first mount state");
        fs::create_dir(&first_root).expect("first mountpoint");
        let first_mount = mount(engine.clone(), &first_root, &first_state).expect("first mount");

        // Both edits are staged while the transport is unavailable. FUSE
        // flush/fsync must durably queue bytes without changing the remote.
        backend.set_network_error(Some(ErrorKind::Offline));
        let queued_path = first_root.join("Personal/queued.txt");
        let mut queued_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&queued_path)
            .expect("open the existing file for a queued edit");
        queued_file
            .write_all(b"local queued v1!")
            .expect("write first queued revision");
        queued_file.flush().expect("queue first revision");
        queued_file
            .seek(SeekFrom::Start(0))
            .expect("rewind the same FUSE handle");
        queued_file
            .write_all(b"local queued v2!")
            .expect("write a later revision through the same handle");
        queued_file.flush().expect("queue later revision");
        queued_file
            .seek(SeekFrom::Start(0))
            .expect("rewind for local readback");
        let mut same_handle_bytes = vec![0; b"local queued v2!".len()];
        queued_file
            .read_exact(&mut same_handle_bytes)
            .expect("read latest queued bytes from same handle");
        assert_eq!(same_handle_bytes, b"local queued v2!");
        drop(queued_file);
        fs::write(
            first_root.join("Personal/conflict.txt"),
            b"local conflict edit",
        )
        .expect("queue a second offline edit");
        assert_eq!(
            fs::read(first_root.join("Personal/queued.txt")).expect("read queued local bytes"),
            b"local queued v2!"
        );
        drop(first_mount);

        // Reopen both the Engine and its cache after the first mount has
        // stopped. Root discovery is online for mount construction, then file
        // listing/content is tested through the real mount while offline.
        backend.set_network_error(None);
        let restarted_engine = make_engine();
        let second_root = temp.path().join("restarted mount");
        let second_state = temp.path().join("restarted mount state");
        fs::create_dir(&second_root).expect("restarted mountpoint");
        let second_mount =
            mount(restarted_engine.clone(), &second_root, &second_state).expect("restart mount");
        backend.set_network_error(Some(ErrorKind::Offline));
        assert_eq!(
            fs::read(second_root.join("Personal/queued.txt"))
                .expect("read queued edit after Engine restart"),
            b"local queued v2!"
        );
        assert_eq!(
            fs::read(second_root.join("Personal/conflict.txt"))
                .expect("read conflict edit after Engine restart"),
            b"local conflict edit"
        );
        drop(second_mount);

        // One base is still current and should upload conditionally. The other
        // changes remotely before reconnect and must remain a local conflict.
        backend.set_network_error(None);
        backend.replace_for_test("/conflict.txt", b"remote concurrent edit", "conflict-v2");
        let restarted_again = make_engine();
        let report = restarted_again
            .reconcile_pending_file_writes("personal")
            .expect("reconcile online edits");
        assert_eq!(report.uploaded, 1);
        assert_eq!(report.conflicts, 1);
        assert_eq!(report.remaining, 0);
        {
            let files = backend.files.lock().expect("inspect synthetic server");
            assert_eq!(
                files[&(String::from("personal"), String::from("/queued.txt"))].1,
                b"local queued v2!"
            );
            assert_eq!(
                files[&(String::from("personal"), String::from("/conflict.txt"))].1,
                b"remote concurrent edit"
            );
        }
        assert_eq!(
            restarted_again
                .fetch_snapshot("personal", "/conflict.txt")
                .map(|mut file| {
                    let mut bytes = Vec::new();
                    file.read_to_end(&mut bytes).expect("read conflict journal");
                    bytes
                })
                .expect("preserved local conflict bytes"),
            b"local conflict edit"
        );
    }
}

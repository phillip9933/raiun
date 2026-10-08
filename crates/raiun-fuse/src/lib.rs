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
//! name before publishing the new file. Cross-Space moves, directory replacement,
//! metadata changes, encrypted content, and pin/offline behavior are unsupported.

use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, SyncSender},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use fuser::{
    Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    InitFlags, KernelConfig, MountOption, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};
use raiun_core::{
    Space,
    backend::{CloudError, CloudSpace, ErrorKind, RemoteEntry, WriteCondition},
    space_entries,
};
use raiun_engine::{Engine, FetchSnapshot};

pub mod recovery;

const ROOT: u64 = 1;
const PERSONAL: u64 = 2;
const SPACES: u64 = 3;
const TTL: Duration = Duration::from_secs(1);
const MAX_READ: u32 = 1024 * 1024;
const MAX_NODES: usize = 100_000;
const MAX_DIRECTORY_ENTRIES: usize = 10_000;
const MAX_DIRECTORY_HANDLES: usize = 512;
const MAX_FILE_HANDLES: usize = 2_048;
static MANIFEST_TEMP_ID: AtomicU64 = AtomicU64::new(1);

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
    Root,
    Personal { space: String },
    Spaces,
    Space { space: String },
    Remote { space: String, entry: RemoteEntry },
}

#[derive(Clone)]
struct Node {
    ino: u64,
    parent: u64,
    name: String,
    kind: NodeKind,
}

enum OpenFile {
    Read(ReadHandle),
    Write(WriteHandle),
}

enum ReadHandle {
    Local(File),
    Snapshot(FetchSnapshot),
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
    dirty: bool,
    ino: u64,
    cleanup_on_release: bool,
}

struct State {
    nodes: HashMap<u64, Node>,
    children: HashMap<(u64, String), u64>,
    file_handles: HashMap<u64, Arc<Mutex<OpenFile>>>,
    directory_handles: HashMap<u64, Vec<(String, u64, FileType)>>,
    active_writers: std::collections::HashSet<String>,
}

struct PathReservation<'a> {
    state: &'a Mutex<State>,
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
            }
        }
    }
}

struct RaiunFilesystem {
    engine: Engine,
    pool: RemotePool,
    project_spaces: Vec<(String, CloudSpace)>,
    space_writable: HashMap<String, bool>,
    spool_dir: PathBuf,
    state: Mutex<State>,
    next_handle: AtomicU64,
}

/// A live FUSE mount. Dropping the handle unmounts and joins the FUSE session.
pub struct MountHandle {
    session: Option<fuser::BackgroundSession>,
    root: PathBuf,
}

impl MountHandle {
    /// Whether this process still sees the FUSE mount at its configured root.
    /// If mountinfo cannot be read, keep the conservative answer that a live
    /// session may still be mounted.
    pub fn is_mounted(&self) -> bool {
        mountpoint_is_mounted(&self.root).unwrap_or(self.session.is_some())
    }

    /// Unmount through fusermount3 while retaining the background session until
    /// the mount has actually disappeared. This lets callers retry a busy or
    /// otherwise failed unmount instead of losing fuser's only session handle.
    pub fn unmount(&mut self) -> Result<(), String> {
        if self.session.is_none() {
            return Ok(());
        }

        if mountpoint_is_mounted(&self.root).unwrap_or(true) {
            let result = Command::new("fusermount3")
                .arg("-u")
                .arg(&self.root)
                .output()
                .map_err(|error| format!("could not run fusermount3: {error}"))?;
            if !result.status.success() && mountpoint_is_mounted(&self.root).unwrap_or(true) {
                let message = String::from_utf8_lossy(&result.stderr);
                let detail = message.trim();
                return Err(if detail.is_empty() {
                    format!("fusermount3 exited with {}", result.status)
                } else {
                    format!("fusermount3 could not unmount the cloud root: {detail}")
                });
            }
            if mountpoint_is_mounted(&self.root).unwrap_or(true) {
                return Err(
                    "fusermount3 reported success but the cloud root is still mounted".into(),
                );
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

fn mountpoint_is_mounted(root: &Path) -> std::io::Result<bool> {
    let mountinfo = fs::read("/proc/self/mountinfo")?;
    Ok(mountinfo_contains_mountpoint(&mountinfo, root))
}

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

/// Mount the account namespace at an existing empty directory.
pub fn mount(engine: Engine, root: &Path, state_dir: &Path) -> Result<MountHandle, String> {
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
    fs::create_dir_all(state_dir)
        .map_err(|error| format!("could not create provider state directory: {error}"))?;
    let state_dir = fs::canonicalize(state_dir)
        .map_err(|error| format!("provider state directory is unavailable: {error}"))?;
    if state_dir == root || state_dir.starts_with(&root) {
        return Err("provider state directory must be outside the mounted cloud root".into());
    }
    let spool_dir = state_dir.join("provider-spool");
    prepare_spool_dir(&spool_dir).map_err(|error| error.to_string())?;
    let filesystem = RaiunFilesystem::new(engine, spool_dir).map_err(|error| error.to_string())?;
    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::FSName("OpenCloud".into()),
        MountOption::DefaultPermissions,
        MountOption::NoDev,
        MountOption::NoSuid,
        MountOption::RW,
    ];
    config.n_threads = Some(4);
    let session = fuser::spawn_mount(filesystem, &root, &config)
        .map_err(|error| format!("could not mount OpenCloud: {error}"))?;
    Ok(MountHandle {
        session: Some(session),
        root,
    })
}

impl RaiunFilesystem {
    fn new(engine: Engine, spool_dir: PathBuf) -> Result<Self, CloudError> {
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
            .filter(|space| !space.personal && !space.encrypted)
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
        let space_writable = spaces
            .iter()
            .map(|space| (space.id.clone(), space.writable))
            .collect();
        let root = Node {
            ino: ROOT,
            parent: ROOT,
            name: String::new(),
            kind: NodeKind::Root,
        };
        let personal = Node {
            ino: PERSONAL,
            parent: ROOT,
            name: "Personal".into(),
            kind: NodeKind::Personal {
                space: personal_space.id.clone(),
            },
        };
        let spaces_node = Node {
            ino: SPACES,
            parent: ROOT,
            name: "Spaces".into(),
            kind: NodeKind::Spaces,
        };
        let mut nodes = HashMap::new();
        nodes.insert(ROOT, root);
        nodes.insert(PERSONAL, personal);
        nodes.insert(SPACES, spaces_node);
        Ok(Self {
            engine,
            pool: RemotePool::new(4),
            project_spaces,
            space_writable,
            spool_dir,
            state: Mutex::new(State {
                nodes,
                children: HashMap::from([
                    ((ROOT, "Personal".into()), PERSONAL),
                    ((ROOT, "Spaces".into()), SPACES),
                ]),
                file_handles: HashMap::new(),
                directory_handles: HashMap::new(),
                active_writers: std::collections::HashSet::new(),
            }),
            next_handle: AtomicU64::new(1),
        })
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

    fn add_node(&self, parent: u64, name: String, kind: NodeKind) -> Result<u64, CloudError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?;
        if let Some(ino) = state.children.get(&(parent, name.clone())) {
            return Ok(*ino);
        }
        if state.nodes.len() >= MAX_NODES {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "provider node limit reached; unmount and remount to release cached namespace state",
            ));
        }
        let key = match &kind {
            NodeKind::Space { space } => format!("space:{space}"),
            NodeKind::Remote { space, entry } => format!("remote:{space}:{}", entry.id),
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
        state.children.insert((parent, name.clone()), ino);
        state.nodes.insert(
            ino,
            Node {
                ino,
                parent,
                name,
                kind,
            },
        );
        Ok(ino)
    }

    fn children(&self, parent_ino: u64) -> Result<Vec<Node>, CloudError> {
        let parent = self.node(parent_ino)?;
        let mut result = Vec::new();
        match parent.kind {
            NodeKind::Root => result.extend([self.node(PERSONAL)?, self.node(SPACES)?]),
            NodeKind::Spaces => {
                for (label, space) in &self.project_spaces {
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
            NodeKind::Personal { space } | NodeKind::Space { space } => {
                let engine = self.engine.clone();
                let request_space = space.clone();
                let entries = self.pool.call(move || engine.list(&request_space, "/"))??;
                if entries.len() > MAX_DIRECTORY_ENTRIES {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "directory exceeds the provider listing limit",
                    ));
                }
                for mut entry in entries.into_iter().filter(|entry| {
                    !entry.encrypted
                        && safe_component(entry.path.rsplit('/').next().unwrap_or_default())
                }) {
                    entry.writable &= self.space_writable.get(&space).copied().unwrap_or(false);
                    let name = entry.path.rsplit('/').next().unwrap_or_default().to_owned();
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
                let path = entry.path;
                let engine = self.engine.clone();
                let request_space = space.clone();
                let entries = self
                    .pool
                    .call(move || engine.list(&request_space, &path))??;
                if entries.len() > MAX_DIRECTORY_ENTRIES {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "directory exceeds the provider listing limit",
                    ));
                }
                for mut entry in entries.into_iter().filter(|entry| {
                    !entry.encrypted
                        && safe_component(entry.path.rsplit('/').next().unwrap_or_default())
                }) {
                    entry.writable &= self.space_writable.get(&space).copied().unwrap_or(false);
                    let name = entry.path.rsplit('/').next().unwrap_or_default().to_owned();
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
            _ => {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "item is not a directory",
                ));
            }
        }
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    fn child_path(&self, parent: &Node, name: &str) -> Result<(String, String), CloudError> {
        if !safe_component(name) {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "file name is not supported",
            ));
        }
        let (space, base) = match &parent.kind {
            NodeKind::Personal { space } | NodeKind::Space { space } => {
                (space.clone(), "/".to_owned())
            }
            NodeKind::Remote { space, entry } if entry.directory && !entry.encrypted => {
                (space.clone(), entry.path.clone())
            }
            _ => {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "destination is not a writable cloud directory",
                ));
            }
        };
        if !self.space_writable.get(&space).copied().unwrap_or(false) {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "cloud Space is read-only",
            ));
        }
        let base = base.trim_end_matches('/');
        Ok((space, format!("{base}/{name}")))
    }

    fn register_handle(&self, file: OpenFile) -> Result<u64, CloudError> {
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

    fn prepare_write(
        &self,
        ino: u64,
        space: &str,
        path: &str,
        existing: Option<&RemoteEntry>,
        truncate: bool,
    ) -> Result<WriteHandle, CloudError> {
        let (spool, manifest) = self.spool_paths(space, path);
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
            condition = read_manifest(&manifest, space, path)?.unwrap_or(condition);
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
        write_manifest(&manifest, space, path, &condition)?;
        Ok(WriteHandle {
            file,
            spool,
            manifest,
            space: space.into(),
            path: path.into(),
            condition,
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
        refreshed.writable &= self.space_writable.get(space).copied().unwrap_or(false);
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
        Ok(current.clone())
    }

    fn reserve_path(&self, space: &str, path: &str) -> Result<PathReservation<'_>, CloudError> {
        let key = format!("{space}\0{path}");
        let mut state = self
            .state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?;
        if !state.active_writers.insert(key.clone()) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "cloud path already has an active operation",
            ));
        }
        drop(state);
        Ok(PathReservation {
            state: &self.state,
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
        let entry = self
            .pool
            .call(move || engine.put(&space, &path, &source, condition))??;
        if let Ok(mut state) = self.state.lock() {
            if let Some(node) = state.nodes.get_mut(&write.ino) {
                if let NodeKind::Remote { entry: current, .. } = &mut node.kind {
                    *current = entry.clone();
                }
            }
        }
        let next_condition = WriteCondition::Match(entry.etag.clone());
        write_manifest(&write.manifest, &write.space, &write.path, &next_condition)?;
        write.condition = next_condition;
        write.dirty = false;
        write.cleanup_on_release = true;
        Ok(())
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

    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let result = name
            .to_str()
            .ok_or_else(|| CloudError::new(ErrorKind::Unsupported, "file name is not UTF-8"))
            .and_then(|name| {
                self.children(parent.0)?
                    .into_iter()
                    .find(|child| child.name == name)
                    .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "cloud item was not found"))
            });
        match result {
            Ok(node) => reply.entry(&TTL, &self.attr(&node, req.uid(), req.gid()), Generation(0)),
            Err(error) => reply.error(errno(&error)),
        }
    }

    fn getattr(&self, req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.refresh_remote_node(ino.0) {
            Ok(node) => reply.attr(&TTL, &self.attr(&node, req.uid(), req.gid())),
            Err(error) => reply.error(errno(&error)),
        }
    }

    fn opendir(&self, req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        match self.children(ino.0) {
            Ok(children) => {
                if children.len() > MAX_DIRECTORY_ENTRIES {
                    reply.error(Errno::EOVERFLOW);
                    return;
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
                let fh = self.next_handle.fetch_add(1, Ordering::Relaxed).max(1);
                if let Ok(mut state) = self.state.lock() {
                    if state.directory_handles.len() >= MAX_DIRECTORY_HANDLES {
                        reply.error(Errno::ENOMEM);
                        return;
                    }
                    state.directory_handles.insert(fh, snapshot);
                    reply.opened(FileHandle(fh), FopenFlags::empty());
                } else {
                    reply.error(Errno::EIO);
                }
            }
            Err(error) => reply.error(errno(&error)),
        }
        let _ = req;
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
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
        for (index, (name, child, kind)) in snapshot.iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(*child), (index + 1) as u64, *kind, name) {
                break;
            }
        }
        let _ = ino;
        reply.ok();
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
        let result = self.open_node(ino.0, flags.0);
        match result {
            Ok(fh) => reply.opened(FileHandle(fh), FopenFlags::empty()),
            Err(error) => reply.error(errno(&error)),
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
        let result = self.file_handle(fh.0).and_then(|handle| {
            let mut open = handle
                .lock()
                .map_err(|_| io_error("open file state is unavailable"))?;
            let file: &mut dyn ReadSeek = match &mut *open {
                OpenFile::Read(ReadHandle::Local(file)) => file,
                OpenFile::Read(ReadHandle::Snapshot(file)) => file,
                OpenFile::Write(write) => &mut write.file,
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
        match self
            .file_handle(fh.0)
            .and_then(|handle| self.commit(&handle))
        {
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
        match self
            .file_handle(fh.0)
            .and_then(|handle| self.commit(&handle))
        {
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
        let handle = self
            .state
            .lock()
            .ok()
            .and_then(|mut state| state.file_handles.remove(&fh.0));
        match handle {
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
                    if let (Some(key), Ok(mut state)) = (key, self.state.lock()) {
                        state.active_writers.remove(&key);
                    }
                    reply.ok()
                }
                Err(error) => {
                    if let Ok(open) = handle.lock() {
                        if let OpenFile::Write(write) = &*open {
                            if let Ok(mut state) = self.state.lock() {
                                state
                                    .active_writers
                                    .remove(&format!("{}\0{}", write.space, write.path));
                            }
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
        req: &Request,
        parent_ino: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
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
                    Ok(node) => {
                        reply.entry(&TTL, &self.attr(&node, req.uid(), req.gid()), Generation(0))
                    }
                    Err(error) => reply.error(errno(&error)),
                }
            }
            Err(error) => reply.error(errno(&error)),
        }
    }

    fn unlink(&self, _req: &Request, parent_ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let result = self.delete_child(parent_ino.0, name, false);
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(errno(&error)),
        }
    }

    fn rmdir(&self, _req: &Request, parent_ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
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
        let result = (|| {
            if flags.bits() != 0 {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "rename flags are not supported",
                ));
            }
            self.node(parent.0)?;
            let destination_parent = self.node(newparent.0)?;
            let source = self.child(
                parent.0,
                name.to_str()
                    .ok_or_else(|| invalid("file name is not UTF-8"))?,
            )?;
            let source_remote = match &source.kind {
                NodeKind::Remote { space, entry } => (space.clone(), entry.clone()),
                _ => return Err(invalid("synthetic folders cannot be renamed")),
            };
            let destination_name = newname
                .to_str()
                .ok_or_else(|| invalid("file name is not UTF-8"))?;
            let (destination_space, destination_path) =
                self.child_path(&destination_parent, destination_name)?;
            let _source_reservation = self.reserve_path(&source_remote.0, &source_remote.1.path)?;
            let _destination_reservation =
                self.reserve_path(&destination_space, &destination_path)?;
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
        req: &Request,
        parent_ino: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
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
            let fh = self.register_handle(OpenFile::Write(write))?;
            let node = self.node(ino)?;
            reservation.disarm();
            Ok((node, fh, flags))
        })();
        match result {
            Ok((node, fh, _)) => reply.created(
                &TTL,
                &self.attr(&node, req.uid(), req.gid()),
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
                let OpenFile::Write(write) = &mut *open else {
                    return Err(CloudError::new(
                        ErrorKind::Forbidden,
                        "file was not opened for writing",
                    ));
                };
                write.file.set_len(size).map_err(io_cloud)?;
                write.dirty = true;
                self.update_size(ino.0, size);
            }
            self.node(ino.0)
        })();
        match result {
            Ok(node) => reply.attr(&TTL, &self.attr(&node, _req.uid(), _req.gid())),
            Err(error) => reply.error(errno(&error)),
        }
    }
}

impl RaiunFilesystem {
    fn open_node(&self, ino: u64, flags: i32) -> Result<u64, CloudError> {
        let initial_node = self.node(ino)?;
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
            let handle = self.register_handle(OpenFile::Write(write))?;
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

    fn file_type(&self, node: &Node) -> FileType {
        match node.kind {
            NodeKind::Root
            | NodeKind::Personal { .. }
            | NodeKind::Spaces
            | NodeKind::Space { .. } => FileType::Directory,
            NodeKind::Remote { ref entry, .. } if entry.directory => FileType::Directory,
            _ => FileType::RegularFile,
        }
    }

    fn attr(&self, node: &Node, uid: u32, gid: u32) -> FileAttr {
        let directory = self.file_type(node) == FileType::Directory;
        let (size, mtime, writable) = match &node.kind {
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
                    entry.writable && !entry.encrypted,
                )
            }
            NodeKind::Personal { space } | NodeKind::Space { space } => (
                0,
                UNIX_EPOCH,
                self.space_writable.get(space).copied().unwrap_or(false),
            ),
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
            uid,
            gid,
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
}

fn same_identity(a: &NodeKind, b: &NodeKind) -> bool {
    match (a, b) {
        (NodeKind::Space { space: a }, NodeKind::Space { space: b }) => a == b,
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
fn errno(error: &CloudError) -> Errno {
    match error.kind {
        ErrorKind::Unauthorized => Errno::EACCES,
        ErrorKind::Forbidden => Errno::EACCES,
        ErrorKind::NotFound => Errno::ENOENT,
        ErrorKind::Conflict => Errno::EEXIST,
        ErrorKind::Offline => Errno::EHOSTUNREACH,
        ErrorKind::Unsupported if error.message.contains("handle limit") => Errno::ENOMEM,
        ErrorKind::Unsupported if error.message.contains("node limit") => Errno::ENOMEM,
        ErrorKind::Unsupported if error.message.contains("listing limit") => Errno::EOVERFLOW,
        ErrorKind::Unsupported => Errno::EOPNOTSUPP,
        ErrorKind::Io | ErrorKind::InvalidResponse => Errno::EIO,
    }
}

fn write_manifest(
    path: &Path,
    space: &str,
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
    let encoded = serde_json::to_vec(&[space, remote, kind, etag])
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
    expected_space: &str,
    expected_path: &str,
) -> Result<Option<WriteCondition>, CloudError> {
    let body = match fs::read_to_string(path) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_cloud(error)),
    };
    let [space, remote, kind, etag]: [String; 4] =
        serde_json::from_str(&body).map_err(|_| invalid("provider spool manifest is malformed"))?;
    if space != expected_space || remote != expected_path {
        return Err(invalid(
            "provider spool manifest does not match the requested file",
        ));
    }
    match (kind.as_str(), etag.as_str()) {
        ("absent", _) => Ok(Some(WriteCondition::Absent)),
        ("match", etag) if !etag.is_empty() => Ok(Some(WriteCondition::Match(etag.into()))),
        _ => Err(invalid("provider spool manifest is malformed")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(!mountinfo_contains_mountpoint(
            fixture.replace("fuse.OpenCloud", "ext4").as_bytes(),
            root
        ));
        assert!(expected.contains("\\040"));
        assert!(expected.contains("\\134"));
        assert!(expected.contains("クラウド"));
    }
    use raiun_core::backend::{CloudBackend, CloudSpace};
    use std::collections::HashMap;

    type FakeFiles = HashMap<(String, String), (RemoteEntry, Vec<u8>)>;

    #[derive(Default)]
    struct FakeBackend {
        files: Mutex<FakeFiles>,
        fail_upload: Mutex<bool>,
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
            }
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
        fn spaces(&self) -> Result<Vec<CloudSpace>, CloudError> {
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
            let files = self.files.lock().expect("fake lock");
            for ((candidate_space, candidate_path), (item, _)) in files.iter() {
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

    fn filesystem(temp: &tempfile::TempDir, backend: Arc<FakeBackend>) -> RaiunFilesystem {
        let engine = Engine::open(&temp.path().join("engine"), backend).expect("engine");
        let spool = temp.path().join("spool");
        fs::create_dir_all(&spool).expect("spool directory");
        RaiunFilesystem::new(engine, spool).expect("filesystem")
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
        let open = Arc::new(Mutex::new(OpenFile::Write(handle)));
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
        let open = Arc::new(Mutex::new(OpenFile::Write(write)));
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
        let engine = Engine::open(&state.join("engine"), backend.clone()).expect("engine");
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
}

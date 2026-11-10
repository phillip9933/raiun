//! Platform-independent cloud protocol boundary. File bodies never enter control JSON.
use serde::{Deserialize, Serialize};

const MAX_DIRECTORY_SNAPSHOT_ENTRIES: usize = 100_000;
const MAX_DIRECTORY_SNAPSHOT_METADATA_BYTES: usize = 32 * 1024 * 1024;
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Irreversible cancellation for one operation owner and its cloned workers.
/// This token carries no account identity or mutation authority.
#[derive(Clone, Debug, Default)]
pub struct OperationCancellation {
    cancelled: Arc<AtomicBool>,
}

impl OperationCancellation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudSpace {
    pub id: String,
    pub name: String,
    pub dav_url: String,
    pub personal: bool,
    pub writable: bool,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteEntry {
    pub id: String,
    /// Absolute logical path within its Space, never a host filesystem path.
    pub path: String,
    pub directory: bool,
    pub size: u64,
    pub etag: String,
    pub modified_unix: i64,
    pub writable: bool,
    pub encrypted: bool,
}

/// Read-only facts for one ordinary-create proof. These are not a reusable
/// lease: callers must still bind the root/account and reprove each phase.
pub struct OrdinaryCreateMetadata {
    pub space: CloudSpace,
    pub root: RemoteEntry,
    /// Exact ordered parent paths, excluding the Space root and target.
    pub ancestors: Vec<RemoteEntry>,
    /// When requested, None means the target returned NotFound. Otherwise this
    /// field is unobserved and grants no absence proof.
    pub target: Option<RemoteEntry>,
}

/// One freshly routed ordinary-directory view. This is scoped to a single
/// read operation and carries no reusable cache or mutation authority.
pub struct OrdinaryDirectorySnapshot {
    pub space: CloudSpace,
    pub root: RemoteEntry,
    pub parent: RemoteEntry,
    pub entries: Vec<RemoteEntry>,
}

/// One fresh Space/root authority observation paired with a target lookup.
/// The outer Result covers discovery/root authority failure; `target` also
/// includes post-root ancestor failures and preserves a scoped NotFound or
/// transport error without treating it as missing root authority.
pub struct OrdinaryStatSnapshot {
    pub space: CloudSpace,
    pub root: RemoteEntry,
    /// Immediate ordinary parent validated in this same observation, when
    /// available. Defaults do not prove a non-root parent for lookup hints.
    pub observed_parent: Option<RemoteEntry>,
    pub target: Result<RemoteEntry, CloudError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WriteCondition {
    Absent,
    Match(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudError {
    pub kind: ErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ErrorKind {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Offline,
    InvalidResponse,
    Unsupported,
    Io,
}

impl CloudError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}
impl std::fmt::Display for CloudError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for CloudError {}

/// Blocking protocol operations run on engine workers, never the UI event loop.
/// A listing is complete only if this method returns Ok; visitors must stage data.
pub trait CloudBackend: Send + Sync {
    /// Canonical configured server origin, when the backend has one. Cache
    /// integration requires this to match the selected profile origin instead
    /// of trusting an IPC-supplied URL.
    fn server_origin(&self) -> Option<String> {
        None
    }
    /// Pure local stamp for read-only observation visibility. Implementations
    /// must change it when authenticated read authority changes; it grants no
    /// mutation authority. Unsupported backends cannot issue lookup hints.
    fn read_only_generation(&self) -> Option<u64> {
        None
    }
    fn spaces(&self) -> Result<Vec<CloudSpace>, CloudError>;
    /// Observe one ordinary Space and its root within one read-only metadata
    /// operation. Returned values grant no mutation authority or cache lease.
    /// Backends may reuse freshly resolved routing only inside this call; the
    /// default preserves separate discovery/stat calls. Read-only Spaces remain
    /// readable; unknown or encrypted Spaces refuse before root observation.
    fn space_root_metadata(&self, space: &str) -> Result<(CloudSpace, RemoteEntry), CloudError> {
        let selected = self
            .spaces()?
            .into_iter()
            .find(|candidate| candidate.id == space)
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "cloud Space was not found"))?;
        if selected.encrypted {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted cloud locations are unavailable to the ordinary cache",
            ));
        }
        let root = self.stat(space, "/")?;
        Ok((selected, root))
    }
    /// Observe a Space/root and one target in a single fresh read operation.
    /// The default preserves independent backend operations; an override may
    /// reuse routing only within this call. A target NotFound remains distinct
    /// from failures to establish the selected Space or root authority.
    fn ordinary_stat_snapshot(
        &self,
        space: &str,
        path: &str,
    ) -> Result<OrdinaryStatSnapshot, CloudError> {
        let (selected, root) = self.space_root_metadata(space)?;
        let target = if path == "/" {
            Ok(root.clone())
        } else {
            self.stat(space, path)
        };
        Ok(OrdinaryStatSnapshot {
            space: selected,
            observed_parent: (path == "/").then(|| root.clone()),
            root,
            target,
        })
    }
    /// Observe one ordinary directory and its direct children. Backends may
    /// override this to reuse freshly resolved routing within this operation;
    /// returned facts are never cached as authority. The default keeps the
    /// existing independent root, parent, and listing observations.
    fn directory_snapshot(
        &self,
        space: &str,
        path: &str,
        expected_parent_id: Option<&str>,
    ) -> Result<OrdinaryDirectorySnapshot, CloudError> {
        self.directory_snapshot_with_root_observer(space, path, expected_parent_id, &|_, _| Ok(()))
    }

    /// Retain fresh root facts even if a later ancestor/list request fails.
    /// Call the observer after validating the root and before reading children;
    /// a caller must never substitute a different saved root after that point.
    /// Reobserving implementations must report every newly observed root.
    fn directory_snapshot_with_root_observer(
        &self,
        space: &str,
        path: &str,
        expected_parent_id: Option<&str>,
        observer: &dyn Fn(&CloudSpace, &RemoteEntry) -> Result<(), CloudError>,
    ) -> Result<OrdinaryDirectorySnapshot, CloudError> {
        let (selected, root) = self.space_root_metadata(space)?;
        observer(&selected, &root)?;
        let parent = if path == "/" {
            root.clone()
        } else {
            self.stat(space, path)?
        };
        if parent.path.trim_end_matches('/') != path.trim_end_matches('/')
            || !parent.directory
            || parent.encrypted
            || expected_parent_id.is_some_and(|expected| expected != parent.id)
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "ordinary directory identity changed",
            ));
        }
        let mut entries = Vec::new();
        let mut metadata_bytes = 0usize;
        self.list(space, path, &mut |entry| {
            if entries.len() >= MAX_DIRECTORY_SNAPSHOT_ENTRIES {
                return Err(CloudError::new(
                    ErrorKind::InvalidResponse,
                    "cloud listing exceeds the 100,000-entry limit",
                ));
            }
            metadata_bytes = metadata_bytes
                .saturating_add(entry.id.len())
                .saturating_add(entry.etag.len())
                .saturating_add(entry.path.len());
            if metadata_bytes > MAX_DIRECTORY_SNAPSHOT_METADATA_BYTES {
                return Err(CloudError::new(
                    ErrorKind::InvalidResponse,
                    "cloud listing metadata exceeds the 32 MiB limit",
                ));
            }
            entries.push(entry);
            Ok(())
        })?;
        Ok(OrdinaryDirectorySnapshot {
            space: selected,
            root,
            parent,
            entries,
        })
    }
    /// Observe a create's root, parents and optionally its target in one
    /// read-only operation. An implementation may resolve routing once inside
    /// this call, but must not cache it across admissions or body transfers.
    /// An absent expected root requests fresh discovery for initial admission;
    /// subsequent phases must supply the root captured by that admission.
    /// The default retains independent backend observations.
    fn ordinary_create_metadata(
        &self,
        space: &str,
        path: &str,
        expected_root: Option<&str>,
        expected_parent: Option<&str>,
        observe_target: bool,
        is_current: &dyn Fn() -> bool,
    ) -> Result<OrdinaryCreateMetadata, CloudError> {
        let current = || {
            if is_current() {
                Ok(())
            } else {
                Err(CloudError::new(
                    ErrorKind::Conflict,
                    "create context changed",
                ))
            }
        };
        crate::validate_remote_path(path)
            .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "create path is invalid"))?;
        if !path.starts_with('/') || path == "/" || path.ends_with('/') {
            return Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "create path is invalid",
            ));
        }
        current()?;
        let (selected, root) = self.space_root_metadata(space)?;
        let valid_parent = |entry: &RemoteEntry, path: &str| {
            entry.path == path
                && entry.directory
                && !entry.encrypted
                && entry.writable
                && !entry.id.is_empty()
                && !entry.id.chars().any(char::is_control)
        };
        if selected.id != space
            || selected.encrypted
            || !selected.writable
            || expected_root.is_some_and(|expected| root.id != expected)
            || !valid_parent(&root, "/")
        {
            return Err(CloudError::new(ErrorKind::Conflict, "create root changed"));
        }
        let mut ancestors = Vec::new();
        let (parent, _) = path.rsplit_once('/').expect("absolute path");
        let mut ancestor = String::new();
        for component in parent.split('/').filter(|part| !part.is_empty()) {
            current()?;
            ancestor.push('/');
            ancestor.push_str(component);
            let entry = self.stat(space, &ancestor)?;
            if !valid_parent(&entry, &ancestor) {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "create parent changed",
                ));
            }
            ancestors.push(entry);
        }
        let parent_id = ancestors.last().unwrap_or(&root).id.as_str();
        if expected_parent.is_some_and(|expected| expected != parent_id) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "create parent changed",
            ));
        }
        let target = if observe_target {
            current()?;
            match self.stat(space, path) {
                Ok(entry) => Some(entry),
                Err(error) if error.kind == ErrorKind::NotFound => None,
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        current()?;
        Ok(OrdinaryCreateMetadata {
            space: selected,
            root,
            ancestors,
            target,
        })
    }
    fn list(
        &self,
        space: &str,
        path: &str,
        visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
    ) -> Result<(), CloudError>;
    fn stat(&self, space: &str, path: &str) -> Result<RemoteEntry, CloudError>;
    fn download(
        &self,
        space: &str,
        path: &str,
        expected_etag: Option<&str>,
        destination: &Path,
    ) -> Result<RemoteEntry, CloudError>;
    fn upload(
        &self,
        space: &str,
        path: &str,
        source: &Path,
        condition: WriteCondition,
    ) -> Result<RemoteEntry, CloudError>;
    /// Transfer against one exact ordinary Space-root resource. Implementors
    /// must validate the root while resolving the actual request URL; a separate
    /// stat followed by an unscoped transfer is not an identity fence.
    fn upload_in_root(
        &self,
        _space: &str,
        _path: &str,
        _source: &Path,
        _condition: WriteCondition,
        _expected_root: &str,
    ) -> Result<RemoteEntry, CloudError> {
        Err(CloudError::new(
            ErrorKind::Unsupported,
            "root-bound upload is unavailable",
        ))
    }
    fn download_in_root(
        &self,
        _space: &str,
        _path: &str,
        _expected_etag: Option<&str>,
        _destination: &Path,
        _expected_root: &str,
    ) -> Result<RemoteEntry, CloudError> {
        Err(CloudError::new(
            ErrorKind::Unsupported,
            "root-bound download is unavailable",
        ))
    }
    /// Root-bound transfer tied to the caller's original operation token.
    /// An implementation must not silently fall back to an uncancellable call.
    fn upload_in_root_with_cancellation(
        &self,
        _space: &str,
        _path: &str,
        _source: &Path,
        _condition: WriteCondition,
        _expected_root: &str,
        _cancellation: &OperationCancellation,
    ) -> Result<RemoteEntry, CloudError> {
        Err(CloudError::new(
            ErrorKind::Unsupported,
            "cancellable root-bound upload is unavailable",
        ))
    }

    /// Whether a successful `upload_new_in_root_with_preflight` confirms a
    /// freshly claimed create without an independent full-body GET. Opting in
    /// requires sending the complete source body, checking the successful
    /// terminal upload status, and returning validated current root, path,
    /// resource ID, strong ETag, size and ordinary writable permissions.
    /// Cancellation and caller currentness must fence the entire operation.
    /// This is server confirmation, not an independently read-back byte hash,
    /// and never authorizes completing historical uncertain/conflict records.
    fn server_confirms_new_upload(&self) -> bool {
        false
    }

    /// Deliver a new ordinary file after one fresh preparation observation.
    /// `claim` must be called exactly once, after validating root, ordered
    /// ordinary parents and target absence, and before any body is sent. False
    /// means the local claim was refused: return None without a PUT. A claimed
    /// operation must never retry the callback or mutation after any failure.
    /// Implementations may compose the observation with their upload prep;
    /// this default deliberately retains independent transfer validation.
    #[allow(clippy::too_many_arguments)]
    fn upload_new_in_root_with_preflight(
        &self,
        space: &str,
        path: &str,
        source: &Path,
        expected_root: &str,
        expected_parent: &str,
        cancellation: &OperationCancellation,
        is_current: &dyn Fn() -> bool,
        claim: &dyn Fn(&OrdinaryCreateMetadata) -> Result<bool, CloudError>,
    ) -> Result<Option<RemoteEntry>, CloudError> {
        let current = || {
            if cancellation.is_cancelled() || !is_current() {
                Err(CloudError::new(
                    ErrorKind::Conflict,
                    "create context changed",
                ))
            } else {
                Ok(())
            }
        };
        current()?;
        let observation = self.ordinary_create_metadata(
            space,
            path,
            Some(expected_root),
            Some(expected_parent),
            true,
            &|| !cancellation.is_cancelled() && is_current(),
        )?;
        current()?;
        if observation.target.is_some() {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "create target already exists",
            ));
        }
        if !claim(&observation)? {
            return Ok(None);
        }
        current()?;
        self.upload_in_root_with_cancellation(
            space,
            path,
            source,
            WriteCondition::Absent,
            expected_root,
            cancellation,
        )
        .map(Some)
    }
    fn download_in_root_with_cancellation(
        &self,
        _space: &str,
        _path: &str,
        _expected_etag: Option<&str>,
        _destination: &Path,
        _expected_root: &str,
        _cancellation: &OperationCancellation,
    ) -> Result<RemoteEntry, CloudError> {
        Err(CloudError::new(
            ErrorKind::Unsupported,
            "cancellable root-bound download is unavailable",
        ))
    }
    /// Verify the entire ordinary file without publishing a local download.
    /// A successful entry requires a full conditional body through EOF, exact
    /// length and lowercase SHA-256, and unchanged root/resource/revision/role
    /// before and after reading. Cancellation must fence every phase.
    /// `None` means this optimization is unimplemented; callers may then use
    /// their existing cancellable download-and-hash path. Errors never grant
    /// permission to fall back or bypass a backend guard.
    fn verify_download_in_root_with_cancellation(
        &self,
        _space: &str,
        _path: &str,
        _expected: &RemoteEntry,
        _expected_sha256: &str,
        _expected_root: &str,
        _cancellation: &OperationCancellation,
    ) -> Result<Option<RemoteEntry>, CloudError> {
        Ok(None)
    }
    fn mkdir(&self, space: &str, path: &str) -> Result<RemoteEntry, CloudError>;
    /// Create a directory and verify its published identity. Backends that can
    /// safely keep selection/root context scoped to the operation may override
    /// this to avoid rediscovering the same Space for readback.
    fn mkdir_and_confirm(&self, space: &str, path: &str) -> Result<RemoteEntry, CloudError> {
        let created = self.mkdir(space, path)?;
        let verified = self.stat(space, path)?;
        if verified.directory && verified.etag == created.etag {
            Ok(verified)
        } else {
            Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "created directory could not be verified",
            ))
        }
    }
    /// Run local admission/invalidation against freshly observed ordinary
    /// Space/root facts before creating. The callback is operation-scoped and
    /// must succeed before any mutation request. Overrides may share the
    /// mutation's fresh checks and bind its confirmation to that same root;
    /// the default preserves independent observations and confirmation behavior.
    fn mkdir_and_confirm_with_preflight(
        &self,
        space: &str,
        path: &str,
        preflight: &dyn Fn(&CloudSpace, &RemoteEntry) -> Result<(), CloudError>,
    ) -> Result<RemoteEntry, CloudError> {
        let (selected, root) = self.space_root_metadata(space)?;
        preflight(&selected, &root)?;
        self.mkdir_and_confirm(space, path)
    }
    /// Optionally observe a complete empty-directory view during the same
    /// confirmed mkdir. The default supplies no visibility hint provenance.
    fn mkdir_and_confirm_with_preflight_and_view(
        &self,
        space: &str,
        path: &str,
        preflight: &dyn Fn(&CloudSpace, &RemoteEntry) -> Result<(), CloudError>,
    ) -> Result<(RemoteEntry, bool), CloudError> {
        self.mkdir_and_confirm_with_preflight(space, path, preflight)
            .map(|entry| (entry, false))
    }
    fn delete(&self, space: &str, path: &str, expected_etag: &str) -> Result<(), CloudError>;
    /// Supports one fresh ordinary empty-directory observation followed by
    /// conditional deletion and confirmation. This is not an atomic guard
    /// against concurrent child creation or a recursive-delete guarantee.
    fn supports_empty_directory_delete(&self) -> bool {
        false
    }
    fn delete_empty_directory_and_confirm_with_preflight(
        &self,
        _space: &str,
        _path: &str,
        _expected_resource_id: &str,
        _preflight: &dyn Fn(&CloudSpace, &RemoteEntry) -> Result<(), CloudError>,
    ) -> Result<(), CloudError> {
        Err(CloudError::new(
            ErrorKind::Unsupported,
            "bound empty-directory deletion is unavailable",
        ))
    }
    /// Delete conditionally and prove the target is absent. Specialized
    /// backends may perform both phases under one fresh operation context.
    fn delete_and_confirm(
        &self,
        space: &str,
        path: &str,
        expected_etag: &str,
    ) -> Result<(), CloudError> {
        self.delete(space, path, expected_etag)?;
        match self.stat(space, path) {
            Err(error) if error.kind == ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "deleted item is still present",
            )),
            Err(error) => Err(error),
        }
    }
    /// Operation-scoped local admission/invalidation before a conditional
    /// delete. No absence or reusable authorization is conveyed by the callback.
    /// Overrides sharing checks must confirm absence under the observed root.
    /// The default retains the backend's existing delete/confirmation behavior.
    fn delete_and_confirm_with_preflight(
        &self,
        space: &str,
        path: &str,
        expected_etag: &str,
        preflight: &dyn Fn(&CloudSpace, &RemoteEntry) -> Result<(), CloudError>,
    ) -> Result<(), CloudError> {
        let (selected, root) = self.space_root_metadata(space)?;
        preflight(&selected, &root)?;
        self.delete_and_confirm(space, path, expected_etag)
    }
    /// Move within one Space without overwriting an existing destination.
    fn rename(
        &self,
        space: &str,
        from: &str,
        to: &str,
        expected_etag: &str,
    ) -> Result<RemoteEntry, CloudError>;
}

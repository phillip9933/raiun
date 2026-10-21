//! A strict virtual `CloudBackend` for one unlocked encrypted root.
//!
//! Paths exposed to the engine are plaintext and relative to the selected
//! vault root (`/` is that root). The adapter binds every request to one
//! account/server/Space/resource scope, revalidates the root marker and token,
//! and performs all crypto through the shared session coordinator. Network I/O
//! never runs while the coordinator holds its session lock.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};

use raiun_cache::{
    CiphertextPinBuild, CiphertextPinInfo, CiphertextWriteInfo, CiphertextWriteState,
};
use raiun_core::backend::{
    CloudBackend, CloudError, CloudSpace, ErrorKind, RemoteEntry, WriteCondition,
};
use raiun_vault::{
    sealed_cache::SealedVaultSnapshot,
    session::{VaultSessionCoordinator, VaultSessionScope},
};
use reqwest::{
    Method, StatusCode,
    header::{CONTENT_LENGTH, CONTENT_TYPE, IF_MATCH, IF_NONE_MATCH},
};
use sha2::{Digest, Sha256};
use tempfile::{NamedTempFile, tempdir};
use url::Url;

use crate::transfer_budget::TransferDirection;
use crate::{
    OpenCloudClient, RangeReadContext, checked, conflict, invalid, io_error, network, same_origin,
    vault::{VaultDavEntry, VaultMetadataClient, VaultRootListing},
    vault_cache::{
        VaultCopySourceBinding, VaultListingMetadata, VaultOfflineCache, VaultPendingCreateRequest,
        VaultPendingDeleteRequest, VaultPendingDirectorySubtreeRetarget, VaultPendingEditMetadata,
        VaultPendingEditRequest, VaultPendingOperationKind, VaultPendingOperationRequest,
        VaultPendingParentRef, VaultPendingRenameRequest, VaultSubtreeRetargetRequest,
    },
};

mod copy;
pub use copy::{
    VaultCopyOutcome, VaultCopyReconciliationReason, VaultCopyRequest, VaultCopyResolutionOutcome,
    VaultCopyResolutionReason,
};

const MAX_VAULT_PLAINTEXT_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_VAULT_PIN_ENTRIES: usize = 100_000;
const MAX_VAULT_PIN_DEPTH: usize = 256;
const PENDING_ETAG_PREFIX: &str = "raiun-pending-v1:";

/// Emit fixed, value-free markers only for explicitly enabled synthetic
/// diagnostics. A separate file per process avoids mixing concurrent agents.
#[cfg(debug_assertions)]
fn trace_vault_upload_stage(stage: &'static str, error: Option<ErrorKind>) {
    if std::env::var_os("RAIUN_TRACE_VAULT_UPLOAD").is_none() {
        return;
    }
    let kind = error.map_or("ok", |kind| match kind {
        ErrorKind::Unauthorized => "unauthorized",
        ErrorKind::Forbidden => "forbidden",
        ErrorKind::NotFound => "not_found",
        ErrorKind::Conflict => "conflict",
        ErrorKind::Offline => "offline",
        ErrorKind::InvalidResponse => "invalid_response",
        ErrorKind::Unsupported => "unsupported",
        ErrorKind::Io => "io",
    });
    let path = std::env::temp_dir().join(format!(
        "raiun-vault-upload-stages-{}.log",
        std::process::id()
    ));
    if let Ok(mut log) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(log, "stage={stage} kind={kind}");
    }
}

#[cfg(not(debug_assertions))]
fn trace_vault_upload_stage(_stage: &'static str, _error: Option<ErrorKind>) {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultRenameOutcome {
    Committed(RemoteEntry),
    Queued {
        entry: RemoteEntry,
        write_id: String,
        revision: u64,
        uncertain: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultDeleteOutcome {
    Committed,
    Queued {
        write_id: String,
        revision: u64,
        uncertain: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultDirectoryCreateOutcome {
    Committed(RemoteEntry),
    Queued {
        entry: RemoteEntry,
        write_id: String,
        revision: u64,
        uncertain: bool,
    },
}

struct VaultPutExpectation<'a> {
    encoded_target: Option<&'a str>,
    parent_binding: Option<(&'a str, &'a str)>,
    expected_token_generation: Option<u64>,
    external_token_generation: Option<(Arc<AtomicU64>, u64)>,
    caller_cancelled: Option<&'a dyn Fn() -> bool>,
}

impl<'a> VaultPutExpectation<'a> {
    fn target(encoded_target: &'a str) -> Self {
        Self {
            encoded_target: Some(encoded_target),
            parent_binding: None,
            expected_token_generation: None,
            external_token_generation: None,
            caller_cancelled: None,
        }
    }
}

fn pending_etag(id: &str, revision: u64) -> String {
    format!("{PENDING_ETAG_PREFIX}{id}:{revision}")
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn pending_create_entry(edit: &VaultPendingEditMetadata) -> RemoteEntry {
    RemoteEntry {
        id: format!("raiun-pending-create:{}", edit.id),
        path: edit.path.clone(),
        directory: false,
        size: edit.plaintext_len,
        etag: pending_etag(&edit.id, edit.revision),
        modified_unix: 0,
        writable: true,
        encrypted: false,
    }
}

fn pending_directory_entry(edit: &VaultPendingEditMetadata) -> RemoteEntry {
    if edit.state == CiphertextWriteState::CommittedReceipt {
        return RemoteEntry {
            id: edit.receipt_resource_id.clone(),
            path: edit.path.clone(),
            directory: true,
            size: 0,
            etag: edit.receipt_etag.clone(),
            modified_unix: 0,
            writable: true,
            encrypted: false,
        };
    }
    RemoteEntry {
        id: format!("raiun-pending-directory:{}", edit.id),
        path: edit.path.clone(),
        directory: true,
        size: 0,
        etag: pending_etag(&edit.id, edit.revision),
        modified_unix: 0,
        // A queued directory is navigable but cannot yet bind children to a
        // server resource ID. Children can still record an explicit dependency
        // on this exact create operation.
        writable: false,
        encrypted: false,
    }
}

fn pending_rename_entry(edit: &VaultPendingEditMetadata) -> RemoteEntry {
    RemoteEntry {
        id: edit.base_resource_id.clone(),
        path: edit.destination_path.clone(),
        directory: false,
        size: edit.source_size,
        etag: pending_etag(&edit.id, edit.revision),
        modified_unix: 0,
        writable: true,
        encrypted: false,
    }
}

fn sha256_file(path: &Path) -> Result<String, CloudError> {
    let mut file = File::open(path).map_err(io_error)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(io_error)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn parse_pending_etag(etag: &str) -> Option<(&str, u64)> {
    let rest = etag.strip_prefix(PENDING_ETAG_PREFIX)?;
    let (id, revision) = rest.split_once(':')?;
    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let revision = revision.parse::<u64>().ok()?;
    (revision > 0).then_some((id, revision))
}

fn compare_reader_to_file<R: Read + Seek>(
    left: &mut R,
    right: &mut File,
    expected_len: u64,
) -> Result<bool, CloudError> {
    if right.metadata().map_err(io_error)?.len() != expected_len {
        return Ok(false);
    }
    left.seek(SeekFrom::Start(0)).map_err(io_error)?;
    right.seek(SeekFrom::Start(0)).map_err(io_error)?;
    let mut remaining = expected_len;
    let mut left_buffer = [0u8; 64 * 1024];
    let mut right_buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let count = usize::try_from(remaining.min(left_buffer.len() as u64))
            .map_err(|_| invalid("encrypted edit length is invalid"))?;
        left.read_exact(&mut left_buffer[..count])
            .map_err(io_error)?;
        right
            .read_exact(&mut right_buffer[..count])
            .map_err(io_error)?;
        if left_buffer[..count] != right_buffer[..count] {
            return Ok(false);
        }
        remaining -= count as u64;
    }
    let mut extra = [0u8; 1];
    if left.read(&mut extra).map_err(io_error)? != 0
        || right.read(&mut extra).map_err(io_error)? != 0
    {
        return Ok(false);
    }
    Ok(true)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VaultPinProgress {
    pub items_done: usize,
    pub bytes_done: u64,
}

/// Result of an encrypted upload attempt. `Queued` means the complete local
/// revision was durably encrypted into the scoped cache journal; it does not
/// mean the server accepted the edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultUploadOutcome {
    Committed(RemoteEntry),
    Queued {
        entry: RemoteEntry,
        write_id: String,
        revision: u64,
        uncertain: bool,
    },
    BuildingCreate {
        entry: RemoteEntry,
        write_id: String,
        revision: u64,
    },
    QueuedCreate {
        entry: RemoteEntry,
        write_id: String,
        revision: u64,
        uncertain: bool,
    },
}

/// Exact current authenticated journal identity used to repair a working-copy
/// manifest after a crash between a journal retarget CAS and local rebind.
/// The plaintext digest is present only for a verified NeverAttempted create;
/// rows that may have been dispatched remain visible without authorizing a
/// spool rebind.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultPendingCreateResolution {
    pub scope: VaultSessionScope,
    pub metadata: VaultPendingEditMetadata,
    pub plaintext_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPendingDirectorySubtreeRetargetExpectedRevision {
    pub write_id: String,
    pub previous_revision: u64,
    pub revision: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultPendingDirectorySubtreeRetargetResolutionState {
    AllOld,
    AllNew,
}

#[derive(Clone, PartialEq, Eq)]
pub struct VaultPendingDirectorySubtreeRetargetCurrentRow {
    pub write_id: String,
    pub revision: u64,
    pub operation: VaultPendingOperationKind,
    pub path: String,
    pub encoded_target: String,
    pub parent_ref: VaultPendingParentRef,
    pub plaintext_len: u64,
    pub plaintext_sha256: String,
    pub state: CiphertextWriteState,
}

#[derive(Clone, PartialEq, Eq)]
pub struct VaultPendingDirectorySubtreeRetargetResolution {
    /// Exact vault scope bound to this backend. The root token is checked
    /// against this scope before rows are returned and is not exposed.
    pub scope: VaultSessionScope,
    pub state: VaultPendingDirectorySubtreeRetargetResolutionState,
    pub root_write_id: String,
    pub root_previous_revision: u64,
    pub root_revision: u64,
    pub rows: Vec<VaultPendingDirectorySubtreeRetargetCurrentRow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultCancelledCreateReceiptState {
    Cancelled,
    Acknowledged,
}

/// Authenticated receipt left behind after a user canceled a never-attempted
/// local file create. The acknowledgement is a compact sealed record so a
/// restart can finish WAL cleanup without retaining the original body.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultCancelledCreateReceipt {
    pub scope: VaultSessionScope,
    pub metadata: VaultPendingEditMetadata,
    pub state: VaultCancelledCreateReceiptState,
    pub original_revision: u64,
    pub current_revision: u64,
    pub plaintext_len: u64,
    pub plaintext_sha256: String,
}

impl std::fmt::Debug for VaultCancelledCreateReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultCancelledCreateReceipt")
            .field("scope", &"[EXACT SCOPE]")
            .field("metadata", &self.metadata)
            .field("state", &self.state)
            .field("original_revision", &self.original_revision)
            .field("current_revision", &self.current_revision)
            .field("plaintext_len", &self.plaintext_len)
            .field("plaintext_sha256", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Debug for VaultPendingCreateResolution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultPendingCreateResolution")
            .field("scope", &"[EXACT SCOPE]")
            .field("metadata", &self.metadata)
            .field(
                "plaintext_sha256",
                &self.plaintext_sha256.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

struct OfflineEditContext {
    base: RemoteEntry,
    condition: WriteCondition,
    existing_id: Option<String>,
    uncertain: bool,
}

fn check_pin_cancelled(cancelled: &AtomicBool) -> Result<(), CloudError> {
    if cancelled.load(Ordering::Acquire) {
        Err(conflict("encrypted pin operation was cancelled"))
    } else {
        Ok(())
    }
}

/// A `CloudBackend` view of exactly one unlocked folder vault or encrypted Space.
///
/// This backend is deliberately vault-only: CloudBackend path `/` maps to the
/// bound physical root folder, and `/notes/a.txt` denotes plaintext path
/// components below it. It never delegates an out-of-vault path to the ordinary
/// OpenCloud backend.
pub struct VaultBackend {
    client: OpenCloudClient,
    sessions: Arc<VaultSessionCoordinator>,
    scope: VaultSessionScope,
    root_path: String,
    space_dav_root: String,
    offline_cache: Option<VaultOfflineCache>,
    offline_root: Option<SealedVaultSnapshot>,
    offline_only: bool,
}

impl std::fmt::Debug for VaultBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultBackend")
            .field("server_origin", &self.scope.server_origin())
            .field("space_id", &self.scope.space_id())
            .field("resource_id", &self.scope.resource_id())
            .field("root_path", &self.root_path)
            .field("token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl VaultBackend {
    /// Bind an authenticated client and already-unlocked session to one folder
    /// vault or whole-Space root. The root's stable resource ID must equal the session scope's
    /// resource ID. Its current integrity token is verified with that session
    /// at construction and before every operation.
    pub fn new(
        client: OpenCloudClient,
        sessions: Arc<VaultSessionCoordinator>,
        scope: VaultSessionScope,
        root_path: String,
    ) -> Result<Self, CloudError> {
        validate_root_path(&root_path)?;
        let origin = client.server.origin().ascii_serialization();
        if scope.server_origin() != origin {
            return Err(invalid("vault session belongs to another server origin"));
        }
        if !sessions.is_unlocked(&scope).map_err(vault_error)? {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault session is locked",
            ));
        }
        let binding = Self {
            client,
            sessions,
            scope,
            root_path: normalize_root_path(&root_path),
            space_dav_root: String::new(),
            offline_cache: None,
            offline_root: None,
            offline_only: false,
        };
        let state = binding.revalidate_root()?;
        Ok(Self {
            space_dav_root: state.space_dav_root,
            ..binding
        })
    }

    /// Online constructor that additionally seals complete metadata listings
    /// and fully verified ciphertext reads into an exact-scope cache.
    pub fn new_with_offline_cache(
        client: OpenCloudClient,
        sessions: Arc<VaultSessionCoordinator>,
        scope: VaultSessionScope,
        root_path: String,
        offline_cache: VaultOfflineCache,
    ) -> Result<Self, CloudError> {
        validate_root_path(&root_path)?;
        let origin = client.server.origin().ascii_serialization();
        if scope.server_origin() != origin || offline_cache.scope() != &scope {
            return Err(invalid(
                "vault cache scope does not match its OpenCloud client",
            ));
        }
        if offline_cache.root_path() != normalize_root_path(&root_path) {
            return Err(invalid("vault cache root path does not match its backend"));
        }
        if !sessions.is_unlocked(&scope).map_err(vault_error)? {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault session is locked",
            ));
        }
        let binding = Self {
            client,
            sessions,
            scope,
            root_path: normalize_root_path(&root_path),
            space_dav_root: String::new(),
            offline_cache: Some(offline_cache),
            offline_root: None,
            offline_only: false,
        };
        let state = binding.revalidate_root()?;
        Ok(Self {
            space_dav_root: state.space_dav_root,
            ..binding
        })
    }

    /// Construct an online backend for copy verification without doing a DAV
    /// probe in the caller's admission path. The exact cached root snapshot
    /// supplies the prior Space URL binding; every subsequent online operation
    /// revalidates the live root before using it.
    #[doc(hidden)]
    pub fn new_for_copy_verification(
        client: OpenCloudClient,
        sessions: Arc<VaultSessionCoordinator>,
        scope: VaultSessionScope,
        root_path: String,
        offline_cache: VaultOfflineCache,
    ) -> Result<Self, CloudError> {
        validate_root_path(&root_path)?;
        let root_path = normalize_root_path(&root_path);
        let origin = client.server.origin().ascii_serialization();
        if scope.server_origin() != origin || offline_cache.scope() != &scope {
            return Err(invalid(
                "vault cache scope does not match its OpenCloud client",
            ));
        }
        if offline_cache.root_path() != root_path {
            return Err(invalid("vault cache root path does not match its backend"));
        }
        if !sessions.is_unlocked(&scope).map_err(vault_error)? {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault session is locked",
            ));
        }
        let snapshot = offline_cache.cached_root_snapshot(&sessions)?;
        if snapshot.root_path != root_path || snapshot.directory_resource_id != scope.resource_id()
        {
            return Err(invalid(
                "cached vault root binding does not match its session",
            ));
        }
        let space_url = Url::parse(&snapshot.space_dav_url)
            .map_err(|_| invalid("cached vault Space URL is invalid"))?;
        let space_root = Url::parse(&snapshot.space_dav_root)
            .map_err(|_| invalid("cached vault DAV root is invalid"))?;
        validate_dav_space_binding(scope.server_origin(), &space_url, &space_root)?;
        let space_dav_root = ensure_trailing_slash(space_root)?.to_string();
        Ok(Self {
            client,
            sessions,
            scope,
            root_path,
            space_dav_root,
            offline_cache: Some(offline_cache),
            offline_root: None,
            offline_only: false,
        })
    }

    /// Construct a read-only backend from a root envelope already unlocked by
    /// `VaultOfflineCache::unlock_root`. The envelope is exact-scope and token
    /// verified; DAV URLs remain untrusted and are origin-checked here. Network
    /// operations are still attempted first and only transport failures use
    /// the cache.
    pub fn new_from_cached_root(
        client: OpenCloudClient,
        sessions: Arc<VaultSessionCoordinator>,
        scope: VaultSessionScope,
        root_path: String,
        offline_cache: VaultOfflineCache,
        root_snapshot: SealedVaultSnapshot,
    ) -> Result<Self, CloudError> {
        validate_root_path(&root_path)?;
        let root_path = normalize_root_path(&root_path);
        if client.server.origin().ascii_serialization() != scope.server_origin()
            || offline_cache.scope() != &scope
            || offline_cache.root_path() != root_path
            || root_snapshot.root_path != root_path
            || root_snapshot.directory_resource_id != scope.resource_id()
            || !root_snapshot.encrypted_directory_path.is_empty()
        {
            return Err(invalid(
                "cached vault root binding does not match its session",
            ));
        }
        if !sessions.is_unlocked(&scope).map_err(vault_error)?
            || !sessions
                .verify_integrity_token(&scope, &root_snapshot.integrity_token)
                .map_err(vault_error)?
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "cached vault root is not unlocked for this session",
            ));
        }
        let space_url = Url::parse(&root_snapshot.space_dav_url)
            .map_err(|_| invalid("cached vault Space URL is invalid"))?;
        let space_root = Url::parse(&root_snapshot.space_dav_root)
            .map_err(|_| invalid("cached vault DAV root is invalid"))?;
        if root_snapshot.space_encrypted != (root_path == "/") {
            return Err(invalid(
                "cached vault DAV binding is outside its server origin",
            ));
        }
        validate_dav_space_binding(scope.server_origin(), &space_url, &space_root)?;
        let space_dav_root = ensure_trailing_slash(space_root)?.to_string();
        let backend = Self {
            client,
            sessions,
            scope,
            root_path,
            space_dav_root,
            offline_cache: Some(offline_cache),
            offline_root: Some(root_snapshot),
            offline_only: true,
        };
        Ok(backend)
    }

    /// Resolve a plaintext mounted path to its exact encrypted relative DAV
    /// target after checking current sibling collisions and the supplied
    /// conditional-write version. The returned string is opaque metadata for
    /// the trusted FUSE adapter, never a host path.
    pub fn prepare_write_target(
        &self,
        virtual_path: &str,
        condition: &WriteCondition,
    ) -> Result<String, CloudError> {
        let path = normalize_virtual_path(virtual_path)?;
        validate_virtual_path(&path)?;
        if self.pending_rename_for_source(&path)?.is_some() {
            return Err(conflict("vault file has a pending encrypted rename"));
        }
        if self.pending_rename_for_destination(&path)?.is_some() {
            return Err(conflict(
                "vault write cannot replace a locally renamed destination",
            ));
        }
        if self
            .pending_delete_for_source(&path)?
            .is_some_and(|delete| {
                matches!(
                    delete.state,
                    CiphertextWriteState::Pending | CiphertextWriteState::Uncertain
                )
            })
        {
            return Err(conflict(
                "vault write cannot replace a locally deleted file",
            ));
        }
        let (condition, _) = self.resolve_pending_condition(&path, condition)?;
        if self.offline_only && !matches!(&condition, WriteCondition::Match(_)) {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "offline encrypted edits require an existing file",
            ));
        }
        if self.offline_only {
            return self.encoded_file_target_from_cache(&path, &condition);
        }
        match self.revalidate_root() {
            Ok(state) => self.encoded_file_target(&state, &path, &condition),
            Err(error) if error.kind == ErrorKind::Offline => {
                self.encoded_file_target_from_cache(&path, &condition)
            }
            Err(error) => Err(error),
        }
    }

    /// Resolve a new regular-file path after validating its parent and sibling
    /// names. The result is an opaque encrypted DAV target bound to this vault.
    pub fn prepare_create_target(&self, virtual_path: &str) -> Result<String, CloudError> {
        self.prepare_file_create_target(virtual_path, None)
    }

    /// Revalidate a new-file target, optionally against the exact prior
    /// Building/queued create revision persisted by a FUSE handle.
    pub fn prepare_file_create_target(
        &self,
        virtual_path: &str,
        existing_create: Option<(&str, u64)>,
    ) -> Result<String, CloudError> {
        let path = normalize_virtual_path(virtual_path)?;
        let (parent_id, _) = self.current_parent_binding(&path)?;
        self.prepare_file_create_target_for_parent(
            &path,
            &VaultPendingParentRef::Stable {
                resource_id: parent_id,
            },
            existing_create,
        )
    }

    pub fn prepare_file_create_target_for_parent(
        &self,
        virtual_path: &str,
        parent_ref: &VaultPendingParentRef,
        existing_create: Option<(&str, u64)>,
    ) -> Result<String, CloudError> {
        let path = normalize_virtual_path(virtual_path)?;
        validate_virtual_path(&path)?;
        if path == "/" {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cannot create over the vault root",
            ));
        }
        let previous = if let Some((id, revision)) = existing_create {
            let cache = self.offline_cache.as_ref().ok_or_else(|| {
                CloudError::new(
                    ErrorKind::Offline,
                    "encrypted create journal is unavailable",
                )
            })?;
            let previous = cache.pending_operation(&self.sessions, id, revision)?;
            if previous.operation != VaultPendingOperationKind::CreateFile
                || previous.base != WriteCondition::Absent
                || previous.path != path
                || !matches!(
                    previous.state,
                    CiphertextWriteState::Building | CiphertextWriteState::NeverAttempted
                )
            {
                return Err(conflict("encrypted create handle does not match this path"));
            }
            Some(previous)
        } else {
            if self.pending_edit_for_path(&path)?.is_some()
                || self.pending_rename_for_destination(&path)?.is_some()
            {
                return Err(conflict("vault destination already has a local operation"));
            }
            None
        };
        let parent_path = logical_parent(&path);
        let expected_parent_id = match parent_ref {
            VaultPendingParentRef::Stable { resource_id } => resource_id.as_str(),
            VaultPendingParentRef::PendingCreate { write_id, .. } => {
                // This value is only used to bind the exact projected parent
                // returned by `parent_ref_for_directory` below.
                let _ = write_id;
                ""
            }
        };
        let verified_parent = if matches!(parent_ref, VaultPendingParentRef::PendingCreate { .. }) {
            let VaultPendingParentRef::PendingCreate { write_id, revision } = parent_ref else {
                unreachable!()
            };
            let cache = self
                .offline_cache
                .as_ref()
                .ok_or_else(|| conflict("pending encrypted parent is unavailable"))?;
            let pending_matches = cache
                .pending_operation(&self.sessions, write_id, *revision)
                .is_ok_and(|parent| {
                    parent.operation == VaultPendingOperationKind::CreateDirectory
                        && matches!(
                            parent.state,
                            CiphertextWriteState::Pending
                                | CiphertextWriteState::Uncertain
                                | CiphertextWriteState::NeverAttempted
                                | CiphertextWriteState::Attempting
                        )
                        && parent.path == parent_path
                });
            let receipt_matches = cache
                .directory_create_receipt(&self.sessions, write_id, *revision)?
                .is_some_and(|receipt| receipt.path == parent_path);
            if !pending_matches && !receipt_matches {
                return Err(conflict(
                    "pending parent operation does not match this directory",
                ));
            }
            parent_ref.clone()
        } else {
            let (_, parent_etag) = self.current_parent_binding(&path)?;
            let current =
                self.parent_ref_for_directory(&parent_path, expected_parent_id, &parent_etag)?;
            if &current != parent_ref {
                return Err(conflict("encrypted create parent identity changed"));
            }
            current
        };
        let (encoded, parent_resource_id, parent_etag) = match &verified_parent {
            VaultPendingParentRef::Stable { resource_id } => {
                let encoded = if self.offline_only {
                    self.encoded_file_target_from_cache(&path, &WriteCondition::Absent)?
                } else {
                    match self.revalidate_root() {
                        Ok(state) => {
                            self.encoded_file_target(&state, &path, &WriteCondition::Absent)?
                        }
                        Err(error) if error.kind == ErrorKind::Offline => {
                            self.encoded_file_target_from_cache(&path, &WriteCondition::Absent)?
                        }
                        Err(error) => return Err(error),
                    }
                };
                let (actual_id, etag) = self.current_parent_binding(&path)?;
                if &actual_id != resource_id {
                    return Err(conflict("encrypted create parent changed before write"));
                }
                (encoded, Some(actual_id), Some(etag))
            }
            VaultPendingParentRef::PendingCreate { .. } => {
                let pending_ref = &verified_parent;
                let VaultPendingParentRef::PendingCreate { write_id, revision } = pending_ref
                else {
                    unreachable!()
                };
                let cache = self
                    .offline_cache
                    .as_ref()
                    .ok_or_else(|| conflict("pending encrypted parent is unavailable"))?;
                let encoded = if let Some(receipt) =
                    cache.directory_create_receipt(&self.sessions, write_id, *revision)?
                {
                    if receipt.path != parent_path {
                        return Err(conflict("committed parent receipt path changed"));
                    }
                    self.encoded_target_under_committed_parent(&path, &parent_path, &receipt)?
                } else {
                    self.encoded_target_under_pending_parent(
                        &path,
                        &parent_path,
                        previous
                            .as_ref()
                            .map(|operation| (operation.id.as_str(), operation.revision)),
                    )?
                };
                (encoded, None, None)
            }
        };
        if previous
            .as_ref()
            .is_some_and(|previous| previous.encoded_target != encoded)
        {
            return Err(conflict(
                "encrypted create target changed during revalidation",
            ));
        }
        if previous.as_ref().is_some_and(|previous| {
            previous.parent_ref.as_ref() != Some(&verified_parent)
                || previous.parent_resource_id != parent_resource_id.as_deref().unwrap_or_default()
                || previous.parent_etag != parent_etag.as_deref().unwrap_or_default()
        }) {
            return Err(conflict("encrypted create parent identity changed"));
        }
        Ok(encoded)
    }

    /// Resolve a new encrypted directory path after checking its exact
    /// parent and ensuring no live or queued item already occupies it.
    pub fn prepare_directory_create_target(
        &self,
        virtual_path: &str,
    ) -> Result<String, CloudError> {
        let path = normalize_virtual_path(virtual_path)?;
        let (parent_resource_id, _) = self.current_parent_binding(&path)?;
        self.prepare_directory_create_target_for_parent(
            &path,
            &VaultPendingParentRef::Stable {
                resource_id: parent_resource_id,
            },
        )
    }

    pub fn prepare_directory_create_target_for_parent(
        &self,
        virtual_path: &str,
        parent_ref: &VaultPendingParentRef,
    ) -> Result<String, CloudError> {
        let path = normalize_virtual_path(virtual_path)?;
        validate_virtual_path(&path)?;
        if path == "/" {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cannot create over the encrypted vault root",
            ));
        }
        if self.pending_edit_for_path(&path)?.is_some()
            || self.pending_directory_for_path(&path)?.is_some()
            || self.pending_rename_for_destination(&path)?.is_some()
            || self.pending_delete_for_source(&path)?.is_some()
        {
            return Err(conflict(
                "encrypted directory destination already has a local operation",
            ));
        }
        let parent_path = logical_parent(&path);
        match parent_ref {
            VaultPendingParentRef::Stable { resource_id } => {
                if resource_id.is_empty() || resource_id.len() > 512 {
                    return Err(invalid("encrypted parent resource ID is invalid"));
                }
                let (_, parent_etag) = self.current_parent_binding(&path)?;
                if self.parent_ref_for_directory(&parent_path, resource_id, &parent_etag)?
                    != *parent_ref
                {
                    return Err(conflict("encrypted directory parent identity changed"));
                }
                let encoded = if self.offline_only {
                    self.encoded_file_target_from_cache(&path, &WriteCondition::Absent)?
                } else {
                    match self.revalidate_root() {
                        Ok(state) => {
                            self.encoded_file_target(&state, &path, &WriteCondition::Absent)?
                        }
                        Err(error) if error.kind == ErrorKind::Offline => {
                            self.encoded_file_target_from_cache(&path, &WriteCondition::Absent)?
                        }
                        Err(error) => return Err(error),
                    }
                };
                let (actual_id, _) = self.current_parent_binding(&path)?;
                if &actual_id != resource_id {
                    return Err(conflict("encrypted directory parent changed before create"));
                }
                Ok(encoded)
            }
            VaultPendingParentRef::PendingCreate { write_id, revision } => {
                let cache = self
                    .offline_cache
                    .as_ref()
                    .ok_or_else(|| conflict("pending encrypted parent is unavailable"))?;
                let pending_matches = cache
                    .pending_operation(&self.sessions, write_id, *revision)
                    .is_ok_and(|parent| {
                        parent.operation == VaultPendingOperationKind::CreateDirectory
                            && matches!(
                                parent.state,
                                CiphertextWriteState::Pending
                                    | CiphertextWriteState::Uncertain
                                    | CiphertextWriteState::NeverAttempted
                                    | CiphertextWriteState::Attempting
                            )
                            && parent.path == parent_path
                    });
                let receipt =
                    cache.directory_create_receipt(&self.sessions, write_id, *revision)?;
                if !pending_matches
                    && receipt
                        .as_ref()
                        .is_none_or(|receipt| receipt.path != parent_path)
                {
                    return Err(conflict(
                        "pending parent operation does not match this directory",
                    ));
                }
                if let Some(receipt) = receipt {
                    self.encoded_target_under_committed_parent(&path, &parent_path, &receipt)
                } else {
                    self.encoded_target_under_pending_parent(&path, &parent_path, None)
                }
            }
        }
    }

    /// Create one encrypted directory. The journal reservation is durable
    /// before MKCOL; a queued result overlays only this exact operation while
    /// unlocked. Ambiguous outcomes are retained and never inferred from a
    /// same-path object discovered later.
    pub fn create_directory_with_queue(
        &self,
        virtual_path: &str,
    ) -> Result<VaultDirectoryCreateOutcome, CloudError> {
        let path = normalize_virtual_path(virtual_path)?;
        let (parent_resource_id, _) = self.current_parent_binding(&path)?;
        self.create_directory_with_parent_queue(
            &path,
            &VaultPendingParentRef::Stable {
                resource_id: parent_resource_id,
            },
        )
    }

    pub fn create_directory_with_parent_queue(
        &self,
        virtual_path: &str,
        parent_ref: &VaultPendingParentRef,
    ) -> Result<VaultDirectoryCreateOutcome, CloudError> {
        let path = normalize_virtual_path(virtual_path)?;
        validate_virtual_path(&path)?;
        if path == "/" {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cannot create over the encrypted vault root",
            ));
        }
        let encoded_target = self.prepare_directory_create_target_for_parent(&path, parent_ref)?;
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "encrypted directory creation requires its durable operation journal",
            )
        })?;
        let state = if self.offline_only
            || matches!(parent_ref, VaultPendingParentRef::PendingCreate { .. })
        {
            None
        } else {
            match self.revalidate_root() {
                Ok(state) => Some(state),
                Err(error) if error.kind == ErrorKind::Offline => None,
                Err(error) => return Err(error),
            }
        };
        let root_token = match &state {
            Some(state) => state.integrity_token.clone(),
            None => cache.cached_root_snapshot(&self.sessions)?.integrity_token,
        };
        let (parent_resource_id, parent_etag) = match parent_ref {
            VaultPendingParentRef::Stable { resource_id } => {
                let (actual_id, actual_etag) = self.current_parent_binding(&path)?;
                if &actual_id != resource_id {
                    return Err(conflict("encrypted directory parent identity changed"));
                }
                (Some(actual_id), Some(actual_etag))
            }
            VaultPendingParentRef::PendingCreate { .. } => (None, None),
        };
        let mut metadata = cache.queue_directory_create(
            &self.sessions,
            VaultPendingCreateRequest {
                integrity_token: &root_token,
                encoded_target: &encoded_target,
                existing_id: None,
                parent_resource_id: parent_resource_id.as_deref(),
                parent_etag: parent_etag.as_deref(),
                parent_ref,
                body_len: 0,
                state: CiphertextWriteState::NeverAttempted,
            },
        )?;
        let Some(state) = state else {
            return Ok(VaultDirectoryCreateOutcome::Queued {
                entry: pending_directory_entry(&metadata),
                write_id: metadata.id,
                revision: metadata.revision,
                uncertain: false,
            });
        };

        // Claim the exact row before the first network mutation. If local
        // cancellation won this CAS, the directory never reaches the server.
        cache.claim_directory_create_attempt(&self.sessions, &metadata.id, metadata.revision)?;
        metadata.state = CiphertextWriteState::Attempting;

        match self.perform_directory_mkcol(
            &state,
            &path,
            &encoded_target,
            &root_token,
            parent_resource_id.as_deref().unwrap_or_default(),
            parent_etag.as_deref().unwrap_or_default(),
        ) {
            Ok(entry) => {
                let stable_parent_ref = parent_ref.clone();
                let parent_id = parent_resource_id.as_deref().unwrap_or_default();
                let parent_etag = parent_etag.as_deref().unwrap_or_default();
                let receipt = match cache.commit_directory_receipt(
                    &self.sessions,
                    &metadata,
                    &entry,
                    &stable_parent_ref,
                    parent_id,
                    parent_etag,
                ) {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        let _ = cache.set_pending_edit_state(
                            &metadata.id,
                            metadata.revision,
                            CiphertextWriteState::Uncertain,
                        );
                        return Err(error);
                    }
                };
                match cache.retire_directory_receipt_if_unreferenced(
                    &self.sessions,
                    &metadata.id,
                    receipt.receipt_for_revision,
                ) {
                    Ok(()) => {}
                    Err(error) if error.kind == ErrorKind::Conflict => {}
                    Err(error) => return Err(error),
                }
                Ok(VaultDirectoryCreateOutcome::Committed(entry))
            }
            Err(error) => {
                let state = match error.kind {
                    ErrorKind::Conflict | ErrorKind::Forbidden => CiphertextWriteState::Conflict,
                    _ => CiphertextWriteState::Uncertain,
                };
                cache.set_pending_edit_state(&metadata.id, metadata.revision, state)?;
                if state == CiphertextWriteState::Conflict {
                    return Err(error);
                }
                Ok(VaultDirectoryCreateOutcome::Queued {
                    entry: pending_directory_entry(&metadata),
                    write_id: metadata.id,
                    revision: metadata.revision,
                    uncertain: state == CiphertextWriteState::Uncertain,
                })
            }
        }
    }

    /// Cancel a directory that is still a local-only, never-dispatched create
    /// intent. This performs no DAV mutation and refuses stale projections,
    /// attempted rows, and any directory with dependent journal operations.
    pub fn cancel_never_attempted_directory_create(
        &self,
        virtual_path: &str,
        write_id: &str,
        revision: u64,
        expected_entry_id: &str,
        expected_entry_etag: &str,
    ) -> Result<(), CloudError> {
        let path = normalize_virtual_path(virtual_path)?;
        validate_virtual_path(&path)?;
        if path == "/" {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "encrypted vault root cannot be canceled",
            ));
        }
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "encrypted directory journal is unavailable",
            )
        })?;
        let operation = cache.pending_operation(&self.sessions, write_id, revision)?;
        let expected = pending_directory_entry(&operation);
        if operation.operation != VaultPendingOperationKind::CreateDirectory
            || operation.state != CiphertextWriteState::NeverAttempted
            || operation.base != WriteCondition::Absent
            || operation.path != path
            || operation.root_integrity_token.is_empty()
            || expected.id != expected_entry_id
            || expected.etag != expected_entry_etag
        {
            return Err(conflict(
                "encrypted directory is stale or has already been attempted",
            ));
        }
        cache.cancel_never_attempted_directory_create(&self.sessions, write_id, revision, &path)
    }

    /// Move an empty queued directory reservation to a different encrypted
    /// path. This is a journal-only retarget: it never sends DAV. Only the
    /// exact NeverAttempted CreateDirectory generation is eligible, and the
    /// cache repeats the no-child test transactionally while publishing so a
    /// child registration or an MKCOL attempt cannot race the retarget.
    pub fn rename_never_attempted_directory_create_with_queue(
        &self,
        from: &str,
        to: &str,
        expected_source_id: &str,
        expected_source_etag: &str,
        destination_parent_ref: &VaultPendingParentRef,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        let from = normalize_virtual_path(from)?;
        let to = normalize_virtual_path(to)?;
        validate_virtual_path(&from)?;
        validate_virtual_path(&to)?;
        if from == "/" || to == "/" || from == to || to.starts_with(&format!("{from}/")) {
            return Err(conflict("queued directory rename paths are invalid"));
        }
        let Some(id) = expected_source_id.strip_prefix("raiun-pending-directory:") else {
            return Err(conflict(
                "directory source is not a queued encrypted create",
            ));
        };
        let Some((etag_id, revision)) = parse_pending_etag(expected_source_etag) else {
            return Err(conflict("queued directory revision is stale"));
        };
        if id.len() != 32
            || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || etag_id != id
            || pending_etag(id, revision) != expected_source_etag
        {
            return Err(conflict("queued directory identity is invalid"));
        }
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "encrypted directory journal is unavailable",
            )
        })?;
        let previous = cache.pending_operation(&self.sessions, id, revision)?;
        let expected_entry = pending_directory_entry(&previous);
        if previous.operation != VaultPendingOperationKind::CreateDirectory
            || previous.state != CiphertextWriteState::NeverAttempted
            || previous.base != WriteCondition::Absent
            || previous.path != from
            || previous.root_integrity_token.is_empty()
            || expected_entry.id != expected_source_id
            || expected_entry.etag != expected_source_etag
            || previous.receipt_for_revision != 0
        {
            return Err(conflict(
                "queued directory is stale or may already have been dispatched",
            ));
        }
        let root = cache.cached_root_snapshot(&self.sessions)?;
        if root.integrity_token != previous.root_integrity_token || !root.space_writable {
            return Err(conflict("queued directory root binding changed"));
        }

        let parent_path = logical_parent(&to);
        if from == parent_path || parent_path.starts_with(&format!("{from}/")) {
            return Err(conflict("queued directory cannot be moved into itself"));
        }
        if self.pending_edit_for_path(&to)?.is_some()
            || self.pending_rename_for_destination(&to)?.is_some()
            || self.pending_directory_for_path(&to)?.is_some()
            || self.pending_delete_for_source(&to)?.is_some()
        {
            return Err(conflict("queued directory destination is occupied locally"));
        }

        let (encoded_target, parent_resource_id, parent_etag) = match destination_parent_ref {
            VaultPendingParentRef::Stable { resource_id } => {
                let parent = cache.stat_with_cached_permissions(&self.sessions, &parent_path)?;
                if !parent.directory
                    || parent.id != *resource_id
                    || parent.id.is_empty()
                    || parent.etag.is_empty()
                    || (parent_path != "/" && !parent.writable)
                {
                    return Err(conflict("queued directory destination parent changed"));
                }
                let target = self.encoded_file_target_from_cache(&to, &WriteCondition::Absent)?;
                (target, Some(parent.id), Some(parent.etag))
            }
            VaultPendingParentRef::PendingCreate {
                write_id: parent_id,
                revision: parent_revision,
            } => {
                let parent =
                    cache.pending_operation(&self.sessions, parent_id, *parent_revision)?;
                if parent.operation != VaultPendingOperationKind::CreateDirectory
                    || parent.path != parent_path
                    || parent.root_integrity_token != previous.root_integrity_token
                    || !matches!(
                        parent.state,
                        CiphertextWriteState::NeverAttempted
                            | CiphertextWriteState::Attempting
                            | CiphertextWriteState::Pending
                            | CiphertextWriteState::Uncertain
                    )
                {
                    return Err(conflict("queued directory destination parent is stale"));
                }
                let (files, files_truncated) =
                    cache.pending_creates_for_parent(&self.sessions, &parent_path, 100)?;
                let (directories, directories_truncated) =
                    cache.pending_directories_for_parent(&self.sessions, &parent_path, 100)?;
                let (renames, renames_truncated) =
                    cache.pending_renames_for_parent(&self.sessions, &parent_path, 100)?;
                if files_truncated || directories_truncated || renames_truncated {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "too many local encrypted siblings to validate this rename",
                    ));
                }
                let mut existing = files
                    .iter()
                    .map(|row| row.path.rsplit('/').next().unwrap_or_default().to_owned())
                    .chain(
                        directories
                            .iter()
                            .map(|row| row.path.rsplit('/').next().unwrap_or_default().to_owned()),
                    )
                    .chain(renames.iter().map(|row| {
                        row.destination_path
                            .rsplit('/')
                            .next()
                            .unwrap_or_default()
                            .to_owned()
                    }))
                    .collect::<Vec<_>>();
                let leaf = to.rsplit('/').next().unwrap_or_default();
                if existing.iter().any(|name| name == leaf) {
                    return Err(conflict("queued directory destination exists locally"));
                }
                let encrypted_existing = existing
                    .iter()
                    .map(|name| self.sessions.encrypt_name(&self.scope, name))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(vault_error)?;
                let existing_refs = encrypted_existing
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                let encoded_leaf = self
                    .sessions
                    .encode_directory_names(&self.scope, &[leaf], &existing_refs)
                    .map_err(vault_error)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| invalid("encrypted name encoding returned no target"))?;
                let encoded_parent = self
                    .sessions
                    .encrypt_path(&self.scope, parent_path.trim_start_matches('/'))
                    .map_err(vault_error)?;
                existing.clear();
                let target = if encoded_parent.is_empty() {
                    encoded_leaf
                } else {
                    format!("{encoded_parent}/{encoded_leaf}")
                };
                (target, None, None)
            }
        };

        let mut metadata = cache.queue_retargeted_directory_create(
            &self.sessions,
            VaultPendingOperationRequest {
                integrity_token: &previous.root_integrity_token,
                encoded_target: &encoded_target,
                operation: VaultPendingOperationKind::CreateDirectory,
                base: WriteCondition::Absent,
                base_resource_id: None,
                parent_resource_id: parent_resource_id.as_deref(),
                parent_etag: parent_etag.as_deref(),
                parent_ref: Some(destination_parent_ref),
                destination_target: None,
                destination_parent_resource_id: None,
                destination_parent_etag: None,
                source_size: None,
                source_ciphertext_sha256: None,
                copy_source: None,
                existing_id: Some(id),
                body_len: 0,
                state: CiphertextWriteState::NeverAttempted,
                receipt_resource_id: None,
                receipt_etag: None,
                receipt_for_revision: None,
            },
            &previous.encoded_target,
            revision,
        )?;
        metadata.path = to;
        Ok(metadata)
    }

    /// Atomically retarget a bounded, populated subtree composed only of
    /// never-attempted queued creates. Every operation is resealed with its
    /// new logical target and parent reference before the cache switches any
    /// journal rows. This method performs no DAV mutation.
    pub fn retarget_never_attempted_directory_subtree_with_queue(
        &self,
        from: &str,
        to: &str,
        expected_source_id: &str,
        expected_source_etag: &str,
        destination_parent_ref: &VaultPendingParentRef,
    ) -> Result<VaultPendingDirectorySubtreeRetarget, CloudError> {
        self.retarget_never_attempted_directory_subtree_before_publish(
            from,
            to,
            expected_source_id,
            expected_source_etag,
            destination_parent_ref,
            |_| Ok(()),
        )
    }

    /// Variant for FUSE recovery: `before_publish` runs after the full
    /// dependency closure and every sealed body have been authenticated, but
    /// before the atomic SQLite publication. A caller can fsync a batch WAL;
    /// if that callback fails, the journal remains entirely unchanged.
    pub fn retarget_never_attempted_directory_subtree_before_publish<F>(
        &self,
        from: &str,
        to: &str,
        expected_source_id: &str,
        expected_source_etag: &str,
        destination_parent_ref: &VaultPendingParentRef,
        mut before_publish: F,
    ) -> Result<VaultPendingDirectorySubtreeRetarget, CloudError>
    where
        F: FnMut(&VaultPendingDirectorySubtreeRetarget) -> Result<(), CloudError>,
    {
        const MAX_ITEMS: usize = 64;
        const MAX_BYTES: u64 = 64 * 1024 * 1024;
        let from = normalize_virtual_path(from)?;
        let to = normalize_virtual_path(to)?;
        validate_virtual_path(&from)?;
        validate_virtual_path(&to)?;
        if from == "/"
            || to == "/"
            || from == to
            || to.starts_with(&format!("{from}/"))
            || from.starts_with(&format!("{to}/"))
        {
            return Err(conflict(
                "queued directory subtree rename paths are invalid",
            ));
        }
        let Some(root_id) = expected_source_id.strip_prefix("raiun-pending-directory:") else {
            return Err(conflict(
                "directory source is not a queued encrypted create",
            ));
        };
        let Some((etag_id, root_revision)) = parse_pending_etag(expected_source_etag) else {
            return Err(conflict("queued directory revision is stale"));
        };
        if root_id.len() != 32
            || !root_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || etag_id != root_id
            || pending_etag(root_id, root_revision) != expected_source_etag
        {
            return Err(conflict("queued directory identity is invalid"));
        }
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "encrypted directory journal is unavailable",
            )
        })?;
        let root_operation = cache.pending_operation(&self.sessions, root_id, root_revision)?;
        if root_operation.operation != VaultPendingOperationKind::CreateDirectory
            || root_operation.state != CiphertextWriteState::NeverAttempted
            || root_operation.base != WriteCondition::Absent
            || root_operation.path != from
            || root_operation.receipt_for_revision != 0
            || !root_operation.receipt_resource_id.is_empty()
            || !root_operation.receipt_etag.is_empty()
            || root_operation.root_integrity_token.is_empty()
        {
            return Err(conflict("queued directory is stale or has been attempted"));
        }
        let root = cache.cached_root_snapshot(&self.sessions)?;
        if root.integrity_token != root_operation.root_integrity_token || !root.space_writable {
            return Err(conflict("queued directory root binding changed"));
        }

        let destination_parent_path = logical_parent(&to);
        let (root_encoded_target, root_parent_id, root_parent_etag) = match destination_parent_ref {
            VaultPendingParentRef::Stable { resource_id } => {
                let parent =
                    cache.stat_with_cached_permissions(&self.sessions, &destination_parent_path)?;
                if !parent.directory
                    || parent.id != *resource_id
                    || parent.id.is_empty()
                    || parent.etag.is_empty()
                    || (destination_parent_path != "/" && !parent.writable)
                {
                    return Err(conflict("queued directory destination parent changed"));
                }
                match cache.stat_with_cached_permissions(&self.sessions, &to) {
                    Ok(_) => return Err(conflict("queued directory destination exists")),
                    Err(error) if error.kind == ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                (
                    self.encoded_file_target_from_cache(&to, &WriteCondition::Absent)?,
                    parent.id,
                    parent.etag,
                )
            }
            VaultPendingParentRef::PendingCreate { write_id, revision } => {
                let parent = cache.pending_operation(&self.sessions, write_id, *revision)?;
                if parent.operation != VaultPendingOperationKind::CreateDirectory
                    || parent.path != destination_parent_path
                    || parent.root_integrity_token != root_operation.root_integrity_token
                    || !matches!(
                        parent.state,
                        CiphertextWriteState::NeverAttempted
                            | CiphertextWriteState::Pending
                            | CiphertextWriteState::Uncertain
                            | CiphertextWriteState::Attempting
                            | CiphertextWriteState::CommittedReceipt
                    )
                {
                    return Err(conflict("queued directory destination parent is stale"));
                }
                let (files, files_truncated) = cache.pending_creates_for_parent(
                    &self.sessions,
                    &destination_parent_path,
                    100,
                )?;
                let (directories, directories_truncated) = cache.pending_directories_for_parent(
                    &self.sessions,
                    &destination_parent_path,
                    100,
                )?;
                let (renames, renames_truncated) = cache.pending_renames_for_parent(
                    &self.sessions,
                    &destination_parent_path,
                    100,
                )?;
                if files_truncated || directories_truncated || renames_truncated {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "too many local encrypted siblings to validate this rename",
                    ));
                }
                let leaf = to.rsplit('/').next().unwrap_or_default();
                if files
                    .iter()
                    .any(|row| row.path.rsplit('/').next() == Some(leaf))
                    || directories
                        .iter()
                        .any(|row| row.path.rsplit('/').next() == Some(leaf))
                    || renames
                        .iter()
                        .any(|row| row.destination_path.rsplit('/').next() == Some(leaf))
                {
                    return Err(conflict("queued directory destination exists locally"));
                }
                let encrypted_existing = files
                    .iter()
                    .map(|row| {
                        self.sessions.encrypt_name(
                            &self.scope,
                            row.path.rsplit('/').next().unwrap_or_default(),
                        )
                    })
                    .chain(directories.iter().map(|row| {
                        self.sessions.encrypt_name(
                            &self.scope,
                            row.path.rsplit('/').next().unwrap_or_default(),
                        )
                    }))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(vault_error)?;
                let existing_refs = encrypted_existing
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                let encoded_leaf = self
                    .sessions
                    .encode_directory_names(&self.scope, &[leaf], &existing_refs)
                    .map_err(vault_error)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| invalid("encrypted name encoding returned no target"))?;
                let encoded_parent = self
                    .sessions
                    .encrypt_path(&self.scope, destination_parent_path.trim_start_matches('/'))
                    .map_err(vault_error)?;
                let target = if encoded_parent.is_empty() {
                    encoded_leaf
                } else {
                    format!("{encoded_parent}/{encoded_leaf}")
                };
                (target, String::new(), String::new())
            }
        };
        if cache
            .pending_edit_ref_for_path(&self.sessions, &to)?
            .is_some()
            || cache
                .pending_directory_for_path(&self.sessions, &to)?
                .is_some()
            || cache
                .pending_delete_for_path(&self.sessions, &to)?
                .is_some()
            || cache
                .pending_rename_for_destination(&self.sessions, &to)?
                .is_some()
        {
            return Err(conflict("queued directory destination is occupied locally"));
        }

        let mut operations = vec![root_operation.clone()];
        let mut cursor = 0usize;
        let mut total_bytes = operations[0].plaintext_len;
        while cursor < operations.len() {
            if operations.len() > MAX_ITEMS || total_bytes > MAX_BYTES {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "queued directory subtree exceeds its bounds",
                ));
            }
            let parent = &operations[cursor];
            if parent.operation != VaultPendingOperationKind::CreateDirectory {
                cursor += 1;
                continue;
            }
            let parent_ref = VaultPendingParentRef::PendingCreate {
                write_id: parent.id.clone(),
                revision: parent.revision,
            };
            let parent_path = parent.path.clone();
            let (children, truncated) = cache.pending_operations_for_parent_ref(
                &self.sessions,
                &parent_ref,
                None,
                MAX_ITEMS,
            )?;
            if truncated {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "queued directory subtree exceeds its operation limit",
                ));
            }
            for child in children {
                if operations.len() >= MAX_ITEMS
                    || !matches!(
                        child.operation,
                        VaultPendingOperationKind::CreateFile
                            | VaultPendingOperationKind::CreateDirectory
                    )
                    || child.state != CiphertextWriteState::NeverAttempted
                    || child.base != WriteCondition::Absent
                    || child.root_integrity_token != root_operation.root_integrity_token
                    || child.parent_ref.as_ref() != Some(&parent_ref)
                    || child.path
                        != format!(
                            "{}/{}",
                            parent_path.trim_end_matches('/'),
                            child.path.rsplit('/').next().unwrap_or_default()
                        )
                    || child.receipt_for_revision != 0
                    || !child.receipt_resource_id.is_empty()
                    || !child.receipt_etag.is_empty()
                {
                    return Err(conflict(
                        "queued directory subtree contains an unsupported dependency",
                    ));
                }
                total_bytes = total_bytes
                    .checked_add(child.plaintext_len)
                    .filter(|bytes| *bytes <= MAX_BYTES)
                    .ok_or_else(|| {
                        CloudError::new(
                            ErrorKind::Unsupported,
                            "queued directory subtree exceeds its byte limit",
                        )
                    })?;
                operations.push(child);
            }
            cursor += 1;
        }

        let mut new_paths = std::collections::BTreeMap::<String, (String, u64)>::new();
        for operation in &operations {
            let suffix = operation
                .path
                .strip_prefix(&from)
                .ok_or_else(|| conflict("queued subtree contains an unrelated path"))?;
            if !suffix.is_empty() && !suffix.starts_with('/') {
                return Err(conflict("queued subtree path boundary is invalid"));
            }
            let new_path = format!("{to}{suffix}");
            new_paths.insert(new_path, (operation.id.clone(), operation.revision + 1));
        }
        let mut requests = Vec::with_capacity(operations.len());
        for (index, operation) in operations.iter().enumerate() {
            let suffix = operation
                .path
                .strip_prefix(&from)
                .ok_or_else(|| conflict("queued subtree contains an unrelated path"))?;
            let new_path = format!("{to}{suffix}");
            let parent_path = logical_parent(&new_path);
            let (parent_ref, parent_resource_id, parent_etag) = if index == 0 {
                (
                    destination_parent_ref.clone(),
                    root_parent_id.clone(),
                    root_parent_etag.clone(),
                )
            } else if let Some((parent_id, parent_revision)) = new_paths.get(&parent_path) {
                (
                    VaultPendingParentRef::PendingCreate {
                        write_id: parent_id.clone(),
                        revision: *parent_revision,
                    },
                    String::new(),
                    String::new(),
                )
            } else {
                return Err(conflict("queued subtree parent binding is incomplete"));
            };
            let encoded_target = if index == 0 {
                root_encoded_target.clone()
            } else {
                self.sessions
                    .encrypt_path(&self.scope, new_path.trim_start_matches('/'))
                    .map_err(vault_error)?
            };
            requests.push(VaultSubtreeRetargetRequest {
                id: operation.id.clone(),
                expected_revision: operation.revision,
                old_path: operation.path.clone(),
                new_path,
                encoded_target,
                parent_ref,
                parent_resource_id,
                parent_etag,
            });
        }
        cache.retarget_never_attempted_directory_subtree(
            &self.sessions,
            root_id,
            root_revision,
            &requests,
            &mut before_publish,
        )
    }

    /// Cancel an exact locally queued file create before it has ever been
    /// dispatched. This atomically changes the row into a durable receipt and
    /// sends no DAV request. The caller must retain its recovery copy until it
    /// has durably recorded the receipt, then retire only the matching copy
    /// and acknowledge the receipt.
    pub fn cancel_never_attempted_file_create(
        &self,
        virtual_path: &str,
        write_id: &str,
        revision: u64,
        expected_entry_id: &str,
        expected_entry_etag: &str,
    ) -> Result<VaultCancelledCreateReceipt, CloudError> {
        let path = normalize_virtual_path(virtual_path)?;
        validate_virtual_path(&path)?;
        if path == "/" {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "encrypted vault root cannot be canceled",
            ));
        }
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "encrypted file-create journal is unavailable",
            )
        })?;
        let operation = cache.pending_operation(&self.sessions, write_id, revision)?;
        let expected = pending_create_entry(&operation);
        if operation.operation != VaultPendingOperationKind::CreateFile
            || !matches!(
                operation.state,
                CiphertextWriteState::NeverAttempted | CiphertextWriteState::CancelledReceipt
            )
            || operation.base != WriteCondition::Absent
            || operation.path != path
            || expected.id != expected_entry_id
            || expected.etag != expected_entry_etag
            || self.decode_target_path(&operation.encoded_target)? != path
        {
            return Err(conflict(
                "encrypted file create is stale or has already been attempted",
            ));
        }
        // Verify the full authenticated body without consulting the cached
        // root listing: a queued create invalidates that listing by design,
        // while this local-only cancellation needs no remote authority.
        let (verified_metadata, _digest) =
            self.verify_cancelled_create_body(cache, write_id, revision)?;
        if verified_metadata != operation {
            return Err(conflict(
                "encrypted file-create body changed during local cancellation",
            ));
        }
        let current = cache
            .pending_operation_current(&self.sessions, write_id)?
            .ok_or_else(|| conflict("encrypted file-create journal disappeared"))?;
        if current != operation {
            return Err(conflict(
                "encrypted file create changed during local cancellation",
            ));
        }
        cache.cancel_never_attempted_file_create(
            &self.sessions,
            write_id,
            revision,
            &operation.encoded_target,
            operation.plaintext_len,
        )?;
        self.resolve_cancelled_file_create_by_id(write_id, revision)?
            .ok_or_else(|| conflict("encrypted file-create cancellation receipt disappeared"))
    }

    /// Resolve a durable local-cancellation receipt by exact opaque operation
    /// identity. No path search or missing-row inference is permitted.
    pub fn resolve_cancelled_file_create_by_id(
        &self,
        write_id: &str,
        revision: u64,
    ) -> Result<Option<VaultCancelledCreateReceipt>, CloudError> {
        let Some(cache) = &self.offline_cache else {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted create cancellation receipts are unavailable",
            ));
        };
        let Some(operation) = cache.pending_operation_current(&self.sessions, write_id)? else {
            return Ok(None);
        };
        if operation.operation != VaultPendingOperationKind::CreateFile
            || operation.base != WriteCondition::Absent
            || operation.id != write_id
            || operation.root_integrity_token.is_empty()
            || self.decode_target_path(&operation.encoded_target)? != operation.path
        {
            return Err(conflict(
                "encrypted create row does not match the requested cancellation identity",
            ));
        }
        // FUSE resolves before attempting the exact NeverAttempted -> receipt
        // CAS. That state is not a cancellation receipt, so report no receipt
        // and let the caller attempt the CAS. Other states remain errors; in
        // particular an attempted/legacy Pending row must never be treated as
        // cancellable or as proof of cancellation.
        if operation.state == CiphertextWriteState::NeverAttempted {
            if operation.revision != revision {
                return Err(conflict("encrypted create cancellation revision is stale"));
            }
            return Ok(None);
        }
        if operation.state == CiphertextWriteState::AcknowledgedReceipt {
            if operation.cancelled_revision != revision
                || operation.revision != revision.saturating_add(1)
                || operation.cancelled_plaintext_len > MAX_VAULT_PLAINTEXT_BYTES
                || !is_sha256_digest(&operation.cancelled_plaintext_sha256)
                || operation.plaintext_len != 0
            {
                return Err(conflict(
                    "encrypted create acknowledgement does not match the requested identity",
                ));
            }
            cache.remove_cancelled_file_create_body(write_id, revision)?;
            return Ok(Some(VaultCancelledCreateReceipt {
                scope: self.scope.clone(),
                state: VaultCancelledCreateReceiptState::Acknowledged,
                original_revision: revision,
                current_revision: operation.revision,
                plaintext_len: operation.cancelled_plaintext_len,
                plaintext_sha256: operation.cancelled_plaintext_sha256.clone(),
                metadata: operation,
            }));
        }
        if operation.state != CiphertextWriteState::CancelledReceipt
            || operation.revision != revision
        {
            return Err(conflict(
                "encrypted create row is not a cancellation receipt",
            ));
        }
        let (verified, plaintext_sha256) =
            self.verify_cancelled_create_body(cache, write_id, revision)?;
        if verified != operation {
            return Err(conflict(
                "encrypted create cancellation receipt changed during verification",
            ));
        }
        Ok(Some(VaultCancelledCreateReceipt {
            scope: self.scope.clone(),
            state: VaultCancelledCreateReceiptState::Cancelled,
            original_revision: revision,
            current_revision: operation.revision,
            plaintext_len: operation.plaintext_len,
            metadata: operation,
            plaintext_sha256,
        }))
    }

    /// Remove a durable cancellation receipt after the caller has durably
    /// retired the exact matching private recovery copy. The full sealed body
    /// is reverified and its digest compared before the final cache CAS.
    pub fn acknowledge_cancelled_file_create(
        &self,
        write_id: &str,
        revision: u64,
        expected_encoded_target: &str,
        expected_plaintext_len: u64,
        expected_plaintext_sha256: &str,
    ) -> Result<(), CloudError> {
        let receipt = self
            .resolve_cancelled_file_create_by_id(write_id, revision)?
            .ok_or_else(|| conflict("encrypted create cancellation receipt is missing"))?;
        if receipt.metadata.encoded_target != expected_encoded_target
            || receipt.plaintext_len != expected_plaintext_len
            || receipt.plaintext_sha256 != expected_plaintext_sha256
        {
            return Err(conflict(
                "encrypted create cancellation acknowledgement does not match its receipt",
            ));
        }
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "encrypted create cancellation receipts are unavailable",
            )
        })?;
        cache.acknowledge_cancelled_file_create(
            &self.sessions,
            write_id,
            receipt.original_revision,
            expected_encoded_target,
            expected_plaintext_len,
            expected_plaintext_sha256,
        )
    }

    /// Finalize an exact compact receipt only after the local cancellation WAL
    /// has been durably removed. Missing or mismatched receipts are errors.
    pub fn finalize_cancelled_file_create_ack(
        &self,
        write_id: &str,
        original_revision: u64,
        current_revision: u64,
        expected_encoded_target: &str,
        expected_plaintext_len: u64,
        expected_plaintext_sha256: &str,
    ) -> Result<(), CloudError> {
        let receipt = self
            .resolve_cancelled_file_create_by_id(write_id, original_revision)?
            .ok_or_else(|| conflict("encrypted cancellation acknowledgement is missing"))?;
        if receipt.state != VaultCancelledCreateReceiptState::Acknowledged
            || receipt.current_revision != current_revision
            || receipt.metadata.encoded_target != expected_encoded_target
            || receipt.plaintext_len != expected_plaintext_len
            || receipt.plaintext_sha256 != expected_plaintext_sha256
        {
            return Err(conflict(
                "encrypted cancellation finalization does not match its acknowledgement",
            ));
        }
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "encrypted create cancellation receipts are unavailable",
            )
        })?;
        cache.finalize_cancelled_file_create_ack(
            &self.sessions,
            write_id,
            original_revision,
            current_revision,
            expected_encoded_target,
            expected_plaintext_len,
            expected_plaintext_sha256,
        )
    }

    fn verify_cancelled_create_body(
        &self,
        cache: &VaultOfflineCache,
        write_id: &str,
        revision: u64,
    ) -> Result<(VaultPendingEditMetadata, String), CloudError> {
        let private = tempdir().map_err(io_error)?;
        let body_path = private.path().join("cancelled-create-verify.bin");
        let downloaded =
            cache.download_pending_edit(&self.sessions, write_id, revision, &body_path)?;
        let size = File::open(&body_path)
            .and_then(|file| file.metadata())
            .map_err(io_error)?
            .len();
        if size != downloaded.plaintext_len {
            return Err(conflict(
                "encrypted file-create body length changed during cancellation",
            ));
        }
        let digest = sha256_file(&body_path)?;
        let current = cache
            .pending_operation_current(&self.sessions, write_id)?
            .ok_or_else(|| conflict("encrypted file-create journal disappeared"))?;
        if current != downloaded {
            return Err(conflict(
                "encrypted file create changed during cancellation verification",
            ));
        }
        Ok((downloaded, digest))
    }

    /// Begin an encrypted file create without making a network mutation. The
    /// `Building` journal row is durable but excluded from directory overlays
    /// and automatic reconciliation until a complete flush replaces it.
    pub fn begin_prepared_create(
        &self,
        encoded_target: &str,
    ) -> Result<VaultUploadOutcome, CloudError> {
        let path = self.decode_target_path(encoded_target)?;
        let (parent_id, _) = self.current_parent_binding(&path)?;
        self.begin_prepared_create_for_parent(
            encoded_target,
            &VaultPendingParentRef::Stable {
                resource_id: parent_id,
            },
        )
    }

    pub fn begin_prepared_create_for_parent(
        &self,
        encoded_target: &str,
        parent_ref: &VaultPendingParentRef,
    ) -> Result<VaultUploadOutcome, CloudError> {
        let path = self.decode_target_path(encoded_target)?;
        if self.prepare_file_create_target_for_parent(&path, parent_ref, None)? != encoded_target {
            return Err(conflict("prepared encrypted create target changed"));
        }
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Offline,
                "encrypted create journal is unavailable",
            )
        })?;
        let integrity_token = if self.offline_only {
            cache.cached_root_snapshot(&self.sessions)?.integrity_token
        } else {
            match self.revalidate_root() {
                Ok(state) => state.integrity_token,
                Err(error) if error.kind == ErrorKind::Offline => {
                    cache.cached_root_snapshot(&self.sessions)?.integrity_token
                }
                Err(error) => return Err(error),
            }
        };
        let (parent_resource_id, parent_etag) = match parent_ref {
            VaultPendingParentRef::Stable { resource_id } => {
                let (actual_id, etag) = self.current_parent_binding(&path)?;
                if actual_id != *resource_id {
                    return Err(conflict("encrypted create parent identity changed"));
                }
                (Some(actual_id), Some(etag))
            }
            VaultPendingParentRef::PendingCreate { .. } => (None, None),
        };
        let mut empty = io::Cursor::new(Vec::<u8>::new());
        let metadata = cache.begin_create(
            &self.sessions,
            &mut empty,
            VaultPendingCreateRequest {
                integrity_token: &integrity_token,
                encoded_target,
                existing_id: None,
                parent_resource_id: parent_resource_id.as_deref(),
                parent_etag: parent_etag.as_deref(),
                parent_ref,
                body_len: 0,
                state: CiphertextWriteState::Building,
            },
        )?;
        Ok(VaultUploadOutcome::BuildingCreate {
            entry: pending_create_entry(&metadata),
            write_id: metadata.id,
            revision: metadata.revision,
        })
    }

    /// Persist and conditionally create one encrypted regular file. A previous
    /// Building/queued create must be supplied for FUSE working-copy revisions;
    /// the authenticated journal retains its original Absent server condition.
    /// Network ambiguity stays durable and is never overwritten automatically.
    pub fn create_prepared_reader_with_queue<R: Read + Seek>(
        &self,
        encoded_target: &str,
        source: &mut R,
        plaintext_len: u64,
        existing_create: Option<(&str, u64)>,
    ) -> Result<VaultUploadOutcome, CloudError> {
        let path = self.decode_target_path(encoded_target)?;
        let parent_ref = if let Some((id, revision)) = existing_create {
            self.offline_cache
                .as_ref()
                .ok_or_else(|| conflict("encrypted create journal is unavailable"))?
                .pending_operation(&self.sessions, id, revision)?
                .parent_ref
                .ok_or_else(|| conflict("encrypted create parent reference is missing"))?
        } else {
            let (resource_id, _) = self.current_parent_binding(&path)?;
            VaultPendingParentRef::Stable { resource_id }
        };
        self.create_prepared_reader_with_queue_for_parent(
            encoded_target,
            source,
            plaintext_len,
            existing_create,
            &parent_ref,
        )
    }

    pub fn create_prepared_reader_with_queue_for_parent<R: Read + Seek>(
        &self,
        encoded_target: &str,
        source: &mut R,
        plaintext_len: u64,
        existing_create: Option<(&str, u64)>,
        parent_ref: &VaultPendingParentRef,
    ) -> Result<VaultUploadOutcome, CloudError> {
        if plaintext_len > MAX_VAULT_PLAINTEXT_BYTES {
            return Err(invalid("vault upload source exceeds its size limit"));
        }
        let path = self.decode_target_path(encoded_target)?;
        if self.prepare_file_create_target_for_parent(&path, parent_ref, existing_create)?
            != encoded_target
        {
            return Err(conflict("prepared encrypted create target changed"));
        }
        let (parent_resource_id, parent_etag) = match parent_ref {
            VaultPendingParentRef::Stable { resource_id } => {
                let (actual_id, etag) = self.current_parent_binding(&path)?;
                if actual_id != *resource_id {
                    return Err(conflict("encrypted create parent identity changed"));
                }
                (Some(actual_id), Some(etag))
            }
            VaultPendingParentRef::PendingCreate { .. } => (None, None),
        };
        if let Some((id, revision)) = existing_create {
            let cache = self.offline_cache.as_ref().ok_or_else(|| {
                CloudError::new(
                    ErrorKind::Offline,
                    "encrypted create journal is unavailable",
                )
            })?;
            let previous = cache.pending_operation(&self.sessions, id, revision)?;
            if previous.path != path
                || previous.encoded_target != encoded_target
                || previous.operation != VaultPendingOperationKind::CreateFile
                || previous.base != WriteCondition::Absent
                || !matches!(
                    previous.state,
                    CiphertextWriteState::Building | CiphertextWriteState::NeverAttempted
                )
                || previous.parent_ref.as_ref() != Some(parent_ref)
                || previous.parent_resource_id != parent_resource_id.as_deref().unwrap_or_default()
                || previous.parent_etag != parent_etag.as_deref().unwrap_or_default()
            {
                return Err(conflict("encrypted create revision changed its target"));
            }
        }
        source.seek(SeekFrom::Start(0)).map_err(io_error)?;

        let state = if self.offline_only
            || matches!(parent_ref, VaultPendingParentRef::PendingCreate { .. })
        {
            None
        } else {
            match self.revalidate_root() {
                Ok(state) => Some(state),
                Err(error) if error.kind == ErrorKind::Offline => None,
                Err(error) => return Err(error),
            }
        };
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Offline,
                "encrypted create journal is unavailable",
            )
        })?;
        let integrity_token = match &state {
            Some(state) => state.integrity_token.clone(),
            None => cache.cached_root_snapshot(&self.sessions)?.integrity_token,
        };

        // New file bodies begin in NeverAttempted, including when online. The
        // cache switches the exact revision to Attempting before the first PUT,
        // so a crash can never turn a dispatched create back into a renameable
        // local reservation.
        let mut journal_source = &mut *source;
        let mut metadata = cache.queue_create_with_state(
            &self.sessions,
            &mut journal_source,
            VaultPendingCreateRequest {
                integrity_token: &integrity_token,
                encoded_target,
                existing_id: existing_create.map(|(id, _)| id),
                parent_resource_id: parent_resource_id.as_deref(),
                parent_etag: parent_etag.as_deref(),
                parent_ref,
                body_len: plaintext_len,
                state: CiphertextWriteState::NeverAttempted,
            },
        )?;
        source.seek(SeekFrom::Start(0)).map_err(io_error)?;
        let Some(state) = state else {
            return Ok(VaultUploadOutcome::QueuedCreate {
                entry: pending_create_entry(&metadata),
                write_id: metadata.id,
                revision: metadata.revision,
                uncertain: false,
            });
        };

        cache.claim_file_create_attempt(&self.sessions, &metadata.id, metadata.revision)?;
        metadata.state = CiphertextWriteState::Attempting;
        match self.put_vault_reader(
            &state,
            &path,
            source,
            plaintext_len,
            WriteCondition::Absent,
            VaultPutExpectation {
                encoded_target: Some(encoded_target),
                parent_binding: Some((
                    parent_resource_id.as_deref().unwrap_or_default(),
                    parent_etag.as_deref().unwrap_or_default(),
                )),
                expected_token_generation: None,
                external_token_generation: None,
                caller_cancelled: None,
            },
        ) {
            Ok(entry) => {
                match self.verify_uploaded_reader(&state, &path, &entry, source, plaintext_len) {
                    Ok(true) => {
                        trace_vault_upload_stage("create_readback_verified", None);
                        cache.retire_pending_edit(&metadata.id, metadata.revision)?;
                        Ok(VaultUploadOutcome::Committed(entry))
                    }
                    Ok(false) => {
                        trace_vault_upload_stage("create_readback_mismatch", None);
                        cache.set_pending_edit_state(
                            &metadata.id,
                            metadata.revision,
                            CiphertextWriteState::Uncertain,
                        )?;
                        metadata.state = CiphertextWriteState::Uncertain;
                        Ok(VaultUploadOutcome::QueuedCreate {
                            entry: pending_create_entry(&metadata),
                            write_id: metadata.id,
                            revision: metadata.revision,
                            uncertain: true,
                        })
                    }
                    Err(error) => {
                        trace_vault_upload_stage("create_readback_failed", Some(error.kind));
                        cache.set_pending_edit_state(
                            &metadata.id,
                            metadata.revision,
                            CiphertextWriteState::Uncertain,
                        )?;
                        metadata.state = CiphertextWriteState::Uncertain;
                        Ok(VaultUploadOutcome::QueuedCreate {
                            entry: pending_create_entry(&metadata),
                            write_id: metadata.id,
                            revision: metadata.revision,
                            uncertain: true,
                        })
                    }
                }
            }
            Err(error) if error.kind == ErrorKind::Offline || error.kind == ErrorKind::Io => {
                cache.set_pending_edit_state(
                    &metadata.id,
                    metadata.revision,
                    CiphertextWriteState::Uncertain,
                )?;
                metadata.state = CiphertextWriteState::Uncertain;
                Ok(VaultUploadOutcome::QueuedCreate {
                    entry: pending_create_entry(&metadata),
                    write_id: metadata.id,
                    revision: metadata.revision,
                    uncertain: true,
                })
            }
            Err(error) if error.kind == ErrorKind::Conflict => {
                trace_vault_upload_stage("create_put_classified_conflict", Some(error.kind));
                cache.set_pending_edit_state(
                    &metadata.id,
                    metadata.revision,
                    CiphertextWriteState::Conflict,
                )?;
                metadata.state = CiphertextWriteState::Conflict;
                Ok(VaultUploadOutcome::QueuedCreate {
                    entry: pending_create_entry(&metadata),
                    write_id: metadata.id,
                    revision: metadata.revision,
                    uncertain: false,
                })
            }
            Err(error) => {
                trace_vault_upload_stage("create_put_failed", Some(error.kind));
                Err(error)
            }
        }
    }

    /// Retarget a locally-created file that is proven never to have been
    /// dispatched. This performs no DAV mutation: it authenticates the exact
    /// journal revision, re-encrypts its body under a new sealed target and
    /// parent binding, and atomically replaces the NeverAttempted revision.
    /// The returned metadata is required for the caller to rebind its durable
    /// working-copy record to the new target; on a crash, callers must resolve
    /// the same operation ID and current revision before changing that record.
    pub fn rename_pending_create_with_queue(
        &self,
        from: &str,
        to: &str,
        expected_source_id: &str,
        expected_source_etag: &str,
        destination_parent_ref: &VaultPendingParentRef,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        let from = normalize_virtual_path(from)?;
        let to = normalize_virtual_path(to)?;
        validate_virtual_path(&from)?;
        validate_virtual_path(&to)?;
        if from == "/" || to == "/" || from == to {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted pending-file rename requires distinct non-root paths",
            ));
        }
        let Some(id) = expected_source_id.strip_prefix("raiun-pending-create:") else {
            return Err(conflict("rename source is not a pending encrypted create"));
        };
        let Some(etag_suffix) = expected_source_etag.strip_prefix(PENDING_ETAG_PREFIX) else {
            return Err(conflict("pending encrypted create revision is stale"));
        };
        let Some((etag_id, revision_text)) = etag_suffix.split_once(':') else {
            return Err(conflict("pending encrypted create revision is invalid"));
        };
        let revision: u64 = revision_text
            .parse()
            .map_err(|_| conflict("pending encrypted create revision is invalid"))?;
        if id.len() != 32
            || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || etag_id != id
            || revision == 0
            || revision > i64::MAX as u64
            || pending_etag(id, revision) != expected_source_etag
        {
            return Err(conflict("pending encrypted create identity is invalid"));
        }
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "encrypted create retarget requires its durable journal",
            )
        })?;
        let previous = cache.pending_operation(&self.sessions, id, revision)?;
        if previous.operation != VaultPendingOperationKind::CreateFile
            || previous.state != CiphertextWriteState::NeverAttempted
            || previous.base != WriteCondition::Absent
            || previous.path != from
            || !previous.base_resource_id.is_empty()
        {
            return Err(conflict(
                "encrypted create is no longer a never-attempted local reservation",
            ));
        }

        let state = if self.offline_only {
            None
        } else {
            match self.revalidate_root() {
                Ok(state) => Some(state),
                Err(error) if error.kind == ErrorKind::Offline => None,
                Err(error) => return Err(error),
            }
        };
        let current_root_token = match &state {
            Some(state) => state.integrity_token.clone(),
            None => cache.cached_root_snapshot(&self.sessions)?.integrity_token,
        };
        if current_root_token != previous.root_integrity_token {
            return Err(conflict("encrypted create root token changed"));
        }

        // A fresh destination must be absent in the selected live/cached
        // namespace and have no competing local operation. Parent resolution
        // validates an exact stable or pending-directory identity.
        if self.pending_edit_for_path(&to)?.is_some()
            || self.pending_rename_for_destination(&to)?.is_some()
            || self.pending_directory_for_path(&to)?.is_some()
            || self.pending_delete_for_source(&to)?.is_some()
        {
            return Err(conflict(
                "encrypted rename destination has a local operation",
            ));
        }
        match &state {
            Some(state) => match self.stat_raw(state, &to) {
                Ok(_) => return Err(conflict("encrypted rename destination exists")),
                Err(error) if error.kind == ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            },
            None => match cache.stat_with_cached_permissions(&self.sessions, &to) {
                Ok(_) => return Err(conflict("encrypted rename destination exists")),
                Err(error) if error.kind == ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            },
        }
        let encoded_target =
            self.prepare_file_create_target_for_parent(&to, destination_parent_ref, None)?;
        let (parent_resource_id, parent_etag) = match destination_parent_ref {
            VaultPendingParentRef::Stable { resource_id } => {
                let (actual_id, etag) = self.current_parent_binding(&to)?;
                if actual_id != *resource_id {
                    return Err(conflict("encrypted rename destination parent changed"));
                }
                (Some(actual_id), Some(etag))
            }
            VaultPendingParentRef::PendingCreate { .. } => (None, None),
        };

        let private = tempdir().map_err(io_error)?;
        let body_path = private.path().join("pending-create-body.bin");
        cache.download_pending_edit(&self.sessions, id, revision, &body_path)?;
        let mut body = File::open(&body_path).map_err(io_error)?;
        let mut metadata = cache.queue_retargeted_create(
            &self.sessions,
            &mut body,
            VaultPendingOperationRequest {
                integrity_token: &previous.root_integrity_token,
                encoded_target: &encoded_target,
                operation: VaultPendingOperationKind::CreateFile,
                base: WriteCondition::Absent,
                base_resource_id: None,
                parent_resource_id: parent_resource_id.as_deref(),
                parent_etag: parent_etag.as_deref(),
                parent_ref: Some(destination_parent_ref),
                destination_target: None,
                destination_parent_resource_id: None,
                destination_parent_etag: None,
                source_size: None,
                source_ciphertext_sha256: None,
                copy_source: None,
                existing_id: Some(id),
                body_len: previous.plaintext_len,
                state: CiphertextWriteState::NeverAttempted,
                receipt_resource_id: None,
                receipt_etag: None,
                receipt_for_revision: None,
            },
            &previous.encoded_target,
            revision,
        )?;
        // Returning the authenticated target and ParentRef lets FUSE update
        // the existing private working-copy manifest without copying or
        // deleting its plaintext recovery bytes.
        metadata.path = to;
        Ok(metadata)
    }

    /// Resolve the current encrypted CreateFile revision by its opaque write
    /// ID. This supports crash repair when the journal retarget CAS completed
    /// but the local working-copy manifest did not. No path lookup is used.
    /// Only NeverAttempted rows receive a plaintext digest; rows that may
    /// have reached the server or have a cancellation receipt remain visible
    /// without authorizing a create-manifest rebind.
    pub fn resolve_pending_create_by_id(
        &self,
        write_id: &str,
    ) -> Result<Option<VaultPendingCreateResolution>, CloudError> {
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "encrypted create recovery requires its scoped journal",
            )
        })?;
        let Some(metadata) = cache.pending_operation_current(&self.sessions, write_id)? else {
            return Ok(None);
        };
        if metadata.id != write_id
            || metadata.operation != VaultPendingOperationKind::CreateFile
            || metadata.base != WriteCondition::Absent
            || metadata.root_integrity_token.is_empty()
        {
            return Err(conflict(
                "current encrypted journal row is not the requested create operation",
            ));
        }
        validate_virtual_path(&metadata.path)?;

        let current_root_token = if self.offline_only {
            cache.cached_root_snapshot(&self.sessions)?.integrity_token
        } else {
            match self.revalidate_root() {
                Ok(state) => state.integrity_token,
                Err(error) if error.kind == ErrorKind::Offline => {
                    cache.cached_root_snapshot(&self.sessions)?.integrity_token
                }
                Err(error) => return Err(error),
            }
        };
        if current_root_token != metadata.root_integrity_token {
            return Err(conflict(
                "encrypted create recovery root token no longer matches",
            ));
        }

        let plaintext_sha256 = if metadata.state == CiphertextWriteState::NeverAttempted {
            let private = tempdir().map_err(io_error)?;
            let body_path = private.path().join("queued-create-recovery.bin");
            let downloaded = cache.download_pending_edit(
                &self.sessions,
                write_id,
                metadata.revision,
                &body_path,
            )?;
            if downloaded != metadata {
                return Err(conflict(
                    "encrypted create changed while its recovery body was verified",
                ));
            }
            let size = File::open(&body_path)
                .and_then(|file| file.metadata())
                .map_err(io_error)?
                .len();
            if size != metadata.plaintext_len {
                return Err(conflict(
                    "encrypted create recovery body length does not match its metadata",
                ));
            }
            let digest = sha256_file(&body_path)?;
            let current = cache
                .pending_operation_current(&self.sessions, write_id)?
                .ok_or_else(|| conflict("encrypted create disappeared during recovery"))?;
            if current != metadata {
                return Err(conflict(
                    "encrypted create revision changed while its recovery body was verified",
                ));
            }
            Some(digest)
        } else {
            None
        };

        Ok(Some(VaultPendingCreateResolution {
            scope: self.scope.clone(),
            metadata,
            plaintext_sha256,
        }))
    }

    /// Resolve an exact persisted batch-WAL identity vector after a crash.
    /// This never searches by path: every current row must be one of the
    /// expected IDs and must agree on either the complete old revision set
    /// or the complete new revision set. Mixed, missing, advanced, or
    /// attempted rows remain unresolved for user attention.
    pub fn resolve_never_attempted_directory_subtree_retarget_by_ids(
        &self,
        root_write_id: &str,
        root_previous_revision: u64,
        expected: &[VaultPendingDirectorySubtreeRetargetExpectedRevision],
    ) -> Result<VaultPendingDirectorySubtreeRetargetResolution, CloudError> {
        const MAX_ITEMS: usize = 64;
        const MAX_BYTES: u64 = 64 * 1024 * 1024;
        if expected.is_empty() || expected.len() > MAX_ITEMS || root_previous_revision == 0 {
            return Err(conflict("queued subtree recovery identity is invalid"));
        }
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "encrypted subtree recovery requires its scoped journal",
            )
        })?;
        let mut expected_by_id = std::collections::BTreeMap::new();
        for row in expected {
            if row.write_id.is_empty()
                || row.write_id.len() > 128
                || !row.write_id.bytes().all(|byte| byte.is_ascii_hexdigit())
                || row.previous_revision == 0
                || row.revision != row.previous_revision.saturating_add(1)
                || expected_by_id.insert(row.write_id.as_str(), row).is_some()
            {
                return Err(conflict("queued subtree recovery identity is invalid"));
            }
        }
        let root_expected = expected_by_id
            .get(root_write_id)
            .ok_or_else(|| conflict("queued subtree recovery root is missing"))?;
        if root_expected.previous_revision != root_previous_revision {
            return Err(conflict("queued subtree recovery root revision changed"));
        }

        let mut current = Vec::with_capacity(expected.len());
        let mut saw_old = false;
        let mut saw_new = false;
        let mut total_bytes = 0u64;
        let mut root_token: Option<String> = None;
        for expected_row in expected {
            let metadata = cache
                .pending_operation_current(&self.sessions, &expected_row.write_id)?
                .ok_or_else(|| conflict("queued subtree recovery row is missing"))?;
            if metadata.id != expected_row.write_id
                || !matches!(
                    metadata.operation,
                    VaultPendingOperationKind::CreateFile
                        | VaultPendingOperationKind::CreateDirectory
                )
                || metadata.state != CiphertextWriteState::NeverAttempted
                || metadata.base != WriteCondition::Absent
                || metadata.receipt_for_revision != 0
                || !metadata.receipt_resource_id.is_empty()
                || !metadata.receipt_etag.is_empty()
                || metadata.root_integrity_token.is_empty()
                || (metadata.operation == VaultPendingOperationKind::CreateDirectory
                    && metadata.plaintext_len != 0)
            {
                return Err(conflict(
                    "queued subtree recovery row is not a never-attempted create",
                ));
            }
            match &root_token {
                Some(token) if token != &metadata.root_integrity_token => {
                    return Err(conflict("queued subtree recovery scope changed"));
                }
                None => root_token = Some(metadata.root_integrity_token.clone()),
                _ => {}
            }
            match metadata.revision {
                revision if revision == expected_row.previous_revision => saw_old = true,
                revision if revision == expected_row.revision => saw_new = true,
                _ => return Err(conflict("queued subtree recovery revision changed")),
            }
            if saw_old && saw_new {
                return Err(conflict("queued subtree recovery is only partly committed"));
            }
            total_bytes = total_bytes
                .checked_add(metadata.plaintext_len)
                .filter(|total| *total <= MAX_BYTES)
                .ok_or_else(|| conflict("queued subtree recovery exceeds its byte limit"))?;
            current.push(metadata);
        }
        if !saw_old && !saw_new {
            return Err(conflict("queued subtree recovery has no current rows"));
        }

        let expected_ids = expected_by_id
            .keys()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        if current
            .iter()
            .find(|metadata| metadata.id == root_write_id)
            .is_none_or(|metadata| metadata.operation != VaultPendingOperationKind::CreateDirectory)
        {
            return Err(conflict(
                "queued subtree recovery root is not a directory create",
            ));
        }
        let current_by_id = current
            .iter()
            .map(|metadata| (metadata.id.as_str(), metadata))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut reachable = std::collections::BTreeSet::new();
        let mut frontier = vec![root_write_id];
        while let Some(parent_id) = frontier.pop() {
            if !reachable.insert(parent_id) {
                continue;
            }
            let parent = current_by_id
                .get(parent_id)
                .ok_or_else(|| conflict("queued subtree recovery parent is missing"))?;
            if parent.operation != VaultPendingOperationKind::CreateDirectory {
                continue;
            }
            let parent_ref = VaultPendingParentRef::PendingCreate {
                write_id: parent.id.clone(),
                revision: parent.revision,
            };
            let expected_children = current
                .iter()
                .filter(|child| child.parent_ref.as_ref() == Some(&parent_ref))
                .map(|child| child.id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            let (children, truncated) = cache.pending_operations_for_parent_ref(
                &self.sessions,
                &parent_ref,
                None,
                MAX_ITEMS,
            )?;
            let actual_children = children
                .iter()
                .map(|child| child.id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            if truncated
                || actual_children != expected_children
                || children.iter().any(|child| {
                    child.parent_ref.as_ref() != Some(&parent_ref)
                        || child.state != CiphertextWriteState::NeverAttempted
                        || child.base != WriteCondition::Absent
                })
            {
                return Err(conflict(
                    "queued subtree recovery no longer matches its dependency closure",
                ));
            }
            frontier.extend(expected_children);
        }
        if reachable != expected_ids {
            return Err(conflict(
                "queued subtree recovery contains unrelated or unreachable rows",
            ));
        }
        for metadata in &current {
            if metadata.operation != VaultPendingOperationKind::CreateDirectory {
                continue;
            }
            if metadata.id != root_write_id
                && !matches!(
                    metadata.parent_ref.as_ref(),
                    Some(VaultPendingParentRef::PendingCreate { write_id, revision })
                        if current_by_id.get(write_id.as_str()).is_some_and(|parent| {
                            parent.operation == VaultPendingOperationKind::CreateDirectory
                                && parent.revision == *revision
                                && metadata
                                    .path
                                    .rsplit_once('/')
                                    .map(|(parent_path, _)| {
                                        if parent_path.is_empty() {
                                            "/"
                                        } else {
                                            parent_path
                                        }
                                    })
                                    == Some(parent.path.as_str())
                        })
                )
            {
                return Err(conflict("queued subtree recovery parent binding changed"));
            }
        }

        let root_token =
            root_token.ok_or_else(|| conflict("queued subtree root token is missing"))?;
        let current_root_token = if self.offline_only {
            cache.cached_root_snapshot(&self.sessions)?.integrity_token
        } else {
            match self.revalidate_root() {
                Ok(state) => state.integrity_token,
                Err(error) if error.kind == ErrorKind::Offline => {
                    cache.cached_root_snapshot(&self.sessions)?.integrity_token
                }
                Err(error) => return Err(error),
            }
        };
        if current_root_token != root_token {
            return Err(conflict("queued subtree recovery root token changed"));
        }

        let state = if saw_old {
            VaultPendingDirectorySubtreeRetargetResolutionState::AllOld
        } else {
            VaultPendingDirectorySubtreeRetargetResolutionState::AllNew
        };
        let mut rows = Vec::with_capacity(current.len());
        for metadata in current {
            let plaintext_sha256 = if metadata.operation == VaultPendingOperationKind::CreateFile {
                let private = tempdir().map_err(io_error)?;
                let body_path = private.path().join("subtree-recovery-body.bin");
                let downloaded = cache.download_pending_edit(
                    &self.sessions,
                    &metadata.id,
                    metadata.revision,
                    &body_path,
                )?;
                if downloaded != metadata
                    || File::open(&body_path)
                        .and_then(|file| file.metadata())
                        .map_err(io_error)?
                        .len()
                        != metadata.plaintext_len
                {
                    return Err(conflict(
                        "queued subtree recovery body changed during verification",
                    ));
                }
                let digest = sha256_file(&body_path)?;
                if cache
                    .pending_operation_current(&self.sessions, &metadata.id)?
                    .as_ref()
                    != Some(&metadata)
                {
                    return Err(conflict(
                        "queued subtree recovery row changed during verification",
                    ));
                }
                digest
            } else {
                Sha256::digest([])
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            };
            rows.push(VaultPendingDirectorySubtreeRetargetCurrentRow {
                write_id: metadata.id,
                revision: metadata.revision,
                operation: metadata.operation,
                path: metadata.path,
                encoded_target: metadata.encoded_target,
                parent_ref: metadata
                    .parent_ref
                    .ok_or_else(|| conflict("queued subtree parent reference is missing"))?,
                plaintext_len: metadata.plaintext_len,
                plaintext_sha256,
                state: metadata.state,
            });
        }
        let root_revision = if state == VaultPendingDirectorySubtreeRetargetResolutionState::AllOld
        {
            root_previous_revision
        } else {
            root_expected.revision
        };
        Ok(VaultPendingDirectorySubtreeRetargetResolution {
            scope: self.scope.clone(),
            state,
            root_write_id: root_write_id.to_owned(),
            root_previous_revision,
            root_revision,
            rows,
        })
    }

    /// Rename an existing regular file within this vault. The complete
    /// precondition set is sealed before any MOVE; transport ambiguity keeps
    /// the operation journal for exact readback or safe conditional retry.
    pub fn rename_file_with_queue(
        &self,
        from: &str,
        to: &str,
        expected_source_id: &str,
        expected_source_etag: &str,
    ) -> Result<VaultRenameOutcome, CloudError> {
        let from = normalize_virtual_path(from)?;
        let to = normalize_virtual_path(to)?;
        validate_virtual_path(&from)?;
        validate_virtual_path(&to)?;
        if from == "/" || to == "/" || from == to {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted file rename requires distinct non-root paths",
            ));
        }
        if expected_source_id.is_empty()
            || expected_source_id.len() > 512
            || expected_source_etag.is_empty()
            || expected_source_etag.len() > 4_096
        {
            return Err(invalid("encrypted rename source condition is invalid"));
        }
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "encrypted rename requires its durable operation journal",
            )
        })?;
        if self.pending_edit_for_path(&from)?.is_some()
            || self.pending_edit_for_path(&to)?.is_some()
            || cache
                .pending_rename_for_destination(&self.sessions, &to)?
                .is_some()
        {
            return Err(conflict(
                "encrypted rename cannot depend on another pending operation",
            ));
        }

        let state = if self.offline_only {
            None
        } else {
            match self.revalidate_root() {
                Ok(state) => Some(state),
                Err(error) if error.kind == ErrorKind::Offline => None,
                Err(error) => return Err(error),
            }
        };
        let root_token = match &state {
            Some(state) => state.integrity_token.clone(),
            None => cache.cached_root_snapshot(&self.sessions)?.integrity_token,
        };
        let source = match &state {
            Some(state) => self.stat_raw(state, &from)?,
            None => cache.stat_with_cached_permissions(&self.sessions, &from)?,
        };
        if source.directory
            || source.id != expected_source_id
            || source.etag != expected_source_etag
            || !source.writable
            || source.size > MAX_VAULT_PLAINTEXT_BYTES
        {
            return Err(conflict("encrypted rename source changed or is not a file"));
        }
        let source_ciphertext_sha256 = if let Some(state) = &state {
            // Hash bytes from a fresh verified remote download. A cached
            // content key may have been reused by a server with a broken or
            // malicious ETag, so it is not sufficient evidence here.
            let private = tempfile::tempdir().map_err(io_error)?;
            let plaintext = private.path().join("rename-source-verify.bin");
            self.download_vault_with_ciphertext_digest(
                state,
                &from,
                Some(&source.etag),
                &plaintext,
            )?
            .1
        } else {
            cache.ciphertext_sha256(&self.sessions, &from, &source.id, &source.etag)?
        };
        let encoded_source = match &state {
            Some(state) => self.encoded_file_target(
                state,
                &from,
                &WriteCondition::Match(expected_source_etag.to_owned()),
            )?,
            None => self.encoded_file_target_from_cache(
                &from,
                &WriteCondition::Match(expected_source_etag.to_owned()),
            )?,
        };
        let encoded_destination = match &state {
            Some(state) => self.encoded_file_target(state, &to, &WriteCondition::Absent)?,
            None => self.encoded_file_target_from_cache(&to, &WriteCondition::Absent)?,
        };
        let (source_parent_resource_id, source_parent_etag) = self.current_parent_binding(&from)?;
        let (destination_parent_resource_id, destination_parent_etag) =
            self.current_parent_binding(&to)?;
        if source_parent_resource_id.is_empty()
            || source_parent_etag.is_empty()
            || destination_parent_resource_id.is_empty()
            || destination_parent_etag.is_empty()
        {
            return Err(invalid("encrypted rename parent is not versioned"));
        }
        let mut metadata = cache.queue_rename(
            &self.sessions,
            VaultPendingRenameRequest {
                integrity_token: &root_token,
                encoded_source: &encoded_source,
                encoded_destination: &encoded_destination,
                source_resource_id: expected_source_id,
                source_etag: expected_source_etag,
                source_parent_resource_id: &source_parent_resource_id,
                source_parent_etag: &source_parent_etag,
                destination_parent_resource_id: &destination_parent_resource_id,
                destination_parent_etag: &destination_parent_etag,
                source_size: source.size,
                source_ciphertext_sha256: &source_ciphertext_sha256,
            },
        )?;

        let Some(_state) = state else {
            return Ok(VaultRenameOutcome::Queued {
                entry: pending_rename_entry(&metadata),
                write_id: metadata.id,
                revision: metadata.revision,
                uncertain: false,
            });
        };
        match self.reconcile_pending_operation(&metadata.id, metadata.revision) {
            Ok(entry) => Ok(VaultRenameOutcome::Committed(entry)),
            Err(error) if matches!(error.kind, ErrorKind::Offline | ErrorKind::Io) => {
                if let Ok(current) =
                    cache.pending_operation(&self.sessions, &metadata.id, metadata.revision)
                {
                    metadata.state = current.state;
                }
                Ok(VaultRenameOutcome::Queued {
                    entry: pending_rename_entry(&metadata),
                    write_id: metadata.id,
                    revision: metadata.revision,
                    uncertain: metadata.state == CiphertextWriteState::Uncertain,
                })
            }
            Err(error) => Err(error),
        }
    }

    /// Delete one existing regular file while retaining its complete content
    /// in the sealed journal until the server confirms removal. Offline and
    /// transport-ambiguous outcomes remain durable tombstones and are never
    /// replayed without rechecking the original source and parent identities.
    pub fn delete_file_with_queue(
        &self,
        path: &str,
        expected_source_id: &str,
        expected_source_etag: &str,
    ) -> Result<VaultDeleteOutcome, CloudError> {
        let path = normalize_virtual_path(path)?;
        validate_virtual_path(&path)?;
        if path == "/" {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cannot delete the encrypted vault root",
            ));
        }
        if expected_source_id.is_empty()
            || expected_source_id.len() > 512
            || expected_source_etag.is_empty()
            || expected_source_etag.len() > 4_096
        {
            return Err(invalid("encrypted delete source condition is invalid"));
        }
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "encrypted delete requires its durable operation journal",
            )
        })?;
        if self.pending_edit_for_path(&path)?.is_some()
            || self.pending_rename_for_destination(&path)?.is_some()
        {
            return Err(conflict(
                "encrypted delete cannot depend on another pending operation",
            ));
        }
        let state = if self.offline_only {
            None
        } else {
            match self.revalidate_root() {
                Ok(state) => Some(state),
                Err(error) if error.kind == ErrorKind::Offline => None,
                Err(error) => return Err(error),
            }
        };
        let root_token = match &state {
            Some(state) => state.integrity_token.clone(),
            None => cache.cached_root_snapshot(&self.sessions)?.integrity_token,
        };
        let source = match &state {
            Some(state) => self.stat_raw(state, &path)?,
            None => cache.stat_with_cached_permissions(&self.sessions, &path)?,
        };
        if source.directory
            || source.id != expected_source_id
            || source.etag != expected_source_etag
            || !source.writable
            || source.size > MAX_VAULT_PLAINTEXT_BYTES
        {
            return Err(conflict("encrypted delete source changed or is not a file"));
        }
        let parent_binding = self.current_parent_binding(&path)?;
        if parent_binding.0.is_empty() || parent_binding.1.is_empty() {
            return Err(invalid("encrypted delete parent is not versioned"));
        }
        let encoded_target = match &state {
            Some(state) => self.encoded_file_target(
                state,
                &path,
                &WriteCondition::Match(expected_source_etag.to_owned()),
            )?,
            None => self.encoded_file_target_from_cache(
                &path,
                &WriteCondition::Match(expected_source_etag.to_owned()),
            )?,
        };

        let private = tempdir().map_err(io_error)?;
        let plaintext_path = private.path().join("delete-recovery-plaintext.bin");
        let source_ciphertext_sha256 = if let Some(state) = &state {
            let (verified_source, digest) = self.download_vault_with_ciphertext_digest(
                state,
                &path,
                Some(expected_source_etag),
                &plaintext_path,
            )?;
            if verified_source.id != source.id || verified_source.size != source.size {
                return Err(conflict("encrypted delete source length changed"));
            }
            digest
        } else {
            let recovered = cache.download(
                &self.sessions,
                &path,
                Some(expected_source_etag),
                &plaintext_path,
            )?;
            if recovered.id != source.id || recovered.size != source.size {
                return Err(conflict("cached encrypted delete source changed"));
            }
            cache.ciphertext_sha256(&self.sessions, &path, &source.id, &source.etag)?
        };
        let mut plaintext = File::open(&plaintext_path).map_err(io_error)?;
        let mut metadata = cache.queue_delete(
            &self.sessions,
            &mut plaintext,
            VaultPendingDeleteRequest {
                integrity_token: &root_token,
                encoded_target: &encoded_target,
                source_resource_id: expected_source_id,
                source_etag: expected_source_etag,
                parent_resource_id: &parent_binding.0,
                parent_etag: &parent_binding.1,
                source_size: source.size,
                source_ciphertext_sha256: &source_ciphertext_sha256,
                body_len: source.size,
            },
        )?;
        let Some(_state) = state else {
            return Ok(VaultDeleteOutcome::Queued {
                write_id: metadata.id,
                revision: metadata.revision,
                uncertain: false,
            });
        };
        match self.reconcile_pending_delete(&metadata.id, metadata.revision) {
            Ok(()) => Ok(VaultDeleteOutcome::Committed),
            Err(error) if matches!(error.kind, ErrorKind::Offline | ErrorKind::Io) => {
                if let Ok(current) =
                    cache.pending_operation(&self.sessions, &metadata.id, metadata.revision)
                {
                    metadata.state = current.state;
                }
                Ok(VaultDeleteOutcome::Queued {
                    write_id: metadata.id,
                    revision: metadata.revision,
                    uncertain: metadata.state == CiphertextWriteState::Uncertain,
                })
            }
            Err(error) => Err(error),
        }
    }

    /// As with `upload_prepared_reader`, but converts only a transport outage
    /// into a durable encrypted local journal revision. Conditional conflicts,
    /// permission failures, and other server responses are returned unchanged.
    pub fn upload_prepared_reader_with_queue<R: Read + Seek>(
        &self,
        encoded_target: &str,
        source: &mut R,
        plaintext_len: u64,
        condition: WriteCondition,
        existing_write_id: Option<&str>,
    ) -> Result<VaultUploadOutcome, CloudError> {
        if plaintext_len > MAX_VAULT_PLAINTEXT_BYTES {
            return Err(invalid("vault upload source exceeds its size limit"));
        }
        let decoded = self
            .sessions
            .decrypt_path(&self.scope, encoded_target)
            .map_err(vault_error)?;
        if decoded.is_root() {
            return Err(invalid("vault upload target cannot be the root"));
        }
        let path = format!("/{}", decoded.into_components().join("/"));
        validate_virtual_path(&path)?;
        if self.pending_rename_for_source(&path)?.is_some() {
            return Err(conflict("vault file has a pending encrypted rename"));
        }
        let (base_condition, pending) = self.resolve_pending_condition(&path, &condition)?;
        source.seek(SeekFrom::Start(0)).map_err(io_error)?;

        if self.offline_only {
            let base = self.cached_base_entry(&path, &base_condition)?;
            let root = self
                .offline_cache
                .as_ref()
                .ok_or_else(|| {
                    CloudError::new(ErrorKind::Offline, "encrypted edit cache is unavailable")
                })?
                .cached_root_snapshot(&self.sessions)?;
            return self.queue_offline_edit(
                encoded_target,
                &root.integrity_token,
                source,
                plaintext_len,
                OfflineEditContext {
                    base,
                    condition: base_condition,
                    existing_id: pending
                        .as_ref()
                        .map(|edit| edit.id.clone())
                        .or_else(|| existing_write_id.map(str::to_owned)),
                    uncertain: false,
                },
            );
        }

        let state = match self.revalidate_root() {
            Ok(state) => state,
            Err(error) if error.kind == ErrorKind::Offline => {
                let base = self.cached_base_entry(&path, &base_condition)?;
                let root = self
                    .offline_cache
                    .as_ref()
                    .ok_or_else(|| error.clone())?
                    .cached_root_snapshot(&self.sessions)?;
                return self.queue_offline_edit(
                    encoded_target,
                    &root.integrity_token,
                    source,
                    plaintext_len,
                    OfflineEditContext {
                        base,
                        condition: base_condition,
                        existing_id: pending
                            .as_ref()
                            .map(|edit| edit.id.clone())
                            .or_else(|| existing_write_id.map(str::to_owned)),
                        uncertain: false,
                    },
                );
            }
            Err(error) => return Err(error),
        };
        let base = self.stat_raw(&state, &path)?;
        if base.directory || base.etag.is_empty() || base.id.is_empty() {
            return Err(invalid("vault edit target is not a regular versioned file"));
        }
        if let WriteCondition::Match(expected) = &base_condition {
            if &base.etag != expected {
                return Err(conflict("vault file changed before its edit was uploaded"));
            }
        } else {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "offline edits require an existing vault file",
            ));
        }
        match self.put_vault_reader(
            &state,
            &path,
            source,
            plaintext_len,
            base_condition.clone(),
            VaultPutExpectation::target(encoded_target),
        ) {
            Ok(entry) => {
                if let Some(edit) = pending.as_ref() {
                    let confirmed =
                        self.verify_uploaded_reader(&state, &path, &entry, source, plaintext_len);
                    if matches!(confirmed, Ok(true)) {
                        if let Some(cache) = &self.offline_cache {
                            cache.retire_pending_edit(&edit.id, edit.revision)?;
                        }
                        return Ok(VaultUploadOutcome::Committed(entry));
                    }
                    source.seek(SeekFrom::Start(0)).map_err(io_error)?;
                    return self.queue_offline_edit(
                        encoded_target,
                        &state.integrity_token,
                        source,
                        plaintext_len,
                        OfflineEditContext {
                            base,
                            condition: base_condition,
                            existing_id: Some(edit.id.clone()),
                            uncertain: true,
                        },
                    );
                }
                Ok(VaultUploadOutcome::Committed(entry))
            }
            Err(error) if error.kind == ErrorKind::Offline => {
                source.seek(SeekFrom::Start(0)).map_err(io_error)?;
                self.queue_offline_edit(
                    encoded_target,
                    &state.integrity_token,
                    source,
                    plaintext_len,
                    OfflineEditContext {
                        base,
                        condition: base_condition,
                        existing_id: pending
                            .as_ref()
                            .map(|edit| edit.id.clone())
                            .or_else(|| existing_write_id.map(str::to_owned)),
                        uncertain: true,
                    },
                )
            }
            Err(error) => Err(error),
        }
    }

    /// Explicitly reconcile one durable encrypted edit against the currently
    /// authorized remote root. No scheduler should call this implicitly: the
    /// operation rechecks the root marker, exact resource ID, and original
    /// ETag, conditionally uploads, then downloads and byte-compares the
    /// resulting remote version before retiring the journal record.
    pub fn reconcile_pending_edit(
        &self,
        id: &str,
        revision: u64,
    ) -> Result<RemoteEntry, CloudError> {
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Offline, "encrypted edit cache is unavailable")
        })?;
        let edit = cache.pending_edit(&self.sessions, id, revision)?;
        if edit.state == CiphertextWriteState::Conflict {
            return Err(conflict("encrypted edit requires conflict resolution"));
        }
        let state = self.revalidate_root()?;
        let current = self.stat_raw(&state, &edit.path)?;
        if current.directory || current.id != edit.base_resource_id {
            cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
            return Err(conflict("encrypted edit target identity changed"));
        }

        if current.etag != edit.base_etag {
            match self.pending_matches_remote(&state, &edit, &current) {
                Ok(true) => {
                    cache.retire_pending_edit(id, revision)?;
                    return Ok(current);
                }
                Ok(false) => {
                    cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
                    return Err(conflict("encrypted edit base version changed remotely"));
                }
                Err(error) => {
                    cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                    return Err(error);
                }
            }
        }

        let plaintext_dir = tempdir().map_err(io_error)?;
        let plaintext_path = plaintext_dir.path().join("pending-plaintext.bin");
        cache.download_pending_edit(&self.sessions, id, revision, &plaintext_path)?;
        let mut plaintext = File::open(&plaintext_path).map_err(io_error)?;
        let put = self.put_vault_reader(
            &state,
            &edit.path,
            &mut plaintext,
            edit.plaintext_len,
            WriteCondition::Match(edit.base_etag.clone()),
            VaultPutExpectation::target(&edit.encoded_target),
        );
        let uploaded = match put {
            Ok(entry) => entry,
            Err(error) => {
                match error.kind {
                    ErrorKind::Conflict | ErrorKind::Forbidden => {
                        cache.set_pending_edit_state(
                            id,
                            revision,
                            CiphertextWriteState::Conflict,
                        )?;
                    }
                    ErrorKind::Offline | ErrorKind::Io => {
                        cache.set_pending_edit_state(
                            id,
                            revision,
                            CiphertextWriteState::Uncertain,
                        )?;
                    }
                    _ => {}
                }
                return Err(error);
            }
        };

        let fresh_state = match self.revalidate_root() {
            Ok(fresh) => fresh,
            Err(error) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(error);
            }
        };
        let readback = match self.stat_raw(&fresh_state, &edit.path) {
            Ok(entry) => entry,
            Err(error) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(error);
            }
        };
        if readback.id != edit.base_resource_id
            || readback.etag != uploaded.etag
            || readback.size != edit.plaintext_len
        {
            cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
            return Err(conflict("encrypted edit readback did not match the upload"));
        }
        match self.pending_matches_remote(&fresh_state, &edit, &readback) {
            Ok(true) => {}
            Ok(false) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(conflict(
                    "encrypted edit content did not match remote readback",
                ));
            }
            Err(error) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(error);
            }
        }
        cache.retire_pending_edit(id, revision)?;
        Ok(readback)
    }

    /// Explicitly reconcile a durable encrypted create or overwrite. A create
    /// remains conditional on its original Absent state. If any remote object
    /// now occupies the destination, it becomes a conflict; byte equality
    /// cannot prove that an ambiguous PUT created that object.
    pub fn reconcile_pending_operation(
        &self,
        id: &str,
        revision: u64,
    ) -> Result<RemoteEntry, CloudError> {
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Offline, "encrypted edit cache is unavailable")
        })?;
        let operation = cache.pending_operation(&self.sessions, id, revision)?;
        if operation.state == CiphertextWriteState::CancelledReceipt {
            return Err(conflict(
                "encrypted create cancellation is awaiting local recovery acknowledgement",
            ));
        }
        if operation.operation == VaultPendingOperationKind::Overwrite {
            return self.reconcile_pending_edit(id, revision);
        }
        if operation.operation == VaultPendingOperationKind::RenameFile {
            return self.reconcile_pending_rename(id, revision, operation);
        }
        if operation.operation == VaultPendingOperationKind::DeleteFile {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted delete reconciliation has no file result",
            ));
        }
        if operation.operation == VaultPendingOperationKind::CopyFile {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "cross-vault copy requires copy-specific source and destination verification",
            ));
        }
        if operation.operation == VaultPendingOperationKind::CreateDirectory {
            return self.reconcile_pending_directory_create(id, revision);
        }
        self.reconcile_pending_file_create(id, revision, None)
    }

    /// Retry a CreateFile left in an interrupted dispatch state. This entry
    /// point is intentionally separate from batch reconciliation and must be
    /// called only after an explicit user action. The state token is a CAS
    /// fence; the journal body is retained until an exact remote readback has
    /// been verified.
    pub fn retry_interrupted_file_create(
        &self,
        id: &str,
        revision: u64,
        expected_retry_state: CiphertextWriteState,
        expected_retry_generation: u64,
    ) -> Result<RemoteEntry, CloudError> {
        if !matches!(
            expected_retry_state,
            CiphertextWriteState::Attempting
                | CiphertextWriteState::RecoveryAttempting
                | CiphertextWriteState::RecoveryRetrying
        ) {
            return Err(conflict("encrypted create retry state is not eligible"));
        }
        self.reconcile_pending_file_create(
            id,
            revision,
            Some((expected_retry_state, expected_retry_generation)),
        )
    }

    fn reconcile_pending_file_create(
        &self,
        id: &str,
        revision: u64,
        explicit_retry: Option<(CiphertextWriteState, u64)>,
    ) -> Result<RemoteEntry, CloudError> {
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Offline, "encrypted edit cache is unavailable")
        })?;
        let operation = cache.pending_operation(&self.sessions, id, revision)?;
        if operation.operation != VaultPendingOperationKind::CreateFile {
            return Err(conflict("encrypted operation is not a file create"));
        }
        match explicit_retry {
            Some((expected, generation))
                if operation.state != expected || operation.retry_generation != generation =>
            {
                return Err(conflict("interrupted encrypted create state changed"));
            }
            Some(_) => {}
            None if matches!(
                operation.state,
                CiphertextWriteState::Conflict
                    | CiphertextWriteState::Building
                    | CiphertextWriteState::Attempting
                    | CiphertextWriteState::RecoveryAttempting
                    | CiphertextWriteState::RecoveryRetrying
            ) =>
            {
                return Err(conflict(
                    "encrypted create requires conflict resolution or a flush",
                ));
            }
            None => {}
        }
        let set_state = |state| -> Result<(), CloudError> {
            if let Some((expected_state, generation)) = explicit_retry {
                cache.set_interrupted_file_create_retry_state(
                    &self.sessions,
                    id,
                    revision,
                    generation,
                    expected_state,
                    state,
                )
            } else {
                cache.set_pending_edit_state(id, revision, state)
            }
        };
        if operation.base != WriteCondition::Absent || !operation.base_resource_id.is_empty() {
            set_state(CiphertextWriteState::Conflict)?;
            return Err(conflict(
                "encrypted create lost its original absence condition",
            ));
        }
        let state = match self.revalidate_root() {
            Ok(state) => state,
            Err(error) if error.kind == ErrorKind::Conflict => {
                set_state(CiphertextWriteState::Conflict)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if state.integrity_token != operation.root_integrity_token {
            set_state(CiphertextWriteState::Conflict)?;
            return Err(conflict("encrypted create root token changed"));
        }
        let (parent_id, parent_etag) = match self.resolve_operation_parent(&state, &operation) {
            Ok(parent) => parent,
            Err(error) if error.kind == ErrorKind::NotFound => {
                set_state(CiphertextWriteState::Conflict)?;
                return Err(conflict("encrypted create parent no longer exists"));
            }
            Err(error) if error.kind == ErrorKind::Conflict => {
                set_state(CiphertextWriteState::Conflict)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if parent_id.is_empty() {
            set_state(CiphertextWriteState::Conflict)?;
            return Err(conflict("encrypted create parent identity changed"));
        }
        match self.stat_raw(&state, &operation.path) {
            Ok(_) => {
                set_state(CiphertextWriteState::Conflict)?;
                return Err(conflict("encrypted create destination is no longer absent"));
            }
            Err(error) if error.kind == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let plaintext_dir = tempdir().map_err(io_error)?;
        let plaintext_path = plaintext_dir.path().join("pending-create-plaintext.bin");
        cache.download_pending_edit(&self.sessions, id, revision, &plaintext_path)?;
        let mut plaintext = File::open(&plaintext_path).map_err(io_error)?;
        let claimed_retry = if let Some((expected, generation)) = explicit_retry {
            let next_generation = cache.claim_interrupted_file_create_retry(
                &self.sessions,
                id,
                revision,
                expected,
                generation,
            )?;
            let next_state = match expected {
                CiphertextWriteState::Attempting | CiphertextWriteState::RecoveryRetrying => {
                    CiphertextWriteState::RecoveryAttempting
                }
                CiphertextWriteState::RecoveryAttempting => CiphertextWriteState::RecoveryRetrying,
                _ => return Err(conflict("encrypted create retry state is not eligible")),
            };
            Some((next_state, next_generation))
        } else {
            cache.claim_file_create_attempt(&self.sessions, id, revision)?;
            None
        };
        let set_claimed_state = |state| -> Result<(), CloudError> {
            if let Some((expected_state, generation)) = claimed_retry {
                cache.set_interrupted_file_create_retry_state(
                    &self.sessions,
                    id,
                    revision,
                    generation,
                    expected_state,
                    state,
                )
            } else {
                cache.set_pending_edit_state(id, revision, state)
            }
        };
        let put = self.put_vault_reader(
            &state,
            &operation.path,
            &mut plaintext,
            operation.plaintext_len,
            WriteCondition::Absent,
            VaultPutExpectation {
                encoded_target: Some(&operation.encoded_target),
                parent_binding: Some((&parent_id, &parent_etag)),
                expected_token_generation: None,
                external_token_generation: None,
                caller_cancelled: None,
            },
        );
        let uploaded = match put {
            Ok(entry) => entry,
            Err(error) => {
                match error.kind {
                    ErrorKind::Conflict | ErrorKind::Forbidden => {
                        set_claimed_state(CiphertextWriteState::Conflict)?;
                    }
                    ErrorKind::Offline | ErrorKind::Io if claimed_retry.is_none() => {
                        set_claimed_state(CiphertextWriteState::Uncertain)?;
                    }
                    _ => {}
                }
                return Err(error);
            }
        };
        let fresh_state = match self.revalidate_root() {
            Ok(fresh) => fresh,
            Err(error) => {
                if claimed_retry.is_none() {
                    set_claimed_state(CiphertextWriteState::Uncertain)?;
                }
                return Err(error);
            }
        };
        let confirmed = self.verify_uploaded_reader(
            &fresh_state,
            &operation.path,
            &uploaded,
            &mut plaintext,
            operation.plaintext_len,
        );
        match confirmed {
            Ok(true) => {
                if let Some((state, generation)) = claimed_retry {
                    cache.retire_interrupted_file_create_retry(
                        &self.sessions,
                        id,
                        revision,
                        generation,
                        state,
                    )?;
                } else {
                    cache.retire_pending_edit(id, revision)?;
                }
                self.retire_parent_receipt(&operation)?;
                Ok(uploaded)
            }
            Ok(false) => {
                if claimed_retry.is_none() {
                    set_claimed_state(CiphertextWriteState::Uncertain)?;
                }
                Err(conflict(
                    "encrypted create readback did not match the uploaded bytes",
                ))
            }
            Err(error) => {
                if claimed_retry.is_none() {
                    set_claimed_state(CiphertextWriteState::Uncertain)?;
                }
                Err(error)
            }
        }
    }

    /// Retry a queued/uncertain directory creation only when the original root
    /// token and parent identity/version still match and the destination is
    /// still absent. An already-present directory is never assumed to be ours.
    pub fn reconcile_pending_directory_create(
        &self,
        id: &str,
        revision: u64,
    ) -> Result<RemoteEntry, CloudError> {
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Offline,
                "encrypted directory journal is unavailable",
            )
        })?;
        let mut operation = cache.pending_operation(&self.sessions, id, revision)?;
        if operation.operation != VaultPendingOperationKind::CreateDirectory
            || operation.base != WriteCondition::Absent
            || operation.plaintext_len != 0
            || matches!(
                operation.state,
                CiphertextWriteState::Building
                    | CiphertextWriteState::CommittedReceipt
                    | CiphertextWriteState::Attempting
            )
        {
            return Err(conflict("encrypted directory create is not retryable"));
        }
        if operation.state == CiphertextWriteState::Conflict {
            return Err(conflict("encrypted directory create is in conflict"));
        }
        let state = match self.revalidate_root() {
            Ok(state) => state,
            Err(error) if error.kind == ErrorKind::Conflict => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if state.integrity_token != operation.root_integrity_token {
            cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
            return Err(conflict("encrypted directory create root token changed"));
        }
        let (parent_id, parent_etag) = match self.resolve_operation_parent(&state, &operation) {
            Ok(parent) => parent,
            Err(error) if error.kind == ErrorKind::Offline => return Err(error),
            Err(error) => {
                if matches!(error.kind, ErrorKind::Conflict | ErrorKind::NotFound) {
                    cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
                }
                return Err(error);
            }
        };
        if matches!(
            operation.parent_ref,
            Some(VaultPendingParentRef::Stable { .. })
        ) && !operation.parent_etag.is_empty()
            && operation.parent_etag != parent_etag
        {
            cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
            return Err(conflict("encrypted directory parent version changed"));
        }
        match self.stat_raw(&state, &operation.path) {
            Ok(_) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
                return Err(conflict(
                    "encrypted directory destination exists without an owned readback",
                ));
            }
            Err(error) if error.kind == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        // The transaction races with local cancellation. Exactly one wins:
        // either the NeverAttempted row is removed, or this durable claim
        // makes it non-cancelable before MKCOL can be dispatched.
        cache.claim_directory_create_attempt(&self.sessions, id, revision)?;
        operation.state = CiphertextWriteState::Attempting;
        match self.perform_directory_mkcol(
            &state,
            &operation.path,
            &operation.encoded_target,
            &operation.root_integrity_token,
            &parent_id,
            &parent_etag,
        ) {
            Ok(entry) => {
                if entry.path != operation.path || !entry.directory || entry.id.is_empty() {
                    cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                    return Err(conflict("encrypted directory readback identity changed"));
                }
                let receipt = cache.commit_directory_receipt(
                    &self.sessions,
                    &operation,
                    &entry,
                    &VaultPendingParentRef::Stable {
                        resource_id: parent_id.clone(),
                    },
                    &parent_id,
                    &parent_etag,
                )?;
                match cache.retire_directory_receipt_if_unreferenced(
                    &self.sessions,
                    id,
                    receipt.receipt_for_revision,
                ) {
                    Ok(()) => {}
                    Err(error) if error.kind == ErrorKind::Conflict => {}
                    Err(error) => return Err(error),
                }
                self.retire_parent_receipt(&operation)?;
                Ok(entry)
            }
            Err(error) => {
                let next = if matches!(error.kind, ErrorKind::Conflict | ErrorKind::Forbidden) {
                    CiphertextWriteState::Conflict
                } else {
                    CiphertextWriteState::Uncertain
                };
                cache.set_pending_edit_state(id, revision, next)?;
                Err(error)
            }
        }
    }

    fn perform_directory_mkcol(
        &self,
        prior_state: &RootState,
        path: &str,
        encoded_target: &str,
        integrity_token: &str,
        expected_parent_id: &str,
        expected_parent_etag: &str,
    ) -> Result<RemoteEntry, CloudError> {
        let state = self.revalidate_root()?;
        if state.integrity_token != integrity_token
            || state.space.id != prior_state.space.id
            || state.space_dav_root != prior_state.space_dav_root
        {
            return Err(conflict("encrypted directory root changed before MKCOL"));
        }
        let (_, parent_listing) = self.parent_listing(&state, path)?;
        let parent = parent_listing.root;
        if !parent.directory
            || parent.id != expected_parent_id
            || parent.strong_etag.as_deref() != Some(expected_parent_etag)
        {
            return Err(conflict("encrypted directory parent changed before MKCOL"));
        }
        match self.stat_raw(&state, path) {
            Ok(_) => return Err(conflict("encrypted directory destination already exists")),
            Err(error) if error.kind == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let physical = format!(
            "{}/{}",
            self.root_path.trim_end_matches('/'),
            encoded_target
        );
        let url = self.url_for_physical(&state, &physical)?;
        if !self
            .sessions
            .is_unlocked(&self.scope)
            .map_err(vault_error)?
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault session was locked before directory creation",
            ));
        }
        if let Some(cache) = &self.offline_cache {
            cache.invalidate_before_remote_mutation()?;
        }
        let (request, token) = self
            .client
            .request(Method::from_bytes(b"MKCOL").expect("static method"), &url)?;
        let parent_url = self.target_url(&state, &logical_parent(path))?;
        let parent_condition = format!("<{parent_url}> [{expected_parent_etag}]");
        let request = request
            .header(IF_NONE_MATCH, "*")
            .header("If", parent_condition);
        checked(
            request.send().map_err(network)?,
            &[StatusCode::CREATED],
            &token,
        )?;
        let fresh_state = self.revalidate_root()?;
        if fresh_state.integrity_token != integrity_token {
            return Err(conflict("encrypted directory root changed after MKCOL"));
        }
        let created = self.stat_raw(&fresh_state, path)?;
        if !created.directory || created.id.is_empty() || created.etag.is_empty() {
            return Err(conflict(
                "encrypted MKCOL readback did not identify a directory",
            ));
        }
        let (_, fresh_parent_listing) = self.parent_listing(&fresh_state, path)?;
        if !fresh_parent_listing.root.directory
            || fresh_parent_listing.root.id != expected_parent_id
        {
            return Err(conflict("encrypted directory parent changed after MKCOL"));
        }
        Ok(created)
    }

    /// Reconcile one encrypted file deletion. DELETE is conditional on the
    /// captured source ETag; the source ID and parent ID/ETag are rechecked
    /// before the request. A 404 retires without another request, whereas a
    /// replacement remains a conflict and retains its recovery body.
    pub fn reconcile_pending_delete(&self, id: &str, revision: u64) -> Result<(), CloudError> {
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Offline, "encrypted delete cache is unavailable")
        })?;
        let operation = cache.pending_operation(&self.sessions, id, revision)?;
        if operation.operation != VaultPendingOperationKind::DeleteFile
            || operation.state == CiphertextWriteState::Building
        {
            return Err(conflict("encrypted delete is not retryable"));
        }
        if operation.state == CiphertextWriteState::Conflict {
            return Err(conflict("encrypted delete requires conflict resolution"));
        }
        let state = match self.revalidate_root() {
            Ok(state) => state,
            Err(error) if error.kind == ErrorKind::Conflict => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
                return Err(error);
            }
            Err(error) if error.kind == ErrorKind::Offline => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if state.integrity_token != operation.root_integrity_token {
            cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
            return Err(conflict("encrypted delete root token changed"));
        }
        match self.stat_raw(&state, &operation.path) {
            Err(error) if error.kind == ErrorKind::NotFound => {
                cache.retire_pending_edit(id, revision)?;
                return Ok(());
            }
            Err(error) if error.kind == ErrorKind::Offline => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(error);
            }
            Err(error) => return Err(error),
            Ok(source) => {
                if source.directory
                    || source.id != operation.base_resource_id
                    || source.etag != operation.base_etag
                    || source.size != operation.source_size
                {
                    cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
                    return Err(conflict("encrypted delete source identity changed"));
                }
                if !source.writable || !state.space.writable {
                    cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
                    return Err(CloudError::new(
                        ErrorKind::Forbidden,
                        "encrypted delete source is no longer writable",
                    ));
                }
            }
        }
        let parent = match self.current_parent_binding(&operation.path) {
            Ok(parent) => parent,
            Err(error) if error.kind == ErrorKind::Offline => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(error);
            }
            Err(error) if matches!(error.kind, ErrorKind::Conflict | ErrorKind::NotFound) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if parent.0 != operation.parent_resource_id || parent.1 != operation.parent_etag {
            cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
            return Err(conflict("encrypted delete parent identity changed"));
        }
        let source = self.stat_raw(&state, &operation.path)?;
        self.verify_item_parent_writable(&state, &operation.path, &source.id)?;
        let url = self.target_url(&state, &operation.path)?;
        if !self
            .sessions
            .is_unlocked(&self.scope)
            .map_err(vault_error)?
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault session was locked before delete",
            ));
        }
        cache.invalidate_before_remote_mutation()?;
        let current_state = match self.revalidate_root() {
            Ok(state) => state,
            Err(error) if error.kind == ErrorKind::Offline => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if current_state.integrity_token != operation.root_integrity_token {
            cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
            return Err(conflict(
                "encrypted delete root token changed before request",
            ));
        }
        // Cache invalidation can take time and another client may replace the
        // file or its parent during that interval. Recheck both bindings as
        // close as possible to the conditional DELETE; the source ETag remains
        // the server-side precondition for the actual mutation.
        let current_source = match self.stat_raw(&current_state, &operation.path) {
            Ok(source) => source,
            Err(error) if error.kind == ErrorKind::NotFound => {
                cache.retire_pending_edit(id, revision)?;
                return Ok(());
            }
            Err(error) if error.kind == ErrorKind::Offline => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let current_parent = match self.current_parent_binding(&operation.path) {
            Ok(parent) => parent,
            Err(error) if error.kind == ErrorKind::Offline => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(error);
            }
            Err(error) if matches!(error.kind, ErrorKind::Conflict | ErrorKind::NotFound) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if current_source.directory
            || current_source.id != operation.base_resource_id
            || current_source.etag != operation.base_etag
            || current_source.size != operation.source_size
            || current_parent.0 != operation.parent_resource_id
            || current_parent.1 != operation.parent_etag
        {
            cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
            return Err(conflict("encrypted delete target changed before request"));
        }
        let (request, token) = self.client.request(Method::DELETE, &url)?;
        let response = match request.header(IF_MATCH, &operation.base_etag).send() {
            Ok(response) => response,
            Err(error) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(network(error));
            }
        };
        if let Err(error) = checked(response, &[StatusCode::NO_CONTENT, StatusCode::OK], &token) {
            if error.kind == ErrorKind::Conflict {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
            } else if matches!(error.kind, ErrorKind::Offline | ErrorKind::Io) {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
            }
            return Err(error);
        }
        let fresh_state = match self.revalidate_root() {
            Ok(state) => state,
            Err(error) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(error);
            }
        };
        match self.stat_raw(&fresh_state, &operation.path) {
            Err(error) if error.kind == ErrorKind::NotFound => {
                cache.retire_pending_edit(id, revision)?;
                Ok(())
            }
            Ok(current) if current.id == operation.base_resource_id => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                Err(CloudError::new(
                    ErrorKind::Offline,
                    "encrypted delete was accepted but source readback is unresolved",
                ))
            }
            Ok(_) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
                Err(conflict(
                    "encrypted delete path now contains a replacement resource",
                ))
            }
            Err(error) if error.kind == ErrorKind::Offline => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    /// Reconcile one encrypted file rename against its complete captured
    /// source/destination and parent identities. A response lost after MOVE
    /// is resolved by exact source/destination readback; otherwise a retry is
    /// allowed only while the original source and absent destination remain.
    fn reconcile_pending_rename(
        &self,
        id: &str,
        revision: u64,
        operation: VaultPendingEditMetadata,
    ) -> Result<RemoteEntry, CloudError> {
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Offline, "encrypted rename cache is unavailable")
        })?;
        if operation.operation != VaultPendingOperationKind::RenameFile
            || operation.state == CiphertextWriteState::Conflict
            || operation.state == CiphertextWriteState::Building
        {
            return Err(conflict("encrypted rename is not retryable"));
        }
        let state = match self.revalidate_root() {
            Ok(state) => state,
            Err(error) if error.kind == ErrorKind::Conflict => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if state.integrity_token != operation.root_integrity_token {
            cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
            return Err(conflict("encrypted rename root token changed"));
        }

        // A completed MOVE is recognized before checking the old source-parent
        // ETag, which normally changes as a consequence of the move itself.
        let destination_readback = self.stat_raw(&state, &operation.destination_path);
        if let Ok(entry) = destination_readback.as_ref() {
            let source_missing = matches!(
                self.stat_raw(&state, &operation.path),
                Err(ref error) if error.kind == ErrorKind::NotFound
            );
            let destination_parent = self.current_parent_binding(&operation.destination_path);
            if source_missing
                && !entry.directory
                && entry.id == operation.base_resource_id
                && entry.size == operation.source_size
                && destination_parent.as_ref().is_ok_and(|(parent_id, _)| {
                    parent_id == &operation.destination_parent_resource_id
                })
            {
                match self.rename_content_matches(&state, &operation, entry) {
                    Ok(true) => {
                        cache.retire_pending_edit(id, revision)?;
                        return Ok(entry.clone());
                    }
                    Ok(false) => {
                        cache.set_pending_edit_state(
                            id,
                            revision,
                            CiphertextWriteState::Conflict,
                        )?;
                        return Err(conflict(
                            "encrypted rename destination content did not match its source",
                        ));
                    }
                    Err(error) => {
                        cache.set_pending_edit_state(
                            id,
                            revision,
                            CiphertextWriteState::Uncertain,
                        )?;
                        return Err(error);
                    }
                }
            }
        }

        let source = match self.stat_raw(&state, &operation.path) {
            Ok(source) => source,
            Err(error) if error.kind == ErrorKind::Offline => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(error);
            }
            Err(error) if error.kind == ErrorKind::NotFound => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
                return Err(conflict("encrypted rename source no longer exists"));
            }
            Err(error) => return Err(error),
        };
        if source.directory
            || source.id != operation.base_resource_id
            || source.etag != operation.base_etag
            || source.size != operation.source_size
        {
            cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
            return Err(conflict("encrypted rename source identity changed"));
        }
        let source_parent = self.current_parent_binding(&operation.path)?;
        let destination_parent = self.current_parent_binding(&operation.destination_path)?;
        if source_parent.0 != operation.parent_resource_id
            || source_parent.1 != operation.parent_etag
            || destination_parent.0 != operation.destination_parent_resource_id
            || destination_parent.1 != operation.destination_parent_etag
        {
            cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
            return Err(conflict("encrypted rename parent identity changed"));
        }
        match self.stat_raw(&state, &operation.destination_path) {
            Ok(_) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
                return Err(conflict("encrypted rename destination is no longer absent"));
            }
            Err(error) if error.kind == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.perform_pending_rename(&state, id, revision, &operation)
    }

    fn perform_pending_rename(
        &self,
        state: &RootState,
        id: &str,
        revision: u64,
        operation: &VaultPendingEditMetadata,
    ) -> Result<RemoteEntry, CloudError> {
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Offline, "encrypted rename cache is unavailable")
        })?;
        let source = self.target_url(state, &operation.path)?;
        let destination = self.target_url(state, &operation.destination_path)?;
        cache.invalidate_before_remote_mutation()?;
        let move_method = Method::from_bytes(b"MOVE").expect("static HTTP method");
        let (request, token) = self.client.request(move_method, &source)?;
        let response = match request
            .header(IF_MATCH, &operation.base_etag)
            .header("Destination", destination.as_str())
            .header("Overwrite", "F")
            .send()
        {
            Ok(response) => response,
            Err(error) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(network(error));
            }
        };
        if let Err(error) = checked(
            response,
            &[StatusCode::CREATED, StatusCode::NO_CONTENT],
            &token,
        ) {
            match error.kind {
                ErrorKind::Conflict | ErrorKind::Forbidden => {
                    cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
                }
                ErrorKind::Offline | ErrorKind::Io => {
                    cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                }
                _ => {}
            }
            return Err(error);
        }
        let fresh_state = match self.revalidate_root() {
            Ok(state) if state.integrity_token == operation.root_integrity_token => state,
            Ok(_) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(conflict("vault root changed after encrypted rename"));
            }
            Err(error) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(error);
            }
        };
        let moved = match self.stat_raw(&fresh_state, &operation.destination_path) {
            Ok(entry)
                if entry.id == operation.base_resource_id
                    && entry.size == operation.source_size
                    && !entry.directory =>
            {
                entry
            }
            Ok(_) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(conflict("encrypted rename readback identity did not match"));
            }
            Err(error) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(error);
            }
        };
        match self.stat_raw(&fresh_state, &operation.path) {
            Err(error) if error.kind == ErrorKind::NotFound => {}
            Ok(_) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(conflict("encrypted rename source remained after MOVE"));
            }
            Err(error) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(error);
            }
        }
        let parent = self.current_parent_binding(&operation.destination_path)?;
        if parent.0 != operation.destination_parent_resource_id {
            cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
            return Err(conflict("encrypted rename destination parent changed"));
        }
        match self.rename_content_matches(&fresh_state, operation, &moved) {
            Ok(true) => {}
            Ok(false) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Conflict)?;
                return Err(conflict(
                    "encrypted rename destination content did not match its source",
                ));
            }
            Err(error) => {
                cache.set_pending_edit_state(id, revision, CiphertextWriteState::Uncertain)?;
                return Err(error);
            }
        }
        cache.retire_pending_edit(id, revision)?;
        Ok(moved)
    }

    fn rename_content_matches(
        &self,
        state: &RootState,
        operation: &VaultPendingEditMetadata,
        entry: &RemoteEntry,
    ) -> Result<bool, CloudError> {
        if entry.directory
            || entry.id != operation.base_resource_id
            || entry.size != operation.source_size
        {
            return Ok(false);
        }
        let private = tempfile::tempdir().map_err(io_error)?;
        let plaintext = private.path().join("rename-readback.bin");
        let (downloaded, digest) = self.download_vault_with_ciphertext_digest(
            state,
            &operation.destination_path,
            Some(&entry.etag),
            &plaintext,
        )?;
        Ok(!downloaded.directory
            && downloaded.id == operation.base_resource_id
            && downloaded.size == operation.source_size
            && digest == operation.source_ciphertext_sha256)
    }

    fn pending_matches_remote(
        &self,
        state: &RootState,
        edit: &VaultPendingEditMetadata,
        remote: &RemoteEntry,
    ) -> Result<bool, CloudError> {
        if remote.directory
            || remote.id != edit.base_resource_id
            || remote.size != edit.plaintext_len
        {
            return Ok(false);
        }
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Offline, "encrypted edit cache is unavailable")
        })?;
        let private = tempdir().map_err(io_error)?;
        let expected_path = private.path().join("expected.bin");
        let actual_path = private.path().join("actual.bin");
        cache.download_pending_edit(&self.sessions, &edit.id, edit.revision, &expected_path)?;
        self.download_vault_inner(
            state,
            &edit.path,
            Some(&remote.etag),
            &actual_path,
            None,
            None,
        )?;
        let mut expected = File::open(&expected_path).map_err(io_error)?;
        let mut actual = File::open(&actual_path).map_err(io_error)?;
        compare_reader_to_file(&mut expected, &mut actual, edit.plaintext_len)
    }

    fn resolve_pending_condition(
        &self,
        path: &str,
        condition: &WriteCondition,
    ) -> Result<(WriteCondition, Option<VaultPendingEditMetadata>), CloudError> {
        let WriteCondition::Match(etag) = condition else {
            return Ok((condition.clone(), None));
        };
        let Some((id, revision)) = parse_pending_etag(etag) else {
            return Ok((condition.clone(), None));
        };
        let cache = self
            .offline_cache
            .as_ref()
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "encrypted edit is unavailable"))?;
        let edit = cache.pending_edit(&self.sessions, id, revision)?;
        if edit.path != path || edit.state != CiphertextWriteState::Pending {
            return Err(conflict("encrypted edit does not match this file revision"));
        }
        Ok((WriteCondition::Match(edit.base_etag.clone()), Some(edit)))
    }

    fn decode_target_path(&self, encoded_target: &str) -> Result<String, CloudError> {
        let decoded = self
            .sessions
            .decrypt_path(&self.scope, encoded_target)
            .map_err(vault_error)?;
        if decoded.is_root() {
            return Err(invalid("vault operation target cannot be the root"));
        }
        let path = format!("/{}", decoded.into_components().join("/"));
        validate_virtual_path(&path)?;
        Ok(path)
    }

    /// Resolve a directory parent reference only from an exact stable remote
    /// identity or an authenticated pending CreateDirectory journal row.
    pub fn parent_ref_for_directory(
        &self,
        virtual_path: &str,
        expected_entry_id: &str,
        expected_entry_etag: &str,
    ) -> Result<VaultPendingParentRef, CloudError> {
        let path = normalize_virtual_path(virtual_path)?;
        validate_virtual_path(&path)?;
        if expected_entry_id.is_empty() || expected_entry_id.len() > 512 {
            return Err(invalid("encrypted parent identity is invalid"));
        }
        if expected_entry_etag.is_empty() || expected_entry_etag.len() > 4_096 {
            return Err(invalid("encrypted parent ETag is invalid"));
        }
        if let Some(pending) = self.pending_directory_for_path(&path)? {
            match pending.state {
                CiphertextWriteState::Pending
                | CiphertextWriteState::Uncertain
                | CiphertextWriteState::NeverAttempted
                | CiphertextWriteState::Attempting
                    if expected_entry_id == format!("raiun-pending-directory:{}", pending.id)
                        && expected_entry_etag == pending_etag(&pending.id, pending.revision) =>
                {
                    return Ok(VaultPendingParentRef::PendingCreate {
                        write_id: pending.id,
                        revision: pending.revision,
                    });
                }
                CiphertextWriteState::CommittedReceipt
                    if expected_entry_id == pending.receipt_resource_id =>
                {
                    let cached_root = self
                        .offline_cache
                        .as_ref()
                        .ok_or_else(|| {
                            conflict("committed encrypted parent receipt is unavailable")
                        })?
                        .cached_root_snapshot(&self.sessions)?;
                    if cached_root.integrity_token != pending.root_integrity_token {
                        return Err(conflict("committed encrypted parent root token changed"));
                    }
                    if !self.offline_only {
                        match self.revalidate_root() {
                            Ok(state) => {
                                let remote = self.stat_raw(&state, &path)?;
                                if !remote.directory || remote.id != pending.receipt_resource_id {
                                    return Err(conflict(
                                        "committed encrypted parent receipt no longer matches the server",
                                    ));
                                }
                            }
                            Err(error) if error.kind == ErrorKind::Offline => {}
                            Err(error) => return Err(error),
                        }
                    }
                    return Ok(VaultPendingParentRef::Stable {
                        resource_id: pending.receipt_resource_id,
                    });
                }
                CiphertextWriteState::CommittedReceipt
                    if expected_entry_id == format!("raiun-pending-directory:{}", pending.id)
                        && pending.receipt_for_revision > 0
                        && expected_entry_etag
                            == pending_etag(&pending.id, pending.receipt_for_revision) =>
                {
                    return Ok(VaultPendingParentRef::PendingCreate {
                        write_id: pending.id,
                        revision: pending.receipt_for_revision,
                    });
                }
                _ => return Err(conflict("encrypted directory parent is not stable")),
            }
        }
        let remote = if self.offline_only {
            self.offline_cache
                .as_ref()
                .ok_or_else(|| CloudError::new(ErrorKind::Offline, "vault cache is unavailable"))?
                .stat_with_cached_permissions(&self.sessions, &path)?
        } else {
            match self.revalidate_root() {
                Ok(state) => self.stat_raw(&state, &path)?,
                Err(error) if error.kind == ErrorKind::Offline => self
                    .offline_cache
                    .as_ref()
                    .ok_or(error.clone())?
                    .stat_with_cached_permissions(&self.sessions, &path)?,
                Err(error) => return Err(error),
            }
        };
        if !remote.directory
            || remote.id != expected_entry_id
            || remote.id.is_empty()
            || remote.etag.is_empty()
        {
            return Err(conflict("encrypted parent resource identity changed"));
        }
        Ok(VaultPendingParentRef::Stable {
            resource_id: remote.id,
        })
    }

    fn encoded_target_under_pending_parent(
        &self,
        path: &str,
        parent_path: &str,
        existing_create: Option<(&str, u64)>,
    ) -> Result<String, CloudError> {
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Offline,
                "encrypted operation journal is unavailable",
            )
        })?;
        let root = cache.cached_root_snapshot(&self.sessions)?;
        let space_writable = if self.offline_only {
            root.space_writable
        } else {
            match self.revalidate_root() {
                Ok(state) => state.space.writable,
                Err(error) if error.kind == ErrorKind::Offline => root.space_writable,
                Err(error) => return Err(error),
            }
        };
        if !space_writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault Space is read only",
            ));
        }
        if !self.offline_only {
            match self.revalidate_root() {
                Ok(state) => match self.stat_raw(&state, parent_path) {
                    Ok(_) => return Err(conflict("pending parent path now exists remotely")),
                    Err(error) if error.kind == ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                },
                Err(error) if error.kind == ErrorKind::Offline => {}
                Err(error) => return Err(error),
            }
        }
        let parent = cache.pending_directory_for_path(&self.sessions, parent_path)?;
        if parent.is_none_or(|entry| {
            !matches!(
                entry.state,
                CiphertextWriteState::Pending
                    | CiphertextWriteState::Uncertain
                    | CiphertextWriteState::NeverAttempted
                    | CiphertextWriteState::Attempting
            )
        }) {
            return Err(conflict("pending encrypted parent is unavailable"));
        }
        let (files, files_truncated) =
            cache.pending_creates_for_parent(&self.sessions, parent_path, 100)?;
        let (directories, directories_truncated) =
            cache.pending_directories_for_parent(&self.sessions, parent_path, 100)?;
        let (renames, renames_truncated) =
            cache.pending_renames_for_parent(&self.sessions, parent_path, 100)?;
        if files_truncated || directories_truncated || renames_truncated {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "too many local encrypted siblings to validate this create",
            ));
        }
        let mut matching_existing_create = false;
        let mut sibling_files = Vec::with_capacity(files.len());
        for operation in &files {
            if let Some((write_id, revision)) = existing_create {
                if operation.id == write_id {
                    if operation.revision != revision
                        || operation.operation != VaultPendingOperationKind::CreateFile
                        || operation.path != path
                        || operation.base != WriteCondition::Absent
                        || operation.state != CiphertextWriteState::NeverAttempted
                    {
                        return Err(conflict(
                            "queued encrypted create changed while revalidating its target",
                        ));
                    }
                    matching_existing_create = true;
                    continue;
                }
            }
            sibling_files.push(operation);
        }
        if !matching_existing_create {
            // Building operations are intentionally omitted from the overlay
            // index. A NeverAttempted operation must be present in the
            // authenticated sibling scan before it can be exempted.
            if let Some((write_id, revision)) = existing_create {
                let cache = self.offline_cache.as_ref().ok_or_else(|| {
                    CloudError::new(
                        ErrorKind::Offline,
                        "encrypted create journal is unavailable",
                    )
                })?;
                let current = cache.pending_operation(&self.sessions, write_id, revision)?;
                if current.state != CiphertextWriteState::Building
                    || current.operation != VaultPendingOperationKind::CreateFile
                    || current.path != path
                    || current.base != WriteCondition::Absent
                {
                    return Err(conflict(
                        "queued encrypted create is missing from its authenticated parent index",
                    ));
                }
            }
        }
        // Keep the plaintext names for the logical collision check, but the
        // vault codec's collision-check argument is specifically a list of
        // encrypted DAV names. These rows came from authenticated journal
        // metadata; use their bound encoded targets rather than passing their
        // plaintext paths to a decoder as if they were base32hex.
        let existing_plain = sibling_files
            .into_iter()
            .map(|entry| entry.path.rsplit('/').next().unwrap_or_default().to_owned())
            .chain(
                directories
                    .iter()
                    .map(|entry| entry.path.rsplit('/').next().unwrap_or_default().to_owned()),
            )
            .chain(renames.iter().map(|entry| {
                entry
                    .destination_path
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            }))
            .collect::<Vec<_>>();
        let leaf = path.rsplit('/').next().unwrap_or_default();
        if existing_plain.iter().any(|name| name == leaf) {
            return Err(conflict(
                "encrypted destination already has a local operation",
            ));
        }
        let existing_encoded = files
            .iter()
            .filter(|operation| {
                !existing_create.is_some_and(|(write_id, _)| operation.id == write_id)
            })
            .map(|operation| {
                operation
                    .encoded_target
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            })
            .chain(directories.iter().map(|operation| {
                operation
                    .encoded_target
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            }))
            .chain(renames.iter().map(|operation| {
                operation
                    .encoded_destination_target
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            }))
            .collect::<Vec<_>>();
        if existing_encoded.iter().any(String::is_empty) {
            return Err(conflict(
                "encrypted sibling operation has an invalid encoded target",
            ));
        }
        let existing_refs = existing_encoded
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let encoded_leaf = self
            .sessions
            .encode_directory_names(&self.scope, &[leaf], &existing_refs)
            .map_err(vault_error)?
            .into_iter()
            .next()
            .ok_or_else(|| invalid("encrypted name encoding returned no target"))?;
        let encoded_parent = self
            .sessions
            .encrypt_path(&self.scope, parent_path.trim_start_matches('/'))
            .map_err(vault_error)?;
        Ok(if encoded_parent.is_empty() {
            encoded_leaf
        } else {
            format!("{encoded_parent}/{encoded_leaf}")
        })
    }

    fn encoded_target_under_committed_parent(
        &self,
        path: &str,
        parent_path: &str,
        receipt: &VaultPendingEditMetadata,
    ) -> Result<String, CloudError> {
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Offline,
                "encrypted parent receipt is unavailable",
            )
        })?;
        if receipt.state != CiphertextWriteState::CommittedReceipt
            || receipt.operation != VaultPendingOperationKind::CreateDirectory
            || receipt.path != parent_path
            || receipt.receipt_resource_id.is_empty()
        {
            return Err(conflict("encrypted parent receipt is invalid"));
        }
        let root = cache.cached_root_snapshot(&self.sessions)?;
        if root.integrity_token != receipt.root_integrity_token {
            return Err(conflict("encrypted parent receipt root token changed"));
        }
        if self.offline_only {
            return self.encoded_file_target_from_cache(path, &WriteCondition::Absent);
        }
        match self.revalidate_root() {
            Ok(state) => {
                if state.integrity_token != receipt.root_integrity_token {
                    return Err(conflict("encrypted parent receipt root token changed"));
                }
                let parent = self.stat_raw(&state, parent_path)?;
                if !parent.directory || parent.id != receipt.receipt_resource_id {
                    return Err(conflict("encrypted parent receipt identity changed"));
                }
                self.encoded_file_target(&state, path, &WriteCondition::Absent)
            }
            Err(error) if error.kind == ErrorKind::Offline => {
                self.encoded_file_target_from_cache(path, &WriteCondition::Absent)
            }
            Err(error) => Err(error),
        }
    }

    /// Capture the parent directory's stable resource identity and current
    /// ETag for a new file. The encrypted path alone cannot distinguish a
    /// deleted-and-recreated directory at the same DAV URL.
    fn current_parent_binding(&self, path: &str) -> Result<(String, String), CloudError> {
        let parent = logical_parent(path);
        let cached = || -> Result<(String, String), CloudError> {
            let cache = self.offline_cache.as_ref().ok_or_else(|| {
                CloudError::new(
                    ErrorKind::Offline,
                    "encrypted parent metadata is unavailable",
                )
            })?;
            let entry = cache.stat_with_cached_permissions(&self.sessions, &parent)?;
            if !entry.directory || entry.id.is_empty() || entry.etag.is_empty() {
                return Err(conflict("cached encrypted create parent is not versioned"));
            }
            Ok((entry.id, entry.etag))
        };
        let binding = if self.offline_only {
            cached()?
        } else {
            match self.revalidate_root() {
                Ok(state) => {
                    let (_, listing) = self.parent_listing(&state, path)?;
                    (
                        listing.root.id,
                        listing
                            .root
                            .strong_etag
                            .ok_or_else(|| invalid("encrypted create parent omitted its ETag"))?,
                    )
                }
                Err(error) if error.kind == ErrorKind::Offline => cached()?,
                Err(error) => return Err(error),
            }
        };
        if binding.0.is_empty()
            || binding.0.len() > 512
            || binding.1.is_empty()
            || binding.1.len() > 4_096
        {
            return Err(invalid("encrypted create parent binding is invalid"));
        }
        Ok(binding)
    }

    fn resolve_operation_parent(
        &self,
        state: &RootState,
        operation: &VaultPendingEditMetadata,
    ) -> Result<(String, String), CloudError> {
        let parent_path = logical_parent(&operation.path);
        let expected_id = match operation.parent_ref.as_ref() {
            Some(VaultPendingParentRef::Stable { resource_id }) => resource_id.clone(),
            Some(VaultPendingParentRef::PendingCreate { write_id, revision }) => {
                let cache = self.offline_cache.as_ref().ok_or_else(|| {
                    CloudError::new(
                        ErrorKind::Offline,
                        "encrypted parent journal is unavailable",
                    )
                })?;
                let Some(receipt) =
                    cache.directory_create_receipt(&self.sessions, write_id, *revision)?
                else {
                    return Err(CloudError::new(
                        ErrorKind::Offline,
                        "encrypted parent is awaiting remote confirmation",
                    ));
                };
                if receipt.path != parent_path
                    || receipt.root_integrity_token != operation.root_integrity_token
                    || receipt.receipt_resource_id.is_empty()
                {
                    return Err(conflict(
                        "encrypted parent receipt does not match this operation",
                    ));
                }
                receipt.receipt_resource_id
            }
            None => return Err(conflict("encrypted operation parent reference is missing")),
        };
        let parent = self.stat_raw(state, &parent_path)?;
        if !parent.directory || parent.id != expected_id || parent.etag.is_empty() {
            return Err(conflict("encrypted operation parent identity changed"));
        }
        Ok((parent.id, parent.etag))
    }

    fn retire_parent_receipt(
        &self,
        operation: &VaultPendingEditMetadata,
    ) -> Result<(), CloudError> {
        let Some(VaultPendingParentRef::PendingCreate { write_id, revision }) =
            operation.parent_ref.as_ref()
        else {
            return Ok(());
        };
        let Some(cache) = &self.offline_cache else {
            return Ok(());
        };
        match cache.retire_directory_receipt_if_unreferenced(&self.sessions, write_id, *revision) {
            Ok(()) => Ok(()),
            // A remaining child dependency keeps the receipt alive.
            Err(error) if error.kind == ErrorKind::Conflict => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn cached_base_entry(
        &self,
        path: &str,
        condition: &WriteCondition,
    ) -> Result<RemoteEntry, CloudError> {
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Offline, "encrypted file cache is unavailable")
        })?;
        let entry = cache.stat(&self.sessions, path)?;
        if entry.directory || entry.id.is_empty() || entry.etag.is_empty() {
            return Err(invalid(
                "cached vault target is not a regular versioned file",
            ));
        }
        match condition {
            WriteCondition::Match(expected) if expected == &entry.etag => Ok(entry),
            _ => Err(conflict("cached vault file version does not match")),
        }
    }

    fn queue_offline_edit<R: Read + Seek>(
        &self,
        encoded_target: &str,
        integrity_token: &str,
        source: &mut R,
        plaintext_len: u64,
        context: OfflineEditContext,
    ) -> Result<VaultUploadOutcome, CloudError> {
        let OfflineEditContext {
            base,
            condition,
            existing_id,
            uncertain,
        } = context;
        let WriteCondition::Match(base_etag) = condition else {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted offline edits require an existing file",
            ));
        };
        if base.etag != base_etag || base.id.is_empty() || base.directory {
            return Err(conflict("encrypted offline edit base changed"));
        }
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Offline, "encrypted edit cache is unavailable")
        })?;
        let metadata = cache.queue_edit(
            &self.sessions,
            source,
            VaultPendingEditRequest {
                integrity_token,
                encoded_target,
                base_resource_id: &base.id,
                base_etag: &base_etag,
                existing_id: existing_id.as_deref(),
                body_len: plaintext_len,
            },
        )?;
        if uncertain {
            cache.set_pending_edit_state(
                &metadata.id,
                metadata.revision,
                CiphertextWriteState::Uncertain,
            )?;
        }
        let mut entry = base;
        entry.size = plaintext_len;
        entry.etag = pending_etag(&metadata.id, metadata.revision);
        entry.writable = true; // local journal edits remain possible; server authorization is rechecked on reconciliation.
        Ok(VaultUploadOutcome::Queued {
            entry,
            write_id: metadata.id,
            revision: metadata.revision,
            uncertain,
        })
    }

    fn verify_uploaded_reader<R: Read + Seek>(
        &self,
        state: &RootState,
        path: &str,
        uploaded: &RemoteEntry,
        source: &mut R,
        expected_len: u64,
    ) -> Result<bool, CloudError> {
        if uploaded.directory || uploaded.size != expected_len || uploaded.etag.is_empty() {
            return Ok(false);
        }
        let private = tempdir().map_err(io_error)?;
        let readback_path = private.path().join("readback.bin");
        self.download_vault_inner(
            state,
            path,
            Some(&uploaded.etag),
            &readback_path,
            None,
            None,
        )?;
        source.seek(SeekFrom::Start(0)).map_err(io_error)?;
        let mut readback = File::open(&readback_path).map_err(io_error)?;
        compare_reader_to_file(source, &mut readback, expected_len)
    }

    fn encoded_file_target_from_cache(
        &self,
        virtual_path: &str,
        condition: &WriteCondition,
    ) -> Result<String, CloudError> {
        if virtual_path == "/" {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cannot replace the vault root",
            ));
        }
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Offline, "encrypted vault cache is unavailable")
        })?;
        let root = cache.cached_root_snapshot(&self.sessions)?;
        if !root.space_writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault Space is read only",
            ));
        }
        let parent = logical_parent(virtual_path);
        let parent_entry = cache.stat_with_cached_permissions(&self.sessions, &parent)?;
        if !parent_entry.directory || (parent != "/" && !parent_entry.writable) {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault parent is read only",
            ));
        }
        let siblings = cache.list_with_cached_permissions(&self.sessions, &parent)?;
        let leaf = virtual_path.rsplit('/').next().unwrap_or_default();
        let encrypted_siblings = siblings
            .iter()
            .map(|entry| {
                self.sessions.encrypt_name(
                    &self.scope,
                    entry.path.rsplit('/').next().unwrap_or_default(),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(vault_error)?;
        let current = siblings.iter().find(|entry| entry.path == virtual_path);
        let excluded = match condition {
            WriteCondition::Absent => {
                if current.is_some() {
                    return Err(conflict("vault destination already exists"));
                }
                None
            }
            WriteCondition::Match(expected) => {
                let current =
                    current.ok_or_else(|| conflict("vault destination no longer exists"))?;
                if current.etag != *expected {
                    return Err(conflict("vault destination changed before local edit"));
                }
                if current.directory {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "encrypted edits support existing files only",
                    ));
                }
                if !current.writable {
                    return Err(CloudError::new(
                        ErrorKind::Forbidden,
                        "vault file is read only",
                    ));
                }
                Some(current.id.as_str())
            }
        };
        let existing = encrypted_siblings
            .iter()
            .zip(&siblings)
            .filter(|(_, entry)| excluded != Some(entry.id.as_str()))
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        let encrypted_leaf = self
            .sessions
            .encode_directory_names(&self.scope, &[leaf], &existing)
            .map_err(vault_error)?
            .into_iter()
            .next()
            .ok_or_else(|| invalid("vault filename encoding failed"))?;
        let parent_relative = relative_virtual_path(&parent)?;
        let encrypted_parent = self
            .sessions
            .encrypt_path(&self.scope, parent_relative)
            .map_err(vault_error)?;
        Ok(if encrypted_parent.is_empty() {
            encrypted_leaf
        } else {
            format!("{encrypted_parent}/{encrypted_leaf}")
        })
    }

    /// Encrypt and conditionally upload a seekable plaintext reader to a target
    /// prepared from the same bound vault. The reader is reset to byte zero,
    /// consumed at exactly `plaintext_len`, and an extra byte is checked before
    /// any PUT. No plaintext-sized in-memory buffer is allocated.
    pub fn upload_prepared_reader<R: Read + Seek>(
        &self,
        encoded_target: &str,
        source: &mut R,
        plaintext_len: u64,
        condition: WriteCondition,
    ) -> Result<RemoteEntry, CloudError> {
        if plaintext_len > MAX_VAULT_PLAINTEXT_BYTES {
            return Err(invalid("vault upload source exceeds its size limit"));
        }
        let decoded = self
            .sessions
            .decrypt_path(&self.scope, encoded_target)
            .map_err(vault_error)?;
        if decoded.is_root() {
            return Err(invalid("vault upload target cannot be the root"));
        }
        let virtual_path = format!("/{}", decoded.components().collect::<Vec<_>>().join("/"));
        validate_virtual_path(&virtual_path)?;
        source.seek(SeekFrom::Start(0)).map_err(io_error)?;
        let state = self.revalidate_root()?;
        self.put_vault_reader(
            &state,
            &virtual_path,
            source,
            plaintext_len,
            condition,
            VaultPutExpectation::target(encoded_target),
        )
    }

    /// Build a copy-on-write encrypted offline snapshot. Each file is
    /// downloaded and authenticated in bounded streams; only ciphertext and
    /// sealed directory metadata enter the cache. Decrypted verification
    /// scratch files are removed before their private temporary directories
    /// close, but secure erasure and crash/paging cleanup are not promised.
    pub fn pin_offline_tree(
        &self,
        existing_pin_id: Option<&str>,
        cancelled: &AtomicBool,
    ) -> Result<CiphertextPinInfo, CloudError> {
        self.pin_offline_tree_with_progress(existing_pin_id, cancelled, |_| {})
    }

    pub fn pin_offline_tree_with_progress<F>(
        &self,
        existing_pin_id: Option<&str>,
        cancelled: &AtomicBool,
        mut progress: F,
    ) -> Result<CiphertextPinInfo, CloudError>
    where
        F: FnMut(VaultPinProgress),
    {
        if self.offline_only {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted snapshots cannot be refreshed while disconnected",
            ));
        }
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Unsupported, "encrypted cache is unavailable")
        })?;
        check_pin_cancelled(cancelled)?;
        let initial = self.revalidate_root()?;
        cache.trim_recent_before_pin()?;
        let epoch = cache.ciphertext_epoch()?;
        let build = cache.begin_pin_generation(epoch, existing_pin_id)?;
        let result = self.pin_generation(&initial, cache, &build, epoch, cancelled, &mut progress);
        if result.is_err() {
            // Remove this generation's references only; its unpinned Recent
            // blobs remain eligible for ordinary LRU eviction.
            let _ = cache.abandon_pin_generation(&build);
        }
        result
    }

    fn pin_generation(
        &self,
        initial: &RootState,
        cache: &VaultOfflineCache,
        build: &CiphertextPinBuild,
        expected_epoch: u64,
        cancelled: &AtomicBool,
        progress: &mut dyn FnMut(VaultPinProgress),
    ) -> Result<CiphertextPinInfo, CloudError> {
        let mut directories = vec![("/".to_owned(), 0usize)];
        let mut seen_resources = std::collections::HashSet::new();
        seen_resources.insert(self.scope.resource_id().to_owned());
        let mut seen_directories = std::collections::HashSet::new();
        seen_directories.insert(self.scope.resource_id().to_owned());
        let mut entry_count = 0usize;
        let mut items_done = 0usize;
        let mut plaintext_bytes = 0u64;

        while let Some((path, depth)) = directories.pop() {
            check_pin_cancelled(cancelled)?;
            if depth > MAX_VAULT_PIN_DEPTH {
                return Err(invalid("encrypted pin exceeds its directory depth limit"));
            }
            let state = self.revalidate_pin_root(initial)?;
            let mut entries = Vec::new();
            self.list_raw_for_pin(
                &state,
                &path,
                &mut |entry| {
                    entries.push(entry);
                    Ok(())
                },
                build,
            )?;
            entry_count = entry_count
                .checked_add(entries.len())
                .ok_or_else(|| invalid("encrypted pin entry count overflowed"))?;
            if entry_count > MAX_VAULT_PIN_ENTRIES {
                return Err(invalid("encrypted pin exceeds its entry limit"));
            }
            for entry in entries {
                check_pin_cancelled(cancelled)?;
                items_done = items_done
                    .checked_add(1)
                    .ok_or_else(|| invalid("encrypted pin item count overflowed"))?;
                let mut progress_snapshot = VaultPinProgress {
                    items_done,
                    bytes_done: plaintext_bytes,
                };
                if entry.id.is_empty() || !seen_resources.insert(entry.id.clone()) {
                    return Err(conflict(
                        "encrypted pin contains a duplicate resource identity",
                    ));
                }
                if entry.directory {
                    if !seen_directories.insert(entry.id.clone()) {
                        return Err(conflict("encrypted pin directory identity is cyclic"));
                    }
                    directories.push((entry.path, depth + 1));
                    progress(progress_snapshot);
                    continue;
                }
                plaintext_bytes = plaintext_bytes
                    .checked_add(entry.size)
                    .ok_or_else(|| invalid("encrypted pin size overflowed"))?;
                if plaintext_bytes > MAX_VAULT_PLAINTEXT_BYTES {
                    return Err(invalid("encrypted pin exceeds its total content limit"));
                }
                let fresh_state = self.revalidate_pin_root(initial)?;
                let scratch = tempdir().map_err(io_error)?;
                let plain_path = scratch.path().join("verified-plaintext.tmp");
                let fetched = self.download_vault_for_pin(
                    &fresh_state,
                    &entry.path,
                    Some(&entry.etag),
                    &plain_path,
                    build,
                )?;
                if fetched.id != entry.id
                    || fetched.etag != entry.etag
                    || fetched.size != entry.size
                    || fetched.directory
                {
                    return Err(conflict("encrypted file changed while it was being pinned"));
                }
                check_pin_cancelled(cancelled)?;
                fs::remove_file(&plain_path).map_err(io_error)?;
                progress_snapshot.bytes_done = plaintext_bytes;
                progress(progress_snapshot);
            }
        }

        check_pin_cancelled(cancelled)?;
        self.revalidate_pin_root(initial)?;
        if cache.ciphertext_epoch()? != expected_epoch {
            return Err(conflict("encrypted cache changed during pin traversal"));
        }
        check_pin_cancelled(cancelled)?;
        cache.finish_pin_generation(build)
    }

    fn revalidate_pin_root(&self, expected: &RootState) -> Result<RootState, CloudError> {
        let current = self.revalidate_root()?;
        if current.integrity_token != expected.integrity_token
            || current.space.id != expected.space.id
            || current.space_dav_root != expected.space_dav_root
        {
            return Err(conflict("encrypted root changed during pin traversal"));
        }
        Ok(current)
    }

    fn encoded_file_target(
        &self,
        state: &RootState,
        virtual_path: &str,
        condition: &WriteCondition,
    ) -> Result<String, CloudError> {
        if virtual_path == "/" {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cannot replace the vault root",
            ));
        }
        let (parent, siblings) = self.parent_listing(state, virtual_path)?;
        let leaf = virtual_path.rsplit('/').next().unwrap_or_default();
        let encrypted_leaf = self
            .sessions
            .encrypt_name(&self.scope, leaf)
            .map_err(vault_error)?;
        let current = siblings
            .children
            .iter()
            .find(|entry| entry.raw_name == encrypted_leaf);
        let excluded = match condition {
            WriteCondition::Absent => {
                if current.is_some() {
                    return Err(conflict("vault destination already exists"));
                }
                None
            }
            WriteCondition::Match(expected) => {
                let current =
                    current.ok_or_else(|| conflict("vault destination no longer exists"))?;
                if current.strong_etag.as_deref() != Some(expected.as_str()) {
                    return Err(conflict("vault destination changed before upload"));
                }
                if current.directory {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "encrypted edits support existing files only",
                    ));
                }
                if !current.writable || !state.space.writable {
                    return Err(CloudError::new(
                        ErrorKind::Forbidden,
                        "vault file is read only",
                    ));
                }
                Some(current.id.as_str())
            }
        };
        let encoded = self.encode_new_leaf(&siblings, leaf, excluded)?;
        if encoded != encrypted_leaf {
            return Err(invalid("vault filename encoding is inconsistent"));
        }
        let parent_rel = relative_virtual_path(&parent)?;
        let encrypted_parent = self
            .sessions
            .encrypt_path(&self.scope, parent_rel)
            .map_err(vault_error)?;
        Ok(if encrypted_parent.is_empty() {
            encoded
        } else {
            format!("{encrypted_parent}/{encoded}")
        })
    }

    fn selected_space(&self, requested_space: &str) -> Result<CloudSpace, CloudError> {
        if requested_space != self.scope.space_id() {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "vault backend is bound to a different OpenCloud Space",
            ));
        }
        self.client
            .spaces()?
            .into_iter()
            .find(|space| space.id == self.scope.space_id())
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "vault Space was not found"))
    }

    fn revalidate_root(&self) -> Result<RootState, CloudError> {
        if self.client.server.origin().ascii_serialization() != self.scope.server_origin() {
            return Err(invalid("vault client origin no longer matches its session"));
        }
        if !self
            .sessions
            .is_unlocked(&self.scope)
            .map_err(vault_error)?
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault session is locked",
            ));
        }
        let space = self.selected_space(self.scope.space_id())?;
        let listing = VaultMetadataClient::new(&self.client)
            .inspect_vault(self.scope.space_id(), &self.root_path)?;
        if space.encrypted != (self.root_path == "/") {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "vault backend root kind does not match the selected Space",
            ));
        }
        if listing.space_id != self.scope.space_id()
            || normalize_root_path(&listing.root_path) != self.root_path
            || listing.root.id != self.scope.resource_id()
            || !listing.root.directory
            || listing.evidence.is_empty()
        {
            return Err(conflict("vault root identity or marker changed"));
        }
        let token = listing
            .integrity_token
            .as_deref()
            .ok_or_else(|| conflict("vault root integrity token is missing"))?;
        if !self
            .sessions
            .verify_integrity_token(&self.scope, token)
            .map_err(vault_error)?
        {
            return Err(conflict(
                "vault root integrity token no longer matches the session",
            ));
        }
        let root_url = Url::parse(&listing.space_dav_root)
            .map_err(|_| invalid("vault Space DAV root is invalid"))?;
        if !same_origin(&self.client.server, &root_url) {
            return Err(invalid(
                "vault Space DAV root is outside the authenticated origin",
            ));
        }
        let space_dav_root = ensure_trailing_slash(root_url)?.to_string();
        if !self.space_dav_root.is_empty() && self.space_dav_root != space_dav_root {
            return Err(conflict("vault Space DAV root changed"));
        }
        Ok(RootState {
            space,
            space_dav_root,
            integrity_token: token.to_owned(),
            root_etag: listing.root.strong_etag,
        })
    }

    fn check_space(&self, space: &str) -> Result<(), CloudError> {
        if space != self.scope.space_id() {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "vault backend is bound to a different OpenCloud Space",
            ));
        }
        Ok(())
    }

    fn physical_path(&self, virtual_path: &str) -> Result<String, CloudError> {
        let relative = relative_virtual_path(virtual_path)?;
        let encrypted = self
            .sessions
            .encrypt_path(&self.scope, relative)
            .map_err(vault_error)?;
        if encrypted.is_empty() {
            Ok(self.root_path.clone())
        } else if self.root_path == "/" {
            Ok(format!("/{encrypted}"))
        } else {
            Ok(format!(
                "{}/{encrypted}",
                self.root_path.trim_end_matches('/')
            ))
        }
    }

    fn raw_listing(
        &self,
        state: &RootState,
        virtual_path: &str,
        depth: &str,
    ) -> Result<VaultRootListing, CloudError> {
        let physical = self.physical_path(virtual_path)?;
        let request_path = if virtual_path == "/" || depth == "1" {
            if physical.ends_with('/') {
                physical.clone()
            } else {
                format!("{physical}/")
            }
        } else {
            physical.clone()
        };
        let listing = VaultMetadataClient::new(&self.client).inspect_raw_path(
            self.scope.space_id(),
            &request_path,
            depth,
        )?;
        if listing.space_id != self.scope.space_id()
            || normalize_root_path(&listing.space_dav_root)
                != normalize_root_path(&state.space_dav_root)
            || normalize_root_path(&listing.root.path) != normalize_root_path(&physical)
        {
            return Err(invalid("vault DAV listing escaped its bound root"));
        }
        if virtual_path != "/" && !listing.root.vault_evidence.is_empty() {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "nested vault roots are not supported by this backend",
            ));
        }
        for child in &listing.children {
            if !child.vault_evidence.is_empty() {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "nested vault roots are not supported by this backend",
                ));
            }
        }
        Ok(listing)
    }

    fn map_entry(
        &self,
        state: &RootState,
        virtual_path: &str,
        entry: &VaultDavEntry,
    ) -> Result<RemoteEntry, CloudError> {
        let size = if entry.directory {
            0
        } else {
            plaintext_len_from_ciphertext(entry.size)?
        };
        if size > MAX_VAULT_PLAINTEXT_BYTES {
            return Err(invalid("vault file exceeds the plaintext size limit"));
        }
        let etag = entry
            .strong_etag
            .clone()
            .ok_or_else(|| invalid("vault DAV entry omitted a strong ETag"))?;
        Ok(RemoteEntry {
            id: entry.id.clone(),
            path: virtual_path.to_owned(),
            directory: entry.directory,
            size,
            etag,
            modified_unix: entry.modified_unix,
            writable: state.space.writable && entry.writable,
            encrypted: false,
        })
    }

    fn stat_raw(&self, state: &RootState, virtual_path: &str) -> Result<RemoteEntry, CloudError> {
        let listing = self.raw_listing(state, virtual_path, "0")?;
        if !listing.children.is_empty() {
            return Err(invalid("vault stat returned nested resources"));
        }
        if virtual_path == "/" {
            if listing.root.id != self.scope.resource_id() {
                return Err(conflict("vault root resource identity changed"));
            }
        } else {
            let physical = self.physical_path(virtual_path)?;
            let relative_encrypted = relative_physical_path(&self.root_path, &physical)?;
            let decoded = self
                .sessions
                .decrypt_path(&self.scope, relative_encrypted)
                .map_err(vault_error)?
                .into_components()
                .join("/");
            if format!("/{decoded}") != virtual_path {
                return Err(invalid(
                    "vault DAV resource name does not match the requested path",
                ));
            }
        }
        if !listing.root.vault_evidence.is_empty() && virtual_path != "/" {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "nested vault roots are not supported by this backend",
            ));
        }
        self.map_entry(state, virtual_path, &listing.root)
    }

    fn list_raw(
        &self,
        state: &RootState,
        virtual_path: &str,
        visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
    ) -> Result<(), CloudError> {
        self.list_raw_inner(state, virtual_path, visit, None)
    }

    fn list_raw_for_pin(
        &self,
        state: &RootState,
        virtual_path: &str,
        visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
        build: &CiphertextPinBuild,
    ) -> Result<(), CloudError> {
        self.list_raw_inner(state, virtual_path, visit, Some(build))
    }

    fn list_raw_inner(
        &self,
        state: &RootState,
        virtual_path: &str,
        visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
        pin: Option<&CiphertextPinBuild>,
    ) -> Result<(), CloudError> {
        let cache_epoch = pin.map(|build| build.epoch()).or_else(|| {
            self.offline_cache
                .as_ref()
                .and_then(|cache| cache.ciphertext_epoch().ok())
        });
        let listing = self.raw_listing(state, virtual_path, "1")?;
        if virtual_path == "/" && listing.root.id != self.scope.resource_id() {
            return Err(conflict("vault root resource identity changed"));
        }
        let encrypted_names: Vec<_> = listing
            .children
            .iter()
            .map(|entry| entry.raw_name.as_str())
            .collect();
        let decoded_names = self
            .sessions
            .decode_directory_names(&self.scope, &encrypted_names)
            .map_err(vault_error)?;
        if let (Some(cache), Some(cache_epoch)) = (&self.offline_cache, cache_epoch) {
            if let Ok(relative) = relative_virtual_path(virtual_path) {
                if let Ok(encrypted_directory_path) =
                    self.sessions.encrypt_path(&self.scope, relative)
                {
                    // This is an optimization only. A valid online listing must
                    // continue to work if local cache publication fails.
                    let metadata = VaultListingMetadata {
                        integrity_token: &state.integrity_token,
                        root_etag: state.root_etag.as_deref(),
                        space: &state.space,
                        space_dav_root: &state.space_dav_root,
                        encrypted_directory_path: &encrypted_directory_path,
                    };
                    if let Some(build) = pin {
                        cache.publish_listing_for_pin(
                            &self.sessions,
                            &metadata,
                            &listing.root,
                            &listing.children,
                            build,
                            virtual_path == "/",
                        )?;
                    } else {
                        let _ = cache.publish_listing(
                            &self.sessions,
                            &metadata,
                            &listing.root,
                            &listing.children,
                            cache_epoch,
                        );
                    }
                }
            }
        }
        let parent = virtual_path.to_owned();
        let mut staged = Vec::with_capacity(listing.children.len());
        for (entry, name) in listing.children.iter().zip(decoded_names) {
            let path = if parent == "/" {
                format!("/{name}")
            } else {
                format!("{parent}/{name}")
            };
            staged.push(self.map_entry(state, &path, entry)?);
        }
        for entry in staged {
            visit(entry)?;
        }
        Ok(())
    }

    fn parent_listing(
        &self,
        state: &RootState,
        virtual_path: &str,
    ) -> Result<(String, VaultRootListing), CloudError> {
        let parent = logical_parent(virtual_path);
        let listing = self.raw_listing(state, &parent, "1")?;
        let names: Vec<_> = listing
            .children
            .iter()
            .map(|entry| entry.raw_name.as_str())
            .collect();
        self.sessions
            .decode_directory_names(&self.scope, &names)
            .map_err(vault_error)?;
        if !listing.root.writable || !state.space.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault parent is read only",
            ));
        }
        Ok((parent, listing))
    }

    fn verify_item_parent_writable(
        &self,
        state: &RootState,
        virtual_path: &str,
        expected_id: &str,
    ) -> Result<(), CloudError> {
        let (_, listing) = self.parent_listing(state, virtual_path)?;
        let leaf = virtual_path.rsplit('/').next().unwrap_or_default();
        let encrypted_leaf = self
            .sessions
            .encrypt_name(&self.scope, leaf)
            .map_err(vault_error)?;
        let item = listing
            .children
            .iter()
            .find(|entry| entry.raw_name == encrypted_leaf && entry.id == expected_id)
            .ok_or_else(|| conflict("vault item moved before operation"))?;
        if !item.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault item is read only",
            ));
        }
        Ok(())
    }

    fn encode_new_leaf(
        &self,
        parent_listing: &VaultRootListing,
        leaf: &str,
        exclude_id: Option<&str>,
    ) -> Result<String, CloudError> {
        let existing: Vec<_> = parent_listing
            .children
            .iter()
            .filter(|entry| exclude_id != Some(entry.id.as_str()))
            .map(|entry| entry.raw_name.as_str())
            .collect();
        self.sessions
            .encode_directory_names(&self.scope, &[leaf], &existing)
            .map(|names| names.into_iter().next().expect("one encoded name"))
            .map_err(vault_error)
    }

    fn target_url(&self, state: &RootState, virtual_path: &str) -> Result<Url, CloudError> {
        let physical = self.physical_path(virtual_path)?;
        let root = Url::parse(&state.space_dav_root)
            .map_err(|_| invalid("vault Space DAV root is invalid"))?;
        let url = super::append_logical_path(&root, &physical)?;
        if !same_origin(&self.client.server, &url) {
            return Err(invalid(
                "vault request URL is outside the authenticated origin",
            ));
        }
        Ok(url)
    }

    fn put_vault(
        &self,
        state: &RootState,
        virtual_path: &str,
        source: &Path,
        condition: WriteCondition,
    ) -> Result<RemoteEntry, CloudError> {
        let metadata = fs::metadata(source).map_err(io_error)?;
        if !metadata.is_file() || metadata.len() > MAX_VAULT_PLAINTEXT_BYTES {
            return Err(invalid(
                "vault upload source is not a regular file or exceeds its size limit",
            ));
        }
        let mut input = File::open(source).map_err(io_error)?;
        self.put_vault_reader(
            state,
            virtual_path,
            &mut input,
            metadata.len(),
            condition,
            VaultPutExpectation {
                encoded_target: None,
                parent_binding: None,
                expected_token_generation: None,
                external_token_generation: None,
                caller_cancelled: None,
            },
        )
    }

    fn put_vault_reader<R: Read>(
        &self,
        state: &RootState,
        virtual_path: &str,
        source: &mut R,
        plaintext_size: u64,
        condition: WriteCondition,
        expectation: VaultPutExpectation<'_>,
    ) -> Result<RemoteEntry, CloudError> {
        if expectation
            .caller_cancelled
            .is_some_and(|cancelled| cancelled())
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "encrypted upload was cancelled",
            ));
        }
        if virtual_path == "/" {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cannot replace the vault root",
            ));
        }
        if plaintext_size > MAX_VAULT_PLAINTEXT_BYTES {
            return Err(invalid("vault upload source exceeds its size limit"));
        }
        let expected_resource_id = match &condition {
            WriteCondition::Absent => None,
            WriteCondition::Match(_) => Some(self.stat_raw(state, virtual_path)?.id),
        };
        let encoded_path = self.encoded_file_target(state, virtual_path, &condition)?;
        if expectation
            .encoded_target
            .is_some_and(|expected| expected != encoded_path)
        {
            return Err(conflict("prepared encrypted destination changed"));
        }
        if expectation
            .external_token_generation
            .as_ref()
            .is_some_and(|(generation, expected)| generation.load(Ordering::Acquire) != *expected)
        {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "source provider generation changed before upload",
            ));
        }
        let physical = format!("{}/{encoded_path}", self.root_path.trim_end_matches('/'));
        let url = self.url_for_physical(state, &physical)?;

        let temp = tempdir().map_err(io_error)?;
        let ciphertext_path = temp.path().join("ciphertext.bin");
        self.sessions
            .encrypt_file_transactional(
                &self.scope,
                source,
                &ciphertext_path,
                plaintext_size,
                MAX_VAULT_PLAINTEXT_BYTES,
            )
            .map_err(vault_error)?;
        let ciphertext = File::open(&ciphertext_path).map_err(io_error)?;
        let ciphertext_size = ciphertext.metadata().map_err(io_error)?.len();
        let transfer_budget = self.client.transfer_budget();
        if !self
            .sessions
            .is_unlocked(&self.scope)
            .map_err(vault_error)?
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault session was locked before upload",
            ));
        }
        let fresh_state = self.revalidate_root()?;
        if expectation
            .external_token_generation
            .as_ref()
            .is_some_and(|(generation, expected)| generation.load(Ordering::Acquire) != *expected)
        {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "source provider generation changed before upload",
            ));
        }
        if expectation
            .expected_token_generation
            .is_some_and(|expected| self.client.token_generation() != expected)
        {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed before upload",
            ));
        }
        if !fresh_state.space.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "encrypted Space became read only before upload",
            ));
        }
        if let Some((expected_id, expected_etag)) = expectation.parent_binding {
            let parent = self.stat_raw(&fresh_state, &logical_parent(virtual_path))?;
            if !parent.directory || parent.id != expected_id || parent.etag != expected_etag {
                return Err(conflict(
                    "encrypted create parent identity changed before upload",
                ));
            }
        }
        if let Some(cache) = &self.offline_cache {
            cache.invalidate_before_remote_mutation()?;
        }
        let total_timeout = crate::transfer_timeout_with_budget(
            &transfer_budget,
            TransferDirection::Upload,
            ciphertext_size,
        );
        let request_context = expectation
            .expected_token_generation
            .map(|token_generation| RangeReadContext {
                deadline: Instant::now() + total_timeout,
                token_generation,
            });
        let (mut request, token) =
            self.client
                .request_async_with_context(Method::PUT, &url, request_context)?;
        request = request
            .header(CONTENT_LENGTH, ciphertext_size)
            .header(CONTENT_TYPE, "application/octet-stream");
        request = match condition {
            WriteCondition::Absent => request.header(IF_NONE_MATCH, "*"),
            WriteCondition::Match(etag) => request.header(IF_MATCH, etag),
        };
        let cancellation = transfer_budget.cancellation();
        let watchdog_cancellation = cancellation.clone();
        let caller_cancelled = expectation.caller_cancelled;
        let expected_token_generation = expectation.expected_token_generation;
        let external_token_generation = expectation.external_token_generation;
        let token_generation = Arc::clone(&self.client.token_generation);
        if expected_token_generation
            .is_some_and(|expected| token_generation.load(Ordering::Acquire) != expected)
        {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed before upload",
            ));
        }
        if external_token_generation
            .as_ref()
            .is_some_and(|(generation, expected)| generation.load(Ordering::Acquire) != *expected)
        {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "source provider generation changed before upload",
            ));
        }
        let body_token_generation = Arc::clone(&token_generation);
        let watchdog_external_generation = external_token_generation.clone();
        let body_external_generation = external_token_generation.clone();
        let response_result = crate::async_body::run_body_operation_cancellable(
            self.client.body_idle_timeout(),
            total_timeout,
            || {
                caller_cancelled.is_some_and(|cancelled| cancelled())
                    || watchdog_cancellation.is_cancelled()
                    || expected_token_generation.is_some_and(|expected| {
                        token_generation.load(Ordering::Acquire) != expected
                    })
                    || watchdog_external_generation.as_ref().is_some_and(
                        |(generation, expected)| generation.load(Ordering::Acquire) != *expected,
                    )
            },
            move |progress| async move {
                let body = crate::async_body::budgeted_upload_stream(
                    tokio::fs::File::from_std(ciphertext),
                    ciphertext_size,
                    transfer_budget,
                    move || {
                        cancellation.is_cancelled()
                            || expected_token_generation.is_some_and(|expected| {
                                body_token_generation.load(Ordering::Acquire) != expected
                            })
                            || body_external_generation.as_ref().is_some_and(
                                |(generation, expected)| {
                                    generation.load(Ordering::Acquire) != *expected
                                },
                            )
                    },
                    progress,
                );
                let response = request
                    .timeout(total_timeout)
                    .body(reqwest::Body::wrap_stream(body))
                    .send()
                    .await
                    .map_err(network)?;
                crate::checked_async(
                    response,
                    &[StatusCode::CREATED, StatusCode::NO_CONTENT],
                    &token,
                )?;
                Ok(())
            },
        );
        if let Err(error) = response_result {
            trace_vault_upload_stage("put_transport_or_response_failed", Some(error.kind));
            trace_vault_upload_stage("put_response_rejected", Some(error.kind));
            return Err(error);
        }
        if expected_token_generation
            .is_some_and(|expected| self.client.token_generation() != expected)
        {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed during upload",
            ));
        }
        if external_token_generation
            .as_ref()
            .is_some_and(|(generation, expected)| generation.load(Ordering::Acquire) != *expected)
        {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "source provider generation changed during upload",
            ));
        }
        trace_vault_upload_stage("put_response_accepted", None);
        let fresh_state = match self.revalidate_root() {
            Ok(state) => state,
            Err(error) => {
                trace_vault_upload_stage("post_put_root_revalidation_failed", Some(error.kind));
                return Err(error);
            }
        };
        trace_vault_upload_stage("post_put_root_revalidated", None);
        let entry = match self.stat_raw(&fresh_state, virtual_path) {
            Ok(entry) => entry,
            Err(error) => {
                trace_vault_upload_stage("post_put_target_stat_failed", Some(error.kind));
                return Err(error);
            }
        };
        trace_vault_upload_stage("post_put_target_stat_succeeded", None);
        if entry.id.is_empty() {
            trace_vault_upload_stage("post_put_empty_resource_id", None);
            return Err(invalid(
                "uploaded vault content failed identity or plaintext-size verification",
            ));
        }
        if entry.etag.is_empty() {
            trace_vault_upload_stage("post_put_empty_etag", None);
            return Err(invalid(
                "uploaded vault content failed identity or plaintext-size verification",
            ));
        }
        if entry.size != plaintext_size {
            trace_vault_upload_stage("post_put_plaintext_size_mismatch", None);
            return Err(invalid(
                "uploaded vault content failed identity or plaintext-size verification",
            ));
        }
        if expected_resource_id
            .as_ref()
            .is_some_and(|expected| expected != &entry.id)
        {
            trace_vault_upload_stage("post_put_resource_id_changed", None);
            return Err(invalid(
                "uploaded vault content failed identity or plaintext-size verification",
            ));
        }
        trace_vault_upload_stage("post_put_metadata_verified", None);
        Ok(entry)
    }

    fn url_for_physical(&self, state: &RootState, physical: &str) -> Result<Url, CloudError> {
        let root = Url::parse(&state.space_dav_root)
            .map_err(|_| invalid("vault Space DAV root is invalid"))?;
        let url = super::append_logical_path(&root, physical)?;
        if !same_origin(&self.client.server, &url) {
            return Err(invalid(
                "vault request URL is outside the authenticated origin",
            ));
        }
        Ok(url)
    }

    fn download_vault(
        &self,
        state: &RootState,
        virtual_path: &str,
        expected_etag: Option<&str>,
        destination: &Path,
    ) -> Result<RemoteEntry, CloudError> {
        self.download_vault_inner(state, virtual_path, expected_etag, destination, None, None)
    }

    fn download_vault_with_ciphertext_digest(
        &self,
        state: &RootState,
        virtual_path: &str,
        expected_etag: Option<&str>,
        destination: &Path,
    ) -> Result<(RemoteEntry, String), CloudError> {
        let mut digest = String::new();
        let entry = self.download_vault_inner(
            state,
            virtual_path,
            expected_etag,
            destination,
            None,
            Some(&mut digest),
        )?;
        Ok((entry, digest))
    }

    fn download_vault_for_pin(
        &self,
        state: &RootState,
        virtual_path: &str,
        expected_etag: Option<&str>,
        destination: &Path,
        build: &CiphertextPinBuild,
    ) -> Result<RemoteEntry, CloudError> {
        self.download_vault_inner(
            state,
            virtual_path,
            expected_etag,
            destination,
            Some(build),
            None,
        )
    }

    fn download_vault_inner(
        &self,
        state: &RootState,
        virtual_path: &str,
        expected_etag: Option<&str>,
        destination: &Path,
        pin: Option<&CiphertextPinBuild>,
        capture_ciphertext_digest: Option<&mut String>,
    ) -> Result<RemoteEntry, CloudError> {
        let cache_epoch = pin.map(|build| build.epoch()).or_else(|| {
            self.offline_cache
                .as_ref()
                .and_then(|cache| cache.ciphertext_epoch().ok())
        });
        if virtual_path == "/" {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cannot download the vault root",
            ));
        }
        let before = self.stat_raw(state, virtual_path)?;
        if before.directory {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cannot download a vault directory as a file",
            ));
        }
        if expected_etag.is_some_and(|etag| etag != before.etag) {
            return Err(conflict("vault file changed before download"));
        }
        let ciphertext_len = ciphertext_len_from_plaintext(before.size)?;
        if ciphertext_len > ciphertext_len_from_plaintext(MAX_VAULT_PLAINTEXT_BYTES)? {
            return Err(invalid("vault ciphertext exceeds its transfer size limit"));
        }
        if pin.is_some() {
            if let Some(cache) = &self.offline_cache {
                cache.preflight_ciphertext_space(ciphertext_len)?;
            }
        }
        let url = self.target_url(state, virtual_path)?;
        let destination_parent = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let temp = tempfile::tempdir_in(destination_parent).map_err(io_error)?;
        let ciphertext_path = temp.path().join("ciphertext.bin");
        let mut ciphertext = NamedTempFile::new_in(temp.path()).map_err(io_error)?;
        let output = ciphertext.as_file().try_clone().map_err(io_error)?;
        let (request, token) = self.client.request_async(Method::GET, &url)?;
        let budget = self.client.transfer_budget();
        let cancellation = budget.cancellation();
        let watchdog_cancellation = cancellation.clone();
        let total_timeout = crate::transfer_timeout_with_budget(
            &budget,
            TransferDirection::Download,
            ciphertext_len,
        );
        let expected_etag = before.etag.clone();
        let copied = crate::async_body::run_body_operation_cancellable(
            self.client.body_idle_timeout(),
            total_timeout,
            || watchdog_cancellation.is_cancelled(),
            move |progress| async move {
                let response = request
                    .header(IF_MATCH, expected_etag.as_str())
                    .timeout(total_timeout)
                    .send()
                    .await
                    .map_err(network)?;
                let mut response = crate::checked_async(response, &[StatusCode::OK], &token)?;
                if response.content_length() != Some(ciphertext_len) {
                    return Err(conflict("vault ciphertext size changed during download"));
                }
                let mut output = tokio::fs::File::from_std(output);
                let copied = crate::async_body::copy_response_body(
                    &mut response,
                    &mut output,
                    ciphertext_len,
                    &budget,
                    || cancellation.is_cancelled(),
                    &progress,
                )
                .await?;
                use tokio::io::AsyncWriteExt;
                output.flush().await.map_err(io_error)?;
                output.sync_all().await.map_err(io_error)?;
                Ok(copied)
            },
        )?;
        if copied != ciphertext_len {
            return Err(invalid(
                "vault ciphertext length did not match its metadata",
            ));
        }
        ciphertext.as_file_mut().flush().map_err(io_error)?;
        ciphertext.as_file().sync_all().map_err(io_error)?;
        ciphertext
            .persist(&ciphertext_path)
            .map_err(|error| io_error(error.error))?;

        let ciphertext_digest = if capture_ciphertext_digest.is_some() {
            Some(sha256_file(&ciphertext_path)?)
        } else {
            None
        };

        let fresh_state = self.revalidate_root()?;
        let after = self.stat_raw(&fresh_state, virtual_path)?;
        if after.id != before.id || after.etag != before.etag || after.size != before.size {
            return Err(conflict("vault file changed during download"));
        }
        let placeholder = NamedTempFile::new_in(destination_parent).map_err(io_error)?;
        let plaintext_path = placeholder.into_temp_path();
        fs::remove_file(&plaintext_path).map_err(io_error)?;
        let mut input = File::open(&ciphertext_path).map_err(io_error)?;
        let decrypted_len = self
            .sessions
            .decrypt_file_transactional(
                &self.scope,
                &mut input,
                &plaintext_path,
                MAX_VAULT_PLAINTEXT_BYTES,
                Some(before.size),
            )
            .map_err(vault_error)?;
        if decrypted_len != before.size {
            return Err(invalid("vault plaintext length did not match its metadata"));
        }
        if !self
            .sessions
            .is_unlocked(&self.scope)
            .map_err(vault_error)?
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault session was locked before download publication",
            ));
        }
        if let (Some(output), Some(digest)) = (capture_ciphertext_digest, ciphertext_digest) {
            *output = digest;
        }
        if let (Some(cache), Some(cache_epoch)) = (&self.offline_cache, cache_epoch) {
            // Cache only after exact remote ID/ETag/length checks and a full
            // successful vault decrypt have authenticated every ciphertext
            // block. Cache failure never changes a successful online read.
            if let Some(build) = pin {
                cache.publish_verified_ciphertext_for_pin(
                    &before.id,
                    &before.etag,
                    &ciphertext_path,
                    ciphertext_len,
                    build,
                )?;
            } else {
                let _ = cache.publish_verified_ciphertext(
                    &before.id,
                    &before.etag,
                    &ciphertext_path,
                    ciphertext_len,
                    cache_epoch,
                );
            }
        }
        let output = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&plaintext_path)
            .map_err(io_error)?;
        NamedTempFile::from_parts(output, plaintext_path)
            .persist(destination)
            .map_err(|error| io_error(error.error))?;
        Ok(after)
    }

    fn mkdir_vault(
        &self,
        state: &RootState,
        virtual_path: &str,
    ) -> Result<RemoteEntry, CloudError> {
        if virtual_path == "/" {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "vault root already exists",
            ));
        }
        let (_, siblings) = self.parent_listing(state, virtual_path)?;
        let leaf = virtual_path.rsplit('/').next().unwrap_or_default();
        let encoded = self.encode_new_leaf(&siblings, leaf, None)?;
        let parent = logical_parent(virtual_path);
        let parent_rel = relative_virtual_path(&parent)?;
        let encrypted_parent = self
            .sessions
            .encrypt_path(&self.scope, parent_rel)
            .map_err(vault_error)?;
        let path = if encrypted_parent.is_empty() {
            encoded
        } else {
            format!("{encrypted_parent}/{encoded}")
        };
        let physical = format!("{}/{path}", self.root_path.trim_end_matches('/'));
        let url = self.url_for_physical(state, &physical)?;
        if !self
            .sessions
            .is_unlocked(&self.scope)
            .map_err(vault_error)?
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault session was locked before folder creation",
            ));
        }
        self.revalidate_root()?;
        if let Some(cache) = &self.offline_cache {
            cache.invalidate_before_remote_mutation()?;
        }
        let (request, token) = self
            .client
            .request(Method::from_bytes(b"MKCOL").expect("static method"), &url)?;
        checked(
            request.send().map_err(network)?,
            &[StatusCode::CREATED],
            &token,
        )?;
        let fresh_state = self.revalidate_root()?;
        self.stat_raw(&fresh_state, virtual_path)
    }

    fn delete_vault(
        &self,
        state: &RootState,
        virtual_path: &str,
        expected_etag: &str,
    ) -> Result<(), CloudError> {
        if virtual_path == "/" {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cannot delete the vault root",
            ));
        }
        let current = self.stat_raw(state, virtual_path)?;
        self.verify_item_parent_writable(state, virtual_path, &current.id)?;
        if !state.space.writable || !current.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault item is read only",
            ));
        }
        if current.etag != expected_etag {
            return Err(conflict("vault item changed before delete"));
        }
        let url = self.target_url(state, virtual_path)?;
        self.revalidate_root()?;
        if !self
            .sessions
            .is_unlocked(&self.scope)
            .map_err(vault_error)?
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault session was locked before delete",
            ));
        }
        if let Some(cache) = &self.offline_cache {
            cache.invalidate_before_remote_mutation()?;
        }
        let (request, token) = self.client.request(Method::DELETE, &url)?;
        let response = request
            .header(IF_MATCH, expected_etag)
            .send()
            .map_err(network)?;
        checked(response, &[StatusCode::NO_CONTENT, StatusCode::OK], &token)?;
        Ok(())
    }

    fn rename_vault(
        &self,
        state: &RootState,
        from: &str,
        to: &str,
        expected_etag: &str,
    ) -> Result<RemoteEntry, CloudError> {
        if from == "/" || to == "/" {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cannot rename the vault root",
            ));
        }
        if from == to {
            return self.stat_raw(state, from);
        }
        let source_entry = self.stat_raw(state, from)?;
        self.verify_item_parent_writable(state, from, &source_entry.id)?;
        if !state.space.writable || !source_entry.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault source is read only",
            ));
        }
        if source_entry.etag != expected_etag {
            return Err(conflict("vault source changed before move"));
        }
        let (_, target_siblings) = self.parent_listing(state, to)?;
        let leaf = to.rsplit('/').next().unwrap_or_default();
        let source_parent = logical_parent(from);
        let target_parent = logical_parent(to);
        let exclude = if source_parent == target_parent {
            Some(source_entry.id.as_str())
        } else {
            None
        };
        let encoded_leaf = self.encode_new_leaf(&target_siblings, leaf, exclude)?;
        let target_parent_rel = relative_virtual_path(&target_parent)?;
        let encrypted_parent = self
            .sessions
            .encrypt_path(&self.scope, target_parent_rel)
            .map_err(vault_error)?;
        let encrypted_target = if encrypted_parent.is_empty() {
            encoded_leaf
        } else {
            format!("{encrypted_parent}/{encoded_leaf}")
        };
        let physical = format!(
            "{}/{encrypted_target}",
            self.root_path.trim_end_matches('/')
        );
        let source = self.target_url(state, from)?;
        let destination = self.url_for_physical(state, &physical)?;
        self.revalidate_root()?;
        if !self
            .sessions
            .is_unlocked(&self.scope)
            .map_err(vault_error)?
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault session was locked before move",
            ));
        }
        if let Some(cache) = &self.offline_cache {
            cache.invalidate_before_remote_mutation()?;
        }
        let (request, token) = self
            .client
            .request(Method::from_bytes(b"MOVE").expect("static method"), &source)?;
        let response = request
            .header(IF_MATCH, expected_etag)
            .header("Destination", destination.as_str())
            .header("Overwrite", "F")
            .send()
            .map_err(network)?;
        checked(
            response,
            &[StatusCode::CREATED, StatusCode::NO_CONTENT],
            &token,
        )?;
        let fresh_state = self.revalidate_root()?;
        self.stat_raw(&fresh_state, to)
    }

    fn cached_list(
        &self,
        path: &str,
        visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
        offline_error: CloudError,
    ) -> Result<(), CloudError> {
        let Some(cache) = &self.offline_cache else {
            return Err(offline_error);
        };
        let cached_result = if self.offline_only {
            cache.list_with_cached_permissions(&self.sessions, path)
        } else {
            cache.list(&self.sessions, path)
        };
        let mut entries = match cached_result {
            Ok(entries) => entries,
            Err(error) => {
                let mut overlay = Vec::new();
                self.apply_pending_deletes(path, &mut overlay)?;
                self.apply_pending_renames(path, &mut overlay)?;
                self.append_pending_creates(path, &mut overlay)?;
                self.append_pending_directories(path, &mut overlay)?;
                let pending_directory =
                    self.pending_directory_for_path(path)?
                        .is_some_and(|directory| {
                            matches!(
                                directory.state,
                                CiphertextWriteState::Pending
                                    | CiphertextWriteState::Uncertain
                                    | CiphertextWriteState::NeverAttempted
                                    | CiphertextWriteState::Attempting
                            )
                        });
                if overlay.is_empty() && !pending_directory {
                    return Err(error);
                }
                for entry in overlay {
                    visit(entry)?;
                }
                return Ok(());
            }
        };
        for entry in &mut entries {
            self.overlay_pending_edit(entry)?;
        }
        self.apply_pending_deletes(path, &mut entries)?;
        self.apply_pending_renames(path, &mut entries)?;
        self.append_pending_creates(path, &mut entries)?;
        self.append_pending_directories(path, &mut entries)?;
        for entry in entries {
            visit(entry)?;
        }
        Ok(())
    }

    fn append_pending_creates(
        &self,
        parent_path: &str,
        entries: &mut Vec<RemoteEntry>,
    ) -> Result<(), CloudError> {
        let Some(cache) = &self.offline_cache else {
            return Ok(());
        };
        let (creates, _) = cache.pending_creates_for_parent(&self.sessions, parent_path, 100)?;
        for create in creates {
            if create.state == CiphertextWriteState::Building {
                continue;
            }
            if entries.iter().any(|entry| entry.path == create.path) {
                if create.state != CiphertextWriteState::Conflict {
                    cache.set_pending_edit_state(
                        &create.id,
                        create.revision,
                        CiphertextWriteState::Conflict,
                    )?;
                }
                continue;
            }
            entries.push(pending_create_entry(&create));
        }
        Ok(())
    }

    fn append_pending_directories(
        &self,
        parent_path: &str,
        entries: &mut Vec<RemoteEntry>,
    ) -> Result<(), CloudError> {
        let Some(cache) = &self.offline_cache else {
            return Ok(());
        };
        let (creates, truncated) =
            cache.pending_directories_for_parent(&self.sessions, parent_path, 100)?;
        if truncated {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "too many encrypted directory create records to enumerate safely",
            ));
        }
        for create in creates {
            if let Some(existing) = entries.iter().find(|entry| entry.path == create.path) {
                if create.state == CiphertextWriteState::CommittedReceipt
                    && existing.directory
                    && existing.id == create.receipt_resource_id
                    && existing.etag == create.receipt_etag
                {
                    continue;
                }
                // A listing racing an in-flight MKCOL cannot determine
                // whether the existing object is that request's result.
                if create.state == CiphertextWriteState::Attempting {
                    continue;
                }
                if create.state != CiphertextWriteState::CommittedReceipt {
                    cache.set_pending_edit_state(
                        &create.id,
                        create.revision,
                        CiphertextWriteState::Conflict,
                    )?;
                }
                continue;
            }
            entries.push(pending_directory_entry(&create));
        }
        Ok(())
    }

    fn pending_directory_for_path(
        &self,
        path: &str,
    ) -> Result<Option<VaultPendingEditMetadata>, CloudError> {
        let Some(cache) = &self.offline_cache else {
            return Ok(None);
        };
        let Some(row) = self.pending_edit_for_path(path)? else {
            return Ok(None);
        };
        if row.operation != raiun_cache::CiphertextWriteOperation::CreateDirectory {
            return Ok(None);
        }
        let operation = cache.pending_operation(&self.sessions, &row.id, row.revision)?;
        if operation.path != path
            || operation.operation != VaultPendingOperationKind::CreateDirectory
            || operation.base != WriteCondition::Absent
        {
            return Err(conflict(
                "encrypted directory create path does not match its cache index",
            ));
        }
        Ok(Some(operation))
    }

    fn pending_delete_for_source(
        &self,
        path: &str,
    ) -> Result<Option<VaultPendingEditMetadata>, CloudError> {
        let Some(row) = self.pending_edit_for_path(path)? else {
            return Ok(None);
        };
        if row.operation != raiun_cache::CiphertextWriteOperation::DeleteFile {
            return Ok(None);
        }
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Offline,
                "encrypted delete journal is unavailable",
            )
        })?;
        let operation = cache.pending_operation(&self.sessions, &row.id, row.revision)?;
        if operation.path != path || operation.operation != VaultPendingOperationKind::DeleteFile {
            return Err(conflict(
                "encrypted delete source does not match its cache index",
            ));
        }
        Ok(Some(operation))
    }

    fn apply_pending_deletes(
        &self,
        parent_path: &str,
        entries: &mut Vec<RemoteEntry>,
    ) -> Result<(), CloudError> {
        let Some(cache) = &self.offline_cache else {
            return Ok(());
        };
        let (deletes, truncated) =
            cache.pending_deletes_for_parent(&self.sessions, parent_path, 100)?;
        if truncated {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "too many encrypted delete records to enumerate safely",
            ));
        }
        let mut hidden_sources = Vec::new();
        for operation in deletes {
            if !matches!(
                operation.state,
                CiphertextWriteState::Pending | CiphertextWriteState::Uncertain
            ) {
                continue;
            }
            let Some(entry) = entries.iter().find(|entry| entry.path == operation.path) else {
                continue;
            };
            let parent = self.current_parent_binding(&operation.path)?;
            if entry.directory
                || entry.id != operation.base_resource_id
                || entry.etag != operation.base_etag
                || entry.size != operation.source_size
                || parent.0 != operation.parent_resource_id
                || parent.1 != operation.parent_etag
            {
                cache.set_pending_edit_state(
                    &operation.id,
                    operation.revision,
                    CiphertextWriteState::Conflict,
                )?;
                continue;
            }
            hidden_sources.push(operation.path);
        }
        entries.retain(|entry| !hidden_sources.iter().any(|path| path == &entry.path));
        Ok(())
    }

    fn pending_rename_for_source(
        &self,
        path: &str,
    ) -> Result<Option<VaultPendingEditMetadata>, CloudError> {
        let Some(row) = self.pending_edit_for_path(path)? else {
            return Ok(None);
        };
        if row.operation != raiun_cache::CiphertextWriteOperation::RenameFile {
            return Ok(None);
        }
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Offline,
                "encrypted rename journal is unavailable",
            )
        })?;
        let operation = cache.pending_operation(&self.sessions, &row.id, row.revision)?;
        if operation.path != path || operation.operation != VaultPendingOperationKind::RenameFile {
            return Err(conflict(
                "encrypted rename source does not match its cache index",
            ));
        }
        Ok(Some(operation))
    }

    fn pending_rename_for_destination(
        &self,
        path: &str,
    ) -> Result<Option<VaultPendingEditMetadata>, CloudError> {
        let Some(cache) = &self.offline_cache else {
            return Ok(None);
        };
        cache.pending_rename_for_destination(&self.sessions, path)
    }

    fn overlay_pending_rename_at_destination(
        &self,
        entry: &mut RemoteEntry,
    ) -> Result<bool, CloudError> {
        let Some(rename) = self.pending_rename_for_destination(&entry.path)? else {
            return Ok(false);
        };
        if !matches!(
            rename.state,
            CiphertextWriteState::Pending | CiphertextWriteState::Uncertain
        ) {
            return Ok(false);
        }
        if entry.id == rename.base_resource_id
            && !entry.directory
            && entry.size == rename.source_size
        {
            entry.etag = pending_etag(&rename.id, rename.revision);
            return Ok(true);
        }
        if let Some(cache) = &self.offline_cache {
            cache.set_pending_edit_state(
                &rename.id,
                rename.revision,
                CiphertextWriteState::Conflict,
            )?;
        }
        Ok(false)
    }

    fn apply_pending_renames(
        &self,
        parent_path: &str,
        entries: &mut Vec<RemoteEntry>,
    ) -> Result<(), CloudError> {
        let Some(cache) = &self.offline_cache else {
            return Ok(());
        };
        let (renames, truncated) =
            cache.pending_renames_for_parent(&self.sessions, parent_path, 100)?;
        if truncated {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "too many encrypted rename records to enumerate safely",
            ));
        }
        for mut rename in renames {
            if !matches!(
                rename.state,
                CiphertextWriteState::Pending | CiphertextWriteState::Uncertain
            ) {
                continue;
            }
            if let Some(existing_index) = entries
                .iter()
                .position(|entry| entry.path == rename.destination_path)
            {
                let existing = &entries[existing_index];
                if existing.id == rename.base_resource_id {
                    entries[existing_index].etag = pending_etag(&rename.id, rename.revision);
                    continue;
                }
                cache.set_pending_edit_state(
                    &rename.id,
                    rename.revision,
                    CiphertextWriteState::Conflict,
                )?;
                rename.state = CiphertextWriteState::Conflict;
                continue;
            }
            entries.push(pending_rename_entry(&rename));
        }
        // Hide queued sources after destination collision checks. This keeps
        // a now-conflicting remote destination from concealing the source.
        let mut hidden_sources = Vec::new();
        for entry in entries.iter() {
            let Some(rename) = self.pending_rename_for_source(&entry.path)? else {
                continue;
            };
            if matches!(
                rename.state,
                CiphertextWriteState::Pending | CiphertextWriteState::Uncertain
            ) {
                hidden_sources.push(rename.path);
            }
        }
        entries.retain(|entry| !hidden_sources.iter().any(|path| path == &entry.path));
        Ok(())
    }

    fn pending_create_for_path(
        &self,
        path: &str,
    ) -> Result<Option<VaultPendingEditMetadata>, CloudError> {
        let Some(row) = self.pending_edit_for_path(path)? else {
            return Ok(None);
        };
        if row.operation != raiun_cache::CiphertextWriteOperation::CreateFile {
            return Ok(None);
        }
        let cache = self.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Offline,
                "encrypted create journal is unavailable",
            )
        })?;
        let create = cache.pending_operation(&self.sessions, &row.id, row.revision)?;
        if create.path != path || create.operation != VaultPendingOperationKind::CreateFile {
            return Err(conflict(
                "encrypted create path does not match its cache index",
            ));
        }
        if create.state == CiphertextWriteState::Building {
            return Ok(None);
        }
        Ok(Some(create))
    }

    fn cached_stat(
        &self,
        path: &str,
        offline_error: CloudError,
    ) -> Result<RemoteEntry, CloudError> {
        let Some(cache) = &self.offline_cache else {
            return Err(offline_error);
        };
        if let Some(delete) = self.pending_delete_for_source(path)?
            && matches!(
                delete.state,
                CiphertextWriteState::Pending | CiphertextWriteState::Uncertain
            )
        {
            return Err(CloudError::new(
                ErrorKind::NotFound,
                "file is deleted locally",
            ));
        }
        let mut entry = if self.offline_only {
            match cache.stat_with_cached_permissions(&self.sessions, path) {
                Ok(entry) => entry,
                Err(error) if error.kind == ErrorKind::NotFound => {
                    if let Some(create) = self.pending_create_for_path(path)? {
                        return Ok(pending_create_entry(&create));
                    }
                    if let Some(create) = self.pending_directory_for_path(path)? {
                        return Ok(pending_directory_entry(&create));
                    }
                    if let Some(rename) = self.pending_rename_for_destination(path)?
                        && matches!(
                            rename.state,
                            CiphertextWriteState::Pending | CiphertextWriteState::Uncertain
                        )
                    {
                        return Ok(pending_rename_entry(&rename));
                    }
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        } else {
            match cache.stat(&self.sessions, path) {
                Ok(entry) => entry,
                Err(error) if error.kind == ErrorKind::NotFound => {
                    if let Some(create) = self.pending_create_for_path(path)? {
                        return Ok(pending_create_entry(&create));
                    }
                    if let Some(create) = self.pending_directory_for_path(path)? {
                        return Ok(pending_directory_entry(&create));
                    }
                    if let Some(rename) = self.pending_rename_for_destination(path)?
                        && matches!(
                            rename.state,
                            CiphertextWriteState::Pending | CiphertextWriteState::Uncertain
                        )
                    {
                        return Ok(pending_rename_entry(&rename));
                    }
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        };
        if let Some(create) = self.pending_directory_for_path(path)?
            && !matches!(
                create.state,
                CiphertextWriteState::CommittedReceipt | CiphertextWriteState::Attempting
            )
        {
            if let Some(cache) = &self.offline_cache {
                cache.set_pending_edit_state(
                    &create.id,
                    create.revision,
                    CiphertextWriteState::Conflict,
                )?;
            }
        }
        if self.overlay_pending_rename_at_destination(&mut entry)? {
            return Ok(entry);
        }
        if let Some(rename) = self.pending_rename_for_source(path)?
            && matches!(
                rename.state,
                CiphertextWriteState::Pending | CiphertextWriteState::Uncertain
            )
        {
            return Err(CloudError::new(
                ErrorKind::NotFound,
                "file is renamed locally",
            ));
        }
        if let Some(delete) = self.pending_delete_for_source(path)?
            && matches!(
                delete.state,
                CiphertextWriteState::Pending | CiphertextWriteState::Uncertain
            )
        {
            return Err(CloudError::new(
                ErrorKind::NotFound,
                "file is deleted locally",
            ));
        }
        self.overlay_pending_edit(&mut entry)?;
        Ok(entry)
    }

    fn cached_download(
        &self,
        path: &str,
        expected_etag: Option<&str>,
        destination: &Path,
        offline_error: CloudError,
    ) -> Result<RemoteEntry, CloudError> {
        let Some(cache) = &self.offline_cache else {
            return Err(offline_error);
        };
        if let Some(rename) = cache.pending_rename_for_destination(&self.sessions, path)?
            && matches!(
                rename.state,
                CiphertextWriteState::Pending | CiphertextWriteState::Uncertain
            )
        {
            let pending_version = pending_etag(&rename.id, rename.revision);
            if expected_etag.is_some_and(|expected| expected != pending_version) {
                return Err(conflict("cached encrypted rename version does not match"));
            }
            let entry = cache.download(
                &self.sessions,
                &rename.path,
                Some(&rename.base_etag),
                destination,
            )?;
            if entry.id != rename.base_resource_id || entry.size != rename.source_size {
                return Err(conflict("cached encrypted rename source identity changed"));
            }
            return Ok(RemoteEntry {
                path: rename.destination_path,
                etag: pending_version,
                ..entry
            });
        }
        if let Some(edit) = self.pending_edit_for_path(path)? {
            let pending_version = pending_etag(&edit.id, edit.revision);
            if expected_etag.is_some_and(|expected| expected != pending_version) {
                return Err(conflict("cached encrypted edit version does not match"));
            }
            let details = cache.pending_operation(&self.sessions, &edit.id, edit.revision)?;
            if details.path != path || details.state == CiphertextWriteState::Building {
                return Err(conflict("encrypted edit target does not match this file"));
            }
            let recovered = cache.download_pending_edit(
                &self.sessions,
                &edit.id,
                edit.revision,
                destination,
            )?;
            if details.operation == VaultPendingOperationKind::CreateFile {
                return Ok(pending_create_entry(&details));
            }
            if details.operation == VaultPendingOperationKind::DeleteFile {
                return cache.download(&self.sessions, path, expected_etag, destination);
            }
            let mut entry = cache.stat(&self.sessions, path)?;
            entry.etag = pending_version;
            entry.size = recovered.plaintext_len;
            return Ok(entry);
        }
        cache.download(&self.sessions, path, expected_etag, destination)
    }

    fn pending_edit_for_path(&self, path: &str) -> Result<Option<CiphertextWriteInfo>, CloudError> {
        let Some(cache) = &self.offline_cache else {
            return Ok(None);
        };
        cache.pending_edit_ref_for_path(&self.sessions, path)
    }

    fn overlay_pending_edit(&self, entry: &mut RemoteEntry) -> Result<(), CloudError> {
        if let Some(edit) = self.pending_edit_for_path(&entry.path)? {
            if edit.operation == raiun_cache::CiphertextWriteOperation::CreateFile {
                if edit.state != CiphertextWriteState::Conflict {
                    if let Some(cache) = &self.offline_cache {
                        cache.set_pending_edit_state(
                            &edit.id,
                            edit.revision,
                            CiphertextWriteState::Conflict,
                        )?;
                    }
                }
                return Ok(());
            }
            if edit.operation == raiun_cache::CiphertextWriteOperation::RenameFile {
                return Ok(());
            }
            if edit.operation == raiun_cache::CiphertextWriteOperation::DeleteFile {
                return Ok(());
            }
            entry.etag = pending_etag(&edit.id, edit.revision);
            entry.size = edit.plaintext_len;
        }
        Ok(())
    }
}

impl CloudBackend for VaultBackend {
    fn spaces(&self) -> Result<Vec<CloudSpace>, CloudError> {
        if self.offline_only {
            let snapshot = self
                .offline_root
                .as_ref()
                .ok_or_else(|| invalid("offline vault root snapshot is unavailable"))?;
            return Ok(vec![CloudSpace {
                id: self.scope.space_id().to_owned(),
                name: snapshot.space_name.clone(),
                dav_url: snapshot.space_dav_url.clone(),
                personal: snapshot.space_personal,
                writable: false,
                encrypted: false,
            }]);
        }
        let state = match self.revalidate_root() {
            Ok(state) => state,
            Err(error) if error.kind == ErrorKind::Offline => {
                if let Some(snapshot) = &self.offline_root {
                    return Ok(vec![CloudSpace {
                        id: self.scope.space_id().to_owned(),
                        name: snapshot.space_name.clone(),
                        dav_url: snapshot.space_dav_url.clone(),
                        personal: snapshot.space_personal,
                        writable: snapshot.space_writable,
                        encrypted: false,
                    }]);
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let mut virtual_space = state.space;
        virtual_space.encrypted = false;
        Ok(vec![virtual_space])
    }

    fn list(
        &self,
        space: &str,
        path: &str,
        visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
    ) -> Result<(), CloudError> {
        self.check_space(space)?;
        let path = normalize_virtual_path(path)?;
        validate_virtual_path(&path)?;
        if self
            .pending_directory_for_path(&path)?
            .is_some_and(|directory| {
                matches!(
                    directory.state,
                    CiphertextWriteState::Pending
                        | CiphertextWriteState::Uncertain
                        | CiphertextWriteState::NeverAttempted
                        | CiphertextWriteState::Attempting
                )
            })
        {
            // A pending directory may already have pending children. Use the
            // cached listing when present and overlay those child operations;
            // if it has no listing row, cached_list returns the local overlay
            // (which may be empty) for this exact pending node.
            return self.cached_list(
                &path,
                visit,
                CloudError::new(
                    ErrorKind::Offline,
                    "encrypted directory is awaiting remote creation",
                ),
            );
        }
        if self.offline_only {
            return self.cached_list(
                &path,
                visit,
                invalid("offline vault listing is unavailable"),
            );
        }
        let state = match self.revalidate_root() {
            Ok(state) => state,
            Err(error) if error.kind == ErrorKind::Offline => {
                return self.cached_list(&path, visit, error);
            }
            Err(error) => return Err(error),
        };
        let mut entries = Vec::new();
        match self.list_raw(&state, &path, &mut |entry| {
            entries.push(entry);
            Ok(())
        }) {
            Err(error) if error.kind == ErrorKind::Offline => {
                if self.pending_directory_for_path(&path)?.is_some() {
                    return Ok(());
                }
                self.cached_list(&path, visit, error)
            }
            Err(error) => Err(error),
            Ok(()) => {
                for entry in &mut entries {
                    self.overlay_pending_edit(entry)?;
                }
                self.apply_pending_deletes(&path, &mut entries)?;
                self.apply_pending_renames(&path, &mut entries)?;
                self.append_pending_creates(&path, &mut entries)?;
                self.append_pending_directories(&path, &mut entries)?;
                for entry in entries {
                    visit(entry)?;
                }
                Ok(())
            }
        }
    }

    fn stat(&self, space: &str, path: &str) -> Result<RemoteEntry, CloudError> {
        self.check_space(space)?;
        let path = normalize_virtual_path(path)?;
        validate_virtual_path(&path)?;
        if self.offline_only {
            return self.cached_stat(&path, invalid("offline vault metadata is unavailable"));
        }
        if let Some(delete) = self.pending_delete_for_source(&path)?
            && matches!(
                delete.state,
                CiphertextWriteState::Pending | CiphertextWriteState::Uncertain
            )
        {
            return Err(CloudError::new(
                ErrorKind::NotFound,
                "file is deleted locally",
            ));
        }
        let state = match self.revalidate_root() {
            Ok(state) => state,
            Err(error) if error.kind == ErrorKind::Offline => {
                return self.cached_stat(&path, error);
            }
            Err(error) => return Err(error),
        };
        match self.stat_raw(&state, &path) {
            Err(error) if error.kind == ErrorKind::Offline => self.cached_stat(&path, error),
            Err(error) if error.kind == ErrorKind::NotFound => {
                if let Some(create) = self.pending_create_for_path(&path)? {
                    Ok(pending_create_entry(&create))
                } else if let Some(create) = self.pending_directory_for_path(&path)? {
                    Ok(pending_directory_entry(&create))
                } else if let Some(rename) = self.pending_rename_for_destination(&path)?
                    && matches!(
                        rename.state,
                        CiphertextWriteState::Pending | CiphertextWriteState::Uncertain
                    )
                {
                    Ok(pending_rename_entry(&rename))
                } else {
                    Err(error)
                }
            }
            Ok(mut entry) => {
                if let Some(create) = self.pending_directory_for_path(&path)?
                    && !matches!(
                        create.state,
                        CiphertextWriteState::CommittedReceipt | CiphertextWriteState::Attempting
                    )
                {
                    if let Some(cache) = &self.offline_cache {
                        cache.set_pending_edit_state(
                            &create.id,
                            create.revision,
                            CiphertextWriteState::Conflict,
                        )?;
                    }
                }
                if self.overlay_pending_rename_at_destination(&mut entry)? {
                    return Ok(entry);
                }
                if let Some(rename) = self.pending_rename_for_source(&path)?
                    && matches!(
                        rename.state,
                        CiphertextWriteState::Pending | CiphertextWriteState::Uncertain
                    )
                {
                    return Err(CloudError::new(
                        ErrorKind::NotFound,
                        "file is renamed locally",
                    ));
                }
                self.overlay_pending_edit(&mut entry)?;
                Ok(entry)
            }
            Err(error) => Err(error),
        }
    }

    fn download(
        &self,
        space: &str,
        path: &str,
        expected_etag: Option<&str>,
        destination: &Path,
    ) -> Result<RemoteEntry, CloudError> {
        self.check_space(space)?;
        let path = normalize_virtual_path(path)?;
        validate_virtual_path(&path)?;
        if let Some(rename) = self.pending_rename_for_source(&path)?
            && matches!(
                rename.state,
                CiphertextWriteState::Pending | CiphertextWriteState::Uncertain
            )
        {
            return Err(CloudError::new(
                ErrorKind::NotFound,
                "file is renamed locally",
            ));
        }
        if let Some(delete) = self.pending_delete_for_source(&path)?
            && matches!(
                delete.state,
                CiphertextWriteState::Pending | CiphertextWriteState::Uncertain
            )
        {
            return Err(CloudError::new(
                ErrorKind::NotFound,
                "file is deleted locally",
            ));
        }
        if let Some((id, revision)) = expected_etag.and_then(parse_pending_etag) {
            let cache = self.offline_cache.as_ref().ok_or_else(|| {
                CloudError::new(ErrorKind::NotFound, "encrypted edit is unavailable")
            })?;
            let edit = cache.pending_operation(&self.sessions, id, revision)?;
            if edit.state == CiphertextWriteState::Building {
                return Err(conflict("encrypted edit does not match this file"));
            }
            if edit.operation == VaultPendingOperationKind::DeleteFile {
                return Err(conflict("encrypted delete has no readable pending version"));
            }
            if edit.operation == VaultPendingOperationKind::RenameFile {
                if edit.destination_path != path {
                    return Err(conflict("encrypted rename does not match this file"));
                }
                let result = if self.offline_only {
                    cache.download(
                        &self.sessions,
                        &edit.path,
                        Some(&edit.base_etag),
                        destination,
                    )
                } else {
                    match self.revalidate_root() {
                        Ok(state) => match self.download_vault(
                            &state,
                            &edit.destination_path,
                            Some(&edit.base_etag),
                            destination,
                        ) {
                            Err(error) if error.kind == ErrorKind::Offline => cache.download(
                                &self.sessions,
                                &edit.path,
                                Some(&edit.base_etag),
                                destination,
                            ),
                            result => result,
                        },
                        Err(error) if error.kind == ErrorKind::Offline => cache.download(
                            &self.sessions,
                            &edit.path,
                            Some(&edit.base_etag),
                            destination,
                        ),
                        Err(error) => Err(error),
                    }
                }?;
                if result.id != edit.base_resource_id || result.size != edit.source_size {
                    return Err(conflict("encrypted rename content identity changed"));
                }
                return Ok(RemoteEntry {
                    path: edit.destination_path,
                    etag: pending_etag(id, revision),
                    ..result
                });
            }
            if edit.path != path {
                return Err(conflict("encrypted edit does not match this file"));
            }
            let recovered =
                cache.download_pending_edit(&self.sessions, id, revision, destination)?;
            if edit.operation == VaultPendingOperationKind::CreateFile {
                return Ok(pending_create_entry(&edit));
            }
            let mut entry =
                self.cached_base_entry(&path, &WriteCondition::Match(edit.base_etag))?;
            entry.etag = pending_etag(id, revision);
            entry.size = recovered.plaintext_len;
            return Ok(entry);
        }
        if self.offline_only {
            return self.cached_download(
                &path,
                expected_etag,
                destination,
                invalid("offline vault content is unavailable"),
            );
        }
        let state = match self.revalidate_root() {
            Ok(state) => state,
            Err(error) if error.kind == ErrorKind::Offline => {
                return self.cached_download(&path, expected_etag, destination, error);
            }
            Err(error) => return Err(error),
        };
        match self.download_vault(&state, &path, expected_etag, destination) {
            Err(error) if error.kind == ErrorKind::Offline => {
                self.cached_download(&path, expected_etag, destination, error)
            }
            result => result,
        }
    }

    fn upload(
        &self,
        space: &str,
        path: &str,
        source: &Path,
        condition: WriteCondition,
    ) -> Result<RemoteEntry, CloudError> {
        self.check_space(space)?;
        if self.offline_only {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "offline encrypted vault access is read only",
            ));
        }
        let path = normalize_virtual_path(path)?;
        validate_virtual_path(&path)?;
        let state = self.revalidate_root()?;
        self.put_vault(&state, &path, source, condition)
    }

    fn mkdir(&self, space: &str, path: &str) -> Result<RemoteEntry, CloudError> {
        self.check_space(space)?;
        if self.offline_only {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "offline encrypted vault access is read only",
            ));
        }
        let path = normalize_virtual_path(path)?;
        validate_virtual_path(&path)?;
        let state = self.revalidate_root()?;
        self.mkdir_vault(&state, &path)
    }

    fn delete(&self, space: &str, path: &str, expected_etag: &str) -> Result<(), CloudError> {
        self.check_space(space)?;
        if self.offline_only {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "offline encrypted vault access is read only",
            ));
        }
        let path = normalize_virtual_path(path)?;
        validate_virtual_path(&path)?;
        let state = self.revalidate_root()?;
        self.delete_vault(&state, &path, expected_etag)
    }

    fn rename(
        &self,
        space: &str,
        from: &str,
        to: &str,
        expected_etag: &str,
    ) -> Result<RemoteEntry, CloudError> {
        self.check_space(space)?;
        if self.offline_only {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "offline encrypted vault access is read only",
            ));
        }
        let from = normalize_virtual_path(from)?;
        let to = normalize_virtual_path(to)?;
        validate_virtual_path(&from)?;
        validate_virtual_path(&to)?;
        let state = self.revalidate_root()?;
        self.rename_vault(&state, &from, &to, expected_etag)
    }
}

struct RootState {
    space: CloudSpace,
    space_dav_root: String,
    integrity_token: String,
    root_etag: Option<String>,
}

fn validate_root_path(path: &str) -> Result<(), CloudError> {
    super::validate_logical_path(path)?;
    Ok(())
}

fn validate_dav_space_binding(
    expected_origin: &str,
    space_url: &Url,
    dav_root: &Url,
) -> Result<(), CloudError> {
    let safe_url = |url: &Url| {
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.origin().ascii_serialization() == expected_origin
    };
    if !safe_url(space_url) || !safe_url(dav_root) {
        return Err(invalid(
            "cached vault DAV binding is outside its server origin",
        ));
    }
    let space_path = ensure_trailing_slash(space_url.clone())?;
    let dav_path = ensure_trailing_slash(dav_root.clone())?;
    if !dav_path.path().starts_with(space_path.path()) {
        return Err(invalid(
            "cached vault DAV root is outside its selected Space path",
        ));
    }
    Ok(())
}

fn normalize_root_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn normalize_virtual_path(path: &str) -> Result<String, CloudError> {
    validate_virtual_path(path)?;
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        Ok("/".to_owned())
    } else {
        Ok(trimmed.to_owned())
    }
}

fn validate_virtual_path(path: &str) -> Result<(), CloudError> {
    super::validate_logical_path(path)?;
    if path != "/" {
        let trimmed = path.strip_suffix('/').unwrap_or(path);
        if trimmed.len() < 2
            || trimmed[1..]
                .split('/')
                .any(|component| component.is_empty())
        {
            return Err(invalid("vault path contains an empty component"));
        }
    }
    Ok(())
}

fn relative_virtual_path(path: &str) -> Result<&str, CloudError> {
    validate_virtual_path(path)?;
    if path == "/" {
        Ok("")
    } else {
        Ok(path.strip_prefix('/').expect("validated absolute path"))
    }
}

fn relative_physical_path<'a>(root: &str, path: &'a str) -> Result<&'a str, CloudError> {
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return path
            .strip_prefix('/')
            .ok_or_else(|| invalid("vault physical path escaped its root"));
    }
    path.strip_prefix(root)
        .and_then(|tail| tail.strip_prefix('/'))
        .ok_or_else(|| invalid("vault physical path escaped its root"))
}

fn logical_parent(path: &str) -> String {
    match path.rsplit_once('/') {
        Some(("", _)) | None => "/".to_owned(),
        Some((parent, _)) => parent.to_owned(),
    }
}

fn plaintext_len_from_ciphertext(ciphertext_size: u64) -> Result<u64, CloudError> {
    const HEADER: u64 = 32;
    const PLAIN_BLOCK: u64 = 65_536;
    const CIPHER_BLOCK: u64 = PLAIN_BLOCK + 16;
    let payload = ciphertext_size
        .checked_sub(HEADER)
        .ok_or_else(|| invalid("vault ciphertext is shorter than its header"))?;
    if payload == 0 {
        return Ok(0);
    }
    let full_blocks = payload / CIPHER_BLOCK;
    let remainder = payload % CIPHER_BLOCK;
    if remainder == 0 {
        return full_blocks
            .checked_mul(PLAIN_BLOCK)
            .ok_or_else(|| invalid("vault file size overflow"));
    }
    if remainder < 16 {
        return Err(invalid("vault ciphertext has an invalid block length"));
    }
    full_blocks
        .checked_mul(PLAIN_BLOCK)
        .and_then(|size| size.checked_add(remainder - 16))
        .ok_or_else(|| invalid("vault file size overflow"))
}

fn ciphertext_len_from_plaintext(plaintext_size: u64) -> Result<u64, CloudError> {
    const HEADER: u64 = 32;
    const PLAIN_BLOCK: u64 = 65_536;
    let blocks = if plaintext_size == 0 {
        0
    } else {
        plaintext_size
            .checked_add(PLAIN_BLOCK - 1)
            .ok_or_else(|| invalid("vault file size overflow"))?
            / PLAIN_BLOCK
    };
    HEADER
        .checked_add(plaintext_size)
        .and_then(|size| size.checked_add(blocks.checked_mul(16)?))
        .ok_or_else(|| invalid("vault file size overflow"))
}

fn ensure_trailing_slash(mut root: Url) -> Result<Url, CloudError> {
    if !root.path().ends_with('/') {
        root.path_segments_mut()
            .map_err(|_| invalid("Space DAV root cannot contain a path"))?
            .push("");
    }
    Ok(root)
}

fn vault_error(error: impl std::fmt::Display) -> CloudError {
    CloudError::new(ErrorKind::InvalidResponse, error.to_string())
}

#[cfg(test)]
mod cached_dav_binding_tests {
    use super::*;

    #[test]
    fn cached_dav_root_must_remain_under_the_exact_space_url_and_origin() {
        let origin = "https://cloud.example";
        let space = Url::parse("https://cloud.example/remote.php/dav/spaces/space-a/").unwrap();
        let root = Url::parse("https://cloud.example/remote.php/dav/spaces/space-a/Travel.vault/")
            .unwrap();
        assert!(validate_dav_space_binding(origin, &space, &root).is_ok());

        let escaped = Url::parse("https://cloud.example/remote.php/dav/spaces/space-b/").unwrap();
        assert!(validate_dav_space_binding(origin, &space, &escaped).is_err());
        let foreign = Url::parse("https://other.example/remote.php/dav/spaces/space-a/").unwrap();
        assert!(validate_dav_space_binding(origin, &foreign, &root).is_err());
        let credentialed =
            Url::parse("https://user@cloud.example/remote.php/dav/spaces/space-a/").unwrap();
        assert!(validate_dav_space_binding(origin, &credentialed, &root).is_err());
    }
}

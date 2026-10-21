//! Revocable read and optional write access to one mounted encrypted-vault route.
//!
//! This module is foundational only: it does not attach routes to the FUSE tree.
//! Callers must run every FUSE reply inside [`VaultRouteControl::with_read_lease`]
//! so revocation waits until the reply has been emitted.

use std::{
    collections::{BTreeMap, HashMap},
    io::{Read, Seek, SeekFrom},
    sync::{
        Arc, Mutex, RwLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use crate::vault_write::{
    PendingVaultDirectoryRetarget, VaultParentRef, VaultWriteScope, VaultWriteTarget,
    VerifiedCreateContent,
};
use raiun_core::backend::{CloudError, ErrorKind, RemoteEntry, WriteCondition};

pub const MAX_VAULT_READ_CHUNK: usize = 1024 * 1024;
pub const MAX_VAULT_OPEN_HANDLES: usize = 2_048;
pub const MAX_VAULT_DIRECTORY_ENTRIES: usize = 10_000;

static NEXT_ROUTE_ID: AtomicU64 = AtomicU64::new(1);
pub type VaultRevokeCallback = Arc<dyn Fn() -> Result<(), CloudError> + Send + Sync>;
pub type VaultInstallCallback = Arc<dyn Fn() -> Result<(), CloudError> + Send + Sync>;

/// A seekable plaintext reader owned by a route and dropped when it is revoked.
pub trait VaultReadStream: Read + Seek + Send {}
impl<T: Read + Seek + Send> VaultReadStream for T {}

/// Minimal read-only interface implemented by a scope-bound vault backend.
///
/// Implementations must enforce the vault's account/server/Space/root binding
/// and revalidate its remote root before returning data. This trait intentionally
/// has no mutation methods.
/// Authenticated current CreateFile row for crash recovery. Only a row whose
/// journal and full content digest were verified may authorize a local manifest
/// retarget; lifecycle and digest are explicit so uncertain rows fail closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPendingCreateResolution {
    pub scope: VaultWriteScope,
    pub target: VaultWriteTarget,
    pub write_id: String,
    pub revision: u64,
    pub path: String,
    pub plaintext_bytes: u64,
    pub plaintext_sha256: Option<String>,
    pub never_attempted: bool,
}

/// State of the authenticated backend cancellation receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultCancelledCreateReceiptState {
    Cancelled,
    Acknowledged,
}

/// Authenticated backend proof for one exact queued CreateFile cancellation.
/// It carries bounded identity and content-integrity metadata, never body bytes.
/// `original_revision` identifies the operation being cancelled; `current_revision`
/// identifies the receipt envelope, which changes when acknowledgement compacts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultCancelledCreateReceipt {
    pub state: VaultCancelledCreateReceiptState,
    pub scope: VaultWriteScope,
    pub target: VaultWriteTarget,
    pub path: String,
    pub write_id: String,
    pub original_revision: u64,
    pub current_revision: u64,
    pub content: VerifiedCreateContent,
}

pub trait VaultReadBackend: Send + Sync {
    /// Recheck the backing session and scope without returning any data.
    fn authorize(&self) -> Result<(), CloudError>;
    fn list(&self, path: &str) -> Result<Vec<RemoteEntry>, CloudError>;
    fn stat(&self, path: &str) -> Result<RemoteEntry, CloudError>;
    fn open(&self, path: &str) -> Result<Box<dyn VaultReadStream>, CloudError>;
    /// Resolve a current sealed CreateFile operation by exact opaque operation
    /// ID. Implementations must not search by path or infer identity from a
    /// synthetic inode. The default keeps older read backends read-only.
    fn resolve_pending_create(
        &self,
        _write_id: &str,
    ) -> Result<Option<VaultPendingCreateResolution>, CloudError> {
        Err(CloudError::new(
            ErrorKind::Unsupported,
            "encrypted create recovery is unavailable",
        ))
    }
    /// Bind a directory projection to either a stable server resource or an
    /// authenticated pending CreateDirectory operation. Implementations must
    /// never derive pending operation identity from synthetic entry strings.
    fn parent_ref_for_directory(
        &self,
        _path: &str,
        expected_entry_id: &str,
        _expected_entry_etag: &str,
    ) -> Result<VaultParentRef, CloudError> {
        VaultParentRef::stable(expected_entry_id).map_err(|_| {
            CloudError::new(ErrorKind::Conflict, "encrypted parent identity is invalid")
        })
    }
}

/// A bounded plaintext reader borrowed from a durable vault working copy.
/// Implementations must not expose its backing path or file handle.
pub trait VaultWriteSource: Read + Seek + Send {}
impl<T: Read + Seek + Send> VaultWriteSource for T {}

/// A local filesystem write may be durably queued while offline. Callers must
/// preserve the distinction: only `Committed` means the remote conditional PUT
/// and readback completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultUploadOutcome {
    Committed(RemoteEntry),
    Queued {
        entry: RemoteEntry,
        write_id: String,
        revision: u64,
        uncertain: bool,
    },
    /// A queued create still has an original `Absent` condition. The returned
    /// entry is a local projection, not proof that a remote resource exists.
    QueuedCreate {
        entry: RemoteEntry,
        write_id: String,
        revision: u64,
        uncertain: bool,
    },
    /// A durable, non-retryable create intent exists, but no file contents
    /// have been published to the operation journal yet.
    BuildingCreate {
        entry: RemoteEntry,
        write_id: String,
        revision: u64,
    },
}

/// Result of an encrypted file rename. A queued rename is a durable local
/// intent, not evidence that the server moved the resource.
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

/// A local rename of a file whose CreateFile operation is proven never to
/// have reached the server. The backend has retargeted the sealed operation;
/// FUSE must rebind the same durable plaintext working copy before returning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPendingCreateRenameOutcome {
    pub entry: RemoteEntry,
    pub write_id: String,
    pub previous_revision: u64,
    pub revision: u64,
    pub scope: VaultWriteScope,
    pub target: VaultWriteTarget,
}

/// Result of retargeting an exact, empty, never-attempted directory-create
/// intent. The operation remains local and its pending-parent identity changes
/// with the new journal revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPendingDirectoryRenameOutcome {
    pub entry: RemoteEntry,
    pub write_id: String,
    pub previous_revision: u64,
    pub revision: u64,
    pub parent_ref: VaultParentRef,
}

/// One exact journal member in a populated, never-attempted directory
/// subtree retarget. File members carry a matching clean local working copy;
/// directory members are bodyless journal rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPendingDirectorySubtreeRenameRow {
    pub write_id: String,
    pub previous_revision: u64,
    pub revision: u64,
    pub operation: VaultPendingSubtreeOperation,
    pub old_path: String,
    pub path: String,
    pub old_target: Option<VaultWriteTarget>,
    pub target: VaultWriteTarget,
    pub plaintext_len: u64,
    pub plaintext_sha256: String,
    pub parent_ref: VaultParentRef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultPendingSubtreeOperation {
    CreateFile,
    CreateDirectory,
}

/// Authenticated all-or-none backend retarget result for a bounded queued
/// subtree. The row list is also the identity vector persisted in the local
/// retarget WAL before backend mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPendingDirectorySubtreeRenameOutcome {
    pub scope: VaultWriteScope,
    pub root_entry: RemoteEntry,
    pub root_write_id: String,
    pub root_previous_revision: u64,
    pub root_revision: u64,
    pub rows: Vec<VaultPendingDirectorySubtreeRenameRow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultPendingDirectoryRetargetState {
    AllOld,
    AllNew,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPendingDirectoryRetargetResolution {
    pub scope: VaultWriteScope,
    pub state: VaultPendingDirectoryRetargetState,
    pub root_write_id: String,
    pub root_previous_revision: u64,
    pub root_revision: u64,
    /// Current authenticated metadata for every exact operation in the WAL.
    /// `path` is the old path in AllOld and the new path in AllNew.
    pub rows: Vec<VaultPendingDirectorySubtreeRenameRow>,
}

/// Result of deleting one stable existing regular file from a restricted
/// offline vault route. A queued delete is a durable tombstone, not a server
/// deletion; its encrypted recovery reference remains available to the
/// backend until reconciliation is resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VaultDeleteOutcome {
    Committed,
    Queued {
        write_id: String,
        revision: u64,
        uncertain: bool,
    },
}

/// Result of creating one encrypted directory on a restricted offline route.
/// A queued entry is only a local projection of its sealed operation intent;
/// it does not establish remote ownership of an existing same-path object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VaultDirectoryCreateOutcome {
    Committed(RemoteEntry),
    Queued {
        entry: RemoteEntry,
        write_id: String,
        revision: u64,
        uncertain: bool,
    },
}

/// Mutation capability for a verified encrypted-vault route.
///
/// This is installed atomically with the matching read backend. `prepare_target`
/// performs the encrypted-name/collision preflight and returns the exact scope
/// and opaque remote target that FUSE persists in its working-copy record.
pub trait VaultWriteBackend: Send + Sync {
    fn supports_pending_parent_operations(&self) -> bool {
        false
    }

    /// Whether this backend has a durable encrypted operation journal for
    /// create intents. Without it FUSE must keep the route read-only for new
    /// names rather than advertise a create flow that cannot recover.
    fn supports_file_create(&self) -> bool {
        false
    }

    fn prepare_target(
        &self,
        path: &str,
        condition: WriteCondition,
    ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError>;

    fn prepare_file_create(
        &self,
        path: &str,
        _existing: Option<(&str, u64)>,
    ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
        self.prepare_target(path, WriteCondition::Absent)
    }

    fn prepare_file_create_under_parent(
        &self,
        path: &str,
        parent_ref: &VaultParentRef,
        existing: Option<(&str, u64)>,
    ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
        if matches!(parent_ref, VaultParentRef::PendingCreate { .. })
            && !self.supports_pending_parent_operations()
        {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted backend cannot create below an uncommitted directory",
            ));
        }
        let (scope, target) = self.prepare_file_create(path, existing)?;
        let target = VaultWriteTarget::new_with_parent(
            target.opaque_relative_target().to_owned(),
            target.condition().clone(),
            parent_ref.clone(),
        )
        .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "invalid parent binding"))?;
        Ok((scope, target))
    }

    fn upload(
        &self,
        target: &VaultWriteTarget,
        source: &mut dyn VaultWriteSource,
        plaintext_len: u64,
    ) -> Result<VaultUploadOutcome, CloudError>;

    /// Create a regular file with a conditional Absent target. `existing`
    /// identifies a prior queued revision of the same create operation.
    fn create_file(
        &self,
        target: &VaultWriteTarget,
        source: &mut dyn VaultWriteSource,
        plaintext_len: u64,
        _existing: Option<(&str, u64)>,
    ) -> Result<VaultUploadOutcome, CloudError> {
        if !matches!(target.condition(), WriteCondition::Absent) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "encrypted create target lost its absence condition",
            ));
        }
        match self.upload(target, source, plaintext_len)? {
            VaultUploadOutcome::Queued {
                entry,
                write_id,
                revision,
                uncertain,
            } => Ok(VaultUploadOutcome::QueuedCreate {
                entry,
                write_id,
                revision,
                uncertain,
            }),
            outcome => Ok(outcome),
        }
    }

    /// Begin a durable create intent without publishing an empty remote file
    /// or retryable empty body. The caller writes into its private spool and
    /// publishes the first body only on flush/release.
    fn begin_file_create(
        &self,
        _target: &VaultWriteTarget,
    ) -> Result<VaultUploadOutcome, CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit file creation",
        ))
    }

    fn mkdir(&self, path: &str) -> Result<RemoteEntry, CloudError>;
    fn delete(&self, path: &str, expected_etag: &str) -> Result<(), CloudError>;
    fn rename(&self, from: &str, to: &str, expected_etag: &str) -> Result<RemoteEntry, CloudError>;

    fn create_directory_under_parent(
        &self,
        path: &str,
        parent_ref: &VaultParentRef,
    ) -> Result<VaultDirectoryCreateOutcome, CloudError> {
        if matches!(parent_ref, VaultParentRef::PendingCreate { .. }) {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted backend cannot create below an uncommitted directory",
            ));
        }
        self.mkdir(path).map(VaultDirectoryCreateOutcome::Committed)
    }

    fn supports_cancel_directory_create(&self) -> bool {
        false
    }

    fn cancel_never_attempted_directory_create(
        &self,
        _path: &str,
        _write_id: &str,
        _revision: u64,
        _expected_entry_id: &str,
        _expected_entry_etag: &str,
    ) -> Result<(), CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit queued-directory cancellation",
        ))
    }

    /// Whether this backend can retarget an exact never-attempted, empty
    /// directory-create operation without issuing MKCOL or MOVE.
    fn supports_pending_directory_rename(&self) -> bool {
        false
    }

    /// Atomically retarget only the exact authenticated directory intent. The
    /// backend must reject dependent operations, occupied destinations, and
    /// every state other than NeverAttempted.
    fn rename_pending_directory_create(
        &self,
        _from: &str,
        _to: &str,
        _expected_entry_id: &str,
        _expected_entry_etag: &str,
        _destination_parent: &VaultParentRef,
    ) -> Result<VaultPendingDirectoryRenameOutcome, CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit queued-directory rename",
        ))
    }

    fn supports_pending_directory_subtree_rename(&self) -> bool {
        false
    }

    fn rename_pending_directory_subtree(
        &self,
        _from: &str,
        _to: &str,
        _expected_entry_id: &str,
        _expected_entry_etag: &str,
        _destination_parent: &VaultParentRef,
        _before_publish: &mut dyn FnMut(
            &VaultPendingDirectorySubtreeRenameOutcome,
        ) -> Result<(), CloudError>,
    ) -> Result<VaultPendingDirectorySubtreeRenameOutcome, CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit queued-directory subtree rename",
        ))
    }

    fn resolve_pending_directory_subtree_retarget(
        &self,
        _wal: &PendingVaultDirectoryRetarget,
    ) -> Result<VaultPendingDirectoryRetargetResolution, CloudError> {
        Err(CloudError::new(
            ErrorKind::Unsupported,
            "queued-directory subtree recovery is unavailable",
        ))
    }

    fn supports_cancel_file_create(&self) -> bool {
        false
    }

    fn cancel_never_attempted_file_create(
        &self,
        _path: &str,
        _write_id: &str,
        _revision: u64,
        _expected_entry_id: &str,
        _expected_entry_etag: &str,
    ) -> Result<VaultCancelledCreateReceipt, CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit queued-file cancellation",
        ))
    }

    fn resolve_cancelled_file_create(
        &self,
        _write_id: &str,
        _revision: u64,
    ) -> Result<Option<VaultCancelledCreateReceipt>, CloudError> {
        Err(CloudError::new(
            ErrorKind::Unsupported,
            "encrypted queued-file cancellation recovery is unavailable",
        ))
    }

    fn acknowledge_cancelled_file_create(
        &self,
        _write_id: &str,
        _revision: u64,
        _target: &VaultWriteTarget,
        _content: &VerifiedCreateContent,
    ) -> Result<(), CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit cancellation receipt acknowledgement",
        ))
    }

    /// Remove only an exact compact Acknowledged receipt after the caller has
    /// durably removed its matching local cancellation WAL. Failure leaves a
    /// bounded metadata-only receipt for later cleanup.
    fn finalize_cancelled_file_create_ack(
        &self,
        _receipt: &VaultCancelledCreateReceipt,
    ) -> Result<(), CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit cancellation receipt finalization",
        ))
    }
}

/// Narrow capability for offline edits to cached regular files and, when
/// explicitly opted in, creating a regular file or queueing a same-vault file
/// rename under verified cached parents. It omits directory and delete
/// mutations.
pub trait VaultExistingFileOverwriteBackend: Send + Sync {
    fn supports_pending_parent_operations(&self) -> bool {
        false
    }

    fn prepare_existing_target(
        &self,
        path: &str,
        base_resource_id: &str,
        base_etag: &str,
    ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError>;

    fn overwrite(
        &self,
        target: &VaultWriteTarget,
        source: &mut dyn VaultWriteSource,
        plaintext_len: u64,
    ) -> Result<VaultUploadOutcome, CloudError>;

    /// Optional narrow create capability. Existing-file-only routes remain
    /// read/overwrite-only unless the backend explicitly opts in.
    fn supports_file_create(&self) -> bool {
        false
    }

    fn prepare_file_create(
        &self,
        _path: &str,
        _existing: Option<(&str, u64)>,
    ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit file creation",
        ))
    }

    fn prepare_file_create_under_parent(
        &self,
        path: &str,
        parent_ref: &VaultParentRef,
        existing: Option<(&str, u64)>,
    ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
        if matches!(parent_ref, VaultParentRef::PendingCreate { .. })
            && !self.supports_pending_parent_operations()
        {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted backend cannot create below an uncommitted directory",
            ));
        }
        let (scope, target) = self.prepare_file_create(path, existing)?;
        let target = VaultWriteTarget::new_with_parent(
            target.opaque_relative_target().to_owned(),
            target.condition().clone(),
            parent_ref.clone(),
        )
        .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "invalid parent binding"))?;
        Ok((scope, target))
    }

    fn create_file(
        &self,
        _target: &VaultWriteTarget,
        _source: &mut dyn VaultWriteSource,
        _plaintext_len: u64,
        _existing: Option<(&str, u64)>,
    ) -> Result<VaultUploadOutcome, CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit file creation",
        ))
    }

    fn begin_file_create(
        &self,
        _target: &VaultWriteTarget,
    ) -> Result<VaultUploadOutcome, CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit file creation",
        ))
    }

    /// Whether this backend can durably queue a same-vault file rename.
    /// Directory, cross-route, and destination-replacement operations remain
    /// outside this narrow capability.
    fn supports_file_rename(&self) -> bool {
        false
    }

    /// Rename one stable existing regular file. Implementations must recheck
    /// its resource ID/ETag, exact parent identities, and destination absence.
    fn rename_file(
        &self,
        _from: &str,
        _to: &str,
        _expected_source_id: &str,
        _expected_source_etag: &str,
    ) -> Result<VaultRenameOutcome, CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit file rename",
        ))
    }

    /// Whether this route can atomically retarget an exact NeverAttempted
    /// CreateFile journal operation without sending a remote mutation.
    fn supports_pending_create_rename(&self) -> bool {
        false
    }

    /// Coalesce a never-attempted queued create into a new logical path. The
    /// implementation must authenticate the exact synthetic source identity,
    /// verify destination absence and parent identity, and preserve the body.
    fn rename_pending_create(
        &self,
        _from: &str,
        _to: &str,
        _expected_source_id: &str,
        _expected_source_etag: &str,
        _destination_parent: &VaultParentRef,
    ) -> Result<VaultPendingCreateRenameOutcome, CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit pending-create rename",
        ))
    }

    /// Whether this backend can durably queue a same-vault regular-file
    /// deletion while retaining an exact recovery reference to its content.
    fn supports_file_delete(&self) -> bool {
        false
    }

    /// Delete one stable existing regular file. Implementations must bind the
    /// intent to the current root and parent identity, and use the source ID
    /// and ETag for any conditional server deletion.
    fn delete_file(
        &self,
        _path: &str,
        _expected_source_id: &str,
        _expected_source_etag: &str,
    ) -> Result<VaultDeleteOutcome, CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit file deletion",
        ))
    }

    /// Whether this restricted route can durably queue one directory creation.
    /// This does not imply directory rename or recursive delete support.
    fn supports_directory_create(&self) -> bool {
        false
    }

    /// Create a directory using an exact-root/parent-bound encrypted intent.
    /// Implementations must require a fresh absent-target check and must not
    /// claim ownership if an uncertain MKCOL is followed by an existing path.
    fn create_directory(&self, _path: &str) -> Result<VaultDirectoryCreateOutcome, CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit directory creation",
        ))
    }

    fn create_directory_under_parent(
        &self,
        path: &str,
        parent_ref: &VaultParentRef,
    ) -> Result<VaultDirectoryCreateOutcome, CloudError> {
        if matches!(parent_ref, VaultParentRef::PendingCreate { .. })
            && !self.supports_pending_parent_operations()
        {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted backend cannot create below an uncommitted directory",
            ));
        }
        self.create_directory(path)
    }

    /// Whether this route can cancel a directory intent only while it is
    /// durably proven never to have reached the server. This is distinct from
    /// deleting a remote directory and must never issue MKCOL or DELETE.
    fn supports_cancel_directory_create(&self) -> bool {
        false
    }

    /// Cancel one exact queued synthetic directory generation. Implementations
    /// must compare the authenticated path, operation ID, revision, and local
    /// entry ID/ETag, and atomically reject any dependent operations. Legacy
    /// Pending, attempted, uncertain, conflicting, or committed rows must fail.
    fn cancel_never_attempted_directory_create(
        &self,
        _path: &str,
        _write_id: &str,
        _revision: u64,
        _expected_entry_id: &str,
        _expected_entry_etag: &str,
    ) -> Result<(), CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit queued-directory cancellation",
        ))
    }

    fn supports_pending_directory_rename(&self) -> bool {
        false
    }

    fn rename_pending_directory_create(
        &self,
        _from: &str,
        _to: &str,
        _expected_entry_id: &str,
        _expected_entry_etag: &str,
        _destination_parent: &VaultParentRef,
    ) -> Result<VaultPendingDirectoryRenameOutcome, CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit queued-directory rename",
        ))
    }

    fn supports_pending_directory_subtree_rename(&self) -> bool {
        false
    }

    fn rename_pending_directory_subtree(
        &self,
        _from: &str,
        _to: &str,
        _expected_entry_id: &str,
        _expected_entry_etag: &str,
        _destination_parent: &VaultParentRef,
        _before_publish: &mut dyn FnMut(
            &VaultPendingDirectorySubtreeRenameOutcome,
        ) -> Result<(), CloudError>,
    ) -> Result<VaultPendingDirectorySubtreeRenameOutcome, CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit queued-directory subtree rename",
        ))
    }

    fn resolve_pending_directory_subtree_retarget(
        &self,
        _wal: &PendingVaultDirectoryRetarget,
    ) -> Result<VaultPendingDirectoryRetargetResolution, CloudError> {
        Err(CloudError::new(
            ErrorKind::Unsupported,
            "queued-directory subtree recovery is unavailable",
        ))
    }

    fn supports_cancel_file_create(&self) -> bool {
        false
    }

    fn cancel_never_attempted_file_create(
        &self,
        _path: &str,
        _write_id: &str,
        _revision: u64,
        _expected_entry_id: &str,
        _expected_entry_etag: &str,
    ) -> Result<VaultCancelledCreateReceipt, CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit queued-file cancellation",
        ))
    }

    fn resolve_cancelled_file_create(
        &self,
        _write_id: &str,
        _revision: u64,
    ) -> Result<Option<VaultCancelledCreateReceipt>, CloudError> {
        Err(CloudError::new(
            ErrorKind::Unsupported,
            "encrypted queued-file cancellation recovery is unavailable",
        ))
    }

    fn acknowledge_cancelled_file_create(
        &self,
        _write_id: &str,
        _revision: u64,
        _target: &VaultWriteTarget,
        _content: &VerifiedCreateContent,
    ) -> Result<(), CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit cancellation receipt acknowledgement",
        ))
    }

    fn finalize_cancelled_file_create_ack(
        &self,
        _receipt: &VaultCancelledCreateReceipt,
    ) -> Result<(), CloudError> {
        Err(CloudError::new(
            ErrorKind::Forbidden,
            "encrypted route does not permit cancellation receipt finalization",
        ))
    }
}

/// Read and offline overwrite capability from one scope-bound backend.
pub trait VaultReadOverwriteBackend: VaultReadBackend + VaultExistingFileOverwriteBackend {}
impl<T: VaultReadBackend + VaultExistingFileOverwriteBackend> VaultReadOverwriteBackend for T {}

/// One inseparable backend binding, so read and write capabilities cannot be
/// installed from different account, origin, Space, or root identities.
pub trait VaultReadWriteBackend: VaultReadBackend + VaultWriteBackend {}
impl<T: VaultReadBackend + VaultWriteBackend> VaultReadWriteBackend for T {}

enum RouteBackend {
    ReadOnly(Arc<dyn VaultReadBackend>),
    ExistingFileOverwrite(Arc<dyn VaultReadOverwriteBackend>),
    ReadWrite(Arc<dyn VaultReadWriteBackend>),
}

impl RouteBackend {
    fn reader(&self) -> &dyn VaultReadBackend {
        match self {
            Self::ReadOnly(backend) => backend.as_ref(),
            Self::ExistingFileOverwrite(backend) => backend.as_ref(),
            Self::ReadWrite(backend) => backend.as_ref(),
        }
    }

    fn writer(&self) -> Option<&dyn VaultWriteBackend> {
        match self {
            Self::ReadOnly(_) | Self::ExistingFileOverwrite(_) => None,
            Self::ReadWrite(backend) => Some(backend.as_ref()),
        }
    }

    fn overwrite_backend(&self) -> Option<&dyn VaultExistingFileOverwriteBackend> {
        match self {
            Self::ExistingFileOverwrite(backend) => Some(backend.as_ref()),
            Self::ReadOnly(_) | Self::ReadWrite(_) => None,
        }
    }

    fn is_writable(&self) -> bool {
        self.writer().is_some()
    }
}

struct RouteState {
    generation: u64,
    backend: Option<RouteBackend>,
}

struct Inner {
    id: u64,
    state: RwLock<RouteState>,
    writable: AtomicBool,
    handles: Mutex<HashMap<u64, Box<dyn VaultReadStream>>>,
    next_handle: AtomicU64,
    max_handles: usize,
    revoke_hooks: Mutex<BTreeMap<u64, VaultRevokeCallback>>,
    install_hooks: Mutex<BTreeMap<u64, VaultInstallCallback>>,
    next_hook: AtomicU64,
}

/// Shared authority for one mounted vault route. Every operation must pass
/// through a generation-checked lease; revocation takes the exclusive gate,
/// drains open readers, and only then invokes the caller's session-lock action.
#[derive(Clone)]
pub struct VaultRouteControl {
    inner: Arc<Inner>,
}

/// Opaque route-owned reader identity. It never exposes the backend or reader.
pub struct VaultReadHandle {
    route_id: u64,
    id: u64,
    generation: u64,
    route: Weak<Inner>,
}

impl VaultRouteControl {
    pub fn new() -> Self {
        Self::with_handle_limit(MAX_VAULT_OPEN_HANDLES)
    }

    /// Construct a route with a smaller handle bound, primarily useful for
    /// mounts with known resource limits and deterministic tests.
    pub fn with_handle_limit(max_handles: usize) -> Self {
        let max_handles = max_handles.clamp(1, MAX_VAULT_OPEN_HANDLES);
        Self {
            inner: Arc::new(Inner {
                id: NEXT_ROUTE_ID.fetch_add(1, Ordering::Relaxed),
                state: RwLock::new(RouteState {
                    generation: 0,
                    backend: None,
                }),
                writable: AtomicBool::new(false),
                handles: Mutex::new(HashMap::new()),
                next_handle: AtomicU64::new(1),
                max_handles,
                revoke_hooks: Mutex::new(BTreeMap::new()),
                install_hooks: Mutex::new(BTreeMap::new()),
                next_hook: AtomicU64::new(1),
            }),
        }
    }

    /// Current route generation. An inactive route still has a generation so
    /// callers can detect the next install/revoke transition.
    pub fn generation(&self) -> Result<u64, CloudError> {
        self.inner
            .state
            .read()
            .map(|state| state.generation)
            .map_err(|_| poisoned("vault route state"))
    }

    pub fn is_active(&self) -> Result<bool, CloudError> {
        self.inner
            .state
            .read()
            .map(|state| state.backend.is_some())
            .map_err(|_| poisoned("vault route state"))
    }

    /// Whether the currently installed generation has a writable capability.
    /// Inactive and read-only generations report `false`.
    pub fn supports_writes(&self) -> Result<bool, CloudError> {
        Ok(self.inner.writable.load(Ordering::Acquire))
    }

    /// Whether this generation supports only overwriting existing files.
    pub fn supports_existing_file_overwrites(&self) -> Result<bool, CloudError> {
        let state = self
            .inner
            .state
            .read()
            .map_err(|_| poisoned("vault route state"))?;
        Ok(state
            .backend
            .as_ref()
            .is_some_and(|backend| backend.overwrite_backend().is_some()))
    }

    /// Whether the installed generation permits creating regular files.
    /// This can be true for a restricted offline route that does not support
    /// general namespace mutations such as mkdir, rename, or delete.
    pub fn supports_file_creates(&self) -> Result<bool, CloudError> {
        let state = self
            .inner
            .state
            .read()
            .map_err(|_| poisoned("vault route state"))?;
        Ok(state.backend.as_ref().is_some_and(|backend| {
            backend
                .writer()
                .is_some_and(VaultWriteBackend::supports_file_create)
                || backend
                    .overwrite_backend()
                    .is_some_and(VaultExistingFileOverwriteBackend::supports_file_create)
        }))
    }

    /// Whether the installed restricted route can queue a same-vault file rename.
    pub fn supports_file_renames(&self) -> Result<bool, CloudError> {
        let state = self
            .inner
            .state
            .read()
            .map_err(|_| poisoned("vault route state"))?;
        Ok(state.backend.as_ref().is_some_and(|backend| {
            backend
                .overwrite_backend()
                .is_some_and(VaultExistingFileOverwriteBackend::supports_file_rename)
        }))
    }

    /// Whether the installed restricted route can queue regular-file deletes.
    pub fn supports_file_deletes(&self) -> Result<bool, CloudError> {
        let state = self
            .inner
            .state
            .read()
            .map_err(|_| poisoned("vault route state"))?;
        Ok(state.backend.as_ref().is_some_and(|backend| {
            backend
                .overwrite_backend()
                .is_some_and(VaultExistingFileOverwriteBackend::supports_file_delete)
        }))
    }

    /// Whether the installed restricted route can queue a directory create.
    pub fn supports_directory_creates(&self) -> Result<bool, CloudError> {
        let state = self
            .inner
            .state
            .read()
            .map_err(|_| poisoned("vault route state"))?;
        Ok(state.backend.as_ref().is_some_and(|backend| {
            backend
                .overwrite_backend()
                .is_some_and(VaultExistingFileOverwriteBackend::supports_directory_create)
        }))
    }

    /// Whether the installed restricted route can cancel a directory creation
    /// that the backend proves was never attempted remotely.
    pub fn supports_cancel_directory_create(&self) -> Result<bool, CloudError> {
        let state = self
            .inner
            .state
            .read()
            .map_err(|_| poisoned("vault route state"))?;
        Ok(state.backend.as_ref().is_some_and(|backend| {
            backend
                .writer()
                .is_some_and(VaultWriteBackend::supports_cancel_directory_create)
                || backend.overwrite_backend().is_some_and(
                    VaultExistingFileOverwriteBackend::supports_cancel_directory_create,
                )
        }))
    }

    pub fn supports_pending_directory_renames(&self) -> Result<bool, CloudError> {
        let state = self
            .inner
            .state
            .read()
            .map_err(|_| poisoned("vault route state"))?;
        Ok(state.backend.as_ref().is_some_and(|backend| {
            backend
                .writer()
                .is_some_and(VaultWriteBackend::supports_pending_directory_rename)
                || backend.overwrite_backend().is_some_and(
                    VaultExistingFileOverwriteBackend::supports_pending_directory_rename,
                )
        }))
    }

    pub fn supports_cancel_file_create(&self) -> Result<bool, CloudError> {
        let state = self
            .inner
            .state
            .read()
            .map_err(|_| poisoned("vault route state"))?;
        Ok(state.backend.as_ref().is_some_and(|backend| {
            backend
                .writer()
                .is_some_and(VaultWriteBackend::supports_cancel_file_create)
                || backend
                    .overwrite_backend()
                    .is_some_and(VaultExistingFileOverwriteBackend::supports_cancel_file_create)
        }))
    }

    pub fn supports_pending_parent_operations(&self) -> Result<bool, CloudError> {
        let state = self
            .inner
            .state
            .read()
            .map_err(|_| poisoned("vault route state"))?;
        Ok(state.backend.as_ref().is_some_and(|backend| {
            backend
                .writer()
                .is_some_and(VaultWriteBackend::supports_pending_parent_operations)
                || backend.overwrite_backend().is_some_and(
                    VaultExistingFileOverwriteBackend::supports_pending_parent_operations,
                )
        }))
    }

    /// Register a mount-cache invalidation hook. Hooks run after the route is
    /// inactive and its readers are dropped, while the exclusive route gate is
    /// still held. They must not call back into this route.
    pub fn register_revoke_hook(
        &self,
        hook: VaultRevokeCallback,
    ) -> Result<VaultRevokeHook, CloudError> {
        let id = self.inner.next_hook.fetch_add(1, Ordering::Relaxed);
        if id == u64::MAX {
            return Err(CloudError::new(
                ErrorKind::Io,
                "vault route hook identifiers exhausted",
            ));
        }
        self.inner
            .revoke_hooks
            .lock()
            .map_err(|_| poisoned("vault route hooks"))?
            .insert(id, hook);
        Ok(VaultRevokeHook {
            route: Arc::downgrade(&self.inner),
            id,
        })
    }

    /// Register a mount-cache invalidation hook run before a new generation is
    /// published. Hooks run under the exclusive route gate and must not call
    /// back into this route. If any hook fails, installation is rejected and
    /// the route remains inactive.
    pub fn register_install_hook(
        &self,
        hook: VaultInstallCallback,
    ) -> Result<VaultInstallHook, CloudError> {
        // Serialize registration against install publication. A callback is
        // therefore either included in the next install's hook snapshot, or
        // registered after that install has fully published its generation.
        let _state = self
            .inner
            .state
            .read()
            .map_err(|_| poisoned("vault route state"))?;
        let id = self.inner.next_hook.fetch_add(1, Ordering::Relaxed);
        if id == u64::MAX {
            return Err(CloudError::new(
                ErrorKind::Io,
                "vault route hook identifiers exhausted",
            ));
        }
        self.inner
            .install_hooks
            .lock()
            .map_err(|_| poisoned("vault route install hooks"))?
            .insert(id, hook);
        Ok(VaultInstallHook {
            route: Arc::downgrade(&self.inner),
            id,
        })
    }

    pub fn route_id(&self) -> u64 {
        self.inner.id
    }

    /// Install a backend for an inactive route and start a fresh generation.
    /// A prior route must first be revoked, which drains its readers.
    pub fn install_backend(&self, backend: Arc<dyn VaultReadBackend>) -> Result<u64, CloudError> {
        self.install(RouteBackend::ReadOnly(backend))
    }

    /// Install matching read and write capabilities in one route generation.
    /// A route is never temporarily exposed writable with another backend's
    /// read identity.
    pub fn install_writable_backend(
        &self,
        backend: Arc<dyn VaultReadWriteBackend>,
    ) -> Result<u64, CloudError> {
        self.install(RouteBackend::ReadWrite(backend))
    }

    /// Install the restricted offline capability. Namespace mutation remains
    /// unavailable because this route variant has no such methods.
    pub fn install_existing_file_overwrite_backend(
        &self,
        backend: Arc<dyn VaultReadOverwriteBackend>,
    ) -> Result<u64, CloudError> {
        self.install(RouteBackend::ExistingFileOverwrite(backend))
    }

    fn install(&self, backend: RouteBackend) -> Result<u64, CloudError> {
        let mut state = self
            .inner
            .state
            .write()
            .map_err(|_| poisoned("vault route state"))?;
        if state.backend.is_some() {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "vault route is already active",
            ));
        }
        let next = state
            .generation
            .checked_add(1)
            .ok_or_else(|| CloudError::new(ErrorKind::Io, "vault route generation exhausted"))?;
        let hooks = self
            .inner
            .install_hooks
            .lock()
            .map_err(|_| poisoned("vault route install hooks"))?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for hook in hooks {
            hook()?;
        }
        state.generation = next;
        self.inner
            .writable
            .store(backend.is_writable(), Ordering::Release);
        state.backend = Some(backend);
        Ok(next)
    }

    /// Run one operation while the route is active and `generation` remains
    /// current. Keep the callback short enough that lock/logout can wait for it.
    /// FUSE callers should send their reply from inside this callback.
    pub fn with_read_lease<T>(
        &self,
        generation: u64,
        operation: impl FnOnce(&VaultRouteLease<'_>) -> Result<T, CloudError>,
    ) -> Result<T, CloudError> {
        let state = self
            .inner
            .state
            .read()
            .map_err(|_| poisoned("vault route state"))?;
        if state.generation != generation || state.backend.is_none() {
            return Err(revoked());
        }
        state
            .backend
            .as_ref()
            .ok_or_else(revoked)?
            .reader()
            .authorize()?;
        let lease = VaultRouteLease {
            inner: &self.inner,
            state: &state,
        };
        operation(&lease)
    }

    /// Release one route-owned reader without asking the backend to authorize
    /// content access. This lets FUSE release handles after an out-of-band
    /// coordinator lock, while still refusing handles from a different route
    /// or generation.
    pub fn release_handle(&self, handle: &VaultReadHandle) -> Result<(), CloudError> {
        let state = self
            .inner
            .state
            .read()
            .map_err(|_| poisoned("vault route state"))?;
        if state.generation != handle.generation || state.backend.is_none() {
            return Err(revoked());
        }
        if handle.route_id != self.inner.id
            || !handle
                .route
                .upgrade()
                .is_some_and(|route| Arc::ptr_eq(&route, &self.inner))
        {
            return Err(revoked());
        }
        self.inner
            .handles
            .lock()
            .map_err(|_| poisoned("vault route handles"))?
            .remove(&handle.id);
        Ok(())
    }

    /// Revoke the current backend, wait for all leased operations, drop every
    /// open reader, then perform the caller's coordinator lock while the route
    /// remains inaccessible. The callback must not acquire this route's locks.
    /// Revocation remains in effect even if the callback reports an error.
    pub fn revoke<T>(
        &self,
        lock_session: impl FnOnce() -> Result<T, CloudError>,
    ) -> Result<T, CloudError> {
        // Recover poisoned route state only to revoke it. Never leave a backend
        // reachable because a generation counter or cleanup lock failed.
        let mut first_error = None;
        let mut state = match self.inner.state.write() {
            Ok(state) => state,
            Err(poisoned_state) => {
                first_error.get_or_insert_with(|| poisoned("vault route state"));
                poisoned_state.into_inner()
            }
        };
        match state.generation.checked_add(1) {
            Some(next) => state.generation = next,
            None => {
                first_error.get_or_insert_with(|| {
                    CloudError::new(ErrorKind::Io, "vault route generation exhausted")
                });
            }
        }
        state.backend = None;
        self.inner.writable.store(false, Ordering::Release);
        let mut handles = match self.inner.handles.lock() {
            Ok(handles) => handles,
            Err(poisoned_handles) => {
                first_error.get_or_insert_with(|| poisoned("vault route handles"));
                poisoned_handles.into_inner()
            }
        };
        handles.clear();
        drop(handles);

        let hooks = match self.inner.revoke_hooks.lock() {
            Ok(hooks) => hooks.values().cloned().collect::<Vec<_>>(),
            Err(poisoned_hooks) => {
                first_error.get_or_insert_with(|| poisoned("vault route hooks"));
                poisoned_hooks
                    .into_inner()
                    .values()
                    .cloned()
                    .collect::<Vec<_>>()
            }
        };
        for hook in hooks {
            if let Err(error) = hook() {
                first_error.get_or_insert(error);
            }
        }

        // Keep the exclusive route gate until session locking has completed.
        let lock_result = lock_session();
        drop(state);
        match (first_error, lock_result) {
            (Some(error), _) => Err(error),
            (None, result) => result,
        }
    }
}

/// RAII registration; dropping it removes the mount-specific invalidation
/// callback so repeated mounts do not accumulate stale hooks.
pub struct VaultRevokeHook {
    route: Weak<Inner>,
    id: u64,
}

/// RAII registration for a mount-specific install invalidation callback.
pub struct VaultInstallHook {
    route: Weak<Inner>,
    id: u64,
}

impl Drop for VaultInstallHook {
    fn drop(&mut self) {
        if let Some(route) = self.route.upgrade()
            && let Ok(mut hooks) = route.install_hooks.lock()
        {
            hooks.remove(&self.id);
        }
    }
}

impl Drop for VaultRevokeHook {
    fn drop(&mut self) {
        if let Some(route) = self.route.upgrade()
            && let Ok(mut hooks) = route.revoke_hooks.lock()
        {
            hooks.remove(&self.id);
        }
    }
}

impl Default for VaultRouteControl {
    fn default() -> Self {
        Self::new()
    }
}

/// A short-lived capability borrowed only while the route's read gate is held.
pub struct VaultRouteLease<'a> {
    inner: &'a Arc<Inner>,
    state: &'a RouteState,
}

impl VaultRouteLease<'_> {
    pub fn generation(&self) -> u64 {
        self.state.generation
    }

    pub fn resolve_pending_create(
        &self,
        write_id: &str,
    ) -> Result<Option<VaultPendingCreateResolution>, CloudError> {
        self.read_backend()?.resolve_pending_create(write_id)
    }

    pub fn list(&self, path: &str) -> Result<Vec<RemoteEntry>, CloudError> {
        let backend = self.read_backend()?;
        let entries = backend.list(path)?;
        if entries.len() > MAX_VAULT_DIRECTORY_ENTRIES {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "vault directory exceeds the mounted entry limit",
            ));
        }
        Ok(entries)
    }

    pub fn supports_writes(&self) -> bool {
        self.state
            .backend
            .as_ref()
            .is_some_and(|backend| backend.writer().is_some())
    }

    pub fn supports_existing_file_overwrites(&self) -> bool {
        self.state.backend.as_ref().is_some_and(|backend| {
            backend.overwrite_backend().is_some() || backend.writer().is_some()
        })
    }

    pub fn supports_file_creates(&self) -> bool {
        self.state.backend.as_ref().is_some_and(|backend| {
            backend
                .writer()
                .is_some_and(VaultWriteBackend::supports_file_create)
                || backend
                    .overwrite_backend()
                    .is_some_and(VaultExistingFileOverwriteBackend::supports_file_create)
        })
    }

    pub fn prepare_file_create(
        &self,
        path: &str,
        existing: Option<(&str, u64)>,
    ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
        if let Some(backend) = self
            .state
            .backend
            .as_ref()
            .and_then(RouteBackend::overwrite_backend)
        {
            if !backend.supports_file_create() {
                return Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "encrypted route does not permit file creation",
                ));
            }
            backend.prepare_file_create(path, existing)
        } else {
            self.writer()?.prepare_file_create(path, existing)
        }
    }

    pub fn parent_ref_for_directory(
        &self,
        path: &str,
        expected_entry_id: &str,
        expected_entry_etag: &str,
    ) -> Result<VaultParentRef, CloudError> {
        self.read_backend()?
            .parent_ref_for_directory(path, expected_entry_id, expected_entry_etag)
    }

    pub fn prepare_file_create_under_parent(
        &self,
        path: &str,
        parent_ref: &VaultParentRef,
        existing: Option<(&str, u64)>,
    ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
        if let Some(backend) = self
            .state
            .backend
            .as_ref()
            .and_then(RouteBackend::overwrite_backend)
        {
            if !backend.supports_file_create() {
                return Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "encrypted route does not permit file creation",
                ));
            }
            backend.prepare_file_create_under_parent(path, parent_ref, existing)
        } else {
            let writer = self.writer()?;
            if !writer.supports_file_create() {
                return Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "encrypted route does not permit file creation",
                ));
            }
            writer.prepare_file_create_under_parent(path, parent_ref, existing)
        }
    }

    pub fn create_file(
        &self,
        target: &VaultWriteTarget,
        source: &mut dyn VaultWriteSource,
        plaintext_len: u64,
        existing: Option<(&str, u64)>,
    ) -> Result<VaultUploadOutcome, CloudError> {
        if !matches!(target.condition(), WriteCondition::Absent) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "encrypted create target lost its absence condition",
            ));
        }
        if let Some(backend) = self
            .state
            .backend
            .as_ref()
            .and_then(RouteBackend::overwrite_backend)
        {
            if !backend.supports_file_create() {
                return Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "encrypted route does not permit file creation",
                ));
            }
            backend.create_file(target, source, plaintext_len, existing)
        } else {
            self.writer()?
                .create_file(target, source, plaintext_len, existing)
        }
    }

    pub fn begin_file_create(
        &self,
        target: &VaultWriteTarget,
    ) -> Result<VaultUploadOutcome, CloudError> {
        if !matches!(target.condition(), WriteCondition::Absent) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "encrypted create target lost its absence condition",
            ));
        }
        match self.state.backend.as_ref() {
            Some(RouteBackend::ExistingFileOverwrite(backend)) => backend.begin_file_create(target),
            Some(RouteBackend::ReadWrite(backend)) => backend.begin_file_create(target),
            Some(RouteBackend::ReadOnly(_)) | None => Err(CloudError::new(
                ErrorKind::Forbidden,
                "encrypted route does not permit file creation",
            )),
        }
    }

    pub fn prepare_existing_target(
        &self,
        path: &str,
        base_resource_id: &str,
        base_etag: &str,
    ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
        if base_etag.is_empty() {
            return Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "existing encrypted file has no base version",
            ));
        }
        if let Some(backend) = self
            .state
            .backend
            .as_ref()
            .and_then(RouteBackend::overwrite_backend)
        {
            backend.prepare_existing_target(path, base_resource_id, base_etag)
        } else {
            let current = self.read_backend()?.stat(path)?;
            if current.directory || current.id != base_resource_id || current.etag != base_etag {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "encrypted file identity or base version changed",
                ));
            }
            self.writer()?
                .prepare_target(path, WriteCondition::Match(base_etag.to_owned()))
        }
    }

    pub fn overwrite_existing(
        &self,
        target: &VaultWriteTarget,
        source: &mut dyn VaultWriteSource,
        plaintext_len: u64,
    ) -> Result<VaultUploadOutcome, CloudError> {
        if let Some(backend) = self
            .state
            .backend
            .as_ref()
            .and_then(RouteBackend::overwrite_backend)
        {
            backend.overwrite(target, source, plaintext_len)
        } else {
            self.writer()?.upload(target, source, plaintext_len)
        }
    }

    pub fn prepare_target(
        &self,
        path: &str,
        condition: WriteCondition,
    ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
        self.writer()?.prepare_target(path, condition)
    }

    pub fn upload(
        &self,
        target: &VaultWriteTarget,
        source: &mut dyn VaultWriteSource,
        plaintext_len: u64,
    ) -> Result<VaultUploadOutcome, CloudError> {
        self.writer()?.upload(target, source, plaintext_len)
    }

    pub fn mkdir(&self, path: &str) -> Result<RemoteEntry, CloudError> {
        self.writer()?.mkdir(path)
    }

    pub fn delete(&self, path: &str, expected_etag: &str) -> Result<(), CloudError> {
        self.writer()?.delete(path, expected_etag)
    }

    pub fn rename(
        &self,
        from: &str,
        to: &str,
        expected_etag: &str,
    ) -> Result<RemoteEntry, CloudError> {
        self.writer()?.rename(from, to, expected_etag)
    }

    pub fn supports_file_renames(&self) -> bool {
        self.state.backend.as_ref().is_some_and(|backend| {
            backend
                .overwrite_backend()
                .is_some_and(VaultExistingFileOverwriteBackend::supports_file_rename)
        })
    }

    pub fn supports_pending_create_renames(&self) -> bool {
        self.state.backend.as_ref().is_some_and(|backend| {
            backend
                .overwrite_backend()
                .is_some_and(VaultExistingFileOverwriteBackend::supports_pending_create_rename)
        })
    }

    pub fn supports_file_deletes(&self) -> bool {
        self.state.backend.as_ref().is_some_and(|backend| {
            backend
                .overwrite_backend()
                .is_some_and(VaultExistingFileOverwriteBackend::supports_file_delete)
        })
    }

    pub fn supports_directory_creates(&self) -> bool {
        self.state.backend.as_ref().is_some_and(|backend| {
            backend
                .overwrite_backend()
                .is_some_and(VaultExistingFileOverwriteBackend::supports_directory_create)
        })
    }

    pub fn supports_cancel_directory_create(&self) -> bool {
        self.state.backend.as_ref().is_some_and(|backend| {
            backend
                .writer()
                .is_some_and(VaultWriteBackend::supports_cancel_directory_create)
                || backend.overwrite_backend().is_some_and(
                    VaultExistingFileOverwriteBackend::supports_cancel_directory_create,
                )
        })
    }

    pub fn supports_cancel_file_create(&self) -> bool {
        self.state.backend.as_ref().is_some_and(|backend| {
            backend
                .writer()
                .is_some_and(VaultWriteBackend::supports_cancel_file_create)
                || backend
                    .overwrite_backend()
                    .is_some_and(VaultExistingFileOverwriteBackend::supports_cancel_file_create)
        })
    }

    pub fn cancel_never_attempted_directory_create(
        &self,
        path: &str,
        write_id: &str,
        revision: u64,
        expected_entry_id: &str,
        expected_entry_etag: &str,
    ) -> Result<(), CloudError> {
        let backend = self.state.backend.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Forbidden,
                "queued-directory cancellation is unavailable",
            )
        })?;
        if let Some(writer) = backend.writer() {
            writer.cancel_never_attempted_directory_create(
                path,
                write_id,
                revision,
                expected_entry_id,
                expected_entry_etag,
            )
        } else if let Some(overwrite) = backend.overwrite_backend() {
            overwrite.cancel_never_attempted_directory_create(
                path,
                write_id,
                revision,
                expected_entry_id,
                expected_entry_etag,
            )
        } else {
            Err(CloudError::new(
                ErrorKind::Forbidden,
                "queued-directory cancellation is unavailable",
            ))
        }
    }

    pub fn supports_pending_directory_renames(&self) -> bool {
        self.state.backend.as_ref().is_some_and(|backend| {
            backend
                .writer()
                .is_some_and(VaultWriteBackend::supports_pending_directory_rename)
                || backend.overwrite_backend().is_some_and(
                    VaultExistingFileOverwriteBackend::supports_pending_directory_rename,
                )
        })
    }

    pub fn rename_pending_directory_create(
        &self,
        from: &str,
        to: &str,
        expected_entry_id: &str,
        expected_entry_etag: &str,
        destination_parent: &VaultParentRef,
    ) -> Result<VaultPendingDirectoryRenameOutcome, CloudError> {
        let backend = self.state.backend.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Forbidden,
                "queued-directory rename is unavailable",
            )
        })?;
        if let Some(overwrite) = backend
            .overwrite_backend()
            .filter(|backend| backend.supports_pending_directory_rename())
        {
            overwrite.rename_pending_directory_create(
                from,
                to,
                expected_entry_id,
                expected_entry_etag,
                destination_parent,
            )
        } else if let Some(writer) = backend
            .writer()
            .filter(|backend| backend.supports_pending_directory_rename())
        {
            writer.rename_pending_directory_create(
                from,
                to,
                expected_entry_id,
                expected_entry_etag,
                destination_parent,
            )
        } else {
            Err(CloudError::new(
                ErrorKind::Forbidden,
                "queued-directory rename is unavailable",
            ))
        }
    }

    pub fn supports_pending_directory_subtree_renames(&self) -> bool {
        self.state.backend.as_ref().is_some_and(|backend| {
            backend
                .writer()
                .is_some_and(VaultWriteBackend::supports_pending_directory_subtree_rename)
                || backend.overwrite_backend().is_some_and(
                    VaultExistingFileOverwriteBackend::supports_pending_directory_subtree_rename,
                )
        })
    }

    pub fn rename_pending_directory_subtree(
        &self,
        from: &str,
        to: &str,
        expected_entry_id: &str,
        expected_entry_etag: &str,
        destination_parent: &VaultParentRef,
        before_publish: &mut dyn FnMut(
            &VaultPendingDirectorySubtreeRenameOutcome,
        ) -> Result<(), CloudError>,
    ) -> Result<VaultPendingDirectorySubtreeRenameOutcome, CloudError> {
        let backend = self.state.backend.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Forbidden,
                "queued-directory subtree rename is unavailable",
            )
        })?;
        if let Some(overwrite) = backend
            .overwrite_backend()
            .filter(|backend| backend.supports_pending_directory_subtree_rename())
        {
            overwrite.rename_pending_directory_subtree(
                from,
                to,
                expected_entry_id,
                expected_entry_etag,
                destination_parent,
                before_publish,
            )
        } else if let Some(writer) = backend
            .writer()
            .filter(|backend| backend.supports_pending_directory_subtree_rename())
        {
            writer.rename_pending_directory_subtree(
                from,
                to,
                expected_entry_id,
                expected_entry_etag,
                destination_parent,
                before_publish,
            )
        } else {
            Err(CloudError::new(
                ErrorKind::Forbidden,
                "queued-directory subtree rename is unavailable",
            ))
        }
    }

    pub fn resolve_pending_directory_subtree_retarget(
        &self,
        wal: &PendingVaultDirectoryRetarget,
    ) -> Result<VaultPendingDirectoryRetargetResolution, CloudError> {
        let backend = self.state.backend.as_ref().ok_or_else(|| {
            CloudError::new(ErrorKind::Forbidden, "subtree recovery is unavailable")
        })?;
        if let Some(overwrite) = backend.overwrite_backend() {
            overwrite.resolve_pending_directory_subtree_retarget(wal)
        } else if let Some(writer) = backend.writer() {
            writer.resolve_pending_directory_subtree_retarget(wal)
        } else {
            Err(CloudError::new(
                ErrorKind::Forbidden,
                "subtree recovery is unavailable",
            ))
        }
    }

    pub fn cancel_never_attempted_file_create(
        &self,
        path: &str,
        write_id: &str,
        revision: u64,
        expected_entry_id: &str,
        expected_entry_etag: &str,
    ) -> Result<VaultCancelledCreateReceipt, CloudError> {
        let backend = self.state.backend.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Forbidden,
                "queued-file cancellation is unavailable",
            )
        })?;
        if let Some(writer) = backend.writer() {
            writer.cancel_never_attempted_file_create(
                path,
                write_id,
                revision,
                expected_entry_id,
                expected_entry_etag,
            )
        } else if let Some(overwrite) = backend.overwrite_backend() {
            overwrite.cancel_never_attempted_file_create(
                path,
                write_id,
                revision,
                expected_entry_id,
                expected_entry_etag,
            )
        } else {
            Err(CloudError::new(
                ErrorKind::Forbidden,
                "queued-file cancellation is unavailable",
            ))
        }
    }

    pub fn resolve_cancelled_file_create(
        &self,
        write_id: &str,
        revision: u64,
    ) -> Result<Option<VaultCancelledCreateReceipt>, CloudError> {
        match self.state.backend.as_ref() {
            Some(RouteBackend::ReadWrite(backend)) => {
                backend.resolve_cancelled_file_create(write_id, revision)
            }
            Some(RouteBackend::ExistingFileOverwrite(backend)) => {
                backend.resolve_cancelled_file_create(write_id, revision)
            }
            Some(RouteBackend::ReadOnly(_)) | None => Err(CloudError::new(
                ErrorKind::Forbidden,
                "queued-file cancellation recovery is unavailable",
            )),
        }
    }

    pub fn acknowledge_cancelled_file_create(
        &self,
        write_id: &str,
        revision: u64,
        target: &VaultWriteTarget,
        content: &VerifiedCreateContent,
    ) -> Result<(), CloudError> {
        match self.state.backend.as_ref() {
            Some(RouteBackend::ReadWrite(backend)) => {
                backend.acknowledge_cancelled_file_create(write_id, revision, target, content)
            }
            Some(RouteBackend::ExistingFileOverwrite(backend)) => {
                backend.acknowledge_cancelled_file_create(write_id, revision, target, content)
            }
            Some(RouteBackend::ReadOnly(_)) | None => Err(CloudError::new(
                ErrorKind::Forbidden,
                "cancellation receipt acknowledgement is unavailable",
            )),
        }
    }

    pub fn finalize_cancelled_file_create_ack(
        &self,
        receipt: &VaultCancelledCreateReceipt,
    ) -> Result<(), CloudError> {
        match self.state.backend.as_ref() {
            Some(RouteBackend::ReadWrite(backend)) => {
                backend.finalize_cancelled_file_create_ack(receipt)
            }
            Some(RouteBackend::ExistingFileOverwrite(backend)) => {
                backend.finalize_cancelled_file_create_ack(receipt)
            }
            Some(RouteBackend::ReadOnly(_)) | None => Err(CloudError::new(
                ErrorKind::Forbidden,
                "cancellation receipt finalization is unavailable",
            )),
        }
    }

    pub fn supports_pending_parent_operations(&self) -> bool {
        self.state.backend.as_ref().is_some_and(|backend| {
            backend
                .writer()
                .is_some_and(VaultWriteBackend::supports_pending_parent_operations)
                || backend.overwrite_backend().is_some_and(
                    VaultExistingFileOverwriteBackend::supports_pending_parent_operations,
                )
        })
    }

    pub fn rename_file(
        &self,
        from: &str,
        to: &str,
        expected_source_id: &str,
        expected_source_etag: &str,
    ) -> Result<VaultRenameOutcome, CloudError> {
        self.state
            .backend
            .as_ref()
            .and_then(RouteBackend::overwrite_backend)
            .ok_or_else(|| {
                CloudError::new(ErrorKind::Forbidden, "vault file rename is unavailable")
            })?
            .rename_file(from, to, expected_source_id, expected_source_etag)
    }

    pub fn rename_pending_create(
        &self,
        from: &str,
        to: &str,
        expected_source_id: &str,
        expected_source_etag: &str,
        destination_parent: &VaultParentRef,
    ) -> Result<VaultPendingCreateRenameOutcome, CloudError> {
        self.state
            .backend
            .as_ref()
            .and_then(RouteBackend::overwrite_backend)
            .filter(|backend| backend.supports_pending_create_rename())
            .ok_or_else(|| {
                CloudError::new(
                    ErrorKind::Forbidden,
                    "pending encrypted create rename is unavailable",
                )
            })?
            .rename_pending_create(
                from,
                to,
                expected_source_id,
                expected_source_etag,
                destination_parent,
            )
    }

    pub fn delete_file(
        &self,
        path: &str,
        expected_source_id: &str,
        expected_source_etag: &str,
    ) -> Result<VaultDeleteOutcome, CloudError> {
        self.state
            .backend
            .as_ref()
            .and_then(RouteBackend::overwrite_backend)
            .ok_or_else(|| {
                CloudError::new(ErrorKind::Forbidden, "vault file deletion is unavailable")
            })?
            .delete_file(path, expected_source_id, expected_source_etag)
    }

    pub fn create_directory(&self, path: &str) -> Result<VaultDirectoryCreateOutcome, CloudError> {
        self.state
            .backend
            .as_ref()
            .and_then(RouteBackend::overwrite_backend)
            .filter(|backend| backend.supports_directory_create())
            .ok_or_else(|| {
                CloudError::new(
                    ErrorKind::Forbidden,
                    "vault directory creation is unavailable",
                )
            })?
            .create_directory(path)
    }

    pub fn create_directory_under_parent(
        &self,
        path: &str,
        parent_ref: &VaultParentRef,
    ) -> Result<VaultDirectoryCreateOutcome, CloudError> {
        if matches!(parent_ref, VaultParentRef::PendingCreate { .. })
            && !self.state.backend.as_ref().is_some_and(|backend| {
                backend
                    .writer()
                    .is_some_and(VaultWriteBackend::supports_pending_parent_operations)
                    || backend.overwrite_backend().is_some_and(
                        VaultExistingFileOverwriteBackend::supports_pending_parent_operations,
                    )
            })
        {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted backend cannot create below an uncommitted directory",
            ));
        }
        match self.state.backend.as_ref() {
            Some(RouteBackend::ExistingFileOverwrite(backend)) => backend
                .as_ref()
                .create_directory_under_parent(path, parent_ref),
            Some(RouteBackend::ReadWrite(backend)) => backend
                .as_ref()
                .create_directory_under_parent(path, parent_ref),
            Some(RouteBackend::ReadOnly(_)) | None => Err(CloudError::new(
                ErrorKind::Forbidden,
                "encrypted route does not permit directory creation",
            )),
        }
    }

    pub fn stat(&self, path: &str) -> Result<RemoteEntry, CloudError> {
        self.read_backend()?.stat(path)
    }

    pub fn open(&self, path: &str) -> Result<VaultReadHandle, CloudError> {
        let reader = self.read_backend()?.open(path)?;
        let mut handles = self
            .inner
            .handles
            .lock()
            .map_err(|_| poisoned("vault route handles"))?;
        if handles.len() >= self.inner.max_handles {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "too many open vault files",
            ));
        }
        let id = self.inner.next_handle.fetch_add(1, Ordering::Relaxed);
        if id == u64::MAX {
            return Err(CloudError::new(
                ErrorKind::Io,
                "vault file handle identifiers exhausted",
            ));
        }
        handles.insert(id, reader);
        Ok(VaultReadHandle {
            route_id: self.inner.id,
            id,
            generation: self.state.generation,
            route: Arc::downgrade(self.inner),
        })
    }

    /// Read at most one MiB from a route-owned open reader. The requested length
    /// is clamped before allocation, so a caller cannot force an oversized read.
    pub fn read(
        &self,
        handle: &VaultReadHandle,
        offset: u64,
        requested: usize,
    ) -> Result<Vec<u8>, CloudError> {
        self.validate_handle(handle)?;
        self.read_backend()?.authorize()?;
        let length = requested.min(MAX_VAULT_READ_CHUNK);
        let mut output = vec![0; length];
        let mut handles = self
            .inner
            .handles
            .lock()
            .map_err(|_| poisoned("vault route handles"))?;
        let reader = handles.get_mut(&handle.id).ok_or_else(revoked)?;
        reader
            .seek(SeekFrom::Start(offset))
            .map_err(|error| CloudError::new(ErrorKind::Io, error.to_string()))?;
        let count = reader
            .read(&mut output)
            .map_err(|error| CloudError::new(ErrorKind::Io, error.to_string()))?;
        output.truncate(count);
        Ok(output)
    }

    pub fn close(&self, handle: VaultReadHandle) -> Result<(), CloudError> {
        self.validate_handle(&handle)?;
        let mut handles = self
            .inner
            .handles
            .lock()
            .map_err(|_| poisoned("vault route handles"))?;
        handles.remove(&handle.id);
        Ok(())
    }

    fn read_backend(&self) -> Result<&dyn VaultReadBackend, CloudError> {
        self.state
            .backend
            .as_ref()
            .map(RouteBackend::reader)
            .ok_or_else(revoked)
    }

    fn writer(&self) -> Result<&dyn VaultWriteBackend, CloudError> {
        self.state
            .backend
            .as_ref()
            .and_then(RouteBackend::writer)
            .ok_or_else(|| CloudError::new(ErrorKind::Forbidden, "vault route is read-only"))
    }

    fn validate_handle(&self, handle: &VaultReadHandle) -> Result<(), CloudError> {
        let Some(route) = handle.route.upgrade() else {
            return Err(revoked());
        };
        if handle.route_id != self.inner.id
            || !Arc::ptr_eq(&route, self.inner)
            || handle.generation != self.state.generation
        {
            return Err(revoked());
        }
        Ok(())
    }
}

fn revoked() -> CloudError {
    CloudError::new(ErrorKind::Unauthorized, "vault route is locked or stale")
}

fn poisoned(name: &str) -> CloudError {
    CloudError::new(ErrorKind::Io, format!("{name} lock is unavailable"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        io::Cursor,
        sync::{
            Barrier,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::Duration,
    };

    struct TestBackend {
        files: HashMap<String, Vec<u8>>,
        opened: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
    }

    impl VaultReadBackend for TestBackend {
        fn authorize(&self) -> Result<(), CloudError> {
            Ok(())
        }

        fn list(&self, path: &str) -> Result<Vec<RemoteEntry>, CloudError> {
            Ok(self
                .files
                .keys()
                .filter(|file| file.starts_with(path))
                .map(|path| entry(path))
                .collect())
        }

        fn stat(&self, path: &str) -> Result<RemoteEntry, CloudError> {
            self.files
                .contains_key(path)
                .then(|| entry(path))
                .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "missing fixture"))
        }

        fn open(&self, path: &str) -> Result<Box<dyn VaultReadStream>, CloudError> {
            let bytes = self
                .files
                .get(path)
                .cloned()
                .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "missing fixture"))?;
            self.opened.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(TrackedReader {
                cursor: Cursor::new(bytes),
                dropped: Arc::clone(&self.dropped),
            }))
        }
    }

    struct TrackedReader {
        cursor: Cursor<Vec<u8>>,
        dropped: Arc<AtomicUsize>,
    }

    impl Read for TrackedReader {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.cursor.read(out)
        }
    }

    impl Seek for TrackedReader {
        fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
            self.cursor.seek(from)
        }
    }

    impl Drop for TrackedReader {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn entry(path: &str) -> RemoteEntry {
        RemoteEntry {
            id: path.to_owned(),
            path: path.to_owned(),
            directory: false,
            size: 5,
            etag: "fixture".into(),
            modified_unix: 0,
            writable: false,
            encrypted: false,
        }
    }

    fn make_backend(content: &str) -> (Arc<dyn VaultReadBackend>, Arc<AtomicUsize>) {
        let opened = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut files = HashMap::new();
        files.insert("/note.txt".into(), content.as_bytes().to_vec());
        (
            Arc::new(TestBackend {
                files,
                opened,
                dropped: Arc::clone(&dropped),
            }),
            dropped,
        )
    }

    struct TestOverwriteBackend {
        reader: TestBackend,
        directory_create: bool,
        pending_parent_operations: bool,
        created_directories: Mutex<Vec<String>>,
        file_parent_refs: Mutex<Vec<VaultParentRef>>,
        directory_parent_refs: Mutex<Vec<VaultParentRef>>,
    }

    impl VaultReadBackend for TestOverwriteBackend {
        fn authorize(&self) -> Result<(), CloudError> {
            Ok(())
        }

        fn list(&self, path: &str) -> Result<Vec<RemoteEntry>, CloudError> {
            self.reader.list(path)
        }

        fn stat(&self, path: &str) -> Result<RemoteEntry, CloudError> {
            self.reader.stat(path)
        }

        fn open(&self, path: &str) -> Result<Box<dyn VaultReadStream>, CloudError> {
            self.reader.open(path)
        }
    }

    impl VaultExistingFileOverwriteBackend for TestOverwriteBackend {
        fn supports_pending_parent_operations(&self) -> bool {
            self.pending_parent_operations
        }

        fn prepare_existing_target(
            &self,
            path: &str,
            base_resource_id: &str,
            base_etag: &str,
        ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
            let current = self.reader.stat(path)?;
            if current.directory || current.id != base_resource_id || current.etag != base_etag {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "cached file identity or version changed",
                ));
            }
            let scope =
                VaultWriteScope::new("account-a", "https://cloud.example", "space-a", "root-a")
                    .unwrap();
            let target = VaultWriteTarget::new(
                "ciphertext-name",
                WriteCondition::Match(base_etag.to_owned()),
            )
            .unwrap();
            Ok((scope, target))
        }

        fn overwrite(
            &self,
            target: &VaultWriteTarget,
            source: &mut dyn VaultWriteSource,
            plaintext_len: u64,
        ) -> Result<VaultUploadOutcome, CloudError> {
            assert!(matches!(target.condition(), WriteCondition::Match(_)));
            let mut bytes = Vec::new();
            source.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes.len() as u64, plaintext_len);
            Ok(VaultUploadOutcome::Queued {
                entry: RemoteEntry {
                    id: "file-a".into(),
                    path: "/note.txt".into(),
                    directory: false,
                    size: plaintext_len,
                    etag: "local-pending".into(),
                    modified_unix: 0,
                    writable: true,
                    encrypted: true,
                },
                write_id: "write-a".into(),
                revision: 1,
                uncertain: false,
            })
        }

        fn supports_file_create(&self) -> bool {
            true
        }

        fn prepare_file_create(
            &self,
            path: &str,
            _existing: Option<(&str, u64)>,
        ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
            let scope =
                VaultWriteScope::new("account-a", "https://cloud.example", "space-a", "root-a")
                    .unwrap();
            let target =
                VaultWriteTarget::new(path.trim_start_matches('/'), WriteCondition::Absent)
                    .unwrap();
            Ok((scope, target))
        }

        fn prepare_file_create_under_parent(
            &self,
            path: &str,
            parent_ref: &VaultParentRef,
            existing: Option<(&str, u64)>,
        ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
            if matches!(parent_ref, VaultParentRef::PendingCreate { .. })
                && !self.pending_parent_operations
            {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "pending parent operation is disabled in fixture",
                ));
            }
            let (scope, target) = self.prepare_file_create(path, existing)?;
            let target = VaultWriteTarget::new_with_parent(
                target.opaque_relative_target().to_owned(),
                target.condition().clone(),
                parent_ref.clone(),
            )
            .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "invalid parent ref"))?;
            self.file_parent_refs
                .lock()
                .unwrap()
                .push(parent_ref.clone());
            Ok((scope, target))
        }

        fn supports_directory_create(&self) -> bool {
            self.directory_create
        }

        fn create_directory_under_parent(
            &self,
            path: &str,
            parent_ref: &VaultParentRef,
        ) -> Result<VaultDirectoryCreateOutcome, CloudError> {
            if matches!(parent_ref, VaultParentRef::PendingCreate { .. })
                && !self.pending_parent_operations
            {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "pending parent operation is disabled in fixture",
                ));
            }
            self.directory_parent_refs
                .lock()
                .unwrap()
                .push(parent_ref.clone());
            self.create_directory(path)
        }

        fn create_directory(&self, path: &str) -> Result<VaultDirectoryCreateOutcome, CloudError> {
            if !self.directory_create {
                return Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "fixture directory-create capability is disabled",
                ));
            }
            self.created_directories
                .lock()
                .unwrap()
                .push(path.to_owned());
            Ok(VaultDirectoryCreateOutcome::Queued {
                entry: RemoteEntry {
                    id: "raiun-pending-directory:directory-create-a".into(),
                    path: path.to_owned(),
                    directory: true,
                    size: 0,
                    etag: "raiun-pending-directory-v1:directory-create-a:1".into(),
                    modified_unix: 0,
                    writable: false,
                    encrypted: true,
                },
                write_id: "directory-create-a".into(),
                revision: 1,
                uncertain: false,
            })
        }
    }

    #[test]
    fn offline_overwrite_route_has_no_namespace_mutation_capability() {
        let opened = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut files = HashMap::new();
        files.insert("/note.txt".into(), b"base".to_vec());
        let backend = Arc::new(TestOverwriteBackend {
            reader: TestBackend {
                files,
                opened,
                dropped,
            },
            directory_create: false,
            pending_parent_operations: false,
            created_directories: Mutex::new(Vec::new()),
            file_parent_refs: Mutex::new(Vec::new()),
            directory_parent_refs: Mutex::new(Vec::new()),
        });
        let route = VaultRouteControl::new();
        let generation = route
            .install_existing_file_overwrite_backend(backend)
            .unwrap();
        assert!(!route.supports_writes().unwrap());
        assert!(route.supports_existing_file_overwrites().unwrap());
        assert!(!route.supports_file_renames().unwrap());
        assert!(!route.supports_file_deletes().unwrap());
        assert!(!route.supports_directory_creates().unwrap());

        route
            .with_read_lease(generation, |lease| {
                let (scope, target) =
                    lease.prepare_existing_target("/note.txt", "/note.txt", "fixture")?;
                assert_eq!(scope.space_id(), "space-a");
                assert!(matches!(target.condition(), WriteCondition::Match(_)));
                assert!(
                    lease
                        .prepare_existing_target("/note.txt", "wrong-id", "fixture")
                        .is_err()
                );
                assert!(
                    lease
                        .prepare_existing_target("/note.txt", "/note.txt", "wrong-etag")
                        .is_err()
                );
                assert!(
                    lease
                        .prepare_target("/new.txt", WriteCondition::Absent)
                        .is_err()
                );
                assert!(lease.mkdir("/folder").is_err());
                assert!(lease.delete("/note.txt", "base").is_err());
                assert!(lease.rename("/note.txt", "/other.txt", "base").is_err());
                assert!(
                    lease
                        .rename_file("/note.txt", "/other.txt", "/note.txt", "base")
                        .is_err()
                );
                assert!(lease.delete_file("/note.txt", "/note.txt", "base").is_err());

                let mut source = Cursor::new(b"edited".to_vec());
                assert!(matches!(
                    lease.overwrite_existing(&target, &mut source, 6)?,
                    VaultUploadOutcome::Queued { .. }
                ));
                Ok(())
            })
            .unwrap();
        route.revoke(|| Ok(())).unwrap();
        assert!(!route.supports_existing_file_overwrites().unwrap());
    }

    #[test]
    fn offline_directory_create_is_an_explicit_narrow_route_capability() {
        let opened = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut files = HashMap::new();
        files.insert("/note.txt".into(), b"base".to_vec());
        let backend = Arc::new(TestOverwriteBackend {
            reader: TestBackend {
                files,
                opened,
                dropped,
            },
            directory_create: true,
            pending_parent_operations: false,
            created_directories: Mutex::new(Vec::new()),
            file_parent_refs: Mutex::new(Vec::new()),
            directory_parent_refs: Mutex::new(Vec::new()),
        });
        let route = VaultRouteControl::new();
        let generation = route
            .install_existing_file_overwrite_backend(backend.clone())
            .unwrap();
        assert!(!route.supports_writes().unwrap());
        assert!(route.supports_directory_creates().unwrap());

        route
            .with_read_lease(generation, |lease| {
                let outcome = lease.create_directory("/folder")?;
                let VaultDirectoryCreateOutcome::Queued {
                    entry,
                    write_id,
                    revision,
                    uncertain,
                } = outcome
                else {
                    panic!("restricted offline create should remain a local intent")
                };
                assert!(entry.directory);
                assert!(!entry.writable);
                assert_eq!(entry.path, "/folder");
                assert!(entry.id.starts_with("raiun-pending-directory:"));
                assert_eq!(write_id, "directory-create-a");
                assert_eq!(revision, 1);
                assert!(!uncertain);
                assert!(lease.mkdir("/other").is_err());
                Ok(())
            })
            .unwrap();
        assert_eq!(
            backend.created_directories.lock().unwrap().as_slice(),
            ["/folder"]
        );
        route.revoke(|| Ok(())).unwrap();
        assert!(!route.supports_directory_creates().unwrap());
    }

    #[test]
    fn pending_parent_reference_is_forwarded_for_file_and_directory_children() {
        let opened = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let backend = Arc::new(TestOverwriteBackend {
            reader: TestBackend {
                files: HashMap::new(),
                opened,
                dropped,
            },
            directory_create: true,
            pending_parent_operations: true,
            created_directories: Mutex::new(Vec::new()),
            file_parent_refs: Mutex::new(Vec::new()),
            directory_parent_refs: Mutex::new(Vec::new()),
        });
        let route = VaultRouteControl::new();
        let generation = route
            .install_existing_file_overwrite_backend(backend.clone())
            .unwrap();
        let parent = VaultParentRef::pending_create("d".repeat(32), 7).unwrap();

        route
            .with_read_lease(generation, |lease| {
                assert!(lease.supports_pending_parent_operations());
                let (_, target) = lease.prepare_file_create_under_parent(
                    "/queued-folder/child.txt",
                    &parent,
                    None,
                )?;
                assert_eq!(target.parent_ref(), Some(&parent));
                assert!(matches!(target.condition(), WriteCondition::Absent));

                let outcome =
                    lease.create_directory_under_parent("/queued-folder/nested", &parent)?;
                assert!(matches!(
                    outcome,
                    VaultDirectoryCreateOutcome::Queued { .. }
                ));
                Ok(())
            })
            .unwrap();

        assert_eq!(
            backend.file_parent_refs.lock().unwrap().as_slice(),
            std::slice::from_ref(&parent)
        );
        assert_eq!(
            backend.directory_parent_refs.lock().unwrap().as_slice(),
            [parent]
        );
        route.revoke(|| Ok(())).unwrap();
    }

    #[test]
    fn pending_parent_mutation_fails_closed_without_explicit_capability() {
        let opened = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let backend = Arc::new(TestOverwriteBackend {
            reader: TestBackend {
                files: HashMap::new(),
                opened,
                dropped,
            },
            directory_create: true,
            pending_parent_operations: false,
            created_directories: Mutex::new(Vec::new()),
            file_parent_refs: Mutex::new(Vec::new()),
            directory_parent_refs: Mutex::new(Vec::new()),
        });
        let route = VaultRouteControl::new();
        let generation = route
            .install_existing_file_overwrite_backend(backend.clone())
            .unwrap();
        let parent = VaultParentRef::pending_create("e".repeat(32), 1).unwrap();

        route
            .with_read_lease(generation, |lease| {
                assert!(
                    lease
                        .prepare_file_create_under_parent("/queued/child.txt", &parent, None)
                        .is_err()
                );
                assert!(
                    lease
                        .create_directory_under_parent("/queued/child", &parent)
                        .is_err()
                );
                Ok(())
            })
            .unwrap();
        assert!(backend.file_parent_refs.lock().unwrap().is_empty());
        assert!(backend.directory_parent_refs.lock().unwrap().is_empty());
        assert!(backend.created_directories.lock().unwrap().is_empty());
        route.revoke(|| Ok(())).unwrap();
    }

    #[test]
    fn revoke_drops_handles_and_old_generation_stays_stale_after_unlock() {
        let route = VaultRouteControl::new();
        let (backend, dropped) = make_backend("secret");
        let first_generation = route.install_backend(backend).unwrap();
        let handle = route
            .with_read_lease(first_generation, |lease| lease.open("/note.txt"))
            .unwrap();
        let first_read = route
            .with_read_lease(first_generation, |lease| lease.read(&handle, 0, 2))
            .unwrap();
        let second_read = route
            .with_read_lease(first_generation, |lease| lease.read(&handle, 2, 4))
            .unwrap();
        assert_eq!(first_read, b"se");
        assert_eq!(second_read, b"cret");

        route.revoke(|| Ok(())).unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(!route.is_active().unwrap());

        let (next_backend, _) = make_backend("new secret");
        let next_generation = route.install_backend(next_backend).unwrap();
        assert!(next_generation > first_generation);
        assert!(
            route
                .with_read_lease(first_generation, |lease| lease.read(&handle, 0, 6))
                .is_err()
        );
        let bytes = route
            .with_read_lease(next_generation, |lease| {
                let new_handle = lease.open("/note.txt")?;
                lease.read(&new_handle, 0, usize::MAX)
            })
            .unwrap();
        assert_eq!(bytes, b"new secret");
        assert!(bytes.len() <= MAX_VAULT_READ_CHUNK);
    }

    #[test]
    fn failed_mount_invalidation_keeps_route_inactive() {
        let route = VaultRouteControl::new();
        let _hook = route
            .register_install_hook(Arc::new(|| {
                Err(CloudError::new(
                    ErrorKind::Io,
                    "fixture invalidation failure",
                ))
            }))
            .unwrap();
        let (backend, _) = make_backend("secret");

        let error = route.install_backend(backend).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Io);
        assert!(!route.is_active().unwrap());
        assert!(!route.supports_writes().unwrap());
    }

    #[test]
    fn install_runs_mount_invalidation_before_publishing_new_generation() {
        let route = VaultRouteControl::new();
        let invalidated = Arc::new(AtomicBool::new(false));
        let callback_state = Arc::clone(&invalidated);
        let _hook = route
            .register_install_hook(Arc::new(move || {
                callback_state.store(true, Ordering::Release);
                Ok(())
            }))
            .unwrap();
        let (backend, _) = make_backend("secret");

        let generation = route.install_backend(backend).unwrap();
        assert!(invalidated.load(Ordering::Acquire));
        assert!(route.is_active().unwrap());
        assert_eq!(route.generation().unwrap(), generation);
    }

    #[test]
    fn install_gate_serializes_mount_state_purge_before_new_readers() {
        let route = VaultRouteControl::new();
        let mount_state = Arc::new(Mutex::new(false));
        let callback_state = Arc::clone(&mount_state);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let _hook = route
            .register_install_hook(Arc::new(move || {
                let mut purged = callback_state
                    .lock()
                    .map_err(|_| poisoned("fixture mount state"))?;
                *purged = true;
                started_tx
                    .send(())
                    .map_err(|_| poisoned("fixture install signal"))?;
                release_rx
                    .lock()
                    .map_err(|_| poisoned("fixture install release"))?
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(|_| poisoned("fixture install release"))?;
                Ok(())
            }))
            .unwrap();

        let installing_route = route.clone();
        let (installed_tx, installed_rx) = mpsc::channel();
        let installing = thread::spawn(move || {
            let result = installing_route.install_backend(make_backend("secret").0);
            installed_tx.send(result).unwrap();
        });
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("mount invalidation hook should start");

        let reading_route = route.clone();
        let reader_state = Arc::clone(&mount_state);
        let (attempt_tx, attempt_rx) = mpsc::channel();
        let (lease_tx, lease_rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            attempt_tx.send(()).unwrap();
            reading_route.with_read_lease(1, |_| {
                lease_tx
                    .send(())
                    .map_err(|_| poisoned("fixture lease signal"))?;
                let _state = reader_state
                    .lock()
                    .map_err(|_| poisoned("fixture mount state"))?;
                Ok(())
            })
        });

        attempt_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("reader should attempt to acquire the route gate");
        assert!(lease_rx.recv_timeout(Duration::from_millis(50)).is_err());
        release_tx.send(()).unwrap();
        assert_eq!(
            installed_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("installation should finish after purge")
                .unwrap(),
            1
        );
        installing.join().unwrap();
        lease_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("new readers should proceed after publication");
        reader.join().unwrap().unwrap();
        assert!(*mount_state.lock().unwrap());
    }

    #[test]
    fn revoke_always_locks_session_after_hook_failure_or_poisoned_cleanup() {
        let route = VaultRouteControl::new();
        route.install_backend(make_backend("secret").0).unwrap();
        let hook_control = route.clone();
        let _hook = route
            .register_revoke_hook(Arc::new(move || {
                let _ = &hook_control;
                Err(CloudError::new(
                    ErrorKind::Io,
                    "synthetic invalidation failure",
                ))
            }))
            .unwrap();
        let locked = Arc::new(AtomicUsize::new(0));
        let locked_callback = Arc::clone(&locked);
        assert!(
            route
                .revoke(move || {
                    locked_callback.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(locked.load(Ordering::SeqCst), 1);
        assert!(!route.is_active().unwrap());

        // A poisoned reader map is recoverable for the purpose of clearing it;
        // session locking must still happen and the route must stay inactive.
        let poisoned_route = VaultRouteControl::new();
        poisoned_route
            .install_backend(make_backend("secret").0)
            .unwrap();
        let handles = Arc::clone(&poisoned_route.inner);
        let _ = thread::spawn(move || {
            let _guard = handles.handles.lock().unwrap();
            panic!("poison synthetic reader map");
        })
        .join();
        let locked = Arc::new(AtomicUsize::new(0));
        let locked_callback = Arc::clone(&locked);
        assert!(
            poisoned_route
                .revoke(move || {
                    locked_callback.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(locked.load(Ordering::SeqCst), 1);
        assert!(!poisoned_route.is_active().unwrap());

        let poisoned_hooks_route = VaultRouteControl::new();
        poisoned_hooks_route
            .install_backend(make_backend("secret").0)
            .unwrap();
        let hooks = Arc::clone(&poisoned_hooks_route.inner);
        let _ = thread::spawn(move || {
            let _guard = hooks.revoke_hooks.lock().unwrap();
            panic!("poison synthetic revoke-hook registry");
        })
        .join();
        let locked = Arc::new(AtomicUsize::new(0));
        let locked_callback = Arc::clone(&locked);
        assert!(
            poisoned_hooks_route
                .revoke(move || {
                    locked_callback.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(locked.load(Ordering::SeqCst), 1);
        assert!(!poisoned_hooks_route.is_active().unwrap());
    }

    #[test]
    fn revoke_waits_for_inflight_backend_operation_and_lock_callback() {
        let route = VaultRouteControl::new();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let control = route.clone();
        let (backend, _) = make_backend("x");
        let generation = route.install_backend(backend).unwrap();

        let reader_entered = Arc::clone(&entered);
        let reader_release = Arc::clone(&release);
        let reader = thread::spawn(move || {
            control.with_read_lease(generation, |_lease| {
                reader_entered.wait();
                reader_release.wait();
                Ok(())
            })
        });
        entered.wait();

        let control = route.clone();
        let (locked_tx, locked_rx) = mpsc::channel();
        let revoker = thread::spawn(move || {
            control.revoke(|| {
                locked_tx.send(()).unwrap();
                Ok(())
            })
        });
        assert!(locked_rx.recv_timeout(Duration::from_millis(50)).is_err());
        release.wait();
        reader.join().unwrap().unwrap();
        locked_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        revoker.join().unwrap().unwrap();
        assert!(!route.is_active().unwrap());
    }

    #[test]
    fn routes_isolate_handles_and_handle_counts_are_bounded() {
        let left = VaultRouteControl::with_handle_limit(1);
        let right = VaultRouteControl::with_handle_limit(1);
        let (left_backend, _) = make_backend("left");
        let (right_backend, _) = make_backend("right");
        let left_generation = left.install_backend(left_backend).unwrap();
        let right_generation = right.install_backend(right_backend).unwrap();
        let left_handle = left
            .with_read_lease(left_generation, |lease| lease.open("/note.txt"))
            .unwrap();

        assert!(
            left.with_read_lease(left_generation, |lease| lease.open("/note.txt"))
                .is_err()
        );
        assert!(
            right
                .with_read_lease(right_generation, |lease| lease.read(&left_handle, 0, 4))
                .is_err()
        );
        let right_bytes = right
            .with_read_lease(right_generation, |lease| {
                let handle = lease.open("/note.txt")?;
                lease.read(&handle, 0, 5)
            })
            .unwrap();
        assert_eq!(right_bytes, b"right");

        left.revoke(|| Ok(())).unwrap();
        assert_eq!(
            left.with_read_lease(left_generation, |_| Ok(()))
                .unwrap_err()
                .kind,
            ErrorKind::Unauthorized
        );
        assert!(right.with_read_lease(right_generation, |_| Ok(())).is_ok());
    }
}

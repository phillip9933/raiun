//! Offline metadata/content adapter for the encrypted vault cache.
//!
//! Only sealed directory envelopes and verified vault ciphertext enter the
//! generic cache. Decrypted names are reconstructed after opening an envelope
//! with the exact unlocked session and are never published as cache metadata.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

use sha2::{Digest, Sha256};

use raiun_cache::{
    Cache, CacheError, CacheScope, CiphertextPinBuild, CiphertextPinInfo, CiphertextPinItemKind,
    CiphertextPinPage, CiphertextPinState, CiphertextSubtreeRetarget,
    CiphertextSubtreeRetargetContent, CiphertextWriteInfo, CiphertextWriteOperation,
    CiphertextWriteState, ContentProtection, ContentVersion, Retention, ScopeProtection,
};
use raiun_core::backend::{CloudError, ErrorKind, RemoteEntry, WriteCondition};
use raiun_vault::{
    sealed_cache::{
        MAX_CIPHERTEXT_BYTES, SealedVaultEntry, SealedVaultSnapshot, open_snapshot, seal_snapshot,
    },
    session::{VaultSessionCoordinator, VaultSessionScope},
};
use tempfile::{NamedTempFile, tempdir, tempdir_in};
use url::Url;

use crate::vault::VaultDavEntry;

const LISTING_ID_PREFIX: &str = "raiun-vault-listing-v1:";
const LISTING_ETAG_PREFIX: &str = "raiun-vault-sealed-metadata-v2:";
const FILE_ETAG_PREFIX: &str = "raiun-vault-file-ciphertext-v1:";
const MAX_PLAINTEXT_BYTES: u64 = 1 << 40;
const MAX_DISCOVERY_PAGE: usize = 100;
const EDIT_MAGIC: [u8; 8] = *b"RAIUNVE1";
const EDIT_VERSION: u16 = 1;
const EDIT_HEADER_BYTES: u64 = 8 + 2 + 4 + 8;
const MAX_EDIT_METADATA_BYTES: usize = 64 * 1024;
const MAX_EDIT_BYTES: u64 = 1 << 40;
const MAX_CREATE_OVERLAY_SCAN_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DIRECTORY_RETARGET_ITEMS: usize = 64;
const MAX_DIRECTORY_RETARGET_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VaultSubtreeRetargetRequest {
    pub id: String,
    pub expected_revision: u64,
    pub old_path: String,
    pub new_path: String,
    pub encoded_target: String,
    pub parent_ref: VaultPendingParentRef,
    pub parent_resource_id: String,
    pub parent_etag: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPendingDirectorySubtreeRetarget {
    pub root_write_id: String,
    pub root_previous_revision: u64,
    pub root_revision: u64,
    pub rows: Vec<VaultPendingDirectorySubtreeRetargetRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPendingDirectorySubtreeRetargetRow {
    pub write_id: String,
    pub previous_revision: u64,
    pub revision: u64,
    pub operation: VaultPendingOperationKind,
    pub old_path: String,
    pub old_encoded_target: String,
    pub old_parent_ref: VaultPendingParentRef,
    pub path: String,
    pub encoded_target: String,
    pub parent_ref: VaultPendingParentRef,
    pub plaintext_len: u64,
    pub plaintext_sha256: String,
    pub state: CiphertextWriteState,
}

/// Decrypted metadata for one local encrypted edit. Names and server IDs are
/// available only after exact-scope session verification; its Debug output is
/// redacted so paths and ETags do not leak into logs.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultPendingEditMetadata {
    pub id: String,
    pub revision: u64,
    /// Monotonic cache CAS token for explicit interrupted CreateFile retries.
    /// It is projected from SQLite, not stored in the sealed metadata body.
    pub retry_generation: u64,
    pub path: String,
    /// Destination logical path for RenameFile. Empty for other operations.
    pub destination_path: String,
    /// Encrypted DAV-relative path; opaque ciphertext, never a host path.
    pub encoded_target: String,
    /// Encrypted destination DAV-relative path for RenameFile.
    pub encoded_destination_target: String,
    pub root_integrity_token: String,
    pub base_resource_id: String,
    pub base_etag: String,
    /// Parent directory identity/version captured when a create was reserved.
    /// Empty only for legacy overwrite records that predate this binding.
    pub parent_resource_id: String,
    pub parent_etag: String,
    /// Authenticated directory identity. Pending references point to a
    /// CreateDirectory journal generation and are never inferred from a
    /// synthetic resource ID.
    pub parent_ref: Option<VaultPendingParentRef>,
    /// Exact readback identity for a committed CreateDirectory receipt.
    pub receipt_resource_id: String,
    pub receipt_etag: String,
    pub receipt_for_revision: u64,
    pub destination_parent_resource_id: String,
    pub destination_parent_etag: String,
    pub source_size: u64,
    /// SHA-256 of the source ciphertext blob captured before RenameFile.
    /// Empty for non-rename operations.
    pub source_ciphertext_sha256: String,
    /// Exact source binding for CopyFile. Present only on v12 copy records;
    /// older CopyFile rows remain review-only because they cannot be resolved
    /// against a source after restart.
    pub(crate) copy_source: Option<VaultCopySourceBinding>,
    pub base: WriteCondition,
    pub operation: VaultPendingOperationKind,
    pub plaintext_len: u64,
    pub state: CiphertextWriteState,
    /// Present only on an acknowledged cancellation's compact envelope. The
    /// original content body is removed; these fields bind the terminal proof
    /// to the exact retired local copy.
    pub cancelled_revision: u64,
    pub cancelled_plaintext_len: u64,
    pub cancelled_plaintext_sha256: String,
}

/// Source identity sealed inside a destination CopyFile journal envelope.
/// Runtime auth generations are intentionally absent; the resolver captures
/// fresh generations from independently unlocked backends after restart.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VaultCopySourceBinding {
    pub account_id: String,
    pub server_origin: String,
    pub space_id: String,
    pub root_resource_id: String,
    pub root_path: String,
    pub path: String,
    pub resource_id: String,
    pub etag: String,
    pub plaintext_len: u64,
    pub plaintext_sha256: String,
}

/// Exact source backend location authenticated by a destination CopyFile
/// journal envelope. This is an internal routing hint for the agent only; it
/// must never be accepted from IPC or serialized to a user-facing response.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultCopySourceTarget {
    pub scope: VaultSessionScope,
    pub root_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultPendingParentRef {
    Stable { resource_id: String },
    PendingCreate { write_id: String, revision: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultPendingOperationKind {
    Overwrite,
    CreateFile,
    RenameFile,
    DeleteFile,
    CreateDirectory,
    CopyFile,
}

pub(crate) struct VaultPendingEditRequest<'a> {
    pub integrity_token: &'a str,
    pub encoded_target: &'a str,
    pub base_resource_id: &'a str,
    pub base_etag: &'a str,
    pub existing_id: Option<&'a str>,
    pub body_len: u64,
}

pub(crate) struct VaultPendingOperationRequest<'a> {
    pub integrity_token: &'a str,
    pub encoded_target: &'a str,
    pub operation: VaultPendingOperationKind,
    pub base: WriteCondition,
    pub base_resource_id: Option<&'a str>,
    pub parent_resource_id: Option<&'a str>,
    pub parent_etag: Option<&'a str>,
    pub parent_ref: Option<&'a VaultPendingParentRef>,
    pub destination_target: Option<&'a str>,
    pub destination_parent_resource_id: Option<&'a str>,
    pub destination_parent_etag: Option<&'a str>,
    pub source_size: Option<u64>,
    pub source_ciphertext_sha256: Option<&'a str>,
    pub copy_source: Option<&'a VaultCopySourceBinding>,
    pub existing_id: Option<&'a str>,
    pub body_len: u64,
    pub state: CiphertextWriteState,
    pub receipt_resource_id: Option<&'a str>,
    pub receipt_etag: Option<&'a str>,
    pub receipt_for_revision: Option<u64>,
}

pub(crate) struct VaultPendingCreateRequest<'a> {
    pub integrity_token: &'a str,
    pub encoded_target: &'a str,
    pub existing_id: Option<&'a str>,
    pub parent_resource_id: Option<&'a str>,
    pub parent_etag: Option<&'a str>,
    pub parent_ref: &'a VaultPendingParentRef,
    pub body_len: u64,
    pub state: CiphertextWriteState,
}

pub(crate) struct VaultPendingRenameRequest<'a> {
    pub integrity_token: &'a str,
    pub encoded_source: &'a str,
    pub encoded_destination: &'a str,
    pub source_resource_id: &'a str,
    pub source_etag: &'a str,
    pub source_parent_resource_id: &'a str,
    pub source_parent_etag: &'a str,
    pub destination_parent_resource_id: &'a str,
    pub destination_parent_etag: &'a str,
    pub source_size: u64,
    pub source_ciphertext_sha256: &'a str,
}

pub(crate) struct VaultPendingDeleteRequest<'a> {
    pub integrity_token: &'a str,
    pub encoded_target: &'a str,
    pub source_resource_id: &'a str,
    pub source_etag: &'a str,
    pub parent_resource_id: &'a str,
    pub parent_etag: &'a str,
    pub source_size: u64,
    pub source_ciphertext_sha256: &'a str,
    pub body_len: u64,
}

struct DecodedPendingEnvelope {
    metadata: VaultPendingEditMetadata,
    _private: tempfile::TempDir,
    path: std::path::PathBuf,
    body_offset: u64,
}

impl std::fmt::Debug for VaultPendingEditMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultPendingEditMetadata")
            .field("id", &self.id)
            .field("revision", &self.revision)
            .field("path", &"[REDACTED]")
            .field("root_integrity_token", &"[REDACTED]")
            .field("base_resource_id", &"[REDACTED]")
            .field("base_etag", &"[REDACTED]")
            .field("parent_resource_id", &"[REDACTED]")
            .field("parent_etag", &"[REDACTED]")
            .field("plaintext_len", &self.plaintext_len)
            .field("state", &self.state)
            .finish()
    }
}

pub(crate) struct VaultListingMetadata<'a> {
    pub integrity_token: &'a str,
    pub root_etag: Option<&'a str>,
    pub space: &'a raiun_core::backend::CloudSpace,
    pub space_dav_root: &'a str,
    pub encrypted_directory_path: &'a str,
}

/// Exact-scope adapter over the encrypted-only content cache. Listing records
/// use opaque directory resource IDs; file records use server resource IDs
/// and strong ETags. No decrypted path/name is stored in SQLite or filenames.
pub struct VaultOfflineCache {
    cache: Cache,
    cache_scope: CacheScope,
    scope: VaultSessionScope,
    root_path: String,
    pin: Option<CiphertextPinInfo>,
}

/// Opaque cache candidate. The encrypted root path, display label, token, and
/// child names are intentionally unavailable until the envelope is unlocked.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultCachedRoot {
    pub space_id: String,
    pub root_resource_id: String,
    pub pin_id: Option<String>,
    pub generation: Option<u64>,
}

impl std::fmt::Debug for VaultCachedRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VaultCachedRoot")
            .field("space_id", &"[REDACTED]")
            .field("root_resource_id", &"[REDACTED]")
            .field("pin_id", &"[REDACTED]")
            .finish()
    }
}

pub struct VaultCachedRootPage {
    pub roots: Vec<VaultCachedRoot>,
    pub next_after: Option<(String, String)>,
    pub truncated: bool,
}

impl std::fmt::Debug for VaultOfflineCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultOfflineCache")
            .field("origin", &self.scope.server_origin())
            .field("scope", &"[REDACTED]")
            .field("root_path", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl VaultOfflineCache {
    /// Bind the generic ciphertext cache to one profile/account, origin, Space,
    /// and vault root. The account ID comes from the exact vault session scope.
    pub fn new(
        cache: Cache,
        scope: VaultSessionScope,
        root_path: impl Into<String>,
    ) -> Result<Self, CloudError> {
        let root_path = normalize_root_path(&root_path.into())?;
        let cache_scope = cache_scope(&scope)?;
        Ok(Self {
            cache,
            cache_scope,
            scope,
            root_path,
            pin: None,
        })
    }

    pub fn new_for_pin(
        cache: Cache,
        scope: VaultSessionScope,
        root_path: impl Into<String>,
        pin_id: &str,
    ) -> Result<Self, CloudError> {
        let root_path = normalize_root_path(&root_path.into())?;
        let cache_scope = cache_scope(&scope)?;
        let pin = cache
            .active_ciphertext_pin_info(&cache_scope, pin_id)
            .map_err(cache_error)?;
        if pin.state != CiphertextPinState::Ready {
            return Err(conflict("encrypted snapshot is not current and complete"));
        }
        Ok(Self {
            cache,
            cache_scope,
            scope,
            root_path,
            pin: Some(pin),
        })
    }

    /// Bind to one specific ready generation rather than whichever generation
    /// is latest when this constructor happens to run.
    pub fn new_for_pin_generation(
        cache: Cache,
        scope: VaultSessionScope,
        root_path: impl Into<String>,
        pin_id: &str,
        expected_generation: u64,
    ) -> Result<Self, CloudError> {
        let root_path = normalize_root_path(&root_path.into())?;
        let cache_scope = cache_scope(&scope)?;
        let pin = cache
            .active_ciphertext_pin_info(&cache_scope, pin_id)
            .map_err(cache_error)?;
        if pin.state != CiphertextPinState::Ready || pin.generation != expected_generation {
            return Err(conflict("encrypted snapshot generation changed"));
        }
        Ok(Self {
            cache,
            cache_scope,
            scope,
            root_path,
            pin: Some(pin),
        })
    }

    pub fn scope(&self) -> &VaultSessionScope {
        &self.scope
    }

    pub fn root_path(&self) -> &str {
        &self.root_path
    }

    pub fn ciphertext_epoch(&self) -> Result<u64, CloudError> {
        self.cache
            .ciphertext_epoch(&self.cache_scope)
            .map_err(cache_error)
    }

    pub(crate) fn begin_pin_generation(
        &self,
        expected_epoch: u64,
        existing_pin_id: Option<&str>,
    ) -> Result<CiphertextPinBuild, CloudError> {
        self.cache
            .begin_ciphertext_pin(&self.cache_scope, expected_epoch, existing_pin_id)
            .map_err(cache_error)
    }

    pub(crate) fn finish_pin_generation(
        &self,
        build: &CiphertextPinBuild,
    ) -> Result<CiphertextPinInfo, CloudError> {
        self.cache
            .finish_ciphertext_pin(&self.cache_scope, build)
            .map_err(cache_error)
    }

    pub(crate) fn abandon_pin_generation(
        &self,
        build: &CiphertextPinBuild,
    ) -> Result<(), CloudError> {
        self.cache
            .abandon_ciphertext_pin(&self.cache_scope, build)
            .map_err(cache_error)
    }

    pub fn pin_info(&self, pin_id: &str) -> Result<CiphertextPinInfo, CloudError> {
        self.cache
            .ciphertext_pin_info(&self.cache_scope, pin_id)
            .map_err(cache_error)
    }

    /// Fence a brief publication step against refresh/removal of the selected
    /// ready snapshot generation. The closure must not call back into this
    /// cache, and should only publish the already-verified offline route.
    pub fn with_active_pin_generation<T>(
        &self,
        pin_id: &str,
        expected_generation: u64,
        operation: impl FnOnce() -> T,
    ) -> Result<T, CloudError> {
        self.cache
            .with_active_ciphertext_pin_generation(
                &self.cache_scope,
                pin_id,
                expected_generation,
                operation,
            )
            .map_err(cache_error)
    }

    pub fn pins(&self, after: Option<&str>, limit: usize) -> Result<CiphertextPinPage, CloudError> {
        self.cache
            .ciphertext_pins(&self.cache_scope, after, limit)
            .map_err(cache_error)
    }

    pub fn remove_pin(&self, pin_id: &str) -> Result<(), CloudError> {
        self.cache
            .remove_ciphertext_pin(&self.cache_scope, pin_id)
            .map_err(cache_error)
    }

    pub(crate) fn preflight_ciphertext_space(&self, required_bytes: u64) -> Result<(), CloudError> {
        self.cache
            .preflight_ciphertext_space(required_bytes)
            .map_err(cache_error)
    }

    pub(crate) fn trim_recent_before_pin(&self) -> Result<(), CloudError> {
        self.cache
            .evict_recent(self.cache.quota_bytes())
            .map(|_| ())
            .map_err(cache_error)
    }

    /// Revoke cached encrypted authority before a remote write. Call this
    /// before sending any mutating request, including requests whose outcome
    /// may be ambiguous after a transport failure.
    pub(crate) fn invalidate_before_remote_mutation(&self) -> Result<u64, CloudError> {
        self.cache
            .invalidate_ciphertext_scope(&self.cache_scope)
            .map_err(cache_error)
    }

    /// Store one complete, exact-scope encrypted edit revision. The file is
    /// framed and encrypted with the verified vault session before the generic
    /// cache sees it; only the random ID, revision, size, and lifecycle state
    /// are stored outside the ciphertext.
    pub(crate) fn queue_edit<R: Read + Seek>(
        &self,
        sessions: &VaultSessionCoordinator,
        source: &mut R,
        request: VaultPendingEditRequest<'_>,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        self.queue_operation(
            sessions,
            source,
            VaultPendingOperationRequest {
                integrity_token: request.integrity_token,
                encoded_target: request.encoded_target,
                operation: VaultPendingOperationKind::Overwrite,
                base: WriteCondition::Match(request.base_etag.to_owned()),
                base_resource_id: Some(request.base_resource_id),
                parent_resource_id: None,
                parent_etag: None,
                parent_ref: None,
                destination_target: None,
                destination_parent_resource_id: None,
                destination_parent_etag: None,
                source_size: None,
                source_ciphertext_sha256: None,
                copy_source: None,
                existing_id: request.existing_id,
                body_len: request.body_len,
                state: CiphertextWriteState::Pending,
                receipt_resource_id: None,
                receipt_etag: None,
                receipt_for_revision: None,
            },
        )
    }

    pub(crate) fn queue_create_with_state<R: Read + Seek>(
        &self,
        sessions: &VaultSessionCoordinator,
        source: &mut R,
        request: VaultPendingCreateRequest<'_>,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        self.queue_operation(
            sessions,
            source,
            VaultPendingOperationRequest {
                integrity_token: request.integrity_token,
                encoded_target: request.encoded_target,
                operation: VaultPendingOperationKind::CreateFile,
                base: WriteCondition::Absent,
                base_resource_id: None,
                parent_resource_id: request.parent_resource_id,
                parent_etag: request.parent_etag,
                parent_ref: Some(request.parent_ref),
                destination_target: None,
                destination_parent_resource_id: None,
                destination_parent_etag: None,
                source_size: None,
                source_ciphertext_sha256: None,
                copy_source: None,
                existing_id: request.existing_id,
                body_len: request.body_len,
                state: request.state,
                receipt_resource_id: None,
                receipt_etag: None,
                receipt_for_revision: None,
            },
        )
    }

    pub(crate) fn queue_copy_file<R: Read + Seek>(
        &self,
        sessions: &VaultSessionCoordinator,
        source: &mut R,
        request: VaultPendingCreateRequest<'_>,
        copy_source: &VaultCopySourceBinding,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        if request.existing_id.is_some() || request.state != CiphertextWriteState::NeverAttempted {
            return Err(invalid("encrypted copy journal request is invalid"));
        }
        self.queue_operation(
            sessions,
            source,
            VaultPendingOperationRequest {
                integrity_token: request.integrity_token,
                encoded_target: request.encoded_target,
                operation: VaultPendingOperationKind::CopyFile,
                base: WriteCondition::Absent,
                base_resource_id: None,
                parent_resource_id: request.parent_resource_id,
                parent_etag: request.parent_etag,
                parent_ref: Some(request.parent_ref),
                destination_target: None,
                destination_parent_resource_id: None,
                destination_parent_etag: None,
                source_size: None,
                source_ciphertext_sha256: None,
                copy_source: Some(copy_source),
                existing_id: None,
                body_len: request.body_len,
                state: CiphertextWriteState::NeverAttempted,
                receipt_resource_id: None,
                receipt_etag: None,
                receipt_for_revision: None,
            },
        )
    }

    pub(crate) fn begin_create<R: Read + Seek>(
        &self,
        sessions: &VaultSessionCoordinator,
        source: &mut R,
        request: VaultPendingCreateRequest<'_>,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        self.queue_create_with_state(
            sessions,
            source,
            VaultPendingCreateRequest {
                state: CiphertextWriteState::Building,
                ..request
            },
        )
    }

    pub(crate) fn queue_rename(
        &self,
        sessions: &VaultSessionCoordinator,
        request: VaultPendingRenameRequest<'_>,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        let mut empty = io::Cursor::new([]);
        self.queue_operation(
            sessions,
            &mut empty,
            VaultPendingOperationRequest {
                integrity_token: request.integrity_token,
                encoded_target: request.encoded_source,
                operation: VaultPendingOperationKind::RenameFile,
                base: WriteCondition::Match(request.source_etag.to_owned()),
                base_resource_id: Some(request.source_resource_id),
                parent_resource_id: Some(request.source_parent_resource_id),
                parent_etag: Some(request.source_parent_etag),
                parent_ref: None,
                destination_target: Some(request.encoded_destination),
                destination_parent_resource_id: Some(request.destination_parent_resource_id),
                destination_parent_etag: Some(request.destination_parent_etag),
                source_size: Some(request.source_size),
                source_ciphertext_sha256: Some(request.source_ciphertext_sha256),
                copy_source: None,
                existing_id: None,
                body_len: 0,
                state: CiphertextWriteState::Pending,
                receipt_resource_id: None,
                receipt_etag: None,
                receipt_for_revision: None,
            },
        )
    }

    pub(crate) fn queue_delete<R: Read + Seek>(
        &self,
        sessions: &VaultSessionCoordinator,
        source: &mut R,
        request: VaultPendingDeleteRequest<'_>,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        if request.body_len != request.source_size {
            return Err(invalid("encrypted delete recovery body length is invalid"));
        }
        self.queue_operation(
            sessions,
            source,
            VaultPendingOperationRequest {
                integrity_token: request.integrity_token,
                encoded_target: request.encoded_target,
                operation: VaultPendingOperationKind::DeleteFile,
                base: WriteCondition::Match(request.source_etag.to_owned()),
                base_resource_id: Some(request.source_resource_id),
                parent_resource_id: Some(request.parent_resource_id),
                parent_etag: Some(request.parent_etag),
                parent_ref: None,
                destination_target: None,
                destination_parent_resource_id: None,
                destination_parent_etag: None,
                source_size: Some(request.source_size),
                source_ciphertext_sha256: Some(request.source_ciphertext_sha256),
                copy_source: None,
                existing_id: None,
                body_len: request.body_len,
                state: CiphertextWriteState::Pending,
                receipt_resource_id: None,
                receipt_etag: None,
                receipt_for_revision: None,
            },
        )
    }

    pub(crate) fn queue_directory_create(
        &self,
        sessions: &VaultSessionCoordinator,
        request: VaultPendingCreateRequest<'_>,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        if request.body_len != 0
            || request.existing_id.is_some()
            || request.state != CiphertextWriteState::NeverAttempted
        {
            return Err(invalid("encrypted directory create request is invalid"));
        }
        let mut empty = io::Cursor::new([]);
        self.queue_operation(
            sessions,
            &mut empty,
            VaultPendingOperationRequest {
                integrity_token: request.integrity_token,
                encoded_target: request.encoded_target,
                operation: VaultPendingOperationKind::CreateDirectory,
                base: WriteCondition::Absent,
                base_resource_id: None,
                parent_resource_id: request.parent_resource_id,
                parent_etag: request.parent_etag,
                parent_ref: Some(request.parent_ref),
                destination_target: None,
                destination_parent_resource_id: None,
                destination_parent_etag: None,
                source_size: None,
                source_ciphertext_sha256: None,
                copy_source: None,
                existing_id: None,
                body_len: 0,
                state: CiphertextWriteState::NeverAttempted,
                receipt_resource_id: None,
                receipt_etag: None,
                receipt_for_revision: None,
            },
        )
    }

    pub(crate) fn commit_directory_receipt(
        &self,
        sessions: &VaultSessionCoordinator,
        previous: &VaultPendingEditMetadata,
        entry: &RemoteEntry,
        parent_ref: &VaultPendingParentRef,
        parent_resource_id: &str,
        parent_etag: &str,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        if previous.operation != VaultPendingOperationKind::CreateDirectory
            || !matches!(
                previous.state,
                CiphertextWriteState::Pending
                    | CiphertextWriteState::Uncertain
                    | CiphertextWriteState::Attempting
            )
            || previous.base != WriteCondition::Absent
            || !entry.directory
            || entry.path != previous.path
            || entry.id.is_empty()
            || entry.id.len() > 512
            || entry.etag.is_empty()
            || entry.etag.len() > 4_096
            || previous.revision == 0
        {
            return Err(conflict(
                "directory readback cannot be recorded as a receipt",
            ));
        }
        let mut empty = io::Cursor::new([]);
        self.queue_operation(
            sessions,
            &mut empty,
            VaultPendingOperationRequest {
                integrity_token: &previous.root_integrity_token,
                encoded_target: &previous.encoded_target,
                operation: VaultPendingOperationKind::CreateDirectory,
                base: WriteCondition::Absent,
                base_resource_id: None,
                parent_resource_id: Some(parent_resource_id),
                parent_etag: Some(parent_etag),
                parent_ref: Some(parent_ref),
                destination_target: None,
                destination_parent_resource_id: None,
                destination_parent_etag: None,
                source_size: None,
                source_ciphertext_sha256: None,
                copy_source: None,
                existing_id: Some(&previous.id),
                body_len: 0,
                state: CiphertextWriteState::CommittedReceipt,
                receipt_resource_id: Some(&entry.id),
                receipt_etag: Some(&entry.etag),
                receipt_for_revision: Some(previous.revision),
            },
        )
    }

    pub(crate) fn queue_operation<R: Read + Seek>(
        &self,
        sessions: &VaultSessionCoordinator,
        source: &mut R,
        request: VaultPendingOperationRequest<'_>,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        self.queue_operation_inner(sessions, source, request, None)
    }

    pub(crate) fn queue_retargeted_create<R: Read + Seek>(
        &self,
        sessions: &VaultSessionCoordinator,
        source: &mut R,
        request: VaultPendingOperationRequest<'_>,
        old_encoded_target: &str,
        expected_revision: u64,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        if request.operation != VaultPendingOperationKind::CreateFile
            || request.state != CiphertextWriteState::NeverAttempted
            || request.existing_id.is_none()
        {
            return Err(conflict("encrypted create retarget request is invalid"));
        }
        self.queue_operation_inner(
            sessions,
            source,
            request,
            Some((old_encoded_target, expected_revision)),
        )
    }

    pub(crate) fn queue_retargeted_directory_create(
        &self,
        sessions: &VaultSessionCoordinator,
        request: VaultPendingOperationRequest<'_>,
        old_encoded_target: &str,
        expected_revision: u64,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        if request.operation != VaultPendingOperationKind::CreateDirectory
            || request.state != CiphertextWriteState::NeverAttempted
            || request.existing_id.is_none()
            || request.body_len != 0
        {
            return Err(conflict("encrypted directory retarget request is invalid"));
        }
        let mut empty = io::Cursor::new([]);
        self.queue_operation_inner(
            sessions,
            &mut empty,
            request,
            Some((old_encoded_target, expected_revision)),
        )
    }

    /// Reseal and atomically retarget an entire never-attempted queued
    /// directory subtree. The cache transaction switches all operation rows
    /// together; on any validation or publication failure, every old row
    /// remains authoritative.
    pub(crate) fn retarget_never_attempted_directory_subtree(
        &self,
        sessions: &VaultSessionCoordinator,
        root_id: &str,
        root_revision: u64,
        requests: &[VaultSubtreeRetargetRequest],
        before_publish: &mut dyn FnMut(
            &VaultPendingDirectorySubtreeRetarget,
        ) -> Result<(), CloudError>,
    ) -> Result<VaultPendingDirectorySubtreeRetarget, CloudError> {
        if !(1..=MAX_DIRECTORY_RETARGET_ITEMS).contains(&requests.len()) {
            return Err(invalid(
                "queued directory subtree exceeds its operation limit",
            ));
        }
        if !sessions.is_unlocked(&self.scope).map_err(vault_error)? {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault session is locked",
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut previous_rows = Vec::with_capacity(requests.len());
        let mut members = Vec::with_capacity(requests.len());
        let mut body_total = 0u64;
        let root = requests
            .iter()
            .find(|request| request.id == root_id)
            .ok_or_else(|| conflict("queued subtree root is missing"))?;
        if root.expected_revision != root_revision {
            return Err(conflict("queued subtree root revision changed"));
        }
        let integrity_token;
        {
            let root_previous = self.pending_operation(sessions, root_id, root_revision)?;
            if root_previous.operation != VaultPendingOperationKind::CreateDirectory
                || root_previous.state != CiphertextWriteState::NeverAttempted
                || root_previous.base != WriteCondition::Absent
                || root_previous.path != root.old_path
                || root_previous.receipt_for_revision != 0
                || root_previous.parent_ref.is_none()
            {
                return Err(conflict(
                    "queued subtree root is stale or has been attempted",
                ));
            }
            integrity_token = root_previous.root_integrity_token.clone();
        }
        for request in requests {
            if !ids.insert(request.id.as_str())
                || request.old_path == "/"
                || request.new_path == "/"
                || request.old_path == request.new_path
                || request.encoded_target.is_empty()
            {
                return Err(conflict("queued subtree member identity is invalid"));
            }
            validate_pending_path(&request.old_path)?;
            validate_pending_path(&request.new_path)?;
            let previous =
                self.pending_operation(sessions, &request.id, request.expected_revision)?;
            if !matches!(
                previous.operation,
                VaultPendingOperationKind::CreateDirectory | VaultPendingOperationKind::CreateFile
            ) || previous.state != CiphertextWriteState::NeverAttempted
                || previous.base != WriteCondition::Absent
                || previous.path != request.old_path
                || previous.root_integrity_token != integrity_token
                || previous.receipt_for_revision != 0
                || !previous.receipt_resource_id.is_empty()
                || !previous.receipt_etag.is_empty()
                || previous.plaintext_len > MAX_DIRECTORY_RETARGET_BYTES
                || (previous.operation == VaultPendingOperationKind::CreateDirectory
                    && previous.plaintext_len != 0)
            {
                return Err(conflict(
                    "queued subtree includes an unsupported or stale operation",
                ));
            }
            let decoded = sessions
                .decrypt_path(&self.scope, &request.encoded_target)
                .map_err(vault_error)?;
            if decoded.is_root()
                || format!("/{}", decoded.into_components().join("/")) != request.new_path
            {
                return Err(conflict(
                    "queued subtree target does not match its sealed path",
                ));
            }
            let parent_path = split_parent(&request.new_path).0;
            let encrypted_parent = sessions
                .encrypt_path(&self.scope, parent_path.trim_start_matches('/'))
                .map_err(vault_error)?;
            let new_parent_operation = match &request.parent_ref {
                VaultPendingParentRef::PendingCreate { write_id, revision } => {
                    Some((write_id.clone(), *revision))
                }
                VaultPendingParentRef::Stable { .. } => None,
            };
            body_total = body_total
                .checked_add(previous.plaintext_len)
                .filter(|total| *total <= MAX_DIRECTORY_RETARGET_BYTES)
                .ok_or_else(|| invalid("queued directory subtree exceeds its byte limit"))?;
            members.push(CiphertextSubtreeRetarget {
                id: request.id.clone(),
                expected_revision: request.expected_revision,
                expected_target: previous.encoded_target.clone(),
                new_target: request.encoded_target.clone(),
                new_parent_path: encrypted_parent,
                new_parent_operation,
                plaintext_len: previous.plaintext_len,
                operation: match previous.operation {
                    VaultPendingOperationKind::CreateFile => CiphertextWriteOperation::CreateFile,
                    VaultPendingOperationKind::CopyFile => CiphertextWriteOperation::CopyFile,
                    VaultPendingOperationKind::CreateDirectory => {
                        CiphertextWriteOperation::CreateDirectory
                    }
                    _ => unreachable!("operation was checked above"),
                },
            });
            previous_rows.push(previous);
        }
        let builds = self
            .cache
            .begin_ciphertext_never_attempted_subtree_retarget(
                &self.cache_scope,
                root_id,
                root_revision,
                &members,
            )
            .map_err(cache_error)?;

        let private = tempdir().map_err(io_error)?;
        let mut private_dirs = Vec::with_capacity(requests.len());
        let mut ciphertext_files = Vec::with_capacity(requests.len());
        let mut plaintext_hashes = Vec::with_capacity(requests.len());
        let mut encrypted_lengths = Vec::with_capacity(requests.len());
        let mut output_metadata = Vec::with_capacity(requests.len());
        for ((request, previous), build) in requests.iter().zip(&previous_rows).zip(&builds) {
            let envelope = self.open_pending_envelope(
                sessions,
                &self
                    .cache
                    .ciphertext_write_info(&self.cache_scope, &request.id)
                    .map_err(cache_error)?,
            )?;
            if envelope.metadata.revision != request.expected_revision
                || envelope.metadata.path != request.old_path
                || envelope.metadata.state != CiphertextWriteState::NeverAttempted
            {
                return Err(conflict(
                    "queued subtree member changed while being resealed",
                ));
            }
            let row_dir = tempdir_in(private.path()).map_err(io_error)?;
            let plain_path = row_dir.path().join("retarget-envelope.tmp");
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&plain_path)
                .map_err(io_error)?;
            set_private_file(&output)?;
            let metadata = serde_json::json!({
                "version": 9,
                "operation": match previous.operation {
                    VaultPendingOperationKind::CreateDirectory => "create_directory",
                    VaultPendingOperationKind::CreateFile => "create_file",
                    VaultPendingOperationKind::CopyFile => "copy_file",
                    _ => unreachable!("operation was checked above"),
                },
                "id": previous.id,
                "revision": build.revision(),
                "account_id": self.scope.account_id(),
                "server_origin": self.scope.server_origin(),
                "space_id": self.scope.space_id(),
                "root_resource_id": self.scope.resource_id(),
                "root_path": self.root_path,
                "integrity_token": integrity_token,
                "encoded_target": request.encoded_target,
                "destination_path": "",
                "encoded_destination_target": "",
                "base_resource_id": "",
                "base_etag": "",
                "base_kind": "absent",
                "parent_resource_id": request.parent_resource_id,
                "parent_etag": request.parent_etag,
                "parent_ref": match &request.parent_ref {
                    VaultPendingParentRef::Stable { resource_id } => serde_json::json!({"kind":"stable","resource_id":resource_id}),
                    VaultPendingParentRef::PendingCreate { write_id, revision } => serde_json::json!({"kind":"pending_create","write_id":write_id,"revision":revision}),
                },
                "receipt_resource_id": "",
                "receipt_etag": "",
                "receipt_for_revision": 0,
                "destination_parent_resource_id": "",
                "destination_parent_etag": "",
                "source_size": 0,
                "source_ciphertext_sha256": "",
                "body_len": previous.plaintext_len,
            });
            let metadata = serde_json::to_vec(&metadata)
                .map_err(|_| invalid("queued subtree metadata could not be encoded"))?;
            if metadata.len() > MAX_EDIT_METADATA_BYTES {
                return Err(invalid("queued subtree metadata exceeds its size limit"));
            }
            let envelope_len = EDIT_HEADER_BYTES
                .checked_add(metadata.len() as u64)
                .and_then(|len| len.checked_add(previous.plaintext_len))
                .ok_or_else(|| invalid("queued subtree envelope size overflowed"))?;
            output.write_all(&EDIT_MAGIC).map_err(io_error)?;
            output
                .write_all(&EDIT_VERSION.to_be_bytes())
                .map_err(io_error)?;
            output
                .write_all(&(metadata.len() as u32).to_be_bytes())
                .map_err(io_error)?;
            output
                .write_all(&previous.plaintext_len.to_be_bytes())
                .map_err(io_error)?;
            output.write_all(&metadata).map_err(io_error)?;
            let mut body = File::open(&envelope.path).map_err(io_error)?;
            body.seek(SeekFrom::Start(envelope.body_offset))
                .map_err(io_error)?;
            let digest = copy_exact_hash(&mut body, &mut output, previous.plaintext_len)?;
            output.flush().map_err(io_error)?;
            output.sync_all().map_err(io_error)?;
            drop(output);
            if !sessions.is_unlocked(&self.scope).map_err(vault_error)? {
                return Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "vault session is locked",
                ));
            }
            let ciphertext_path = row_dir.path().join("retarget-ciphertext.tmp");
            let mut plaintext = File::open(&plain_path).map_err(io_error)?;
            let encrypted_len = sessions
                .encrypt_file_transactional(
                    &self.scope,
                    &mut plaintext,
                    &ciphertext_path,
                    envelope_len,
                    MAX_EDIT_BYTES + EDIT_HEADER_BYTES + MAX_EDIT_METADATA_BYTES as u64,
                )
                .map_err(vault_error)?;
            let ciphertext = File::open(&ciphertext_path).map_err(io_error)?;
            let cipher_len = ciphertext.metadata().map_err(io_error)?.len();
            if encrypted_len != envelope_len || cipher_len == 0 {
                return Err(invalid("queued subtree ciphertext length is invalid"));
            }
            let updated = VaultPendingEditMetadata {
                revision: build.revision(),
                path: request.new_path.clone(),
                encoded_target: request.encoded_target.clone(),
                parent_resource_id: request.parent_resource_id.clone(),
                parent_etag: request.parent_etag.clone(),
                parent_ref: Some(request.parent_ref.clone()),
                ..previous.clone()
            };
            private_dirs.push(row_dir);
            ciphertext_files.push(ciphertext);
            plaintext_hashes.push(
                if previous.operation == VaultPendingOperationKind::CreateDirectory {
                    String::new()
                } else {
                    digest
                },
            );
            encrypted_lengths.push(cipher_len);
            output_metadata.push(updated);
        }
        let mut batch = builds
            .iter()
            .zip(ciphertext_files.iter_mut())
            .zip(encrypted_lengths.iter().copied())
            .map(
                |((build, source), expected_len)| CiphertextSubtreeRetargetContent {
                    build,
                    source,
                    expected_len,
                },
            )
            .collect::<Vec<_>>();
        let rows = output_metadata
            .iter()
            .zip(&previous_rows)
            .zip(&builds)
            .zip(&plaintext_hashes)
            .map(|(((metadata, previous), build), plaintext_sha256)| {
                Ok(VaultPendingDirectorySubtreeRetargetRow {
                    write_id: metadata.id.clone(),
                    previous_revision: previous.revision,
                    revision: build.revision(),
                    operation: metadata.operation,
                    old_path: previous.path.clone(),
                    old_encoded_target: previous.encoded_target.clone(),
                    old_parent_ref: previous
                        .parent_ref
                        .clone()
                        .ok_or_else(|| conflict("queued subtree old parent is missing"))?,
                    path: metadata.path.clone(),
                    encoded_target: metadata.encoded_target.clone(),
                    parent_ref: metadata
                        .parent_ref
                        .clone()
                        .ok_or_else(|| conflict("queued subtree parent is missing"))?,
                    plaintext_len: metadata.plaintext_len,
                    plaintext_sha256: plaintext_sha256.clone(),
                    state: CiphertextWriteState::NeverAttempted,
                })
            })
            .collect::<Result<Vec<_>, CloudError>>()?;
        let root_revision = rows
            .iter()
            .find(|row| row.write_id == root_id)
            .map(|row| row.revision)
            .ok_or_else(|| conflict("queued subtree root disappeared"))?;
        let retarget = VaultPendingDirectorySubtreeRetarget {
            root_write_id: root_id.to_owned(),
            root_previous_revision: root_revision.saturating_sub(1),
            root_revision,
            rows,
        };
        // The caller must durably record this complete exact-ID batch before
        // the following cache transaction can change any current revision.
        before_publish(&retarget)?;
        self.cache
            .publish_ciphertext_subtree_retarget(&self.cache_scope, &builds, &mut batch, root_id)
            .map_err(cache_error)?;
        drop(private_dirs);
        drop(private);
        Ok(retarget)
    }

    fn queue_operation_inner<R: Read + Seek>(
        &self,
        sessions: &VaultSessionCoordinator,
        source: &mut R,
        request: VaultPendingOperationRequest<'_>,
        retarget_create: Option<(&str, u64)>,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        let VaultPendingOperationRequest {
            integrity_token,
            encoded_target,
            operation,
            mut base,
            base_resource_id,
            parent_resource_id,
            parent_etag,
            parent_ref,
            destination_target,
            destination_parent_resource_id,
            destination_parent_etag,
            source_size,
            source_ciphertext_sha256,
            copy_source,
            existing_id,
            body_len,
            state,
            receipt_resource_id,
            receipt_etag,
            receipt_for_revision,
        } = request;
        let mut base_resource_id = base_resource_id.map(str::to_owned);
        let mut parent_resource_id = parent_resource_id.map(str::to_owned);
        let mut parent_etag = parent_etag.map(str::to_owned);
        let parent_ref = parent_ref.cloned();
        let copy_source = copy_source.cloned();
        let receipt_resource_id = receipt_resource_id.map(str::to_owned);
        let receipt_etag = receipt_etag.map(str::to_owned);
        let receipt_valid = state == CiphertextWriteState::CommittedReceipt
            && operation == VaultPendingOperationKind::CreateDirectory
            && receipt_resource_id
                .as_deref()
                .is_some_and(|id| !id.is_empty() && id.len() <= 512)
            && receipt_etag
                .as_deref()
                .is_some_and(|etag| !etag.is_empty() && etag.len() <= 4_096)
            && receipt_for_revision
                .is_some_and(|revision| revision > 0 && revision <= i64::MAX as u64);
        if (state == CiphertextWriteState::CommittedReceipt) != receipt_valid
            || (state != CiphertextWriteState::CommittedReceipt
                && (receipt_resource_id.is_some()
                    || receipt_etag.is_some()
                    || receipt_for_revision.is_some()))
        {
            return Err(invalid("encrypted directory receipt is invalid"));
        }
        let base_valid = match (operation, &base, base_resource_id.as_deref()) {
            (VaultPendingOperationKind::Overwrite, WriteCondition::Match(etag), Some(id)) => {
                !etag.is_empty() && etag.len() <= 4096 && !id.is_empty() && id.len() <= 512
            }
            (VaultPendingOperationKind::CreateFile, WriteCondition::Absent, None)
            | (VaultPendingOperationKind::CopyFile, WriteCondition::Absent, None) => true,
            (VaultPendingOperationKind::RenameFile, WriteCondition::Match(etag), Some(id)) => {
                !etag.is_empty() && etag.len() <= 4_096 && !id.is_empty() && id.len() <= 512
            }
            (VaultPendingOperationKind::DeleteFile, WriteCondition::Match(etag), Some(id)) => {
                !etag.is_empty() && etag.len() <= 4_096 && !id.is_empty() && id.len() <= 512
            }
            (VaultPendingOperationKind::CreateDirectory, WriteCondition::Absent, None) => true,
            _ => false,
        };
        if body_len > MAX_EDIT_BYTES
            || !base_valid
            || (operation == VaultPendingOperationKind::CopyFile
                && copy_source
                    .as_ref()
                    .is_none_or(|binding| !valid_copy_source_binding(binding, body_len)))
            || (operation != VaultPendingOperationKind::CopyFile && copy_source.is_some())
            || (matches!(
                state,
                CiphertextWriteState::NeverAttempted | CiphertextWriteState::Attempting
            ) && !matches!(
                operation,
                VaultPendingOperationKind::CreateDirectory
                    | VaultPendingOperationKind::CreateFile
                    | VaultPendingOperationKind::CopyFile
            ))
            || (state == CiphertextWriteState::Building
                && operation != VaultPendingOperationKind::CreateFile)
            || encoded_target.is_empty()
            || encoded_target.len() > 32_768
            || (matches!(
                operation,
                VaultPendingOperationKind::CreateFile | VaultPendingOperationKind::CopyFile
            ) && parent_ref.is_none())
            || (operation == VaultPendingOperationKind::RenameFile
                && destination_target.is_none_or(|value| value.is_empty() || value.len() > 32_768))
            || (operation == VaultPendingOperationKind::RenameFile
                && destination_parent_resource_id
                    .is_none_or(|value| value.is_empty() || value.len() > 512))
            || (operation == VaultPendingOperationKind::RenameFile
                && destination_parent_etag
                    .is_none_or(|value| value.is_empty() || value.len() > 4_096))
            || (operation == VaultPendingOperationKind::RenameFile
                && parent_resource_id
                    .as_deref()
                    .is_none_or(|value| value.is_empty() || value.len() > 512))
            || (operation == VaultPendingOperationKind::RenameFile
                && parent_etag
                    .as_deref()
                    .is_none_or(|value| value.is_empty() || value.len() > 4_096))
            || (operation == VaultPendingOperationKind::RenameFile && source_size.is_none())
            || (operation == VaultPendingOperationKind::RenameFile
                && source_ciphertext_sha256.is_none_or(|value| !is_sha256_digest(value)))
            || (operation == VaultPendingOperationKind::DeleteFile
                && (source_size != Some(body_len)
                    || source_ciphertext_sha256.is_none_or(|value| !is_sha256_digest(value))))
            || (operation == VaultPendingOperationKind::DeleteFile
                && parent_resource_id
                    .as_deref()
                    .is_none_or(|value| value.is_empty() || value.len() > 512))
            || (operation == VaultPendingOperationKind::DeleteFile
                && parent_etag
                    .as_deref()
                    .is_none_or(|value| value.is_empty() || value.len() > 4_096))
            || (operation == VaultPendingOperationKind::CreateDirectory
                && (body_len != 0 || parent_ref.is_none()))
            || (!matches!(
                operation,
                VaultPendingOperationKind::CreateFile
                    | VaultPendingOperationKind::CreateDirectory
                    | VaultPendingOperationKind::CopyFile
            ) && parent_ref.is_some())
        {
            return Err(invalid("encrypted operation metadata exceeds its bounds"));
        }
        if let Some(parent_ref) = parent_ref.as_ref() {
            match parent_ref {
                VaultPendingParentRef::Stable { resource_id }
                    if !resource_id.is_empty()
                        && resource_id.len() <= 512
                        && parent_resource_id.as_deref() == Some(resource_id)
                        && parent_etag
                            .as_deref()
                            .is_some_and(|etag| !etag.is_empty() && etag.len() <= 4_096) => {}
                VaultPendingParentRef::PendingCreate { write_id, revision }
                    if matches!(
                        operation,
                        VaultPendingOperationKind::CreateFile
                            | VaultPendingOperationKind::CreateDirectory
                    ) && !write_id.is_empty()
                        && write_id.len() == 32
                        && write_id.bytes().all(|byte| byte.is_ascii_hexdigit())
                        && *revision > 0
                        && *revision <= i64::MAX as u64
                        && parent_resource_id.is_none()
                        && parent_etag.is_none() => {}
                _ => return Err(invalid("encrypted parent reference is invalid")),
            }
        }
        if !sessions
            .verify_integrity_token(&self.scope, integrity_token)
            .map_err(vault_error)?
        {
            return Err(conflict(
                "encrypted operation does not match the unlocked vault",
            ));
        }
        let decoded = sessions
            .decrypt_path(&self.scope, encoded_target)
            .map_err(vault_error)?;
        if decoded.is_root() {
            return Err(invalid("encrypted operation cannot target the vault root"));
        }
        let path = format!("/{}", decoded.into_components().join("/"));
        validate_pending_path(&path)?;
        let (destination_path, destination_encoded_parent) =
            if operation == VaultPendingOperationKind::RenameFile {
                let encoded = destination_target.expect("validated rename destination");
                let decoded = sessions
                    .decrypt_path(&self.scope, encoded)
                    .map_err(vault_error)?;
                if decoded.is_root() {
                    return Err(invalid("encrypted rename cannot target the vault root"));
                }
                let destination = format!("/{}", decoded.into_components().join("/"));
                validate_pending_path(&destination)?;
                if destination == path {
                    return Err(invalid("encrypted rename source and destination are equal"));
                }
                let parent_relative = split_parent(&destination).0.trim_start_matches('/');
                let encrypted_parent = sessions
                    .encrypt_path(&self.scope, parent_relative)
                    .map_err(vault_error)?;
                (destination, Some(encrypted_parent))
            } else {
                if destination_target.is_some()
                    || destination_parent_resource_id.is_some()
                    || destination_parent_etag.is_some()
                    || (operation != VaultPendingOperationKind::DeleteFile
                        && (source_size.is_some() || source_ciphertext_sha256.is_some()))
                {
                    return Err(invalid("encrypted operation has unexpected metadata"));
                }
                (String::new(), None)
            };

        if let Some(existing_id) = existing_id {
            let row = self
                .cache
                .ciphertext_write_info(&self.cache_scope, existing_id)
                .map_err(cache_error)?;
            let previous = self.pending_operation(sessions, existing_id, row.revision)?;
            if previous.operation != operation
                || previous.root_integrity_token != integrity_token
                || match retarget_create {
                    Some((old_target, expected_revision)) => {
                        previous.revision != expected_revision
                            || previous.encoded_target != old_target
                            || previous.path == path
                            || previous.state != CiphertextWriteState::NeverAttempted
                            || previous.base != WriteCondition::Absent
                    }
                    None => previous.path != path || previous.encoded_target != encoded_target,
                }
            {
                return Err(conflict("encrypted operation revision changed its target"));
            }
            // The revision's original server condition is immutable. A local
            // pending ETag supplied by the FUSE handle is only a revision
            // token and must never replace Absent or the original Match ETag.
            base = previous.base.clone();
            base_resource_id = match (operation, base_resource_id) {
                (VaultPendingOperationKind::Overwrite, Some(_)) => {
                    Some(previous.base_resource_id.clone())
                }
                (VaultPendingOperationKind::RenameFile, Some(_)) => {
                    Some(previous.base_resource_id.clone())
                }
                (VaultPendingOperationKind::DeleteFile, Some(_)) => {
                    Some(previous.base_resource_id.clone())
                }
                (
                    VaultPendingOperationKind::CreateFile | VaultPendingOperationKind::CopyFile,
                    None,
                ) => None,
                (VaultPendingOperationKind::CreateDirectory, None) => None,
                _ => return Err(conflict("encrypted operation base condition changed")),
            };
            match operation {
                VaultPendingOperationKind::CreateFile => {
                    if retarget_create.is_none() {
                        if parent_ref.as_ref() != previous.parent_ref.as_ref() {
                            return Err(conflict("encrypted create parent identity changed"));
                        }
                        parent_resource_id = (!previous.parent_resource_id.is_empty())
                            .then(|| previous.parent_resource_id.clone());
                        parent_etag = (!previous.parent_etag.is_empty())
                            .then(|| previous.parent_etag.clone());
                    } else if base != WriteCondition::Absent
                        || previous.base != WriteCondition::Absent
                    {
                        return Err(conflict("encrypted create lost its Absent condition"));
                    }
                }
                VaultPendingOperationKind::CopyFile => {
                    if parent_ref.as_ref() != previous.parent_ref.as_ref()
                        || previous.state != CiphertextWriteState::NeverAttempted
                        || copy_source != previous.copy_source
                    {
                        return Err(conflict("encrypted copy binding changed"));
                    }
                    parent_resource_id = (!previous.parent_resource_id.is_empty())
                        .then(|| previous.parent_resource_id.clone());
                    parent_etag =
                        (!previous.parent_etag.is_empty()).then(|| previous.parent_etag.clone());
                }
                VaultPendingOperationKind::Overwrite => {
                    parent_resource_id = None;
                    parent_etag = None;
                }
                VaultPendingOperationKind::RenameFile => {
                    if parent_resource_id.as_deref() != Some(previous.parent_resource_id.as_str())
                        || parent_etag.as_deref() != Some(previous.parent_etag.as_str())
                        || destination_target != Some(previous.encoded_destination_target.as_str())
                        || destination_parent_resource_id
                            != Some(previous.destination_parent_resource_id.as_str())
                        || destination_parent_etag
                            != Some(previous.destination_parent_etag.as_str())
                        || source_size != Some(previous.source_size)
                        || source_ciphertext_sha256
                            != Some(previous.source_ciphertext_sha256.as_str())
                    {
                        return Err(conflict("encrypted rename binding changed"));
                    }
                    parent_resource_id = Some(previous.parent_resource_id.clone());
                    parent_etag = Some(previous.parent_etag.clone());
                }
                VaultPendingOperationKind::DeleteFile => {
                    if parent_resource_id.as_deref() != Some(previous.parent_resource_id.as_str())
                        || parent_etag.as_deref() != Some(previous.parent_etag.as_str())
                        || source_size != Some(previous.source_size)
                        || source_ciphertext_sha256
                            != Some(previous.source_ciphertext_sha256.as_str())
                    {
                        return Err(conflict("encrypted delete binding changed"));
                    }
                    parent_resource_id = Some(previous.parent_resource_id.clone());
                    parent_etag = Some(previous.parent_etag.clone());
                }
                VaultPendingOperationKind::CreateDirectory => {
                    let receipt_rebind = state == CiphertextWriteState::CommittedReceipt
                        && matches!(
                            (&previous.parent_ref, &parent_ref),
                            (
                                Some(VaultPendingParentRef::PendingCreate { .. }),
                                Some(VaultPendingParentRef::Stable { resource_id })
                            ) if parent_resource_id.as_deref() == Some(resource_id.as_str())
                        );
                    if (parent_ref.as_ref() != previous.parent_ref.as_ref()
                        && !receipt_rebind
                        && retarget_create.is_none())
                        || base != WriteCondition::Absent
                    {
                        return Err(conflict("encrypted directory create binding changed"));
                    }
                    if !receipt_rebind && retarget_create.is_none() {
                        parent_resource_id = (!previous.parent_resource_id.is_empty())
                            .then(|| previous.parent_resource_id.clone());
                        parent_etag = (!previous.parent_etag.is_empty())
                            .then(|| previous.parent_etag.clone());
                    }
                }
            }
        }

        let base_resource_id_text = base_resource_id.as_deref().unwrap_or("");
        let base_etag = match &base {
            WriteCondition::Absent => "",
            WriteCondition::Match(etag) => etag.as_str(),
        };

        let parent_operation = match parent_ref.as_ref() {
            Some(VaultPendingParentRef::PendingCreate { write_id, revision }) => {
                Some((write_id.as_str(), *revision))
            }
            _ => None,
        };
        let build = if let Some((old_encoded_target, expected_revision)) = retarget_create {
            self.cache
                .begin_ciphertext_never_attempted_operation_retarget(
                    &self.cache_scope,
                    match operation {
                        VaultPendingOperationKind::CreateFile => {
                            CiphertextWriteOperation::CreateFile
                        }
                        VaultPendingOperationKind::CreateDirectory => {
                            CiphertextWriteOperation::CreateDirectory
                        }
                        _ => return Err(conflict("only a create can be retargeted")),
                    },
                    existing_id.ok_or_else(|| conflict("retargeted create ID is missing"))?,
                    expected_revision,
                    old_encoded_target,
                    encoded_target,
                    destination_encoded_parent.as_deref(),
                    parent_operation,
                    body_len,
                )
        } else {
            self.cache.begin_ciphertext_operation_with_state_parent_ref(
                &self.cache_scope,
                existing_id,
                encoded_target,
                destination_encoded_parent.as_deref(),
                parent_operation,
                body_len,
                match operation {
                    VaultPendingOperationKind::Overwrite => CiphertextWriteOperation::Overwrite,
                    VaultPendingOperationKind::CreateFile => CiphertextWriteOperation::CreateFile,
                    VaultPendingOperationKind::CopyFile => CiphertextWriteOperation::CopyFile,
                    VaultPendingOperationKind::RenameFile => CiphertextWriteOperation::RenameFile,
                    VaultPendingOperationKind::DeleteFile => CiphertextWriteOperation::DeleteFile,
                    VaultPendingOperationKind::CreateDirectory => {
                        CiphertextWriteOperation::CreateDirectory
                    }
                },
                state,
            )
        }
        .map_err(cache_error)?;
        let metadata = serde_json::json!({
            "version": 12,
            "operation": match operation {
                VaultPendingOperationKind::Overwrite => "overwrite",
                VaultPendingOperationKind::CreateFile => "create_file",
                VaultPendingOperationKind::CopyFile => "copy_file",
                VaultPendingOperationKind::RenameFile => "rename_file",
                VaultPendingOperationKind::DeleteFile => "delete_file",
                VaultPendingOperationKind::CreateDirectory => "create_directory",
            },
            "id": build.id(),
            "revision": build.revision(),
            "account_id": self.scope.account_id(),
            "server_origin": self.scope.server_origin(),
            "space_id": self.scope.space_id(),
            "root_resource_id": self.scope.resource_id(),
            "root_path": self.root_path,
            "integrity_token": integrity_token,
            "encoded_target": encoded_target,
            "destination_path": destination_path,
            "encoded_destination_target": destination_target.unwrap_or_default(),
            "base_resource_id": base_resource_id_text,
            "base_etag": base_etag,
            "base_kind": match base {
                WriteCondition::Absent => "absent",
                WriteCondition::Match(_) => "match",
            },
            "parent_resource_id": parent_resource_id.as_deref().unwrap_or(""),
            "parent_etag": parent_etag.as_deref().unwrap_or(""),
            "parent_ref": parent_ref.as_ref().map(|parent| match parent {
                VaultPendingParentRef::Stable { resource_id } => serde_json::json!({
                    "kind": "stable",
                    "resource_id": resource_id,
                }),
                VaultPendingParentRef::PendingCreate { write_id, revision } => serde_json::json!({
                    "kind": "pending_create",
                    "write_id": write_id,
                    "revision": revision,
                }),
            }),
            "receipt_resource_id": receipt_resource_id.as_deref().unwrap_or(""),
            "receipt_etag": receipt_etag.as_deref().unwrap_or(""),
            "receipt_for_revision": receipt_for_revision.unwrap_or(0),
            "destination_parent_resource_id": destination_parent_resource_id.unwrap_or(""),
            "destination_parent_etag": destination_parent_etag.unwrap_or(""),
            "source_size": source_size.unwrap_or(0),
            "source_ciphertext_sha256": source_ciphertext_sha256.unwrap_or(""),
            "copy_source": copy_source.as_ref().map(|binding| serde_json::json!({
                "account_id": binding.account_id,
                "server_origin": binding.server_origin,
                "space_id": binding.space_id,
                "root_resource_id": binding.root_resource_id,
                "root_path": binding.root_path,
                "path": binding.path,
                "resource_id": binding.resource_id,
                "etag": binding.etag,
                "plaintext_len": binding.plaintext_len,
                "plaintext_sha256": binding.plaintext_sha256,
            })),
            "body_len": body_len,
            "cancelled_revision": 0,
            "cancelled_plaintext_len": 0,
            "cancelled_plaintext_sha256": "",
        });
        let metadata = serde_json::to_vec(&metadata)
            .map_err(|_| invalid("encrypted edit metadata could not be encoded"))?;
        if metadata.len() > MAX_EDIT_METADATA_BYTES {
            return Err(invalid("encrypted edit metadata exceeds its size limit"));
        }
        let envelope_len = EDIT_HEADER_BYTES
            .checked_add(metadata.len() as u64)
            .and_then(|length| length.checked_add(body_len))
            .ok_or_else(|| invalid("encrypted edit size overflowed"))?;
        let private = tempdir().map_err(io_error)?;
        let envelope_path = private.path().join("edit-envelope.tmp");
        let mut envelope = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&envelope_path)
            .map_err(io_error)?;
        set_private_file(&envelope)?;
        envelope.write_all(&EDIT_MAGIC).map_err(io_error)?;
        envelope
            .write_all(&EDIT_VERSION.to_be_bytes())
            .map_err(io_error)?;
        envelope
            .write_all(&(metadata.len() as u32).to_be_bytes())
            .map_err(io_error)?;
        envelope
            .write_all(&body_len.to_be_bytes())
            .map_err(io_error)?;
        envelope.write_all(&metadata).map_err(io_error)?;
        source.seek(SeekFrom::Start(0)).map_err(io_error)?;
        copy_exact_bounded(source, &mut envelope, body_len)?;
        let mut extra = [0u8; 1];
        if source.read(&mut extra).map_err(io_error)? != 0 {
            return Err(invalid("encrypted edit source exceeds its declared size"));
        }
        envelope.flush().map_err(io_error)?;
        envelope.sync_all().map_err(io_error)?;
        drop(envelope);

        let ciphertext_path = private.path().join("edit-ciphertext.tmp");
        let mut plaintext = File::open(&envelope_path).map_err(io_error)?;
        let encrypted_len = sessions
            .encrypt_file_transactional(
                &self.scope,
                &mut plaintext,
                &ciphertext_path,
                envelope_len,
                MAX_EDIT_BYTES + EDIT_HEADER_BYTES + MAX_EDIT_METADATA_BYTES as u64,
            )
            .map_err(vault_error)?;
        if encrypted_len != envelope_len {
            return Err(invalid("encrypted edit length did not match its envelope"));
        }
        let mut ciphertext = File::open(&ciphertext_path).map_err(io_error)?;
        let encrypted_bytes = ciphertext.metadata().map_err(io_error)?.len();
        let info = self
            .cache
            .publish_ciphertext_write(&self.cache_scope, &build, &mut ciphertext, encrypted_bytes)
            .map_err(cache_error)?;
        Ok(VaultPendingEditMetadata {
            id: info.id,
            revision: info.revision,
            retry_generation: info.retry_generation,
            path,
            destination_path,
            encoded_target: encoded_target.to_owned(),
            encoded_destination_target: destination_target.unwrap_or_default().to_owned(),
            root_integrity_token: integrity_token.to_owned(),
            base_resource_id: base_resource_id_text.to_owned(),
            base_etag: base_etag.to_owned(),
            parent_resource_id: parent_resource_id.unwrap_or_default(),
            parent_etag: parent_etag.unwrap_or_default(),
            parent_ref,
            receipt_resource_id: receipt_resource_id.unwrap_or_default(),
            receipt_etag: receipt_etag.unwrap_or_default(),
            receipt_for_revision: receipt_for_revision.unwrap_or(0),
            destination_parent_resource_id: destination_parent_resource_id
                .unwrap_or_default()
                .to_owned(),
            destination_parent_etag: destination_parent_etag.unwrap_or_default().to_owned(),
            source_size: source_size.unwrap_or(0),
            source_ciphertext_sha256: source_ciphertext_sha256.unwrap_or_default().to_owned(),
            copy_source,
            base,
            operation,
            plaintext_len: body_len,
            state: info.state,
            cancelled_revision: 0,
            cancelled_plaintext_len: 0,
            cancelled_plaintext_sha256: String::new(),
        })
    }

    /// List bounded journal rows and decrypt only the authenticated metadata
    /// prefix. The remainder of each body is not read or verified by this
    /// status API; full body integrity is checked when content is opened or
    /// reconciled.
    pub fn pending_edits(
        &self,
        sessions: &VaultSessionCoordinator,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<VaultPendingEditMetadata>, bool), CloudError> {
        let (rows, truncated) = match self
            .cache
            .ciphertext_writes(&self.cache_scope, after, limit)
        {
            Err(CacheError::NotFound) => return Ok((Vec::new(), false)),
            Err(error) => return Err(cache_error(error)),
            Ok(rows) => rows,
        };
        let mut edits = Vec::with_capacity(rows.len());
        for row in rows {
            edits.push(self.open_pending_metadata(sessions, &row)?);
        }
        Ok((edits, truncated))
    }

    /// Return a bounded batch of Pending/Uncertain edits only. Conflict rows
    /// remain available through `pending_edits` for inspection, but they do
    /// not consume retry capacity or starve later work after a restart.
    pub fn retryable_pending_edits(
        &self,
        sessions: &VaultSessionCoordinator,
        limit: usize,
    ) -> Result<(Vec<VaultPendingEditMetadata>, bool), CloudError> {
        let (rows, truncated) = match self
            .cache
            .retryable_ciphertext_writes(&self.cache_scope, limit)
        {
            Err(CacheError::NotFound) => return Ok((Vec::new(), false)),
            Err(error) => return Err(cache_error(error)),
            Ok(rows) => rows,
        };
        let mut edits = Vec::with_capacity(rows.len());
        for row in rows {
            edits.push(self.open_pending_metadata(sessions, &row)?);
        }
        Ok((edits, truncated))
    }

    /// Cheap scheduler precheck. This reads only the opaque retryable-state
    /// index in the cache; it does not open or decrypt any journal envelope.
    pub fn has_retryable_pending_edits(&self) -> Result<bool, CloudError> {
        self.cache
            .has_retryable_ciphertext_writes(&self.cache_scope)
            .map_err(cache_error)
    }

    pub fn pending_edit(
        &self,
        sessions: &VaultSessionCoordinator,
        id: &str,
        revision: u64,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        let operation = self.pending_operation(sessions, id, revision)?;
        if operation.operation != VaultPendingOperationKind::Overwrite {
            return Err(conflict("encrypted journal row is not an overwrite"));
        }
        Ok(operation)
    }

    pub fn pending_operation(
        &self,
        sessions: &VaultSessionCoordinator,
        id: &str,
        revision: u64,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        let row = self
            .cache
            .ciphertext_write_info(&self.cache_scope, id)
            .map_err(cache_error)?;
        if row.revision != revision {
            return Err(CloudError::new(
                ErrorKind::NotFound,
                "encrypted edit revision is unavailable",
            ));
        }
        self.open_pending_metadata(sessions, &row)
    }

    /// Read the source target for an exact authenticated CopyFile revision.
    /// The returned scope and root path come only from the sealed destination
    /// journal record; caller-supplied source routing is never consulted.
    pub fn pending_copy_source_target(
        &self,
        sessions: &VaultSessionCoordinator,
        id: &str,
        revision: u64,
    ) -> Result<Option<VaultCopySourceTarget>, CloudError> {
        let operation = self.pending_operation(sessions, id, revision)?;
        if operation.operation != VaultPendingOperationKind::CopyFile {
            return Err(conflict("encrypted journal row is not a copy"));
        }
        let Some(source) = operation.copy_source else {
            return Ok(None);
        };
        let scope = VaultSessionScope::new(
            &source.account_id,
            &source.server_origin,
            &source.space_id,
            &source.root_resource_id,
        )
        .map_err(|_| conflict("copy source scope is invalid"))?;
        Ok(Some(VaultCopySourceTarget {
            scope,
            root_path: source.root_path,
        }))
    }

    /// Resolve the current authenticated journal revision by its opaque write
    /// ID. This is intended for repairing a local working-copy manifest after
    /// a crash between the journal CAS and manifest rebind; callers must not
    /// search by path or infer a row from an index alone.
    pub fn pending_operation_current(
        &self,
        sessions: &VaultSessionCoordinator,
        id: &str,
    ) -> Result<Option<VaultPendingEditMetadata>, CloudError> {
        let row = match self.cache.ciphertext_write_info(&self.cache_scope, id) {
            Ok(row) => row,
            Err(CacheError::NotFound) => return Ok(None),
            Err(error) => return Err(cache_error(error)),
        };
        self.open_pending_metadata(sessions, &row).map(Some)
    }

    pub fn pending_operations_for_parent_ref(
        &self,
        sessions: &VaultSessionCoordinator,
        parent: &VaultPendingParentRef,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<VaultPendingEditMetadata>, bool), CloudError> {
        let VaultPendingParentRef::PendingCreate { write_id, revision } = parent else {
            return Ok((Vec::new(), false));
        };
        let (rows, truncated) = match self.cache.ciphertext_operation_children(
            &self.cache_scope,
            write_id,
            *revision,
            after,
            limit,
        ) {
            Err(CacheError::NotFound) => return Ok((Vec::new(), false)),
            Ok(rows) => rows,
            Err(error) => return Err(cache_error(error)),
        };
        let mut children = Vec::with_capacity(rows.len());
        for row in rows {
            let metadata = self.open_pending_metadata(sessions, &row)?;
            if metadata.parent_ref.as_ref() != Some(parent) {
                return Err(conflict(
                    "encrypted child parent reference does not match its index",
                ));
            }
            children.push(metadata);
        }
        Ok((children, truncated))
    }

    pub fn directory_create_receipt(
        &self,
        sessions: &VaultSessionCoordinator,
        operation_id: &str,
        operation_revision: u64,
    ) -> Result<Option<VaultPendingEditMetadata>, CloudError> {
        let row = match self.cache.ciphertext_directory_receipt(
            &self.cache_scope,
            operation_id,
            operation_revision,
        ) {
            Err(CacheError::NotFound) => return Ok(None),
            Ok(row) => row,
            Err(error) => return Err(cache_error(error)),
        };
        let Some(row) = row else {
            return Ok(None);
        };
        let metadata = self.open_pending_metadata(sessions, &row)?;
        if metadata.operation != VaultPendingOperationKind::CreateDirectory
            || metadata.state != CiphertextWriteState::CommittedReceipt
            || metadata.receipt_for_revision != operation_revision
            || metadata.id != operation_id
        {
            return Err(conflict(
                "encrypted directory receipt does not match its operation",
            ));
        }
        Ok(Some(metadata))
    }

    pub fn retire_directory_receipt_if_unreferenced(
        &self,
        sessions: &VaultSessionCoordinator,
        operation_id: &str,
        operation_revision: u64,
    ) -> Result<(), CloudError> {
        let receipt = self
            .directory_create_receipt(sessions, operation_id, operation_revision)?
            .ok_or_else(|| conflict("encrypted directory receipt is unavailable"))?;
        self.cache
            .retire_ciphertext_directory_receipt(
                &self.cache_scope,
                operation_id,
                receipt.revision,
                operation_revision,
            )
            .map_err(cache_error)
    }

    /// Return a bounded page of create operations whose encrypted parent path
    /// matches `parent_path`. The row index contains only hashes; the child
    /// paths are decrypted from authenticated envelopes after checking session
    /// scope and root token.
    pub fn pending_creates_for_parent(
        &self,
        sessions: &VaultSessionCoordinator,
        parent_path: &str,
        limit: usize,
    ) -> Result<(Vec<VaultPendingEditMetadata>, bool), CloudError> {
        self.ensure_unlocked(sessions)?;
        if !(1..=100).contains(&limit) {
            return Err(invalid("encrypted create listing limit is invalid"));
        }
        let parent_path = normalize_virtual_path(sessions, &self.scope, parent_path)?;
        let parent_relative = parent_path.trim_start_matches('/');
        let encrypted_parent = sessions
            .encrypt_path(&self.scope, parent_relative)
            .map_err(vault_error)?;
        let mut after: Option<String> = None;
        let mut creates = Vec::new();
        let mut truncated = false;
        let mut scan_bytes = 0u64;
        loop {
            let page_limit = limit.saturating_sub(creates.len()).clamp(1, 100);
            let (rows, page_truncated) = match self.cache.ciphertext_creates_for_parent(
                &self.cache_scope,
                &encrypted_parent,
                after.as_deref(),
                page_limit,
            ) {
                // A fresh ciphertext scope has no journal rows yet. Treat that
                // as an empty overlay; all other cache errors remain visible.
                Err(CacheError::NotFound) => return Ok((creates, false)),
                Ok(rows) => rows,
                Err(error) => return Err(cache_error(error)),
            };
            for row in rows {
                after = Some(row.id.clone());
                if matches!(
                    row.state,
                    CiphertextWriteState::Building | CiphertextWriteState::CancelledReceipt
                ) {
                    continue;
                }
                scan_bytes = scan_bytes
                    .checked_add(row.byte_len)
                    .filter(|total| *total <= MAX_CREATE_OVERLAY_SCAN_BYTES)
                    .ok_or_else(|| {
                        CloudError::new(
                            ErrorKind::Unsupported,
                            "too much encrypted create recovery data to enumerate safely",
                        )
                    })?;
                let metadata = self.open_pending_metadata(sessions, &row)?;
                if metadata.operation != VaultPendingOperationKind::CreateFile
                    || split_parent(&metadata.path).0 != parent_path
                {
                    return Err(conflict("encrypted create does not match its parent index"));
                }
                creates.push(metadata);
            }
            if !page_truncated {
                break;
            }
            if creates.len() >= limit {
                truncated = true;
                break;
            }
        }
        Ok((creates, truncated))
    }

    pub fn pending_directories_for_parent(
        &self,
        sessions: &VaultSessionCoordinator,
        parent_path: &str,
        limit: usize,
    ) -> Result<(Vec<VaultPendingEditMetadata>, bool), CloudError> {
        self.ensure_unlocked(sessions)?;
        if !(1..=100).contains(&limit) {
            return Err(invalid(
                "encrypted directory create listing limit is invalid",
            ));
        }
        let parent_path = normalize_virtual_path(sessions, &self.scope, parent_path)?;
        let encrypted_parent = sessions
            .encrypt_path(&self.scope, parent_path.trim_start_matches('/'))
            .map_err(vault_error)?;
        let mut after: Option<String> = None;
        let mut creates = Vec::new();
        let mut truncated = false;
        let mut scan_bytes = 0u64;
        loop {
            let page_limit = limit.saturating_sub(creates.len()).clamp(1, 100);
            let (rows, page_truncated) = match self.cache.ciphertext_directory_creates_for_parent(
                &self.cache_scope,
                &encrypted_parent,
                after.as_deref(),
                page_limit,
            ) {
                Err(CacheError::NotFound) => return Ok((creates, false)),
                Ok(rows) => rows,
                Err(error) => return Err(cache_error(error)),
            };
            for row in rows {
                after = Some(row.id.clone());
                scan_bytes = scan_bytes
                    .checked_add(row.byte_len)
                    .filter(|total| *total <= MAX_CREATE_OVERLAY_SCAN_BYTES)
                    .ok_or_else(|| {
                        CloudError::new(
                            ErrorKind::Unsupported,
                            "too much encrypted directory recovery data to enumerate safely",
                        )
                    })?;
                let metadata = self.open_pending_metadata(sessions, &row)?;
                if metadata.operation != VaultPendingOperationKind::CreateDirectory
                    || split_parent(&metadata.path).0 != parent_path
                    || metadata.base != WriteCondition::Absent
                    || metadata.plaintext_len != 0
                {
                    return Err(conflict(
                        "encrypted directory create does not match its parent index",
                    ));
                }
                if matches!(
                    metadata.state,
                    CiphertextWriteState::Pending
                        | CiphertextWriteState::Uncertain
                        | CiphertextWriteState::NeverAttempted
                        | CiphertextWriteState::Attempting
                        | CiphertextWriteState::CommittedReceipt
                ) {
                    creates.push(metadata);
                }
            }
            if !page_truncated {
                break;
            }
            if creates.len() >= limit {
                truncated = true;
                break;
            }
        }
        Ok((creates, truncated))
    }

    /// Enumerate durable renames projected into one destination directory.
    /// Only the encrypted parent hash is queried in SQLite; decoded paths are
    /// recovered from the authenticated envelopes after scope/token checks.
    pub fn pending_renames_for_parent(
        &self,
        sessions: &VaultSessionCoordinator,
        parent_path: &str,
        limit: usize,
    ) -> Result<(Vec<VaultPendingEditMetadata>, bool), CloudError> {
        self.ensure_unlocked(sessions)?;
        if !(1..=100).contains(&limit) {
            return Err(invalid("encrypted rename listing limit is invalid"));
        }
        let parent_path = normalize_virtual_path(sessions, &self.scope, parent_path)?;
        let parent_relative = parent_path.trim_start_matches('/');
        let encrypted_parent = sessions
            .encrypt_path(&self.scope, parent_relative)
            .map_err(vault_error)?;
        let mut after: Option<String> = None;
        let mut renames = Vec::new();
        let mut truncated = false;
        let mut scan_bytes = 0u64;
        loop {
            let page_limit = limit.saturating_sub(renames.len()).clamp(1, 100);
            let (rows, page_truncated) = match self.cache.ciphertext_renames_for_parent(
                &self.cache_scope,
                &encrypted_parent,
                after.as_deref(),
                page_limit,
            ) {
                Err(CacheError::NotFound) => return Ok((renames, false)),
                Ok(rows) => rows,
                Err(error) => return Err(cache_error(error)),
            };
            for row in rows {
                after = Some(row.id.clone());
                scan_bytes = scan_bytes
                    .checked_add(row.byte_len)
                    .filter(|total| *total <= MAX_CREATE_OVERLAY_SCAN_BYTES)
                    .ok_or_else(|| {
                        CloudError::new(
                            ErrorKind::Unsupported,
                            "too much encrypted rename recovery data to enumerate safely",
                        )
                    })?;
                let metadata = self.open_pending_metadata(sessions, &row)?;
                if metadata.operation != VaultPendingOperationKind::RenameFile
                    || split_parent(&metadata.destination_path).0 != parent_path
                {
                    return Err(conflict("encrypted rename does not match its parent index"));
                }
                if metadata.state != CiphertextWriteState::Building {
                    renames.push(metadata);
                }
            }
            if !page_truncated {
                break;
            }
            if renames.len() >= limit {
                truncated = true;
                break;
            }
        }
        Ok((renames, truncated))
    }

    /// Enumerate durable delete tombstones in one source directory. SQLite
    /// stores only the encrypted parent-path hash and operation class; the
    /// original source path and recovery body are decoded from the sealed row.
    pub fn pending_deletes_for_parent(
        &self,
        sessions: &VaultSessionCoordinator,
        parent_path: &str,
        limit: usize,
    ) -> Result<(Vec<VaultPendingEditMetadata>, bool), CloudError> {
        self.ensure_unlocked(sessions)?;
        if !(1..=100).contains(&limit) {
            return Err(invalid("encrypted delete listing limit is invalid"));
        }
        let parent_path = normalize_virtual_path(sessions, &self.scope, parent_path)?;
        let encrypted_parent = sessions
            .encrypt_path(&self.scope, parent_path.trim_start_matches('/'))
            .map_err(vault_error)?;
        let mut after: Option<String> = None;
        let mut deletes = Vec::new();
        let mut truncated = false;
        let mut scan_bytes = 0u64;
        loop {
            let page_limit = limit.saturating_sub(deletes.len()).clamp(1, 100);
            let (rows, page_truncated) = match self.cache.ciphertext_deletes_for_parent(
                &self.cache_scope,
                &encrypted_parent,
                after.as_deref(),
                page_limit,
            ) {
                Err(CacheError::NotFound) => return Ok((deletes, false)),
                Ok(rows) => rows,
                Err(error) => return Err(cache_error(error)),
            };
            for row in rows {
                after = Some(row.id.clone());
                scan_bytes = scan_bytes
                    .checked_add(row.byte_len)
                    .filter(|total| *total <= MAX_CREATE_OVERLAY_SCAN_BYTES)
                    .ok_or_else(|| {
                        CloudError::new(
                            ErrorKind::Unsupported,
                            "too much encrypted delete recovery data to enumerate safely",
                        )
                    })?;
                let metadata = self.open_pending_metadata(sessions, &row)?;
                if metadata.operation != VaultPendingOperationKind::DeleteFile
                    || split_parent(&metadata.path).0 != parent_path
                {
                    return Err(conflict("encrypted delete does not match its parent index"));
                }
                if matches!(
                    metadata.state,
                    CiphertextWriteState::Pending | CiphertextWriteState::Uncertain
                ) {
                    deletes.push(metadata);
                }
            }
            if !page_truncated {
                break;
            }
            if deletes.len() >= limit {
                truncated = true;
                break;
            }
        }
        Ok((deletes, truncated))
    }

    pub fn pending_delete_for_path(
        &self,
        sessions: &VaultSessionCoordinator,
        path: &str,
    ) -> Result<Option<VaultPendingEditMetadata>, CloudError> {
        let path = normalize_virtual_path(sessions, &self.scope, path)?;
        let parent = split_parent(&path).0;
        let (rows, truncated) = self.pending_deletes_for_parent(sessions, parent, 100)?;
        if truncated {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "too many encrypted delete records to resolve this path safely",
            ));
        }
        Ok(rows.into_iter().find(|row| row.path == path))
    }

    pub fn pending_directory_for_path(
        &self,
        sessions: &VaultSessionCoordinator,
        path: &str,
    ) -> Result<Option<VaultPendingEditMetadata>, CloudError> {
        let path = normalize_virtual_path(sessions, &self.scope, path)?;
        let parent = split_parent(&path).0;
        let (rows, truncated) = self.pending_directories_for_parent(sessions, parent, 100)?;
        if truncated {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "too many encrypted directory create records to resolve this path safely",
            ));
        }
        Ok(rows.into_iter().find(|row| row.path == path))
    }

    pub fn pending_rename_for_destination(
        &self,
        sessions: &VaultSessionCoordinator,
        destination: &str,
    ) -> Result<Option<VaultPendingEditMetadata>, CloudError> {
        let destination = normalize_virtual_path(sessions, &self.scope, destination)?;
        let parent = split_parent(&destination).0;
        let (rows, truncated) = self.pending_renames_for_parent(sessions, parent, 100)?;
        if truncated {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "too many encrypted rename records to resolve this path safely",
            ));
        }
        Ok(rows
            .into_iter()
            .find(|row| row.destination_path == destination))
    }

    /// Look up only the opaque revision/length row for a logical file. The
    /// index is derived from the encrypted DAV target, so directory listings
    /// can overlay a local ETag without decrypting the journal body's blocks.
    pub fn pending_edit_ref_for_path(
        &self,
        sessions: &VaultSessionCoordinator,
        path: &str,
    ) -> Result<Option<CiphertextWriteInfo>, CloudError> {
        self.ensure_unlocked(sessions)?;
        let normalized = normalize_virtual_path(sessions, &self.scope, path)?;
        if normalized == "/" {
            return Ok(None);
        }
        let relative = normalized.trim_start_matches('/');
        let encrypted_target = sessions
            .encrypt_path(&self.scope, relative)
            .map_err(vault_error)?;
        match self
            .cache
            .ciphertext_write_for_target(&self.cache_scope, &encrypted_target)
        {
            Err(CacheError::NotFound) => Ok(None),
            Ok(row) => Ok(row),
            Err(error) => Err(cache_error(error)),
        }
    }

    /// Decrypt one queued revision to a fresh destination, publishing no
    /// plaintext unless its authenticated scope, marker, lengths, target, and
    /// original server version all pass validation.
    pub fn download_pending_edit(
        &self,
        sessions: &VaultSessionCoordinator,
        id: &str,
        revision: u64,
        destination: &Path,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        let row = self
            .cache
            .ciphertext_write_info(&self.cache_scope, id)
            .map_err(cache_error)?;
        if row.revision != revision {
            return Err(CloudError::new(
                ErrorKind::NotFound,
                "encrypted edit revision is unavailable",
            ));
        }
        let envelope = self.open_pending_envelope(sessions, &row)?;
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        // Keep the original private tempfile inode throughout publication.
        // Recreating it would apply the process umask and could expose plaintext.
        let mut output = NamedTempFile::new_in(parent).map_err(io_error)?;
        let mut input = File::open(&envelope.path).map_err(io_error)?;
        input
            .seek(SeekFrom::Start(envelope.body_offset))
            .map_err(io_error)?;
        copy_exact_bounded(&mut input, &mut output, envelope.metadata.plaintext_len)?;
        output.flush().map_err(io_error)?;
        output.as_file().sync_all().map_err(io_error)?;
        if !sessions.is_unlocked(&self.scope).map_err(vault_error)? {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault session is locked",
            ));
        }
        output
            .persist_noclobber(destination)
            .map_err(|error| io_error(error.error))?;
        Ok(envelope.metadata)
    }

    pub fn set_pending_edit_state(
        &self,
        id: &str,
        revision: u64,
        state: CiphertextWriteState,
    ) -> Result<(), CloudError> {
        self.cache
            .set_ciphertext_write_state(&self.cache_scope, id, revision, state)
            .map_err(cache_error)
    }

    pub(crate) fn claim_directory_create_attempt(
        &self,
        sessions: &VaultSessionCoordinator,
        id: &str,
        revision: u64,
    ) -> Result<(), CloudError> {
        let operation = self.pending_operation(sessions, id, revision)?;
        if operation.operation != VaultPendingOperationKind::CreateDirectory
            || !matches!(
                operation.state,
                CiphertextWriteState::NeverAttempted
                    | CiphertextWriteState::Pending
                    | CiphertextWriteState::Uncertain
            )
        {
            return Err(conflict("encrypted directory create is not claimable"));
        }
        self.cache
            .claim_ciphertext_directory_create_attempt(&self.cache_scope, id, revision)
            .map_err(cache_error)
    }

    pub(crate) fn claim_file_create_attempt(
        &self,
        sessions: &VaultSessionCoordinator,
        id: &str,
        revision: u64,
    ) -> Result<(), CloudError> {
        let operation = self.pending_operation(sessions, id, revision)?;
        if operation.operation != VaultPendingOperationKind::CreateFile
            || operation.base != WriteCondition::Absent
            || !matches!(
                operation.state,
                CiphertextWriteState::NeverAttempted
                    | CiphertextWriteState::Pending
                    | CiphertextWriteState::Uncertain
            )
        {
            return Err(conflict("encrypted file create is not claimable"));
        }
        self.cache
            .claim_ciphertext_file_create_attempt(&self.cache_scope, id, revision)
            .map_err(cache_error)
    }

    #[cfg(all(test, unix))]
    pub(crate) fn claim_copy_file_attempt(
        &self,
        sessions: &VaultSessionCoordinator,
        id: &str,
        revision: u64,
    ) -> Result<(), CloudError> {
        let operation = self.pending_operation(sessions, id, revision)?;
        if operation.operation != VaultPendingOperationKind::CopyFile
            || operation.base != WriteCondition::Absent
            || operation.state != CiphertextWriteState::NeverAttempted
            || !matches!(
                operation.parent_ref,
                Some(VaultPendingParentRef::Stable { .. })
            )
        {
            return Err(conflict("encrypted copy operation is not claimable"));
        }
        self.cache
            .claim_ciphertext_copy_attempt(&self.cache_scope, id, revision)
            .map_err(cache_error)
    }

    /// Claim only while the caller holds both vault scopes and token generations.
    /// Reuse the supplied destination session rather than acquiring its lease again.
    pub(crate) fn claim_copy_file_attempt_with_session(
        &self,
        session: &raiun_vault::VerifiedVaultSession,
        expected: &VaultPendingEditMetadata,
    ) -> Result<(), CloudError> {
        self.reopen_copy_for_resolution(session, expected)?;
        if expected.base != WriteCondition::Absent
            || expected.state != CiphertextWriteState::NeverAttempted
            || !matches!(
                expected.parent_ref,
                Some(VaultPendingParentRef::Stable { .. })
            )
        {
            return Err(conflict("encrypted copy operation is not claimable"));
        }
        self.cache
            .claim_ciphertext_copy_attempt(&self.cache_scope, &expected.id, expected.revision)
            .map_err(cache_error)
    }

    pub(crate) fn claim_interrupted_file_create_retry(
        &self,
        sessions: &VaultSessionCoordinator,
        id: &str,
        revision: u64,
        expected_state: CiphertextWriteState,
        expected_generation: u64,
    ) -> Result<u64, CloudError> {
        let operation = self.pending_operation(sessions, id, revision)?;
        if operation.operation != VaultPendingOperationKind::CreateFile
            || operation.base != WriteCondition::Absent
            || !operation.base_resource_id.is_empty()
            || operation.state != expected_state
            || operation.retry_generation != expected_generation
            || !matches!(
                expected_state,
                CiphertextWriteState::Attempting
                    | CiphertextWriteState::RecoveryAttempting
                    | CiphertextWriteState::RecoveryRetrying
            )
        {
            return Err(conflict("interrupted encrypted file create changed"));
        }
        self.cache
            .claim_interrupted_ciphertext_file_create_retry(
                &self.cache_scope,
                id,
                revision,
                expected_state,
                expected_generation,
            )
            .map_err(cache_error)
    }

    pub(crate) fn set_interrupted_file_create_retry_state(
        &self,
        sessions: &VaultSessionCoordinator,
        id: &str,
        revision: u64,
        expected_generation: u64,
        expected_state: CiphertextWriteState,
        next_state: CiphertextWriteState,
    ) -> Result<(), CloudError> {
        let operation = self.pending_operation(sessions, id, revision)?;
        if operation.operation != VaultPendingOperationKind::CreateFile
            || operation.retry_generation != expected_generation
            || operation.state != expected_state
        {
            return Err(conflict("interrupted encrypted file create changed"));
        }
        self.cache
            .set_interrupted_ciphertext_file_create_retry_state(
                &self.cache_scope,
                id,
                revision,
                expected_generation,
                expected_state,
                next_state,
            )
            .map_err(cache_error)
    }

    pub(crate) fn retire_interrupted_file_create_retry(
        &self,
        sessions: &VaultSessionCoordinator,
        id: &str,
        revision: u64,
        expected_generation: u64,
        expected_state: CiphertextWriteState,
    ) -> Result<(), CloudError> {
        let operation = self.pending_operation(sessions, id, revision)?;
        if operation.operation != VaultPendingOperationKind::CreateFile
            || operation.retry_generation != expected_generation
            || operation.state != expected_state
        {
            return Err(conflict("interrupted encrypted file create changed"));
        }
        self.cache
            .retire_interrupted_ciphertext_file_create_retry(
                &self.cache_scope,
                id,
                revision,
                expected_generation,
                expected_state,
            )
            .map_err(cache_error)
    }

    pub(crate) fn cancel_never_attempted_directory_create(
        &self,
        sessions: &VaultSessionCoordinator,
        id: &str,
        revision: u64,
        expected_path: &str,
    ) -> Result<(), CloudError> {
        let operation = self.pending_operation(sessions, id, revision)?;
        if operation.operation != VaultPendingOperationKind::CreateDirectory
            || operation.state != CiphertextWriteState::NeverAttempted
            || operation.path != expected_path
            || operation.base != WriteCondition::Absent
        {
            return Err(conflict(
                "encrypted directory create no longer matches the local cancellation",
            ));
        }
        self.cache
            .cancel_never_attempted_ciphertext_directory_create(&self.cache_scope, id, revision)
            .map_err(cache_error)
    }

    pub(crate) fn cancel_never_attempted_file_create(
        &self,
        sessions: &VaultSessionCoordinator,
        id: &str,
        revision: u64,
        expected_target: &str,
        plaintext_len: u64,
    ) -> Result<(), CloudError> {
        let operation = self.pending_operation(sessions, id, revision)?;
        if operation.operation != VaultPendingOperationKind::CreateFile
            || !matches!(
                operation.state,
                CiphertextWriteState::NeverAttempted | CiphertextWriteState::CancelledReceipt
            )
            || operation.base != WriteCondition::Absent
            || operation.encoded_target != expected_target
            || operation.plaintext_len != plaintext_len
        {
            return Err(conflict(
                "encrypted file create no longer matches the local cancellation",
            ));
        }
        self.cache
            .cancel_never_attempted_ciphertext_file_create(
                &self.cache_scope,
                id,
                revision,
                expected_target,
                plaintext_len,
            )
            .map_err(cache_error)
    }

    pub(crate) fn acknowledge_cancelled_file_create(
        &self,
        sessions: &VaultSessionCoordinator,
        id: &str,
        revision: u64,
        expected_target: &str,
        plaintext_len: u64,
        plaintext_sha256: &str,
    ) -> Result<(), CloudError> {
        if !is_sha256_digest(plaintext_sha256) || plaintext_len > MAX_EDIT_BYTES {
            return Err(invalid("encrypted cancellation digest is invalid"));
        }
        let current = self
            .pending_operation_current(sessions, id)?
            .ok_or_else(|| conflict("encrypted create cancellation receipt is missing"))?;
        if current.operation != VaultPendingOperationKind::CreateFile
            || current.base != WriteCondition::Absent
            || current.encoded_target != expected_target
        {
            return Err(conflict("encrypted cancellation receipt changed identity"));
        }
        if current.state == CiphertextWriteState::AcknowledgedReceipt {
            if current.cancelled_revision != revision
                || current.cancelled_plaintext_len != plaintext_len
                || current.cancelled_plaintext_sha256 != plaintext_sha256
            {
                return Err(conflict(
                    "encrypted cancellation acknowledgement does not match its receipt",
                ));
            }
            // A crash may have happened after the compact row committed but
            // before the old large body blob was unlinked. Retrying is safe.
            return self
                .cache
                .remove_unreferenced_ciphertext_write_content(&self.cache_scope, id, revision)
                .map_err(cache_error);
        }
        if current.state != CiphertextWriteState::CancelledReceipt
            || current.revision != revision
            || current.plaintext_len != plaintext_len
        {
            return Err(conflict("encrypted create cancellation receipt is stale"));
        }

        let build = self
            .cache
            .begin_ciphertext_cancel_ack_compaction(
                &self.cache_scope,
                id,
                revision,
                expected_target,
            )
            .map_err(cache_error)?;
        let parent_ref = current.parent_ref.as_ref().map(|parent| match parent {
            VaultPendingParentRef::Stable { resource_id } => serde_json::json!({
                "kind": "stable",
                "resource_id": resource_id,
            }),
            VaultPendingParentRef::PendingCreate { write_id, revision } => serde_json::json!({
                "kind": "pending_create",
                "write_id": write_id,
                "revision": revision,
            }),
        });
        let compact = serde_json::json!({
            "version": 10,
            "operation": "create_file",
            "id": id,
            "revision": build.revision(),
            "account_id": self.scope.account_id(),
            "server_origin": self.scope.server_origin(),
            "space_id": self.scope.space_id(),
            "root_resource_id": self.scope.resource_id(),
            "root_path": self.root_path,
            "integrity_token": current.root_integrity_token,
            "encoded_target": current.encoded_target,
            "destination_path": "",
            "encoded_destination_target": "",
            "base_resource_id": "",
            "base_etag": "",
            "base_kind": "absent",
            "parent_resource_id": current.parent_resource_id,
            "parent_etag": current.parent_etag,
            "parent_ref": parent_ref,
            "receipt_resource_id": "",
            "receipt_etag": "",
            "receipt_for_revision": 0,
            "destination_parent_resource_id": "",
            "destination_parent_etag": "",
            "source_size": 0,
            "source_ciphertext_sha256": "",
            "body_len": 0,
            "cancelled_revision": revision,
            "cancelled_plaintext_len": plaintext_len,
            "cancelled_plaintext_sha256": plaintext_sha256,
        });
        let metadata = serde_json::to_vec(&compact)
            .map_err(|_| invalid("encrypted cancellation proof could not be encoded"))?;
        if metadata.is_empty() || metadata.len() > MAX_EDIT_METADATA_BYTES {
            return Err(invalid(
                "encrypted cancellation proof exceeds its size limit",
            ));
        }
        let envelope_len = EDIT_HEADER_BYTES
            .checked_add(metadata.len() as u64)
            .ok_or_else(|| invalid("encrypted cancellation envelope size overflowed"))?;
        let private = tempdir().map_err(io_error)?;
        let envelope_path = private.path().join("cancel-ack-envelope.tmp");
        let mut envelope = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&envelope_path)
            .map_err(io_error)?;
        set_private_file(&envelope)?;
        envelope.write_all(&EDIT_MAGIC).map_err(io_error)?;
        envelope
            .write_all(&EDIT_VERSION.to_be_bytes())
            .map_err(io_error)?;
        envelope
            .write_all(&(metadata.len() as u32).to_be_bytes())
            .map_err(io_error)?;
        envelope.write_all(&0u64.to_be_bytes()).map_err(io_error)?;
        envelope.write_all(&metadata).map_err(io_error)?;
        envelope.flush().map_err(io_error)?;
        envelope.sync_all().map_err(io_error)?;
        drop(envelope);

        let ciphertext_path = private.path().join("cancel-ack-ciphertext.tmp");
        let mut plaintext = File::open(&envelope_path).map_err(io_error)?;
        let encrypted_len = sessions
            .encrypt_file_transactional(
                &self.scope,
                &mut plaintext,
                &ciphertext_path,
                envelope_len,
                EDIT_HEADER_BYTES + MAX_EDIT_METADATA_BYTES as u64,
            )
            .map_err(vault_error)?;
        if encrypted_len != envelope_len {
            return Err(invalid("encrypted cancellation proof length changed"));
        }
        let mut ciphertext = File::open(&ciphertext_path).map_err(io_error)?;
        let encrypted_bytes = ciphertext.metadata().map_err(io_error)?.len();
        let published = self
            .cache
            .publish_ciphertext_write(&self.cache_scope, &build, &mut ciphertext, encrypted_bytes)
            .map_err(cache_error)?;
        if published.state != CiphertextWriteState::AcknowledgedReceipt
            || published.revision != revision.saturating_add(1)
        {
            return Err(conflict("encrypted cancellation proof publication changed"));
        }
        self.cache
            .remove_unreferenced_ciphertext_write_content(&self.cache_scope, id, revision)
            .map_err(cache_error)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finalize_cancelled_file_create_ack(
        &self,
        sessions: &VaultSessionCoordinator,
        id: &str,
        original_revision: u64,
        current_revision: u64,
        expected_target: &str,
        plaintext_len: u64,
        plaintext_sha256: &str,
    ) -> Result<(), CloudError> {
        let current = self
            .pending_operation_current(sessions, id)?
            .ok_or_else(|| conflict("encrypted cancellation acknowledgement is missing"))?;
        if current.state != CiphertextWriteState::AcknowledgedReceipt
            || current.cancelled_revision != original_revision
            || current.revision != current_revision
            || current.encoded_target != expected_target
            || current.cancelled_plaintext_len != plaintext_len
            || current.cancelled_plaintext_sha256 != plaintext_sha256
        {
            return Err(conflict(
                "encrypted cancellation finalization does not match its acknowledgement",
            ));
        }
        self.cache
            .finalize_cancelled_ciphertext_file_create_ack(
                &self.cache_scope,
                id,
                original_revision,
                current_revision,
                expected_target,
            )
            .map_err(cache_error)
    }

    pub(crate) fn remove_cancelled_file_create_body(
        &self,
        id: &str,
        revision: u64,
    ) -> Result<(), CloudError> {
        self.cache
            .remove_unreferenced_ciphertext_write_content(&self.cache_scope, id, revision)
            .map_err(cache_error)
    }

    pub fn retire_pending_edit(&self, id: &str, revision: u64) -> Result<(), CloudError> {
        self.cache
            .retire_ciphertext_write(&self.cache_scope, id, revision)
            .map_err(cache_error)
    }

    pub(crate) fn reopen_copy_for_resolution(
        &self,
        session: &raiun_vault::VerifiedVaultSession,
        expected: &VaultPendingEditMetadata,
    ) -> Result<(), CloudError> {
        let row = self
            .cache
            .ciphertext_write_info(&self.cache_scope, &expected.id)
            .map_err(cache_error)?;
        if row.revision != expected.revision {
            return Err(conflict(
                "encrypted copy revision changed during resolution",
            ));
        }
        let current = self.open_pending_metadata_with_session(session, &row)?;
        if &current != expected || current.operation != VaultPendingOperationKind::CopyFile {
            return Err(conflict("encrypted copy changed during resolution"));
        }
        Ok(())
    }

    pub(crate) fn retire_resolved_copy(
        &self,
        id: &str,
        revision: u64,
        expected_state: CiphertextWriteState,
    ) -> Result<(), CloudError> {
        self.cache
            .retire_ciphertext_copy_write(&self.cache_scope, id, revision, expected_state)
            .map_err(cache_error)
    }

    fn open_pending_envelope(
        &self,
        sessions: &VaultSessionCoordinator,
        row: &CiphertextWriteInfo,
    ) -> Result<DecodedPendingEnvelope, CloudError> {
        if !sessions.is_unlocked(&self.scope).map_err(vault_error)? {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault session is locked",
            ));
        }
        let mut ciphertext = self
            .cache
            .open_ciphertext_write(&self.cache_scope, &row.id, row.revision)
            .map_err(cache_error)?;
        let ciphertext_len = ciphertext.metadata().map_err(io_error)?.len();
        let envelope_len = plaintext_len_from_ciphertext(ciphertext_len)?;
        if envelope_len > MAX_EDIT_BYTES + EDIT_HEADER_BYTES + MAX_EDIT_METADATA_BYTES as u64 {
            return Err(invalid("encrypted edit exceeds its size limit"));
        }
        let private = tempdir().map_err(io_error)?;
        let path = private.path().join("decrypted-edit.tmp");
        let envelope_len = sessions
            .decrypt_file_transactional(
                &self.scope,
                &mut ciphertext,
                &path,
                MAX_EDIT_BYTES + EDIT_HEADER_BYTES + MAX_EDIT_METADATA_BYTES as u64,
                Some(envelope_len),
            )
            .map_err(vault_error)?;
        if envelope_len < EDIT_HEADER_BYTES {
            return Err(invalid("encrypted edit envelope is truncated"));
        }
        let mut file = File::open(&path).map_err(io_error)?;
        let mut header = [0u8; EDIT_HEADER_BYTES as usize];
        file.read_exact(&mut header).map_err(io_error)?;
        if header[..8] != EDIT_MAGIC || u16::from_be_bytes([header[8], header[9]]) != EDIT_VERSION {
            return Err(invalid("encrypted edit envelope format is invalid"));
        }
        let metadata_len = u32::from_be_bytes(header[10..14].try_into().unwrap()) as usize;
        let body_len = u64::from_be_bytes(header[14..22].try_into().unwrap());
        let expected_len = EDIT_HEADER_BYTES
            .checked_add(metadata_len as u64)
            .and_then(|length| length.checked_add(body_len))
            .ok_or_else(|| invalid("encrypted edit size overflowed"))?;
        if metadata_len == 0
            || metadata_len > MAX_EDIT_METADATA_BYTES
            || body_len > MAX_EDIT_BYTES
            || envelope_len != expected_len
        {
            return Err(invalid("encrypted edit envelope lengths are invalid"));
        }
        let mut metadata_bytes = vec![0u8; metadata_len];
        file.read_exact(&mut metadata_bytes).map_err(io_error)?;
        let value: serde_json::Value = serde_json::from_slice(&metadata_bytes)
            .map_err(|_| invalid("encrypted edit metadata is invalid"))?;
        let mut metadata = sessions
            .with_unlocked_session(&self.scope, |session| {
                parse_pending_metadata(&value, &self.scope, &self.root_path, session, row.state)
            })
            .map_err(vault_error)??;
        if raiun_cache::ciphertext_target_hash(&metadata.encoded_target).map_err(cache_error)?
            != row.target_key
        {
            return Err(conflict(
                "encrypted edit target does not match its cache index",
            ));
        }
        let indexed_operation = match row.operation {
            CiphertextWriteOperation::Overwrite => VaultPendingOperationKind::Overwrite,
            CiphertextWriteOperation::CreateFile => VaultPendingOperationKind::CreateFile,
            CiphertextWriteOperation::RenameFile => VaultPendingOperationKind::RenameFile,
            CiphertextWriteOperation::DeleteFile => VaultPendingOperationKind::DeleteFile,
            CiphertextWriteOperation::CreateDirectory => VaultPendingOperationKind::CreateDirectory,
            CiphertextWriteOperation::CopyFile => VaultPendingOperationKind::CopyFile,
        };
        if metadata.id != row.id
            || metadata.revision != row.revision
            || metadata.plaintext_len != body_len
            || metadata.state != row.state
            || metadata.operation != indexed_operation
        {
            return Err(conflict(
                "encrypted edit revision does not match its journal row",
            ));
        }
        metadata.retry_generation = row.retry_generation;
        let body_offset = EDIT_HEADER_BYTES + metadata_len as u64;
        Ok(DecodedPendingEnvelope {
            metadata,
            _private: private,
            path,
            body_offset,
        })
    }

    fn open_pending_metadata(
        &self,
        sessions: &VaultSessionCoordinator,
        row: &CiphertextWriteInfo,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        sessions
            .with_unlocked_session(&self.scope, |session| {
                self.open_pending_metadata_with_session(session, row)
            })
            .map_err(vault_error)?
    }

    fn open_pending_metadata_with_session(
        &self,
        session: &raiun_vault::VerifiedVaultSession,
        row: &CiphertextWriteInfo,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        let mut ciphertext = self
            .cache
            .open_ciphertext_write(&self.cache_scope, &row.id, row.revision)
            .map_err(cache_error)?;
        let ciphertext_len = ciphertext.metadata().map_err(io_error)?.len();
        if ciphertext_len != row.byte_len {
            return Err(conflict(
                "encrypted journal size does not match its cache row",
            ));
        }
        let plaintext_len = plaintext_len_from_ciphertext(ciphertext_len)?;
        if plaintext_len < EDIT_HEADER_BYTES
            || plaintext_len > MAX_EDIT_BYTES + EDIT_HEADER_BYTES + MAX_EDIT_METADATA_BYTES as u64
        {
            return Err(invalid("encrypted edit exceeds its size limit"));
        }
        let prefix = session
            .decrypt_authenticated_prefix(
                &mut ciphertext,
                MAX_EDIT_METADATA_BYTES + EDIT_HEADER_BYTES as usize,
            )
            .map_err(vault_error)?;
        if prefix.len() < EDIT_HEADER_BYTES as usize {
            return Err(invalid("encrypted edit envelope is truncated"));
        }
        if prefix[..8] != EDIT_MAGIC || u16::from_be_bytes([prefix[8], prefix[9]]) != EDIT_VERSION {
            return Err(invalid("encrypted edit envelope format is invalid"));
        }
        let metadata_len = u32::from_be_bytes(prefix[10..14].try_into().unwrap()) as usize;
        let body_len = u64::from_be_bytes(prefix[14..22].try_into().unwrap());
        let metadata_end = (EDIT_HEADER_BYTES as usize)
            .checked_add(metadata_len)
            .ok_or_else(|| invalid("encrypted edit metadata length overflowed"))?;
        let expected_len = EDIT_HEADER_BYTES
            .checked_add(metadata_len as u64)
            .and_then(|length| length.checked_add(body_len))
            .ok_or_else(|| invalid("encrypted edit size overflowed"))?;
        if metadata_len == 0
            || metadata_len > MAX_EDIT_METADATA_BYTES
            || metadata_end > prefix.len()
            || body_len != row.plaintext_len
            || expected_len != plaintext_len
        {
            return Err(invalid("encrypted edit envelope lengths are invalid"));
        }
        let value: serde_json::Value =
            serde_json::from_slice(&prefix[EDIT_HEADER_BYTES as usize..metadata_end])
                .map_err(|_| invalid("encrypted edit metadata is invalid"))?;
        let mut metadata =
            parse_pending_metadata(&value, &self.scope, &self.root_path, session, row.state)?;
        if raiun_cache::ciphertext_target_hash(&metadata.encoded_target).map_err(cache_error)?
            != row.target_key
        {
            return Err(conflict(
                "encrypted edit target does not match its cache index",
            ));
        }
        let indexed_operation = match row.operation {
            CiphertextWriteOperation::Overwrite => VaultPendingOperationKind::Overwrite,
            CiphertextWriteOperation::CreateFile => VaultPendingOperationKind::CreateFile,
            CiphertextWriteOperation::RenameFile => VaultPendingOperationKind::RenameFile,
            CiphertextWriteOperation::DeleteFile => VaultPendingOperationKind::DeleteFile,
            CiphertextWriteOperation::CreateDirectory => VaultPendingOperationKind::CreateDirectory,
            CiphertextWriteOperation::CopyFile => VaultPendingOperationKind::CopyFile,
        };
        if metadata.id != row.id
            || metadata.revision != row.revision
            || metadata.plaintext_len != body_len
            || metadata.state != row.state
            || metadata.operation != indexed_operation
        {
            return Err(conflict(
                "encrypted edit revision does not match its journal row",
            ));
        }
        metadata.retry_generation = row.retry_generation;
        Ok(metadata)
    }

    /// Read the sealed root envelope before a session exists. The caller may
    /// pass this file to `raiun_vault::sealed_cache::unlock_from_snapshot`,
    /// which publishes a session only after embedded root-token verification.
    pub fn open_root_envelope(&self) -> Result<raiun_cache::CacheContentReader, CloudError> {
        if let Some(pin) = &self.pin {
            let version = listing_version_for_pin_parts(
                self.scope.resource_id(),
                &pin.id,
                pin.generation,
                self.ciphertext_epoch()?,
            );
            self.cache
                .open_ciphertext_pin_content(&self.cache_scope, &pin.id, &version)
                .map_err(cache_error)
        } else {
            open_root_envelope(&self.cache, &self.scope)
        }
    }

    /// Derive a candidate key from the cached root envelope and publish the
    /// unlocked session only after its embedded token and exact scope verify.
    pub fn unlock_root(
        &self,
        sessions: &VaultSessionCoordinator,
        password: &mut [u8],
    ) -> Result<
        (
            SealedVaultSnapshot,
            raiun_vault::sealed_cache::SealedVaultBlobInfo,
        ),
        CloudError,
    > {
        let mut envelope = self.open_root_envelope()?;
        raiun_vault::sealed_cache::unlock_from_snapshot(
            sessions,
            &self.scope,
            password,
            &mut envelope,
            MAX_CIPHERTEXT_BYTES,
        )
        .map_err(vault_error)
    }

    /// Discover current-epoch sealed root envelopes for one exact account and
    /// origin. Returned IDs are untrusted opaque candidates until the selected
    /// root envelope is authenticated by `unlock_cached_root`.
    pub fn discover_cached_roots(
        cache: &Cache,
        origin: &str,
        account_id: &str,
        after: Option<(&str, &str)>,
        limit: usize,
    ) -> Result<VaultCachedRootPage, CloudError> {
        if !(1..=MAX_DISCOVERY_PAGE).contains(&limit) {
            return Err(invalid("invalid encrypted cache discovery limit"));
        }
        let page = cache
            .ciphertext_scopes_for_account(origin, account_id, after, limit)
            .map_err(cache_error)?;
        let mut roots = Vec::new();
        for cached_scope in page.items {
            let scope = VaultSessionScope::new(
                cached_scope.account_id(),
                cached_scope.origin(),
                cached_scope.space_id(),
                cached_scope.root_resource_id(),
            )
            .map_err(vault_error)?;
            let cache_scope = cache_scope(&scope)?;
            let pins = cache
                .ciphertext_pins(&cache_scope, None, 100)
                .map_err(cache_error)?;
            let mut ready_pin = None;
            for candidate in pins.items {
                match cache.active_ciphertext_pin_info(&cache_scope, &candidate.id) {
                    Ok(pin) if pin.state == CiphertextPinState::Ready => {
                        ready_pin = Some(pin);
                        break;
                    }
                    Ok(_) => {}
                    Err(
                        raiun_cache::CacheError::PinNotFound | raiun_cache::CacheError::Conflict,
                    ) => {}
                    Err(error) => return Err(cache_error(error)),
                }
            }
            if let Some(pin) = ready_pin {
                roots.push(VaultCachedRoot {
                    space_id: scope.space_id().to_owned(),
                    root_resource_id: scope.resource_id().to_owned(),
                    pin_id: Some(pin.id),
                    generation: Some(pin.generation),
                });
                continue;
            }
            match open_root_envelope(cache, &scope) {
                Ok(envelope) => {
                    drop(envelope);
                    roots.push(VaultCachedRoot {
                        space_id: scope.space_id().to_owned(),
                        root_resource_id: scope.resource_id().to_owned(),
                        pin_id: None,
                        generation: None,
                    });
                }
                Err(error) if error.kind == ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(VaultCachedRootPage {
            roots,
            next_after: page.next_after,
            truncated: page.truncated,
        })
    }

    /// Unlock an exact cached candidate without caller-supplied path metadata.
    /// The physical root path and display fields become available only after
    /// the root token and scope-bound envelope have authenticated.
    pub fn unlock_cached_root(
        cache: &Cache,
        sessions: &VaultSessionCoordinator,
        scope: &VaultSessionScope,
        password: &mut [u8],
    ) -> Result<
        (
            SealedVaultSnapshot,
            raiun_vault::sealed_cache::SealedVaultBlobInfo,
        ),
        CloudError,
    > {
        let mut envelope = open_root_envelope(cache, scope)?;
        raiun_vault::sealed_cache::unlock_from_snapshot(
            sessions,
            scope,
            password,
            &mut envelope,
            MAX_CIPHERTEXT_BYTES,
        )
        .map_err(vault_error)
    }

    pub fn unlock_cached_pin_root(
        cache: &Cache,
        sessions: &VaultSessionCoordinator,
        scope: &VaultSessionScope,
        pin_id: &str,
        password: &mut [u8],
    ) -> Result<SealedVaultSnapshot, CloudError> {
        let cache_scope = cache_scope(scope)?;
        let pin = cache
            .active_ciphertext_pin_info(&cache_scope, pin_id)
            .map_err(cache_error)?;
        Self::unlock_cached_pin_root_expected(
            cache,
            sessions,
            scope,
            pin_id,
            pin.generation,
            password,
        )
    }

    /// Unlock only the exact ready pin generation selected by the caller.
    /// The active generation is checked both before and after authenticated
    /// decryption; a concurrent refresh cannot return an older snapshot as
    /// though it were the requested one.
    pub fn unlock_cached_pin_root_expected(
        cache: &Cache,
        sessions: &VaultSessionCoordinator,
        scope: &VaultSessionScope,
        pin_id: &str,
        expected_generation: u64,
        password: &mut [u8],
    ) -> Result<SealedVaultSnapshot, CloudError> {
        let cache_scope = cache_scope(scope)?;
        let pin = cache
            .active_ciphertext_pin_info(&cache_scope, pin_id)
            .map_err(cache_error)?;
        if pin.state != CiphertextPinState::Ready || pin.generation != expected_generation {
            return Err(conflict("encrypted snapshot generation changed"));
        }
        let epoch = cache.ciphertext_epoch(&cache_scope).map_err(cache_error)?;
        let version =
            listing_version_for_pin_parts(scope.resource_id(), &pin.id, pin.generation, epoch);
        let mut envelope = cache
            .open_ciphertext_pin_content(&cache_scope, &pin.id, &version)
            .map_err(cache_error)?;
        let (snapshot, _) = raiun_vault::sealed_cache::unlock_from_snapshot(
            sessions,
            scope,
            password,
            &mut envelope,
            MAX_CIPHERTEXT_BYTES,
        )
        .map_err(vault_error)?;
        // Successful decryption has already installed the derived key in the
        // session manager. If validation of the active generation itself
        // fails (for example the pin was concurrently removed or its cache
        // row became unreadable), revoke that key just as we do for a clear
        // generation mismatch. Never leave a usable session behind when this
        // helper returns an error.
        let current = cache.active_ciphertext_pin_info(&cache_scope, pin_id);
        revalidate_unlocked_pin_generation(sessions, scope, current, expected_generation)?;
        Ok(snapshot)
    }

    /// Confirm that the current encrypted scope has a root-envelope record.
    /// This is only an availability check; it does not authenticate the file.
    pub fn cached_root_available(
        cache: &Cache,
        scope: &VaultSessionScope,
    ) -> Result<bool, CloudError> {
        match open_root_envelope(cache, scope) {
            Ok(envelope) => {
                drop(envelope);
                Ok(true)
            }
            Err(error) if error.kind == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Persist a complete live DAV listing in a vault-encrypted envelope.
    /// Call only after the backend has validated the root token, every entry,
    /// and the complete DAV response. Cache failures must not make a successful
    /// online listing fail.
    pub(crate) fn publish_listing(
        &self,
        sessions: &VaultSessionCoordinator,
        metadata: &VaultListingMetadata<'_>,
        directory: &VaultDavEntry,
        children: &[VaultDavEntry],
        expected_epoch: u64,
    ) -> Result<(), CloudError> {
        self.publish_listing_inner(
            sessions,
            metadata,
            directory,
            children,
            expected_epoch,
            None,
        )
    }

    pub(crate) fn publish_listing_for_pin(
        &self,
        sessions: &VaultSessionCoordinator,
        metadata: &VaultListingMetadata<'_>,
        directory: &VaultDavEntry,
        children: &[VaultDavEntry],
        build: &CiphertextPinBuild,
        root_listing: bool,
    ) -> Result<(), CloudError> {
        self.publish_listing_inner(
            sessions,
            metadata,
            directory,
            children,
            build.epoch(),
            Some((
                build,
                if root_listing {
                    CiphertextPinItemKind::RootListing
                } else {
                    CiphertextPinItemKind::ChildListing
                },
            )),
        )
    }

    fn publish_listing_inner(
        &self,
        sessions: &VaultSessionCoordinator,
        metadata: &VaultListingMetadata<'_>,
        directory: &VaultDavEntry,
        children: &[VaultDavEntry],
        expected_epoch: u64,
        pin: Option<(&CiphertextPinBuild, CiphertextPinItemKind)>,
    ) -> Result<(), CloudError> {
        if !sessions
            .verify_integrity_token(&self.scope, metadata.integrity_token)
            .map_err(vault_error)?
        {
            return Err(conflict("vault listing token does not match the session"));
        }
        let mut entries = Vec::with_capacity(children.len());
        for entry in children {
            let etag = entry
                .strong_etag
                .clone()
                .ok_or_else(|| invalid("vault listing entry omitted a strong ETag"))?;
            entries.push(SealedVaultEntry {
                resource_id: entry.id.clone(),
                parent_resource_id: directory.id.clone(),
                encrypted_name: entry.raw_name.clone(),
                etag: Some(etag),
                ciphertext_len: if entry.directory { 0 } else { entry.size },
                directory: entry.directory,
                modified_unix: entry.modified_unix,
                writable: entry.writable,
            });
        }
        let directory_etag = directory
            .strong_etag
            .clone()
            .ok_or_else(|| invalid("vault directory omitted a strong ETag"))?;
        let snapshot = SealedVaultSnapshot {
            integrity_token: metadata.integrity_token.to_owned(),
            root_etag: metadata.root_etag.map(str::to_owned),
            root_path: self.root_path.clone(),
            space_dav_root: metadata.space_dav_root.to_owned(),
            space_name: metadata.space.name.clone(),
            space_dav_url: metadata.space.dav_url.clone(),
            space_personal: metadata.space.personal,
            space_writable: metadata.space.writable,
            space_encrypted: metadata.space.encrypted,
            directory_resource_id: directory.id.clone(),
            encrypted_directory_path: metadata.encrypted_directory_path.to_owned(),
            directory_etag,
            directory_modified_unix: directory.modified_unix,
            directory_writable: directory.writable,
            entries,
        };

        let private = tempdir().map_err(io_error)?;
        let ciphertext_path = private.path().join("listing.bin");
        let info = seal_snapshot(sessions, &self.scope, &snapshot, &ciphertext_path)
            .map_err(vault_error)?;
        let mut ciphertext = File::open(&ciphertext_path).map_err(io_error)?;
        if let Some((build, kind)) = pin {
            let version = listing_version_for_pin(&directory.id, build);
            self.cache
                .publish_ciphertext_for_pin_if_epoch(
                    &self.cache_scope,
                    &version,
                    &mut ciphertext,
                    info.ciphertext_bytes,
                    build,
                    kind,
                )
                .map_err(cache_error)?;
        } else {
            let version = listing_version(&directory.id, expected_epoch);
            self.cache
                .publish_ciphertext_if_epoch(
                    &self.cache_scope,
                    &version,
                    &mut ciphertext,
                    info.ciphertext_bytes,
                    Retention::Recent,
                    expected_epoch,
                )
                .map_err(cache_error)?;
            let _ = self.cache.evict_recent(self.cache.quota_bytes());
        }
        Ok(())
    }

    /// Store one ciphertext file only after the caller has downloaded it with
    /// exact ETag/length and successfully decrypted it. This method is private
    /// to the OpenCloud backend so unverified callers cannot publish arbitrary
    /// bytes as a verified file snapshot.
    pub(crate) fn publish_verified_ciphertext(
        &self,
        resource_id: &str,
        etag: &str,
        ciphertext_path: &Path,
        ciphertext_len: u64,
        expected_epoch: u64,
    ) -> Result<(), CloudError> {
        self.publish_verified_ciphertext_inner(
            resource_id,
            etag,
            ciphertext_path,
            ciphertext_len,
            expected_epoch,
            None,
        )
    }

    pub(crate) fn publish_verified_ciphertext_for_pin(
        &self,
        resource_id: &str,
        etag: &str,
        ciphertext_path: &Path,
        ciphertext_len: u64,
        build: &CiphertextPinBuild,
    ) -> Result<(), CloudError> {
        self.publish_verified_ciphertext_inner(
            resource_id,
            etag,
            ciphertext_path,
            ciphertext_len,
            build.epoch(),
            Some(build),
        )
    }

    fn publish_verified_ciphertext_inner(
        &self,
        resource_id: &str,
        etag: &str,
        ciphertext_path: &Path,
        ciphertext_len: u64,
        expected_epoch: u64,
        pin: Option<&CiphertextPinBuild>,
    ) -> Result<(), CloudError> {
        let version = if let Some(build) = pin {
            file_version_for_pin(resource_id, etag, build)
        } else {
            file_version(resource_id, etag, expected_epoch)
        };
        let mut ciphertext = File::open(ciphertext_path).map_err(io_error)?;
        if let Some(build) = pin {
            self.cache
                .publish_ciphertext_for_pin_if_epoch(
                    &self.cache_scope,
                    &version,
                    &mut ciphertext,
                    ciphertext_len,
                    build,
                    CiphertextPinItemKind::FileContent,
                )
                .map_err(cache_error)?;
        } else {
            self.cache
                .publish_ciphertext_if_epoch(
                    &self.cache_scope,
                    &version,
                    &mut ciphertext,
                    ciphertext_len,
                    Retention::Recent,
                    expected_epoch,
                )
                .map_err(cache_error)?;
            let _ = self.cache.evict_recent(self.cache.quota_bytes());
        }
        Ok(())
    }

    /// Return one complete cached directory after verifying the envelope with
    /// the exact unlocked scope. The cached root token is rechecked every time.
    pub fn list(
        &self,
        sessions: &VaultSessionCoordinator,
        path: &str,
    ) -> Result<Vec<RemoteEntry>, CloudError> {
        self.list_inner(sessions, path, false)
    }

    /// Explicit offline-edit projection. Permission fields are only cached
    /// hints used to decide whether an existing file may be edited locally;
    /// they do not authorize any remote write and reconciliation rechecks
    /// current server permissions and ETag.
    pub fn list_with_cached_permissions(
        &self,
        sessions: &VaultSessionCoordinator,
        path: &str,
    ) -> Result<Vec<RemoteEntry>, CloudError> {
        self.list_inner(sessions, path, true)
    }

    fn list_inner(
        &self,
        sessions: &VaultSessionCoordinator,
        path: &str,
        keep_cached_permissions: bool,
    ) -> Result<Vec<RemoteEntry>, CloudError> {
        self.ensure_unlocked(sessions)?;
        let epoch = self.ciphertext_epoch()?;
        let normalized = normalize_virtual_path(sessions, &self.scope, path)?;
        let snapshot = self.listing_for_directory(sessions, &normalized)?;
        let names = decode_names(sessions, &self.scope, &snapshot.entries)?;
        let entries = snapshot
            .entries
            .iter()
            .zip(names)
            .map(|(entry, name)| {
                remote_entry(
                    entry,
                    join_path(&normalized, &name),
                    false,
                    keep_cached_permissions,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.ensure_epoch(epoch)?;
        Ok(entries)
    }

    pub(crate) fn cached_root_snapshot(
        &self,
        sessions: &VaultSessionCoordinator,
    ) -> Result<SealedVaultSnapshot, CloudError> {
        self.ensure_unlocked(sessions)?;
        let snapshot = self.listing_for_directory(sessions, "/")?;
        if snapshot.directory_resource_id != self.scope.resource_id()
            || !snapshot.encrypted_directory_path.is_empty()
            || snapshot.root_path != self.root_path
        {
            return Err(conflict(
                "cached encrypted edit root does not match its scope",
            ));
        }
        Ok(snapshot)
    }

    pub fn stat(
        &self,
        sessions: &VaultSessionCoordinator,
        path: &str,
    ) -> Result<RemoteEntry, CloudError> {
        self.stat_inner(sessions, path, false)
    }

    pub fn stat_with_cached_permissions(
        &self,
        sessions: &VaultSessionCoordinator,
        path: &str,
    ) -> Result<RemoteEntry, CloudError> {
        self.stat_inner(sessions, path, true)
    }

    fn stat_inner(
        &self,
        sessions: &VaultSessionCoordinator,
        path: &str,
        keep_cached_permissions: bool,
    ) -> Result<RemoteEntry, CloudError> {
        self.ensure_unlocked(sessions)?;
        let epoch = self.ciphertext_epoch()?;
        let normalized = normalize_virtual_path(sessions, &self.scope, path)?;
        if normalized == "/" {
            let snapshot = self.listing_for_directory(sessions, "/")?;
            self.ensure_epoch(epoch)?;
            return Ok(directory_root_entry(&snapshot));
        }
        let (parent, leaf) = split_parent(&normalized);
        let snapshot = self.listing_for_directory(sessions, parent)?;
        let (entry, name) = find_child(sessions, &self.scope, &snapshot, leaf)?;
        if name != leaf {
            return Err(CloudError::new(
                ErrorKind::NotFound,
                "cached vault path was not found",
            ));
        }
        let remote = remote_entry(entry, normalized, false, keep_cached_permissions)?;
        self.ensure_epoch(epoch)?;
        Ok(remote)
    }

    /// Return the verified SHA-256 recorded for an exact cached ciphertext
    /// version. `open_content` checks the object against that digest before
    /// this method returns it; DAV metadata alone never supplies the proof.
    pub(crate) fn ciphertext_sha256(
        &self,
        sessions: &VaultSessionCoordinator,
        path: &str,
        expected_resource_id: &str,
        expected_etag: &str,
    ) -> Result<String, CloudError> {
        self.ensure_unlocked(sessions)?;
        let epoch = self.ciphertext_epoch()?;
        let normalized = normalize_virtual_path(sessions, &self.scope, path)?;
        if normalized == "/"
            || expected_resource_id.is_empty()
            || expected_resource_id.len() > 512
            || expected_etag.is_empty()
            || expected_etag.len() > 4_096
        {
            return Err(invalid("cached ciphertext identity is invalid"));
        }
        let raw = self.find_raw_entry(sessions, &normalized)?;
        if raw.directory
            || raw.resource_id != expected_resource_id
            || raw.etag.as_deref() != Some(expected_etag)
        {
            return Err(conflict("cached ciphertext identity changed"));
        }
        let version = if let Some(pin) = &self.pin {
            file_version_for_pin_parts(
                &raw.resource_id,
                expected_etag,
                &pin.id,
                pin.generation,
                epoch,
            )
        } else {
            file_version(&raw.resource_id, expected_etag, epoch)
        };
        let content = if let Some(pin) = &self.pin {
            self.cache
                .open_ciphertext_pin_content(&self.cache_scope, &pin.id, &version)
        } else {
            self.cache.open_content(&self.cache_scope, &version)
        }
        .map_err(cache_error)?;
        let ciphertext_len = content.metadata().map_err(io_error)?.len();
        if ciphertext_len != raw.ciphertext_len {
            return Err(conflict("cached ciphertext length changed"));
        }
        let record = self
            .cache
            .content_record(&self.cache_scope, &version)
            .map_err(cache_error)?;
        if record.byte_len != ciphertext_len || !is_sha256_digest(&record.sha256) {
            return Err(conflict("cached ciphertext digest metadata is invalid"));
        }
        self.ensure_epoch(epoch)?;
        Ok(record.sha256)
    }

    /// Decrypt an exact cached ciphertext version to a new destination. The
    /// destination must be temporary/private when used for mounted reads; this
    /// API itself does not provide secure disk erasure or crash cleanup.
    pub fn download(
        &self,
        sessions: &VaultSessionCoordinator,
        path: &str,
        expected_etag: Option<&str>,
        destination: &Path,
    ) -> Result<RemoteEntry, CloudError> {
        self.ensure_unlocked(sessions)?;
        let cache_epoch = self.ciphertext_epoch()?;
        let entry = self.stat(sessions, path)?;
        if entry.directory {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cannot download a cached vault directory",
            ));
        }
        if expected_etag.is_some_and(|etag| etag != entry.etag) {
            return Err(conflict("cached vault file version does not match"));
        }
        let raw = self.find_raw_entry(sessions, path)?;
        let etag = raw
            .etag
            .as_deref()
            .ok_or_else(|| invalid("cached vault file omitted its ETag"))?;
        let expected_ciphertext = raw.ciphertext_len;
        let mut ciphertext = if let Some(pin) = &self.pin {
            self.cache
                .open_ciphertext_pin_content(
                    &self.cache_scope,
                    &pin.id,
                    &file_version_for_pin_parts(
                        &raw.resource_id,
                        etag,
                        &pin.id,
                        pin.generation,
                        cache_epoch,
                    ),
                )
                .map_err(cache_error)?
        } else {
            self.cache
                .open_content(
                    &self.cache_scope,
                    &file_version(&raw.resource_id, etag, cache_epoch),
                )
                .map_err(cache_error)?
        };
        let actual_len = ciphertext.metadata().map_err(io_error)?.len();
        if actual_len != expected_ciphertext {
            return Err(conflict("cached vault ciphertext length changed"));
        }

        let parent = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let placeholder = NamedTempFile::new_in(parent).map_err(io_error)?;
        let plaintext_path = placeholder.into_temp_path();
        fs::remove_file(&plaintext_path).map_err(io_error)?;
        let plaintext_len = plaintext_len_from_ciphertext(expected_ciphertext)?;
        if plaintext_len != entry.size || plaintext_len > MAX_PLAINTEXT_BYTES {
            return Err(conflict("cached vault plaintext length is invalid"));
        }
        let decrypted = sessions
            .decrypt_file_transactional(
                &self.scope,
                &mut ciphertext,
                &plaintext_path,
                MAX_PLAINTEXT_BYTES,
                Some(plaintext_len),
            )
            .map_err(vault_error)?;
        if decrypted != plaintext_len
            || !sessions.is_unlocked(&self.scope).map_err(vault_error)?
            || self.ciphertext_epoch()? != cache_epoch
        {
            let _ = fs::remove_file(&plaintext_path);
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault session was locked before cached read publication",
            ));
        }
        let output = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&plaintext_path)
            .map_err(io_error)?;
        NamedTempFile::from_parts(output, plaintext_path)
            .persist(destination)
            .map_err(|error| io_error(error.error))?;
        Ok(entry)
    }

    fn ensure_unlocked(&self, sessions: &VaultSessionCoordinator) -> Result<(), CloudError> {
        if !sessions.is_unlocked(&self.scope).map_err(vault_error)? {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault session is locked",
            ));
        }
        Ok(())
    }

    fn ensure_epoch(&self, expected: u64) -> Result<(), CloudError> {
        if self.ciphertext_epoch()? == expected {
            Ok(())
        } else {
            Err(conflict("encrypted cache changed during the operation"))
        }
    }

    fn listing_for_directory(
        &self,
        sessions: &VaultSessionCoordinator,
        path: &str,
    ) -> Result<SealedVaultSnapshot, CloudError> {
        let mut directory_id = self.scope.resource_id().to_owned();
        let mut encrypted_path = String::new();
        let mut snapshot = self.load_listing(sessions, &directory_id, &encrypted_path)?;
        if path == "/" {
            return Ok(snapshot);
        }
        for component in path.trim_start_matches('/').split('/') {
            let (entry, _) = find_child(sessions, &self.scope, &snapshot, component)?;
            if !entry.directory {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "cached vault path is not a directory",
                ));
            }
            directory_id = entry.resource_id.clone();
            if encrypted_path.is_empty() {
                encrypted_path = entry.encrypted_name.clone();
            } else {
                encrypted_path.push('/');
                encrypted_path.push_str(&entry.encrypted_name);
            }
            snapshot = self.load_listing(sessions, &directory_id, &encrypted_path)?;
        }
        Ok(snapshot)
    }

    fn find_raw_entry(
        &self,
        sessions: &VaultSessionCoordinator,
        path: &str,
    ) -> Result<SealedVaultEntry, CloudError> {
        let normalized = normalize_virtual_path(sessions, &self.scope, path)?;
        if normalized == "/" {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "vault root has no file content",
            ));
        }
        let (parent, leaf) = split_parent(&normalized);
        let snapshot = self.listing_for_directory(sessions, parent)?;
        let (entry, name) = find_child(sessions, &self.scope, &snapshot, leaf)?;
        if name != leaf {
            return Err(CloudError::new(
                ErrorKind::NotFound,
                "cached vault path was not found",
            ));
        }
        Ok(entry.clone())
    }

    fn load_listing(
        &self,
        sessions: &VaultSessionCoordinator,
        directory_id: &str,
        encrypted_path: &str,
    ) -> Result<SealedVaultSnapshot, CloudError> {
        let epoch = self.ciphertext_epoch()?;
        let mut ciphertext = if let Some(pin) = &self.pin {
            self.cache
                .open_ciphertext_pin_content(
                    &self.cache_scope,
                    &pin.id,
                    &listing_version_for_pin_parts(directory_id, &pin.id, pin.generation, epoch),
                )
                .map_err(cache_error)?
        } else {
            self.cache
                .open_content(&self.cache_scope, &listing_version(directory_id, epoch))
                .map_err(cache_error)?
        };
        let (snapshot, _) =
            open_snapshot(sessions, &self.scope, &mut ciphertext, MAX_CIPHERTEXT_BYTES)
                .map_err(vault_error)?;
        if snapshot.directory_resource_id != directory_id
            || snapshot.encrypted_directory_path != encrypted_path
            || snapshot.root_path != self.root_path
            || !valid_cached_dav_binding(
                self.scope.server_origin(),
                &snapshot.space_dav_url,
                &snapshot.space_dav_root,
            )
            || snapshot
                .entries
                .iter()
                .any(|entry| entry.parent_resource_id != directory_id)
        {
            return Err(conflict(
                "sealed vault listing identity does not match its cache key",
            ));
        }
        Ok(snapshot)
    }
}

fn valid_cached_dav_binding(origin: &str, space_url: &str, dav_root: &str) -> bool {
    let Ok(space_url) = Url::parse(space_url) else {
        return false;
    };
    let Ok(dav_root) = Url::parse(dav_root) else {
        return false;
    };
    let safe = |url: &Url| {
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.origin().ascii_serialization() == origin
    };
    if !safe(&space_url) || !safe(&dav_root) {
        return false;
    }
    let mut prefix = space_url.path().to_owned();
    if !prefix.ends_with('/') {
        prefix.push('/');
    }
    let mut root = dav_root.path().to_owned();
    if !root.ends_with('/') {
        root.push('/');
    }
    root.starts_with(&prefix)
}

fn listing_version(directory_id: &str, epoch: u64) -> ContentVersion {
    ContentVersion {
        resource_id: format!("{LISTING_ID_PREFIX}{directory_id}"),
        etag: format!("{LISTING_ETAG_PREFIX}{epoch}"),
        protection: ContentProtection::Ciphertext,
    }
}

fn listing_version_for_pin(directory_id: &str, build: &CiphertextPinBuild) -> ContentVersion {
    listing_version_for_pin_parts(directory_id, build.id(), build.generation(), build.epoch())
}

fn listing_version_for_pin_parts(
    directory_id: &str,
    pin_id: &str,
    generation: u64,
    epoch: u64,
) -> ContentVersion {
    ContentVersion {
        resource_id: format!("{LISTING_ID_PREFIX}{directory_id}"),
        etag: format!("{LISTING_ETAG_PREFIX}pin:{pin_id}:{generation}:{epoch}"),
        protection: ContentProtection::Ciphertext,
    }
}

fn revalidate_unlocked_pin_generation(
    sessions: &VaultSessionCoordinator,
    scope: &VaultSessionScope,
    current: Result<CiphertextPinInfo, raiun_cache::CacheError>,
    expected_generation: u64,
) -> Result<(), CloudError> {
    let current = match current {
        Ok(current) => current,
        Err(error) => {
            // Decryption has installed the derived key. A failed lookup is as
            // unsafe as an explicit generation mismatch: do not leave the key
            // usable after the selected cache proof could not be revalidated.
            let _ = sessions.lock(scope);
            return Err(cache_error(error));
        }
    };
    if current.state != CiphertextPinState::Ready || current.generation != expected_generation {
        let _ = sessions.lock(scope);
        return Err(conflict("encrypted snapshot generation changed"));
    }
    Ok(())
}

fn cache_scope(scope: &VaultSessionScope) -> Result<CacheScope, CloudError> {
    CacheScope::new(
        scope.server_origin(),
        scope.account_id(),
        scope.space_id(),
        scope.resource_id(),
        ScopeProtection::CiphertextOnly,
    )
    .map_err(cache_error)
}

fn open_root_envelope(
    cache: &Cache,
    scope: &VaultSessionScope,
) -> Result<raiun_cache::CacheContentReader, CloudError> {
    let cache_scope = cache_scope(scope)?;
    let epoch = cache.ciphertext_epoch(&cache_scope).map_err(cache_error)?;
    cache
        .open_content(&cache_scope, &listing_version(scope.resource_id(), epoch))
        .map_err(cache_error)
}

fn file_version(resource_id: &str, etag: &str, epoch: u64) -> ContentVersion {
    ContentVersion {
        resource_id: resource_id.to_owned(),
        etag: format!("{FILE_ETAG_PREFIX}{epoch}:{etag}"),
        protection: ContentProtection::Ciphertext,
    }
}

fn file_version_for_pin(
    resource_id: &str,
    etag: &str,
    build: &CiphertextPinBuild,
) -> ContentVersion {
    file_version_for_pin_parts(
        resource_id,
        etag,
        build.id(),
        build.generation(),
        build.epoch(),
    )
}

fn file_version_for_pin_parts(
    resource_id: &str,
    etag: &str,
    pin_id: &str,
    generation: u64,
    epoch: u64,
) -> ContentVersion {
    ContentVersion {
        resource_id: resource_id.to_owned(),
        etag: format!(
            "{FILE_ETAG_PREFIX}pin:{}:{}:{}:{}",
            pin_id, generation, epoch, etag
        ),
        protection: ContentProtection::Ciphertext,
    }
}

fn decode_names(
    sessions: &VaultSessionCoordinator,
    scope: &VaultSessionScope,
    entries: &[SealedVaultEntry],
) -> Result<Vec<String>, CloudError> {
    let encrypted = entries
        .iter()
        .map(|entry| entry.encrypted_name.as_str())
        .collect::<Vec<_>>();
    sessions
        .decode_directory_names(scope, &encrypted)
        .map_err(vault_error)
}

fn find_child<'a>(
    sessions: &VaultSessionCoordinator,
    scope: &VaultSessionScope,
    snapshot: &'a SealedVaultSnapshot,
    wanted: &str,
) -> Result<(&'a SealedVaultEntry, String), CloudError> {
    let names = decode_names(sessions, scope, &snapshot.entries)?;
    let mut matches = snapshot
        .entries
        .iter()
        .zip(names)
        .filter(|(_, name)| name == wanted);
    let first = matches.next();
    if matches.next().is_some() {
        return Err(conflict("sealed vault listing has ambiguous decoded names"));
    }
    first.ok_or_else(|| CloudError::new(ErrorKind::NotFound, "cached vault path was not found"))
}

fn remote_entry(
    entry: &SealedVaultEntry,
    path: String,
    encrypted: bool,
    keep_cached_permissions: bool,
) -> Result<RemoteEntry, CloudError> {
    let etag = entry
        .etag
        .clone()
        .ok_or_else(|| invalid("cached vault entry omitted its ETag"))?;
    let size = if entry.directory {
        0
    } else {
        plaintext_len_from_ciphertext(entry.ciphertext_len)?
    };
    Ok(RemoteEntry {
        id: entry.resource_id.clone(),
        path,
        directory: entry.directory,
        size,
        etag,
        modified_unix: entry.modified_unix,
        // Cached permission hints are never current server authorization.
        // They are exposed only for the explicit local-edit projection;
        // the queue never sends a mutation until online revalidation.
        writable: keep_cached_permissions && entry.writable,
        encrypted,
    })
}

fn directory_root_entry(snapshot: &SealedVaultSnapshot) -> RemoteEntry {
    RemoteEntry {
        id: snapshot.directory_resource_id.clone(),
        path: "/".to_owned(),
        directory: true,
        size: 0,
        etag: snapshot.directory_etag.clone(),
        modified_unix: snapshot.directory_modified_unix,
        // Offline edits are only queued locally and are revalidated against
        // current root/parent permissions before any remote mutation. Preserve
        // the authenticated last-known permission hint so FUSE can expose the
        // limited local edit/create surface when it builds directory modes.
        writable: snapshot.space_writable && snapshot.directory_writable,
        encrypted: false,
    }
}

fn normalize_virtual_path(
    sessions: &VaultSessionCoordinator,
    scope: &VaultSessionScope,
    path: &str,
) -> Result<String, CloudError> {
    if path == "/" {
        return Ok(path.to_owned());
    }
    if path.len() > 32_768 || !path.starts_with('/') || path.ends_with('/') {
        return Err(invalid("invalid cached vault path"));
    }
    let relative = path.trim_start_matches('/');
    if relative.split('/').any(|component| component.is_empty()) {
        return Err(invalid("invalid cached vault path"));
    }
    sessions
        .encrypt_path(scope, relative)
        .map_err(vault_error)?;
    Ok(path.to_owned())
}

fn normalize_root_path(path: &str) -> Result<String, CloudError> {
    if path == "/" {
        return Ok("/".to_owned());
    }
    if path.is_empty() || !path.starts_with('/') || path.ends_with('/') || path.len() > 32_768 {
        return Err(invalid("invalid cached vault root path"));
    }
    if path
        .trim_start_matches('/')
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(invalid("invalid cached vault root path"));
    }
    Ok(path.to_owned())
}

fn split_parent(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        Some(("", leaf)) => ("/", leaf),
        Some((parent, leaf)) => (parent, leaf),
        None => ("/", path),
    }
}

fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn plaintext_len_from_ciphertext(ciphertext_size: u64) -> Result<u64, CloudError> {
    const HEADER: u64 = 32;
    const PLAIN_BLOCK: u64 = 65_536;
    const CIPHER_BLOCK: u64 = PLAIN_BLOCK + 16;
    let payload = ciphertext_size
        .checked_sub(HEADER)
        .ok_or_else(|| invalid("cached vault ciphertext is shorter than its header"))?;
    if payload == 0 {
        return Ok(0);
    }
    let full_blocks = payload / CIPHER_BLOCK;
    let remainder = payload % CIPHER_BLOCK;
    if remainder == 0 {
        return full_blocks
            .checked_mul(PLAIN_BLOCK)
            .ok_or_else(|| invalid("cached vault size overflow"));
    }
    if remainder < 16 {
        return Err(invalid(
            "cached vault ciphertext has an invalid block length",
        ));
    }
    full_blocks
        .checked_mul(PLAIN_BLOCK)
        .and_then(|size| size.checked_add(remainder - 16))
        .ok_or_else(|| invalid("cached vault size overflow"))
}

fn parse_pending_metadata(
    value: &serde_json::Value,
    scope: &VaultSessionScope,
    root_path: &str,
    session: &raiun_vault::VerifiedVaultSession,
    state: CiphertextWriteState,
) -> Result<VaultPendingEditMetadata, CloudError> {
    let text = |key: &str, limit: usize| -> Result<String, CloudError> {
        let value = value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| invalid("encrypted edit metadata is incomplete"))?;
        if value.is_empty() || value.len() > limit {
            return Err(invalid("encrypted edit metadata is outside its bounds"));
        }
        Ok(value.to_owned())
    };
    let number = |key: &str| -> Result<u64, CloudError> {
        value
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| invalid("encrypted edit metadata is incomplete"))
    };
    let version = number("version")?;
    if !(1..=12).contains(&version)
        || text("account_id", 256)? != scope.account_id()
        || text("server_origin", 2_048)? != scope.server_origin()
        || text("space_id", 512)? != scope.space_id()
        || text("root_resource_id", 512)? != scope.resource_id()
        || text("root_path", 32_768)? != root_path
    {
        return Err(conflict("encrypted edit belongs to another vault scope"));
    }
    let id = text("id", 32)?;
    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("encrypted edit identifier is invalid"));
    }
    let revision = number("revision")?;
    if revision == 0 {
        return Err(invalid("encrypted edit revision is invalid"));
    }
    let token = text("integrity_token", 256)?;
    if !session.verify_integrity_token(&token) {
        return Err(conflict("encrypted edit root token does not match"));
    }
    let encoded_target = text("encoded_target", 32_768)?;
    let decoded = session.decrypt_path(&encoded_target).map_err(vault_error)?;
    if decoded.is_root() {
        return Err(invalid("encrypted edit targets the vault root"));
    }
    let path = format!("/{}", decoded.into_components().join("/"));
    validate_pending_path(&path)?;
    let (operation, base, base_resource_id, base_etag) = if version == 1 {
        let resource_id = text("base_resource_id", 512)?;
        let etag = text("base_etag", 4_096)?;
        (
            VaultPendingOperationKind::Overwrite,
            WriteCondition::Match(etag.clone()),
            resource_id,
            etag,
        )
    } else {
        let operation = match text("operation", 32)?.as_str() {
            "overwrite" => VaultPendingOperationKind::Overwrite,
            "create_file" => VaultPendingOperationKind::CreateFile,
            "copy_file" if version >= 11 => VaultPendingOperationKind::CopyFile,
            "rename_file" if version >= 5 => VaultPendingOperationKind::RenameFile,
            "delete_file" if version >= 6 => VaultPendingOperationKind::DeleteFile,
            "create_directory" if version >= 7 => VaultPendingOperationKind::CreateDirectory,
            _ => return Err(invalid("encrypted operation kind is invalid")),
        };
        let optional_text = |key: &str, limit: usize| -> Result<String, CloudError> {
            match value.get(key) {
                Some(serde_json::Value::Null) | None => Ok(String::new()),
                Some(serde_json::Value::String(text))
                    if text.len() <= limit && !text.contains('\0') =>
                {
                    Ok(text.clone())
                }
                _ => Err(invalid(
                    "encrypted operation metadata is outside its bounds",
                )),
            }
        };
        let base_resource_id = optional_text("base_resource_id", 512)?;
        let base_etag = optional_text("base_etag", 4_096)?;
        let base = match value.get("base_kind").and_then(serde_json::Value::as_str) {
            Some("absent") if base_resource_id.is_empty() && base_etag.is_empty() => {
                WriteCondition::Absent
            }
            Some("match") if !base_resource_id.is_empty() && !base_etag.is_empty() => {
                WriteCondition::Match(base_etag.clone())
            }
            _ => return Err(invalid("encrypted operation base condition is invalid")),
        };
        if (operation == VaultPendingOperationKind::CreateFile
            || operation == VaultPendingOperationKind::CopyFile
            || operation == VaultPendingOperationKind::CreateDirectory)
            != matches!(base, WriteCondition::Absent)
        {
            return Err(invalid("encrypted operation base does not match its kind"));
        }
        let parent_resource_id = optional_text("parent_resource_id", 512)?;
        let parent_etag = optional_text("parent_etag", 4_096)?;
        let parent_ref =
            parse_parent_ref(value, version, operation, &parent_resource_id, &parent_etag)?;
        if matches!(
            operation,
            VaultPendingOperationKind::CreateFile
                | VaultPendingOperationKind::CopyFile
                | VaultPendingOperationKind::CreateDirectory
        ) && (version < 3 || parent_ref.is_none())
        {
            return Err(conflict("encrypted create parent binding is unavailable"));
        }
        if operation == VaultPendingOperationKind::Overwrite
            && (!parent_resource_id.is_empty() || !parent_etag.is_empty())
        {
            return Err(invalid(
                "overwrite unexpectedly contains a create parent binding",
            ));
        }
        if operation == VaultPendingOperationKind::RenameFile
            && (version < 5
                || !matches!(base, WriteCondition::Match(_))
                || base_resource_id.is_empty()
                || parent_resource_id.is_empty()
                || parent_etag.is_empty())
        {
            return Err(conflict("encrypted rename source binding is unavailable"));
        }
        if operation == VaultPendingOperationKind::DeleteFile
            && (version < 6
                || !matches!(base, WriteCondition::Match(_))
                || base_resource_id.is_empty()
                || parent_resource_id.is_empty()
                || parent_etag.is_empty())
        {
            return Err(conflict("encrypted delete source binding is unavailable"));
        }
        if operation == VaultPendingOperationKind::CreateDirectory
            && (version < 7 || number("body_len")? != 0)
        {
            return Err(invalid("encrypted directory create metadata is invalid"));
        }
        if operation == VaultPendingOperationKind::CopyFile
            && (!matches!(parent_ref, Some(VaultPendingParentRef::Stable { .. }))
                || state == CiphertextWriteState::Building)
        {
            return Err(conflict(
                "encrypted copy destination binding is unavailable",
            ));
        }
        (operation, base, base_resource_id, base_etag)
    };
    let plaintext_len = number("body_len")?;
    if plaintext_len > MAX_EDIT_BYTES {
        return Err(invalid("encrypted edit body exceeds its size limit"));
    }
    let copy_source = if operation == VaultPendingOperationKind::CopyFile && version >= 12 {
        let binding = value
            .get("copy_source")
            .filter(|value| !value.is_null())
            .ok_or_else(|| conflict("encrypted copy source binding is unavailable"))?;
        let binding_text = |key: &str, limit: usize| -> Result<String, CloudError> {
            let text = binding
                .get(key)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| invalid("encrypted copy source binding is incomplete"))?;
            if text.is_empty() || text.len() > limit || text.contains('\0') {
                return Err(invalid(
                    "encrypted copy source binding is outside its bounds",
                ));
            }
            Ok(text.to_owned())
        };
        let source = VaultCopySourceBinding {
            account_id: binding_text("account_id", 256)?,
            server_origin: binding_text("server_origin", 2_048)?,
            space_id: binding_text("space_id", 512)?,
            root_resource_id: binding_text("root_resource_id", 512)?,
            root_path: binding_text("root_path", 32_768)?,
            path: binding_text("path", 32_768)?,
            resource_id: binding_text("resource_id", 512)?,
            etag: binding_text("etag", 4_096)?,
            plaintext_len: binding
                .get("plaintext_len")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| invalid("encrypted copy source length is invalid"))?,
            plaintext_sha256: binding_text("plaintext_sha256", 64)?,
        };
        if !valid_copy_source_binding(&source, plaintext_len) {
            return Err(invalid("encrypted copy source binding is invalid"));
        }
        Some(source)
    } else {
        if operation != VaultPendingOperationKind::CopyFile
            && value
                .get("copy_source")
                .is_some_and(|binding| !binding.is_null())
        {
            return Err(invalid("non-copy operation contains a copy source binding"));
        }
        None
    };
    let cancelled_revision = if version >= 10 {
        number("cancelled_revision")?
    } else {
        0
    };
    let cancelled_plaintext_len = if version >= 10 {
        number("cancelled_plaintext_len")?
    } else {
        0
    };
    let cancelled_plaintext_sha256 = if version >= 10 {
        match value.get("cancelled_plaintext_sha256") {
            Some(serde_json::Value::String(text)) if text.len() <= 64 && !text.contains('\0') => {
                text.clone()
            }
            _ => return Err(invalid("encrypted cancellation proof digest is invalid")),
        }
    } else {
        String::new()
    };
    if state == CiphertextWriteState::AcknowledgedReceipt {
        if version < 10
            || operation != VaultPendingOperationKind::CreateFile
            || base != WriteCondition::Absent
            || plaintext_len != 0
            || cancelled_revision == 0
            || cancelled_revision >= revision
            || cancelled_plaintext_len > MAX_EDIT_BYTES
            || !is_sha256_digest(&cancelled_plaintext_sha256)
        {
            return Err(invalid(
                "encrypted cancellation acknowledgement is incomplete",
            ));
        }
    } else if cancelled_revision != 0
        || cancelled_plaintext_len != 0
        || !cancelled_plaintext_sha256.is_empty()
    {
        return Err(invalid(
            "non-acknowledged operation contains cancellation proof data",
        ));
    }
    let parent_resource_id = if version == 1 {
        String::new()
    } else {
        value
            .get("parent_resource_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let parent_etag = if version == 1 {
        String::new()
    } else {
        value
            .get("parent_etag")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let parent_ref =
        parse_parent_ref(value, version, operation, &parent_resource_id, &parent_etag)?;
    let optional_text = |key: &str, limit: usize| -> Result<String, CloudError> {
        match value.get(key) {
            Some(serde_json::Value::Null) | None => Ok(String::new()),
            Some(serde_json::Value::String(text))
                if text.len() <= limit && !text.contains('\0') =>
            {
                Ok(text.clone())
            }
            _ => Err(invalid(
                "encrypted operation metadata is outside its bounds",
            )),
        }
    };
    let receipt_resource_id = if version >= 9 {
        optional_text("receipt_resource_id", 512)?
    } else {
        String::new()
    };
    let receipt_etag = if version >= 9 {
        optional_text("receipt_etag", 4_096)?
    } else {
        String::new()
    };
    let receipt_for_revision = if version >= 9 {
        value
            .get("receipt_for_revision")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| invalid("encrypted receipt revision is missing"))?
    } else {
        0
    };
    if state == CiphertextWriteState::CommittedReceipt {
        if version < 9
            || operation != VaultPendingOperationKind::CreateDirectory
            || receipt_resource_id.is_empty()
            || receipt_etag.is_empty()
            || receipt_for_revision == 0
            || receipt_for_revision > i64::MAX as u64
        {
            return Err(invalid("encrypted directory receipt is incomplete"));
        }
    } else if !receipt_resource_id.is_empty()
        || !receipt_etag.is_empty()
        || receipt_for_revision != 0
    {
        return Err(invalid("non-receipt operation contains receipt data"));
    }
    let (
        destination_path,
        encoded_destination_target,
        destination_parent_resource_id,
        destination_parent_etag,
        source_size,
        source_ciphertext_sha256,
    ) = if operation == VaultPendingOperationKind::RenameFile {
        let encoded = text("encoded_destination_target", 32_768)?;
        let decoded = session.decrypt_path(&encoded).map_err(vault_error)?;
        if decoded.is_root() {
            return Err(invalid("encrypted rename targets the vault root"));
        }
        let destination = format!("/{}", decoded.into_components().join("/"));
        validate_pending_path(&destination)?;
        if destination == path {
            return Err(invalid("encrypted rename source and destination are equal"));
        }
        let source_parent = optional_text("parent_resource_id", 512)?;
        let source_parent_etag = optional_text("parent_etag", 4_096)?;
        let destination_parent = text("destination_parent_resource_id", 512)?;
        let destination_parent_etag = text("destination_parent_etag", 4_096)?;
        if source_parent.is_empty() || source_parent_etag.is_empty() {
            return Err(invalid("encrypted rename source parent binding is missing"));
        }
        let source_size = number("source_size")?;
        let source_ciphertext_sha256 = text("source_ciphertext_sha256", 64)?;
        if !is_sha256_digest(&source_ciphertext_sha256) {
            return Err(invalid("encrypted rename content proof is invalid"));
        }
        if source_size > MAX_EDIT_BYTES || plaintext_len != 0 {
            return Err(invalid("encrypted rename size metadata is invalid"));
        }
        (
            destination,
            encoded,
            destination_parent,
            destination_parent_etag,
            source_size,
            source_ciphertext_sha256,
        )
    } else if operation == VaultPendingOperationKind::DeleteFile {
        let source_size = number("source_size")?;
        let source_ciphertext_sha256 = text("source_ciphertext_sha256", 64)?;
        if !is_sha256_digest(&source_ciphertext_sha256)
            || source_size != plaintext_len
            || source_size > MAX_EDIT_BYTES
        {
            return Err(invalid("encrypted delete recovery binding is invalid"));
        }
        (
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            source_size,
            source_ciphertext_sha256,
        )
    } else {
        if version >= 5
            && operation != VaultPendingOperationKind::DeleteFile
            && (!optional_text("encoded_destination_target", 32_768)?.is_empty()
                || !optional_text("destination_parent_resource_id", 512)?.is_empty()
                || !optional_text("destination_parent_etag", 4_096)?.is_empty()
                || number("source_size")? != 0
                || !optional_text("source_ciphertext_sha256", 64)?.is_empty())
        {
            return Err(invalid("operation contains unexpected rename metadata"));
        }
        (
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            0,
            String::new(),
        )
    };
    Ok(VaultPendingEditMetadata {
        id,
        revision,
        retry_generation: 0,
        path,
        destination_path,
        encoded_target,
        encoded_destination_target,
        root_integrity_token: token,
        base_resource_id,
        base_etag,
        parent_resource_id,
        parent_etag,
        parent_ref,
        receipt_resource_id,
        receipt_etag,
        receipt_for_revision,
        destination_parent_resource_id,
        destination_parent_etag,
        source_size,
        source_ciphertext_sha256,
        copy_source,
        base,
        operation,
        plaintext_len,
        state,
        cancelled_revision,
        cancelled_plaintext_len,
        cancelled_plaintext_sha256,
    })
}

fn parse_parent_ref(
    value: &serde_json::Value,
    version: u64,
    operation: VaultPendingOperationKind,
    parent_resource_id: &str,
    parent_etag: &str,
) -> Result<Option<VaultPendingParentRef>, CloudError> {
    let is_create = matches!(
        operation,
        VaultPendingOperationKind::CreateFile
            | VaultPendingOperationKind::CopyFile
            | VaultPendingOperationKind::CreateDirectory
    );
    if !is_create {
        if value
            .get("parent_ref")
            .is_some_and(|entry| !entry.is_null())
        {
            return Err(invalid("non-create operation has a parent reference"));
        }
        return Ok(None);
    }
    let reference = if version >= 8 {
        let reference = value
            .get("parent_ref")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| invalid("encrypted create parent reference is missing"))?;
        match reference.get("kind").and_then(serde_json::Value::as_str) {
            Some("stable") => {
                let resource_id = reference
                    .get("resource_id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| !value.is_empty() && value.len() <= 512)
                    .ok_or_else(|| invalid("stable parent identity is invalid"))?;
                VaultPendingParentRef::Stable {
                    resource_id: resource_id.to_owned(),
                }
            }
            Some("pending_create") => {
                let write_id = reference
                    .get("write_id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| {
                        value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
                    .ok_or_else(|| invalid("pending parent operation identity is invalid"))?;
                let revision = reference
                    .get("revision")
                    .and_then(serde_json::Value::as_u64)
                    .filter(|revision| *revision > 0 && *revision <= i64::MAX as u64)
                    .ok_or_else(|| invalid("pending parent operation revision is invalid"))?;
                VaultPendingParentRef::PendingCreate {
                    write_id: write_id.to_owned(),
                    revision,
                }
            }
            _ => return Err(invalid("encrypted create parent reference is invalid")),
        }
    } else {
        if parent_resource_id.is_empty() || parent_etag.is_empty() {
            return Err(conflict("legacy encrypted create has no stable parent"));
        }
        VaultPendingParentRef::Stable {
            resource_id: parent_resource_id.to_owned(),
        }
    };
    match &reference {
        VaultPendingParentRef::Stable { resource_id }
            if resource_id == parent_resource_id
                && !parent_etag.is_empty()
                && parent_etag.len() <= 4_096 => {}
        VaultPendingParentRef::PendingCreate { .. }
            if parent_resource_id.is_empty() && parent_etag.is_empty() => {}
        _ => return Err(invalid("encrypted create parent binding is inconsistent")),
    }
    Ok(Some(reference))
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_copy_source_binding(binding: &VaultCopySourceBinding, body_len: u64) -> bool {
    let origin = Url::parse(&binding.server_origin);
    let valid_origin = origin.is_ok_and(|origin| {
        matches!(origin.scheme(), "http" | "https")
            && origin.host_str().is_some()
            && origin.username().is_empty()
            && origin.password().is_none()
            && (origin.path().is_empty() || origin.path() == "/")
            && origin.query().is_none()
            && origin.fragment().is_none()
    });
    valid_origin
        && !binding.account_id.is_empty()
        && binding.account_id.len() <= 256
        && !binding.space_id.is_empty()
        && binding.space_id.len() <= 512
        && !binding.root_resource_id.is_empty()
        && binding.root_resource_id.len() <= 512
        && binding.root_path.starts_with('/')
        && binding.root_path.len() <= 32_768
        && !binding.root_path.contains('\0')
        && validate_pending_path(&binding.path).is_ok()
        && !binding.resource_id.is_empty()
        && binding.resource_id.len() <= 512
        && binding.etag.len() >= 2
        && binding.etag.len() <= 4_096
        && binding.etag.starts_with('"')
        && binding.etag.ends_with('"')
        && !binding.etag.starts_with("W/")
        && !binding.etag.chars().any(char::is_control)
        && binding.plaintext_len == body_len
        && binding.plaintext_len <= MAX_EDIT_BYTES
        && is_sha256_digest(&binding.plaintext_sha256)
}

fn validate_pending_path(path: &str) -> Result<(), CloudError> {
    if path.len() > 32_768
        || !path.starts_with('/')
        || path == "/"
        || path.ends_with('/')
        || path[1..]
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(invalid("encrypted edit target path is invalid"));
    }
    Ok(())
}

fn copy_exact_bounded<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    mut remaining: u64,
) -> Result<(), CloudError> {
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| invalid("encrypted edit length is invalid"))?;
        let count = loop {
            match input.read(&mut buffer[..take]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => break result.map_err(io_error)?,
            }
        };
        if count == 0 {
            return Err(invalid(
                "encrypted edit source ended before its declared size",
            ));
        }
        output.write_all(&buffer[..count]).map_err(io_error)?;
        remaining -= count as u64;
    }
    Ok(())
}

fn copy_exact_hash<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    mut remaining: u64,
) -> Result<String, CloudError> {
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| invalid("queued subtree body length is invalid"))?;
        let count = loop {
            match input.read(&mut buffer[..take]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => break result.map_err(io_error)?,
            }
        };
        if count == 0 {
            return Err(invalid("queued subtree body is truncated"));
        }
        digest.update(&buffer[..count]);
        output.write_all(&buffer[..count]).map_err(io_error)?;
        remaining -= count as u64;
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn set_private_file(file: &File) -> Result<(), CloudError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(io_error)?;
    }
    #[cfg(not(unix))]
    {
        let _ = file;
    }
    Ok(())
}

fn cache_error(error: CacheError) -> CloudError {
    match error {
        CacheError::NotFound | CacheError::IncompleteListing => {
            CloudError::new(ErrorKind::NotFound, "cached vault data is unavailable")
        }
        CacheError::Corrupt => invalid("cached vault content is corrupt"),
        CacheError::Conflict => conflict("cached vault scope does not match"),
        CacheError::UnsafeDirectory => CloudError::new(
            ErrorKind::Io,
            "private encrypted cache storage is unavailable",
        ),
        CacheError::InsufficientSpace => CloudError::new(
            ErrorKind::Io,
            "not enough disk space for the encrypted cache snapshot",
        ),
        _ => CloudError::new(ErrorKind::Io, "encrypted cache storage is unavailable"),
    }
}

fn vault_error(error: impl std::fmt::Display) -> CloudError {
    CloudError::new(ErrorKind::InvalidResponse, error.to_string())
}

fn io_error(error: impl std::fmt::Display) -> CloudError {
    CloudError::new(ErrorKind::Io, error.to_string())
}

fn invalid(message: &'static str) -> CloudError {
    CloudError::new(ErrorKind::InvalidResponse, message)
}

fn conflict(message: &'static str) -> CloudError {
    CloudError::new(ErrorKind::Conflict, message)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::fs::{self, File};

    #[cfg(unix)]
    use raiun_cache::{Cache, CacheScope, CiphertextWriteState, ScopeProtection};
    use raiun_cache::{CacheError, ContentProtection, Retention};
    #[cfg(unix)]
    use raiun_core::backend::WriteCondition;
    use raiun_vault::session::{VaultSessionCoordinator, VaultSessionScope};
    #[cfg(unix)]
    use tempfile::tempdir;

    #[cfg(unix)]
    use super::{
        VaultCopySourceBinding, VaultListingMetadata, VaultOfflineCache, VaultPendingCreateRequest,
        VaultPendingDeleteRequest, VaultPendingEditRequest, VaultPendingOperationKind,
        VaultPendingParentRef, parse_pending_metadata,
    };
    use super::{file_version, listing_version, revalidate_unlocked_pin_generation};
    #[cfg(unix)]
    use crate::vault::VaultDavEntry;

    const TOKEN: &str = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64");

    fn scope() -> VaultSessionScope {
        VaultSessionScope::new("profile-a", "https://vault.example", "space-a", "root-id").unwrap()
    }

    #[cfg(unix)]
    fn entry(id: &str, path: &str, raw_name: String, directory: bool, size: u64) -> VaultDavEntry {
        VaultDavEntry {
            id: id.to_owned(),
            path: path.to_owned(),
            raw_name,
            directory,
            modified_unix: 1,
            writable: true,
            size,
            strong_etag: Some(format!("\"{id}-e1\"")),
            vault_evidence: Vec::new(),
            href: String::new(),
        }
    }

    fn unlocked(scope: &VaultSessionScope) -> VaultSessionCoordinator {
        let sessions = VaultSessionCoordinator::new();
        let mut password = b"potato".to_vec();
        sessions.unlock(scope, &mut password, TOKEN.trim()).unwrap();
        sessions
    }

    #[test]
    fn failed_post_decrypt_pin_lookup_revokes_the_derived_session() {
        let scope = scope();
        let sessions = unlocked(&scope);
        assert!(sessions.is_unlocked(&scope).unwrap());

        let result =
            revalidate_unlocked_pin_generation(&sessions, &scope, Err(CacheError::PinNotFound), 6);
        assert!(result.is_err());
        assert!(!sessions.is_unlocked(&scope).unwrap());
    }

    #[cfg(unix)]
    fn make_private_cache_root(path: &std::path::Path) {
        fs::create_dir(path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    #[cfg(unix)]
    fn assert_cache_contains_no_plaintext(root: &std::path::Path, needles: &[&[u8]]) {
        let mut pending = vec![root.to_path_buf()];
        while let Some(path) = pending.pop() {
            for item in fs::read_dir(path).unwrap() {
                let path = item.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                let bytes = fs::read(path).unwrap();
                for needle in needles {
                    assert!(!bytes.windows(needle.len()).any(|window| window == *needle));
                }
            }
        }
    }

    // `raiun-cache` intentionally refuses to open on Windows until it has a
    // native ACL verifier. Keep these disk-backed integration tests on the
    // platforms where the private-directory contract is implemented.
    #[cfg(unix)]
    #[test]
    fn legacy_copy_envelope_without_source_binding_remains_review_only() {
        let temp = tempdir().unwrap();
        let cache_root = temp.path().join("cache");
        make_private_cache_root(&cache_root);
        let cache = Cache::open(&cache_root, 8 * 1024 * 1024).unwrap();
        let scope = scope();
        let sessions = unlocked(&scope);
        let adapter =
            VaultOfflineCache::new(cache.clone(), scope.clone(), "/Travel.vault").unwrap();
        let parent_ref = VaultPendingParentRef::Stable {
            resource_id: "parent-id".into(),
        };
        let source = VaultCopySourceBinding {
            account_id: "profile-a".into(),
            server_origin: "https://vault.example".into(),
            space_id: "space-a".into(),
            root_resource_id: "root-id".into(),
            root_path: "/Travel.vault".into(),
            path: "/source.txt".into(),
            resource_id: "source-id".into(),
            etag: "\"source-e1\"".into(),
            plaintext_len: 3,
            plaintext_sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                .into(),
        };
        let encoded_target = sessions.encrypt_path(&scope, "copied.txt").unwrap();
        let mut body = std::io::Cursor::new(b"abc".to_vec());
        let queued = adapter
            .queue_copy_file(
                &sessions,
                &mut body,
                VaultPendingCreateRequest {
                    integrity_token: TOKEN.trim(),
                    encoded_target: &encoded_target,
                    existing_id: None,
                    parent_resource_id: Some("parent-id"),
                    parent_etag: Some("\"parent-e1\""),
                    parent_ref: &parent_ref,
                    body_len: 3,
                    state: CiphertextWriteState::NeverAttempted,
                },
                &source,
            )
            .unwrap();
        let row = cache
            .ciphertext_write_info(&adapter.cache_scope, &queued.id)
            .unwrap();
        let envelope = adapter.open_pending_envelope(&sessions, &row).unwrap();
        let bytes = fs::read(&envelope.path).unwrap();
        let metadata_len = u32::from_be_bytes(bytes[10..14].try_into().unwrap()) as usize;
        let metadata_end = 22 + metadata_len;
        let mut legacy: serde_json::Value =
            serde_json::from_slice(&bytes[22..metadata_end]).unwrap();
        legacy["version"] = serde_json::json!(11);
        legacy.as_object_mut().unwrap().remove("copy_source");
        let parsed = sessions
            .with_unlocked_session(&scope, |session| {
                parse_pending_metadata(
                    &legacy,
                    &scope,
                    "/Travel.vault",
                    session,
                    CiphertextWriteState::Uncertain,
                )
            })
            .unwrap()
            .unwrap();
        assert_eq!(parsed.operation, VaultPendingOperationKind::CopyFile);
        assert!(parsed.copy_source.is_none());
        assert_eq!(parsed.state, CiphertextWriteState::Uncertain);
    }

    #[cfg(unix)]
    #[test]
    fn encrypted_edit_journal_is_scoped_durable_and_lock_gated() {
        use std::io::{Cursor, Read};

        let temp = tempdir().unwrap();
        let cache_root = temp.path().join("cache");
        make_private_cache_root(&cache_root);
        let cache = Cache::open(&cache_root, 32 * 1024 * 1024).unwrap();
        let scope = scope();
        let sessions = unlocked(&scope);
        let offline =
            VaultOfflineCache::new(cache.clone(), scope.clone(), "/Travel.vault").unwrap();
        let target = sessions.encrypt_path(&scope, "notes.txt").unwrap();
        let mut queued_bytes = vec![0x5a; 2 * 1024 * 1024];
        queued_bytes[..b"private queued edit".len()].copy_from_slice(b"private queued edit");
        let queued = offline
            .queue_edit(
                &sessions,
                &mut Cursor::new(queued_bytes.clone()),
                VaultPendingEditRequest {
                    integrity_token: TOKEN.trim(),
                    encoded_target: &target,
                    base_resource_id: "resource-note-1",
                    base_etag: "\"base-v1\"",
                    existing_id: None,
                    body_len: queued_bytes.len() as u64,
                },
            )
            .unwrap();
        assert_eq!(queued.path, "/notes.txt");
        assert_eq!(queued.state, CiphertextWriteState::Pending);
        let listed = offline.pending_edits(&sessions, None, 10).unwrap().0;
        assert_eq!(listed, vec![queued.clone()]);

        let output = temp.path().join("recovered.tmp");
        let recovered = offline
            .download_pending_edit(&sessions, &queued.id, queued.revision, &output)
            .unwrap();
        assert_eq!(recovered, queued);
        let mut contents = Vec::new();
        File::open(&output)
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();
        assert_eq!(contents, queued_bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(
            offline
                .download_pending_edit(&sessions, &queued.id, queued.revision, &output)
                .is_err()
        );
        assert_eq!(fs::read(&output).unwrap(), queued_bytes);
        assert_cache_contains_no_plaintext(
            cache.root(),
            &[
                b"private queued edit",
                b"resource-note-1",
                b"base-v1",
                b"notes.txt",
            ],
        );

        let other = VaultSessionScope::new(
            "another-profile",
            scope.server_origin(),
            scope.space_id(),
            scope.resource_id(),
        )
        .unwrap();
        let other_sessions = unlocked(&other);
        let other_cache = VaultOfflineCache::new(cache, other, "/Travel.vault").unwrap();
        assert!(
            other_cache
                .download_pending_edit(
                    &other_sessions,
                    &queued.id,
                    queued.revision,
                    &temp.path().join("wrong.tmp")
                )
                .is_err()
        );
        sessions.lock(&scope).unwrap();
        assert!(offline.pending_edits(&sessions, None, 10).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn first_use_operation_status_is_an_empty_page_for_an_unregistered_cache_scope() {
        let temp = tempdir().unwrap();
        let cache_root = temp.path().join("cache");
        make_private_cache_root(&cache_root);
        let cache = Cache::open(&cache_root, 32 * 1024 * 1024).unwrap();
        let scope = scope();
        let sessions = unlocked(&scope);
        let offline = VaultOfflineCache::new(cache, scope, "/Travel.vault").unwrap();

        let (items, truncated) = offline.pending_edits(&sessions, None, 25).unwrap();
        assert!(items.is_empty());
        assert!(!truncated);
        let (retryable, retryable_truncated) =
            offline.retryable_pending_edits(&sessions, 25).unwrap();
        assert!(retryable.is_empty());
        assert!(!retryable_truncated);
    }

    #[cfg(unix)]
    #[test]
    fn retryable_edit_page_excludes_conflicts_without_hiding_them_from_status() {
        use std::io::Cursor;

        let temp = tempdir().unwrap();
        let cache_root = temp.path().join("cache");
        make_private_cache_root(&cache_root);
        let cache = Cache::open(&cache_root, 32 * 1024 * 1024).unwrap();
        let scope = scope();
        let sessions = unlocked(&scope);
        let offline = VaultOfflineCache::new(cache, scope.clone(), "/Travel.vault").unwrap();

        let first_target = sessions.encrypt_path(&scope, "conflicted.txt").unwrap();
        let conflicted = offline
            .queue_edit(
                &sessions,
                &mut Cursor::new(b"conflict"),
                VaultPendingEditRequest {
                    integrity_token: TOKEN.trim(),
                    encoded_target: &first_target,
                    base_resource_id: "resource-conflict",
                    base_etag: "\"base-conflict\"",
                    existing_id: None,
                    body_len: 8,
                },
            )
            .unwrap();
        offline
            .set_pending_edit_state(
                &conflicted.id,
                conflicted.revision,
                CiphertextWriteState::Conflict,
            )
            .unwrap();

        let pending_target = sessions.encrypt_path(&scope, "pending.txt").unwrap();
        let pending = offline
            .queue_edit(
                &sessions,
                &mut Cursor::new(b"pending"),
                VaultPendingEditRequest {
                    integrity_token: TOKEN.trim(),
                    encoded_target: &pending_target,
                    base_resource_id: "resource-pending",
                    base_etag: "\"base-pending\"",
                    existing_id: None,
                    body_len: 7,
                },
            )
            .unwrap();

        let (retryable, truncated) = offline.retryable_pending_edits(&sessions, 32).unwrap();
        assert!(!truncated);
        assert_eq!(retryable, vec![pending]);
        let (all, truncated) = offline.pending_edits(&sessions, None, 32).unwrap();
        assert!(!truncated);
        assert!(all.iter().any(|item| item.id == conflicted.id));
    }

    #[cfg(unix)]
    #[test]
    fn retryable_presence_query_is_opaque_and_does_not_open_envelopes() {
        use std::io::Cursor;

        let temp = tempdir().unwrap();
        let cache_root = temp.path().join("cache");
        make_private_cache_root(&cache_root);
        let cache = Cache::open(&cache_root, 32 * 1024 * 1024).unwrap();
        let scope = scope();
        let sessions = unlocked(&scope);
        let offline = VaultOfflineCache::new(cache, scope.clone(), "/Travel.vault").unwrap();

        assert!(!offline.has_retryable_pending_edits().unwrap());
        let target = sessions.encrypt_path(&scope, "private-body.txt").unwrap();
        offline
            .queue_edit(
                &sessions,
                &mut Cursor::new(b"body must not be opened by scheduler precheck"),
                VaultPendingEditRequest {
                    integrity_token: TOKEN.trim(),
                    encoded_target: &target,
                    base_resource_id: "resource-presence-check",
                    base_etag: "\"base-presence-check\"",
                    existing_id: None,
                    body_len: b"body must not be opened by scheduler precheck".len() as u64,
                },
            )
            .unwrap();

        sessions.lock(&scope).unwrap();
        // The opaque index stays queryable while locked, but the normal
        // retry-page path is session-gated and therefore cannot decrypt an
        // envelope or expose its path while locked.
        assert!(offline.has_retryable_pending_edits().unwrap());
        assert!(offline.retryable_pending_edits(&sessions, 32).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn sealed_listing_and_ciphertext_reads_survive_cache_restart() {
        let dir = tempdir().unwrap();
        let scope = scope();
        let sessions = unlocked(&scope);
        let cache_root = dir.path().join("cache");
        make_private_cache_root(&cache_root);
        let cache = Cache::open(&cache_root, 64 * 1024 * 1024).unwrap();
        let adapter =
            VaultOfflineCache::new(cache.clone(), scope.clone(), "/Travel.vault").unwrap();
        let epoch = adapter.ciphertext_epoch().unwrap();
        let encrypted_name = sessions.encrypt_name(&scope, "notes.txt").unwrap();
        let root = entry("root-id", "/Travel.vault", String::new(), true, 0);
        let cipher_path = dir.path().join("cipher.bin");
        let plaintext = b"offline vault plaintext";
        let mut source = std::io::Cursor::new(plaintext);
        let encrypted_plaintext_len = sessions
            .encrypt_file_transactional(
                &scope,
                &mut source,
                &cipher_path,
                plaintext.len() as u64,
                1024,
            )
            .unwrap();
        assert_eq!(encrypted_plaintext_len, plaintext.len() as u64);
        let ciphertext_len = std::fs::metadata(&cipher_path).unwrap().len();
        let child = entry(
            "file-id",
            "/Travel.vault/notes.txt",
            encrypted_name,
            false,
            std::fs::metadata(&cipher_path).unwrap().len(),
        );
        adapter
            .publish_listing(
                &sessions,
                &VaultListingMetadata {
                    integrity_token: TOKEN.trim(),
                    root_etag: Some("\"root-e1\""),
                    space: &raiun_core::backend::CloudSpace {
                        id: "space-a".to_owned(),
                        name: "Personal".to_owned(),
                        dav_url: "https://vault.example/remote.php/dav/files/user/".to_owned(),
                        personal: true,
                        writable: true,
                        encrypted: false,
                    },
                    space_dav_root: "https://vault.example/remote.php/dav/files/user/",
                    encrypted_directory_path: "",
                },
                &root,
                std::slice::from_ref(&child),
                epoch,
            )
            .unwrap();
        adapter
            .publish_verified_ciphertext(
                &child.id,
                child.strong_etag.as_deref().unwrap(),
                &cipher_path,
                ciphertext_len,
                epoch,
            )
            .unwrap();
        assert_cache_contains_no_plaintext(cache.root(), &[b"notes.txt", plaintext]);

        drop(adapter);
        let cache = Cache::open(&cache_root, 64 * 1024 * 1024).unwrap();
        let candidates = VaultOfflineCache::discover_cached_roots(
            &cache,
            "https://vault.example",
            "profile-a",
            None,
            100,
        )
        .unwrap();
        assert_eq!(candidates.roots.len(), 1);
        assert_eq!(candidates.roots[0].space_id, "space-a");
        assert_eq!(candidates.roots[0].root_resource_id, "root-id");
        assert!(candidates.next_after.is_none());
        assert!(!candidates.truncated);
        assert!(
            VaultOfflineCache::discover_cached_roots(
                &cache,
                "https://other.example",
                "profile-a",
                None,
                100,
            )
            .unwrap()
            .roots
            .is_empty()
        );
        let restarted_sessions = VaultSessionCoordinator::new();
        let mut password = b"wrong".to_vec();
        assert!(
            VaultOfflineCache::unlock_cached_root(
                &cache,
                &restarted_sessions,
                &scope,
                &mut password,
            )
            .is_err()
        );
        assert!(password.iter().all(|byte| *byte == 0));
        assert!(!restarted_sessions.is_unlocked(&scope).unwrap());
        let mut password = b"potato".to_vec();
        let (root_snapshot, _) = VaultOfflineCache::unlock_cached_root(
            &cache,
            &restarted_sessions,
            &scope,
            &mut password,
        )
        .unwrap();
        assert!(password.iter().all(|byte| *byte == 0));
        assert_eq!(root_snapshot.directory_resource_id, "root-id");
        assert_eq!(root_snapshot.root_path, "/Travel.vault");
        let adapter =
            VaultOfflineCache::new(cache, scope.clone(), root_snapshot.root_path.clone()).unwrap();
        let listing = adapter.list(&restarted_sessions, "/").unwrap();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].path, "/notes.txt");
        assert_eq!(listing[0].id, "file-id");

        let downloaded = dir.path().join("offline-file");
        let metadata = adapter
            .download(
                &restarted_sessions,
                "/notes.txt",
                Some(&listing[0].etag),
                &downloaded,
            )
            .unwrap();
        assert_eq!(metadata.id, "file-id");
        assert_eq!(fs::read(downloaded).unwrap(), plaintext);
    }

    #[cfg(unix)]
    #[test]
    fn cache_scope_and_lock_fail_closed_and_tamper_is_detected() {
        let dir = tempdir().unwrap();
        let scope = scope();
        let sessions = unlocked(&scope);
        let cache_root = dir.path().join("cache");
        make_private_cache_root(&cache_root);
        let cache = Cache::open(&cache_root, 64 * 1024 * 1024).unwrap();
        let adapter =
            VaultOfflineCache::new(cache.clone(), scope.clone(), "/Travel.vault").unwrap();
        let epoch = adapter.ciphertext_epoch().unwrap();
        let root = entry("root-id", "/Travel.vault", String::new(), true, 0);
        adapter
            .publish_listing(
                &sessions,
                &VaultListingMetadata {
                    integrity_token: TOKEN.trim(),
                    root_etag: None,
                    space: &raiun_core::backend::CloudSpace {
                        id: "space-a".to_owned(),
                        name: "Personal".to_owned(),
                        dav_url: "https://vault.example/remote.php/dav/files/user/".to_owned(),
                        personal: true,
                        writable: true,
                        encrypted: false,
                    },
                    space_dav_root: "https://vault.example/remote.php/dav/files/user/",
                    encrypted_directory_path: "",
                },
                &root,
                &[],
                epoch,
            )
            .unwrap();
        assert_eq!(adapter.list(&sessions, "/").unwrap().len(), 0);

        let other_scope =
            VaultSessionScope::new("profile-b", "https://vault.example", "space-a", "root-id")
                .unwrap();
        let other_adapter =
            VaultOfflineCache::new(cache.clone(), other_scope.clone(), "/Travel.vault").unwrap();
        assert!(other_adapter.list(&sessions, "/").is_err());
        sessions.lock(&scope).unwrap();
        assert!(adapter.list(&sessions, "/").is_err());

        let cache_scope = CacheScope::new(
            "https://vault.example",
            "profile-a",
            "space-a",
            "root-id",
            ScopeProtection::CiphertextOnly,
        )
        .unwrap();
        let record = cache
            .content_record(&cache_scope, &listing_version("root-id", epoch))
            .unwrap();
        let content_dir = cache.root().join("content");
        let mut blobs = fs::read_dir(&content_dir).unwrap();
        let blob = blobs.next().unwrap().unwrap().path();
        assert!(blobs.next().is_none());
        assert!(record.byte_len > 40);
        let mut bytes = fs::read(&blob).unwrap();
        bytes[40] ^= 0x80;
        fs::write(blob, bytes).unwrap();
        assert!(
            cache
                .open_content(&cache_scope, &listing_version("root-id", epoch))
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn delete_journal_retains_sealed_source_and_indexes_only_encrypted_parent() {
        use std::io::Cursor;

        let dir = tempdir().unwrap();
        let root = dir.path().join("cache");
        make_private_cache_root(&root);
        let cache = Cache::open(&root, 32 * 1024 * 1024).unwrap();
        let scope = scope();
        let sessions = unlocked(&scope);
        let offline = VaultOfflineCache::new(cache, scope.clone(), "/Travel.vault").unwrap();
        let encoded = sessions.encrypt_path(&scope, "docs/quarterly.txt").unwrap();
        let plaintext = b"recoverable original file";
        let queued = offline
            .queue_delete(
                &sessions,
                &mut Cursor::new(plaintext),
                VaultPendingDeleteRequest {
                    integrity_token: TOKEN.trim(),
                    encoded_target: &encoded,
                    source_resource_id: "source-id",
                    source_etag: "\"source-e1\"",
                    parent_resource_id: "docs-id",
                    parent_etag: "\"docs-e1\"",
                    source_size: plaintext.len() as u64,
                    source_ciphertext_sha256: &"a".repeat(64),
                    body_len: plaintext.len() as u64,
                },
            )
            .unwrap();

        assert_eq!(queued.operation, VaultPendingOperationKind::DeleteFile);
        assert_eq!(queued.base, WriteCondition::Match("\"source-e1\"".into()));
        assert_eq!(queued.base_resource_id, "source-id");
        assert_eq!(queued.parent_resource_id, "docs-id");
        assert_eq!(queued.source_size, plaintext.len() as u64);
        assert_eq!(queued.source_ciphertext_sha256, "a".repeat(64));
        let reopened = offline
            .pending_operation(&sessions, &queued.id, queued.revision)
            .unwrap();
        assert_eq!(reopened, queued);
        assert_eq!(
            offline
                .pending_delete_for_path(&sessions, "/docs/quarterly.txt")
                .unwrap()
                .unwrap()
                .id,
            queued.id
        );
        let (parent_rows, truncated) = offline
            .pending_deletes_for_parent(&sessions, "/docs", 10)
            .unwrap();
        assert_eq!(parent_rows.len(), 1);
        assert!(!truncated);

        let recovered_path = dir.path().join("recovered-file");
        offline
            .download_pending_edit(&sessions, &queued.id, queued.revision, &recovered_path)
            .unwrap();
        assert_eq!(fs::read(recovered_path).unwrap(), plaintext);
        assert_cache_contains_no_plaintext(&root, &[b"quarterly.txt", plaintext]);
    }

    #[test]
    fn cache_versions_use_ciphertext_protection_only() {
        assert_eq!(
            listing_version("root-id", 0).protection,
            ContentProtection::Ciphertext
        );
        assert_eq!(
            file_version("file-id", "e1", 0).protection,
            ContentProtection::Ciphertext
        );
        let _ = Retention::Recent;
    }
}

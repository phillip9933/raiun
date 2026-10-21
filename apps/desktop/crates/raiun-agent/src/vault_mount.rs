//! Provider for a verified encrypted folder or Space mounted by FUSE.
//!
//! Plaintext downloads are staged in a private temporary directory and never
//! pass through the engine cache or transfer history. On Unix, the plaintext
//! file and its directory are removed before the open file descriptor is
//! returned to FUSE. A process crash during a download can leave named
//! plaintext staging data behind; this does not provide disk encryption or
//! secure erasure. Each new list/stat/open checks current server root metadata
//! and the integrity token. Reads from an already-open file use its immutable
//! verified plaintext snapshot and check only that the local session remains
//! unlocked; a remote permission change is observed on the next metadata or
//! open request. Local route revocation is required to block later reads.

#[cfg(unix)]
use std::fs;
#[cfg(not(unix))]
use std::io::{Read, Seek, SeekFrom};
use std::{fs::File, path::Path, sync::Arc};

use raiun_cache::Cache;
use raiun_core::backend::{CloudBackend, CloudError, ErrorKind, RemoteEntry};
use raiun_fuse::vault_routes::{
    VaultCancelledCreateReceipt, VaultDeleteOutcome, VaultDirectoryCreateOutcome,
    VaultExistingFileOverwriteBackend, VaultPendingCreateRenameOutcome,
    VaultPendingCreateResolution as FusePendingCreateResolution,
    VaultPendingDirectoryRenameOutcome, VaultPendingDirectoryRetargetResolution,
    VaultPendingDirectoryRetargetState, VaultPendingDirectorySubtreeRenameOutcome,
    VaultPendingDirectorySubtreeRenameRow, VaultPendingSubtreeOperation, VaultReadBackend,
    VaultReadOverwriteBackend, VaultReadStream, VaultReadWriteBackend, VaultRenameOutcome,
    VaultUploadOutcome, VaultWriteBackend, VaultWriteSource,
};
use raiun_fuse::vault_write::{
    VaultParentRef, VaultWriteScope, VaultWriteTarget, VerifiedCreateContent,
};
use raiun_opencloud::{
    OpenCloudClient,
    vault::VaultMetadataClient,
    vault_backend::VaultBackend,
    vault_cache::{VaultOfflineCache, VaultPendingParentRef},
};
use raiun_vault::{
    sealed_cache::SealedVaultSnapshot,
    session::{VaultSessionCoordinator, VaultSessionScope},
};
use tempfile::TempDir;

/// Construct a read-only provider for the exact inspected folder or Space root.
///
/// `expected_root_resource_id` must come from the caller's current inspection
/// result. The factory independently inspects the root, verifies that stable
/// identity and marker evidence, then lets `VaultBackend` verify the currently
/// unlocked session and integrity token. The server origin is supplied by the
/// authenticated account context; it is checked against the client by the
/// backend constructor.
pub(crate) fn new_read_backend(
    client: OpenCloudClient,
    sessions: Arc<VaultSessionCoordinator>,
    account_id: &str,
    server_origin: &str,
    space_id: &str,
    root_path: &str,
    expected_root_resource_id: &str,
) -> Result<Arc<dyn VaultReadBackend>, CloudError> {
    validate_root_identity(&client, space_id, root_path, expected_root_resource_id)?;

    let scope = VaultSessionScope::new(
        account_id,
        server_origin,
        space_id,
        expected_root_resource_id,
    )
    .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "vault scope is invalid"))?;
    let backend = VaultBackend::new(
        client,
        Arc::clone(&sessions),
        scope.clone(),
        root_path.to_owned(),
    )?;
    Ok(Arc::new(ReadOnlyVaultBackend {
        backend,
        space_id: space_id.to_owned(),
        sessions,
        scope,
        writable: false,
        existing_file_overwrite: false,
        file_create: false,
        directory_create: false,
    }))
}

/// Construct a separately opt-in read/write provider for the exact inspected
/// root. Callers must install this single combined object atomically; the
/// existing `new_read_backend` remains the default and stays read-only.
pub(crate) fn new_writable_backend(
    client: OpenCloudClient,
    sessions: Arc<VaultSessionCoordinator>,
    account_id: &str,
    server_origin: &str,
    space_id: &str,
    root_path: &str,
    expected_root_resource_id: &str,
) -> Result<Arc<dyn VaultReadWriteBackend>, CloudError> {
    validate_root_identity(&client, space_id, root_path, expected_root_resource_id)?;
    let scope = VaultSessionScope::new(
        account_id,
        server_origin,
        space_id,
        expected_root_resource_id,
    )
    .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "vault scope is invalid"))?;
    let backend = VaultBackend::new(
        client,
        Arc::clone(&sessions),
        scope.clone(),
        root_path.into(),
    )?;
    Ok(Arc::new(ReadOnlyVaultBackend {
        backend,
        space_id: space_id.to_owned(),
        sessions,
        scope,
        writable: true,
        existing_file_overwrite: false,
        // This constructor has no encrypted journal; keep create disabled.
        file_create: false,
        directory_create: false,
    }))
}

pub(crate) fn new_cached_read_backend(
    client: OpenCloudClient,
    sessions: Arc<VaultSessionCoordinator>,
    cache: Cache,
    scope: VaultSessionScope,
    root_path: &str,
) -> Result<Arc<dyn VaultReadBackend>, CloudError> {
    validate_root_identity(&client, scope.space_id(), root_path, scope.resource_id())?;
    if client.server_origin().as_deref() != Some(scope.server_origin()) {
        return Err(CloudError::new(
            ErrorKind::InvalidResponse,
            "vault scope does not match the configured server",
        ));
    }
    let offline_cache = VaultOfflineCache::new(cache, scope.clone(), root_path)?;
    let backend = VaultBackend::new_with_offline_cache(
        client,
        Arc::clone(&sessions),
        scope.clone(),
        root_path.to_owned(),
        offline_cache,
    )?;
    Ok(Arc::new(ReadOnlyVaultBackend {
        backend,
        space_id: scope.space_id().to_owned(),
        sessions,
        scope,
        writable: false,
        existing_file_overwrite: false,
        file_create: false,
        directory_create: false,
    }))
}

pub(crate) fn new_cached_writable_backend(
    client: OpenCloudClient,
    sessions: Arc<VaultSessionCoordinator>,
    cache: Cache,
    scope: VaultSessionScope,
    root_path: &str,
) -> Result<Arc<dyn VaultReadWriteBackend>, CloudError> {
    validate_root_identity(&client, scope.space_id(), root_path, scope.resource_id())?;
    if client.server_origin().as_deref() != Some(scope.server_origin()) {
        return Err(CloudError::new(
            ErrorKind::InvalidResponse,
            "vault scope does not match the configured server",
        ));
    }
    let offline_cache = VaultOfflineCache::new(cache, scope.clone(), root_path)?;
    let backend = VaultBackend::new_with_offline_cache(
        client,
        Arc::clone(&sessions),
        scope.clone(),
        root_path.to_owned(),
        offline_cache,
    )?;
    Ok(Arc::new(ReadOnlyVaultBackend {
        backend,
        space_id: scope.space_id().to_owned(),
        sessions,
        scope,
        writable: true,
        existing_file_overwrite: false,
        file_create: true,
        directory_create: false,
    }))
}

#[cfg(test)]
pub(crate) fn new_offline_read_backend(
    client: OpenCloudClient,
    sessions: Arc<VaultSessionCoordinator>,
    cache: Cache,
    scope: VaultSessionScope,
    root_path: &str,
    snapshot: SealedVaultSnapshot,
) -> Result<Arc<dyn VaultReadBackend>, CloudError> {
    if client.server_origin().as_deref() != Some(scope.server_origin()) {
        return Err(CloudError::new(
            ErrorKind::InvalidResponse,
            "vault scope does not match the configured server",
        ));
    }
    let offline_cache = VaultOfflineCache::new(cache, scope.clone(), root_path)?;
    let backend = VaultBackend::new_from_cached_root(
        client,
        Arc::clone(&sessions),
        scope.clone(),
        root_path.to_owned(),
        offline_cache,
        snapshot,
    )?;
    Ok(Arc::new(ReadOnlyVaultBackend {
        backend,
        space_id: scope.space_id().to_owned(),
        sessions,
        scope,
        writable: false,
        existing_file_overwrite: false,
        file_create: false,
        directory_create: false,
    }))
}

/// Offline capability for editing cached files and queuing regular-file or
/// directory creation beneath verified cached parents. Pending directories
/// remain local journal identities until their exact create is reconciled.
#[cfg(test)]
pub(crate) fn new_offline_overwrite_backend(
    client: OpenCloudClient,
    sessions: Arc<VaultSessionCoordinator>,
    cache: Cache,
    scope: VaultSessionScope,
    root_path: &str,
    pin_id: Option<&str>,
    snapshot: SealedVaultSnapshot,
) -> Result<Arc<dyn VaultReadOverwriteBackend>, CloudError> {
    new_offline_overwrite_backend_inner(
        client,
        sessions,
        cache,
        scope,
        root_path,
        OfflineBackendCacheSelection {
            pin_id,
            expected_generation: None,
        },
        snapshot,
    )
}

pub(crate) fn new_offline_overwrite_backend_expected(
    client: OpenCloudClient,
    sessions: Arc<VaultSessionCoordinator>,
    cache: Cache,
    scope: VaultSessionScope,
    root_path: &str,
    pin: Option<(&str, u64)>,
    snapshot: SealedVaultSnapshot,
) -> Result<Arc<dyn VaultReadOverwriteBackend>, CloudError> {
    new_offline_overwrite_backend_inner(
        client,
        sessions,
        cache,
        scope,
        root_path,
        OfflineBackendCacheSelection {
            pin_id: pin.map(|(id, _)| id),
            expected_generation: pin.map(|(_, generation)| generation),
        },
        snapshot,
    )
}

struct OfflineBackendCacheSelection<'a> {
    pin_id: Option<&'a str>,
    expected_generation: Option<u64>,
}

fn new_offline_overwrite_backend_inner(
    client: OpenCloudClient,
    sessions: Arc<VaultSessionCoordinator>,
    cache: Cache,
    scope: VaultSessionScope,
    root_path: &str,
    selection: OfflineBackendCacheSelection<'_>,
    snapshot: SealedVaultSnapshot,
) -> Result<Arc<dyn VaultReadOverwriteBackend>, CloudError> {
    if client.server_origin().as_deref() != Some(scope.server_origin()) {
        return Err(CloudError::new(
            ErrorKind::InvalidResponse,
            "vault scope does not match the configured server",
        ));
    }
    let offline_cache = match selection.pin_id {
        Some(pin_id) => match selection.expected_generation {
            Some(generation) => VaultOfflineCache::new_for_pin_generation(
                cache,
                scope.clone(),
                root_path,
                pin_id,
                generation,
            )?,
            None => VaultOfflineCache::new_for_pin(cache, scope.clone(), root_path, pin_id)?,
        },
        None => VaultOfflineCache::new(cache, scope.clone(), root_path)?,
    };
    let backend = VaultBackend::new_from_cached_root(
        client,
        Arc::clone(&sessions),
        scope.clone(),
        root_path.to_owned(),
        offline_cache,
        snapshot,
    )?;
    Ok(Arc::new(ReadOnlyVaultBackend {
        backend,
        space_id: scope.space_id().to_owned(),
        sessions,
        scope,
        writable: true,
        existing_file_overwrite: true,
        file_create: true,
        directory_create: true,
    }))
}

pub(crate) fn validate_root_identity(
    client: &OpenCloudClient,
    space_id: &str,
    root_path: &str,
    expected_root_resource_id: &str,
) -> Result<(), CloudError> {
    let listing = VaultMetadataClient::new(client).inspect_vault(space_id, root_path)?;
    validate_listing_identity(&listing, expected_root_resource_id)
}

fn validate_listing_identity(
    listing: &raiun_opencloud::vault::VaultRootListing,
    expected_root_resource_id: &str,
) -> Result<(), CloudError> {
    if listing.root.id != expected_root_resource_id
        || !listing.root.directory
        || listing.evidence.is_empty()
        || listing.integrity_token.is_none()
    {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "vault root identity or initialization changed",
        ));
    }
    Ok(())
}

struct ReadOnlyVaultBackend {
    backend: VaultBackend,
    space_id: String,
    sessions: Arc<VaultSessionCoordinator>,
    scope: VaultSessionScope,
    writable: bool,
    existing_file_overwrite: bool,
    file_create: bool,
    directory_create: bool,
}

impl VaultExistingFileOverwriteBackend for ReadOnlyVaultBackend {
    fn supports_pending_parent_operations(&self) -> bool {
        self.file_create && self.directory_create
    }

    fn prepare_existing_target(
        &self,
        path: &str,
        base_resource_id: &str,
        base_etag: &str,
    ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
        if !self.existing_file_overwrite || base_etag.is_empty() {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "offline route does not allow this file overwrite",
            ));
        }
        self.authorize()?;
        let current = self.backend.stat(&self.space_id, path)?;
        if current.directory
            || current.id != base_resource_id
            || current.etag != base_etag
            || !current.writable
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "cached encrypted file identity, permission, or version changed",
            ));
        }
        let condition = raiun_core::backend::WriteCondition::Match(base_etag.to_owned());
        let encoded_target = self.backend.prepare_write_target(path, &condition)?;
        let scope = VaultWriteScope::new(
            self.scope.account_id(),
            self.scope.server_origin(),
            self.scope.space_id(),
            self.scope.resource_id(),
        )
        .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "vault write scope is invalid"))?;
        let target = VaultWriteTarget::new(encoded_target, condition)
            .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "vault target is invalid"))?;
        Ok((scope, target))
    }

    fn overwrite(
        &self,
        target: &VaultWriteTarget,
        source: &mut dyn VaultWriteSource,
        plaintext_len: u64,
    ) -> Result<VaultUploadOutcome, CloudError> {
        if !self.existing_file_overwrite
            || !matches!(
                target.condition(),
                raiun_core::backend::WriteCondition::Match(_)
            )
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "offline route only permits overwriting an existing file",
            ));
        }
        self.authorize()?;
        let mut source = source;
        map_upload_outcome(self.backend.upload_prepared_reader_with_queue(
            target.opaque_relative_target(),
            &mut source,
            plaintext_len,
            target.condition().clone(),
            None,
        )?)
    }

    fn supports_file_create(&self) -> bool {
        self.existing_file_overwrite
    }

    fn prepare_file_create(
        &self,
        path: &str,
        existing: Option<(&str, u64)>,
    ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
        if !self.existing_file_overwrite {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "offline route does not permit file creation",
            ));
        }
        self.authorize()?;
        let target = self.backend.prepare_file_create_target(path, existing)?;
        write_scope_target(&self.scope, target)
    }

    fn prepare_file_create_under_parent(
        &self,
        path: &str,
        parent_ref: &VaultParentRef,
        existing: Option<(&str, u64)>,
    ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
        if !self.file_create {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route does not permit file creation",
            ));
        }
        self.authorize()?;
        let backend_ref = to_backend_parent_ref(parent_ref);
        let target =
            self.backend
                .prepare_file_create_target_for_parent(path, &backend_ref, existing)?;
        write_scope_parent_target(&self.scope, target, parent_ref.clone())
    }

    fn create_file(
        &self,
        target: &VaultWriteTarget,
        source: &mut dyn VaultWriteSource,
        plaintext_len: u64,
        existing: Option<(&str, u64)>,
    ) -> Result<VaultUploadOutcome, CloudError> {
        if !self.existing_file_overwrite
            || !matches!(
                target.condition(),
                raiun_core::backend::WriteCondition::Absent
            )
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "offline route does not permit this file create",
            ));
        }
        self.authorize()?;
        let parent_ref = target.parent_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Conflict,
                "encrypted create has no parent reference",
            )
        })?;
        let parent_ref = to_backend_parent_ref(parent_ref);
        let mut source = source;
        map_upload_outcome(self.backend.create_prepared_reader_with_queue_for_parent(
            target.opaque_relative_target(),
            &mut source,
            plaintext_len,
            existing,
            &parent_ref,
        )?)
    }

    fn begin_file_create(
        &self,
        target: &VaultWriteTarget,
    ) -> Result<VaultUploadOutcome, CloudError> {
        if !self.existing_file_overwrite
            || !matches!(
                target.condition(),
                raiun_core::backend::WriteCondition::Absent
            )
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "offline route does not permit this file create",
            ));
        }
        self.authorize()?;
        let parent_ref = target.parent_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Conflict,
                "encrypted create has no parent reference",
            )
        })?;
        let parent_ref = to_backend_parent_ref(parent_ref);
        map_upload_outcome(
            self.backend
                .begin_prepared_create_for_parent(target.opaque_relative_target(), &parent_ref)?,
        )
    }

    fn supports_file_rename(&self) -> bool {
        self.existing_file_overwrite
    }

    fn rename_file(
        &self,
        from: &str,
        to: &str,
        expected_source_id: &str,
        expected_source_etag: &str,
    ) -> Result<VaultRenameOutcome, CloudError> {
        if !self.existing_file_overwrite {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route does not permit file rename",
            ));
        }
        self.authorize()?;
        match self.backend.rename_file_with_queue(
            from,
            to,
            expected_source_id,
            expected_source_etag,
        )? {
            raiun_opencloud::vault_backend::VaultRenameOutcome::Committed(entry) => Ok(
                VaultRenameOutcome::Committed(self.apply_write_permission(entry)),
            ),
            raiun_opencloud::vault_backend::VaultRenameOutcome::Queued {
                entry,
                write_id,
                revision,
                uncertain,
            } => Ok(VaultRenameOutcome::Queued {
                entry: self.apply_write_permission(entry),
                write_id,
                revision,
                uncertain,
            }),
        }
    }

    fn supports_pending_create_rename(&self) -> bool {
        self.existing_file_overwrite && self.file_create
    }

    fn rename_pending_create(
        &self,
        from: &str,
        to: &str,
        expected_source_id: &str,
        expected_source_etag: &str,
        destination_parent: &VaultParentRef,
    ) -> Result<VaultPendingCreateRenameOutcome, CloudError> {
        if !self.supports_pending_create_rename() {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route does not permit pending file rename",
            ));
        }
        self.authorize()?;
        let backend_parent = to_backend_parent_ref(destination_parent);
        let metadata = self.backend.rename_pending_create_with_queue(
            from,
            to,
            expected_source_id,
            expected_source_etag,
            &backend_parent,
        )?;
        let write_id = expected_source_id
            .strip_prefix("raiun-pending-create:")
            .ok_or_else(|| CloudError::new(ErrorKind::Conflict, "pending create ID changed"))?;
        let expected_revision = expected_source_etag
            .strip_prefix("raiun-pending-v1:")
            .and_then(|value| value.strip_prefix(&format!("{write_id}:")))
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| {
                CloudError::new(ErrorKind::Conflict, "pending create version changed")
            })?;
        if metadata.id != write_id
            || metadata.revision <= expected_revision
            || metadata.path != to
            || metadata.operation
                != raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateFile
            || metadata.base != raiun_core::backend::WriteCondition::Absent
            || metadata.state != raiun_cache::CiphertextWriteState::NeverAttempted
            || metadata.parent_ref.as_ref() != Some(&backend_parent)
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "retargeted encrypted create did not match the verified operation",
            ));
        }
        let parent_ref = from_backend_parent_ref(backend_parent)?;
        let (scope, target) =
            write_scope_parent_target(&self.scope, metadata.encoded_target, parent_ref)?;
        let entry = self.apply_write_permission(RemoteEntry {
            id: format!("raiun-pending-create:{write_id}"),
            path: metadata.path,
            directory: false,
            size: metadata.plaintext_len,
            etag: format!("raiun-pending-v1:{write_id}:{}", metadata.revision),
            modified_unix: 0,
            encrypted: false,
            writable: true,
        });
        Ok(VaultPendingCreateRenameOutcome {
            entry,
            write_id: write_id.to_owned(),
            previous_revision: expected_revision,
            revision: metadata.revision,
            scope,
            target,
        })
    }

    fn supports_file_delete(&self) -> bool {
        self.existing_file_overwrite
    }

    fn delete_file(
        &self,
        path: &str,
        expected_source_id: &str,
        expected_source_etag: &str,
    ) -> Result<VaultDeleteOutcome, CloudError> {
        if !self.existing_file_overwrite {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route does not permit file deletion",
            ));
        }
        self.authorize()?;
        match self
            .backend
            .delete_file_with_queue(path, expected_source_id, expected_source_etag)?
        {
            raiun_opencloud::vault_backend::VaultDeleteOutcome::Committed => {
                Ok(VaultDeleteOutcome::Committed)
            }
            raiun_opencloud::vault_backend::VaultDeleteOutcome::Queued {
                write_id,
                revision,
                uncertain,
            } => Ok(VaultDeleteOutcome::Queued {
                write_id,
                revision,
                uncertain,
            }),
        }
    }

    fn supports_directory_create(&self) -> bool {
        self.directory_create
    }

    fn supports_cancel_directory_create(&self) -> bool {
        self.directory_create
    }

    fn cancel_never_attempted_directory_create(
        &self,
        path: &str,
        write_id: &str,
        revision: u64,
        expected_entry_id: &str,
        expected_entry_etag: &str,
    ) -> Result<(), CloudError> {
        if !self.directory_create {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route does not permit directory cancellation",
            ));
        }
        self.authorize()?;
        self.backend.cancel_never_attempted_directory_create(
            path,
            write_id,
            revision,
            expected_entry_id,
            expected_entry_etag,
        )
    }

    fn supports_pending_directory_rename(&self) -> bool {
        self.directory_create
    }

    fn rename_pending_directory_create(
        &self,
        from: &str,
        to: &str,
        expected_entry_id: &str,
        expected_entry_etag: &str,
        destination_parent: &VaultParentRef,
    ) -> Result<VaultPendingDirectoryRenameOutcome, CloudError> {
        self.retarget_never_attempted_directory(
            from,
            to,
            expected_entry_id,
            expected_entry_etag,
            destination_parent,
        )
    }

    fn supports_pending_directory_subtree_rename(&self) -> bool {
        self.writable && self.directory_create && self.file_create
    }

    fn rename_pending_directory_subtree(
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
        if !self.writable || !self.directory_create || !self.file_create {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route does not permit queued-directory subtree rename",
            ));
        }
        self.retarget_never_attempted_directory_subtree(
            from,
            to,
            expected_entry_id,
            expected_entry_etag,
            destination_parent,
            before_publish,
        )
    }

    fn resolve_pending_directory_subtree_retarget(
        &self,
        wal: &raiun_fuse::vault_write::PendingVaultDirectoryRetarget,
    ) -> Result<VaultPendingDirectoryRetargetResolution, CloudError> {
        self.resolve_never_attempted_directory_subtree(wal)
    }

    fn supports_cancel_file_create(&self) -> bool {
        self.existing_file_overwrite
    }

    fn cancel_never_attempted_file_create(
        &self,
        path: &str,
        write_id: &str,
        revision: u64,
        expected_entry_id: &str,
        expected_entry_etag: &str,
    ) -> Result<VaultCancelledCreateReceipt, CloudError> {
        if !self.existing_file_overwrite {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route does not permit queued-file cancellation",
            ));
        }
        self.authorize()?;
        let receipt = self.backend.cancel_never_attempted_file_create(
            path,
            write_id,
            revision,
            expected_entry_id,
            expected_entry_etag,
        )?;
        map_cancelled_create_receipt(&self.scope, receipt)
    }

    fn resolve_cancelled_file_create(
        &self,
        write_id: &str,
        revision: u64,
    ) -> Result<Option<VaultCancelledCreateReceipt>, CloudError> {
        self.authorize()?;
        self.backend
            .resolve_cancelled_file_create_by_id(write_id, revision)?
            .map(|receipt| map_cancelled_create_receipt(&self.scope, receipt))
            .transpose()
    }

    fn acknowledge_cancelled_file_create(
        &self,
        write_id: &str,
        revision: u64,
        target: &VaultWriteTarget,
        content: &VerifiedCreateContent,
    ) -> Result<(), CloudError> {
        self.authorize()?;
        self.backend.acknowledge_cancelled_file_create(
            write_id,
            revision,
            target.opaque_relative_target(),
            content.bytes,
            &content.sha256,
        )
    }

    fn finalize_cancelled_file_create_ack(
        &self,
        receipt: &VaultCancelledCreateReceipt,
    ) -> Result<(), CloudError> {
        self.authorize()?;
        self.backend.finalize_cancelled_file_create_ack(
            &receipt.write_id,
            receipt.original_revision,
            receipt.current_revision,
            receipt.target.opaque_relative_target(),
            receipt.content.bytes,
            &receipt.content.sha256,
        )
    }

    fn create_directory(&self, path: &str) -> Result<VaultDirectoryCreateOutcome, CloudError> {
        if !self.directory_create {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "offline route does not allow directory creation",
            ));
        }
        self.authorize()?;
        match self.backend.create_directory_with_queue(path)? {
            raiun_opencloud::vault_backend::VaultDirectoryCreateOutcome::Committed(entry) => Ok(
                VaultDirectoryCreateOutcome::Committed(self.apply_write_permission(entry)),
            ),
            raiun_opencloud::vault_backend::VaultDirectoryCreateOutcome::Queued {
                entry,
                write_id,
                revision,
                uncertain,
            } => Ok(VaultDirectoryCreateOutcome::Queued {
                entry: self.apply_write_permission(entry),
                write_id,
                revision,
                uncertain,
            }),
        }
    }

    fn create_directory_under_parent(
        &self,
        path: &str,
        parent_ref: &VaultParentRef,
    ) -> Result<VaultDirectoryCreateOutcome, CloudError> {
        if !self.directory_create {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route does not permit directory creation",
            ));
        }
        self.authorize()?;
        let backend_ref = to_backend_parent_ref(parent_ref);
        map_directory_create_outcome(
            self.backend
                .create_directory_with_parent_queue(path, &backend_ref)?,
            self.writable,
        )
    }
}

impl ReadOnlyVaultBackend {
    fn apply_write_permission(&self, mut entry: RemoteEntry) -> RemoteEntry {
        entry.writable &= self.writable;
        entry
    }

    fn retarget_never_attempted_directory(
        &self,
        from: &str,
        to: &str,
        expected_entry_id: &str,
        expected_entry_etag: &str,
        destination_parent: &VaultParentRef,
    ) -> Result<VaultPendingDirectoryRenameOutcome, CloudError> {
        if !self.directory_create {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route does not permit queued-directory rename",
            ));
        }
        self.authorize()?;
        let write_id = expected_entry_id
            .strip_prefix("raiun-pending-directory:")
            .filter(|id| id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| CloudError::new(ErrorKind::Conflict, "pending directory ID changed"))?;
        let previous_revision = expected_entry_etag
            .strip_prefix("raiun-pending-v1:")
            .and_then(|value| value.strip_prefix(&format!("{write_id}:")))
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|revision| *revision > 0)
            .ok_or_else(|| {
                CloudError::new(ErrorKind::Conflict, "pending directory version changed")
            })?;
        let backend_parent = to_backend_parent_ref(destination_parent);
        let metadata = self
            .backend
            .rename_never_attempted_directory_create_with_queue(
                from,
                to,
                expected_entry_id,
                expected_entry_etag,
                &backend_parent,
            )?;
        if metadata.id != write_id
            || metadata.revision <= previous_revision
            || metadata.path != to
            || metadata.operation
                != raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateDirectory
            || metadata.base != raiun_core::backend::WriteCondition::Absent
            || metadata.state != raiun_cache::CiphertextWriteState::NeverAttempted
            || metadata.parent_ref.as_ref() != Some(&backend_parent)
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "retargeted directory does not match the verified operation",
            ));
        }
        let parent_ref = from_backend_parent_ref(backend_parent)?;
        let entry = RemoteEntry {
            id: format!("raiun-pending-directory:{write_id}"),
            path: metadata.path,
            directory: true,
            size: 0,
            etag: format!("raiun-pending-v1:{write_id}:{}", metadata.revision),
            modified_unix: 0,
            encrypted: false,
            writable: false,
        };
        Ok(VaultPendingDirectoryRenameOutcome {
            entry,
            write_id: write_id.to_owned(),
            previous_revision,
            revision: metadata.revision,
            parent_ref,
        })
    }

    fn retarget_never_attempted_directory_subtree(
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
        if !self.directory_create || !self.file_create {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route does not permit queued-directory subtree rename",
            ));
        }
        self.authorize()?;
        let backend_parent = to_backend_parent_ref(destination_parent);
        let write_scope = VaultWriteScope::new(
            self.scope.account_id(),
            self.scope.server_origin(),
            self.scope.space_id(),
            self.scope.resource_id(),
        )
        .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "vault scope is invalid"))?;
        let mut publish =
            |candidate: &raiun_opencloud::vault_cache::VaultPendingDirectorySubtreeRetarget| {
                let mapped = map_pending_directory_subtree_retarget(
                    candidate,
                    expected_entry_id,
                    expected_entry_etag,
                    to,
                    write_scope.clone(),
                )?;
                before_publish(&mapped)
            };
        let result = self
            .backend
            .retarget_never_attempted_directory_subtree_before_publish(
                from,
                to,
                expected_entry_id,
                expected_entry_etag,
                &backend_parent,
                &mut publish,
            )?;
        map_pending_directory_subtree_retarget(
            &result,
            expected_entry_id,
            expected_entry_etag,
            to,
            VaultWriteScope::new(
                self.scope.account_id(),
                self.scope.server_origin(),
                self.scope.space_id(),
                self.scope.resource_id(),
            )
            .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "vault scope is invalid"))?,
        )
    }

    fn resolve_never_attempted_directory_subtree(
        &self,
        wal: &raiun_fuse::vault_write::PendingVaultDirectoryRetarget,
    ) -> Result<VaultPendingDirectoryRetargetResolution, CloudError> {
        if !self.directory_create || !self.file_create {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route does not permit queued-directory subtree recovery",
            ));
        }
        self.authorize()?;
        let expected = wal
            .rows
            .iter()
            .map(|row| {
                raiun_opencloud::vault_backend::VaultPendingDirectorySubtreeRetargetExpectedRevision {
                    write_id: row.write_id.clone(),
                    previous_revision: row.previous_revision,
                    revision: row.revision,
                }
            })
            .collect::<Vec<_>>();
        let resolved = self
            .backend
            .resolve_never_attempted_directory_subtree_retarget_by_ids(
                &wal.root_write_id,
                wal.root_previous_revision,
                &expected,
            )?;
        let expected_scope = VaultWriteScope::new(
            self.scope.account_id(),
            self.scope.server_origin(),
            self.scope.space_id(),
            self.scope.resource_id(),
        )
        .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "vault scope is invalid"))?;
        if resolved.scope != self.scope
            || wal.scope != expected_scope
            || resolved.root_write_id != wal.root_write_id
            || resolved.root_previous_revision != wal.root_previous_revision
            || resolved.rows.len() != wal.rows.len()
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "queued subtree recovery identity changed",
            ));
        }
        let state = match resolved.state {
            raiun_opencloud::vault_backend::VaultPendingDirectorySubtreeRetargetResolutionState::AllOld => {
                VaultPendingDirectoryRetargetState::AllOld
            }
            raiun_opencloud::vault_backend::VaultPendingDirectorySubtreeRetargetResolutionState::AllNew => {
                VaultPendingDirectoryRetargetState::AllNew
            }
        };
        let mut rows = Vec::with_capacity(wal.rows.len());
        for current in &resolved.rows {
            let row = wal
                .rows
                .iter()
                .find(|row| row.write_id == current.write_id)
                .ok_or_else(|| {
                    CloudError::new(ErrorKind::Conflict, "queued subtree row was not expected")
                })?;
            let expected_revision = match state {
                VaultPendingDirectoryRetargetState::AllOld => row.previous_revision,
                VaultPendingDirectoryRetargetState::AllNew => row.revision,
            };
            let expected_path = match state {
                VaultPendingDirectoryRetargetState::AllOld => &row.old_path,
                VaultPendingDirectoryRetargetState::AllNew => &row.path,
            };
            let expected_operation = match row.operation {
                raiun_fuse::vault_write::PendingVaultRetargetOperation::CreateFile => {
                    raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateFile
                }
                raiun_fuse::vault_write::PendingVaultRetargetOperation::CreateDirectory => {
                    raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateDirectory
                }
            };
            let expected_digest = if current.operation
                == raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateDirectory
            {
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            } else {
                row.sha256.as_str()
            };
            if current.revision != expected_revision
                || current.path != *expected_path
                || current.operation != expected_operation
                || current.state != raiun_cache::CiphertextWriteState::NeverAttempted
                || current.plaintext_len != row.bytes
                || current.plaintext_sha256 != expected_digest
            {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "queued subtree recovery row changed",
                ));
            }
            let current_parent = from_backend_parent_ref(current.parent_ref.clone())?;
            let current_target = VaultWriteTarget::new_with_parent(
                current.encoded_target.clone(),
                raiun_core::backend::WriteCondition::Absent,
                current_parent.clone(),
            )
            .map_err(|_| {
                CloudError::new(
                    ErrorKind::InvalidResponse,
                    "queued subtree target is invalid",
                )
            })?;
            match state {
                VaultPendingDirectoryRetargetState::AllOld => {
                    if let Some(old_target) = &row.old_target
                        && current_target != *old_target
                    {
                        return Err(CloudError::new(
                            ErrorKind::Conflict,
                            "queued subtree old binding changed",
                        ));
                    }
                }
                VaultPendingDirectoryRetargetState::AllNew => {
                    if current_target != row.target {
                        return Err(CloudError::new(
                            ErrorKind::Conflict,
                            "queued subtree new binding changed",
                        ));
                    }
                }
            }
            let operation = match current.operation {
                raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateFile => {
                    VaultPendingSubtreeOperation::CreateFile
                }
                raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateDirectory => {
                    VaultPendingSubtreeOperation::CreateDirectory
                }
                _ => {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "queued subtree recovery contains an unsupported operation",
                    ));
                }
            };
            rows.push(VaultPendingDirectorySubtreeRenameRow {
                write_id: current.write_id.clone(),
                previous_revision: row.previous_revision,
                revision: row.revision,
                operation,
                old_path: row.old_path.clone(),
                path: current.path.clone(),
                old_target: row.old_target.clone(),
                target: current_target,
                plaintext_len: current.plaintext_len,
                plaintext_sha256: if current.operation
                    == raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateDirectory
                {
                    String::new()
                } else {
                    current.plaintext_sha256.clone()
                },
                parent_ref: current_parent,
            });
        }
        let root = rows
            .iter()
            .find(|row| row.write_id == wal.root_write_id)
            .ok_or_else(|| {
                CloudError::new(ErrorKind::Conflict, "queued subtree root is missing")
            })?;
        if root.revision != wal.root_revision
            || root.previous_revision != wal.root_previous_revision
            || root.operation != VaultPendingSubtreeOperation::CreateDirectory
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "queued subtree root changed",
            ));
        }
        let current_root_revision = match state {
            VaultPendingDirectoryRetargetState::AllOld => wal.root_previous_revision,
            VaultPendingDirectoryRetargetState::AllNew => wal.root_revision,
        };
        Ok(VaultPendingDirectoryRetargetResolution {
            scope: expected_scope,
            state,
            root_write_id: wal.root_write_id.clone(),
            root_previous_revision: wal.root_previous_revision,
            root_revision: current_root_revision,
            rows,
        })
    }
}

fn map_pending_directory_subtree_retarget(
    retarget: &raiun_opencloud::vault_cache::VaultPendingDirectorySubtreeRetarget,
    expected_entry_id: &str,
    expected_entry_etag: &str,
    destination_path: &str,
    scope: VaultWriteScope,
) -> Result<VaultPendingDirectorySubtreeRenameOutcome, CloudError> {
    let write_id = expected_entry_id
        .strip_prefix("raiun-pending-directory:")
        .filter(|id| id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| CloudError::new(ErrorKind::Conflict, "pending directory ID changed"))?;
    let previous_revision = expected_entry_etag
        .strip_prefix("raiun-pending-v1:")
        .and_then(|value| value.strip_prefix(&format!("{write_id}:")))
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|revision| *revision > 0)
        .ok_or_else(|| CloudError::new(ErrorKind::Conflict, "pending directory version changed"))?;
    let root_row = retarget
        .rows
        .iter()
        .find(|row| row.write_id == write_id)
        .ok_or_else(|| CloudError::new(ErrorKind::Conflict, "retarget omitted subtree root"))?;
    if retarget.root_write_id != write_id
        || retarget.root_previous_revision != previous_revision
        || retarget.root_revision != previous_revision + 1
        || root_row.previous_revision != previous_revision
        || root_row.revision != retarget.root_revision
        || root_row.path != destination_path
        || root_row.operation
            != raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateDirectory
        || root_row.state != raiun_cache::CiphertextWriteState::NeverAttempted
    {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "retargeted subtree root does not match its source",
        ));
    }
    let mut rows = Vec::with_capacity(retarget.rows.len());
    for row in &retarget.rows {
        if row.state != raiun_cache::CiphertextWriteState::NeverAttempted
            || row.revision != row.previous_revision + 1
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "retargeted subtree contains an unsupported state",
            ));
        }
        let parent_ref = from_backend_parent_ref(row.parent_ref.clone())?;
        let target = VaultWriteTarget::new_with_parent(
            row.encoded_target.clone(),
            raiun_core::backend::WriteCondition::Absent,
            parent_ref.clone(),
        )
        .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "retarget target is invalid"))?;
        let old_parent_ref = from_backend_parent_ref(row.old_parent_ref.clone())?;
        let old_target = VaultWriteTarget::new_with_parent(
            row.old_encoded_target.clone(),
            raiun_core::backend::WriteCondition::Absent,
            old_parent_ref,
        )
        .map_err(|_| {
            CloudError::new(ErrorKind::InvalidResponse, "retarget old target is invalid")
        })?;
        let operation = match row.operation {
            raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateFile => {
                if row.plaintext_sha256.len() != 64
                    || !row
                        .plaintext_sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(CloudError::new(
                        ErrorKind::InvalidResponse,
                        "retargeted file digest is invalid",
                    ));
                }
                VaultPendingSubtreeOperation::CreateFile
            }
            raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateDirectory => {
                if row.plaintext_len != 0 || !row.plaintext_sha256.is_empty() {
                    return Err(CloudError::new(
                        ErrorKind::InvalidResponse,
                        "retargeted directory body is invalid",
                    ));
                }
                VaultPendingSubtreeOperation::CreateDirectory
            }
            _ => {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "retargeted subtree contains an unsupported operation",
                ));
            }
        };
        rows.push(VaultPendingDirectorySubtreeRenameRow {
            write_id: row.write_id.clone(),
            previous_revision: row.previous_revision,
            revision: row.revision,
            operation,
            old_path: row.old_path.clone(),
            path: row.path.clone(),
            old_target: Some(old_target),
            target,
            plaintext_len: row.plaintext_len,
            plaintext_sha256: row.plaintext_sha256.clone(),
            parent_ref,
        });
    }
    let root_entry = RemoteEntry {
        id: expected_entry_id.to_owned(),
        path: destination_path.to_owned(),
        directory: true,
        size: 0,
        etag: format!("raiun-pending-v1:{write_id}:{}", retarget.root_revision),
        modified_unix: 0,
        encrypted: false,
        writable: false,
    };
    Ok(VaultPendingDirectorySubtreeRenameOutcome {
        scope,
        root_entry,
        root_write_id: write_id.to_owned(),
        root_previous_revision: previous_revision,
        root_revision: retarget.root_revision,
        rows,
    })
}

impl VaultReadBackend for ReadOnlyVaultBackend {
    fn authorize(&self) -> Result<(), CloudError> {
        // Avoid network I/O on every FUSE read chunk. New metadata/open calls
        // revalidate the root marker and token in VaultBackend; this check
        // blocks cached open readers immediately after the coordinator locks.
        match self.sessions.is_unlocked(&self.scope) {
            Ok(true) => Ok(()),
            Ok(false) => Err(CloudError::new(
                ErrorKind::Unauthorized,
                "vault session is locked",
            )),
            Err(_) => Err(CloudError::new(
                ErrorKind::Io,
                "vault session state is unavailable",
            )),
        }
    }

    fn list(&self, path: &str) -> Result<Vec<RemoteEntry>, CloudError> {
        let mut entries = Vec::new();
        self.backend.list(&self.space_id, path, &mut |entry| {
            if entries.len() >= raiun_fuse::vault_routes::MAX_VAULT_DIRECTORY_ENTRIES {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "vault directory exceeds the mounted entry limit",
                ));
            }
            entries.push(self.apply_write_permission(entry));
            Ok(())
        })?;
        Ok(entries)
    }

    fn stat(&self, path: &str) -> Result<RemoteEntry, CloudError> {
        self.backend
            .stat(&self.space_id, path)
            .map(|entry| self.apply_write_permission(entry))
    }

    fn resolve_pending_create(
        &self,
        write_id: &str,
    ) -> Result<Option<FusePendingCreateResolution>, CloudError> {
        self.authorize()?;
        let Some(resolved) = self.backend.resolve_pending_create_by_id(write_id)? else {
            return Ok(None);
        };
        let metadata = resolved.metadata;
        if resolved.scope != self.scope
            || metadata.id != write_id
            || metadata.operation
                != raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateFile
            || metadata.base != raiun_core::backend::WriteCondition::Absent
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "encrypted create resolver returned a different scoped operation",
            ));
        }
        let parent = metadata.parent_ref.clone().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Conflict,
                "encrypted create parent binding is missing",
            )
        })?;
        let parent = from_backend_parent_ref(parent)?;
        let (scope, target) =
            write_scope_parent_target(&self.scope, metadata.encoded_target, parent)?;
        let never_attempted = metadata.state == raiun_cache::CiphertextWriteState::NeverAttempted;
        Ok(Some(FusePendingCreateResolution {
            scope,
            target,
            write_id: metadata.id,
            revision: metadata.revision,
            path: metadata.path,
            plaintext_bytes: metadata.plaintext_len,
            plaintext_sha256: resolved.plaintext_sha256,
            never_attempted,
        }))
    }

    fn parent_ref_for_directory(
        &self,
        path: &str,
        expected_entry_id: &str,
        expected_entry_etag: &str,
    ) -> Result<VaultParentRef, CloudError> {
        self.authorize()?;
        let reference =
            self.backend
                .parent_ref_for_directory(path, expected_entry_id, expected_entry_etag)?;
        from_backend_parent_ref(reference)
    }

    fn open(&self, path: &str) -> Result<Box<dyn VaultReadStream>, CloudError> {
        let before = self.backend.stat(&self.space_id, path)?;
        if before.directory {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cannot open a vault directory as a file",
            ));
        }

        // tempfile creates a unique directory with owner-only access. The
        // download call creates its own temporary ciphertext staging beneath
        // this directory and publishes plaintext only at `plaintext`.
        let staging = tempfile::tempdir().map_err(io_error)?;
        let plaintext_path = staging.path().join("plaintext");
        let after =
            self.backend
                .download(&self.space_id, path, Some(&before.etag), &plaintext_path)?;
        if after.id != before.id
            || after.etag != before.etag
            || after.size != before.size
            || after.directory
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "vault file changed while it was being opened",
            ));
        }

        staged_reader(staging, &plaintext_path)
    }
}

impl VaultWriteBackend for ReadOnlyVaultBackend {
    fn supports_pending_parent_operations(&self) -> bool {
        self.file_create && self.directory_create
    }

    fn supports_file_create(&self) -> bool {
        self.file_create
    }

    fn prepare_target(
        &self,
        path: &str,
        condition: raiun_core::backend::WriteCondition,
    ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
        if !self.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route is read-only",
            ));
        }
        self.authorize()?;
        let target = self.backend.prepare_write_target(path, &condition)?;
        let scope = VaultWriteScope::new(
            self.scope.account_id(),
            self.scope.server_origin(),
            self.scope.space_id(),
            self.scope.resource_id(),
        )
        .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "vault write scope is invalid"))?;
        let target = VaultWriteTarget::new(target, condition)
            .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "vault target is invalid"))?;
        Ok((scope, target))
    }

    fn prepare_file_create(
        &self,
        path: &str,
        existing: Option<(&str, u64)>,
    ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
        if !self.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route is read-only",
            ));
        }
        self.authorize()?;
        let target = self.backend.prepare_file_create_target(path, existing)?;
        write_scope_target(&self.scope, target)
    }

    fn prepare_file_create_under_parent(
        &self,
        path: &str,
        parent_ref: &VaultParentRef,
        existing: Option<(&str, u64)>,
    ) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
        if !self.writable || !self.file_create {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route does not permit file creation",
            ));
        }
        self.authorize()?;
        let backend_ref = to_backend_parent_ref(parent_ref);
        let target =
            self.backend
                .prepare_file_create_target_for_parent(path, &backend_ref, existing)?;
        write_scope_parent_target(&self.scope, target, parent_ref.clone())
    }

    fn upload(
        &self,
        target: &VaultWriteTarget,
        source: &mut dyn VaultWriteSource,
        plaintext_len: u64,
    ) -> Result<VaultUploadOutcome, CloudError> {
        if !self.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route is read-only",
            ));
        }
        self.authorize()?;
        let mut source = source;
        map_upload_outcome(self.backend.upload_prepared_reader_with_queue(
            target.opaque_relative_target(),
            &mut source,
            plaintext_len,
            target.condition().clone(),
            None,
        )?)
    }

    fn create_file(
        &self,
        target: &VaultWriteTarget,
        source: &mut dyn VaultWriteSource,
        plaintext_len: u64,
        existing: Option<(&str, u64)>,
    ) -> Result<VaultUploadOutcome, CloudError> {
        if !self.writable
            || !matches!(
                target.condition(),
                raiun_core::backend::WriteCondition::Absent
            )
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault create is not allowed",
            ));
        }
        self.authorize()?;
        let parent_ref = target.parent_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Conflict,
                "encrypted create has no parent reference",
            )
        })?;
        let parent_ref = to_backend_parent_ref(parent_ref);
        let mut source = source;
        map_upload_outcome(self.backend.create_prepared_reader_with_queue_for_parent(
            target.opaque_relative_target(),
            &mut source,
            plaintext_len,
            existing,
            &parent_ref,
        )?)
    }

    fn begin_file_create(
        &self,
        target: &VaultWriteTarget,
    ) -> Result<VaultUploadOutcome, CloudError> {
        if !self.writable
            || !matches!(
                target.condition(),
                raiun_core::backend::WriteCondition::Absent
            )
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault create is not allowed",
            ));
        }
        self.authorize()?;
        let parent_ref = target.parent_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Conflict,
                "encrypted create has no parent reference",
            )
        })?;
        let parent_ref = to_backend_parent_ref(parent_ref);
        map_upload_outcome(
            self.backend
                .begin_prepared_create_for_parent(target.opaque_relative_target(), &parent_ref)?,
        )
    }

    fn mkdir(&self, path: &str) -> Result<RemoteEntry, CloudError> {
        if !self.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route is read-only",
            ));
        }
        self.authorize()?;
        self.backend.mkdir(&self.space_id, path)
    }

    fn create_directory_under_parent(
        &self,
        path: &str,
        parent_ref: &VaultParentRef,
    ) -> Result<VaultDirectoryCreateOutcome, CloudError> {
        if !self.writable || !self.directory_create {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route does not permit directory creation",
            ));
        }
        self.authorize()?;
        let backend_ref = to_backend_parent_ref(parent_ref);
        map_directory_create_outcome(
            self.backend
                .create_directory_with_parent_queue(path, &backend_ref)?,
            self.writable,
        )
    }

    fn supports_cancel_directory_create(&self) -> bool {
        self.writable && self.directory_create
    }

    fn cancel_never_attempted_directory_create(
        &self,
        path: &str,
        write_id: &str,
        revision: u64,
        expected_entry_id: &str,
        expected_entry_etag: &str,
    ) -> Result<(), CloudError> {
        if !self.writable || !self.directory_create {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route does not permit directory cancellation",
            ));
        }
        self.authorize()?;
        self.backend.cancel_never_attempted_directory_create(
            path,
            write_id,
            revision,
            expected_entry_id,
            expected_entry_etag,
        )
    }

    fn supports_pending_directory_rename(&self) -> bool {
        self.writable && self.directory_create
    }

    fn rename_pending_directory_create(
        &self,
        from: &str,
        to: &str,
        expected_entry_id: &str,
        expected_entry_etag: &str,
        destination_parent: &VaultParentRef,
    ) -> Result<VaultPendingDirectoryRenameOutcome, CloudError> {
        if !self.writable || !self.directory_create {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route does not permit queued-directory rename",
            ));
        }
        self.retarget_never_attempted_directory(
            from,
            to,
            expected_entry_id,
            expected_entry_etag,
            destination_parent,
        )
    }

    fn supports_pending_directory_subtree_rename(&self) -> bool {
        self.writable && self.directory_create && self.file_create
    }

    fn rename_pending_directory_subtree(
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
        if !self.writable || !self.directory_create || !self.file_create {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route does not permit queued-directory subtree rename",
            ));
        }
        self.retarget_never_attempted_directory_subtree(
            from,
            to,
            expected_entry_id,
            expected_entry_etag,
            destination_parent,
            before_publish,
        )
    }

    fn resolve_pending_directory_subtree_retarget(
        &self,
        wal: &raiun_fuse::vault_write::PendingVaultDirectoryRetarget,
    ) -> Result<VaultPendingDirectoryRetargetResolution, CloudError> {
        self.resolve_never_attempted_directory_subtree(wal)
    }

    fn supports_cancel_file_create(&self) -> bool {
        self.writable && self.file_create
    }

    fn cancel_never_attempted_file_create(
        &self,
        path: &str,
        write_id: &str,
        revision: u64,
        expected_entry_id: &str,
        expected_entry_etag: &str,
    ) -> Result<VaultCancelledCreateReceipt, CloudError> {
        if !self.writable || !self.file_create {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route does not permit queued-file cancellation",
            ));
        }
        self.authorize()?;
        let receipt = self.backend.cancel_never_attempted_file_create(
            path,
            write_id,
            revision,
            expected_entry_id,
            expected_entry_etag,
        )?;
        map_cancelled_create_receipt(&self.scope, receipt)
    }

    fn resolve_cancelled_file_create(
        &self,
        write_id: &str,
        revision: u64,
    ) -> Result<Option<VaultCancelledCreateReceipt>, CloudError> {
        self.authorize()?;
        self.backend
            .resolve_cancelled_file_create_by_id(write_id, revision)?
            .map(|receipt| map_cancelled_create_receipt(&self.scope, receipt))
            .transpose()
    }

    fn acknowledge_cancelled_file_create(
        &self,
        write_id: &str,
        revision: u64,
        target: &VaultWriteTarget,
        content: &VerifiedCreateContent,
    ) -> Result<(), CloudError> {
        self.authorize()?;
        self.backend.acknowledge_cancelled_file_create(
            write_id,
            revision,
            target.opaque_relative_target(),
            content.bytes,
            &content.sha256,
        )
    }

    fn finalize_cancelled_file_create_ack(
        &self,
        receipt: &VaultCancelledCreateReceipt,
    ) -> Result<(), CloudError> {
        self.authorize()?;
        self.backend.finalize_cancelled_file_create_ack(
            &receipt.write_id,
            receipt.original_revision,
            receipt.current_revision,
            receipt.target.opaque_relative_target(),
            receipt.content.bytes,
            &receipt.content.sha256,
        )
    }

    fn delete(&self, path: &str, expected_etag: &str) -> Result<(), CloudError> {
        if !self.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route is read-only",
            ));
        }
        self.authorize()?;
        self.backend.delete(&self.space_id, path, expected_etag)
    }

    fn rename(&self, from: &str, to: &str, expected_etag: &str) -> Result<RemoteEntry, CloudError> {
        if !self.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "vault route is read-only",
            ));
        }
        self.authorize()?;
        self.backend.rename(&self.space_id, from, to, expected_etag)
    }
}

fn write_scope_target(
    scope: &VaultSessionScope,
    encoded_target: String,
) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
    let scope = VaultWriteScope::new(
        scope.account_id(),
        scope.server_origin(),
        scope.space_id(),
        scope.resource_id(),
    )
    .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "vault write scope is invalid"))?;
    let target = VaultWriteTarget::new(encoded_target, raiun_core::backend::WriteCondition::Absent)
        .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "vault target is invalid"))?;
    Ok((scope, target))
}

fn write_scope_parent_target(
    scope: &VaultSessionScope,
    encoded_target: String,
    parent_ref: VaultParentRef,
) -> Result<(VaultWriteScope, VaultWriteTarget), CloudError> {
    let scope = VaultWriteScope::new(
        scope.account_id(),
        scope.server_origin(),
        scope.space_id(),
        scope.resource_id(),
    )
    .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "vault write scope is invalid"))?;
    let target = VaultWriteTarget::new_with_parent(
        encoded_target,
        raiun_core::backend::WriteCondition::Absent,
        parent_ref,
    )
    .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "vault target is invalid"))?;
    Ok((scope, target))
}

fn map_cancelled_create_receipt(
    expected_scope: &VaultSessionScope,
    receipt: raiun_opencloud::vault_backend::VaultCancelledCreateReceipt,
) -> Result<VaultCancelledCreateReceipt, CloudError> {
    let metadata = receipt.metadata;
    let expected_state = match receipt.state {
        raiun_opencloud::vault_backend::VaultCancelledCreateReceiptState::Cancelled => {
            raiun_cache::CiphertextWriteState::CancelledReceipt
        }
        raiun_opencloud::vault_backend::VaultCancelledCreateReceiptState::Acknowledged => {
            raiun_cache::CiphertextWriteState::AcknowledgedReceipt
        }
    };
    if receipt.scope != *expected_scope
        || metadata.operation != raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateFile
        || metadata.base != raiun_core::backend::WriteCondition::Absent
        || metadata.state != expected_state
        || metadata.id.is_empty()
        || metadata.revision != receipt.current_revision
        || receipt.original_revision == 0
        || receipt.current_revision < receipt.original_revision
        || metadata.encoded_target.is_empty()
        || receipt.plaintext_sha256.len() != 64
        || !receipt
            .plaintext_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "encrypted cancellation receipt does not match its scope or operation",
        ));
    }
    let scope = VaultWriteScope::new(
        receipt.scope.account_id(),
        receipt.scope.server_origin(),
        receipt.scope.space_id(),
        receipt.scope.resource_id(),
    )
    .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "vault write scope is invalid"))?;
    let parent = from_backend_parent_ref(metadata.parent_ref.ok_or_else(|| {
        CloudError::new(
            ErrorKind::Conflict,
            "cancelled create has no parent reference",
        )
    })?)?;
    let target = VaultWriteTarget::new_with_parent(
        metadata.encoded_target,
        raiun_core::backend::WriteCondition::Absent,
        parent,
    )
    .map_err(|_| CloudError::new(ErrorKind::InvalidResponse, "vault target is invalid"))?;
    Ok(VaultCancelledCreateReceipt {
        state: match receipt.state {
            raiun_opencloud::vault_backend::VaultCancelledCreateReceiptState::Cancelled => {
                raiun_fuse::vault_routes::VaultCancelledCreateReceiptState::Cancelled
            }
            raiun_opencloud::vault_backend::VaultCancelledCreateReceiptState::Acknowledged => {
                raiun_fuse::vault_routes::VaultCancelledCreateReceiptState::Acknowledged
            }
        },
        scope,
        target,
        path: metadata.path,
        write_id: metadata.id,
        original_revision: receipt.original_revision,
        current_revision: receipt.current_revision,
        content: VerifiedCreateContent {
            bytes: receipt.plaintext_len,
            sha256: receipt.plaintext_sha256,
        },
    })
}

fn to_backend_parent_ref(parent: &VaultParentRef) -> VaultPendingParentRef {
    match parent {
        VaultParentRef::Stable { resource_id } => VaultPendingParentRef::Stable {
            resource_id: resource_id.clone(),
        },
        VaultParentRef::PendingCreate { write_id, revision } => {
            VaultPendingParentRef::PendingCreate {
                write_id: write_id.clone(),
                revision: *revision,
            }
        }
    }
}

fn from_backend_parent_ref(parent: VaultPendingParentRef) -> Result<VaultParentRef, CloudError> {
    match parent {
        VaultPendingParentRef::Stable { resource_id } => VaultParentRef::stable(resource_id),
        VaultPendingParentRef::PendingCreate { write_id, revision } => {
            VaultParentRef::pending_create(write_id, revision)
        }
    }
    .map_err(|_| {
        CloudError::new(
            ErrorKind::InvalidResponse,
            "encrypted parent reference is invalid",
        )
    })
}

fn map_directory_create_outcome(
    outcome: raiun_opencloud::vault_backend::VaultDirectoryCreateOutcome,
    writable: bool,
) -> Result<VaultDirectoryCreateOutcome, CloudError> {
    Ok(match outcome {
        raiun_opencloud::vault_backend::VaultDirectoryCreateOutcome::Committed(mut entry) => {
            entry.writable &= writable;
            VaultDirectoryCreateOutcome::Committed(entry)
        }
        raiun_opencloud::vault_backend::VaultDirectoryCreateOutcome::Queued {
            mut entry,
            write_id,
            revision,
            uncertain,
        } => {
            entry.writable &= writable;
            VaultDirectoryCreateOutcome::Queued {
                entry,
                write_id,
                revision,
                uncertain,
            }
        }
    })
}

fn map_upload_outcome(
    outcome: raiun_opencloud::vault_backend::VaultUploadOutcome,
) -> Result<VaultUploadOutcome, CloudError> {
    Ok(match outcome {
        raiun_opencloud::vault_backend::VaultUploadOutcome::Committed(entry) => {
            VaultUploadOutcome::Committed(entry)
        }
        raiun_opencloud::vault_backend::VaultUploadOutcome::Queued {
            entry,
            write_id,
            revision,
            uncertain,
        } => VaultUploadOutcome::Queued {
            entry,
            write_id,
            revision,
            uncertain,
        },
        raiun_opencloud::vault_backend::VaultUploadOutcome::QueuedCreate {
            entry,
            write_id,
            revision,
            uncertain,
        } => VaultUploadOutcome::QueuedCreate {
            entry,
            write_id,
            revision,
            uncertain,
        },
        raiun_opencloud::vault_backend::VaultUploadOutcome::BuildingCreate {
            entry,
            write_id,
            revision,
        } => VaultUploadOutcome::BuildingCreate {
            entry,
            write_id,
            revision,
        },
    })
}

fn staged_reader(
    staging: TempDir,
    plaintext_path: &Path,
) -> Result<Box<dyn VaultReadStream>, CloudError> {
    let file = File::open(plaintext_path).map_err(io_error)?;
    #[cfg(unix)]
    {
        // Keep the descriptor, but make the plaintext path disappear before
        // it becomes reachable through a FUSE handle.
        fs::remove_file(plaintext_path).map_err(io_error)?;
        staging.close().map_err(io_error)?;
        Ok(Box::new(file))
    }
    #[cfg(not(unix))]
    {
        // Windows cannot unlink an open file using these portable APIs. Keep
        // the private directory alive until the route closes the reader.
        Ok(Box::new(StagedReader {
            file,
            _staging: staging,
        }))
    }
}

#[cfg(not(unix))]
struct StagedReader {
    file: File,
    _staging: TempDir,
}

#[cfg(not(unix))]
impl std::io::Read for StagedReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buffer)
    }
}

#[cfg(not(unix))]
impl std::io::Seek for StagedReader {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        self.file.seek(position)
    }
}

fn io_error(_error: std::io::Error) -> CloudError {
    CloudError::new(ErrorKind::Io, "vault plaintext staging operation failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use raiun_cache::{
        Cache, CacheScope, ContentProtection, ContentVersion, Retention, ScopeProtection,
    };
    use raiun_opencloud::vault::{VaultDavEntry, VaultEvidence, VaultRootListing};
    use raiun_vault::{
        sealed_cache::{SealedVaultEntry, SealedVaultSnapshot, seal_snapshot},
        session::VaultSessionCoordinator,
    };
    use std::{
        fs::OpenOptions,
        io::{Read, Seek, SeekFrom, Write},
    };

    fn listing() -> VaultRootListing {
        VaultRootListing {
            space_id: "space-a".into(),
            space_dav_root: "https://cloud.example/dav/".into(),
            root_path: "/Travel.vault".into(),
            root: VaultDavEntry {
                id: "resource-a".into(),
                path: "/Travel.vault".into(),
                raw_name: "Travel.vault".into(),
                directory: true,
                modified_unix: 0,
                writable: true,
                size: 0,
                strong_etag: Some("root-etag".into()),
                vault_evidence: vec![VaultEvidence::FolderNameSuffix],
                href: "https://cloud.example/dav/Travel.vault/".into(),
            },
            children: Vec::new(),
            integrity_token: Some("synthetic-token".into()),
            evidence: vec![VaultEvidence::FolderNameSuffix],
        }
    }

    #[test]
    fn factory_identity_gate_rejects_changed_or_uninitialized_root() {
        assert!(validate_listing_identity(&listing(), "resource-a").is_ok());
        assert!(validate_listing_identity(&listing(), "resource-b").is_err());

        let mut uninitialized = listing();
        uninitialized.integrity_token = None;
        assert!(validate_listing_identity(&uninitialized, "resource-a").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn opened_reader_survives_unlink_and_private_staging_directory_removal() {
        let staging = tempfile::tempdir().unwrap();
        let directory = staging.path().to_owned();
        let path = directory.join("plaintext");
        fs::write(&path, b"decrypted fixture").unwrap();

        let mut reader = staged_reader(staging, &path).unwrap();
        assert!(!directory.exists());
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"decrypted fixture");
    }

    #[cfg(unix)]
    #[test]
    fn failed_open_drops_its_empty_staging_directory() {
        let staging = tempfile::tempdir().unwrap();
        let directory = staging.path().to_owned();
        let missing = directory.join("missing");

        assert!(staged_reader(staging, &missing).is_err());
        assert!(!directory.exists());
    }

    #[test]
    fn offline_factory_reads_only_the_exact_sealed_scope_without_network() {
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let origin = "http://127.0.0.1:9";
        let scope = VaultSessionScope::new("profile-a", origin, "space-a", "resource-a").unwrap();
        let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim();
        let mut password = b"potato".to_vec();
        let initial_sessions = VaultSessionCoordinator::new();
        initial_sessions
            .unlock(&scope, &mut password, token)
            .unwrap();
        assert!(password.iter().all(|byte| *byte == 0));

        let encrypted_name = initial_sessions.encrypt_name(&scope, "Notes").unwrap();
        let snapshot = SealedVaultSnapshot {
            integrity_token: token.to_owned(),
            root_etag: Some("root-etag".into()),
            root_path: "/Travel.vault".into(),
            space_dav_root: format!("{origin}/dav/"),
            space_name: "Personal".into(),
            space_dav_url: format!("{origin}/dav/"),
            space_personal: true,
            space_writable: true,
            space_encrypted: false,
            directory_resource_id: "resource-a".into(),
            encrypted_directory_path: String::new(),
            directory_etag: "root-etag".into(),
            directory_modified_unix: 1,
            directory_writable: true,
            entries: vec![SealedVaultEntry {
                resource_id: "child-a".into(),
                parent_resource_id: "resource-a".into(),
                encrypted_name,
                etag: Some("child-etag".into()),
                ciphertext_len: 0,
                directory: true,
                modified_unix: 1,
                writable: true,
            }],
        };

        let cache = Cache::open(temp.path(), 1024 * 1024).unwrap();
        let cache_scope = CacheScope::new(
            origin,
            "profile-a",
            "space-a",
            "resource-a",
            ScopeProtection::CiphertextOnly,
        )
        .unwrap();
        let epoch = cache.ciphertext_epoch(&cache_scope).unwrap();
        let sealed_path = temp.path().join("sealed-root.bin");
        let info = seal_snapshot(&initial_sessions, &scope, &snapshot, &sealed_path).unwrap();
        let mut sealed = File::open(sealed_path).unwrap();
        cache
            .publish_ciphertext_if_epoch(
                &cache_scope,
                &ContentVersion {
                    resource_id: "raiun-vault-listing-v1:resource-a".into(),
                    etag: format!("raiun-vault-sealed-metadata-v2:{epoch}"),
                    protection: ContentProtection::Ciphertext,
                },
                &mut sealed,
                info.ciphertext_bytes,
                Retention::Recent,
                epoch,
            )
            .unwrap();
        initial_sessions.lock(&scope).unwrap();

        let adapter =
            VaultOfflineCache::new(cache.clone(), scope.clone(), "/Travel.vault").unwrap();
        let offline_sessions = Arc::new(VaultSessionCoordinator::new());
        let mut password = b"potato".to_vec();
        let (unlocked_snapshot, _) = adapter
            .unlock_root(&offline_sessions, &mut password)
            .unwrap();
        let client = OpenCloudClient::new(origin, "expired-synthetic-token".into()).unwrap();
        let backend = new_offline_read_backend(
            client,
            Arc::clone(&offline_sessions),
            cache,
            scope.clone(),
            "/Travel.vault",
            unlocked_snapshot,
        )
        .unwrap();

        let entries = backend.list("/").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/Notes");
        assert!(!entries[0].writable);
        assert_eq!(backend.stat("/Notes").unwrap().id, "child-a");
        offline_sessions.lock(&scope).unwrap();
        assert_eq!(backend.list("/").unwrap_err().kind, ErrorKind::Forbidden);
    }

    #[cfg(unix)]
    struct OfflineWholeSpaceFixture;

    #[cfg(unix)]
    impl raiun_core::backend::CloudBackend for OfflineWholeSpaceFixture {
        fn server_origin(&self) -> Option<String> {
            Some("http://127.0.0.1:9".into())
        }

        fn spaces(&self) -> Result<Vec<raiun_core::backend::CloudSpace>, CloudError> {
            Ok(vec![
                raiun_core::backend::CloudSpace {
                    id: "personal".into(),
                    name: "Personal".into(),
                    dav_url: "http://127.0.0.1:9/dav/personal/".into(),
                    personal: true,
                    writable: true,
                    encrypted: false,
                },
                raiun_core::backend::CloudSpace {
                    id: "space-a".into(),
                    name: "Offline Projects".into(),
                    dav_url: "http://127.0.0.1:9/dav/space-a/".into(),
                    personal: false,
                    writable: true,
                    encrypted: true,
                },
            ])
        }

        fn list(
            &self,
            _space: &str,
            _path: &str,
            _visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
        ) -> Result<(), CloudError> {
            Err(CloudError::new(
                ErrorKind::Offline,
                "ordinary backend must not list the encrypted Space",
            ))
        }

        fn stat(&self, _space: &str, _path: &str) -> Result<RemoteEntry, CloudError> {
            Err(CloudError::new(
                ErrorKind::Offline,
                "ordinary backend must not stat the encrypted Space",
            ))
        }

        fn download(
            &self,
            _space: &str,
            _path: &str,
            _expected_etag: Option<&str>,
            _destination: &Path,
        ) -> Result<RemoteEntry, CloudError> {
            Err(CloudError::new(ErrorKind::Offline, "offline fixture"))
        }

        fn upload(
            &self,
            _space: &str,
            _path: &str,
            _source: &Path,
            _condition: raiun_core::backend::WriteCondition,
        ) -> Result<RemoteEntry, CloudError> {
            Err(CloudError::new(ErrorKind::Offline, "offline fixture"))
        }

        fn mkdir(&self, _space: &str, _path: &str) -> Result<RemoteEntry, CloudError> {
            Err(CloudError::new(ErrorKind::Offline, "offline fixture"))
        }

        fn delete(
            &self,
            _space: &str,
            _path: &str,
            _expected_etag: &str,
        ) -> Result<(), CloudError> {
            Err(CloudError::new(ErrorKind::Offline, "offline fixture"))
        }

        fn rename(
            &self,
            _space: &str,
            _from: &str,
            _to: &str,
            _expected_etag: &str,
        ) -> Result<RemoteEntry, CloudError> {
            Err(CloudError::new(ErrorKind::Offline, "offline fixture"))
        }
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires an explicitly requested isolated host FUSE mount"]
    fn live_fuse_offline_whole_space_reads_sealed_vault_cache_read_only() {
        use raiun_cache::{
            CacheScope, ContentProtection, ContentVersion, Retention, ScopeProtection,
        };
        use raiun_engine::Engine;
        use raiun_fuse::{
            VaultMountRegistry, VaultMountRoute, mount_with_vault_registry,
            vault_routes::VaultRouteControl,
        };
        use raiun_vault::sealed_cache::{SealedVaultEntry, SealedVaultSnapshot, seal_snapshot};
        use std::{
            fs::{self, OpenOptions},
            io::{Cursor, Read},
            os::unix::fs::PermissionsExt,
        };

        assert!(
            Path::new("/dev/fuse").exists(),
            "host FUSE device is required"
        );
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let origin = "http://127.0.0.1:9";
        let scope = VaultSessionScope::new("profile-a", origin, "space-a", "root-id").unwrap();
        let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim();
        let initial_sessions = VaultSessionCoordinator::new();
        let mut password = b"potato".to_vec();
        initial_sessions
            .unlock(&scope, &mut password, token)
            .unwrap();

        let cache_dir = temp.path().join("offline-cache");
        fs::create_dir(&cache_dir).unwrap();
        fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let cache = Cache::open(&cache_dir, 64 * 1024 * 1024).unwrap();
        let cache_scope = CacheScope::new(
            origin,
            scope.account_id(),
            scope.space_id(),
            scope.resource_id(),
            ScopeProtection::CiphertextOnly,
        )
        .unwrap();
        let epoch = cache.ciphertext_epoch(&cache_scope).unwrap();

        let plaintext = b"verified offline encrypted-space bytes";
        let ciphertext_path = temp.path().join("ciphertext.bin");
        let mut source = Cursor::new(plaintext);
        initial_sessions
            .encrypt_file_transactional(
                &scope,
                &mut source,
                &ciphertext_path,
                plaintext.len() as u64,
                1024,
            )
            .unwrap();
        let ciphertext_len = fs::metadata(&ciphertext_path).unwrap().len();
        let encrypted_name = initial_sessions
            .encrypt_name(&scope, "offline-note.txt")
            .unwrap();
        let root_snapshot = SealedVaultSnapshot {
            integrity_token: token.into(),
            root_etag: Some("\"root-e1\"".into()),
            root_path: "/".into(),
            space_dav_root: format!("{origin}/dav/space-a/"),
            space_name: "Offline Projects".into(),
            space_dav_url: format!("{origin}/dav/space-a/"),
            space_personal: false,
            space_writable: true,
            space_encrypted: true,
            directory_resource_id: "root-id".into(),
            encrypted_directory_path: String::new(),
            directory_etag: "\"root-e1\"".into(),
            directory_modified_unix: 1,
            directory_writable: true,
            entries: vec![SealedVaultEntry {
                resource_id: "file-id".into(),
                parent_resource_id: "root-id".into(),
                encrypted_name,
                etag: Some("\"file-e1\"".into()),
                ciphertext_len,
                directory: false,
                modified_unix: 1,
                writable: true,
            }],
        };
        let envelope_path = temp.path().join("sealed-root.bin");
        let envelope_info =
            seal_snapshot(&initial_sessions, &scope, &root_snapshot, &envelope_path).unwrap();
        let mut envelope = File::open(&envelope_path).unwrap();
        cache
            .publish_ciphertext_if_epoch(
                &cache_scope,
                &ContentVersion {
                    resource_id: "raiun-vault-listing-v1:root-id".into(),
                    etag: format!("raiun-vault-sealed-metadata-v2:{epoch}"),
                    protection: ContentProtection::Ciphertext,
                },
                &mut envelope,
                envelope_info.ciphertext_bytes,
                Retention::Recent,
                epoch,
            )
            .unwrap();
        let mut ciphertext = File::open(&ciphertext_path).unwrap();
        cache
            .publish_ciphertext_if_epoch(
                &cache_scope,
                &ContentVersion {
                    resource_id: "file-id".into(),
                    etag: format!("raiun-vault-file-ciphertext-v1:{epoch}:\"file-e1\""),
                    protection: ContentProtection::Ciphertext,
                },
                &mut ciphertext,
                ciphertext_len,
                Retention::Recent,
                epoch,
            )
            .unwrap();
        initial_sessions.lock(&scope).unwrap();

        // Simulate a fresh explicit offline unlock from only the encrypted
        // cache. The OpenCloud adapter is configured with a dead local origin;
        // any accidental network fallback fails the OS read below.
        let offline_sessions = Arc::new(VaultSessionCoordinator::new());
        let mut password = b"potato".to_vec();
        let (unlocked_snapshot, _) =
            VaultOfflineCache::unlock_cached_root(&cache, &offline_sessions, &scope, &mut password)
                .unwrap();
        let client = OpenCloudClient::new(origin, "expired-synthetic-token".into()).unwrap();
        let backend = new_offline_read_backend(
            client,
            Arc::clone(&offline_sessions),
            cache,
            scope.clone(),
            "/",
            unlocked_snapshot,
        )
        .unwrap();
        let control = VaultRouteControl::new();
        control.install_backend(backend).unwrap();
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    "space-a".into(),
                    "/".into(),
                    "root-id".into(),
                    control.clone(),
                )
                .unwrap(),
            )
            .unwrap();
        let engine = Engine::open(
            &temp.path().join("engine"),
            Arc::new(OfflineWholeSpaceFixture),
        )
        .unwrap();
        let mount_root = temp.path().join("mount");
        fs::create_dir(&mount_root).unwrap();
        let mount = mount_with_vault_registry(
            engine,
            &mount_root,
            &temp.path().join("provider-state"),
            registry,
        )
        .unwrap();

        let file_path = mount_root.join("Spaces/Offline Projects/offline-note.txt");
        assert_eq!(fs::read(&file_path).unwrap(), plaintext);
        assert!(OpenOptions::new().write(true).open(&file_path).is_err());
        let mut open = File::open(&file_path).unwrap();
        let mut prefix = [0; 8];
        open.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"verified");
        control
            .revoke(|| {
                offline_sessions
                    .lock(&scope)
                    .map_err(|error| CloudError::new(ErrorKind::Io, error.to_string()))
            })
            .unwrap();
        open.rewind().unwrap();
        assert!(open.read(&mut prefix).is_err());

        drop(open);
        drop(mount);
        assert!(fs::read_dir(&mount_root).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[derive(Clone)]
    struct PinFixtureNode {
        path: String,
        name: String,
        id: String,
        etag: String,
        directory: bool,
        children: Vec<String>,
        ciphertext: Vec<u8>,
    }

    #[cfg(unix)]
    struct PinFixtureState {
        nodes: std::collections::BTreeMap<String, PinFixtureNode>,
        token: String,
    }

    #[cfg(unix)]
    struct PinFixture {
        authority: String,
        stop: Arc<std::sync::atomic::AtomicBool>,
        disconnected: Arc<std::sync::atomic::AtomicBool>,
        put_count: Arc<std::sync::atomic::AtomicUsize>,
        mkcol_count: Arc<std::sync::atomic::AtomicUsize>,
        move_count: Arc<std::sync::atomic::AtomicUsize>,
        delete_count: Arc<std::sync::atomic::AtomicUsize>,
        worker: Option<std::thread::JoinHandle<()>>,
    }

    #[cfg(unix)]
    impl PinFixture {
        fn start(nodes: Vec<PinFixtureNode>, token: String) -> Self {
            use std::net::TcpListener;
            use std::sync::atomic::Ordering;
            use std::time::Duration;

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let authority = listener.local_addr().unwrap().to_string();
            let state = Arc::new(std::sync::Mutex::new(PinFixtureState {
                nodes: nodes
                    .into_iter()
                    .map(|node| (node.path.clone(), node))
                    .collect(),
                token,
            }));
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let disconnected = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let put_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mkcol_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let move_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let delete_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let worker_state = Arc::clone(&state);
            let worker_stop = Arc::clone(&stop);
            let worker_disconnected = Arc::clone(&disconnected);
            let worker_put_count = Arc::clone(&put_count);
            let worker_mkcol_count = Arc::clone(&mkcol_count);
            let worker_move_count = Arc::clone(&move_count);
            let worker_delete_count = Arc::clone(&delete_count);
            let worker_authority = authority.clone();
            let worker = std::thread::spawn(move || {
                while !worker_stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => pin_fixture_serve(
                            stream,
                            &worker_authority,
                            &worker_state,
                            &worker_disconnected,
                            &worker_put_count,
                            &worker_mkcol_count,
                            &worker_move_count,
                            &worker_delete_count,
                        ),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => panic!("synthetic encrypted-pin listener failed: {error}"),
                    }
                }
            });
            Self {
                authority,
                stop,
                disconnected,
                put_count,
                mkcol_count,
                move_count,
                delete_count,
                worker: Some(worker),
            }
        }

        fn origin(&self) -> String {
            format!("http://{}", self.authority)
        }

        fn disconnect(&self, disconnected: bool) {
            self.disconnected
                .store(disconnected, std::sync::atomic::Ordering::Release);
        }

        fn put_count(&self) -> usize {
            self.put_count.load(std::sync::atomic::Ordering::Acquire)
        }

        fn mkcol_count(&self) -> usize {
            self.mkcol_count.load(std::sync::atomic::Ordering::Acquire)
        }

        fn move_count(&self) -> usize {
            self.move_count.load(std::sync::atomic::Ordering::Acquire)
        }

        fn delete_count(&self) -> usize {
            self.delete_count.load(std::sync::atomic::Ordering::Acquire)
        }
    }

    #[cfg(unix)]
    impl Drop for PinFixture {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Release);
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
        }
    }

    #[cfg(unix)]
    #[allow(clippy::too_many_arguments)]
    fn pin_fixture_serve(
        mut stream: std::net::TcpStream,
        authority: &str,
        state: &Arc<std::sync::Mutex<PinFixtureState>>,
        disconnected: &std::sync::atomic::AtomicBool,
        put_count: &std::sync::atomic::AtomicUsize,
        mkcol_count: &std::sync::atomic::AtomicUsize,
        move_count: &std::sync::atomic::AtomicUsize,
        delete_count: &std::sync::atomic::AtomicUsize,
    ) {
        use std::io::Read;
        use std::time::Duration;

        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            if stream.read_exact(&mut byte).is_err() {
                return;
            }
            request.push(byte[0]);
            assert!(request.len() <= 64 * 1024);
        }
        let request = String::from_utf8(request).unwrap();
        let mut lines = request.lines();
        let mut first = lines.next().unwrap().split_ascii_whitespace();
        let method = first.next().unwrap();
        let target = first.next().unwrap();
        let headers: std::collections::BTreeMap<_, _> = lines
            .filter_map(|line| {
                let (key, value) = line.split_once(':')?;
                Some((key.to_ascii_lowercase(), value.trim().to_owned()))
            })
            .collect();
        let content_len = headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        assert!(content_len <= 1024 * 1024);
        let mut request_body = vec![0; content_len];
        if content_len > 0 && stream.read_exact(&mut request_body).is_err() {
            return;
        }
        if disconnected.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        let mut state_guard = state.lock().unwrap();
        if headers.get("authorization").map(String::as_str) != Some("Bearer synthetic-token") {
            pin_fixture_respond(&mut stream, 401, "text/plain", b"unauthorized");
            return;
        }
        if method == "GET" && target == "/graph/v1.0/me/drives" {
            let body = format!(
                r#"{{"value":[{{"id":"personal-drive","name":"Personal","driveType":"personal","root":{{"id":"personal-root","webDavUrl":"http://{authority}/dav/personal/"}}}},{{"id":"space-a","name":"Offline Projects","driveType":"project","root":{{"id":"pin-root-id","webDavUrl":"http://{authority}/dav/space-a/","permissions":"RDNVW","@libre.graph.contentType":"application/vnd.opencloud.vault"}}}}]}}"#
            );
            pin_fixture_respond(&mut stream, 200, "application/json", body.as_bytes());
            return;
        }
        if method == "PROPFIND" && target.starts_with("/dav/space-a/") {
            let requested = target
                .strip_prefix("/dav/space-a/")
                .unwrap()
                .trim_end_matches('/');
            let logical_path = if requested.is_empty() {
                "/".to_owned()
            } else {
                format!("/{requested}")
            };
            let Some(root) = state_guard.nodes.get(&logical_path) else {
                pin_fixture_respond(&mut stream, 404, "text/plain", b"missing");
                return;
            };
            let depth_one = headers.get("depth").is_some_and(|value| value == "1");
            let mut body = format!(
                r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone">{}"#,
                pin_fixture_node_xml(authority, root, logical_path == "/", &state_guard.token)
            );
            if depth_one && root.directory {
                for child_path in &root.children {
                    let child = state_guard.nodes.get(child_path).unwrap();
                    body.push_str(&pin_fixture_node_xml(
                        authority,
                        child,
                        false,
                        &state_guard.token,
                    ));
                }
            }
            body.push_str("</d:multistatus>");
            pin_fixture_respond(&mut stream, 207, "application/xml", body.as_bytes());
            return;
        }
        if method == "GET" && target.starts_with("/dav/space-a/") {
            let requested = target
                .strip_prefix("/dav/space-a/")
                .unwrap()
                .trim_end_matches('/');
            let logical_path = format!("/{requested}");
            if let Some(node) = state_guard.nodes.get(&logical_path) {
                if !node.directory
                    && headers.get("if-match").map(String::as_str) == Some(&node.etag)
                {
                    pin_fixture_respond(
                        &mut stream,
                        200,
                        "application/octet-stream",
                        &node.ciphertext,
                    );
                } else {
                    pin_fixture_respond(&mut stream, 412, "text/plain", b"version mismatch");
                }
            } else {
                pin_fixture_respond(&mut stream, 404, "text/plain", b"missing");
            }
            return;
        }
        if method == "MKCOL" && target.starts_with("/dav/space-a/") {
            mkcol_count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let requested = target
                .strip_prefix("/dav/space-a/")
                .unwrap()
                .trim_end_matches('/');
            let logical_path = format!("/{requested}");
            let parent_path = logical_path
                .rsplit_once('/')
                .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
                .unwrap_or("/");
            let parent = state_guard.nodes.get(parent_path).cloned();
            let parent_matches = parent.as_ref().is_some_and(|parent| {
                parent.directory
                    && headers
                        .get("if")
                        .is_some_and(|condition| condition.contains(&parent.etag))
            });
            if !parent_matches
                || headers.get("if-none-match").map(String::as_str) != Some("*")
                || state_guard.nodes.contains_key(&logical_path)
            {
                pin_fixture_respond(&mut stream, 412, "text/plain", b"precondition failed");
                return;
            }
            let parent = parent.expect("validated MKCOL parent");
            let entry_name = logical_path.rsplit('/').next().unwrap().to_owned();
            let created_id = format!(
                "created-directory-{}",
                mkcol_count.load(std::sync::atomic::Ordering::Acquire)
            );
            state_guard.nodes.insert(
                logical_path.clone(),
                PinFixtureNode {
                    path: logical_path.clone(),
                    name: entry_name,
                    id: created_id,
                    etag: "\"created-directory-v1\"".into(),
                    directory: true,
                    children: Vec::new(),
                    ciphertext: Vec::new(),
                },
            );
            state_guard
                .nodes
                .get_mut(parent_path)
                .expect("parent remains present")
                .children
                .push(logical_path);
            let _ = parent;
            pin_fixture_respond(&mut stream, 201, "text/plain", b"");
            return;
        }
        if method == "PUT" && target.starts_with("/dav/space-a/") {
            put_count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let requested = target
                .strip_prefix("/dav/space-a/")
                .unwrap()
                .trim_end_matches('/');
            let logical_path = format!("/{requested}");
            let parent_path = logical_path
                .rsplit_once('/')
                .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
                .unwrap_or("/");
            let parent_matches = state_guard
                .nodes
                .get(parent_path)
                .is_some_and(|parent| parent.directory);
            if !parent_matches
                || headers.get("if-none-match").map(String::as_str) != Some("*")
                || state_guard.nodes.contains_key(&logical_path)
            {
                pin_fixture_respond(&mut stream, 412, "text/plain", b"precondition failed");
                return;
            }
            let encrypted_name = logical_path.rsplit('/').next().unwrap().to_owned();
            let created_file_id = format!(
                "created-file-id-{}",
                put_count.load(std::sync::atomic::Ordering::Acquire)
            );
            state_guard.nodes.insert(
                logical_path.clone(),
                PinFixtureNode {
                    path: logical_path.clone(),
                    name: encrypted_name,
                    id: created_file_id,
                    etag: "\"created-v1\"".into(),
                    directory: false,
                    children: Vec::new(),
                    ciphertext: request_body,
                },
            );
            state_guard
                .nodes
                .get_mut(parent_path)
                .unwrap()
                .children
                .push(logical_path);
            pin_fixture_respond(&mut stream, 201, "text/plain", b"");
            return;
        }
        if method == "MOVE" && target.starts_with("/dav/space-a/") {
            move_count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let source_requested = target
                .strip_prefix("/dav/space-a/")
                .unwrap()
                .trim_end_matches('/');
            let source_path = format!("/{source_requested}");
            let destination = headers.get("destination").map(String::as_str).unwrap_or("");
            let destination_requested = destination
                .split_once("/dav/space-a/")
                .map(|(_, path)| path.trim_end_matches('/'));
            let Some(destination_requested) = destination_requested else {
                pin_fixture_respond(&mut stream, 400, "text/plain", b"invalid destination");
                return;
            };
            let destination_path = format!("/{destination_requested}");
            let source = state_guard.nodes.get(&source_path).cloned();
            let source_parent = source_path
                .rsplit_once('/')
                .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
                .unwrap_or("/");
            let destination_parent = destination_path
                .rsplit_once('/')
                .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
                .unwrap_or("/");
            let parents_match = state_guard
                .nodes
                .get(source_parent)
                .is_some_and(|parent| parent.directory && parent.id == "folder-id")
                && state_guard
                    .nodes
                    .get(destination_parent)
                    .is_some_and(|parent| parent.directory && parent.id == "pin-root-id");
            let source_matches = source.as_ref().is_some_and(|source| {
                !source.directory
                    && headers.get("if-match").map(String::as_str) == Some(source.etag.as_str())
            });
            if !parents_match
                || !source_matches
                || headers.get("overwrite").map(String::as_str) != Some("F")
                || state_guard.nodes.contains_key(&destination_path)
            {
                pin_fixture_respond(&mut stream, 412, "text/plain", b"precondition failed");
                return;
            }
            let mut source = source.expect("validated move source");
            state_guard.nodes.remove(&source_path);
            source.path = destination_path.clone();
            source.name = destination_requested.to_owned();
            source.etag = "\"moved-v1\"".into();
            state_guard.nodes.insert(destination_path.clone(), source);
            state_guard
                .nodes
                .get_mut(source_parent)
                .unwrap()
                .children
                .retain(|path| path != &source_path);
            state_guard
                .nodes
                .get_mut(destination_parent)
                .unwrap()
                .children
                .push(destination_path);
            pin_fixture_respond(&mut stream, 201, "text/plain", b"");
            return;
        }
        if method == "DELETE" && target.starts_with("/dav/space-a/") {
            delete_count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let requested = target
                .strip_prefix("/dav/space-a/")
                .unwrap()
                .trim_end_matches('/');
            let logical_path = format!("/{requested}");
            let Some(source) = state_guard.nodes.get(&logical_path).cloned() else {
                pin_fixture_respond(&mut stream, 404, "text/plain", b"missing");
                return;
            };
            if source.directory
                || headers.get("if-match").map(String::as_str) != Some(source.etag.as_str())
            {
                pin_fixture_respond(&mut stream, 412, "text/plain", b"precondition failed");
                return;
            }
            let parent_path = logical_path
                .rsplit_once('/')
                .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
                .unwrap_or("/");
            state_guard.nodes.remove(&logical_path);
            if let Some(parent) = state_guard.nodes.get_mut(parent_path) {
                parent.children.retain(|path| path != &logical_path);
            }
            pin_fixture_respond(&mut stream, 204, "text/plain", b"");
            return;
        }
        pin_fixture_respond(&mut stream, 404, "text/plain", b"not found");
    }

    #[cfg(unix)]
    fn pin_fixture_node_xml(
        authority: &str,
        node: &PinFixtureNode,
        space_root: bool,
        token: &str,
    ) -> String {
        let href = format!(
            "http://{authority}/dav/space-a/{}",
            node.path.trim_start_matches('/')
        );
        let href = if node.directory && !href.ends_with('/') {
            format!("{href}/")
        } else {
            href
        };
        let resource_type = if node.directory {
            "<d:resourcetype><d:collection/></d:resourcetype>"
        } else {
            "<d:resourcetype/>"
        };
        let marker = if space_root {
            format!(
                "<d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype><ocrclone:integrity-id>{token}</ocrclone:integrity-id>"
            )
        } else {
            String::new()
        };
        let byte_len = node.ciphertext.len();
        format!(
            r#"<d:response><d:href>{href}</d:href><d:propstat><d:prop>{resource_type}<d:getcontentlength>{byte_len}</d:getcontentlength><d:getetag>{}</d:getetag><oc:fileid>{}</oc:fileid><oc:name>{}</oc:name><oc:permissions>RDNVW</oc:permissions>{marker}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"#,
            node.etag, node.id, node.name
        )
    }

    #[cfg(unix)]
    fn pin_fixture_respond(
        stream: &mut std::net::TcpStream,
        status: u16,
        content_type: &str,
        body: &[u8],
    ) {
        use std::io::Write;
        write!(
            stream,
            "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires an explicitly requested isolated host FUSE mount"]
    fn live_fuse_reads_actual_encrypted_pin_offline_and_relock_revokes_nested_handles() {
        use raiun_cache::Cache;
        use raiun_engine::Engine;
        use raiun_fuse::{
            VaultMountRegistry, VaultMountRoute, mount_with_vault_registry,
            vault_routes::VaultRouteControl,
        };
        use raiun_opencloud::{
            OpenCloudClient, vault_backend::VaultBackend, vault_cache::VaultOfflineCache,
        };
        use std::{
            fs::{self, File},
            io::{Cursor, Read, Seek},
            os::unix::fs::PermissionsExt,
            sync::atomic::AtomicBool,
        };

        assert!(
            Path::new("/dev/fuse").exists(),
            "host FUSE device is required"
        );
        let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64")
            .trim()
            .to_owned();
        let initial_sessions = Arc::new(VaultSessionCoordinator::new());
        let placeholder_scope = VaultSessionScope::new(
            "profile-pin",
            "http://127.0.0.1:1",
            "space-a",
            "pin-root-id",
        )
        .unwrap();
        let mut password = b"potato".to_vec();
        initial_sessions
            .unlock(&placeholder_scope, &mut password, &token)
            .unwrap();

        let make_ciphertext = |bytes: &[u8]| {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("ciphertext");
            let mut reader = Cursor::new(bytes);
            initial_sessions
                .encrypt_file_transactional(
                    &placeholder_scope,
                    &mut reader,
                    &path,
                    bytes.len() as u64,
                    1024 * 1024,
                )
                .unwrap();
            fs::read(path).unwrap()
        };
        let root_file_name = initial_sessions
            .encrypt_name(&placeholder_scope, "root-note.txt")
            .unwrap();
        let folder_name = initial_sessions
            .encrypt_name(&placeholder_scope, "Folder")
            .unwrap();
        let nested_file_name = initial_sessions
            .encrypt_name(&placeholder_scope, "nested-note.txt")
            .unwrap();
        let folder_path = format!("/{folder_name}");
        let root_file_path = format!("/{root_file_name}");
        let nested_file_path = format!("{folder_path}/{nested_file_name}");
        let root_plaintext = b"root encrypted pin fixture";
        let nested_plaintext = b"nested encrypted pin fixture bytes";
        let nodes = vec![
            PinFixtureNode {
                path: "/".into(),
                name: "space-a".into(),
                id: "pin-root-id".into(),
                etag: "\"root-v1\"".into(),
                directory: true,
                children: vec![folder_path.clone(), root_file_path.clone()],
                ciphertext: Vec::new(),
            },
            PinFixtureNode {
                path: folder_path.clone(),
                name: folder_name,
                id: "folder-id".into(),
                etag: "\"folder-v1\"".into(),
                directory: true,
                children: vec![nested_file_path.clone()],
                ciphertext: Vec::new(),
            },
            PinFixtureNode {
                path: root_file_path,
                name: root_file_name,
                id: "root-file-id".into(),
                etag: "\"root-file-v1\"".into(),
                directory: false,
                children: Vec::new(),
                ciphertext: make_ciphertext(root_plaintext),
            },
            PinFixtureNode {
                path: nested_file_path,
                name: nested_file_name,
                id: "nested-file-id".into(),
                etag: "\"nested-file-v1\"".into(),
                directory: false,
                children: Vec::new(),
                ciphertext: make_ciphertext(nested_plaintext),
            },
        ];
        initial_sessions.lock(&placeholder_scope).unwrap();
        let fixture = PinFixture::start(nodes, token.clone());
        let origin = fixture.origin();
        let scope =
            VaultSessionScope::new("profile-pin", &origin, "space-a", "pin-root-id").unwrap();
        let mut password = b"potato".to_vec();
        initial_sessions
            .unlock(&scope, &mut password, &token)
            .unwrap();

        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cache_dir = temp.path().join("encrypted-cache");
        fs::create_dir(&cache_dir).unwrap();
        fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let cache = Cache::open(&cache_dir, 64 * 1024 * 1024).unwrap();
        let cache_scope = raiun_cache::CacheScope::new(
            &origin,
            scope.account_id(),
            scope.space_id(),
            scope.resource_id(),
            ScopeProtection::CiphertextOnly,
        )
        .unwrap();
        let offline_cache = VaultOfflineCache::new(cache.clone(), scope.clone(), "/").unwrap();
        let client = OpenCloudClient::new(&origin, "synthetic-token".into()).unwrap();
        let online_backend = VaultBackend::new_with_offline_cache(
            client,
            Arc::clone(&initial_sessions),
            scope.clone(),
            "/".into(),
            offline_cache,
        )
        .unwrap();
        let pin = online_backend
            .pin_offline_tree(None, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(pin.state, raiun_cache::CiphertextPinState::Ready);
        assert!(
            pin.item_count >= 4,
            "root/folder listings and two file blobs are present"
        );
        assert_eq!(
            cache.ciphertext_pin_info(&cache_scope, &pin.id).unwrap(),
            pin
        );
        assert!(cache.usage().unwrap().pinned_bytes > 0);
        initial_sessions.lock(&scope).unwrap();
        drop(online_backend);
        drop(fixture);

        let offline_sessions = Arc::new(VaultSessionCoordinator::new());
        let mut password = b"potato".to_vec();
        let snapshot = VaultOfflineCache::unlock_cached_pin_root(
            &cache,
            &offline_sessions,
            &scope,
            &pin.id,
            &mut password,
        )
        .unwrap();
        let client = OpenCloudClient::new(&origin, "expired-synthetic-token".into()).unwrap();
        let backend = new_offline_overwrite_backend(
            client,
            Arc::clone(&offline_sessions),
            cache.clone(),
            scope.clone(),
            "/",
            Some(&pin.id),
            snapshot,
        )
        .unwrap();
        let control = VaultRouteControl::new();
        control
            .install_existing_file_overwrite_backend(backend)
            .unwrap();
        assert!(!control.supports_writes().unwrap());
        assert!(control.supports_existing_file_overwrites().unwrap());
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    scope.space_id().into(),
                    "/".into(),
                    scope.resource_id().into(),
                    control.clone(),
                )
                .unwrap(),
            )
            .unwrap();
        let engine = Engine::open(
            &temp.path().join("engine"),
            Arc::new(OfflineWholeSpaceFixture),
        )
        .unwrap();
        let mount_root = temp.path().join("mount");
        fs::create_dir(&mount_root).unwrap();
        let mount = mount_with_vault_registry(
            engine,
            &mount_root,
            &temp.path().join("provider-state"),
            registry,
        )
        .unwrap();

        let root_file = mount_root.join("Spaces/Offline Projects/root-note.txt");
        let nested_file = mount_root.join("Spaces/Offline Projects/Folder/nested-note.txt");
        assert_eq!(fs::read(&root_file).unwrap(), root_plaintext);
        assert_eq!(fs::read(&nested_file).unwrap(), nested_plaintext);
        fs::write(&root_file, b"offline replacement bytes").unwrap();
        assert_eq!(fs::read(&root_file).unwrap(), b"offline replacement bytes");
        let new_file = mount_root.join("Spaces/Offline Projects/new.txt");
        let mut created = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&new_file)
            .expect("offline create queues a new encrypted regular file");
        created.write_all(b"offline new file").unwrap();
        created.sync_all().unwrap();
        created.seek(SeekFrom::Start(0)).unwrap();
        let mut created_contents = Vec::new();
        created.read_to_end(&mut created_contents).unwrap();
        assert_eq!(created_contents, b"offline new file");
        drop(created);
        let pending_directory = mount_root.join("Spaces/Offline Projects/new-folder");
        fs::create_dir(&pending_directory)
            .expect("offline MKCOL is durably queued under the verified parent");
        assert!(fs::read_dir(&pending_directory).unwrap().next().is_none());
        let pending_child = pending_directory.join("child.txt");
        let mut child = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&pending_child)
            .expect("the queued directory passes its explicit ParentRef to child creation");
        child.write_all(b"queued child bytes").unwrap();
        child.sync_all().unwrap();
        drop(child);
        assert_eq!(fs::read(&pending_child).unwrap(), b"queued child bytes");
        // This route includes the offline file-delete capability, so leave
        // the pinned source in place for the lock/revocation assertions below.
        let mut old_handle = File::open(&nested_file).unwrap();
        let mut prefix = [0; 6];
        old_handle.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"nested");

        let occupied = mount_root.join("Spaces/Offline Projects/root-note.txt");
        assert!(fs::rename(&nested_file, &occupied).is_err());
        assert_eq!(fs::read(&occupied).unwrap(), b"offline replacement bytes");
        let renamed = mount_root.join("Spaces/Offline Projects/renamed-note.txt");
        fs::rename(&nested_file, &renamed)
            .expect("same-vault rename may keep a stable read-only source handle open");
        assert!(!nested_file.exists());
        assert_eq!(fs::read(&renamed).unwrap(), nested_plaintext);
        old_handle.rewind().unwrap();
        let mut renamed_handle_contents = Vec::new();
        old_handle
            .read_to_end(&mut renamed_handle_contents)
            .unwrap();
        assert_eq!(renamed_handle_contents, nested_plaintext);
        drop(old_handle);
        let mut old_handle = File::open(&renamed).unwrap();
        old_handle.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"nested");

        control
            .revoke(|| {
                offline_sessions
                    .lock(&scope)
                    .map_err(|error| CloudError::new(ErrorKind::Io, error.to_string()))
            })
            .unwrap();
        old_handle.rewind().unwrap();
        assert!(old_handle.read(&mut prefix).is_err());
        assert!(File::open(&nested_file).is_err());
        assert!(File::open(&renamed).is_err());

        drop(old_handle);
        drop(mount);
        assert!(fs::read_dir(&mount_root).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires an explicitly requested isolated host FUSE mount"]
    fn live_fuse_offline_create_survives_restart_and_reconciles_conditionally() {
        use raiun_cache::Cache;
        use raiun_engine::Engine;
        use raiun_fuse::{
            VaultMountRegistry, VaultMountRoute, mount_with_vault_registry,
            vault_routes::VaultRouteControl,
        };
        use raiun_opencloud::{
            OpenCloudClient, vault_backend::VaultBackend, vault_cache::VaultOfflineCache,
        };
        use std::{
            fs::{self, OpenOptions},
            io::Write,
            os::unix::fs::PermissionsExt,
            sync::atomic::AtomicBool,
        };

        assert!(
            Path::new("/dev/fuse").exists(),
            "host FUSE device is required"
        );
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64")
            .trim()
            .to_owned();
        let initial_sessions = Arc::new(VaultSessionCoordinator::new());
        let provisional_scope = VaultSessionScope::new(
            "profile-create",
            "http://127.0.0.1:1",
            "space-a",
            "pin-root-id",
        )
        .unwrap();
        let mut password = b"potato".to_vec();
        initial_sessions
            .unlock(&provisional_scope, &mut password, &token)
            .unwrap();
        let encrypted_name = initial_sessions
            .encrypt_name(&provisional_scope, "existing.txt")
            .unwrap();
        let plaintext = b"existing pinned bytes";
        let encrypted_temp = temp.path().join("existing-ciphertext");
        initial_sessions
            .encrypt_file_transactional(
                &provisional_scope,
                &mut std::io::Cursor::new(plaintext),
                &encrypted_temp,
                plaintext.len() as u64,
                1024 * 1024,
            )
            .unwrap();
        let existing_path = format!("/{encrypted_name}");
        let root = PinFixtureNode {
            path: "/".into(),
            name: "space-a".into(),
            id: "pin-root-id".into(),
            etag: "\"root-v1\"".into(),
            directory: true,
            children: vec![existing_path.clone()],
            ciphertext: Vec::new(),
        };
        let existing = PinFixtureNode {
            path: existing_path,
            name: encrypted_name,
            id: "existing-file-id".into(),
            etag: "\"existing-v1\"".into(),
            directory: false,
            children: Vec::new(),
            ciphertext: fs::read(&encrypted_temp).unwrap(),
        };
        initial_sessions.lock(&provisional_scope).unwrap();
        let fixture = PinFixture::start(vec![root, existing], token.clone());
        let origin = fixture.origin();
        let scope =
            VaultSessionScope::new("profile-create", &origin, "space-a", "pin-root-id").unwrap();
        let mut password = b"potato".to_vec();
        initial_sessions
            .unlock(&scope, &mut password, &token)
            .unwrap();

        let cache_dir = temp.path().join("cache");
        fs::create_dir(&cache_dir).unwrap();
        fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let cache = Cache::open(&cache_dir, 64 * 1024 * 1024).unwrap();
        let online_cache = VaultOfflineCache::new(cache.clone(), scope.clone(), "/").unwrap();
        let client = OpenCloudClient::new(&origin, "synthetic-token".into()).unwrap();
        let online_backend = VaultBackend::new_with_offline_cache(
            client,
            Arc::clone(&initial_sessions),
            scope.clone(),
            "/".into(),
            online_cache,
        )
        .unwrap();
        let pin = online_backend
            .pin_offline_tree(None, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(pin.state, raiun_cache::CiphertextPinState::Ready);
        initial_sessions.lock(&scope).unwrap();

        // First mount has only the verified encrypted pin and an explicitly
        // unlocked session. The synthetic DAV origin drops requests while
        // disconnected; no real server/account is involved.
        let first_sessions = Arc::new(VaultSessionCoordinator::new());
        let mut password = b"potato".to_vec();
        let snapshot = VaultOfflineCache::unlock_cached_pin_root(
            &cache,
            &first_sessions,
            &scope,
            &pin.id,
            &mut password,
        )
        .unwrap();
        let client = OpenCloudClient::new(&origin, "expired-synthetic-token".into()).unwrap();
        let backend = new_offline_overwrite_backend(
            client,
            Arc::clone(&first_sessions),
            cache.clone(),
            scope.clone(),
            "/",
            Some(&pin.id),
            snapshot,
        )
        .unwrap();
        let journal =
            VaultOfflineCache::new_for_pin(cache.clone(), scope.clone(), "/", &pin.id).unwrap();
        let control = VaultRouteControl::new();
        control
            .install_existing_file_overwrite_backend(backend)
            .unwrap();
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    scope.space_id().into(),
                    "/".into(),
                    scope.resource_id().into(),
                    control.clone(),
                )
                .unwrap(),
            )
            .unwrap();
        let ordinary = Arc::new(OfflineWholeSpaceFixture);
        let engine = Engine::open(&temp.path().join("engine-one"), ordinary.clone()).unwrap();
        let first_mount_root = temp.path().join("mount-one");
        fs::create_dir(&first_mount_root).unwrap();
        let first_mount = mount_with_vault_registry(
            engine,
            &first_mount_root,
            &temp.path().join("provider-one"),
            registry,
        )
        .unwrap();

        fixture.disconnect(true);
        let virtual_directory =
            first_mount_root.join("Spaces/Offline Projects/created-offline-folder");
        fs::create_dir(&virtual_directory)
            .expect("offline MKCOL records a durable parent operation");
        let virtual_path = virtual_directory.join("created-offline.txt");
        let mut created = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&virtual_path)
            .expect("offline child create records a durable Building intent");
        let (building, _) = journal.pending_edits(&first_sessions, None, 16).unwrap();
        assert_eq!(building.len(), 2);
        assert_eq!(
            building
                .iter()
                .find(|row| row.state == raiun_cache::CiphertextWriteState::Building)
                .unwrap()
                .state,
            raiun_cache::CiphertextWriteState::Building
        );
        let (retryable, _) = journal
            .retryable_pending_edits(&first_sessions, 16)
            .unwrap();
        assert_eq!(retryable.len(), 1);
        assert_eq!(
            retryable[0].operation,
            raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateDirectory,
            "the parent folder can reconcile, but an incomplete child body must not"
        );

        let cancel_path = first_mount_root.join("Spaces/Offline Projects/cancel-me.txt");
        let mut cancel_file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&cancel_path)
            .expect("offline file creation starts a durable local intent");
        cancel_file
            .write_all(b"cancel this never-uploaded file")
            .unwrap();
        cancel_file.sync_all().expect("publish queued create body");
        drop(cancel_file);
        fs::remove_file(&cancel_path)
            .expect("close then unlink cancels only the exact never-attempted file create");
        assert!(!cancel_path.exists());
        assert_eq!(fixture.put_count(), 0, "offline create/cancel sends no PUT");
        assert_eq!(
            fixture.delete_count(),
            0,
            "offline create/cancel sends no DELETE"
        );
        let (after_cancel, _) = journal.pending_edits(&first_sessions, None, 16).unwrap();
        assert!(after_cancel.iter().all(|row| row.path != "/cancel-me.txt"));

        let latest_bytes = b"latest durable create contents after restart";
        created.write_all(latest_bytes).unwrap();
        created
            .sync_all()
            .expect("flush encrypted create to journal");
        drop(created);
        assert_eq!(fixture.put_count(), 0, "offline flush must not reach PUT");
        assert_eq!(
            fixture.mkcol_count(),
            0,
            "offline directory create stays local"
        );
        assert_eq!(fs::read(&virtual_path).unwrap(), latest_bytes);
        let (queued, _) = journal.pending_edits(&first_sessions, None, 16).unwrap();
        assert_eq!(queued.len(), 2);
        let directory = queued
            .iter()
            .find(|row| {
                row.operation
                    == raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateDirectory
            })
            .unwrap();
        let directory_id = directory.id.clone();
        let directory_revision = directory.revision;
        let child = queued
            .iter()
            .find(|row| {
                row.operation == raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateFile
            })
            .unwrap();
        let queued_id = child.id.clone();
        let previous_revision = child.revision;
        let renamed_path = first_mount_root.join("Spaces/Offline Projects/renamed-offline.txt");
        fs::rename(&virtual_path, &renamed_path)
            .expect("never-attempted queued create can be retargeted offline");
        assert!(!virtual_path.exists(), "the old local name is hidden");
        assert_eq!(fs::read(&renamed_path).unwrap(), latest_bytes);
        assert_eq!(fixture.move_count(), 0, "offline retarget sends no MOVE");
        let (retargeted, _) = journal.pending_edits(&first_sessions, None, 16).unwrap();
        let child = retargeted
            .iter()
            .find(|row| row.id == queued_id)
            .expect("same create operation remains in the journal");
        assert_eq!(
            child.operation,
            raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateFile
        );
        assert_eq!(child.path, "/renamed-offline.txt");
        assert_eq!(child.base, raiun_core::backend::WriteCondition::Absent);
        assert_eq!(
            child.parent_ref,
            Some(
                raiun_opencloud::vault_cache::VaultPendingParentRef::Stable {
                    resource_id: "pin-root-id".into(),
                }
            )
        );
        assert_eq!(
            child.state,
            raiun_cache::CiphertextWriteState::NeverAttempted
        );
        assert!(child.revision > previous_revision);
        let queued_revision = child.revision;
        let old_parent_ref = raiun_opencloud::vault_cache::VaultPendingParentRef::PendingCreate {
            write_id: directory_id.clone(),
            revision: directory_revision,
        };
        let (old_parent_children, _) = journal
            .pending_operations_for_parent_ref(&first_sessions, &old_parent_ref, None, 16)
            .unwrap();
        assert!(
            old_parent_children.iter().all(|row| row.id != queued_id),
            "retarget must atomically remove the child from the old parent index"
        );

        // The file operation no longer depends on its original queued parent,
        // so that now-empty NeverAttempted directory can itself be retargeted.
        // Keep its stable operation ID and advance only its revision/path.
        let old_directory_path =
            first_mount_root.join("Spaces/Offline Projects/created-offline-folder");
        let moved_directory_path =
            first_mount_root.join("Spaces/Offline Projects/moved-offline-folder");
        fs::rename(&old_directory_path, &moved_directory_path)
            .expect("empty never-attempted directory can be retargeted offline");
        assert!(!old_directory_path.exists(), "old directory path is hidden");
        assert!(moved_directory_path.is_dir());
        assert_eq!(
            fixture.move_count(),
            0,
            "offline directory retarget sends no MOVE"
        );
        let (after_directory_retarget, _) =
            journal.pending_edits(&first_sessions, None, 16).unwrap();
        let directory = after_directory_retarget
            .iter()
            .find(|row| row.id == directory_id)
            .expect("same directory operation remains queued");
        assert_eq!(directory.path, "/moved-offline-folder");
        assert_eq!(
            directory.state,
            raiun_cache::CiphertextWriteState::NeverAttempted
        );
        assert!(directory.revision > directory_revision);
        let moved_directory_revision = directory.revision;
        assert_eq!(
            directory.parent_ref,
            Some(
                raiun_opencloud::vault_cache::VaultPendingParentRef::Stable {
                    resource_id: "pin-root-id".into(),
                }
            )
        );

        // A populated never-attempted subtree retarget updates every exact
        // journal row as one batch. The child body and parent dependency move
        // together; no MOVE is sent while disconnected.
        let populated_source =
            first_mount_root.join("Spaces/Offline Projects/populated-pending-folder");
        fs::create_dir(&populated_source).expect("queue populated source directory");
        let populated_child = populated_source.join("child.txt");
        let mut populated_file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&populated_child)
            .expect("queue a never-attempted file under the pending directory");
        let populated_bytes = b"subtree member remains bound through batch retarget";
        populated_file.write_all(populated_bytes).unwrap();
        populated_file
            .sync_all()
            .expect("publish queued subtree file body");
        drop(populated_file);
        let (before_batch, _) = journal.pending_edits(&first_sessions, None, 32).unwrap();
        let batch_directory = before_batch
            .iter()
            .find(|row| row.path == "/populated-pending-folder")
            .expect("directory intent is durable before batch move");
        let batch_directory_id = batch_directory.id.clone();
        let batch_directory_old_revision = batch_directory.revision;
        let batch_file = before_batch
            .iter()
            .find(|row| row.path == "/populated-pending-folder/child.txt")
            .expect("file intent is durable before batch move");
        let batch_file_id = batch_file.id.clone();
        let batch_file_old_revision = batch_file.revision;
        let populated_destination =
            first_mount_root.join("Spaces/Offline Projects/populated-pending-folder-moved");
        fs::rename(&populated_source, &populated_destination)
            .expect("complete never-attempted subtree retarget is atomic");
        assert!(!populated_source.exists(), "old subtree path stays hidden");
        assert_eq!(
            fs::read(populated_destination.join("child.txt")).unwrap(),
            populated_bytes
        );
        assert_eq!(
            fixture.move_count(),
            0,
            "offline subtree retarget sends no MOVE"
        );
        let (after_batch, _) = journal.pending_edits(&first_sessions, None, 32).unwrap();
        let batch_directory = after_batch
            .iter()
            .find(|row| row.id == batch_directory_id)
            .expect("same directory operation remains after batch retarget");
        let batch_directory_revision = batch_directory.revision;
        assert_eq!(batch_directory.path, "/populated-pending-folder-moved");
        assert_eq!(batch_directory_revision, batch_directory_old_revision + 1);
        let batch_file = after_batch
            .iter()
            .find(|row| row.id == batch_file_id)
            .expect("same file operation remains after batch retarget");
        let batch_file_revision = batch_file.revision;
        assert_eq!(batch_file.path, "/populated-pending-folder-moved/child.txt");
        assert_eq!(batch_file_revision, batch_file_old_revision + 1);
        assert_eq!(
            batch_file.parent_ref,
            Some(
                raiun_opencloud::vault_cache::VaultPendingParentRef::PendingCreate {
                    write_id: batch_directory_id.clone(),
                    revision: batch_directory_revision,
                }
            )
        );

        let open_source = first_mount_root.join("Spaces/Offline Projects/open-pending-folder");
        fs::create_dir(&open_source).expect("queue empty directory for handle check");
        let open_handle = fs::read_dir(&open_source).expect("open pending directory handle");
        assert!(
            fs::rename(
                &open_source,
                first_mount_root.join("Spaces/Offline Projects/open-pending-folder-moved")
            )
            .is_err(),
            "an open directory handle prevents retarget"
        );
        drop(open_handle);
        fs::remove_dir(&open_source).expect("cancel open-handle fixture directory");
        let cancel_path = first_mount_root.join("Spaces/Offline Projects/cancel-after-restart");
        fs::create_dir(&cancel_path).expect("offline empty directory create is durably queued");
        assert_eq!(fixture.mkcol_count(), 0, "offline mkdir sends no MKCOL");
        drop(first_mount);
        assert!(fs::read_dir(&first_mount_root).unwrap().next().is_none());
        first_sessions.lock(&scope).unwrap();

        // Simulate process restart: construct a fresh coordinator, decrypt
        // the exact ready pin again, and verify the queued create overlay and
        // its latest bytes survive without contacting the disconnected DAV.
        let restarted_sessions = Arc::new(VaultSessionCoordinator::new());
        let mut password = b"potato".to_vec();
        let snapshot = VaultOfflineCache::unlock_cached_pin_root(
            &cache,
            &restarted_sessions,
            &scope,
            &pin.id,
            &mut password,
        )
        .unwrap();
        let client = OpenCloudClient::new(&origin, "expired-synthetic-token".into()).unwrap();
        let backend = new_offline_overwrite_backend(
            client,
            Arc::clone(&restarted_sessions),
            cache.clone(),
            scope.clone(),
            "/",
            Some(&pin.id),
            snapshot,
        )
        .unwrap();
        let control = VaultRouteControl::new();
        control
            .install_existing_file_overwrite_backend(backend)
            .unwrap();
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    scope.space_id().into(),
                    "/".into(),
                    scope.resource_id().into(),
                    control.clone(),
                )
                .unwrap(),
            )
            .unwrap();
        let engine = Engine::open(&temp.path().join("engine-two"), ordinary).unwrap();
        let second_mount_root = temp.path().join("mount-two");
        fs::create_dir(&second_mount_root).unwrap();
        let second_mount = mount_with_vault_registry(
            engine,
            &second_mount_root,
            &temp.path().join("provider-two"),
            registry,
        )
        .unwrap();
        let restarted_path = second_mount_root.join("Spaces/Offline Projects/renamed-offline.txt");
        assert_eq!(fs::read(&restarted_path).unwrap(), latest_bytes);
        let stale_directory_path =
            second_mount_root.join("Spaces/Offline Projects/created-offline-folder");
        let restarted_directory_path =
            second_mount_root.join("Spaces/Offline Projects/moved-offline-folder");
        assert!(
            !stale_directory_path.exists(),
            "the old queued-directory name must not return after restart"
        );
        assert!(
            restarted_directory_path.is_dir(),
            "the retargeted queued directory survives restart"
        );
        assert!(
            !second_mount_root
                .join("Spaces/Offline Projects/cancel-me.txt")
                .exists(),
            "a safely canceled never-attempted file must not reappear after restart"
        );
        assert!(
            !second_mount_root
                .join("Spaces/Offline Projects/created-offline-folder/created-offline.txt")
                .exists(),
            "restart must not restore the obsolete create name"
        );
        let restarted_journal =
            VaultOfflineCache::new_for_pin(cache.clone(), scope.clone(), "/", &pin.id).unwrap();

        let restarted_populated_dir =
            second_mount_root.join("Spaces/Offline Projects/populated-pending-folder-moved");
        assert!(restarted_populated_dir.is_dir());
        assert_eq!(
            fs::read(restarted_populated_dir.join("child.txt")).unwrap(),
            populated_bytes,
            "the file body follows the batch-retargeted directory across restart"
        );
        assert!(
            !second_mount_root
                .join("Spaces/Offline Projects/populated-pending-folder")
                .exists(),
            "the populated subtree's old root stays absent after restart"
        );

        // Child creation after restart must bind to the exact new parent
        // revision written by the all-new subtree batch.
        let post_restart_child_path = restarted_populated_dir.join("after-restart.txt");
        let mut post_restart_child = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&post_restart_child_path)
            .expect("create a child below the retargeted directory after restart");
        let post_restart_child_bytes = b"child bound after subtree restart";
        post_restart_child
            .write_all(post_restart_child_bytes)
            .unwrap();
        post_restart_child
            .sync_all()
            .expect("queue post-restart subtree child");
        drop(post_restart_child);
        let (restart_operations, _) = restarted_journal
            .pending_edits(&restarted_sessions, None, 32)
            .unwrap();
        let post_restart_child_row = restart_operations
            .iter()
            .find(|row| row.path == "/populated-pending-folder-moved/after-restart.txt")
            .expect("post-restart child operation is in the journal");
        let post_restart_child_id = post_restart_child_row.id.clone();
        let post_restart_child_revision = post_restart_child_row.revision;
        assert_eq!(
            post_restart_child_row.parent_ref,
            Some(
                raiun_opencloud::vault_cache::VaultPendingParentRef::PendingCreate {
                    write_id: batch_directory_id.clone(),
                    revision: batch_directory_revision,
                }
            )
        );
        assert_eq!(fixture.put_count(), 0);
        assert_eq!(fixture.mkcol_count(), 0);

        // A new child created after restart must bind to the exact retargeted
        // directory generation, not the pre-rename revision or old path.
        let nested_path = restarted_directory_path.join("created-after-restart.txt");
        let mut nested_file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&nested_path)
            .expect("create child under retargeted directory after restart");
        let nested_bytes = b"nested child follows verified directory receipt";
        nested_file.write_all(nested_bytes).unwrap();
        nested_file.sync_all().expect("queue nested child body");
        drop(nested_file);
        assert_eq!(fs::read(&nested_path).unwrap(), nested_bytes);
        assert_eq!(
            fixture.mkcol_count(),
            0,
            "offline nested create sends no MKCOL"
        );
        assert_eq!(fixture.put_count(), 0, "offline nested create sends no PUT");
        let (with_nested_child, _) = restarted_journal
            .pending_edits(&restarted_sessions, None, 16)
            .unwrap();
        let nested_operation = with_nested_child
            .iter()
            .find(|row| row.path == "/moved-offline-folder/created-after-restart.txt")
            .expect("nested create is durably indexed at the retargeted path");
        assert_eq!(
            nested_operation.parent_ref,
            Some(
                raiun_opencloud::vault_cache::VaultPendingParentRef::PendingCreate {
                    write_id: directory_id.clone(),
                    revision: moved_directory_revision,
                }
            ),
            "child binds to the exact latest parent operation revision"
        );
        let nested_id = nested_operation.id.clone();
        let nested_revision = nested_operation.revision;

        let restarted_cancel_path =
            second_mount_root.join("Spaces/Offline Projects/cancel-after-restart");
        assert!(
            restarted_cancel_path.is_dir(),
            "queued empty directory survives restart"
        );
        let held_dir = fs::read_dir(&restarted_cancel_path)
            .expect("queued directory can be opened after restart");
        assert!(
            fs::remove_dir(&restarted_cancel_path).is_err(),
            "an open directory handle prevents cancellation"
        );
        drop(held_dir);
        fs::remove_dir(&restarted_cancel_path)
            .expect("closed never-attempted empty directory can be canceled");
        assert!(!restarted_cancel_path.exists());

        let dependent_parent =
            second_mount_root.join("Spaces/Offline Projects/cancel-parent-with-child");
        fs::create_dir(&dependent_parent).unwrap();
        let dependent_child = dependent_parent.join("child");
        fs::create_dir(&dependent_child).unwrap();
        assert!(
            fs::remove_dir(&dependent_parent).is_err(),
            "a pending child prevents canceling its parent operation"
        );
        fs::remove_dir(&dependent_child)
            .expect("child operation can be canceled before its parent");
        fs::remove_dir(&dependent_parent)
            .expect("parent can be canceled after its child is removed");
        assert_eq!(fixture.mkcol_count(), 0, "cancel sends no MKCOL");
        assert_eq!(fixture.delete_count(), 0, "cancel sends no DELETE");
        drop(second_mount);
        assert!(fs::read_dir(&second_mount_root).unwrap().next().is_none());
        restarted_sessions.lock(&scope).unwrap();

        // Reconnect only after restart and explicit unlock. Reconciliation
        // performs a conditional absent-create and verifies the stored bytes
        // by fetching the resulting remote resource before retiring the row.
        fixture.disconnect(false);
        let online_sessions = Arc::new(VaultSessionCoordinator::new());
        let mut password = b"potato".to_vec();
        online_sessions
            .unlock(&scope, &mut password, &token)
            .unwrap();
        let online_cache = VaultOfflineCache::new(cache.clone(), scope.clone(), "/").unwrap();
        let client = OpenCloudClient::new(&origin, "synthetic-token".into()).unwrap();
        let online_backend = VaultBackend::new_with_offline_cache(
            client,
            Arc::clone(&online_sessions),
            scope.clone(),
            "/".into(),
            online_cache,
        )
        .unwrap();
        let committed_directory = online_backend
            .reconcile_pending_directory_create(&directory_id, moved_directory_revision)
            .expect("restart reconciliation conditionally creates the retargeted directory");
        assert!(committed_directory.directory);
        assert_eq!(
            fixture.mkcol_count(),
            1,
            "one conditional MKCOL is sufficient"
        );
        assert_eq!(
            fixture.delete_count(),
            0,
            "cancellation sends no remote DELETE"
        );
        let committed = online_backend
            .reconcile_pending_operation(&queued_id, queued_revision)
            .expect("restart reconciliation conditionally creates the remote file");
        assert_eq!(committed.path, "/renamed-offline.txt");
        assert_eq!(committed.id, "created-file-id-1");
        assert_eq!(fixture.put_count(), 1, "one conditional PUT is sufficient");
        let path = temp.path().join("verified-created-plaintext");
        online_backend
            .download("space-a", &committed.path, Some(&committed.etag), &path)
            .unwrap();
        assert_eq!(fs::read(path).unwrap(), latest_bytes);
        let nested_committed = online_backend
            .reconcile_pending_operation(&nested_id, nested_revision)
            .expect("nested child reconciles only after exact parent receipt");
        assert_eq!(
            nested_committed.path,
            "/moved-offline-folder/created-after-restart.txt"
        );
        assert_eq!(nested_committed.id, "created-file-id-2");
        assert_eq!(
            fixture.put_count(),
            2,
            "one PUT per queued file is sufficient"
        );
        let nested_verified = temp.path().join("verified-nested-plaintext");
        online_backend
            .download(
                "space-a",
                &nested_committed.path,
                Some(&nested_committed.etag),
                &nested_verified,
            )
            .unwrap();
        assert_eq!(fs::read(nested_verified).unwrap(), nested_bytes);

        let committed_batch_directory = online_backend
            .reconcile_pending_directory_create(&batch_directory_id, batch_directory_revision)
            .expect("retargeted populated directory reconciles before its children");
        assert_eq!(
            committed_batch_directory.path,
            "/populated-pending-folder-moved"
        );
        assert_eq!(
            fixture.mkcol_count(),
            2,
            "the two queued directories each issue one conditional MKCOL"
        );
        let committed_batch_file = online_backend
            .reconcile_pending_operation(&batch_file_id, batch_file_revision)
            .expect("pre-retarget child follows its exact parent receipt");
        assert_eq!(
            committed_batch_file.path,
            "/populated-pending-folder-moved/child.txt"
        );
        let committed_post_restart_child = online_backend
            .reconcile_pending_operation(&post_restart_child_id, post_restart_child_revision)
            .expect("post-restart child follows the same parent receipt");
        assert_eq!(
            committed_post_restart_child.path,
            "/populated-pending-folder-moved/after-restart.txt"
        );
        assert_eq!(fixture.put_count(), 4, "each queued file uploads once");
        for (label, entry, expected) in [
            (
                "batch child",
                committed_batch_file,
                populated_bytes.as_slice(),
            ),
            (
                "post-restart child",
                committed_post_restart_child,
                post_restart_child_bytes.as_slice(),
            ),
        ] {
            let verified = temp.path().join(format!("verified-{label}"));
            online_backend
                .download("space-a", &entry.path, Some(&entry.etag), &verified)
                .unwrap();
            assert_eq!(fs::read(verified).unwrap(), expected);
        }
        let (remaining, _) = VaultOfflineCache::new(cache, scope, "/")
            .unwrap()
            .pending_edits(&online_sessions, None, 16)
            .unwrap();
        let remaining_summary: Vec<_> = remaining
            .iter()
            .map(|row| (row.operation, row.state, row.revision, row.path.clone()))
            .collect();
        assert!(
            remaining.is_empty(),
            "verified create retires its journal row; remaining kinds/states/revisions: {remaining_summary:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires an explicitly requested isolated host FUSE mount"]
    fn live_fuse_offline_rename_survives_restart_and_reconciles_conditionally() {
        use raiun_cache::Cache;
        use raiun_engine::Engine;
        use raiun_fuse::{
            VaultMountRegistry, VaultMountRoute, mount_with_vault_registry,
            vault_routes::VaultRouteControl,
        };
        use raiun_opencloud::{
            OpenCloudClient, vault_backend::VaultBackend, vault_cache::VaultOfflineCache,
        };
        use std::{fs, os::unix::fs::PermissionsExt, sync::atomic::AtomicBool};

        assert!(
            Path::new("/dev/fuse").exists(),
            "host FUSE device is required"
        );
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64")
            .trim()
            .to_owned();
        let initial_sessions = Arc::new(VaultSessionCoordinator::new());
        let provisional_scope = VaultSessionScope::new(
            "profile-rename",
            "http://127.0.0.1:1",
            "space-a",
            "pin-root-id",
        )
        .unwrap();
        let mut password = b"potato".to_vec();
        initial_sessions
            .unlock(&provisional_scope, &mut password, &token)
            .unwrap();
        let encrypted_folder = initial_sessions
            .encrypt_name(&provisional_scope, "Folder")
            .unwrap();
        let encrypted_name = initial_sessions
            .encrypt_name(&provisional_scope, "before.txt")
            .unwrap();
        let plaintext = b"stable encrypted source bytes";
        let encrypted_temp = temp.path().join("source-ciphertext");
        initial_sessions
            .encrypt_file_transactional(
                &provisional_scope,
                &mut std::io::Cursor::new(plaintext),
                &encrypted_temp,
                plaintext.len() as u64,
                1024 * 1024,
            )
            .unwrap();
        let folder_path = format!("/{encrypted_folder}");
        let source_path = format!("{folder_path}/{encrypted_name}");
        let root = PinFixtureNode {
            path: "/".into(),
            name: "space-a".into(),
            id: "pin-root-id".into(),
            etag: "\"root-v1\"".into(),
            directory: true,
            children: vec![folder_path.clone()],
            ciphertext: Vec::new(),
        };
        let folder = PinFixtureNode {
            path: folder_path.clone(),
            name: encrypted_folder,
            id: "folder-id".into(),
            etag: "\"folder-v1\"".into(),
            directory: true,
            children: vec![source_path.clone()],
            ciphertext: Vec::new(),
        };
        let source = PinFixtureNode {
            path: source_path,
            name: encrypted_name,
            id: "source-file-id".into(),
            etag: "\"source-v1\"".into(),
            directory: false,
            children: Vec::new(),
            ciphertext: fs::read(&encrypted_temp).unwrap(),
        };
        initial_sessions.lock(&provisional_scope).unwrap();
        let fixture = PinFixture::start(vec![root, folder, source], token.clone());
        let origin = fixture.origin();
        let scope =
            VaultSessionScope::new("profile-rename", &origin, "space-a", "pin-root-id").unwrap();
        let mut password = b"potato".to_vec();
        initial_sessions
            .unlock(&scope, &mut password, &token)
            .unwrap();

        let cache_dir = temp.path().join("cache");
        fs::create_dir(&cache_dir).unwrap();
        fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let cache = Cache::open(&cache_dir, 64 * 1024 * 1024).unwrap();
        let online_cache = VaultOfflineCache::new(cache.clone(), scope.clone(), "/").unwrap();
        let client = OpenCloudClient::new(&origin, "synthetic-token".into()).unwrap();
        let online_backend = VaultBackend::new_with_offline_cache(
            client,
            Arc::clone(&initial_sessions),
            scope.clone(),
            "/".into(),
            online_cache,
        )
        .unwrap();
        let pin = online_backend
            .pin_offline_tree(None, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(pin.state, raiun_cache::CiphertextPinState::Ready);
        initial_sessions.lock(&scope).unwrap();

        let first_sessions = Arc::new(VaultSessionCoordinator::new());
        let mut password = b"potato".to_vec();
        let snapshot = VaultOfflineCache::unlock_cached_pin_root(
            &cache,
            &first_sessions,
            &scope,
            &pin.id,
            &mut password,
        )
        .unwrap();
        let client = OpenCloudClient::new(&origin, "expired-synthetic-token".into()).unwrap();
        let backend = new_offline_overwrite_backend(
            client,
            Arc::clone(&first_sessions),
            cache.clone(),
            scope.clone(),
            "/",
            Some(&pin.id),
            snapshot,
        )
        .unwrap();
        let journal =
            VaultOfflineCache::new_for_pin(cache.clone(), scope.clone(), "/", &pin.id).unwrap();
        let control = VaultRouteControl::new();
        control
            .install_existing_file_overwrite_backend(backend)
            .unwrap();
        assert!(control.supports_file_renames().unwrap());
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    scope.space_id().into(),
                    "/".into(),
                    scope.resource_id().into(),
                    control.clone(),
                )
                .unwrap(),
            )
            .unwrap();
        let engine = Engine::open(
            &temp.path().join("engine-one"),
            Arc::new(OfflineWholeSpaceFixture),
        )
        .unwrap();
        let first_mount_root = temp.path().join("mount-one");
        fs::create_dir(&first_mount_root).unwrap();
        let first_mount = mount_with_vault_registry(
            engine,
            &first_mount_root,
            &temp.path().join("provider-one"),
            registry,
        )
        .unwrap();

        fixture.disconnect(true);
        let cloud_root = first_mount_root.join("Spaces/Offline Projects");
        let original = cloud_root.join("Folder/before.txt");
        let renamed = cloud_root.join("after.txt");
        assert_eq!(fs::read(&original).unwrap(), plaintext);
        fs::rename(&original, &renamed).expect("offline cross-parent rename is durably queued");
        assert!(!original.exists());
        assert_eq!(fs::read(&renamed).unwrap(), plaintext);
        assert_eq!(
            fixture.move_count(),
            0,
            "offline rename must not reach MOVE"
        );
        let (pending, _) = journal.pending_edits(&first_sessions, None, 16).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].operation,
            raiun_opencloud::vault_cache::VaultPendingOperationKind::RenameFile
        );
        assert_eq!(
            pending[0].base_resource_id, "source-file-id",
            "delete journal is bound to the original resource"
        );
        assert_eq!(pending[0].base_etag, "\"source-v1\"");
        assert_eq!(pending[0].root_integrity_token, token);
        assert_eq!(pending[0].parent_resource_id, "folder-id");
        assert_eq!(pending[0].parent_etag, "\"folder-v1\"");
        assert_eq!(pending[0].destination_parent_resource_id, "pin-root-id");
        assert_eq!(pending[0].destination_parent_etag, "\"root-v1\"");
        let operation_id = pending[0].id.clone();
        let operation_revision = pending[0].revision;
        drop(first_mount);
        assert!(fs::read_dir(&first_mount_root).unwrap().next().is_none());
        first_sessions.lock(&scope).unwrap();

        let restarted_sessions = Arc::new(VaultSessionCoordinator::new());
        let mut password = b"potato".to_vec();
        let snapshot = VaultOfflineCache::unlock_cached_pin_root(
            &cache,
            &restarted_sessions,
            &scope,
            &pin.id,
            &mut password,
        )
        .unwrap();
        let client = OpenCloudClient::new(&origin, "expired-synthetic-token".into()).unwrap();
        let backend = new_offline_overwrite_backend(
            client,
            Arc::clone(&restarted_sessions),
            cache.clone(),
            scope.clone(),
            "/",
            Some(&pin.id),
            snapshot,
        )
        .unwrap();
        let control = VaultRouteControl::new();
        control
            .install_existing_file_overwrite_backend(backend)
            .unwrap();
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    scope.space_id().into(),
                    "/".into(),
                    scope.resource_id().into(),
                    control.clone(),
                )
                .unwrap(),
            )
            .unwrap();
        let engine = Engine::open(
            &temp.path().join("engine-two"),
            Arc::new(OfflineWholeSpaceFixture),
        )
        .unwrap();
        let second_mount_root = temp.path().join("mount-two");
        fs::create_dir(&second_mount_root).unwrap();
        let second_mount = mount_with_vault_registry(
            engine,
            &second_mount_root,
            &temp.path().join("provider-two"),
            registry,
        )
        .unwrap();
        let restarted_cloud_root = second_mount_root.join("Spaces/Offline Projects");
        assert!(!restarted_cloud_root.join("Folder/before.txt").exists());
        assert_eq!(
            fs::read(restarted_cloud_root.join("after.txt")).unwrap(),
            plaintext
        );
        drop(second_mount);
        assert!(fs::read_dir(&second_mount_root).unwrap().next().is_none());
        restarted_sessions.lock(&scope).unwrap();

        fixture.disconnect(false);
        let online_sessions = Arc::new(VaultSessionCoordinator::new());
        let mut password = b"potato".to_vec();
        online_sessions
            .unlock(&scope, &mut password, &token)
            .unwrap();
        let online_cache = VaultOfflineCache::new(cache.clone(), scope.clone(), "/").unwrap();
        let client = OpenCloudClient::new(&origin, "synthetic-token".into()).unwrap();
        let online_backend = VaultBackend::new_with_offline_cache(
            client,
            Arc::clone(&online_sessions),
            scope.clone(),
            "/".into(),
            online_cache,
        )
        .unwrap();
        let committed = online_backend
            .reconcile_pending_operation(&operation_id, operation_revision)
            .expect("reconcile conditional MOVE after exact offline restart");
        assert_eq!(committed.path, "/after.txt");
        assert_eq!(committed.id, "source-file-id");
        assert_eq!(
            fixture.move_count(),
            1,
            "one conditional MOVE is sufficient"
        );
        let verified = temp.path().join("verified-renamed-plaintext");
        online_backend
            .download("space-a", "/after.txt", Some(&committed.etag), &verified)
            .unwrap();
        assert_eq!(fs::read(verified).unwrap(), plaintext);
        let (remaining, _) = VaultOfflineCache::new(cache, scope, "/")
            .unwrap()
            .pending_edits(&online_sessions, None, 16)
            .unwrap();
        assert!(remaining.is_empty(), "verified MOVE retires its operation");
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires an explicitly requested isolated host FUSE mount"]
    fn live_fuse_offline_delete_survives_restart_and_reconciles_conditionally() {
        use raiun_cache::Cache;
        use raiun_engine::Engine;
        use raiun_fuse::{
            VaultMountRegistry, VaultMountRoute, mount_with_vault_registry,
            vault_routes::VaultRouteControl,
        };
        use raiun_opencloud::{
            OpenCloudClient, vault_backend::VaultBackend, vault_cache::VaultOfflineCache,
        };
        use std::{fs, os::unix::fs::PermissionsExt, sync::atomic::AtomicBool};

        assert!(
            Path::new("/dev/fuse").exists(),
            "host FUSE device is required"
        );
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64")
            .trim()
            .to_owned();
        let initial_sessions = Arc::new(VaultSessionCoordinator::new());
        let provisional_scope = VaultSessionScope::new(
            "profile-delete",
            "http://127.0.0.1:1",
            "space-a",
            "pin-root-id",
        )
        .unwrap();
        let mut password = b"potato".to_vec();
        initial_sessions
            .unlock(&provisional_scope, &mut password, &token)
            .unwrap();
        let encrypted_folder = initial_sessions
            .encrypt_name(&provisional_scope, "Folder")
            .unwrap();
        let encrypted_name = initial_sessions
            .encrypt_name(&provisional_scope, "before.txt")
            .unwrap();
        let plaintext = b"stable encrypted source bytes";
        let encrypted_temp = temp.path().join("source-ciphertext");
        initial_sessions
            .encrypt_file_transactional(
                &provisional_scope,
                &mut std::io::Cursor::new(plaintext),
                &encrypted_temp,
                plaintext.len() as u64,
                1024 * 1024,
            )
            .unwrap();
        let folder_path = format!("/{encrypted_folder}");
        let source_path = format!("{folder_path}/{encrypted_name}");
        let root = PinFixtureNode {
            path: "/".into(),
            name: "space-a".into(),
            id: "pin-root-id".into(),
            etag: "\"root-v1\"".into(),
            directory: true,
            children: vec![folder_path.clone()],
            ciphertext: Vec::new(),
        };
        let folder = PinFixtureNode {
            path: folder_path.clone(),
            name: encrypted_folder,
            id: "folder-id".into(),
            etag: "\"folder-v1\"".into(),
            directory: true,
            children: vec![source_path.clone()],
            ciphertext: Vec::new(),
        };
        let source = PinFixtureNode {
            path: source_path,
            name: encrypted_name,
            id: "source-file-id".into(),
            etag: "\"source-v1\"".into(),
            directory: false,
            children: Vec::new(),
            ciphertext: fs::read(&encrypted_temp).unwrap(),
        };
        initial_sessions.lock(&provisional_scope).unwrap();
        let fixture = PinFixture::start(vec![root, folder, source], token.clone());
        let origin = fixture.origin();
        let scope =
            VaultSessionScope::new("profile-delete", &origin, "space-a", "pin-root-id").unwrap();
        let mut password = b"potato".to_vec();
        initial_sessions
            .unlock(&scope, &mut password, &token)
            .unwrap();

        let cache_dir = temp.path().join("cache");
        fs::create_dir(&cache_dir).unwrap();
        fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let cache = Cache::open(&cache_dir, 64 * 1024 * 1024).unwrap();
        let online_cache = VaultOfflineCache::new(cache.clone(), scope.clone(), "/").unwrap();
        let client = OpenCloudClient::new(&origin, "synthetic-token".into()).unwrap();
        let online_backend = VaultBackend::new_with_offline_cache(
            client,
            Arc::clone(&initial_sessions),
            scope.clone(),
            "/".into(),
            online_cache,
        )
        .unwrap();
        let pin = online_backend
            .pin_offline_tree(None, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(pin.state, raiun_cache::CiphertextPinState::Ready);
        initial_sessions.lock(&scope).unwrap();

        let first_sessions = Arc::new(VaultSessionCoordinator::new());
        let mut password = b"potato".to_vec();
        let snapshot = VaultOfflineCache::unlock_cached_pin_root(
            &cache,
            &first_sessions,
            &scope,
            &pin.id,
            &mut password,
        )
        .unwrap();
        let client = OpenCloudClient::new(&origin, "expired-synthetic-token".into()).unwrap();
        let backend = new_offline_overwrite_backend(
            client,
            Arc::clone(&first_sessions),
            cache.clone(),
            scope.clone(),
            "/",
            Some(&pin.id),
            snapshot,
        )
        .unwrap();
        let journal =
            VaultOfflineCache::new_for_pin(cache.clone(), scope.clone(), "/", &pin.id).unwrap();
        let control = VaultRouteControl::new();
        control
            .install_existing_file_overwrite_backend(backend)
            .unwrap();
        assert!(control.supports_file_renames().unwrap());
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    scope.space_id().into(),
                    "/".into(),
                    scope.resource_id().into(),
                    control.clone(),
                )
                .unwrap(),
            )
            .unwrap();
        let engine = Engine::open(
            &temp.path().join("engine-one"),
            Arc::new(OfflineWholeSpaceFixture),
        )
        .unwrap();
        let first_mount_root = temp.path().join("mount-one");
        fs::create_dir(&first_mount_root).unwrap();
        let first_mount = mount_with_vault_registry(
            engine,
            &first_mount_root,
            &temp.path().join("provider-one"),
            registry,
        )
        .unwrap();

        fixture.disconnect(true);
        let cloud_root = first_mount_root.join("Spaces/Offline Projects");
        let original = cloud_root.join("Folder/before.txt");
        assert_eq!(fs::read(&original).unwrap(), plaintext);
        fs::remove_file(&original).expect("offline file delete is durably queued");
        assert!(!original.exists());
        assert_eq!(
            fixture.delete_count(),
            0,
            "offline delete must not reach the server"
        );
        let (pending, _) = journal.pending_edits(&first_sessions, None, 16).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].operation,
            raiun_opencloud::vault_cache::VaultPendingOperationKind::DeleteFile
        );
        assert_eq!(
            pending[0].base_resource_id, "source-file-id",
            "rename journal is bound to the original resource"
        );
        assert_eq!(pending[0].base_etag, "\"source-v1\"");
        assert_eq!(pending[0].parent_resource_id, "folder-id");
        assert_eq!(pending[0].parent_etag, "\"folder-v1\"");
        assert!(
            !pending[0].source_ciphertext_sha256.is_empty(),
            "delete journal retains a verifiable encrypted recovery reference"
        );
        assert_eq!(pending[0].source_size, plaintext.len() as u64);
        let operation_id = pending[0].id.clone();
        let operation_revision = pending[0].revision;
        drop(first_mount);
        assert!(fs::read_dir(&first_mount_root).unwrap().next().is_none());
        first_sessions.lock(&scope).unwrap();

        let restarted_sessions = Arc::new(VaultSessionCoordinator::new());
        let mut password = b"potato".to_vec();
        let snapshot = VaultOfflineCache::unlock_cached_pin_root(
            &cache,
            &restarted_sessions,
            &scope,
            &pin.id,
            &mut password,
        )
        .unwrap();
        let client = OpenCloudClient::new(&origin, "expired-synthetic-token".into()).unwrap();
        let backend = new_offline_overwrite_backend(
            client,
            Arc::clone(&restarted_sessions),
            cache.clone(),
            scope.clone(),
            "/",
            Some(&pin.id),
            snapshot,
        )
        .unwrap();
        let control = VaultRouteControl::new();
        control
            .install_existing_file_overwrite_backend(backend)
            .unwrap();
        let registry = VaultMountRegistry::new();
        registry
            .register(
                VaultMountRoute::new(
                    scope.space_id().into(),
                    "/".into(),
                    scope.resource_id().into(),
                    control.clone(),
                )
                .unwrap(),
            )
            .unwrap();
        let engine = Engine::open(
            &temp.path().join("engine-two"),
            Arc::new(OfflineWholeSpaceFixture),
        )
        .unwrap();
        let second_mount_root = temp.path().join("mount-two");
        fs::create_dir(&second_mount_root).unwrap();
        let second_mount = mount_with_vault_registry(
            engine,
            &second_mount_root,
            &temp.path().join("provider-two"),
            registry,
        )
        .unwrap();
        let restarted_cloud_root = second_mount_root.join("Spaces/Offline Projects");
        assert!(
            !restarted_cloud_root.join("Folder/before.txt").exists(),
            "the durable tombstone remains hidden after restart"
        );
        drop(second_mount);
        assert!(fs::read_dir(&second_mount_root).unwrap().next().is_none());
        restarted_sessions.lock(&scope).unwrap();

        fixture.disconnect(false);
        let online_sessions = Arc::new(VaultSessionCoordinator::new());
        let mut password = b"potato".to_vec();
        online_sessions
            .unlock(&scope, &mut password, &token)
            .unwrap();
        let online_cache = VaultOfflineCache::new(cache.clone(), scope.clone(), "/").unwrap();
        let client = OpenCloudClient::new(&origin, "synthetic-token".into()).unwrap();
        let online_backend = VaultBackend::new_with_offline_cache(
            client,
            Arc::clone(&online_sessions),
            scope.clone(),
            "/".into(),
            online_cache,
        )
        .unwrap();
        online_backend
            .reconcile_pending_delete(&operation_id, operation_revision)
            .expect("reconcile conditional DELETE after exact offline restart");
        assert_eq!(
            fixture.delete_count(),
            1,
            "one conditional DELETE is sufficient"
        );
        assert!(
            online_backend
                .stat("space-a", "/Folder/before.txt")
                .is_err()
        );
        let (remaining, _) = VaultOfflineCache::new(cache, scope, "/")
            .unwrap()
            .pending_edits(&online_sessions, None, 16)
            .unwrap();
        assert!(
            remaining.is_empty(),
            "verified DELETE retires its operation"
        );
    }
}

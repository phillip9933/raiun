//! Cached-only producer admission. The original opaque epoch is supplied by
//! the live native route; no serialized history can reconstruct this request.
use super::*;
use raiun_vault::session::VaultSessionEpoch;

pub struct VaultCachedChildTarget {
    path: String,
    encoded: String,
    integrity: String,
    parent: RemoteEntry,
    parent_ref: VaultPendingParentRef,
    directory: bool,
    epoch: VaultSessionEpoch,
}
impl VaultCachedChildTarget {
    pub fn encoded_target(&self) -> &str {
        &self.encoded
    }
    pub fn integrity_token(&self) -> &str {
        &self.integrity
    }
}
impl VaultBackend {
    pub fn cached_pending_operation(
        &self,
        id: &str,
        revision: u64,
        epoch: &VaultSessionEpoch,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        self.cached_namespace_current(epoch, cancelled)?;
        let cache = self
            .offline_cache
            .as_ref()
            .ok_or_else(|| conflict("encrypted journal is unavailable"))?;
        let result = cache.pending_operation(&self.sessions, id, revision)?;
        self.cached_namespace_current(epoch, cancelled)?;
        Ok(result)
    }

    pub fn cached_parent_ref(
        &self,
        parent: &RemoteEntry,
        epoch: &VaultSessionEpoch,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<VaultPendingParentRef, CloudError> {
        self.cached_namespace_current(epoch, cancelled)?;
        if !parent.directory {
            return Err(conflict("cached destination parent is not a directory"));
        }
        let current = self.stat(self.scope.space_id(), &parent.path)?;
        if current.id != parent.id || current.path != parent.path || current.etag != parent.etag {
            return Err(conflict("cached destination parent changed"));
        }
        let result = self.parent_ref_for_directory(&parent.path, &parent.id, &parent.etag)?;
        self.cached_namespace_current(epoch, cancelled)?;
        Ok(result)
    }

    /// Admit a clean cached FILE rename only for the live original unlock.
    /// The returned queued entry is local journal history, never a MOVE proof.
    pub fn queue_cached_file_rename(
        &self,
        from: &str,
        to: &str,
        source_id: &str,
        source_etag: &str,
        epoch: &VaultSessionEpoch,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<VaultRenameOutcome, CloudError> {
        self.cached_namespace_current(epoch, cancelled)?;
        let result = self.rename_file_with_queue(from, to, source_id, source_etag)?;
        self.cached_namespace_current(epoch, cancelled)?;
        match result {
            VaultRenameOutcome::Queued {
                uncertain: false, ..
            } => Ok(result),
            _ => Err(conflict("cached rename did not remain local")),
        }
    }

    /// Admit a clean cached FILE delete with ciphertext-only retained recovery.
    /// This never grants remote or native completion authority.
    pub fn queue_cached_file_delete(
        &self,
        path: &str,
        source_id: &str,
        source_etag: &str,
        epoch: &VaultSessionEpoch,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<VaultDeleteOutcome, CloudError> {
        self.cached_namespace_current(epoch, cancelled)?;
        let result = self.delete_file_with_queue(path, source_id, source_etag)?;
        self.cached_namespace_current(epoch, cancelled)?;
        match result {
            VaultDeleteOutcome::Queued {
                uncertain: false, ..
            } => Ok(result),
            _ => Err(conflict("cached delete did not remain local")),
        }
    }

    /// Change only the sealed target of a never-attempted local FILE create.
    pub fn retarget_cached_file_create(
        &self,
        from: &str,
        to: &str,
        source_id: &str,
        source_etag: &str,
        destination_parent_ref: &VaultPendingParentRef,
        epoch: &VaultSessionEpoch,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<VaultPendingEditMetadata, CloudError> {
        self.cached_namespace_current(epoch, cancelled)?;
        let result = self.rename_pending_create_with_queue(
            from,
            to,
            source_id,
            source_etag,
            destination_parent_ref,
        )?;
        self.cached_namespace_current(epoch, cancelled)?;
        Ok(result)
    }

    /// Atomically retarget at most 64 never-attempted rows / 64 MiB.
    pub fn retarget_cached_directory_subtree(
        &self,
        from: &str,
        to: &str,
        source_id: &str,
        source_etag: &str,
        destination_parent_ref: &VaultPendingParentRef,
        epoch: &VaultSessionEpoch,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<VaultPendingDirectorySubtreeRetarget, CloudError> {
        self.cached_namespace_current(epoch, cancelled)?;
        let result = self.retarget_never_attempted_directory_subtree_with_queue(
            from,
            to,
            source_id,
            source_etag,
            destination_parent_ref,
        )?;
        self.cached_namespace_current(epoch, cancelled)?;
        Ok(result)
    }

    pub fn prepare_cached_child_create(
        &self,
        path: &str,
        parent: &RemoteEntry,
        directory: bool,
        epoch: &VaultSessionEpoch,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<VaultCachedChildTarget, CloudError> {
        self.cached_namespace_current(epoch, cancelled)?;
        let path = normalize_virtual_path(path)?;
        validate_virtual_path(&path)?;
        if !parent.directory || parent.path != logical_parent(&path) {
            return Err(conflict("cached create parent changed"));
        }
        let parent_ref = self.parent_ref_for_directory(&parent.path, &parent.id, &parent.etag)?;
        let actual = self.stat(self.scope.space_id(), &parent.path)?;
        if actual.id != parent.id
            || actual.path != parent.path
            || actual.etag != parent.etag
            || !actual.directory
        {
            return Err(conflict("cached create parent changed"));
        }
        let encoded = if directory {
            self.prepare_directory_create_target_for_parent(&path, &parent_ref)?
        } else {
            self.prepare_file_create_target_for_parent(&path, &parent_ref, None)?
        };
        let integrity = self
            .offline_cache
            .as_ref()
            .ok_or_else(|| conflict("encrypted journal is unavailable"))?
            .cached_root_snapshot(&self.sessions)?
            .integrity_token;
        self.cached_namespace_current(epoch, cancelled)?;
        Ok(VaultCachedChildTarget {
            path: path.into(),
            encoded,
            integrity,
            parent: parent.clone(),
            parent_ref,
            directory,
            epoch: epoch.clone(),
        })
    }
    pub fn queue_cached_child_create<R: Read>(
        &self,
        target: VaultCachedChildTarget,
        source: &mut R,
        length: u64,
        sha: [u8; 32],
        epoch: &VaultSessionEpoch,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<VaultUploadOutcome, CloudError> {
        self.cached_namespace_current(epoch, cancelled)?;
        if !target.epoch.same_identity(epoch)
            || (target.directory && length != 0)
            || length > MAX_VAULT_PLAINTEXT_BYTES
        {
            return Err(conflict("cached create source changed"));
        }
        let refreshed = self.prepare_cached_child_create(
            &target.path,
            &target.parent,
            target.directory,
            epoch,
            cancelled,
        )?;
        if refreshed.encoded != target.encoded
            || refreshed.integrity != target.integrity
            || refreshed.parent_ref != target.parent_ref
        {
            return Err(conflict("cached create target changed"));
        }
        let cache = self
            .offline_cache
            .as_ref()
            .ok_or_else(|| conflict("encrypted journal is unavailable"))?;
        let (parent_id, parent_etag) = match &target.parent_ref {
            VaultPendingParentRef::Stable { .. } => (
                Some(target.parent.id.as_str()),
                Some(target.parent.etag.as_str()),
            ),
            VaultPendingParentRef::PendingCreate { .. } => (None, None),
        };
        let metadata = cache.queue_create_reader(
            &self.sessions,
            epoch,
            source,
            VaultPendingCreateRequest {
                integrity_token: &target.integrity,
                encoded_target: &target.encoded,
                existing_id: None,
                parent_resource_id: parent_id,
                parent_etag,
                parent_ref: &target.parent_ref,
                body_len: length,
                state: CiphertextWriteState::NeverAttempted,
            },
            target.directory,
            sha,
            cancelled,
        )?;
        self.cached_namespace_current(epoch, cancelled)?;
        let entry = if target.directory {
            pending_directory_entry(&metadata)
        } else {
            pending_create_entry(&metadata)
        };
        Ok(VaultUploadOutcome::QueuedCreate {
            entry,
            write_id: metadata.id,
            revision: metadata.revision,
            uncertain: false,
        })
    }
    fn cached_namespace_current(
        &self,
        epoch: &VaultSessionEpoch,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), CloudError> {
        if !self.offline_only || !self.client.is_offline() || cancelled() {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "cached vault authority changed",
            ));
        }
        self.sessions
            .with_session_epoch(&self.scope, epoch, || ())
            .map_err(vault_error)
    }
}

/// Local immutable lineage witness. The original epoch stays live-only.
pub struct VaultCachedEditTarget {
    current: RemoteEntry,
    original: Option<RemoteEntry>,
    pending: Option<VaultPendingEditMetadata>,
    encoded: String,
    integrity: String,
    epoch: VaultSessionEpoch,
}
impl VaultCachedEditTarget {
    pub fn current(&self) -> &RemoteEntry {
        &self.current
    }
    pub fn original_base(&self) -> Option<&RemoteEntry> {
        self.original.as_ref()
    }
    pub fn pending(&self) -> Option<&VaultPendingEditMetadata> {
        self.pending.as_ref()
    }
}
impl VaultBackend {
    pub fn prepare_cached_edit_capture(
        &self,
        expected: &RemoteEntry,
        epoch: &VaultSessionEpoch,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<VaultCachedEditTarget, CloudError> {
        self.cached_namespace_current(epoch, cancelled)?;
        let current = self.stat(self.scope.space_id(), &expected.path)?;
        if current.directory
            || current.id != expected.id
            || current.path != expected.path
            || current.etag != expected.etag
            || current.size != expected.size
        {
            return Err(conflict("cached edit current identity changed"));
        }
        let cache = self
            .offline_cache
            .as_ref()
            .ok_or_else(|| conflict("encrypted journal is unavailable"))?;
        let pending = match self.pending_edit_for_path(&current.path)? {
            Some(row) => Some(cache.pending_operation(&self.sessions, &row.id, row.revision)?),
            None => None,
        };
        let (original, encoded) = match &pending {
            Some(p)
                if p.operation == VaultPendingOperationKind::CreateFile
                    && p.state == CiphertextWriteState::NeverAttempted
                    && current == pending_create_entry(p) =>
            {
                (None, p.encoded_target.clone())
            }
            Some(p)
                if p.operation == VaultPendingOperationKind::Overwrite
                    && p.state == CiphertextWriteState::Pending
                    && current.id == p.base_resource_id
                    && current.etag == pending_etag(&p.id, p.revision)
                    && current.size == p.plaintext_len =>
            {
                let original = self.cached_base_entry(
                    &current.path,
                    &WriteCondition::Match(p.base_etag.clone()),
                )?;
                if original.id != p.base_resource_id {
                    return Err(conflict("cached edit original identity changed"));
                }
                (Some(original), p.encoded_target.clone())
            }
            None => {
                let original = self.cached_base_entry(
                    &current.path,
                    &WriteCondition::Match(current.etag.clone()),
                )?;
                if original.id != current.id || original.size != current.size {
                    return Err(conflict("cached edit original identity changed"));
                }
                let encoded = self.prepare_write_target(
                    &current.path,
                    &WriteCondition::Match(current.etag.clone()),
                )?;
                (Some(original), encoded)
            }
            _ => return Err(conflict("cached edit lineage requires review")),
        };
        let integrity = cache.cached_root_snapshot(&self.sessions)?.integrity_token;
        self.cached_namespace_current(epoch, cancelled)?;
        Ok(VaultCachedEditTarget {
            current,
            original,
            pending,
            encoded,
            integrity,
            epoch: epoch.clone(),
        })
    }
    pub fn queue_cached_capture_reader<R: Read>(
        &self,
        target: VaultCachedEditTarget,
        source: &mut R,
        length: u64,
        sha: [u8; 32],
        epoch: &VaultSessionEpoch,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<VaultUploadOutcome, CloudError> {
        self.cached_namespace_current(epoch, cancelled)?;
        if !target.epoch.same_identity(epoch) {
            return Err(conflict("cached edit unlock changed"));
        }
        let fresh = self.prepare_cached_edit_capture(&target.current, epoch, cancelled)?;
        if fresh.pending != target.pending
            || fresh.original != target.original
            || fresh.encoded != target.encoded
            || fresh.integrity != target.integrity
        {
            return Err(conflict("cached edit lineage changed"));
        }
        let cache = self
            .offline_cache
            .as_ref()
            .ok_or_else(|| conflict("encrypted journal is unavailable"))?;
        let metadata = if let Some(p) = target
            .pending
            .as_ref()
            .filter(|p| p.operation == VaultPendingOperationKind::CreateFile)
        {
            cache.queue_create_reader_existing(
                &self.sessions,
                epoch,
                source,
                VaultPendingCreateRequest {
                    integrity_token: &target.integrity,
                    encoded_target: &target.encoded,
                    existing_id: Some(&p.id),
                    parent_resource_id: (!p.parent_resource_id.is_empty())
                        .then_some(p.parent_resource_id.as_str()),
                    parent_etag: (!p.parent_etag.is_empty()).then_some(p.parent_etag.as_str()),
                    parent_ref: p
                        .parent_ref
                        .as_ref()
                        .ok_or_else(|| conflict("cached create parent is missing"))?,
                    body_len: length,
                    state: CiphertextWriteState::NeverAttempted,
                },
                false,
                sha,
                cancelled,
                Some(p.revision),
            )?
        } else {
            let original = target
                .original
                .as_ref()
                .ok_or_else(|| conflict("cached edit original is missing"))?;
            cache.queue_edit_reader_exact(
                &self.sessions,
                epoch,
                source,
                VaultPendingEditRequest {
                    integrity_token: &target.integrity,
                    encoded_target: &target.encoded,
                    base_resource_id: &original.id,
                    base_etag: &original.etag,
                    existing_id: target.pending.as_ref().map(|p| p.id.as_str()),
                    body_len: length,
                },
                sha,
                cancelled,
                target.pending.as_ref().map(|p| p.revision),
            )?
        };
        self.cached_namespace_current(epoch, cancelled)?;
        let entry = if metadata.operation == VaultPendingOperationKind::CreateFile {
            pending_create_entry(&metadata)
        } else {
            let mut entry = target
                .original
                .ok_or_else(|| conflict("cached edit original is missing"))?;
            entry.size = length;
            entry.etag = pending_etag(&metadata.id, metadata.revision);
            entry
        };
        Ok(VaultUploadOutcome::Queued {
            entry,
            write_id: metadata.id,
            revision: metadata.revision,
            uncertain: false,
        })
    }
}

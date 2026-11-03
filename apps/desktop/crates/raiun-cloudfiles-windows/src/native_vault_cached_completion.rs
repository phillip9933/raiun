//! Original live connection readback after an SDK-minted guarded remote proof.
//! Queued metadata alone never enters this native completion path.
use super::*;
use raiun_opencloud::vault_backend::VaultReconciledPending;
use raiun_opencloud::vault_cache::VaultPendingOperationKind;

impl ConfiguredRootConnection {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn complete_cached_vault_pending(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        route: &Arc<crate::vault_routes::VerifiedVaultRoute>,
        proof: &VaultReconciledPending,
        expected: &crate::VaultCachedNativeExpectation,
        provider: &Arc<AtomicU64>,
        provider_generation: u64,
    ) -> Result<crate::VaultCachedNativeCompleted, Error> {
        let no = || Error::EditRecoveryUnavailable;
        let erased: Arc<dyn PlaceholderBackend> = backend.clone();
        if !self.connected
            || !Arc::ptr_eq(&erased, &self.state.backend)
            || self.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
            || expected.root != route.local_root()
            || expected.identity == [0; 16]
            || expected.file == 0
            || expected.usn <= 0
            || expected.revision == 0
            || expected.write_id.is_empty()
            || expected.components.len() < 2
            || expected.components.len() > 256
            || expected.components.iter().any(|p| !valid_component(p))
            || !route.backend().binding().matches_cached_reconciliation(
                proof,
                provider,
                provider_generation,
            )
        {
            return Err(no());
        }
        let current = backend
            .verified_vault_copy_route(
                expected.root,
                route.space_id(),
                route.root_resource_id(),
                route.root_path(),
            )
            .map_err(|_| no())?;
        if !Arc::ptr_eq(&current, route) {
            return Err(no());
        }
        let m = proof.metadata();
        if m.id != expected.write_id
            || m.revision != expected.revision
            || m.plaintext_len != expected.plaintext_len
            || proof.plaintext_len() != expected.plaintext_len
            || expected.operation != m.operation
            || proof.entry().is_none() != expected.entry.is_none()
            || expected.original.as_ref().is_some_and(|original| {
                original.path != m.path || original.id != m.base_resource_id
            })
        {
            return Err(no());
        }
        if let Some(entry) = expected.entry.as_ref() {
            let path = if m.operation == VaultPendingOperationKind::RenameFile {
                &m.destination_path
            } else {
                &m.path
            };
            if &entry.path != path {
                return Err(no());
            }
        } else if expected.original.is_none() {
            return Err(no());
        }
        if let Some(pending) = expected.entry.as_ref() {
            let verified = proof.entry().ok_or_else(no)?;
            if pending.path != verified.path
                || pending.directory != verified.directory
                || pending.size != verified.size
                || !verified.etag.starts_with('"')
                || !verified.etag.ends_with('"')
                || (m.operation == VaultPendingOperationKind::RenameFile
                    && pending.id != verified.id)
            {
                return Err(no());
            }
        }
        let root = self.root.as_ref().ok_or_else(no)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let lease = pin_registered_configured_root(&root.path, expected.root)?;
        let mut target = root.path.clone();
        for part in &expected.components {
            target.push(part);
        }
        if expected.entry.is_none() {
            if !native_vault_file_rename::absent(&target)? {
                return Err(no());
            }
            native_namespace_directory::verify_reinspected_namespace_root(&lease, &root.path)?;
            return Ok(crate::VaultCachedNativeCompleted {
                write_id: expected.write_id.clone(),
                revision: expected.revision,
                identity: expected.identity,
                file: expected.file,
                usn: expected.usn,
                entry: None,
            });
        }
        let pending = expected.entry.as_ref().ok_or_else(no)?;
        let protected = ProtectedCompletionFile::open_for_cleanup(&wide_path(&target)?)?;
        let snapshot = root_snapshot(protected.raw)?;
        if snapshot.identity.volume_serial != expected.root.volume_serial
            || snapshot.identity.file_index != expected.file
            || snapshot.file_size != expected.plaintext_len
            || (snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != pending.directory
            || snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            || !cleanup_cloud_reparse_tag(snapshot.reparse_tag)
            || snapshot.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
            || snapshot.placeholder_state & CF_PLACEHOLDER_STATE_IN_SYNC != 0
            || snapshot.placeholder_state & CF_PLACEHOLDER_STATE_SYNC_ROOT != 0
            || completion_usn(protected.raw, expected.file)? != expected.usn
            || native_namespace_directory::opaque_directory_identity(protected.raw)?
                != expected.identity
            || !windows_paths_equal(
                &final_path_for_handle(protected.raw).map_err(|_| no())?,
                &target,
            )
        {
            return Err(no());
        }
        if !pending.directory {
            let digest = proof
                .plaintext_sha256()
                .or(expected.source_sha256)
                .ok_or_else(no)?;
            let mut hash = Sha256::new();
            let mut offset = 0u64;
            let mut bytes = Zeroizing::new(vec![0u8; 64 * 1024]);
            while offset < expected.plaintext_len {
                let len =
                    usize::try_from((expected.plaintext_len - offset).min(bytes.len() as u64))
                        .map_err(|_| no())?;
                protected.read_complete_at(offset, &mut bytes[..len])?;
                hash.update(&bytes[..len]);
                offset += len as u64;
            }
            let actual: [u8; 32] = hash.finalize().into();
            if actual != digest
                || proof.plaintext_sha256().is_some_and(|remote| {
                    expected.source_sha256.is_some_and(|local| local != remote)
                })
            {
                return Err(no());
            }
        }
        if completion_usn(protected.raw, expected.file)? != expected.usn
            || native_namespace_directory::opaque_directory_identity(protected.raw)?
                != expected.identity
        {
            return Err(no());
        }
        native_namespace_directory::verify_reinspected_namespace_root(&lease, &root.path)?;
        let mut usn = expected.usn;
        let hr = unsafe { CfSetInSyncState(protected.protected, 1, 0, &mut usn) };
        if hr < 0 || usn < expected.usn {
            return Err(no());
        }
        let after = root_snapshot(protected.raw)?;
        if after.identity != snapshot.identity
            || after.file_size != snapshot.file_size
            || after.placeholder_state & CF_PLACEHOLDER_STATE_IN_SYNC == 0
            || completion_usn(protected.raw, expected.file)? != usn
            || native_namespace_directory::opaque_directory_identity(protected.raw)?
                != expected.identity
        {
            return Err(no());
        }
        Ok(crate::VaultCachedNativeCompleted {
            write_id: expected.write_id.clone(),
            revision: expected.revision,
            identity: expected.identity,
            file: expected.file,
            usn,
            entry: proof.entry().cloned(),
        })
    }
}

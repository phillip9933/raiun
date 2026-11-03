//! Native admission of protected current cached rows on a retained root.
//! This never turns a queued row into clean history or cleanup authority.
use super::*;
use crate::vault_custody::VaultPendingNativeIntent;

pub(super) fn inspect(
    root: &OwnedConfiguredRoot,
    expected: crate::ConfiguredRootIdentity,
    row: &VaultPendingNativeIntent,
) -> Result<(), Error> {
    let no = || Error::EditRecoveryUnavailable;
    if row.identity == [0; 16]
        || row.file_index == 0
        || row.usn <= 0
        || row.revision == 0
        || row.write_id.is_empty()
        || row.components.len() < 2
        || row.components.len() > 256
        || row.components.iter().any(|s| !valid_component(s))
        || row.length > MAX_FILE_BYTES
    {
        return Err(no());
    }
    let lease = pin_registered_configured_root(&root.path, expected)?;
    let mut path = root.path.clone();
    // Pin every parent without following reparse points; retain these handles
    // through the final object or absence inspection.
    let mut parents = Vec::with_capacity(row.components.len() - 1);
    for part in &row.components[..row.components.len() - 1] {
        path.push(part);
        let raw = unsafe {
            CreateFileW(
                wide_path(&path)?.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(no());
        }
        let handle = RawOwnedHandle(raw);
        let snapshot = root_snapshot(handle.0)?;
        if snapshot.identity.volume_serial != expected.volume_serial
            || snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || !valid_callback_directory_snapshot(snapshot)
            || !windows_paths_equal(&final_path_for_handle(handle.0).map_err(|_| no())?, &path)
        {
            return Err(no());
        }
        parents.push(handle);
    }
    path.push(row.components.last().ok_or_else(no)?);
    match row.entry.as_ref() {
        None => {
            // The deleted source's historical length/hash may be retained as
            // journal evidence; absence cannot prove or disprove those bytes.
            if !native_vault_file_rename::absent(&path)? {
                return Err(no());
            }
        }
        Some(entry) if entry.directory => {
            if row.length != 0 || row.source_sha256.is_some() {
                return Err(no());
            }
            let raw = unsafe {
                CreateFileW(
                    wide_path(&path)?.as_ptr(),
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    null_mut(),
                )
            };
            if raw.is_null() || raw == INVALID_HANDLE_VALUE {
                return Err(no());
            }
            let handle = RawOwnedHandle(raw);
            let snapshot = root_snapshot(handle.0)?;
            if snapshot.identity.volume_serial != expected.volume_serial
                || snapshot.identity.file_index != row.file_index
                || snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
                || !valid_callback_directory_snapshot(snapshot)
                || (snapshot.placeholder_state & CF_PLACEHOLDER_STATE_IN_SYNC != 0)
                    != row.terminal_verified
                || completion_usn(handle.0, row.file_index)? != row.usn
                || native_namespace_directory::opaque_directory_identity(handle.0)? != row.identity
                || !windows_paths_equal(&final_path_for_handle(handle.0).map_err(|_| no())?, &path)
            {
                return Err(no());
            }
        }
        Some(entry) => {
            if entry.size != row.length || row.source_sha256.is_none() {
                return Err(no());
            }
            let file = ProtectedCompletionFile::open_for_cleanup(&wide_path(&path)?)?;
            let before = root_snapshot(file.raw)?;
            if before.identity.volume_serial != expected.volume_serial
                || before.identity.file_index != row.file_index
                || before.file_size != row.length
                || before.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
                || before.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                || !cleanup_cloud_reparse_tag(before.reparse_tag)
                || before.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
                || (before.placeholder_state & CF_PLACEHOLDER_STATE_IN_SYNC != 0)
                    != row.terminal_verified
                || completion_usn(file.raw, row.file_index)? != row.usn
                || native_namespace_directory::opaque_directory_identity(file.raw)? != row.identity
                || !windows_paths_equal(&final_path_for_handle(file.raw).map_err(|_| no())?, &path)
            {
                return Err(no());
            }
            let mut hash = Sha256::new();
            let mut bytes = Zeroizing::new(vec![0u8; 64 * 1024]);
            let mut offset = 0u64;
            while offset < row.length {
                let len = usize::try_from((row.length - offset).min(bytes.len() as u64))
                    .map_err(|_| no())?;
                file.read_complete_at(offset, &mut bytes[..len])?;
                hash.update(&bytes[..len]);
                offset += len as u64;
            }
            if <[u8; 32]>::from(hash.finalize()) != row.source_sha256.ok_or_else(no)?
                || !same_edit_snapshot(root_snapshot(file.raw)?, before)
                || completion_usn(file.raw, row.file_index)? != row.usn
                || native_namespace_directory::opaque_directory_identity(file.raw)? != row.identity
            {
                return Err(no());
            }
        }
    }
    native_namespace_directory::verify_reinspected_namespace_root(&lease, &root.path)?;
    Ok(())
}

impl ConfiguredRootConnection {
    /// Clean only disjoint, already published read-only files. Pending rows are
    /// retained in place and never passed through clean dehydration. The
    /// ordinary connection disconnect subsequently leaves registration live.
    pub(crate) fn cleanup_clean_history_preserving_cached_pending(
        &self,
        route_root: crate::ConfiguredRootIdentity,
        route_owned: &std::collections::BTreeSet<[u8; 16]>,
        history: &dyn crate::vault_custody::VaultPublishedHistorySource,
        owner: &crate::ProviderScope,
        registration: &str,
    ) -> Result<bool, Error> {
        if !self.audit_cached_pending_for_disconnect(history, owner, registration)? {
            return Ok(false);
        }
        let inventory = self
            .state
            .hydrated_files
            .lock()
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        if !inventory.is_complete() {
            return Err(Error::EditRecoveryUnavailable);
        }
        let clean = inventory.snapshot(route_owned);
        drop(inventory);
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        let identity = crate::ConfiguredRootIdentity {
            volume_serial: root.identity.volume_serial,
            file_index: root.identity.file_index,
        };
        if route_root != identity {
            return Err(Error::ConfiguredRootChanged);
        }
        let current = history
            .current_native_intents(owner, identity, registration)
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        let current_ids = current
            .iter()
            .filter(|row| !row.terminal_verified)
            .map(|row| row.identity)
            .collect::<std::collections::BTreeSet<_>>();
        let clean_ids = clean
            .iter()
            .map(|row| *row.identity())
            .collect::<std::collections::BTreeSet<_>>();
        if clean.iter().any(|row| current_ids.contains(row.identity()))
            || current.iter().any(|row| {
                row.terminal_verified
                    && row.entry.as_ref().is_some_and(|entry| !entry.directory)
                    && route_owned.contains(&row.identity)
                    && !clean_ids.contains(&row.identity)
            })
        {
            return Err(Error::EditRecoveryUnavailable);
        }
        for row in &clean {
            let components = row
                .components()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            self.dehydrate_clean_vault_placeholder_inner(
                &components,
                row.file_index(),
                row.length(),
                row.identity(),
                true,
            )?;
        }
        self.audit_cached_pending_for_disconnect(history, owner, registration)
    }

    /// A factual pre-disconnect audit. It permits retaining a registered root
    /// with known queued bytes; it grants no cleanup or remote authority.
    pub(crate) fn audit_cached_pending_for_disconnect(
        &self,
        history: &dyn crate::vault_custody::VaultPublishedHistorySource,
        owner: &crate::ProviderScope,
        registration: &str,
    ) -> Result<bool, Error> {
        let no = || Error::EditRecoveryUnavailable;
        if !self.connected
            || self.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
            || self.state.non_vault_modified_closes.load(Ordering::Acquire) != 0
            || self
                .state
                .unverifiable_placeholder_closes
                .load(Ordering::Acquire)
                != 0
            || self
                .state
                .recovery
                .as_ref()
                .is_some_and(|recovery| recovery.has_unresolved().unwrap_or(true))
        {
            return Err(no());
        }
        let root = self.root.as_ref().ok_or_else(no)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let expected = crate::ConfiguredRootIdentity {
            volume_serial: root.identity.volume_serial,
            file_index: root.identity.file_index,
        };
        let rows = history
            .current_native_intents(owner, expected, registration)
            .map_err(|_| no())?;
        if rows.is_empty() || rows.len() > 100_000 {
            return Ok(false);
        }
        let mut current = std::collections::BTreeMap::new();
        let mut files = std::collections::BTreeSet::new();
        let mut paths = std::collections::BTreeSet::new();
        for row in &rows {
            if current.insert(row.identity, row).is_some()
                || !files.insert(row.file_index)
                || !paths.insert(&row.components)
            {
                return Err(no());
            }
            if !row.terminal_verified {
                inspect(root, expected, row)?;
            }
        }
        let dirty = self
            .state
            .vault_dirty
            .lock()
            .map_err(|_| no())?
            .snapshot_all()
            .map_err(|_| no())?;
        for observed in &dirty {
            let row = current.get(&observed.identity).ok_or_else(no)?;
            if row.terminal_verified
                || row.entry.as_ref().is_none_or(|entry| entry.directory)
                || observed.file.volume_serial != expected.volume_serial
                || observed.file.file_index != row.file_index
                || observed.length != row.length
                || observed.components != row.components
                || row.source_sha256 != Some(observed.sha256)
            {
                return Err(no());
            }
        }
        let known = self.state.known_cached_pending.lock().map_err(|_| no())?;
        for (identity, (write_id, revision, file)) in known.iter() {
            let row = current.get(identity).ok_or_else(no)?;
            if row.terminal_verified
                || row.write_id != *write_id
                || row.revision != *revision
                || row.file_index != *file
            {
                return Err(no());
            }
        }
        root.verify_identity(true)?;
        root.verify_registered()?;
        Ok(rows.iter().any(|row| !row.terminal_verified))
    }

    /// Called only after the Agent has durably recorded this typed native
    /// completion. Exact mismatch never retires another queued identity.
    pub(crate) fn acknowledge_cached_native_durable(
        &self,
        completed: &crate::VaultCachedNativeCompleted,
    ) -> Result<(), Error> {
        let mut rows = self
            .state
            .known_cached_pending
            .lock()
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        if let Some((write_id, revision, file)) = rows.get(&completed.identity) {
            if write_id != &completed.write_id
                || *revision != completed.revision
                || *file != completed.file
                || completed.usn <= 0
            {
                return Err(Error::EditRecoveryUnavailable);
            }
        }
        if let Some(observed) = completed.observed_dirty.as_ref() {
            self.state
                .vault_dirty
                .lock()
                .map_err(|_| Error::EditRecoveryUnavailable)?
                .resolve(observed)
                .map_err(|_| Error::EditRecoveryUnavailable)?;
        }
        rows.remove(&completed.identity);
        Ok(())
    }
}

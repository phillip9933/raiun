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
            rows.remove(&completed.identity);
        }
        Ok(())
    }
}

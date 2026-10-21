//! Fresh bounded ordinary-folder manifests and pin-bound content acquisition.
use super::*;
use raiun_cache::{CacheScope, PinInfo, PinManifestEntry, PinState, ScopeProtection};
use std::collections::HashSet;

const MAX_FOLDER_ITEMS: usize = 10_000;
const MAX_FOLDER_DEPTH: usize = 128;
const MAX_FOLDER_METADATA_BYTES: usize = 16 * 1024 * 1024;

/// An already admitted ordinary directory, scoped by the authenticated owner.
/// This tuple carries no origin, account, local path or callback authority.
pub struct FolderCacheBindingExpectation<'a> {
    pub space_id: &'a str,
    pub root_resource_id: &'a str,
    pub path: &'a str,
    pub resource_id: &'a str,
}

impl OpenCloudPlaceholderBackend {
    pub(super) fn resolve_folder_binding(
        &self,
        expected: &FolderCacheBindingExpectation<'_>,
        cancellation: &CancellationToken,
    ) -> Result<(OpaqueIdentity, DirectoryBinding), BackendError> {
        check_cancel(cancellation)?;
        self.catalog_scope_snapshot()?
            .ok_or(BackendError::Unavailable)?;
        if !valid_remote_path(
            expected.space_id,
            expected.root_resource_id,
            expected.path,
            true,
        ) || !valid_remote_id(expected.resource_id)
            || !valid_remote_id(expected.root_resource_id)
        {
            return Err(BackendError::NotFound);
        }
        let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
        let mut found = None;
        for (identity, binding) in &state.directories {
            check_cancel(cancellation)?;
            if binding.space_id == expected.space_id
                && binding.root_resource_id == expected.root_resource_id
                && binding.path == expected.path
                && binding.remote_id == expected.resource_id
            {
                if found.is_some() {
                    return Err(BackendError::Unavailable);
                }
                found = Some((*identity, binding.clone()));
            }
        }
        found.ok_or(BackendError::NotFound)
    }

    fn check_folder_identity(
        &self,
        directory: &DirectoryBinding,
        cancellation: &CancellationToken,
    ) -> Result<(), BackendError> {
        check_cancel(cancellation)?;
        self.ensure_active()?;
        let context = RangeReadContext {
            deadline: cancellation.request_deadline(),
            token_generation: self.token_generation,
        };
        for (path, id) in [
            ("/", directory.root_resource_id.as_str()),
            (directory.path.as_str(), directory.remote_id.as_str()),
        ] {
            let entry = self
                .client
                .stat_with_context(&directory.space_id, path, context)
                .map_err(|error| self.reject_cached_cloud_error(error))?;
            if !entry.directory || entry.encrypted || entry.id != id {
                return Err(BackendError::Unavailable);
            }
            check_cancel(cancellation)?;
            self.ensure_active()?;
        }
        Ok(())
    }

    /// Fetch a complete fresh tree, persist its pin, then acquire exact member
    /// versions through the existing guarded transport. No cached listing can
    /// establish a new folder snapshot. Progress first exposes the durable ID;
    /// later failure/cancellation preserves that pin and all verified content.
    /// Listings are successive observations, not one atomic remote revision.
    /// This performs no cloud writes and does not resume uncertain stage bytes.
    pub fn pin_folder_offline_for_binding(
        &self,
        expected: &FolderCacheBindingExpectation<'_>,
        cancellation: &CancellationToken,
        progress: impl FnMut(PinInfo),
    ) -> Result<PinInfo, OfflineDownloadError> {
        self.pin_folder_snapshot(expected, None, None, cancellation, progress)
    }

    /// Retry the exact unchanged Building pin after obtaining a complete fresh
    /// tree. Never allocates another pin or mutates a Ready/stale snapshot. A
    /// changed tree requires a separately staged explicit refresh. Callers must
    /// serialize folder jobs and retain the durable pin ID across cancellation.
    pub fn resume_folder_offline_for_binding(
        &self,
        expected: &FolderCacheBindingExpectation<'_>,
        pin_id: &str,
        cancellation: &CancellationToken,
        progress: impl FnMut(PinInfo),
    ) -> Result<PinInfo, OfflineDownloadError> {
        self.pin_folder_snapshot(expected, Some(pin_id), None, cancellation, progress)
    }

    /// Refresh an existing Ready/Stale snapshot using a separately retained
    /// staging pin. Capture active metadata before network work so a concurrent
    /// newer refresh cannot be overwritten. Failure before local replacement
    /// commits preserves both snapshots. A final auth/root check may fail after
    /// that commit; the durable active ID then remains the reconciliation target.
    /// A supplied staging ID retries only its exact unchanged Building/Ready
    /// manifest; cached readiness inspection may have promoted the stage.
    /// Callers must serialize jobs for the provider binding/generation.
    pub fn refresh_folder_offline_for_binding(
        &self,
        expected: &FolderCacheBindingExpectation<'_>,
        active_pin_id: &str,
        staging_pin_id: Option<&str>,
        cancellation: &CancellationToken,
        mut progress: impl FnMut(PinInfo),
    ) -> Result<PinInfo, OfflineDownloadError> {
        let cache = self.cache.as_ref().ok_or(BackendError::Unavailable)?;
        let (identity, selected) = {
            let _lease = self
                .lease_gate
                .read()
                .map_err(|_| BackendError::Unavailable)?;
            self.ensure_active()?;
            self.resolve_folder_binding(expected, cancellation)?
        };
        let scope = CacheScope::new(
            self.scope.server_origin(),
            self.scope.account_id(),
            &selected.space_id,
            &selected.root_resource_id,
            ScopeProtection::PlaintextAllowed,
        )
        .map_err(|_| BackendError::Unavailable)?;
        let roles = cache
            .folder_pin_roles(&scope, &selected.remote_id, &selected.path)
            .map_err(folder_cache_error)?
            .ok_or(BackendError::Unavailable)?;
        if roles.active_pin_id.as_deref() != Some(active_pin_id)
            || roles.staging_pin_id.as_deref() != staging_pin_id
        {
            return Err(BackendError::Unavailable.into());
        }
        let active = cache
            .pin_refresh_expectation(&scope, active_pin_id, &selected.remote_id, &selected.path)
            .map_err(folder_cache_error)?;
        let staged = self.pin_folder_snapshot(
            expected,
            staging_pin_id,
            Some(active_pin_id),
            cancellation,
            &mut progress,
        )?;
        // Verification hashes without an auth/lease guard. Local metadata
        // publication grants no access authority; recheck auth/root afterward.
        let completed = cache
            .replace_pin_snapshot_if_current_cancellable(&scope, &active, &staged.id, || {
                cancellation.is_cancelled()
                    || cancellation.is_expired()
                    || self.revoked.load(Ordering::Acquire)
            })
            .map_err(folder_cache_error)?;
        self.check_folder_identity(&selected, cancellation)?;
        let lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        self.ensure_active()?;
        if self.resolve_folder_binding(expected, cancellation)? != (identity, selected) {
            return Err(BackendError::NotFound.into());
        }
        drop(lease);
        progress(completed.clone());
        Ok(completed)
    }

    fn pin_folder_snapshot(
        &self,
        expected: &FolderCacheBindingExpectation<'_>,
        resume_pin: Option<&str>,
        refresh_active: Option<&str>,
        cancellation: &CancellationToken,
        mut progress: impl FnMut(PinInfo),
    ) -> Result<PinInfo, OfflineDownloadError> {
        let cache = self.cache.as_ref().ok_or(BackendError::Unavailable)?;
        let (identity, selected) = {
            let _lease = self
                .lease_gate
                .read()
                .map_err(|_| BackendError::Unavailable)?;
            self.ensure_active()?;
            self.resolve_folder_binding(expected, cancellation)?
        };
        let scope = CacheScope::new(
            self.scope.server_origin(),
            self.scope.account_id(),
            &selected.space_id,
            &selected.root_resource_id,
            ScopeProtection::PlaintextAllowed,
        )
        .map_err(|_| BackendError::Unavailable)?;
        if let Some(pin_id) = resume_pin
            && refresh_active.is_none()
        {
            let roles = cache
                .folder_pin_roles(&scope, &selected.remote_id, &selected.path)
                .map_err(folder_cache_error)?
                .ok_or(BackendError::Unavailable)?;
            if !roles.staging_is_initial
                || roles.active_pin_id.is_some()
                || roles.staging_pin_id.as_deref() != Some(pin_id)
            {
                return Err(BackendError::Unavailable.into());
            }
        }
        // A non-root selection must still be the exact member of a fresh parent
        // listing; path reuse alone never authorizes pinning a replacement.
        if selected.path != "/" {
            let parent_path = selected
                .path
                .rsplit_once('/')
                .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
                .ok_or(BackendError::NotFound)?;
            let parent = self
                .client
                .stat_with_context(
                    &selected.space_id,
                    parent_path,
                    RangeReadContext {
                        deadline: cancellation.request_deadline(),
                        token_generation: self.token_generation,
                    },
                )
                .map_err(|error| self.reject_cached_cloud_error(error))?;
            if !parent.directory || parent.encrypted {
                return Err(BackendError::Unavailable.into());
            }
            let parent_binding = DirectoryBinding {
                space_id: selected.space_id.clone(),
                root_resource_id: selected.root_resource_id.clone(),
                path: parent_path.into(),
                remote_id: parent.id,
            };
            let entries = self.fresh_directory_entries(&parent_binding, cancellation)?;
            if !entries.iter().any(|(_, entry)| {
                entry.directory
                    && !entry.encrypted
                    && entry.id == selected.remote_id
                    && entry.path == selected.path
            }) {
                return Err(BackendError::NotFound.into());
            }
        }
        let mut pending = vec![(selected.clone(), 0_usize)];
        let mut manifest = Vec::new();
        let mut files = Vec::new();
        let mut seen = HashSet::from([
            selected.remote_id.clone(),
            selected.root_resource_id.clone(),
        ]);
        let mut metadata_bytes = 0_usize;
        while let Some((directory, depth)) = pending.pop() {
            check_cancel(cancellation)?;
            if depth > MAX_FOLDER_DEPTH {
                return Err(BackendError::Unavailable.into());
            }
            let entries = self.fresh_directory_entries(&directory, cancellation)?;
            for (_, entry) in &entries {
                check_cancel(cancellation)?;
                metadata_bytes = metadata_bytes
                    .checked_add(directory.remote_id.len())
                    .and_then(|n| n.checked_add(entry.id.len()))
                    .and_then(|n| n.checked_add(entry.path.len()))
                    .and_then(|n| n.checked_add(entry.etag.len()))
                    .ok_or(BackendError::Unavailable)?;
                if manifest.len() >= MAX_FOLDER_ITEMS
                    || metadata_bytes > MAX_FOLDER_METADATA_BYTES
                    || !seen.insert(entry.id.clone())
                {
                    return Err(BackendError::Unavailable.into());
                }
                manifest.push(PinManifestEntry {
                    parent_resource_id: directory.remote_id.clone(),
                    entry: entry.clone(),
                });
                if entry.directory {
                    pending.push((
                        DirectoryBinding {
                            space_id: directory.space_id.clone(),
                            root_resource_id: directory.root_resource_id.clone(),
                            path: entry.path.clone(),
                            remote_id: entry.id.clone(),
                        },
                        depth + 1,
                    ));
                } else {
                    files.push(entry.clone());
                }
            }
            // Reuse enumeration's catalog admission, including durable identity
            // validation. No network or content hashing runs under this lease.
            let _lease = self
                .lease_gate
                .read()
                .map_err(|_| BackendError::Unavailable)?;
            self.ensure_active()?;
            self.admit_directory_entries(&directory, entries, cancellation)?;
        }
        let pin = {
            let _lease = self
                .lease_gate
                .read()
                .map_err(|_| BackendError::Unavailable)?;
            self.ensure_active()?;
            if self.resolve_folder_binding(expected, cancellation)? != (identity, selected.clone())
            {
                return Err(BackendError::NotFound.into());
            }
            let _publication = self.begin_scoped_publish(cancellation)?;
            // Token generation is already locked by the permit. The probe must
            // use atomics only and must not reenter either auth or cache locks.
            let cancelled = || {
                cancellation.is_cancelled()
                    || cancellation.is_expired()
                    || self.revoked.load(Ordering::Acquire)
            };
            match resume_pin {
                Some(pin_id) if refresh_active.is_some() => cache
                    .resume_staging_pin_manifest_at_cancellable(
                        &scope,
                        pin_id,
                        &selected.remote_id,
                        &selected.path,
                        &manifest,
                        cancelled,
                    ),
                Some(pin_id) => cache.resume_pin_manifest_at_cancellable(
                    &scope,
                    pin_id,
                    &selected.remote_id,
                    &selected.path,
                    &manifest,
                    cancelled,
                ),
                None if refresh_active.is_none() => cache
                    .begin_initial_pin_manifest_at_cancellable(
                        &scope,
                        &selected.remote_id,
                        &selected.path,
                        &manifest,
                        cancelled,
                    ),
                None => cache.begin_folder_refresh_manifest_at_cancellable(
                    &scope,
                    refresh_active.ok_or(BackendError::Unavailable)?,
                    &selected.remote_id,
                    &selected.path,
                    &manifest,
                    cancelled,
                ),
            }
            .map_err(folder_cache_error)?
        };
        progress(pin.clone());
        let mut observed = pin.clone();
        for file in files {
            self.download_pinned_file_offline_for_binding(
                &FileCacheBindingExpectation {
                    space_id: &selected.space_id,
                    root_resource_id: &selected.root_resource_id,
                    path: &file.path,
                    resource_id: &file.id,
                    etag: &file.etag,
                    size: file.size,
                },
                &pin.id,
                cancellation,
            )?;
            observed.ready_content_count += 1;
            // This is verified-member progress, not a Ready folder assertion.
            progress(observed.clone());
        }
        // Hashing keeps no backend lease/auth permit. Ready is local evidence
        // for the exact durable snapshot; it grants no access authority. Active
        // auth/root/catalog checks still gate the successful job result below.
        // The cache holds its DB mutex while probing: never acquire the auth
        // mutex here, since a concurrent publisher holds auth before cache.
        let completed = cache
            .refresh_pin_cancellable(&pin.id, || {
                cancellation.is_cancelled()
                    || cancellation.is_expired()
                    || self.revoked.load(Ordering::Acquire)
            })
            .map_err(folder_cache_error)?;
        self.check_folder_identity(&selected, cancellation)?;
        let final_lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        self.ensure_active()?;
        if self.resolve_folder_binding(expected, cancellation)? != (identity, selected) {
            return Err(BackendError::NotFound.into());
        }
        if completed.state != PinState::Ready {
            return Err(BackendError::Unavailable.into());
        }
        drop(final_lease);
        progress(completed.clone());
        Ok(completed)
    }
}

fn folder_cache_error(error: raiun_cache::CacheError) -> BackendError {
    match error {
        raiun_cache::CacheError::Cancelled => BackendError::Cancelled,
        _ => BackendError::Unavailable,
    }
}

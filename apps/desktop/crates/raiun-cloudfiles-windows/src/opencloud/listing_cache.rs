//! Complete listings for already verified ordinary directory bindings.
use super::*;
use raiun_cache::{CacheScope, CachedEntry, ScopeProtection};

impl OpenCloudPlaceholderBackend {
    pub(super) fn cached_directory_entries(
        &self,
        directory: &DirectoryBinding,
        cancellation: &CancellationToken,
    ) -> Result<Vec<(String, raiun_core::backend::RemoteEntry)>, BackendError> {
        self.directory_entries(directory, cancellation, true)
    }

    #[cfg(windows)]
    pub(super) fn fresh_directory_entries(
        &self,
        directory: &DirectoryBinding,
        cancellation: &CancellationToken,
    ) -> Result<Vec<(String, raiun_core::backend::RemoteEntry)>, BackendError> {
        self.directory_entries(directory, cancellation, false)
    }

    fn directory_entries(
        &self,
        directory: &DirectoryBinding,
        cancellation: &CancellationToken,
        allow_cached: bool,
    ) -> Result<Vec<(String, raiun_core::backend::RemoteEntry)>, BackendError> {
        check_cancel(cancellation)?;
        self.ensure_active()?;
        self.ensure_ordinary_location(&directory.space_id, &directory.path)?;
        let uncached_parent = self.vault_parent_uncached(&directory.space_id, &directory.path)?;
        let vault_entry_seen = std::cell::Cell::new(false);
        let online = (|| -> Result<_, raiun_core::backend::CloudError> {
            let context = RangeReadContext {
                deadline: cancellation
                    .deadline()
                    .min(std::time::Instant::now() + DEFAULT_FETCH_TIMEOUT),
                token_generation: self.token_generation,
            };
            let root = self
                .client
                .stat_with_context(&directory.space_id, "/", context)?;
            let dir =
                self.client
                    .stat_with_context(&directory.space_id, &directory.path, context)?;
            if !root.directory
                || root.encrypted
                || root.id != directory.root_resource_id
                || !dir.directory
                || dir.encrypted
                || dir.id != directory.remote_id
            {
                return Err(raiun_core::backend::CloudError::new(
                    ErrorKind::Conflict,
                    "directory identity changed",
                ));
            }

            let mut entries = Vec::new();
            let mut names = std::collections::HashSet::new();
            let mut ids = std::collections::HashSet::new();
            self.client.list_with_context(
                &directory.space_id,
                &directory.path,
                context,
                &mut |entry| {
                    if entries.len() >= MAX_DIRECTORY_CHILDREN {
                        return Err(raiun_core::backend::CloudError::new(
                            ErrorKind::InvalidResponse,
                            "directory exceeds its provider entry limit",
                        ));
                    }
                    let name =
                        direct_child_name(&directory.path, &entry.path).ok_or_else(|| {
                            raiun_core::backend::CloudError::new(
                                ErrorKind::InvalidResponse,
                                "directory listing contains an invalid child path",
                            )
                        })?;
                    if entry.encrypted {
                        if !self
                            .accepted_encrypted_root(&directory.space_id, &entry)
                            .map_err(|_| {
                                raiun_core::backend::CloudError::new(
                                    ErrorKind::Forbidden,
                                    "Encrypted root is not admitted",
                                )
                            })?
                        {
                            return Err(raiun_core::backend::CloudError::new(
                                ErrorKind::Forbidden,
                                "Encrypted root is not admitted",
                            ));
                        }
                        vault_entry_seen.set(true);
                    }
                    if !valid_windows_component(name)
                        || !valid_remote_id(&entry.id)
                        || !names.insert(name.to_owned())
                        || !ids.insert(entry.id.clone())
                        || (!entry.directory && (entry.etag.is_empty() || entry.etag.len() > 4096))
                    {
                        return Err(raiun_core::backend::CloudError::new(
                            ErrorKind::InvalidResponse,
                            "directory listing contains an unsupported child",
                        ));
                    }
                    entries.push((name.to_owned(), entry));
                    Ok(())
                },
            )?;
            let root_after = self
                .client
                .stat_with_context(&directory.space_id, "/", context)?;
            let dir_after =
                self.client
                    .stat_with_context(&directory.space_id, &directory.path, context)?;
            if !root_after.directory
                || root_after.encrypted
                || root_after.id != directory.root_resource_id
                || !dir_after.directory
                || dir_after.encrypted
                || dir_after.id != directory.remote_id
            {
                return Err(raiun_core::backend::CloudError::new(
                    ErrorKind::Conflict,
                    "directory identity changed",
                ));
            }

            Ok(entries)
        })();
        check_cancel(cancellation)?;
        self.ensure_active()?;
        // A route-bearing parent is fresh-only in BOTH directions. Route IDs
        // and decrypted children must never enter an ordinary plaintext cache.
        if uncached_parent || vault_entry_seen.get() {
            return online.map_err(map_cloud_error);
        }
        let Some(cache) = &self.cache else {
            return online.map_err(map_cloud_error);
        };
        let scope = CacheScope::new(
            self.scope.server_origin(),
            self.scope.account_id(),
            &directory.space_id,
            &directory.root_resource_id,
            ScopeProtection::PlaintextAllowed,
        )
        .map_err(|_| BackendError::Unavailable)?;
        match online {
            Ok(entries) => {
                let _publication = self
                    .publish_gate
                    .lock()
                    .map_err(|_| BackendError::Unavailable)?;
                check_cancel(cancellation)?;
                self.ensure_active()?;
                self.ensure_ordinary_location(&directory.space_id, &directory.path)?;
                // Route admission uses this same publication fence. Recheck
                // after network I/O, including marker-less roots admitted then.
                if self.vault_parent_uncached(&directory.space_id, &directory.path)? {
                    return Ok(entries);
                }
                let rows = entries
                    .iter()
                    .map(|(_, entry)| CachedEntry {
                        parent_resource_id: directory.remote_id.clone(),
                        entry: entry.clone(),
                    })
                    .collect::<Vec<_>>();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| BackendError::Unavailable)?
                    .as_secs();
                let now = i64::try_from(now).map_err(|_| BackendError::Unavailable)?;
                self.client
                    .with_token_generation(self.token_generation, || {
                        if self.revoked.load(Ordering::Acquire) {
                            return Err(BackendError::Unavailable);
                        }
                        cache
                            .publish_listing(&scope, &directory.remote_id, &rows, now)
                            .map_err(|_| BackendError::Unavailable)?;
                        check_cancel(cancellation)?;
                        Ok(entries)
                    })
                    .map_err(map_cloud_error)?
            }
            Err(error) if allow_cached && error.kind == ErrorKind::Offline => {
                let _publication = self
                    .publish_gate
                    .lock()
                    .map_err(|_| BackendError::Unavailable)?;
                self.ensure_active()?;
                self.ensure_ordinary_location(&directory.space_id, &directory.path)?;
                if self.vault_parent_uncached(&directory.space_id, &directory.path)? {
                    return Err(BackendError::Unavailable);
                }
                let listing = cache
                    .listing(&scope, &directory.remote_id)
                    .map_err(|_| BackendError::Unavailable)?;
                if !listing.complete || listing.entries.len() > MAX_DIRECTORY_CHILDREN {
                    return Err(BackendError::Unavailable);
                }
                let mut names = std::collections::HashSet::new();
                let mut ids = std::collections::HashSet::new();
                let mut entries = Vec::with_capacity(listing.entries.len());
                for row in listing.entries {
                    let entry = row.entry;
                    let name = direct_child_name(&directory.path, &entry.path)
                        .ok_or(BackendError::Unavailable)?;
                    if row.parent_resource_id != directory.remote_id
                        || entry.encrypted
                        || !valid_windows_component(name)
                        || !valid_remote_id(&entry.id)
                        || !names.insert(name.to_owned())
                        || !ids.insert(entry.id.clone())
                        || (!entry.directory && (entry.etag.is_empty() || entry.etag.len() > 4096))
                    {
                        return Err(BackendError::Unavailable);
                    }
                    entries.push((name.to_owned(), entry));
                }
                check_cancel(cancellation)?;
                self.ensure_active()?;
                Ok(entries)
            }
            Err(error) => Err(self.reject_cached_cloud_error(error)),
        }
    }
}

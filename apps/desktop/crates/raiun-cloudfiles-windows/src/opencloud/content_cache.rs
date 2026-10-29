//! Complete verified ordinary-file versions; never persist callback fragments.
use super::{BackendError, CancellationToken, FileBinding, OpenCloudPlaceholderBackend};
use raiun_cache::{CacheScope, ContentProtection, ContentVersion, ScopeProtection};
use std::io::{Read, Seek, SeekFrom};

impl OpenCloudPlaceholderBackend {
    /// Read the existing device-wide cache accounting, never an account total.
    /// The cache store is shared across profiles; the live backend lease only
    /// authorizes this observation and does not change its accounting scope.
    pub fn device_cache_usage(&self) -> Result<raiun_cache::CacheUsage, BackendError> {
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        self.ensure_active()?;
        self.cache
            .as_ref()
            .ok_or(BackendError::Unavailable)?
            .usage()
            .map_err(|_| BackendError::Unavailable)
    }

    /// Change the existing device store's admission allowance under its live lease.
    /// Saving never deletes cached data, protected edits or cloud content.
    pub fn set_device_cache_quota(&self, quota_bytes: u64) -> Result<(), BackendError> {
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        self.ensure_active()?;
        self.cache
            .as_ref()
            .ok_or(BackendError::Unavailable)?
            .set_quota_bytes(quota_bytes)
            .map_err(|_| BackendError::Unavailable)
    }

    /// Query existing cache metadata for an exact live file binding. Unknown
    /// identities never acquire a default Recent policy or count as a cache hit.
    /// This performs no network requests, cache initialization, or file reads.
    pub fn file_cache_status(
        &self,
        identity: &[u8],
        expected_resource_id: &str,
        expected_etag: &str,
        cancellation: &CancellationToken,
    ) -> Result<super::FileCacheStatus, BackendError> {
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        super::check_cancel(cancellation)?;
        self.ensure_active()?;
        let identity: [u8; 16] = identity.try_into().map_err(|_| BackendError::NotFound)?;
        let identity = super::OpaqueIdentity(identity);
        let binding = self
            .state
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .files
            .get(&identity)
            .cloned()
            .ok_or(BackendError::NotFound)?;
        if binding.remote_id != expected_resource_id || binding.etag != expected_etag {
            return Err(BackendError::NotFound);
        }
        self.file_cache_status_under_lease(identity, binding, cancellation)
    }

    /// Inspect one already-admitted file without network access or identity
    /// creation. Every field must match the current authenticated catalog.
    pub fn file_cache_status_for_binding(
        &self,
        expected: &super::FileCacheBindingExpectation<'_>,
        cancellation: &CancellationToken,
    ) -> Result<super::FileCacheStatus, BackendError> {
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        super::check_cancel(cancellation)?;
        self.ensure_active()?;
        let (identity, binding) = self.resolve_file_cache_binding_under_lease(expected)?;
        self.file_cache_status_under_lease(identity, binding, cancellation)
    }

    // Caller must retain either the read lease (status) or write lease
    // (policy) for this exact catalog/binding through its final operation.
    pub(super) fn resolve_file_cache_binding_under_lease(
        &self,
        expected: &super::FileCacheBindingExpectation<'_>,
    ) -> Result<(super::OpaqueIdentity, FileBinding), BackendError> {
        self.resolve_file_cache_binding_under_lease_cancellable(expected, &CancellationToken::new())
    }

    pub(super) fn resolve_file_cache_binding_under_lease_cancellable(
        &self,
        expected: &super::FileCacheBindingExpectation<'_>,
        cancellation: &CancellationToken,
    ) -> Result<(super::OpaqueIdentity, FileBinding), BackendError> {
        self.ensure_ordinary_location(expected.space_id, expected.path)?;
        super::check_cancel(cancellation)?;
        self.catalog_scope_snapshot()?
            .ok_or(BackendError::Unavailable)?;
        if expected.space_id.is_empty()
            || expected.space_id.len() > 512
            || expected.root_resource_id.is_empty()
            || expected.root_resource_id.len() > 256 * 1024
            || expected.resource_id.is_empty()
            || expected.resource_id.len() > 256 * 1024
            || expected.etag.is_empty()
            || expected.etag.len() > 16 * 1024
            || [
                expected.space_id,
                expected.root_resource_id,
                expected.resource_id,
                expected.etag,
            ]
            .iter()
            .any(|field| field.chars().any(char::is_control))
            || expected.path.len() > 16 * 1024
            || !expected.path.starts_with('/')
            || expected.path.ends_with('/')
            || expected.path.contains("//")
            || expected.path.contains('\\')
            || expected.path.chars().any(char::is_control)
            || expected
                .path
                .split('/')
                .any(|part| matches!(part, "." | ".."))
        {
            return Err(BackendError::NotFound);
        }
        let (identity, binding) = {
            let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
            let mut found = None;
            for (identity, binding) in &state.files {
                super::check_cancel(cancellation)?;
                if binding.space_id == expected.space_id
                    && binding.root_resource_id == expected.root_resource_id
                    && binding.path == expected.path
                    && binding.remote_id == expected.resource_id
                    && binding.etag == expected.etag
                    && binding.size == expected.size
                {
                    if found.is_some() {
                        return Err(BackendError::Unavailable);
                    }
                    found = Some((*identity, binding.clone()));
                }
            }
            found.ok_or(BackendError::NotFound)?
        };
        super::check_cancel(cancellation)?;
        Ok((identity, binding))
    }

    // The caller retains the backend read lease. Do not reacquire it here:
    // recursive RwLock reads can deadlock behind a waiting policy writer.
    fn file_cache_status_under_lease(
        &self,
        identity: super::OpaqueIdentity,
        binding: FileBinding,
        cancellation: &CancellationToken,
    ) -> Result<super::FileCacheStatus, BackendError> {
        let cache = self.cache.as_ref().ok_or(BackendError::Unavailable)?;
        let (scope, version) = self.content_cache_key(&binding)?;
        let policy = cache
            .policy(&scope, &binding.remote_id)
            .map_err(|_| BackendError::Unavailable)?;
        let pending_offline_intent = cache
            .pending_plaintext_offline_intent(&scope, &binding.remote_id)
            .map_err(|_| BackendError::Unavailable)?
            .is_some_and(|intent| intent.path == binding.path && intent.etag == binding.etag);
        let recorded_bytes = match cache.content_record(&scope, &version) {
            Ok(record) if record.byte_len == binding.size => Some(record.byte_len),
            Ok(_) => return Err(BackendError::Unavailable),
            Err(raiun_cache::CacheError::NotFound) => None,
            Err(_) => return Err(BackendError::Unavailable),
        };
        super::check_cancel(cancellation)?;
        self.ensure_active()?;
        if self
            .state
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .files
            .get(&identity)
            != Some(&binding)
        {
            return Err(BackendError::NotFound);
        }
        Ok(super::FileCacheStatus {
            pending_offline_intent,
            policy,
            recorded_complete_version: recorded_bytes.is_some(),
            recorded_bytes: recorded_bytes.unwrap_or(0),
        })
    }

    /// Change local cache retention for an exact registered ordinary file.
    /// This drains in-flight callbacks and fences the account token until the
    /// metadata-conditional update commits. It does not dehydrate an OS file,
    /// delete remote content, or create a verified offline download.
    pub fn set_file_cache_policy(
        &self,
        identity: &[u8],
        expected_resource_id: &str,
        expected_etag: &str,
        policy: raiun_cache::AvailabilityPolicy,
        cancellation: &CancellationToken,
    ) -> Result<(), BackendError> {
        // AlwaysOffline needs a separate full-version download workflow.
        if policy == raiun_cache::AvailabilityPolicy::AlwaysOffline {
            return Err(BackendError::Unavailable);
        }
        let _lease = loop {
            super::check_cancel(cancellation)?;
            self.ensure_active()?;
            match self.lease_gate.try_write() {
                Ok(lease) => break lease,
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(BackendError::Unavailable);
                }
            }
        };
        super::check_cancel(cancellation)?;
        self.ensure_active()?;
        let identity: [u8; 16] = identity.try_into().map_err(|_| BackendError::NotFound)?;
        let binding = self
            .state
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .files
            .get(&super::OpaqueIdentity(identity))
            .cloned()
            .ok_or(BackendError::NotFound)?;
        if binding.remote_id != expected_resource_id || binding.etag != expected_etag {
            return Err(BackendError::NotFound);
        }
        self.set_file_cache_policy_under_lease(binding, policy, cancellation)
    }

    /// Change local Recent/CloudOnly retention for one exact authenticated
    /// catalog row. This does not dehydrate Windows placeholders, delete cloud
    /// content, or establish AlwaysOffline availability.
    pub fn set_file_cache_policy_for_binding(
        &self,
        expected: &super::FileCacheBindingExpectation<'_>,
        policy: raiun_cache::AvailabilityPolicy,
        cancellation: &CancellationToken,
    ) -> Result<(), BackendError> {
        if policy == raiun_cache::AvailabilityPolicy::AlwaysOffline {
            return Err(BackendError::Unavailable);
        }
        let _lease = loop {
            super::check_cancel(cancellation)?;
            self.ensure_active()?;
            match self.lease_gate.try_write() {
                Ok(lease) => break lease,
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(BackendError::Unavailable),
            }
        };
        super::check_cancel(cancellation)?;
        self.ensure_active()?;
        let (_, binding) = self.resolve_file_cache_binding_under_lease(expected)?;
        self.set_file_cache_policy_under_lease(binding, policy, cancellation)
    }

    fn set_file_cache_policy_under_lease(
        &self,
        binding: FileBinding,
        policy: raiun_cache::AvailabilityPolicy,
        cancellation: &CancellationToken,
    ) -> Result<(), BackendError> {
        let cache = self.cache.as_ref().ok_or(BackendError::Unavailable)?;
        let (scope, _) = self.content_cache_key(&binding)?;
        let entry = raiun_core::backend::RemoteEntry {
            id: binding.remote_id,
            path: binding.path,
            directory: false,
            size: binding.size,
            etag: binding.etag,
            modified_unix: 0,
            writable: false,
            encrypted: false,
        };
        // State is unlocked before acquiring the token guard. The exclusive
        // backend lease keeps this binding immutable through the commit.
        let _publication = self.begin_scoped_publish(cancellation)?;
        super::check_cancel(cancellation)?;
        self.ensure_active()?;
        cache
            .set_listed_file_policy(&scope, &entry, policy)
            .map_err(|_| BackendError::Unavailable)
        // Completion wins cancellation after the durable policy change.
    }

    pub(super) fn reject_cached_cloud_error(
        &self,
        error: raiun_core::backend::CloudError,
    ) -> BackendError {
        if self.cache.is_some()
            && matches!(
                error.kind,
                raiun_core::backend::ErrorKind::Unauthorized
                    | raiun_core::backend::ErrorKind::Forbidden
                    | raiun_core::backend::ErrorKind::NotFound
                    | raiun_core::backend::ErrorKind::Conflict
            )
        {
            // Do not acquire the write lease from inside a read callback.
            // Authoritative denial, removal or version/root conflict fences this
            // backend until the agent verifies and constructs a replacement.
            // The publication gate makes denial sticky before any later
            // cached transfer; the external lifecycle owner still drains.
            let _publication = self
                .publish_gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.revoked
                .store(true, std::sync::atomic::Ordering::Release);
        }
        super::map_cloud_error(error)
    }

    pub(super) fn content_cache_key(
        &self,
        binding: &FileBinding,
    ) -> Result<(CacheScope, ContentVersion), BackendError> {
        self.ensure_ordinary_location(&binding.space_id, &binding.path)?;
        let scope = CacheScope::new(
            self.scope.server_origin(),
            self.scope.account_id(),
            &binding.space_id,
            &binding.root_resource_id,
            ScopeProtection::PlaintextAllowed,
        )
        .map_err(|_| BackendError::Unavailable)?;
        Ok((
            scope,
            ContentVersion {
                resource_id: binding.remote_id.clone(),
                etag: binding.etag.clone(),
                protection: ContentProtection::Plaintext,
            },
        ))
    }

    pub(super) fn publish_complete_cached_content(
        &self,
        binding: &FileBinding,
        offset: u64,
        bytes: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<(), BackendError> {
        let Some(cache) = &self.cache else {
            return Ok(());
        };
        // A ranged response is not an offline copy of the whole file. Cache
        // only complete versions within the existing callback staging bound.
        if offset != 0
            || bytes.len() as u64 != binding.size
            || binding.size > raiun_opencloud::MAX_CALLBACK_RANGE_BYTES as u64
        {
            return Ok(());
        }
        let _publication = self
            .publish_gate
            .lock()
            .map_err(|_| BackendError::Unavailable)?;
        super::check_cancel(cancellation)?;
        self.ensure_active()?;
        let (scope, version) = self.content_cache_key(binding)?;
        self.client
            .with_token_generation(self.token_generation, || {
                if self.revoked.load(std::sync::atomic::Ordering::Acquire) {
                    return Err(BackendError::Unavailable);
                }
                let already_recorded = cache
                    .content_record(&scope, &version)
                    .is_ok_and(|record| record.byte_len == binding.size);
                if !already_recorded {
                    let Some(target) = cache
                        .try_quota_bytes()
                        .map_err(|_| BackendError::Unavailable)?
                        .checked_sub(binding.size)
                    else {
                        return Ok(());
                    };
                    // Best effort only: Dirty/Recovery/pins stay protected and
                    // active readers may refuse eviction. Atomic admission below
                    // still refuses an allocation that does not fit.
                    let _ = cache.evict_recent_bounded(target, 8);
                }
                match cache.publish_recent_content_with_budget(
                    &scope,
                    &version,
                    &mut &bytes[..],
                    binding.size,
                ) {
                    Ok(_) => {}
                    // A direct registered-file read may precede a complete
                    // parent listing; never invent metadata to retain it.
                    // Policy/budget refusal also leaves verified online reads
                    // usable without claiming an offline copy was retained.
                    Err(
                        raiun_cache::CacheError::Conflict
                        | raiun_cache::CacheError::PolicyConflict
                        | raiun_cache::CacheError::LimitExceeded
                        | raiun_cache::CacheError::InsufficientSpace,
                    ) => {}
                    Err(_) => return Err(BackendError::Unavailable),
                }
                super::check_cancel(cancellation)?;
                Ok(())
            })
            .map_err(super::map_cloud_error)?
    }

    pub(super) fn read_cached_range(
        &self,
        binding: &FileBinding,
        offset: u64,
        length: usize,
        cancellation: &CancellationToken,
    ) -> Result<Vec<u8>, BackendError> {
        super::check_cancel(cancellation)?;
        self.ensure_active()?;
        let cache = self.cache.as_ref().ok_or(BackendError::Unavailable)?;
        // File length is quota-bounded at explicit download admission; one
        // returned slice remains bounded independently of the whole file.
        if length > raiun_opencloud::MAX_CALLBACK_RANGE_BYTES {
            return Err(BackendError::InvalidRange);
        }
        if offset > binding.size {
            return Err(BackendError::Unavailable);
        }
        let (scope, version) = self.content_cache_key(binding)?;
        if cache
            .policy(&scope, &binding.remote_id)
            .map_err(|_| BackendError::Unavailable)?
            == raiun_cache::AvailabilityPolicy::CloudOnly
        {
            return Err(BackendError::Unavailable);
        }
        let record = cache
            .content_record(&scope, &version)
            .map_err(|_| BackendError::Unavailable)?;
        if record.byte_len != binding.size {
            return Err(BackendError::Unavailable);
        }
        let mut reader = cache
            .open_content_cancellable(&scope, &version, || {
                cancellation.is_cancelled()
                    || cancellation.is_expired()
                    || self.revoked.load(std::sync::atomic::Ordering::Acquire)
                    || self.client.token_generation() != self.token_generation
            })
            .map_err(|_| BackendError::Unavailable)?;
        reader
            .seek(SeekFrom::Start(offset))
            .map_err(|_| BackendError::Unavailable)?;
        let wanted = length
            .min(usize::try_from(binding.size - offset).map_err(|_| BackendError::Unavailable)?);
        let mut bytes = vec![0; wanted];
        reader
            .read_exact(&mut bytes)
            .map_err(|_| BackendError::Unavailable)?;
        super::check_cancel(cancellation)?;
        self.ensure_active()?;
        Ok(bytes)
    }
}

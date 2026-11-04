//! Online encrypted child-directory creation. The caller owns the durable
//! one-attempt intent and exact native child/parent pins; no queued replay.
use super::*;

/// Original live context, never reconstructed from an operation journal.
/// `cancelled` must be a pure bounded local predicate; epoch leases stay local.
pub struct VaultChildDirectoryCreateRequest<'a> {
    pub scope: &'a VaultSessionScope,
    pub epoch: &'a VaultSessionEpoch,
    pub vault_root_path: &'a str,
    pub logical_path: &'a str,
    pub parent_resource_id: &'a str,
    pub parent_etag: &'a str,
    pub expected_token_generation: u64,
    pub provider_generation: Arc<AtomicU64>,
    pub expected_provider_generation: u64,
    pub context: crate::RangeReadContext,
    pub cancelled: &'a dyn Fn() -> bool,
}

/// Prepared online once. Possession supplies no native or durable authority.
/// Intentionally not Clone/serializable, and consumed by one attempted send.
pub struct VaultChildDirectoryCreateTarget {
    scope: VaultSessionScope,
    epoch: VaultSessionEpoch,
    root_path: String,
    token_generation: u64,
    provider_generation: Arc<AtomicU64>,
    expected_provider_generation: u64,
    logical_path: String,
    encoded_target: String,
    integrity_token: String,
    parent_id: String,
    parent_etag: String,
}
impl VaultChildDirectoryCreateTarget {
    pub fn encoded_target(&self) -> &str {
        &self.encoded_target
    }
    pub fn integrity_token(&self) -> &str {
        &self.integrity_token
    }
}
/// Constructed only after the conditional create and fresh exact-parent
/// readback. Its metadata is historical evidence, never native authority.
pub struct VaultVerifiedChildDirectory {
    entry: RemoteEntry,
    target: VaultChildDirectoryCreateTarget,
}
impl VaultVerifiedChildDirectory {
    pub fn matches_epoch(&self, epoch: &VaultSessionEpoch) -> bool {
        self.target.epoch.same_identity(epoch)
    }
    pub fn entry(&self) -> &RemoteEntry {
        &self.entry
    }
    pub fn scope(&self) -> &VaultSessionScope {
        &self.target.scope
    }
    pub fn root_path(&self) -> &str {
        &self.target.root_path
    }
    pub fn parent_resource_id(&self) -> &str {
        &self.target.parent_id
    }
    pub fn token_generation(&self) -> u64 {
        self.target.token_generation
    }
    pub fn provider_current(&self, generation: &Arc<AtomicU64>, expected: u64) -> bool {
        Arc::ptr_eq(generation, &self.target.provider_generation)
            && expected == self.target.expected_provider_generation
            && generation.load(Ordering::Acquire) == expected
    }
}
pub enum VaultChildDirectoryCreateOutcome {
    Verified(VaultVerifiedChildDirectory),
    /// The conditional MKCOL may have reached the server. Keep the original
    /// intent and local directory; this result never authorizes another send.
    NeedsReconciliation {
        reason: ErrorKind,
    },
}

impl VaultBackend {
    fn check_child_directory_context(
        &self,
        request: &VaultChildDirectoryCreateRequest<'_>,
    ) -> Result<(), CloudError> {
        self.client.ensure_context_current(request.context)?;
        if request.context.token_generation != request.expected_token_generation
            || self.offline_only
            || self.offline_cache.is_some()
            || self.offline_root.is_some()
            || request.scope != &self.scope
            || request.vault_root_path != self.root_path
            || request.logical_path == "/"
            || normalize_virtual_path(request.logical_path)? != request.logical_path
            || request.expected_token_generation == 0
            || request.expected_provider_generation == 0
            || self.client.token_generation() != request.expected_token_generation
            || request.provider_generation.load(Ordering::Acquire)
                != request.expected_provider_generation
            || (request.cancelled)()
            || request.parent_resource_id.is_empty()
            || request.parent_resource_id.len() > 4096
            || request.parent_resource_id.chars().any(char::is_control)
        {
            return Err(conflict("encrypted child directory context changed"));
        }
        validate_virtual_path(request.logical_path)?;
        validate_existing_overwrite_etag(request.parent_etag)?;
        self.sessions
            .try_lock_session_epoch(request.scope, request.epoch)
            .map_err(vault_error)?
            .ok_or_else(|| conflict("encrypted child directory epoch is unavailable"))?;
        Ok(())
    }

    pub fn prepare_child_directory_create_guarded(
        &self,
        request: &VaultChildDirectoryCreateRequest<'_>,
    ) -> Result<VaultChildDirectoryCreateTarget, CloudError> {
        let _context = crate::RangeContextGuard::enter(request.context);
        self.check_child_directory_context(request)?;
        let state = self.revalidate_root()?;
        let (parent_id, parent_etag) = self.current_parent_binding(request.logical_path)?;
        if parent_id != request.parent_resource_id || parent_etag != request.parent_etag {
            return Err(conflict("encrypted child directory parent changed"));
        }
        let encoded_target = self.prepare_directory_create_target_for_parent(
            request.logical_path,
            &VaultPendingParentRef::Stable {
                resource_id: parent_id.clone(),
            },
        )?;
        let fresh = self.revalidate_root()?;
        self.check_child_directory_context(request)?;
        if fresh.integrity_token != state.integrity_token
            || self.current_parent_binding(request.logical_path)?
                != (parent_id.clone(), parent_etag.clone())
        {
            return Err(conflict("encrypted child directory preparation changed"));
        }
        Ok(VaultChildDirectoryCreateTarget {
            scope: request.scope.clone(),
            epoch: request.epoch.clone(),
            root_path: request.vault_root_path.to_owned(),
            token_generation: request.expected_token_generation,
            provider_generation: request.provider_generation.clone(),
            expected_provider_generation: request.expected_provider_generation,
            logical_path: request.logical_path.to_owned(),
            encoded_target,
            integrity_token: state.integrity_token,
            parent_id,
            parent_etag,
        })
    }

    /// The hook must publish/read back the durable one-attempt intent and
    /// revalidate the original native directory and parent pins. It runs once,
    /// after HTTP metadata preparation, immediately before the single send,
    /// with no token/session/publication lock held. Failure sends nothing.
    pub fn create_child_directory_guarded(
        &self,
        request: &VaultChildDirectoryCreateRequest<'_>,
        target: VaultChildDirectoryCreateTarget,
        before_send: &mut dyn FnMut() -> Result<(), CloudError>,
    ) -> Result<VaultChildDirectoryCreateOutcome, CloudError> {
        let _context = crate::RangeContextGuard::enter(request.context);
        self.check_child_directory_context(request)?;
        if target.scope != *request.scope
            || target.root_path != request.vault_root_path
            || target.token_generation != request.expected_token_generation
            || !Arc::ptr_eq(&target.provider_generation, &request.provider_generation)
            || target.expected_provider_generation != request.expected_provider_generation
            || target.logical_path != request.logical_path
            || target.parent_id != request.parent_resource_id
            || target.parent_etag != request.parent_etag
        {
            return Err(conflict("encrypted child directory target changed"));
        }
        self.sessions
            .try_lock_session_epoch(&target.scope, &target.epoch)
            .map_err(vault_error)?
            .ok_or_else(|| conflict("original directory preparation epoch changed"))?;
        let state = self.revalidate_root()?;
        if state.integrity_token != target.integrity_token
            || self.current_parent_binding(request.logical_path)?
                != (target.parent_id.clone(), target.parent_etag.clone())
            || self.prepare_directory_create_target(request.logical_path)? != target.encoded_target
        {
            return Err(conflict("encrypted child directory baseline changed"));
        }
        let physical = format!(
            "{}/{}",
            self.root_path.trim_end_matches('/'),
            target.encoded_target
        );
        let url = self.url_for_physical(&state, &physical)?;
        let parent_url = self.target_url(&state, &logical_parent(request.logical_path))?;
        let (http, token) = self.client.request_with_context(
            Method::from_bytes(b"MKCOL").expect("static method"),
            &url,
            Some(request.context),
        )?;
        let http = http
            .header(IF_NONE_MATCH, "*")
            .header("If", format!("<{parent_url}> ([{}])", target.parent_etag));
        let http = http
            .build()
            .map_err(|_| invalid("encrypted directory request is invalid"))?;
        self.check_child_directory_context(request)?;
        before_send()?;
        self.check_child_directory_context(request)?;
        // The intent is already durable. Every subsequent error is uncertain;
        // the caller must not classify a lost response as permission to replay.
        let result = (|| {
            checked(
                self.client
                    .conditional_http
                    .execute(http)
                    .map_err(network)?,
                &[StatusCode::CREATED],
                &token,
            )?;
            self.check_child_directory_context(request)?;
            let fresh = self.revalidate_root()?;
            if fresh.integrity_token != target.integrity_token {
                return Err(conflict(
                    "encrypted child directory root changed after MKCOL",
                ));
            }
            let entry = self.stat_raw(&fresh, request.logical_path)?;
            let (_, parent) = self.parent_listing(&fresh, request.logical_path)?;
            if !entry.directory
                || entry.size != 0
                || entry.id.is_empty()
                || entry.path != request.logical_path
                || !parent.root.directory
                || parent.root.id != target.parent_id
            {
                return Err(conflict("encrypted child directory readback changed"));
            }
            validate_existing_overwrite_etag(&entry.etag)?;
            self.check_child_directory_context(request)?;
            Ok(entry)
        })();
        Ok(match result {
            Ok(entry) => VaultChildDirectoryCreateOutcome::Verified(VaultVerifiedChildDirectory {
                entry,
                target,
            }),
            Err(error) => {
                VaultChildDirectoryCreateOutcome::NeedsReconciliation { reason: error.kind }
            }
        })
    }
}

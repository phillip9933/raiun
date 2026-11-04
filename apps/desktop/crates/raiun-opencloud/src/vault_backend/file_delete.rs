//! One original online vault FILE deletion, with a single conditional send.
//! A stored locator or a successful HTTP response alone is never completion.
use super::*;
pub struct VaultFileDeleteRequest<'a> {
    pub scope: &'a VaultSessionScope,
    pub epoch: &'a VaultSessionEpoch,
    pub vault_root_path: &'a str,
    pub source: &'a RemoteEntry,
    pub parent: &'a RemoteEntry,
    pub context: RangeReadContext,
    pub provider_generation: Arc<AtomicU64>,
    pub expected_provider_generation: u64,
    pub cancelled: &'a dyn Fn() -> bool,
}
pub struct VaultFileDeleteTarget {
    scope: VaultSessionScope,
    epoch: VaultSessionEpoch,
    root: String,
    source: RemoteEntry,
    parent: RemoteEntry,
    encoded: String,
    integrity: String,
    token: u64,
    generation: Arc<AtomicU64>,
    expected: u64,
}
pub struct VaultVerifiedFileDelete {
    target: VaultFileDeleteTarget,
}
impl VaultVerifiedFileDelete {
    pub fn original(&self) -> &RemoteEntry {
        &self.target.source
    }
    pub fn parent(&self) -> &RemoteEntry {
        &self.target.parent
    }
    pub fn scope(&self) -> &VaultSessionScope {
        &self.target.scope
    }
    pub fn root_path(&self) -> &str {
        &self.target.root
    }
    pub fn matches_epoch(&self, e: &VaultSessionEpoch) -> bool {
        self.target.epoch.same_identity(e)
    }
    pub fn token_generation(&self) -> u64 {
        self.target.token
    }
    pub fn provider_current(&self, g: &Arc<AtomicU64>, expected: u64) -> bool {
        Arc::ptr_eq(g, &self.target.generation)
            && expected == self.target.expected
            && g.load(Ordering::Acquire) == expected
    }
}
pub enum VaultFileDeleteOutcome {
    Verified(VaultVerifiedFileDelete),
    NeedsReconciliation,
}
fn check(
    b: &VaultBackend,
    r: &VaultFileDeleteRequest<'_>,
    directory: bool,
) -> Result<(), CloudError> {
    b.client.ensure_context_current(r.context)?;
    if (r.cancelled)()
        || r.expected_provider_generation == 0
        || r.provider_generation.load(Ordering::Acquire) != r.expected_provider_generation
        || r.scope != &b.scope
        || r.vault_root_path != b.root_path
        || b.offline_only
        || b.offline_cache.is_some()
        || b.offline_root.is_some()
    {
        return Err(conflict("encrypted delete context changed"));
    }
    b.sessions
        .try_lock_session_epoch(r.scope, r.epoch)
        .map_err(vault_error)?
        .ok_or_else(|| conflict("original delete unlock changed"))?;
    validate_virtual_path(&r.source.path)?;
    validate_virtual_path(&r.parent.path)?;
    validate_existing_overwrite_etag(&r.source.etag)?;
    validate_existing_overwrite_etag(&r.parent.etag)?;
    let parent = r
        .source
        .path
        .rsplit_once('/')
        .map(|(p, _)| if p.is_empty() { "/" } else { p })
        .unwrap_or("/");
    if r.source.directory != directory
        || (directory && r.source.size != 0)
        || !r.parent.directory
        || r.source.id.is_empty()
        || r.source.id == r.scope.resource_id()
        || r.source.id == r.parent.id
        || r.source.path == "/"
        || parent != r.parent.path
        || r.source.id.len() > 4096
        || r.parent.id.is_empty()
        || r.parent.id.len() > 4096
        || r.source.id.chars().any(char::is_control)
        || r.parent.id.chars().any(char::is_control)
    {
        return Err(conflict("encrypted delete is not one original file"));
    }
    Ok(())
}
impl VaultBackend {
    pub fn prepare_file_delete_guarded(
        &self,
        r: &VaultFileDeleteRequest<'_>,
    ) -> Result<VaultFileDeleteTarget, CloudError> {
        self.prepare_namespace_delete_guarded(r, false)
    }
    pub fn prepare_empty_directory_delete_guarded(
        &self,
        r: &VaultFileDeleteRequest<'_>,
    ) -> Result<VaultFileDeleteTarget, CloudError> {
        self.prepare_namespace_delete_guarded(r, true)
    }
    fn prepare_namespace_delete_guarded(
        &self,
        r: &VaultFileDeleteRequest<'_>,
        directory: bool,
    ) -> Result<VaultFileDeleteTarget, CloudError> {
        let _context = crate::RangeContextGuard::enter(r.context);
        check(self, r, directory)?;
        let state = self.revalidate_root()?;
        if !state.space.writable
            || self.current_parent_binding(&r.source.path)?
                != (r.parent.id.clone(), r.parent.etag.clone())
        {
            return Err(conflict("encrypted delete parent changed"));
        }
        let source = self.stat_raw(&state, &r.source.path)?;
        if source.directory != directory
            || !source.writable
            || source.id != r.source.id
            || source.etag != r.source.etag
            || source.size != r.source.size
        {
            return Err(conflict("encrypted delete source changed"));
        }
        let encoded = if directory {
            let mut children = false;
            self.list_raw(&state, &r.source.path, &mut |_| {
                children = true;
                Ok(())
            })?;
            if children {
                return Err(conflict(
                    "encrypted directory delete requires a fresh empty source",
                ));
            }
            self.sessions
                .encrypt_path(&self.scope, relative_virtual_path(&r.source.path)?)
                .map_err(vault_error)?
        } else {
            self.encoded_file_target(
                &state,
                &r.source.path,
                &WriteCondition::Match(r.source.etag.clone()),
            )?
        };
        let fresh = self.revalidate_root()?;
        check(self, r, directory)?;
        if fresh.integrity_token != state.integrity_token
            || self.current_parent_binding(&r.source.path)?
                != (r.parent.id.clone(), r.parent.etag.clone())
        {
            return Err(conflict("encrypted delete preparation changed"));
        }
        Ok(VaultFileDeleteTarget {
            scope: r.scope.clone(),
            epoch: r.epoch.clone(),
            root: r.vault_root_path.into(),
            source: r.source.clone(),
            parent: r.parent.clone(),
            encoded,
            integrity: state.integrity_token,
            token: r.context.token_generation,
            generation: r.provider_generation.clone(),
            expected: r.expected_provider_generation,
        })
    }
    /// Local native postproof and durable one-attempt claim run immediately
    /// before the single ID-addressed DELETE. Every later error is uncertain.
    pub fn delete_file_guarded(
        &self,
        r: &VaultFileDeleteRequest<'_>,
        target: VaultFileDeleteTarget,
        before_send: &mut dyn FnMut() -> Result<(), CloudError>,
    ) -> Result<VaultFileDeleteOutcome, CloudError> {
        self.delete_namespace_guarded(r, target, before_send, false)
    }
    pub fn delete_empty_directory_guarded(
        &self,
        r: &VaultFileDeleteRequest<'_>,
        target: VaultFileDeleteTarget,
        before_send: &mut dyn FnMut() -> Result<(), CloudError>,
    ) -> Result<VaultFileDeleteOutcome, CloudError> {
        self.delete_namespace_guarded(r, target, before_send, true)
    }
    fn delete_namespace_guarded(
        &self,
        r: &VaultFileDeleteRequest<'_>,
        target: VaultFileDeleteTarget,
        before_send: &mut dyn FnMut() -> Result<(), CloudError>,
        directory: bool,
    ) -> Result<VaultFileDeleteOutcome, CloudError> {
        let _context = crate::RangeContextGuard::enter(r.context);
        check(self, r, directory)?;
        if target.scope != *r.scope
            || !target.epoch.same_identity(r.epoch)
            || target.root != r.vault_root_path
            || target.source.id != r.source.id
            || target.source.path != r.source.path
            || target.source.etag != r.source.etag
            || target.source.size != r.source.size
            || target.source.directory != directory
            || target.parent.id != r.parent.id
            || target.parent.path != r.parent.path
            || target.parent.etag != r.parent.etag
            || target.token != r.context.token_generation
            || !Arc::ptr_eq(&target.generation, &r.provider_generation)
            || target.expected != r.expected_provider_generation
        {
            return Err(conflict("encrypted delete target changed"));
        }
        let fresh = self.prepare_namespace_delete_guarded(r, directory)?;
        if fresh.integrity != target.integrity || fresh.encoded != target.encoded {
            return Err(conflict("encrypted delete encoded binding changed"));
        }
        let state = self.revalidate_root()?;
        if state.integrity_token != target.integrity {
            return Err(conflict("encrypted delete root changed"));
        }
        let space_root =
            Url::parse(&state.space_dav_root).map_err(|_| invalid("vault DAV root invalid"))?;
        let root = self.client.stat_at_dav(&space_root, "/")?;
        if !root.directory || !root.writable || !state.space.writable {
            return Err(conflict("encrypted delete Space root changed"));
        }
        let source = super::super::conditional_delete::resource_delete_url(
            &self.client.server,
            &space_root,
            &state.space.id,
            &root.id,
            &target.source.id,
        )?;
        let parent = self.target_url(&state, &target.parent.path)?;
        let (builder, token) =
            self.client
                .request_with_context(Method::DELETE, &source, Some(r.context))?;
        let request = builder
            .header(IF_MATCH, &target.source.etag)
            .header("If", format!("<{}> ([{}])", parent, target.parent.etag))
            .build()
            .map_err(network)?;
        check(self, r, directory)?;
        before_send()?;
        let result = (|| {
            // The local native/DPAPI claim can block. Recheck the original
            // context after it, keeping this claimed attempt on any refusal.
            check(self, r, directory)?;
            let response = self
                .client
                .conditional_http
                .execute(request)
                .map_err(network)?;
            checked(response, &[StatusCode::NO_CONTENT, StatusCode::OK], &token)?;
            check(self, r, directory)?;
            // Qualify absence at the exact opaque resource URL, independently
            // of the old virtual name. A missing/changed parent is not absence.
            match self.client.stat_at_dav(&source, &target.source.path) {
                Err(e) if e.kind == ErrorKind::NotFound => (),
                _ => {
                    return Err(conflict(
                        "original encrypted resource absence is unqualified",
                    ));
                }
            }
            let fresh = self.revalidate_root()?;
            check(self, r, directory)?;
            if fresh.integrity_token != target.integrity
                || !fresh.space.writable
                || self.current_parent_binding(&target.source.path)?.0 != target.parent.id
            {
                return Err(conflict(
                    "encrypted delete root or parent changed after DELETE",
                ));
            }
            match self.stat_raw(&fresh, &target.source.path) {
                Err(e) if e.kind == ErrorKind::NotFound => (),
                _ => return Err(conflict("encrypted source name absence is unqualified")),
            }
            let root_after = self.client.stat_at_dav(&space_root, "/")?;
            if !root_after.directory || !root_after.writable || root_after.id != root.id {
                return Err(conflict("encrypted delete Space witness changed"));
            }
            check(self, r, directory)?;
            Ok(())
        })();
        Ok(match result {
            Ok(()) => VaultFileDeleteOutcome::Verified(VaultVerifiedFileDelete { target }),
            Err(_) => VaultFileDeleteOutcome::NeedsReconciliation,
        })
    }
}

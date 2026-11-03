//! One original-live-epoch encrypted FILE MOVE. Metadata only; no replay/body rewrite.
use super::*;
pub struct VaultFileRenameRequest<'a> {
    pub scope: &'a VaultSessionScope,
    pub epoch: &'a VaultSessionEpoch,
    pub vault_root_path: &'a str,
    pub source: &'a RemoteEntry,
    pub destination: &'a str,
    pub parent: &'a RemoteEntry,
    pub context: RangeReadContext,
    pub provider_generation: Arc<AtomicU64>,
    pub expected_provider_generation: u64,
    pub cancelled: &'a dyn Fn() -> bool,
}
pub struct VaultFileRenameTarget {
    scope: VaultSessionScope,
    epoch: VaultSessionEpoch,
    root: String,
    source: RemoteEntry,
    destination: String,
    parent: RemoteEntry,
    encoded_source: String,
    encoded_destination: String,
    integrity: String,
    token: u64,
    generation: Arc<AtomicU64>,
    expected: u64,
}
impl VaultFileRenameTarget {
    pub fn encoded_source(&self) -> &str {
        &self.encoded_source
    }
    pub fn encoded_destination(&self) -> &str {
        &self.encoded_destination
    }
    pub fn integrity_token(&self) -> &str {
        &self.integrity
    }
}
pub struct VaultVerifiedFileRename {
    target: VaultFileRenameTarget,
    entry: RemoteEntry,
}
impl VaultVerifiedFileRename {
    pub fn entry(&self) -> &RemoteEntry {
        &self.entry
    }
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
    pub fn provider_current(&self, g: &Arc<AtomicU64>, v: u64) -> bool {
        Arc::ptr_eq(g, &self.target.generation)
            && v == self.target.expected
            && g.load(Ordering::Acquire) == v
    }
}
pub enum VaultFileRenameOutcome {
    Verified(VaultVerifiedFileRename),
    NeedsReconciliation,
}
fn check(b: &VaultBackend, r: &VaultFileRenameRequest<'_>) -> Result<(), CloudError> {
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
        return Err(conflict("encrypted rename context changed"));
    }
    b.sessions
        .try_lock_session_epoch(r.scope, r.epoch)
        .map_err(vault_error)?
        .ok_or_else(|| conflict("original rename unlock changed"))?;
    validate_virtual_path(&r.source.path)?;
    validate_virtual_path(r.destination)?;
    validate_existing_overwrite_etag(&r.source.etag)?;
    validate_existing_overwrite_etag(&r.parent.etag)?;
    fn parent(p: &str) -> &str {
        p.rsplit_once('/')
            .map(|(p, _)| if p.is_empty() { "/" } else { p })
            .unwrap_or("/")
    }
    if r.source.directory
        || !r.parent.directory
        || r.source.id.is_empty()
        || r.source.id == r.scope.resource_id()
        || r.source.id == r.parent.id
        || r.source.path == "/"
        || r.destination == "/"
        || r.source.path.eq_ignore_ascii_case(r.destination)
        || parent(&r.source.path) != r.parent.path
        || parent(r.destination) != r.parent.path
        || normalize_virtual_path(r.destination)? != r.destination
    {
        return Err(conflict("encrypted rename is not one same-parent file"));
    }
    Ok(())
}
impl VaultBackend {
    pub fn prepare_file_rename_guarded(
        &self,
        r: &VaultFileRenameRequest<'_>,
    ) -> Result<VaultFileRenameTarget, CloudError> {
        let _context = crate::RangeContextGuard::enter(r.context);
        check(self, r)?;
        let state = self.revalidate_root()?;
        if !state.space.writable
            || self.current_parent_binding(&r.source.path)?
                != (r.parent.id.clone(), r.parent.etag.clone())
        {
            return Err(conflict("encrypted rename parent changed"));
        }
        let source = self.stat_raw(&state, &r.source.path)?;
        if source.directory
            || !source.writable
            || source.id != r.source.id
            || source.etag != r.source.etag
            || source.size != r.source.size
        {
            return Err(conflict("encrypted rename original source changed"));
        }
        let encoded_source = self.encoded_file_target(
            &state,
            &r.source.path,
            &WriteCondition::Match(r.source.etag.clone()),
        )?;
        let encoded_destination =
            self.encoded_file_target(&state, r.destination, &WriteCondition::Absent)?;
        let fresh = self.revalidate_root()?;
        check(self, r)?;
        if fresh.integrity_token != state.integrity_token
            || self.current_parent_binding(r.destination)?
                != (r.parent.id.clone(), r.parent.etag.clone())
        {
            return Err(conflict("encrypted rename preparation changed"));
        }
        Ok(VaultFileRenameTarget {
            scope: r.scope.clone(),
            epoch: r.epoch.clone(),
            root: r.vault_root_path.into(),
            source: r.source.clone(),
            destination: r.destination.into(),
            parent: r.parent.clone(),
            encoded_source,
            encoded_destination,
            integrity: state.integrity_token,
            token: r.context.token_generation,
            generation: r.provider_generation.clone(),
            expected: r.expected_provider_generation,
        })
    }
    /// `before_send` is LOCAL ONLY. One durable claim, then a single ID-addressed MOVE.
    /// No post-hook error is classified as definitely unsent.
    pub fn rename_file_guarded(
        &self,
        r: &VaultFileRenameRequest<'_>,
        target: VaultFileRenameTarget,
        before_send: &mut dyn FnMut() -> Result<(), CloudError>,
    ) -> Result<VaultFileRenameOutcome, CloudError> {
        let _context = crate::RangeContextGuard::enter(r.context);
        check(self, r)?;
        if target.scope != *r.scope
            || !target.epoch.same_identity(r.epoch)
            || target.root != r.vault_root_path
            || target.source.id != r.source.id
            || target.source.path != r.source.path
            || target.source.etag != r.source.etag
            || target.source.size != r.source.size
            || target.destination != r.destination
            || target.parent.id != r.parent.id
            || target.parent.etag != r.parent.etag
            || target.token != r.context.token_generation
            || !Arc::ptr_eq(&target.generation, &r.provider_generation)
            || target.expected != r.expected_provider_generation
        {
            return Err(conflict("encrypted rename target changed"));
        }
        let fresh = self.prepare_file_rename_guarded(r)?;
        if fresh.integrity != target.integrity
            || fresh.encoded_source != target.encoded_source
            || fresh.encoded_destination != target.encoded_destination
        {
            return Err(conflict("encrypted rename encoded binding changed"));
        }
        let state = self.revalidate_root()?;
        if state.integrity_token != target.integrity {
            return Err(conflict("encrypted rename root changed"));
        }
        let space_root =
            Url::parse(&state.space_dav_root).map_err(|_| invalid("vault DAV root invalid"))?;
        let root = self.client.stat_at_dav(&space_root, "/")?;
        if !root.directory || !root.writable || !state.space.writable {
            return Err(conflict("encrypted rename Space root changed"));
        }
        let source = super::super::conditional_delete::resource_delete_url(
            &self.client.server,
            &space_root,
            &state.space.id,
            &root.id,
            &target.source.id,
        )?;
        let destination = self.target_url(&state, &target.destination)?;
        let parent = self.target_url(&state, &target.parent.path)?;
        let (request, token) = self.client.request_with_context(
            Method::from_bytes(b"MOVE").expect("static method"),
            &source,
            Some(r.context),
        )?;
        let request = request
            .header(IF_MATCH, &target.source.etag)
            .header("Destination", destination.as_str())
            .header("Overwrite", "F")
            .header("If", format!("<{}> ([{}])", parent, target.parent.etag))
            .build()
            .map_err(network)?;
        check(self, r)?;
        before_send()?;
        let result = (|| {
            let response = self
                .client
                .conditional_http
                .execute(request)
                .map_err(network)?;
            checked(
                response,
                &[StatusCode::CREATED, StatusCode::NO_CONTENT],
                &token,
            )?;
            check(self, r)?;
            let state = self.revalidate_root()?;
            if state.integrity_token != target.integrity {
                return Err(conflict("encrypted rename root changed after MOVE"));
            }
            let entry = self.stat_raw(&state, &target.destination)?;
            validate_existing_overwrite_etag(&entry.etag)?;
            if entry.directory
                || entry.id != target.source.id
                || entry.etag != target.source.etag
                || entry.size != target.source.size
                || !entry.writable
            {
                return Err(conflict(
                    "encrypted rename destination differs from original ciphertext",
                ));
            }
            match self.stat_raw(&state, &target.source.path) {
                Err(e) if e.kind == ErrorKind::NotFound => (),
                _ => return Err(conflict("encrypted rename source absence is unqualified")),
            }
            if self.current_parent_binding(&target.destination)?.0 != target.parent.id {
                return Err(conflict("encrypted rename parent changed after MOVE"));
            }
            check(self, r)?;
            Ok(entry)
        })();
        Ok(match result {
            Ok(entry) => {
                VaultFileRenameOutcome::Verified(VaultVerifiedFileRename { target, entry })
            }
            Err(_) => VaultFileRenameOutcome::NeedsReconciliation,
        })
    }
}

//! One original-live-epoch encrypted FILE MOVE. Metadata only; no replay/body rewrite.
use super::*;
pub struct VaultFileRenameRequest<'a> {
    pub scope: &'a VaultSessionScope,
    pub epoch: &'a VaultSessionEpoch,
    pub vault_root_path: &'a str,
    pub source: &'a RemoteEntry,
    pub destination: &'a str,
    pub parent: &'a RemoteEntry,
    pub destination_parent: Option<&'a RemoteEntry>,
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
    destination_parent: RemoteEntry,
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
    pub fn destination_parent(&self) -> &RemoteEntry {
        &self.target.destination_parent
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
fn check(
    b: &VaultBackend,
    r: &VaultFileRenameRequest<'_>,
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
    let destination_parent = r.destination_parent.unwrap_or(r.parent);
    validate_existing_overwrite_etag(&destination_parent.etag)?;
    fn parent(p: &str) -> &str {
        p.rsplit_once('/')
            .map(|(p, _)| if p.is_empty() { "/" } else { p })
            .unwrap_or("/")
    }
    if r.source.directory != directory
        || !r.parent.directory
        || !destination_parent.directory
        || r.source.id.is_empty()
        || r.source.id == r.scope.resource_id()
        || r.source.id == r.parent.id
        || r.source.id == destination_parent.id
        || r.source.path == "/"
        || r.destination == "/"
        || (directory
            && (r.source.size != 0 || r.destination.starts_with(&format!("{}/", r.source.path))))
        || r.source.path.eq_ignore_ascii_case(r.destination)
        || parent(&r.source.path) != r.parent.path
        || parent(r.destination) != destination_parent.path
        || normalize_virtual_path(r.destination)? != r.destination
    {
        return Err(conflict(
            "encrypted MOVE is not one file within the original vault",
        ));
    }
    Ok(())
}
impl VaultBackend {
    pub fn prepare_file_rename_guarded(
        &self,
        r: &VaultFileRenameRequest<'_>,
    ) -> Result<VaultFileRenameTarget, CloudError> {
        self.prepare_namespace_rename_guarded(r, false)
    }
    fn prepare_namespace_rename_guarded(
        &self,
        r: &VaultFileRenameRequest<'_>,
        directory: bool,
    ) -> Result<VaultFileRenameTarget, CloudError> {
        let _context = crate::RangeContextGuard::enter(r.context);
        check(self, r, directory)?;
        let state = self.revalidate_root()?;
        let destination_parent = r.destination_parent.unwrap_or(r.parent);
        if !state.space.writable
            || self.current_parent_binding(&r.source.path)?
                != (r.parent.id.clone(), r.parent.etag.clone())
        {
            return Err(conflict("encrypted rename parent changed"));
        }
        let source = self.stat_raw(&state, &r.source.path)?;
        if source.directory != directory
            || !source.writable
            || source.id != r.source.id
            || source.etag != r.source.etag
            || source.size != r.source.size
        {
            return Err(conflict("encrypted rename original source changed"));
        }
        let encoded_source = if directory {
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
        let encoded_destination = if directory {
            self.prepare_directory_create_target_for_parent(
                r.destination,
                &VaultPendingParentRef::Stable {
                    resource_id: destination_parent.id.clone(),
                },
            )?
        } else {
            self.encoded_file_target(&state, r.destination, &WriteCondition::Absent)?
        };
        let fresh = self.revalidate_root()?;
        check(self, r, directory)?;
        if fresh.integrity_token != state.integrity_token
            || self.current_parent_binding(r.destination)?
                != (
                    destination_parent.id.clone(),
                    destination_parent.etag.clone(),
                )
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
            destination_parent: destination_parent.clone(),
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
        self.rename_namespace_guarded(r, target, before_send, false)
    }
    fn rename_namespace_guarded(
        &self,
        r: &VaultFileRenameRequest<'_>,
        target: VaultFileRenameTarget,
        before_send: &mut dyn FnMut() -> Result<(), CloudError>,
        directory: bool,
    ) -> Result<VaultFileRenameOutcome, CloudError> {
        let _context = crate::RangeContextGuard::enter(r.context);
        check(self, r, directory)?;
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
            || target.destination_parent.id != r.destination_parent.unwrap_or(r.parent).id
            || target.destination_parent.path != r.destination_parent.unwrap_or(r.parent).path
            || target.destination_parent.etag != r.destination_parent.unwrap_or(r.parent).etag
            || target.token != r.context.token_generation
            || !Arc::ptr_eq(&target.generation, &r.provider_generation)
            || target.expected != r.expected_provider_generation
        {
            return Err(conflict("encrypted rename target changed"));
        }
        let fresh = self.prepare_namespace_rename_guarded(r, directory)?;
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
        let destination_parent = self.target_url(&state, &target.destination_parent.path)?;
        let mut parent_if = format!("<{}> ([{}])", parent, target.parent.etag);
        if target.parent.id != target.destination_parent.id {
            parent_if.push_str(&format!(
                " <{}> ([{}])",
                destination_parent, target.destination_parent.etag
            ));
        } else if target.parent.path != target.destination_parent.path
            || target.parent.etag != target.destination_parent.etag
        {
            return Err(conflict("same parent has conflicting bindings"));
        }
        let (request, token) = self.client.request_with_context(
            Method::from_bytes(b"MOVE").expect("static method"),
            &source,
            Some(r.context),
        )?;
        let request = request
            .header(IF_MATCH, &target.source.etag)
            .header("Destination", destination.as_str())
            .header("Overwrite", "F")
            .header("If", parent_if)
            .build()
            .map_err(network)?;
        check(self, r, directory)?;
        before_send()?;
        let result = (|| {
            // The local native/DPAPI claim can block. Refuse expired or retired
            // custody again here, after claim but BEFORE the one HTTP attempt.
            check(self, r, directory)?;
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
            check(self, r, directory)?;
            let state = self.revalidate_root()?;
            if state.integrity_token != target.integrity {
                return Err(conflict("encrypted rename root changed after MOVE"));
            }
            let entry = self.stat_raw(&state, &target.destination)?;
            validate_existing_overwrite_etag(&entry.etag)?;
            if entry.directory != directory
                || entry.id != target.source.id
                || (!directory && entry.etag != target.source.etag)
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
            if self.current_parent_binding(&target.destination)?.0 != target.destination_parent.id
                || self.current_parent_binding(&target.source.path)?.0 != target.parent.id
            {
                return Err(conflict("encrypted rename parent changed after MOVE"));
            }
            check(self, r, directory)?;
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

/// Exact captured subtree, not a recursive path grant. No tree body is rewritten.
pub struct VaultDirectoryRenameTarget {
    root: VaultFileRenameTarget,
    original: Vec<RemoteEntry>,
}
impl VaultDirectoryRenameTarget {
    pub fn encoded_source(&self) -> &str {
        self.root.encoded_source()
    }
    pub fn encoded_destination(&self) -> &str {
        self.root.encoded_destination()
    }
    pub fn integrity_token(&self) -> &str {
        self.root.integrity_token()
    }
    pub fn original_tree(&self) -> &[RemoteEntry] {
        &self.original
    }
}
pub struct VaultVerifiedDirectoryRename {
    root: VaultVerifiedFileRename,
    original: Vec<RemoteEntry>,
    entries: Vec<RemoteEntry>,
}
impl VaultVerifiedDirectoryRename {
    pub fn root_proof(&self) -> &VaultVerifiedFileRename {
        &self.root
    }
    pub fn original_tree(&self) -> &[RemoteEntry] {
        &self.original
    }
    pub fn entries(&self) -> &[RemoteEntry] {
        &self.entries
    }
}
pub enum VaultDirectoryRenameOutcome {
    Verified(VaultVerifiedDirectoryRename),
    NeedsReconciliation,
}
fn same_entry(a: &RemoteEntry, b: &RemoteEntry) -> bool {
    a.id == b.id
        && a.path == b.path
        && ((a.directory && b.directory) || a.etag == b.etag)
        && a.size == b.size
        && a.directory == b.directory
}
fn exact_tree(a: &[RemoteEntry], b: &[RemoteEntry]) -> bool {
    a.len() == b.len()
        && a.iter()
            .all(|e| b.iter().filter(|v| same_entry(e, v)).count() == 1)
}
impl VaultBackend {
    fn live_rename_tree(
        &self,
        r: &VaultFileRenameRequest<'_>,
        path: &str,
    ) -> Result<Vec<RemoteEntry>, CloudError> {
        check(self, r, true)?;
        let state = self.revalidate_root()?;
        let root = self.stat_raw(&state, path)?;
        if !root.directory || !root.writable {
            return Err(conflict("encrypted rename tree root changed"));
        }
        let mut rows = vec![root];
        let mut index = 0;
        let mut ids = std::collections::BTreeSet::new();
        let mut paths = std::collections::BTreeSet::new();
        while index < rows.len() {
            check(self, r, true)?;
            let e = rows[index].clone();
            index += 1;
            if !ids.insert(e.id.clone()) || !paths.insert(e.path.to_lowercase()) || !e.writable {
                return Err(conflict("encrypted rename subtree aliases or role changed"));
            }
            validate_existing_overwrite_etag(&e.etag)?;
            if e.directory {
                self.list_raw(&state, &e.path, &mut |child| {
                    if rows.len() >= 1024 {
                        return Err(invalid("encrypted rename subtree exceeds bound"));
                    }
                    rows.push(child);
                    Ok(())
                })?;
            }
        }
        check(self, r, true)?;
        rows.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(rows)
    }
    pub fn prepare_directory_rename_guarded(
        &self,
        r: &VaultFileRenameRequest<'_>,
        expected: &[RemoteEntry],
    ) -> Result<VaultDirectoryRenameTarget, CloudError> {
        let _context = crate::RangeContextGuard::enter(r.context);
        if expected.is_empty() || expected.len() > 1024 {
            return Err(invalid("encrypted directory rename catalogue bound"));
        }
        let root = self.prepare_namespace_rename_guarded(r, true)?;
        let tree = self.live_rename_tree(r, &r.source.path)?;
        if !tree
            .iter()
            .any(|e| e.path == r.source.path && e.id == r.source.id && e.etag == r.source.etag)
            || !exact_tree(expected, &tree)
        {
            return Err(conflict(
                "encrypted directory rename catalogue differs from remote tree",
            ));
        }
        Ok(VaultDirectoryRenameTarget {
            root,
            original: tree,
        })
    }
    pub fn rename_directory_guarded(
        &self,
        r: &VaultFileRenameRequest<'_>,
        target: VaultDirectoryRenameTarget,
        before: &mut dyn FnMut() -> Result<(), CloudError>,
    ) -> Result<VaultDirectoryRenameOutcome, CloudError> {
        let _context = crate::RangeContextGuard::enter(r.context);
        let fresh = self.live_rename_tree(r, &r.source.path)?;
        if !exact_tree(&fresh, &target.original) {
            return Err(conflict("encrypted directory subtree changed before MOVE"));
        }
        let result = self.rename_namespace_guarded(r, target.root, before, true)?;
        let VaultFileRenameOutcome::Verified(root) = result else {
            return Ok(VaultDirectoryRenameOutcome::NeedsReconciliation);
        };
        let readback = (|| {
            let tree = self.live_rename_tree(r, r.destination)?;
            let mut expected = target.original.clone();
            for e in &mut expected {
                let suffix = e
                    .path
                    .strip_prefix(&r.source.path)
                    .ok_or_else(|| conflict("encrypted rename subtree outside source"))?;
                e.path = format!("{}{suffix}", r.destination);
            }
            if !exact_tree(&expected, &tree) {
                return Err(conflict("encrypted directory whole-tree readback changed"));
            }
            Ok(tree)
        })();
        Ok(match readback {
            Ok(entries) => VaultDirectoryRenameOutcome::Verified(VaultVerifiedDirectoryRename {
                root,
                original: target.original,
                entries,
            }),
            Err(_) => VaultDirectoryRenameOutcome::NeedsReconciliation,
        })
    }
}

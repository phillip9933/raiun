//! Atomic ordinary-folder CloudOnly admission. No network operations occur here.

use super::*;

/// A complete live listing collected without publishing metadata. The caller
/// captures the local generation before its network read; admission compares
/// every baseline before publishing any of these observations.
#[derive(Debug, Clone)]
pub struct FolderPolicyListing {
    pub parent_resource_id: String,
    pub expected_generation: Option<u64>,
    pub entries: Vec<CachedEntry>,
}

struct Tree {
    ids: BTreeSet<String>,
    directories: BTreeSet<String>,
}

fn tree(
    db: &Connection,
    scope: &CacheScope,
    root: &RemoteEntry,
    missing_is_empty: bool,
) -> Result<Tree, CacheError> {
    let mut result = Tree {
        ids: BTreeSet::from([root.id.clone()]),
        directories: BTreeSet::new(),
    };
    let mut pending = vec![(root.id.clone(), root.path.clone(), 0usize)];
    let mut metadata_bytes = root.id.len() + root.path.len() + root.etag.len();
    while let Some((id, path, depth)) = pending.pop() {
        if depth > 64 || !result.directories.insert(id.clone()) {
            return Err(CacheError::LimitExceeded);
        }
        let listing = match load_listing(db, scope, &id) {
            Ok(listing) => listing,
            Err(CacheError::NotFound | CacheError::IncompleteListing) if missing_is_empty => {
                continue;
            }
            Err(error) => return Err(error),
        };
        if !listing.complete {
            return Err(CacheError::IncompleteListing);
        }
        for item in listing.entries {
            let entry = item.entry;
            validate_entry(&entry)?;
            let parent = entry
                .path
                .rsplit_once('/')
                .map(|(parent, _)| if parent.is_empty() { "/" } else { parent });
            if item.parent_resource_id != id
                || parent != Some(path.as_str())
                || !result.ids.insert(entry.id.clone())
            {
                return Err(CacheError::PolicyConflict);
            }
            if entry.encrypted {
                return Err(CacheError::ProtectionMismatch);
            }
            metadata_bytes = metadata_bytes
                .saturating_add(item.parent_resource_id.len())
                .saturating_add(entry.id.len())
                .saturating_add(entry.path.len())
                .saturating_add(entry.etag.len());
            if result.ids.len() > MAX_LISTING_ENTRIES || metadata_bytes > MAX_LISTING_BYTES {
                return Err(CacheError::LimitExceeded);
            }
            if entry.directory {
                pending.push((entry.id, entry.path, depth + 1));
            }
        }
    }
    Ok(result)
}

fn selected_identity(
    db: &Connection,
    scope: &CacheScope,
    selected: &CachedEntry,
    exact_metadata: bool,
) -> Result<(), CacheError> {
    let entry = &selected.entry;
    if entry.id == scope.root_resource_id {
        if entry.path != "/" || selected.parent_resource_id != scope.root_resource_id {
            return Err(CacheError::PolicyConflict);
        }
    } else {
        let listing = load_listing(db, scope, &selected.parent_resource_id)?;
        if !listing.complete
            || !listing.entries.iter().any(|item| {
                if exact_metadata {
                    item == selected
                } else {
                    item.parent_resource_id == selected.parent_resource_id
                        && item.entry.id == entry.id
                        && item.entry.path == entry.path
                        && item.entry.directory
                        && !item.entry.encrypted
                }
            })
        {
            return Err(CacheError::Conflict);
        }
    }
    folder_policy::validate_ancestry(db, scope, &entry.id, true)
}

impl Cache {
    /// Install a stable-folder intent and evict only its eligible Recent bytes.
    /// All metadata, protection checks, intent and index updates share one
    /// transaction. Refusal publishes no metadata and changes no policy or bytes.
    /// Open handles already handed to callers are not secure-erasure revoked.
    pub fn set_folder_cloud_only(
        &self,
        scope: &CacheScope,
        selected: &CachedEntry,
        observed: &[FolderPolicyListing],
    ) -> Result<(), CacheError> {
        if scope.protection != ScopeProtection::PlaintextAllowed
            || !selected.entry.directory
            || selected.entry.encrypted
        {
            return Err(CacheError::ProtectionMismatch);
        }
        if selected.entry.id == scope.root_resource_id {
            validate_id(&selected.entry.id)?;
            validate_path(&selected.entry.path)?;
            if selected.entry.etag.len() > MAX_SCOPE_FIELD
                || selected.entry.size > MAX_CONTENT_BYTES
            {
                return Err(CacheError::InvalidEntry);
            }
        } else {
            validate_entry(&selected.entry)?;
        }
        validate_id(&selected.parent_resource_id)?;
        if observed.is_empty() || observed.len() > MAX_SNAPSHOTS {
            return Err(CacheError::LimitExceeded);
        }
        let mut observed_parents = BTreeSet::new();
        let mut count = 0usize;
        let mut bytes = 0usize;
        for listing in observed {
            validate_id(&listing.parent_resource_id)?;
            bytes = bytes.saturating_add(listing.parent_resource_id.len());
            validate_listing(&listing.entries)?;
            if !observed_parents.insert(listing.parent_resource_id.clone())
                || listing
                    .entries
                    .iter()
                    .any(|item| item.parent_resource_id != listing.parent_resource_id)
            {
                return Err(CacheError::InvalidEntry);
            }
            count = count.saturating_add(listing.entries.len());
            for item in &listing.entries {
                bytes = bytes
                    .saturating_add(item.parent_resource_id.len())
                    .saturating_add(item.entry.id.len())
                    .saturating_add(item.entry.path.len())
                    .saturating_add(item.entry.etag.len());
            }
        }
        if count > MAX_LISTING_ENTRIES || bytes > MAX_LISTING_BYTES {
            return Err(CacheError::LimitExceeded);
        }
        // Same cross-process publication domain as ordinary file CloudOnly.
        let _deletion = self.lock_content_deletion()?;
        let mut db = self.lock_db()?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        validate_registered_scope(&tx, scope)?;
        for listing in observed {
            let current: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT generation,complete FROM listings WHERE scope_key=?1 AND parent_id=?2",
                    params![scope.key, listing.parent_resource_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(db_error)?;
            let expected = listing
                .expected_generation
                .map(|generation| i64::try_from(generation).map(|generation| (generation, 1)))
                .transpose()
                .map_err(|_| CacheError::LimitExceeded)?;
            if current != expected {
                return Err(CacheError::Conflict);
            }
        }
        selected_identity(&tx, scope, selected, false)?;
        let old = tree(&tx, scope, &selected.entry, true)?;
        // A previously unlisted directory can have no proven children. Refuse
        // if any retained identity in this scope lacks complete, unambiguous
        // ancestry; otherwise an unknown Dirty item could be silently bypassed.
        let retained = {
            let mut stmt = tx.prepare(
                "SELECT resource_id FROM contents WHERE scope_key=?1 UNION SELECT resource_id FROM policies WHERE scope_key=?1 UNION SELECT root_id FROM pins WHERE scope_key=?1 UNION SELECT pi.resource_id FROM pin_items pi JOIN pins p ON p.pin_id=pi.pin_id WHERE p.scope_key=?1 UNION SELECT parent_id FROM writes WHERE scope_key=?1 AND state IN (0,1) UNION SELECT root_resource_id FROM ciphertext_pin_roots WHERE scope_key=?1 LIMIT 100001",
            ).map_err(db_error)?;
            stmt.query_map([&scope.key], |row| row.get::<_, String>(0))
                .map_err(db_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?
        };
        if retained.len() > MAX_LISTING_ENTRIES {
            return Err(CacheError::LimitExceeded);
        }
        for id in &retained {
            folder_policy::validate_ancestry(&tx, scope, id, false)?;
        }
        for listing in observed {
            listing_publication::publish_listing_in_transaction(
                &tx,
                scope,
                &listing.parent_resource_id,
                &listing.entries,
                now_unix(),
            )?;
        }
        selected_identity(&tx, scope, selected, true)?;
        let current = tree(&tx, scope, &selected.entry, false)?;
        for id in &retained {
            folder_policy::validate_ancestry(&tx, scope, id, false)?;
        }
        let mut expected_parents = current.directories;
        if selected.entry.id != scope.root_resource_id {
            expected_parents.insert(selected.parent_resource_id.clone());
        }
        if observed_parents != expected_parents || !old.ids.is_subset(&current.ids) {
            // An old-only identity may have moved out. Never evict it merely
            // because the previous snapshot placed it under this folder.
            return Err(CacheError::Conflict);
        }
        for id in &current.ids {
            folder_policy::validate_ancestry(&tx, scope, id, false)?;
            let protected: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM contents c WHERE c.scope_key=?1 AND c.resource_id=?2 AND (c.retention<>0 OR c.protection<>0 OR EXISTS(SELECT 1 FROM writes w WHERE w.content_key=c.content_key AND w.state IN (0,1)) OR EXISTS(SELECT 1 FROM ciphertext_writes w WHERE w.content_key=c.content_key) OR EXISTS(SELECT 1 FROM ciphertext_pin_items pi WHERE pi.content_key=c.content_key))) OR EXISTS(SELECT 1 FROM writes WHERE scope_key=?1 AND state IN (0,1) AND (resource_id=?2 OR parent_id=?2)) OR EXISTS(SELECT 1 FROM policies WHERE scope_key=?1 AND resource_id=?2 AND policy=1) OR EXISTS(SELECT 1 FROM pins WHERE scope_key=?1 AND root_id=?2) OR EXISTS(SELECT 1 FROM ciphertext_pin_roots WHERE scope_key=?1 AND root_resource_id=?2) OR EXISTS(SELECT 1 FROM pin_items pi JOIN pins p ON p.pin_id=pi.pin_id WHERE p.scope_key=?1 AND pi.resource_id=?2)",
                params![scope.key, id], |row| row.get(0),
            ).map_err(db_error)?;
            if protected {
                return Err(CacheError::PolicyConflict);
            }
        }
        let mut removed = Vec::new();
        for id in &current.ids {
            removed.extend(remove_recent_content(&tx, &scope.key, id)?);
        }
        tx.execute(
            "INSERT INTO folder_cloud_only_intents(scope_key,root_id) VALUES(?1,?2) ON CONFLICT(scope_key,root_id) DO NOTHING",
            params![scope.key, selected.entry.id],
        ).map_err(db_error)?;
        tx.commit().map_err(db_error)?;
        for name in removed {
            match fs::remove_file(self.inner.content_dir.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        sync_directory(&self.inner.content_dir)
    }
}

//! Read-only retained metadata for an explicitly partial recovery view.
//! This is never evidence of the current remote namespace or remote absence.
use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedPinManifest {
    pub pin_id: String,
    pub root_resource_id: String,
    pub root_path: String,
    pub state: PinState,
    /// Historical entries, all read-only. No content availability is promised.
    pub entries: Vec<PinManifestEntry>,
}

/// Historical, read-only identity for a retained ordinary-file snapshot.
/// The catalog does not promise that any entry is current or that its bytes
/// remain available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedPinSummary {
    pub pin_id: String,
    pub root_resource_id: String,
    pub root_path: String,
    pub state: PinState,
}

impl Cache {
    /// List bounded historical pin roots for an explicit recovery view.
    /// This does not refresh pins, publish listings, or inspect file content.
    /// Unavailable pins are omitted; malformed records fail the whole query.
    pub fn retained_pin_catalog(
        &self,
        scope: &CacheScope,
    ) -> Result<Vec<RetainedPinSummary>, CacheError> {
        if scope.protection != ScopeProtection::PlaintextAllowed {
            return Err(CacheError::ProtectionMismatch);
        }
        let mut db = self.lock_db()?;
        let tx = db.transaction().map_err(db_error)?;
        validate_registered_scope(&tx, scope)?;
        let (count, bytes): (i64, i64) = tx
            .query_row(
                "SELECT COUNT(*),COALESCE(SUM(length(CAST(pin_id AS BLOB))+length(CAST(root_id AS BLOB))+length(CAST(root_path AS BLOB))),0) FROM pins WHERE scope_key=?1",
                params![scope.key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(db_error)?;
        if count < 0
            || count > MAX_PIN_RECORDS as i64
            || bytes < 0
            || bytes > MAX_LISTING_BYTES as i64
        {
            return Err(CacheError::LimitExceeded);
        }

        let mut statement = tx
            .prepare("SELECT pin_id,root_id,root_path,state FROM pins WHERE scope_key=?1 ORDER BY pin_id")
            .map_err(db_error)?;
        let mut rows = statement.query(params![scope.key]).map_err(db_error)?;
        let mut summaries = Vec::with_capacity(count as usize);
        while let Some(row) = rows.next().map_err(db_error)? {
            let pin_id: String = row.get(0).map_err(db_error)?;
            let root_resource_id: String = row.get(1).map_err(db_error)?;
            let root_path: String = row.get(2).map_err(db_error)?;
            let raw_state: i64 = row.get(3).map_err(db_error)?;
            validate_id(&pin_id)?;
            validate_id(&root_resource_id)?;
            validate_path(&root_path)?;
            if (root_resource_id == scope.root_resource_id) != (root_path == "/") {
                return Err(CacheError::IncompleteManifest);
            }
            let state = match raw_state {
                0 => PinState::Building,
                1 => PinState::Ready,
                2 => PinState::Stale,
                3 => PinState::Unavailable,
                _ => return Err(CacheError::Corrupt),
            };
            if state != PinState::Unavailable {
                summaries.push(RetainedPinSummary {
                    pin_id,
                    root_resource_id,
                    root_path,
                    state,
                });
            }
        }
        drop(rows);
        drop(statement);
        tx.commit().map_err(db_error)?;
        Ok(summaries)
    }

    /// Read one exact plaintext pin for recovery without refreshing it, changing
    /// write states, publishing a listing, or inferring that any object is absent.
    /// Unavailable pins and encrypted metadata are never exposed here.
    pub fn retained_pin_manifest(
        &self,
        scope: &CacheScope,
        pin_id: &str,
    ) -> Result<RetainedPinManifest, CacheError> {
        if scope.protection != ScopeProtection::PlaintextAllowed {
            return Err(CacheError::ProtectionMismatch);
        }
        validate_id(pin_id)?;
        let mut db = self.lock_db()?;
        let tx = db.transaction().map_err(db_error)?;
        validate_registered_scope(&tx, scope)?;
        let (root, path, state): (String, String, i64) = tx
            .query_row(
                "SELECT root_id,root_path,state FROM pins WHERE pin_id=?1 AND scope_key=?2",
                params![pin_id, scope.key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(db_error)?
            .ok_or(CacheError::PinNotFound)?;
        validate_id(&root)?;
        validate_path(&path)?;
        if (root == scope.root_resource_id) != (path == "/") {
            return Err(CacheError::IncompleteManifest);
        }
        let state = match state {
            0 => PinState::Building,
            1 => PinState::Ready,
            2 => PinState::Stale,
            3 => return Err(CacheError::NotFound),
            _ => return Err(CacheError::Corrupt),
        };
        // Bound allocations before reading variable-size manifest strings.
        let (count, bytes): (i64, i64) = tx.query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(CAST(resource_id AS BLOB))+length(CAST(parent_id AS BLOB))+length(CAST(name AS BLOB))+length(CAST(path AS BLOB))+length(CAST(etag AS BLOB))),0) FROM pin_items WHERE pin_id=?1",
            params![pin_id], |row| Ok((row.get(0)?,row.get(1)?)),
        ).map_err(db_error)?;
        if count < 0
            || count > MAX_LISTING_ENTRIES as i64
            || bytes < 0
            || bytes > MAX_LISTING_BYTES as i64
        {
            return Err(CacheError::LimitExceeded);
        }
        let mut statement = tx.prepare(
            "SELECT resource_id,parent_id,name,path,etag,size,directory,encrypted FROM pin_items WHERE pin_id=?1 ORDER BY path,resource_id",
        ).map_err(db_error)?;
        let mut rows = statement.query(params![pin_id]).map_err(db_error)?;
        let mut entries = Vec::with_capacity(count as usize);
        let mut paths = BTreeSet::new();
        while let Some(row) = rows.next().map_err(db_error)? {
            let id: String = row.get(0).map_err(db_error)?;
            let parent: String = row.get(1).map_err(db_error)?;
            let name: String = row.get(2).map_err(db_error)?;
            let item_path: String = row.get(3).map_err(db_error)?;
            let etag: String = row.get(4).map_err(db_error)?;
            let size: i64 = row.get(5).map_err(db_error)?;
            let directory: i64 = row.get(6).map_err(db_error)?;
            let encrypted: i64 = row.get(7).map_err(db_error)?;
            if size < 0 || ![0, 1].contains(&directory) || encrypted != 0 {
                return Err(CacheError::InvalidEntry);
            }
            if leaf_name(&item_path)? != name || !paths.insert(item_path.clone()) {
                return Err(CacheError::InvalidEntry);
            }
            entries.push(PinManifestEntry {
                parent_resource_id: parent,
                entry: RemoteEntry {
                    id,
                    path: item_path,
                    etag,
                    size: size as u64,
                    directory: directory == 1,
                    encrypted: false,
                    writable: false,
                    modified_unix: 0,
                },
            });
        }
        let mut ids = BTreeSet::new();
        for item in &entries {
            validate_id(&item.parent_resource_id)?;
            validate_entry(&item.entry)?;
            if item.entry.id == root || !ids.insert(item.entry.id.as_str()) {
                return Err(CacheError::IncompleteManifest);
            }
        }
        // ID reachability alone does not prove a path belongs under this pin.
        // Check every direct parent/path edge, including the pin root edge.
        // Each edge shortens the normalized path, so cycles are impossible;
        // every referenced parent must terminate at this exact root. Avoid an
        // iterative reachability walk with quadratic work for deep manifests.
        let mut directories = BTreeMap::from([(root.as_str(), path.as_str())]);
        for item in &entries {
            if item.entry.directory {
                directories.insert(&item.entry.id, &item.entry.path);
            }
        }
        for item in &entries {
            let parent_path = item
                .entry
                .path
                .rsplit_once('/')
                .map(|(p, _)| if p.is_empty() { "/" } else { p })
                .ok_or(CacheError::InvalidEntry)?;
            if directories.get(item.parent_resource_id.as_str()).copied() != Some(parent_path) {
                return Err(CacheError::IncompleteManifest);
            }
        }
        Ok(RetainedPinManifest {
            pin_id: pin_id.into(),
            root_resource_id: root,
            root_path: path,
            state,
            entries,
        })
    }
}

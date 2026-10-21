//! Re-admit an unchanged interrupted folder manifest without allocating a pin.
use super::*;

type StoredItem = (String, String, String, String, String, i64, i64, i64);

impl Cache {
    /// Resume only an exact, still-Building plaintext folder snapshot. The
    /// caller supplies the durable ID and freshly observed complete manifest;
    /// this never discovers a candidate by path, changes metadata, or hashes
    /// content. Changed manifests require a separately staged explicit refresh.
    /// Readiness remains conservative until exact member verification succeeds.
    /// Probes must not block or reenter the cache. Membership must also be
    /// rechecked by the existing download tickets at admission and publication.
    pub fn resume_pin_manifest_at_cancellable(
        &self,
        scope: &CacheScope,
        pin_id: &str,
        root_resource_id: &str,
        root_path: &str,
        manifest: &[PinManifestEntry],
        cancelled: impl FnMut() -> bool,
    ) -> Result<PinInfo, CacheError> {
        self.resume_exact_manifest(
            scope,
            (pin_id, false),
            root_resource_id,
            root_path,
            manifest,
            cancelled,
        )
    }

    /// Re-admit the exact staging snapshot even if a readiness inspection has
    /// promoted its complete cached bytes to Ready. This does not replace the
    /// active snapshot, grant access, mutate metadata or skip byte verification.
    /// The returned progress is conservative Building until verified again.
    pub fn resume_staging_pin_manifest_at_cancellable(
        &self,
        scope: &CacheScope,
        pin_id: &str,
        root_resource_id: &str,
        root_path: &str,
        manifest: &[PinManifestEntry],
        cancelled: impl FnMut() -> bool,
    ) -> Result<PinInfo, CacheError> {
        self.resume_exact_manifest(
            scope,
            (pin_id, true),
            root_resource_id,
            root_path,
            manifest,
            cancelled,
        )
    }

    fn resume_exact_manifest(
        &self,
        scope: &CacheScope,
        pin: (&str, bool),
        root_resource_id: &str,
        root_path: &str,
        manifest: &[PinManifestEntry],
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<PinInfo, CacheError> {
        let (pin_id, allow_ready) = pin;
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        if scope.protection != ScopeProtection::PlaintextAllowed {
            return Err(CacheError::ProtectionMismatch);
        }
        validate_id(pin_id)?;
        validate_id(root_resource_id)?;
        validate_path(root_path)?;
        if manifest.len() > MAX_LISTING_ENTRIES {
            return Err(CacheError::IncompleteManifest);
        }
        validate_manifest(root_resource_id, manifest)?;
        if manifest.iter().any(|item| item.entry.encrypted) {
            return Err(CacheError::ProtectionMismatch);
        }
        let mut expected = Vec::with_capacity(manifest.len());
        for item in manifest {
            if cancelled() {
                return Err(CacheError::Cancelled);
            }
            expected.push((
                item.entry.id.clone(),
                item.parent_resource_id.clone(),
                leaf_name(&item.entry.path)?.to_owned(),
                item.entry.path.clone(),
                item.entry.etag.clone(),
                i64_from_u64(item.entry.size)?,
                item.entry.directory as i64,
                item.entry.encrypted as i64,
            ));
        }
        expected.sort_by(|a, b| a.0.cmp(&b.0));
        let mut db = self.pin_db(&mut cancelled)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        validate_registered_scope(&tx, scope)?;
        let found: Option<(String, String, i64)> = tx
            .query_row(
                "SELECT root_id,root_path,state FROM pins WHERE scope_key=?1 AND pin_id=?2",
                params![scope.key, pin_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(db_error)?;
        let (root, path, state) = found.ok_or(CacheError::PinNotFound)?;
        if root != root_resource_id
            || path != root_path
            || !(state == 0 || (allow_ready && state == 1))
        {
            return Err(CacheError::Conflict);
        }
        if root_resource_id != scope.root_resource_id {
            let known: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=?1 AND e.resource_id=?2 AND e.path=?3 AND e.directory=1 AND e.encrypted=0 AND l.complete=1)",
                params![scope.key,root_resource_id,root_path], |row| row.get(0),
            ).map_err(db_error)?;
            if !known {
                return Err(CacheError::IncompleteManifest);
            }
        }
        validate_complete_manifest_in_db(&tx, scope, root_resource_id, manifest)?;
        let stored = {
            let mut stmt = tx.prepare("SELECT resource_id,parent_id,name,path,etag,size,directory,encrypted FROM pin_items WHERE pin_id=?1 ORDER BY resource_id LIMIT ?2").map_err(db_error)?;
            stmt.query_map(params![pin_id, (MAX_LISTING_ENTRIES + 1) as i64], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })
            .map_err(db_error)?
            .collect::<Result<Vec<StoredItem>, _>>()
            .map_err(db_error)?
        };
        if stored != expected {
            return Err(CacheError::Conflict);
        }
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        tx.commit().map_err(db_error)?;
        Ok(PinInfo {
            id: pin_id.to_owned(),
            root_resource_id: root_resource_id.to_owned(),
            root_path: root_path.to_owned(),
            state: PinState::Building,
            item_count: manifest.len(),
            ready_content_count: 0,
            required_content_count: manifest.iter().filter(|item| !item.entry.directory).count(),
        })
    }
}

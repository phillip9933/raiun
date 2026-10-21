//! Verify content outside the metadata mutex, then fence the exact snapshot.
use super::*;

type ItemRow = (String, String, String, String, String, i64, i64, i64);

#[derive(PartialEq, Eq)]
struct ContentRow {
    key: String,
    relative: String,
    len: i64,
    hash: String,
    protection: i64,
}

#[derive(PartialEq, Eq)]
struct PinSnapshot {
    scope: String,
    root: String,
    path: String,
    state: i64,
    items: Vec<ItemRow>,
    contents: Vec<ContentRow>,
}

/// Opaque exact observation captured before a folder refresh performs network
/// work. It is not an access credential and cannot authorize content reads.
/// Keep it until replacement; any intervening metadata/content-record change
/// must refuse the stale refresh instead of overwriting a newer snapshot.
pub struct PinRefreshExpectation {
    pin_id: String,
    observed: PinSnapshot,
}

impl PinSnapshot {
    fn matches_refresh_expectation(&self, current: &Self) -> bool {
        // Fresh listing admission may mark the old manifest Stale. This is
        // invalidation, not publication of a replacement manifest. Permit only
        // this monotonic state transition while fencing every identity, item
        // and content record. Final transaction still compares state exactly.
        self.scope == current.scope
            && self.root == current.root
            && self.path == current.path
            && (self.state == current.state || (self.state == 1 && current.state == 2))
            && self.items == current.items
            && self.contents == current.contents
    }

    fn info(&self, id: &str, ready: usize) -> Result<PinInfo, CacheError> {
        let required = self.items.iter().filter(|row| row.6 == 0).count();
        let state = match self.state {
            2 => PinState::Stale,
            3 => PinState::Unavailable,
            0 | 1 if required == ready => PinState::Ready,
            0 | 1 => PinState::Building,
            _ => return Err(CacheError::Corrupt),
        };
        Ok(PinInfo {
            id: id.to_owned(),
            root_resource_id: self.root.clone(),
            root_path: self.path.clone(),
            state,
            item_count: self.items.len(),
            ready_content_count: ready,
            required_content_count: required,
        })
    }
}

fn snapshot(db: &Connection, pin_id: &str) -> Result<PinSnapshot, CacheError> {
    let (scope, root, path, state): (String, String, String, i64) = db
        .query_row(
            "SELECT scope_key,root_id,root_path,state FROM pins WHERE pin_id=?1",
            [pin_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(db_error)?
        .ok_or(CacheError::PinNotFound)?;
    decode_pin_state(state).map_err(|_| CacheError::Corrupt)?;
    let descriptor: (String, String, String, String, i64) = db.query_row(
        "SELECT origin,account_id,space_id,root_resource_id,protection FROM scopes WHERE scope_key=?1",
        [&scope], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))
        .optional().map_err(db_error)?.ok_or(CacheError::NotFound)?;
    let protection = match descriptor.4 {
        0 => ScopeProtection::PlaintextAllowed,
        1 => ScopeProtection::CiphertextOnly,
        _ => return Err(CacheError::Corrupt),
    };
    let registered = CacheScope::new(
        &descriptor.0,
        &descriptor.1,
        &descriptor.2,
        &descriptor.3,
        protection,
    )
    .map_err(|_| CacheError::Corrupt)?;
    if registered.key != scope {
        return Err(CacheError::Corrupt);
    }
    let items = {
        let mut stmt = db.prepare("SELECT resource_id,parent_id,name,path,etag,size,directory,encrypted FROM pin_items WHERE pin_id=?1 ORDER BY resource_id LIMIT ?2").map_err(db_error)?;
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
        .collect::<Result<Vec<ItemRow>, _>>()
        .map_err(db_error)?
    };
    if items.len() > MAX_LISTING_ENTRIES {
        return Err(CacheError::LimitExceeded);
    }
    if items
        .iter()
        .any(|row| row.5 < 0 || !matches!(row.6, 0 | 1) || !matches!(row.7, 0 | 1))
    {
        return Err(CacheError::Corrupt);
    }
    if protection == ScopeProtection::PlaintextAllowed && items.iter().any(|row| row.7 != 0) {
        return Err(CacheError::ProtectionMismatch);
    }
    let contents = {
        let mut stmt = db.prepare("SELECT c.content_key,c.relative_path,c.byte_len,c.sha256,c.protection FROM pin_items pi JOIN contents c ON c.scope_key=?2 AND c.resource_id=pi.resource_id AND c.etag=pi.etag AND c.byte_len=pi.size WHERE pi.pin_id=?1 AND pi.directory=0 ORDER BY pi.resource_id,c.protection LIMIT ?3").map_err(db_error)?;
        stmt.query_map(
            params![pin_id, scope, (MAX_LISTING_ENTRIES * 2 + 1) as i64],
            |row| {
                Ok(ContentRow {
                    key: row.get(0)?,
                    relative: row.get(1)?,
                    len: row.get(2)?,
                    hash: row.get(3)?,
                    protection: row.get(4)?,
                })
            },
        )
        .map_err(db_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_error)?
    };
    if contents.len() > MAX_LISTING_ENTRIES * 2 {
        return Err(CacheError::LimitExceeded);
    }
    if contents
        .iter()
        .any(|row| row.protection != ContentProtection::from(protection) as i64)
    {
        return Err(CacheError::ProtectionMismatch);
    }
    Ok(PinSnapshot {
        scope,
        root,
        path,
        state,
        items,
        contents,
    })
}

impl Cache {
    pub(super) fn pin_db<'a>(
        &'a self,
        cancelled: &mut impl FnMut() -> bool,
    ) -> Result<std::sync::MutexGuard<'a, DbOwner>, CacheError> {
        loop {
            if cancelled() {
                return Err(CacheError::Cancelled);
            }
            match self.inner.db.try_lock() {
                Ok(db) => return Ok(db),
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(std::time::Duration::from_millis(1))
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(CacheError::Database("cache lock is poisoned".into()));
                }
            }
        }
    }

    fn verify_pin_contents(
        &self,
        observed: &PinSnapshot,
        cancelled: &mut impl FnMut() -> bool,
    ) -> Result<usize, CacheError> {
        let mut ready = 0;
        for item in &observed.contents {
            if cancelled() {
                return Err(CacheError::Cancelled);
            }
            validate_object_filename(&item.relative)?;
            if item.len < 0 || !matches!(item.protection, 0 | 1) {
                return Err(CacheError::Corrupt);
            }
            #[cfg(windows)]
            {
                match self.inner.windows_content.open_verified_cancellable(
                    &item.relative,
                    item.len as u64,
                    &item.hash,
                    &mut *cancelled,
                ) {
                    Ok(_reader) => ready += 1,
                    Err(CacheError::NotFound | CacheError::Corrupt) => {}
                    Err(error) => return Err(error),
                }
                continue;
            }
            #[cfg(not(windows))]
            {
                let path = self.inner.content_dir.join(&item.relative);
                if matches!(fs::symlink_metadata(&path), Err(error) if error.kind() == io::ErrorKind::NotFound)
                {
                    continue;
                }
                let mut file = open_private_file(&path)?;
                let (len, hash) = hash_file_cancellable(&mut file, &mut *cancelled)?;
                if len == item.len as u64 && hash == item.hash {
                    ready += 1;
                }
            }
        }
        Ok(ready)
    }

    /// Hash bounded slices without holding the metadata mutex. Before publishing
    /// status, compare the complete manifest and content-record snapshot again.
    /// A concurrent change returns Conflict and preserves its newer state.
    /// Probes must not block or reenter the cache; final publication probes run
    /// while its metadata mutex is held. Publication wins after the final probe.
    pub fn refresh_pin_cancellable(
        &self,
        pin_id: &str,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<PinInfo, CacheError> {
        let observed = {
            let db = self.pin_db(&mut cancelled)?;
            snapshot(&db, pin_id)?
        };
        let ready = self.verify_pin_contents(&observed, &mut cancelled)?;
        let mut db = self.pin_db(&mut cancelled)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        if snapshot(&tx, pin_id)? != observed {
            return Err(CacheError::Conflict);
        }
        let info = observed.info(pin_id, ready)?;
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        tx.execute(
            "UPDATE pins SET state=?2 WHERE pin_id=?1",
            params![pin_id, encode_pin_state(info.state)],
        )
        .map_err(db_error)?;
        if info.state == PinState::Ready {
            folder_pin_roles::promote_initial(
                &tx,
                &observed.scope,
                &observed.root,
                &observed.path,
                pin_id,
            )?;
        }
        tx.commit().map_err(db_error)?;
        Ok(info)
    }

    /// Capture the exact active snapshot before fetching a replacement tree.
    /// No byte hashing occurs. The expected root/path must be the caller's
    /// already verified directory binding, not a path-only lookup.
    pub fn pin_refresh_expectation(
        &self,
        scope: &CacheScope,
        pin_id: &str,
        root_resource_id: &str,
        root_path: &str,
    ) -> Result<PinRefreshExpectation, CacheError> {
        if scope.protection != ScopeProtection::PlaintextAllowed {
            return Err(CacheError::ProtectionMismatch);
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let observed = snapshot(&db, pin_id)?;
        if observed.scope != scope.key {
            return Err(CacheError::PinNotFound);
        }
        if observed.root != root_resource_id
            || observed.path != root_path
            || !matches!(observed.state, 1 | 2)
        {
            return Err(CacheError::Conflict);
        }
        Ok(PinRefreshExpectation {
            pin_id: pin_id.to_owned(),
            observed,
        })
    }

    /// Refuse a refresh if its active snapshot has changed since the caller
    /// captured it, including changes completed before staging verification.
    /// Listing-only Ready-to-Stale invalidation is allowed when every manifest
    /// field and content record remains identical; it is not a newer snapshot.
    pub fn replace_pin_snapshot_if_current_cancellable(
        &self,
        scope: &CacheScope,
        expected: &PinRefreshExpectation,
        staging_pin_id: &str,
        cancelled: impl FnMut() -> bool,
    ) -> Result<PinInfo, CacheError> {
        self.replace_pin_snapshot_checked(
            scope,
            &expected.pin_id,
            staging_pin_id,
            Some(&expected.observed),
            cancelled,
        )
    }

    /// Verify staging bytes before replacing an active manifest. Metadata is
    /// swapped atomically only if both complete snapshots still match. Failure
    /// or observed cancellation before commit preserves both pins. Commit wins
    /// after its final probe and returns the durable active ID without more I/O.
    pub fn replace_pin_snapshot_cancellable(
        &self,
        scope: &CacheScope,
        active_pin_id: &str,
        staging_pin_id: &str,
        cancelled: impl FnMut() -> bool,
    ) -> Result<PinInfo, CacheError> {
        self.replace_pin_snapshot_checked(scope, active_pin_id, staging_pin_id, None, cancelled)
    }

    fn replace_pin_snapshot_checked(
        &self,
        scope: &CacheScope,
        active_pin_id: &str,
        staging_pin_id: &str,
        expected: Option<&PinSnapshot>,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<PinInfo, CacheError> {
        if active_pin_id == staging_pin_id {
            return Err(CacheError::Conflict);
        }
        let (active, staged) = {
            let db = self.pin_db(&mut cancelled)?;
            validate_registered_scope(&db, scope)?;
            let active = snapshot(&db, active_pin_id)?;
            let staged = snapshot(&db, staging_pin_id)?;
            if active.scope != scope.key || staged.scope != scope.key {
                return Err(CacheError::PinNotFound);
            }
            if expected.is_some_and(|expected| !expected.matches_refresh_expectation(&active)) {
                return Err(CacheError::Conflict);
            }
            if active.root != staged.root {
                return Err(CacheError::IncompleteManifest);
            }
            (active, staged)
        };
        let ready = self.verify_pin_contents(&staged, &mut cancelled)?;
        let info = staged.info(active_pin_id, ready)?;
        if info.state != PinState::Ready {
            return Err(CacheError::IncompleteManifest);
        }
        let mut db = self.pin_db(&mut cancelled)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        validate_registered_scope(&tx, scope)?;
        if snapshot(&tx, active_pin_id)? != active || snapshot(&tx, staging_pin_id)? != staged {
            return Err(CacheError::Conflict);
        }
        folder_pin_roles::commit_refresh(
            &tx,
            &scope.key,
            &active.root,
            &active.path,
            active_pin_id,
            staging_pin_id,
        )?;
        tx.execute("DELETE FROM pin_items WHERE pin_id=?1", [active_pin_id])
            .map_err(db_error)?;
        tx.execute("INSERT INTO pin_items(pin_id,resource_id,parent_id,name,path,etag,size,directory,encrypted) SELECT ?1,resource_id,parent_id,name,path,etag,size,directory,encrypted FROM pin_items WHERE pin_id=?2", params![active_pin_id, staging_pin_id]).map_err(db_error)?;
        tx.execute(
            "UPDATE pins SET root_path=?3,state=1,created_at=?4 WHERE pin_id=?1 AND scope_key=?2",
            params![active_pin_id, scope.key, staged.path, now_unix()],
        )
        .map_err(db_error)?;
        tx.execute(
            "DELETE FROM pins WHERE pin_id=?1 AND scope_key=?2",
            params![staging_pin_id, scope.key],
        )
        .map_err(db_error)?;
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        tx.commit().map_err(db_error)?;
        Ok(info)
    }
}

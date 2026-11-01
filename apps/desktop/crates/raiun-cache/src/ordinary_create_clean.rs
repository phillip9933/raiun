//! Exact local custody acknowledgement and new-create-only clean eviction.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum CleanupPoint {
    Retired,
    Unlinked,
}

fn disposition(db: &Connection, scope: &CacheScope, id: i64) -> Result<i64, CacheError> {
    db.query_row(
        "SELECT body_state FROM ordinary_create_handoffs WHERE scope_key=?1 AND write_id=?2",
        params![scope.key, id],
        |r| r.get(0),
    )
    .map_err(db_error)
}
fn policy_holds(db: &Connection, scope: &CacheScope, key: &str) -> Result<bool, CacheError> {
    // Scope-wide offline intent is deliberately conservative: an invalidated
    // parent listing cannot prove that a new child is outside a saved folder.
    db.query_row("SELECT EXISTS(SELECT 1 FROM pins WHERE scope_key=?1) OR EXISTS(SELECT 1 FROM folder_pin_roles WHERE scope_key=?1) OR EXISTS(SELECT 1 FROM policies WHERE scope_key=?1 AND policy NOT IN(0,2)) OR EXISTS(SELECT 1 FROM contents WHERE content_key=?2 AND retention<>1) OR EXISTS(SELECT 1 FROM writes WHERE content_key=?2 AND state IN(0,1)) OR EXISTS(SELECT 1 FROM ciphertext_writes WHERE content_key=?2) OR EXISTS(SELECT 1 FROM ciphertext_pin_items WHERE content_key=?2)",params![scope.key,key],|r|r.get(0)).map_err(db_error)
}
fn verified_custody(receipt: &OrdinaryCreateReceipt) -> Result<(), CacheError> {
    if receipt.state != OrdinaryCreateState::Verified
        || receipt.write.state != WriteState::Verified
        || !receipt.local_handoff_acknowledged
        || receipt.remote.is_none()
    {
        Err(CacheError::Conflict)
    } else {
        Ok(())
    }
}
impl Cache {
    /// Record the caller's durable receipt acceptance, not cloud completion.
    /// FUSE must first fsync its exact receipt manifest and retain its original
    /// spool on failure. Neither dispatch nor retention state is reset here.
    pub fn acknowledge_ordinary_create_handoff(
        &self,
        scope: &CacheScope,
        receipt: &OrdinaryCreateReceipt,
    ) -> Result<OrdinaryCreateReceipt, CacheError> {
        let found = {
            let db = self.lock_db()?;
            current(&db, scope, receipt)?
        };
        if found.local_handoff_acknowledged {
            return Ok(found);
        }
        if !matches!(
            found.state,
            OrdinaryCreateState::Ready
                | OrdinaryCreateState::Claimed
                | OrdinaryCreateState::Uncertain
                | OrdinaryCreateState::Verified
        ) {
            return Err(CacheError::Conflict);
        }
        // First acknowledgement proves the indexed immutable copy still opens.
        // Keep the verified reader pinned until the transaction commits.
        let _reader = self.open_content(scope, &found.write.content)?;
        let db = self.lock_db()?;
        let tx = db.unchecked_transaction().map_err(db_error)?;
        let found = current(&tx, scope, receipt)?;
        if found.local_handoff_acknowledged {
            return Ok(found);
        }
        if !matches!(
            found.state,
            OrdinaryCreateState::Ready
                | OrdinaryCreateState::Claimed
                | OrdinaryCreateState::Uncertain
                | OrdinaryCreateState::Verified
        ) {
            return Err(CacheError::Conflict);
        }
        let n=tx.execute("UPDATE ordinary_create_handoffs SET local_handoff_ack=1,updated_at=?3 WHERE scope_key=?1 AND write_id=?2 AND local_handoff_ack=0 AND body_state=0",params![scope.key,found.write.id,now_unix()]).map_err(db_error)?;
        if n != 1 {
            return Err(CacheError::Conflict);
        }
        let out = load(&tx, scope, found.write.id)?.ok_or(CacheError::Corrupt)?;
        tx.commit().map_err(db_error)?;
        Ok(out)
    }

    /// Bounded, exact-scope cleanup. Only fully verified and locally accepted
    /// new creates qualify. Scope-wide offline intent conservatively holds all
    /// candidates. Failure is separate from delivery and never permits resend.
    pub fn evict_acknowledged_ordinary_create_bodies(
        &self,
        scope: &CacheScope,
        target_quota: u64,
        max_candidates: usize,
    ) -> Result<EvictionReport, CacheError> {
        self.evict_clean_creates_with_hook(scope, target_quota, max_candidates, |_| Ok(()))
    }
    fn evict_clean_creates_with_hook(
        &self,
        scope: &CacheScope,
        target_quota: u64,
        max_candidates: usize,
        mut hook: impl FnMut(CleanupPoint) -> Result<(), CacheError>,
    ) -> Result<EvictionReport, CacheError> {
        plain(scope)?;
        if !(1..=64).contains(&max_candidates) || target_quota > MAX_CONTENT_BYTES {
            return Err(CacheError::LimitExceeded);
        }
        #[cfg(windows)]
        let lease = self.inner.windows_content.publication_lease()?;
        #[cfg(not(windows))]
        let lease = self.lock_content_deletion()?;
        let (candidates, mut used) = {
            let db = self.lock_db()?;
            validate_registered_scope(&db, scope)?;
            let mut statement=db.prepare("SELECT h.write_id FROM ordinary_create_handoffs h JOIN contents c ON c.content_key=h.content_key AND c.scope_key=h.scope_key WHERE h.scope_key=?1 AND h.state=5 AND h.local_handoff_ack=1 AND h.body_state IN(0,1) AND c.retention=1 AND NOT EXISTS(SELECT 1 FROM writes w WHERE w.content_key=c.content_key AND w.state IN(0,1)) AND NOT EXISTS(SELECT 1 FROM ciphertext_writes w WHERE w.content_key=c.content_key) AND NOT EXISTS(SELECT 1 FROM ciphertext_pin_items p WHERE p.content_key=c.content_key) ORDER BY h.body_state DESC,c.last_accessed,h.write_id LIMIT ?2").map_err(db_error)?;
            let ids = statement
                .query_map(params![scope.key, max_candidates as i64], |r| {
                    r.get::<_, i64>(0)
                })
                .map_err(db_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?;
            (ids, total_content_bytes(&db)?)
        };
        let mut attempted = 0;
        let mut removed = 0u64;
        for id in candidates {
            let receipt = {
                let db = self.lock_db()?;
                let receipt = load(&db, scope, id)?.ok_or(CacheError::Corrupt)?;
                verified_custody(&receipt)?;
                if policy_holds(&db, scope, &content_key(scope, &receipt.write.content))? {
                    continue;
                }
                if !receipt.body_evicted && used <= target_quota {
                    continue;
                }
                receipt
            };
            attempted += 1;
            let key = content_key(scope, &receipt.write.content);
            let name = format!("{key}.blob");
            // Body hashing stays outside the DB transaction; the storage lease
            // and immutable identity prevent a different object from being deleted.
            #[cfg(windows)]
            let candidate = match self.inner.windows_content.prepare_verified_clean_eviction(
                &lease,
                &name,
                receipt.byte_len,
                &receipt.sha256,
            ) {
                Ok(c) => c,
                Err(CacheError::Conflict) => continue,
                Err(e) => return Err(e),
            };
            #[cfg(not(windows))]
            let candidate = prepare_portable(self, &name, &receipt)?;
            if candidate.is_none() && !receipt.body_evicted {
                return Err(CacheError::Corrupt);
            }
            {
                let db = self.lock_db()?;
                let tx = db.unchecked_transaction().map_err(db_error)?;
                let found = current(&tx, scope, &receipt)?;
                verified_custody(&found)?;
                if policy_holds(&tx, scope, &key)? {
                    continue;
                }
                if disposition(&tx, scope, id)? == 0 {
                    let n=tx.execute("UPDATE ordinary_create_handoffs SET body_state=1,updated_at=?3 WHERE scope_key=?1 AND write_id=?2 AND body_state=0 AND state=5 AND local_handoff_ack=1",params![scope.key,id,now_unix()]).map_err(db_error)?;
                    if n != 1 {
                        return Err(CacheError::Conflict);
                    }
                }
                tx.commit().map_err(db_error)?;
            }
            // This permanent retirement fact precedes physical deletion. The
            // retained contents row continues to charge quota across all failures.
            hook(CleanupPoint::Retired)?;
            let db = self.lock_db()?;
            let tx = db.unchecked_transaction().map_err(db_error)?;
            let found = current(&tx, scope, &receipt)?;
            verified_custody(&found)?;
            if disposition(&tx, scope, id)? != 1 {
                return Err(CacheError::Conflict);
            }
            if policy_holds(&tx, scope, &key)? {
                continue;
            }
            #[cfg(windows)]
            let deleted = match candidate {
                Some(file) => {
                    file.delete().map_err(io_error)?;
                    true
                }
                None => {
                    self.inner
                        .windows_content
                        .verify_clean_absence(&lease, &name)?;
                    false
                }
            };
            #[cfg(not(windows))]
            let deleted = unlink_portable(self, &name, candidate)?;
            // The directory durability step is intentionally inside this short
            // transaction, so new policy cannot race the last check and unlink.
            sync_directory(&self.inner.content_dir)?;
            hook(CleanupPoint::Unlinked)?;
            let n = tx
                .execute(
                    "DELETE FROM contents WHERE content_key=?1 AND scope_key=?2 AND retention=1",
                    params![key, scope.key],
                )
                .map_err(db_error)?;
            if n != 1 {
                return Err(CacheError::Corrupt);
            }
            let n=tx.execute("UPDATE ordinary_create_handoffs SET body_state=2,updated_at=?3 WHERE scope_key=?1 AND write_id=?2 AND body_state=1 AND state=5 AND local_handoff_ack=1",params![scope.key,id,now_unix()]).map_err(db_error)?;
            if n != 1 {
                return Err(CacheError::Conflict);
            }
            tx.commit().map_err(db_error)?;
            used = used.saturating_sub(receipt.byte_len);
            if deleted {
                removed = removed.saturating_add(receipt.byte_len);
            }
        }
        // Inventory supplies names only; an unindexed name is never deletion
        // authority. Only an exact retained clean tombstone plus byte/identity
        // verification may authorize a residual cleanup.
        if attempted < max_candidates {
            #[cfg(windows)]
            let names = self.inner.windows_content.clean_retry_names(&lease)?;
            #[cfg(not(windows))]
            let names = portable_names(self)?;
            for name in names {
                if attempted >= max_candidates {
                    break;
                }
                let Some(key) = name.strip_suffix(".blob") else {
                    continue;
                };
                let receipt = {
                    let db = self.lock_db()?;
                    let id:Option<i64>=db.query_row("SELECT write_id FROM ordinary_create_handoffs WHERE scope_key=?1 AND content_key=?2 AND body_state=2 AND state=5 AND local_handoff_ack=1",params![scope.key,key],|r|r.get(0)).optional().map_err(db_error)?;
                    id.map(|id| load(&db, scope, id)?.ok_or(CacheError::Corrupt))
                        .transpose()?
                };
                let Some(receipt) = receipt else {
                    continue;
                };
                attempted += 1;
                #[cfg(windows)]
                let candidate = match self.inner.windows_content.prepare_verified_clean_eviction(
                    &lease,
                    &name,
                    receipt.byte_len,
                    &receipt.sha256,
                ) {
                    Ok(c) => c,
                    Err(CacheError::Conflict) => continue,
                    Err(e) => return Err(e),
                };
                #[cfg(not(windows))]
                let candidate = prepare_portable(self, &name, &receipt)?;
                let db = self.lock_db()?;
                let tx = db.unchecked_transaction().map_err(db_error)?;
                let found = current(&tx, scope, &receipt)?;
                verified_custody(&found)?;
                if disposition(&tx, scope, receipt.write.id)? != 2 || policy_holds(&tx, scope, key)?
                {
                    continue;
                }
                #[cfg(windows)]
                let deleted = match candidate {
                    Some(file) => {
                        file.delete().map_err(io_error)?;
                        true
                    }
                    None => {
                        self.inner
                            .windows_content
                            .verify_clean_absence(&lease, &name)?;
                        false
                    }
                };
                #[cfg(not(windows))]
                let deleted = unlink_portable(self, &name, candidate)?;
                sync_directory(&self.inner.content_dir)?;
                tx.commit().map_err(db_error)?;
                if deleted {
                    removed = removed.saturating_add(receipt.byte_len);
                }
            }
        }
        drop(lease);
        let usage = self.usage()?;
        #[cfg(not(windows))]
        let usage = self.clean_portable_usage(usage)?;
        Ok(EvictionReport {
            removed_bytes: removed,
            used_bytes: usage.used_bytes,
            protected_bytes: usage.protected_bytes,
            over_quota: usage.used_bytes > target_quota,
        })
    }
    #[cfg(not(windows))]
    fn clean_portable_usage(&self, mut usage: CacheUsage) -> Result<CacheUsage, CacheError> {
        let db = self.lock_db()?;
        for name in portable_names(self)? {
            let indexed: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM contents WHERE relative_path=?1)",
                    [&name],
                    |r| r.get(0),
                )
                .map_err(db_error)?;
            if !indexed {
                let path = self.inner.content_dir.join(name);
                let metadata = match fs::symlink_metadata(path) {
                    Ok(m) => m,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(io_error(e)),
                };
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(CacheError::UnsafeDirectory);
                }
                usage.used_bytes = usage.used_bytes.saturating_add(metadata.len());
                usage.protected_bytes = usage.protected_bytes.saturating_add(metadata.len());
            }
        }
        Ok(usage)
    }
}
#[cfg(not(windows))]
fn portable_names(cache: &Cache) -> Result<Vec<String>, CacheError> {
    let mut names = Vec::new();
    let mut scanned = 0usize;
    for entry in fs::read_dir(&cache.inner.content_dir).map_err(io_error)? {
        scanned += 1;
        if scanned > MAX_CONTENT_RECORDS + MAX_JOURNAL_RECORDS {
            return Err(CacheError::LimitExceeded);
        }
        let name = entry
            .map_err(io_error)?
            .file_name()
            .into_string()
            .map_err(|_| CacheError::Corrupt)?;
        if name.ends_with(".blob") {
            validate_object_filename(&name)?;
        }
        names.push(name);
    }
    names.sort();
    Ok(names)
}
#[cfg(not(windows))]
fn prepare_portable(
    cache: &Cache,
    name: &str,
    receipt: &OrdinaryCreateReceipt,
) -> Result<Option<File>, CacheError> {
    validate_object_filename(name)?;
    let mut file = match open_private_file(&cache.inner.content_dir.join(name)) {
        Ok(f) => f,
        Err(CacheError::Io(_))
            if !cache
                .inner
                .content_dir
                .join(name)
                .try_exists()
                .map_err(io_error)? =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let (len, digest) = hash_file(&mut file)?;
    if len != receipt.byte_len || digest != receipt.sha256 {
        return Err(CacheError::Corrupt);
    }
    Ok(Some(file))
}
#[cfg(not(windows))]
fn unlink_portable(cache: &Cache, name: &str, candidate: Option<File>) -> Result<bool, CacheError> {
    let path = cache.inner.content_dir.join(name);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(m) => Some(m),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(io_error(e)),
    };
    match (candidate, metadata) {
        (None, None) => Ok(false),
        (Some(file), Some(metadata)) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let pinned = file.metadata().map_err(io_error)?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.dev() != pinned.dev()
                    || metadata.ino() != pinned.ino()
                {
                    return Err(CacheError::Conflict);
                }
                fs::remove_file(path).map_err(io_error)?;
                Ok(true)
            }
            #[cfg(not(unix))]
            {
                let _ = (file, metadata);
                Err(CacheError::UnsafeDirectory)
            }
        }
        _ => Err(CacheError::Conflict),
    }
}
#[cfg(all(test, unix))]
#[path = "ordinary_create_clean_tests.rs"]
mod tests;

//! Two-phase ordinary-file downloads. Network work belongs to the caller.

use super::*;

/// Streamed explicit downloads remain bounded by configured quota and the
/// private object hard limit. Native callback buffers have separate limits.
pub const MAX_STAGED_PLAINTEXT_BYTES: u64 = MAX_CONTENT_BYTES;

// The authorization is retained through readback and revalidated in the final
// metadata transaction. Folder downloads must not create per-file policies.
enum DownloadIntent {
    FileRevision(i64),
    FolderPin {
        id: String,
        root_id: String,
        root_path: String,
    },
}

/// A private reservation tied to one cache, account/root and exact file version.
/// Dropping it preserves uncertain stage bytes; it never deletes a cloud file.
pub struct PlaintextDownloadStage<'a> {
    cache: &'a Cache,
    scope: CacheScope,
    entry: RemoteEntry,
    intent: DownloadIntent,
    blob: windows_blob::ReservedDownload<'a>,
}

/// An already-indexed version pinned before recording its offline intent.
/// Verification runs without a database, publication, backend or auth lock.
pub struct CachedPlaintextVerification<'a> {
    cache: &'a Cache,
    scope: CacheScope,
    entry: RemoteEntry,
    intent: DownloadIntent,
    reader: raiun_control_windows::OwnedPrivateReader,
    relative: String,
    digest: String,
}

impl<'a> CachedPlaintextVerification<'a> {
    /// Verify in bounded read slices; cancellation preserves the indexed bytes
    /// and leaves the new offline intent stale rather than claiming Ready.
    pub fn finish_cancellable(
        self,
        cancelled: impl FnMut() -> bool,
    ) -> Result<VerifiedPlaintextDownload<'a>, CacheError> {
        let blob = windows_blob::WindowsBlobStore::finish_existing_download_cancellable(
            self.reader,
            &self.relative,
            self.entry.size,
            &self.digest,
            cancelled,
        )?;
        Ok(VerifiedPlaintextDownload {
            cache: self.cache,
            scope: self.scope,
            entry: self.entry,
            intent: self.intent,
            blob,
        })
    }

    pub fn finish(self) -> Result<VerifiedPlaintextDownload<'a>, CacheError> {
        let blob = windows_blob::WindowsBlobStore::finish_existing_download(
            self.reader,
            &self.relative,
            self.entry.size,
            &self.digest,
        )?;
        Ok(VerifiedPlaintextDownload {
            cache: self.cache,
            scope: self.scope,
            entry: self.entry,
            intent: self.intent,
            blob,
        })
    }
}

/// Fully read-back local bytes. No Ready/index claim exists until commit.
pub struct VerifiedPlaintextDownload<'a> {
    cache: &'a Cache,
    scope: CacheScope,
    entry: RemoteEntry,
    intent: DownloadIntent,
    blob: windows_blob::PublishedBlob,
}

impl<'a> PlaintextDownloadStage<'a> {
    /// Cancellation may occur after private publication. On error the caller
    /// must preserve and report retained bytes; no Ready claim was committed.
    pub fn finish_cancellable(
        self,
        cancelled: impl FnMut() -> bool,
    ) -> Result<VerifiedPlaintextDownload<'a>, CacheError> {
        let blob = self.blob.finish_cancellable(cancelled)?;
        Ok(VerifiedPlaintextDownload {
            cache: self.cache,
            scope: self.scope,
            entry: self.entry,
            intent: self.intent,
            blob,
        })
    }

    /// Explicit cancellation may release this exact unfinished reservation.
    /// Failure preserves its charge; no policy, content index or cloud object
    /// is removed. Once finish consumes the stage, this API is unavailable.
    pub fn abort(self) -> Result<(), CacheError> {
        self.blob.abort()
    }
    /// Append one sequential chunk, at most 1 MiB. This holds no global lease.
    pub fn append(&mut self, offset: u64, bytes: &[u8]) -> Result<(), CacheError> {
        self.blob.append(offset, bytes)
    }

    /// Publish only private bytes and verify their immutable readback. Call
    /// before acquiring backend/token publication guards: verification may do
    /// local I/O. Cancellation still leaves no Ready policy or content index.
    pub fn finish(self) -> Result<VerifiedPlaintextDownload<'a>, CacheError> {
        let blob = self.blob.finish()?;
        Ok(VerifiedPlaintextDownload {
            cache: self.cache,
            scope: self.scope,
            entry: self.entry,
            intent: self.intent,
            blob,
        })
    }
}

impl VerifiedPlaintextDownload<'_> {
    /// Caller must hold its exact backend/root and short auth-generation
    /// publication guards. This performs no network or full-file readback.
    /// The final transaction fences metadata and the latest policy intent.
    pub fn commit(self) -> Result<ContentRecord, CacheError> {
        let store = &self.cache.inner.windows_content;
        let _lease = store.publication_lease()?;
        let mut db = self.cache.lock_db()?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        validate_registered_scope(&tx, &self.scope)?;
        validate_download_binding(&tx, &self.scope, &self.entry)?;
        match &self.intent {
            DownloadIntent::FileRevision(revision) => {
                let current: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM policies p JOIN policy_intent_revisions r ON r.scope_key=p.scope_key AND r.resource_id=p.resource_id WHERE p.scope_key=?1 AND p.resource_id=?2 AND p.policy=1 AND p.target_path=?3 AND p.target_etag=?4 AND p.target_state=1 AND r.revision=?5)",
                    params![self.scope.key,self.entry.id,self.entry.path,self.entry.etag,revision],
                    |row| row.get(0),
                ).map_err(db_error)?;
                if !current {
                    return Err(CacheError::PolicyConflict);
                }
            }
            DownloadIntent::FolderPin {
                id,
                root_id,
                root_path,
            } => {
                let current = pin_download_intent(&tx, &self.scope, &self.entry, id)?;
                if !matches!(current, DownloadIntent::FolderPin { root_id: r, root_path: p, .. } if &r == root_id && &p == root_path)
                {
                    return Err(CacheError::PolicyConflict);
                }
            }
        }
        let version = download_version(&self.entry);
        let key = content_key(&self.scope, &version);
        let relative = format!("{key}.blob");
        // Other reservations may have committed while this body streamed.
        // Recheck the final index bound in the same serialized transaction.
        let (count, exists): (i64, bool) = tx.query_row(
            "SELECT (SELECT COUNT(*) FROM contents), EXISTS(SELECT 1 FROM contents WHERE content_key=?1)",
            params![key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(db_error)?;
        if !exists && count >= MAX_CONTENT_RECORDS as i64 {
            return Err(CacheError::LimitExceeded);
        }
        let changed = tx.execute(
            "INSERT INTO contents(content_key,scope_key,resource_id,etag,protection,byte_len,sha256,relative_path,last_accessed,retention) VALUES(?1,?2,?3,?4,0,?5,?6,?7,?8,0) ON CONFLICT(content_key) DO UPDATE SET last_accessed=excluded.last_accessed WHERE contents.scope_key=excluded.scope_key AND contents.resource_id=excluded.resource_id AND contents.etag=excluded.etag AND contents.protection=0 AND contents.byte_len=excluded.byte_len AND contents.sha256=excluded.sha256 AND contents.relative_path=excluded.relative_path",
            params![key,self.scope.key,self.entry.id,self.entry.etag,i64_from_u64(self.blob.byte_len)?,self.blob.digest,relative,now_unix()],
        ).map_err(db_error)?;
        if changed != 1 || self.blob.byte_len != self.entry.size {
            return Err(CacheError::Corrupt);
        }
        if matches!(&self.intent, DownloadIntent::FileRevision(_)) {
            // State-only update deliberately does not create a new user intent.
            let changed = tx.execute(
            "UPDATE policies SET target_state=0 WHERE scope_key=?1 AND resource_id=?2 AND policy=1 AND target_path=?3 AND target_etag=?4 AND target_state=1",
            params![self.scope.key,self.entry.id,self.entry.path,self.entry.etag],
        ).map_err(db_error)?;
            if changed != 1 {
                return Err(CacheError::PolicyConflict);
            }
        }
        tx.commit().map_err(db_error)?;
        // Retain the exact immutable receipt through the durable transaction.
        let record = load_content_record(&db, &self.scope, &version)?;
        drop(self.blob);
        Ok(record)
    }
}

impl Cache {
    /// Record an explicit offline intent for an existing version and pin its
    /// exact private object. No duplicate body allocation or quota charge is
    /// needed, even when protected recovery data already exceeds the quota.
    /// The caller must hold live backend/auth admission guards for this short
    /// operation, release them for finish(), then revalidate for commit().
    pub fn begin_cached_plaintext_offline_verification<'a>(
        &'a self,
        scope: &CacheScope,
        entry: &RemoteEntry,
    ) -> Result<CachedPlaintextVerification<'a>, CacheError> {
        self.begin_cached_plaintext_verification_with_intent(scope, entry, None)
    }

    /// Acquire content for one existing exact folder manifest member without
    /// creating an independent AlwaysOffline file policy. Caller retains the
    /// same backend/auth guards required by ordinary offline downloads.
    pub fn begin_cached_plaintext_pin_verification<'a>(
        &'a self,
        scope: &CacheScope,
        entry: &RemoteEntry,
        pin_id: &str,
    ) -> Result<CachedPlaintextVerification<'a>, CacheError> {
        self.begin_cached_plaintext_verification_with_intent(scope, entry, Some(pin_id))
    }

    fn begin_cached_plaintext_verification_with_intent<'a>(
        &'a self,
        scope: &CacheScope,
        entry: &RemoteEntry,
        pin_id: Option<&str>,
    ) -> Result<CachedPlaintextVerification<'a>, CacheError> {
        validate_download_entry(scope, entry)?;
        let store = &self.inner.windows_content;
        let _lease = store.publication_lease()?;
        let mut db = self.lock_db()?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        validate_registered_scope(&tx, scope)?;
        validate_download_binding(&tx, scope, entry)?;
        let version = download_version(entry);
        let record = load_content_record(&tx, scope, &version)?;
        if record.byte_len != entry.size {
            return Err(CacheError::Corrupt);
        }
        let relative = format!("{}.blob", content_key(scope, &version));
        let reader = store
            .directory
            .open_owned_immutable_file(std::ffi::OsStr::new(&relative))
            .map_err(io_error)?;
        let intent = match pin_id {
            Some(id) => pin_download_intent(&tx, scope, entry, id)?,
            None => DownloadIntent::FileRevision(record_download_intent(&tx, scope, entry)?),
        };
        tx.commit().map_err(db_error)?;
        Ok(CachedPlaintextVerification {
            cache: self,
            scope: scope.clone(),
            entry: entry.clone(),
            intent,
            reader,
            relative,
            digest: record.sha256,
        })
    }
    /// Reserve a bounded ordinary file and record a new, not-ready offline
    /// intent atomically. All byte admission precedes any network operation.
    /// Existing complete versions use a separate verified promotion path.
    pub fn begin_plaintext_offline_download<'a>(
        &'a self,
        scope: &CacheScope,
        entry: &RemoteEntry,
    ) -> Result<PlaintextDownloadStage<'a>, CacheError> {
        self.begin_plaintext_download_with_intent(scope, entry, None)
    }

    /// Acquire content for one existing exact folder manifest member without
    /// creating an independent AlwaysOffline file policy. Caller retains the
    /// same backend/auth guards required by ordinary offline downloads.
    pub fn begin_plaintext_pin_download<'a>(
        &'a self,
        scope: &CacheScope,
        entry: &RemoteEntry,
        pin_id: &str,
    ) -> Result<PlaintextDownloadStage<'a>, CacheError> {
        self.begin_plaintext_download_with_intent(scope, entry, Some(pin_id))
    }

    fn begin_plaintext_download_with_intent<'a>(
        &'a self,
        scope: &CacheScope,
        entry: &RemoteEntry,
        pin_id: Option<&str>,
    ) -> Result<PlaintextDownloadStage<'a>, CacheError> {
        validate_download_entry(scope, entry)?;
        let store = &self.inner.windows_content;
        let lease = store.publication_lease()?;
        let mut db = self.lock_db()?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        validate_registered_scope(&tx, scope)?;
        validate_download_binding(&tx, scope, entry)?;
        let version = download_version(entry);
        match load_content_record(&tx, scope, &version) {
            Ok(_) => return Err(CacheError::Conflict),
            Err(CacheError::NotFound) => {}
            Err(error) => return Err(error),
        }
        let inventory = windows_content_inventory(&tx, store, &lease)?;
        let used = total_content_bytes(&tx)?
            .saturating_add(inventory.unindexed_bytes)
            .max(inventory.physical_bytes);
        if used
            .checked_add(entry.size)
            .is_none_or(|total| total > self.inner.quota_bytes)
        {
            return Err(CacheError::InsufficientSpace);
        }
        let count: i64 = tx
            .query_row("SELECT COUNT(*) FROM contents", [], |row| row.get(0))
            .map_err(db_error)?;
        if count >= MAX_CONTENT_RECORDS as i64 {
            return Err(CacheError::LimitExceeded);
        }
        // Validate intent capacity before creating a reservation file.
        let intent = match pin_id {
            Some(id) => pin_download_intent(&tx, scope, entry, id)?,
            None => DownloadIntent::FileRevision(record_download_intent(&tx, scope, entry)?),
        };
        let relative = format!("{}.blob", content_key(scope, &version));
        let blob = store.reserve_download(&lease, &relative, entry.size)?;
        tx.commit().map_err(db_error)?;
        drop(db);
        drop(lease);
        Ok(PlaintextDownloadStage {
            cache: self,
            scope: scope.clone(),
            entry: entry.clone(),
            intent,
            blob,
        })
    }
}

fn download_version(entry: &RemoteEntry) -> ContentVersion {
    ContentVersion {
        resource_id: entry.id.clone(),
        etag: entry.etag.clone(),
        protection: ContentProtection::Plaintext,
    }
}

fn validate_download_binding(
    db: &Connection,
    scope: &CacheScope,
    entry: &RemoteEntry,
) -> Result<(), CacheError> {
    let matches: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=?1 AND e.resource_id=?2 AND e.path=?3 AND e.etag=?4 AND e.size=?5 AND e.directory=0 AND e.encrypted=0 AND l.complete=1) AND NOT EXISTS(SELECT 1 FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=?1 AND l.complete=1 AND (e.resource_id=?2 OR e.path=?3) AND (e.resource_id<>?2 OR e.path<>?3 OR e.etag<>?4 OR e.size<>?5 OR e.directory<>0 OR e.encrypted<>0))",
        params![scope.key,entry.id,entry.path,entry.etag,i64_from_u64(entry.size)?], |row| row.get(0),
    ).map_err(db_error)?;
    if matches {
        Ok(())
    } else {
        Err(CacheError::PolicyConflict)
    }
}

fn validate_download_entry(scope: &CacheScope, entry: &RemoteEntry) -> Result<(), CacheError> {
    validate_entry(entry)?;
    if scope.protection != ScopeProtection::PlaintextAllowed || entry.encrypted || entry.directory {
        return Err(CacheError::ProtectionMismatch);
    }
    if entry.size > MAX_STAGED_PLAINTEXT_BYTES {
        return Err(CacheError::LimitExceeded);
    }
    if entry.etag.trim().is_empty()
        || entry.etag.trim() != entry.etag
        || entry.etag.starts_with("W/")
        || entry.etag.chars().any(char::is_control)
    {
        return Err(CacheError::InvalidContentVersion);
    }
    Ok(())
}

fn record_download_intent(
    tx: &Connection,
    scope: &CacheScope,
    entry: &RemoteEntry,
) -> Result<i64, CacheError> {
    tx.execute(
            "INSERT INTO policies(scope_key,resource_id,policy,target_path,target_etag,target_state) VALUES(?1,?2,1,?3,?4,1) ON CONFLICT(scope_key,resource_id) DO UPDATE SET policy=1,target_path=excluded.target_path,target_etag=excluded.target_etag,target_state=1",
            params![scope.key,entry.id,entry.path,entry.etag],
        ).map_err(db_error)?;
    let intent_revision: i64 = tx
        .query_row(
            "SELECT revision FROM policy_intent_revisions WHERE scope_key=?1 AND resource_id=?2",
            params![scope.key, entry.id],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    Ok(intent_revision)
}

// Read and validate a complete manifest member in the same transaction as
// admission/commit. Removing, staling or replacing the pin fences publication.
fn pin_download_intent(
    db: &Connection,
    scope: &CacheScope,
    entry: &RemoteEntry,
    pin_id: &str,
) -> Result<DownloadIntent, CacheError> {
    validate_id(pin_id)?;
    let root = db.query_row(
        "SELECT p.root_id,p.root_path FROM pins p JOIN pin_items i ON i.pin_id=p.pin_id WHERE p.pin_id=?1 AND p.scope_key=?2 AND p.state IN (0,1) AND i.resource_id=?3 AND i.path=?4 AND i.etag=?5 AND i.size=?6 AND i.directory=0 AND i.encrypted=0 AND NOT EXISTS(SELECT 1 FROM policies q WHERE q.scope_key=p.scope_key AND q.resource_id=i.resource_id AND q.policy NOT IN (0,1))",
        params![pin_id,scope.key,entry.id,entry.path,entry.etag,i64_from_u64(entry.size)?],
        |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)),
    ).optional().map_err(db_error)?.ok_or(CacheError::PolicyConflict)?;
    validate_id(&root.0)?;
    validate_path(&root.1)?;
    Ok(DownloadIntent::FolderPin {
        id: pin_id.to_owned(),
        root_id: root.0,
        root_path: root.1,
    })
}

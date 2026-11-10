//! Storage-only ordinary-create custody. Admission is not server authorization.
use super::*;
#[path = "ordinary_create_clean.rs"]
mod clean;
#[cfg(target_os = "linux")]
#[path = "ordinary_create_discard.rs"]
mod discard;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum OrdinaryCreateState {
    Staged = 0,
    Ready = 1,
    Claimed = 2,
    Uncertain = 3,
    Conflict = 4,
    /// Terminal success: independently byte-verified, or server-confirmed for
    /// a fresh owned upload. The persisted value does not distinguish these;
    /// it is not evidence that an independent cloud-body hash was obtained.
    Verified = 5,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrdinaryCreateRequest {
    pub max_pending_bytes: u64,
    pub handoff_id: String,
    pub parent_resource_id: String,
    pub name: String,
    pub logical_path: String,
    pub expected_len: u64,
    pub expected_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrdinaryCreateReceipt {
    pub write: QueuedWrite,
    pub handoff_id: String,
    pub byte_len: u64,
    pub sha256: String,
    pub state: OrdinaryCreateState,
    pub remote: Option<ContentVersion>,
    pub local_handoff_acknowledged: bool,
    /// Committed retirement/eviction; a normal cache miss only after Verified+ACK.
    pub body_evicted: bool,
}
/// Opaque durable attempt authority. Dropping never resets a claim.
pub struct OrdinaryCreateClaim {
    receipt: OrdinaryCreateReceipt,
    nonce: String,
}
impl OrdinaryCreateClaim {
    pub fn receipt(&self) -> &OrdinaryCreateReceipt {
        &self.receipt
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrdinaryCreateCounts {
    pub staged: u64,
    pub ready: u64,
    pub claimed: u64,
    pub uncertain: u64,
    pub conflict: u64,
    pub verified: u64,
    pub legacy_unclassified: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrdinaryCreatePage {
    pub items: Vec<OrdinaryCreateReceipt>,
    pub counts: OrdinaryCreateCounts,
    pub next_after: Option<i64>,
}
fn plain(scope: &CacheScope) -> Result<(), CacheError> {
    if scope.protection != ScopeProtection::PlaintextAllowed {
        Err(CacheError::ProtectionMismatch)
    } else {
        Ok(())
    }
}
fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn strong_etag(value: &str) -> bool {
    value.len() > 2
        && value.len() <= MAX_SCOPE_FIELD
        && value.starts_with('"')
        && value.ends_with('"')
        && value.as_bytes()[1..value.len() - 1]
            .iter()
            .all(|b| *b == 0x21 || (0x23..=0x7e).contains(b) || *b >= 0x80)
}
fn validate_create_completion(
    receipt: &OrdinaryCreateReceipt,
    remote: &RemoteEntry,
) -> Result<(), CacheError> {
    validate_entry(remote)?;
    if remote.directory
        || remote.encrypted
        || !remote.writable
        || remote.path != receipt.write.logical_path
        || remote.size != receipt.byte_len
        || !strong_etag(&remote.etag)
        || remote.id == receipt.write.content.resource_id
    {
        return Err(CacheError::Conflict);
    }
    Ok(())
}
fn state(value: i64) -> Result<OrdinaryCreateState, CacheError> {
    match value {
        0 => Ok(OrdinaryCreateState::Staged),
        1 => Ok(OrdinaryCreateState::Ready),
        2 => Ok(OrdinaryCreateState::Claimed),
        3 => Ok(OrdinaryCreateState::Uncertain),
        4 => Ok(OrdinaryCreateState::Conflict),
        5 => Ok(OrdinaryCreateState::Verified),
        _ => Err(CacheError::Corrupt),
    }
}
pub(super) fn refuse_ledger_write(db: &Connection, id: i64) -> Result<(), CacheError> {
    let owned: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM ordinary_create_handoffs WHERE write_id=?1)",
            [id],
            |r| r.get(0),
        )
        .map_err(db_error)?;
    if owned {
        Err(CacheError::Conflict)
    } else {
        Ok(())
    }
}
// Validate the source digest before atomic publication, including idempotent retries.
struct CheckedSource<'a, R> {
    source: &'a mut R,
    expected: &'a str,
    digest: Sha256,
}
impl<R: Read> Read for CheckedSource<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let n = self.source.read(buf)?;
        if n == 0 {
            if format!("{:x}", self.digest.clone().finalize()) != self.expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "ordinary create source digest mismatch",
                ));
            }
        } else {
            self.digest.update(&buf[..n]);
        }
        Ok(n)
    }
}
fn version(scope: &CacheScope, request: &OrdinaryCreateRequest) -> ContentVersion {
    ContentVersion {
        resource_id: hash_fields(&[
            &scope.key,
            &request.parent_resource_id,
            &request.name,
            &request.logical_path,
        ]),
        etag: format!("journal-create-{}", request.handoff_id),
        protection: ContentProtection::Plaintext,
    }
}
// Load through the authenticated storage scope, and validate every redundant binding.
pub(super) fn load(
    db: &Connection,
    scope: &CacheScope,
    id: i64,
) -> Result<Option<OrdinaryCreateReceipt>, CacheError> {
    let result = db.query_row("SELECT w.parent_id,w.name,w.path,w.resource_id,w.base_kind,w.base_etag,w.content_key,w.state,w.created_at,h.handoff_id,h.state,h.path,h.content_key,h.claim_id,h.remote_id,h.remote_etag,h.body_len,h.body_sha256,h.local_handoff_ack,h.body_state,c.resource_id,c.etag,c.protection,c.byte_len,c.sha256,c.scope_key,c.relative_path FROM ordinary_create_handoffs h JOIN writes w ON w.id=h.write_id LEFT JOIN contents c ON c.content_key=w.content_key WHERE h.scope_key=?1 AND w.scope_key=?1 AND h.write_id=?2",
        params![scope.key,id], |r| Ok((
            r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,i64>(4)?,r.get::<_,String>(5)?,r.get::<_,String>(6)?,r.get::<_,i64>(7)?,r.get::<_,i64>(8)?,r.get::<_,String>(9)?,r.get::<_,i64>(10)?,r.get::<_,String>(11)?,r.get::<_,String>(12)?,r.get::<_,String>(13)?,r.get::<_,Option<String>>(14)?,r.get::<_,Option<String>>(15)?,r.get::<_,i64>(16)?,r.get::<_,String>(17)?,r.get::<_,i64>(18)?,r.get::<_,i64>(19)?,r.get::<_,Option<String>>(20)?,r.get::<_,Option<String>>(21)?,r.get::<_,Option<i64>>(22)?,r.get::<_,Option<i64>>(23)?,r.get::<_,Option<String>>(24)?,r.get::<_,Option<String>>(25)?,r.get::<_,Option<String>>(26)?
        ))).optional().map_err(db_error)?;
    let Some((
        parent,
        name,
        path,
        resource,
        base_kind,
        base_etag,
        key,
        write_state,
        created,
        handoff,
        raw_state,
        hpath,
        hkey,
        nonce,
        remote_id,
        remote_etag,
        len,
        digest,
        ack,
        body_state,
        content_id,
        etag,
        protection,
        content_len,
        content_digest,
        content_scope,
        relative_path,
    )) = result
    else {
        let exists: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM ordinary_create_handoffs WHERE scope_key=?1 AND write_id=?2)", params![scope.key,id], |r| r.get(0)).map_err(db_error)?;
        return if exists {
            Err(CacheError::Corrupt)
        } else {
            Ok(None)
        };
    };
    let status = state(raw_state)?;
    let expected_write = match status {
        OrdinaryCreateState::Uncertain | OrdinaryCreateState::Conflict => WriteState::Conflict,
        OrdinaryCreateState::Verified => WriteState::Verified,
        _ => WriteState::Pending,
    };
    let content = ContentVersion {
        resource_id: hash_fields(&[&scope.key, &parent, &name, &path]),
        etag: format!("journal-create-{handoff}"),
        protection: ContentProtection::Plaintext,
    };
    if id <= 0
        || base_kind != 0
        || !base_etag.is_empty()
        || resource.is_some()
        || path != hpath
        || key != hkey
        || content_key(scope, &content) != key
        || !hex(&handoff, 32)
        || !hex(&digest, 64)
        || len < 0
        || len as u64 > MAX_CONTENT_BYTES
        || decode_write_state(write_state)? != expected_write
        || (status == OrdinaryCreateState::Claimed) != !nonce.is_empty()
        || (!nonce.is_empty() && !hex(&nonce, 32))
        || !matches!(ack, 0 | 1)
        || !matches!(body_state, 0..=2)
        || (body_state != 0 && (ack != 1 || status != OrdinaryCreateState::Verified))
    {
        return Err(CacheError::Corrupt);
    }
    match (
        content_id,
        etag,
        protection,
        content_len,
        content_digest,
        content_scope,
        relative_path,
    ) {
        (
            Some(cid),
            Some(etag),
            Some(protection),
            Some(clen),
            Some(digest_found),
            Some(cscope),
            Some(relative),
        ) if body_state != 2
            && cid == content.resource_id
            && etag == content.etag
            && protection == ContentProtection::Plaintext as i64
            && clen == len
            && digest_found == digest
            && cscope == scope.key
            && relative == format!("{key}.blob") => {}
        (None, None, None, None, None, None, None) if body_state == 2 => {}
        _ => return Err(CacheError::Corrupt),
    }
    validate_id(&parent)?;
    validate_name(&name)?;
    validate_path(&path)?;
    if leaf_name(&path)? != name {
        return Err(CacheError::Corrupt);
    }
    let remote = match (remote_id, remote_etag) {
        (Some(id), Some(etag))
            if status == OrdinaryCreateState::Verified
                && strong_etag(&etag)
                && id != content.resource_id =>
        {
            validate_id(&id)?;
            Some(ContentVersion {
                resource_id: id,
                etag,
                protection: ContentProtection::Plaintext,
            })
        }
        (None, None) if status != OrdinaryCreateState::Verified => None,
        _ => return Err(CacheError::Corrupt),
    };
    Ok(Some(OrdinaryCreateReceipt {
        write: QueuedWrite {
            id,
            parent_resource_id: parent,
            name,
            logical_path: path,
            resource_id: resource,
            base: WriteCondition::Absent,
            content,
            state: expected_write,
            created_at_unix: created,
        },
        handoff_id: handoff,
        byte_len: len as u64,
        sha256: digest,
        state: status,
        remote,
        local_handoff_acknowledged: ack == 1,
        body_evicted: body_state != 0,
    }))
}
impl OrdinaryCreateReceipt {
    /// Compare only immutable custody identity; this grants no dispatch authority.
    pub fn has_same_immutable_binding(&self, other: &Self) -> bool {
        same_binding(self, other)
    }
}
fn same_binding(a: &OrdinaryCreateReceipt, b: &OrdinaryCreateReceipt) -> bool {
    let mut a = a.clone();
    let mut b = b.clone();
    a.state = OrdinaryCreateState::Staged;
    b.state = a.state;
    a.write.state = WriteState::Pending;
    b.write.state = a.write.state;
    a.remote = None;
    b.remote = None;
    a.local_handoff_acknowledged = false;
    b.local_handoff_acknowledged = false;
    a.body_evicted = false;
    b.body_evicted = false;
    a == b
}
#[cfg(test)]
std::thread_local! {
    static AFTER_CREATE_TRANSACTION_READ: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

fn current(
    db: &Connection,
    scope: &CacheScope,
    receipt: &OrdinaryCreateReceipt,
) -> Result<OrdinaryCreateReceipt, CacheError> {
    plain(scope)?;
    validate_registered_scope(db, scope)?;
    refuse_discarded_handoff(db, scope, &receipt.handoff_id)?;
    let found = load(db, scope, receipt.write.id)?.ok_or(CacheError::NotFound)?;
    #[cfg(test)]
    if !db.is_autocommit() {
        let hook = AFTER_CREATE_TRANSACTION_READ.with(|slot| slot.borrow_mut().take());
        if let Some(hook) = hook {
            hook();
        }
    }
    if !same_binding(&found, receipt) {
        return Err(CacheError::Conflict);
    }
    Ok(found)
}
fn refuse_discarded_handoff(
    db: &Connection,
    scope: &CacheScope,
    handoff_id: &str,
) -> Result<(), CacheError> {
    let discarded: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM ordinary_create_discards WHERE scope_key=?1 AND handoff_id=?2)",
        params![scope.key, handoff_id], |row| row.get(0),
    ).map_err(db_error)?;
    if discarded {
        Err(CacheError::Conflict)
    } else {
        Ok(())
    }
}
fn count(db: &Connection, sql: &str, scope: &CacheScope) -> Result<u64, CacheError> {
    let n: i64 = db
        .query_row(sql, params![scope.key], |r| r.get(0))
        .map_err(db_error)?;
    u64::try_from(n).map_err(|_| CacheError::Corrupt)
}
fn limits(
    db: &Connection,
    scope: &CacheScope,
    request: &OrdinaryCreateRequest,
) -> Result<(), CacheError> {
    let quota = configured_quota_bytes(db)?;
    if request.max_pending_bytes == 0
        || request.max_pending_bytes > quota
        || request.expected_len > MAX_CONTENT_BYTES
    {
        return Err(CacheError::LimitExceeded);
    }
    let protected = protected_content_bytes(db)?;
    let pending:i64 = db.query_row("SELECT COALESCE(SUM(byte_len),0) FROM contents c WHERE EXISTS(SELECT 1 FROM writes w WHERE w.content_key=c.content_key AND w.state IN(0,1))",[],|r|r.get(0)).map_err(db_error)?;
    if pending < 0
        || (pending as u64)
            .checked_add(request.expected_len)
            .is_none_or(|n| n > request.max_pending_bytes)
        || request
            .expected_len
            .checked_mul(2)
            .and_then(|n| n.checked_add(protected))
            .is_none_or(|n| n > quota)
    {
        return Err(CacheError::LimitExceeded);
    }
    let content_records: i64 = db
        .query_row("SELECT COUNT(*) FROM contents", [], |r| r.get(0))
        .map_err(db_error)?;
    if content_records < 0 || content_records as usize >= MAX_CONTENT_RECORDS {
        return Err(CacheError::LimitExceeded);
    }
    let global: i64 = db
        .query_row("SELECT COUNT(*) FROM ordinary_create_handoffs", [], |r| {
            r.get(0)
        })
        .map_err(db_error)?;
    if global < 0
        || global as usize >= MAX_JOURNAL_RECORDS
        || count(db, "SELECT COUNT(*) FROM writes WHERE scope_key=?1", scope)?
            >= MAX_JOURNAL_RECORDS as u64
    {
        return Err(CacheError::LimitExceeded);
    }
    let collision:bool = db.query_row("SELECT EXISTS(SELECT 1 FROM writes WHERE scope_key=?1 AND state IN(0,1) AND (path=?2 OR (parent_id=?3 AND name=?4)))",params![scope.key,request.logical_path,request.parent_resource_id,request.name],|r|r.get(0)).map_err(db_error)?;
    if collision {
        return Err(CacheError::Conflict);
    }
    Ok(())
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
        if found.body_evicted {
            if found.state != OrdinaryCreateState::Verified
                || found.write.state != WriteState::Verified
                || !found.local_handoff_acknowledged
                || found.remote.is_none()
            {
                return Err(CacheError::Conflict);
            }
            return Ok(found);
        }
        if !found.local_handoff_acknowledged
            && !matches!(
                found.state,
                OrdinaryCreateState::Ready
                    | OrdinaryCreateState::Claimed
                    | OrdinaryCreateState::Uncertain
                    | OrdinaryCreateState::Verified
            )
        {
            return Err(CacheError::Conflict);
        }
        // Every live-body acknowledgement proves the entire indexed immutable
        // copy, including retries. Callers may prepare a durable manifest from
        // metadata alone; only this verification grants local custody success.
        // Keep the verified reader pinned until the transaction commits.
        let _reader = self.open_content(scope, &found.write.content)?;
        let db = self.lock_db()?;
        let tx =
            Transaction::new_unchecked(&db, TransactionBehavior::Immediate).map_err(db_error)?;
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

    /// Copy one exact Ready body into the caller's new private disposable file.
    /// Success means the complete copy matched the immutable receipt; partial
    /// output on any error must be discarded. This grants no dispatch authority.
    /// The original durable body/journal remain custody, so the copy is not synced.
    /// Unix only: Windows callers must retain protected-storage streaming instead
    /// of exporting its bytes through an ordinary plaintext temporary path.
    #[cfg(unix)]
    pub fn copy_ready_ordinary_create_snapshot_cancellable(
        &self,
        scope: &CacheScope,
        receipt: &OrdinaryCreateReceipt,
        output: &mut File,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<(), CacheError> {
        use std::os::unix::fs::MetadataExt;
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        plain(scope)?;
        // Pin indexed source lifetime against cache deletion while copying.
        // Neither the DB guard nor a global mutation lock spans body IO.
        let _lease = self.lock_content_publication()?;
        let key = content_key(scope, &receipt.write.content);
        let validate = |db: &Connection| -> Result<(), CacheError> {
            let found = current(db, scope, receipt)?;
            if found.state != OrdinaryCreateState::Ready || found.body_evicted {
                return Err(CacheError::Conflict);
            }
            let (retention, policy): (i64, i64) = db
                .query_row(
                    "SELECT c.retention,COALESCE(p.policy,0) FROM contents c LEFT JOIN policies p ON p.scope_key=c.scope_key AND p.resource_id=c.resource_id WHERE c.content_key=?1 AND c.scope_key=?2",
                    params![key, scope.key],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(db_error)?
                .ok_or(CacheError::NotFound)?;
            if retention == Retention::Recent as i64
                && (policy == AvailabilityPolicy::CloudOnly as i64
                    || folder_policy::inherited_cloud_only(
                        db,
                        scope,
                        &receipt.write.content.resource_id,
                    )?)
            {
                return Err(CacheError::PolicyConflict);
            }
            Ok(())
        };
        {
            let db = self.lock_db()?;
            validate(&db)?;
        }
        let directory = File::from(
            rustix::fs::open(
                &self.inner.content_dir,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| io_error(error.into()))?,
        );
        let mut source = File::from(
            rustix::fs::openat(
                &directory,
                format!("{key}.blob"),
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| io_error(error.into()))?,
        );
        let directory_metadata = directory.metadata().map_err(io_error)?;
        if directory_metadata.mode() & 0o077 != 0 {
            return Err(CacheError::UnsafeDirectory);
        }
        let owner = directory_metadata.uid();
        let source_metadata = source.metadata().map_err(io_error)?;
        let output_metadata = output.metadata().map_err(io_error)?;
        for metadata in [&source_metadata, &output_metadata] {
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != owner
                || metadata.mode() & 0o077 != 0
            {
                return Err(CacheError::UnsafeDirectory);
            }
        }
        if source_metadata.len() != receipt.byte_len
            || output_metadata.len() != 0
            || (source_metadata.dev(), source_metadata.ino())
                == (output_metadata.dev(), output_metadata.ino())
        {
            return Err(CacheError::Conflict);
        }
        output.rewind().map_err(io_error)?;
        let mut hasher = Sha256::new();
        let mut length = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            if cancelled() {
                return Err(CacheError::Cancelled);
            }
            let count = source.read(&mut buffer).map_err(io_error)?;
            if cancelled() {
                return Err(CacheError::Cancelled);
            }
            if count == 0 {
                break;
            }
            length = length
                .checked_add(count as u64)
                .filter(|length| *length <= receipt.byte_len)
                .ok_or(CacheError::Corrupt)?;
            output.write_all(&buffer[..count]).map_err(io_error)?;
            hasher.update(&buffer[..count]);
        }
        if length != receipt.byte_len
            || format!("{:x}", hasher.finalize()) != receipt.sha256
            || output.metadata().map_err(io_error)?.len() != receipt.byte_len
        {
            return Err(CacheError::Corrupt);
        }
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        let db = self.lock_db()?;
        validate(&db)?;
        db.execute(
            "UPDATE contents SET last_accessed=?2 WHERE content_key=?1",
            params![key, now_unix()],
        )
        .map_err(db_error)?;
        drop(db);
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        Ok(())
    }

    /// Persist immutable bytes only. This does not prove target absence or admit HTTP.
    pub fn stage_ordinary_create<R: Read>(
        &self,
        scope: &CacheScope,
        request: OrdinaryCreateRequest,
        source: &mut R,
    ) -> Result<OrdinaryCreateReceipt, CacheError> {
        plain(scope)?;
        validate_id(&request.parent_resource_id)?;
        validate_name(&request.name)?;
        validate_path(&request.logical_path)?;
        if leaf_name(&request.logical_path)? != request.name
            || !hex(&request.handoff_id, 32)
            || !hex(&request.expected_sha256, 64)
        {
            return Err(CacheError::InvalidEntry);
        }
        if request.expected_len > MAX_CONTENT_BYTES
            || request.max_pending_bytes == 0
            || request.max_pending_bytes > self.try_quota_bytes()?
        {
            return Err(CacheError::LimitExceeded);
        }
        #[cfg(windows)]
        let lease = self.inner.windows_content.publication_lease()?;
        #[cfg(not(windows))]
        let _lease = self.lock_content_publication()?;
        let existing = {
            let db = self.lock_db()?;
            register_scope(&db, scope)?;
            refuse_discarded_handoff(&db, scope, &request.handoff_id)?;
            let id:Option<i64> = db.query_row("SELECT write_id FROM ordinary_create_handoffs WHERE scope_key=?1 AND handoff_id=?2",params![scope.key,request.handoff_id],|r|r.get(0)).optional().map_err(db_error)?;
            let existing = id
                .map(|id| load(&db, scope, id)?.ok_or(CacheError::Corrupt))
                .transpose()?;
            if let Some(existing) = &existing {
                if existing.write.parent_resource_id != request.parent_resource_id
                    || existing.write.name != request.name
                    || existing.write.logical_path != request.logical_path
                    || existing.byte_len != request.expected_len
                    || existing.sha256 != request.expected_sha256
                {
                    return Err(CacheError::Conflict);
                }
            } else {
                limits(&db, scope, &request)?;
            }
            existing
        };
        if existing.is_none()
            && fs2::available_space(&self.inner.content_dir).map_err(io_error)?
                < request.expected_len
        {
            return Err(CacheError::InsufficientSpace);
        }
        if let Some(existing) = &existing
            && existing.body_evicted
        {
            let mut bounded = source.take(request.expected_len + 1);
            let mut checked = CheckedSource {
                source: &mut bounded,
                expected: &request.expected_sha256,
                digest: Sha256::new(),
            };
            let len = io::copy(&mut checked, &mut io::sink()).map_err(io_error)?;
            if len != request.expected_len {
                return Err(CacheError::Conflict);
            }
            let db = self.lock_db()?;
            return load(&db, scope, existing.write.id)?.ok_or(CacheError::Corrupt);
        }
        let mut checked_source = CheckedSource {
            source,
            expected: &request.expected_sha256,
            digest: Sha256::new(),
        };
        let source = &mut checked_source;
        let content = version(scope, &request);
        let key = content_key(scope, &content);
        let relative = format!("{key}.blob");
        #[cfg(windows)]
        let (len, digest) = {
            let receipt = self.inner.windows_content.publish_under_lease(
                &lease,
                &relative,
                source,
                request.expected_len,
            )?;
            (receipt.byte_len, receipt.digest)
        };
        #[cfg(not(windows))]
        let (len, digest) = {
            let (len, digest, _) = write_content_atomically(
                &self.inner.content_dir,
                &self.inner.content_dir.join(&relative),
                source,
                request.expected_len,
            )?;
            (len, digest)
        };
        if len != request.expected_len || digest != request.expected_sha256 {
            return Err(CacheError::Conflict);
        }
        let db = self.lock_db()?;
        if let Some(existing) = existing {
            // Exact idempotent custody lookup is read-only, not a writer.
            return load(&db, scope, existing.write.id)?.ok_or(CacheError::Corrupt);
        }
        let tx =
            Transaction::new_unchecked(&db, TransactionBehavior::Immediate).map_err(db_error)?;
        refuse_discarded_handoff(&tx, scope, &request.handoff_id)?;
        limits(&tx, scope, &request)?;
        tx.execute("INSERT INTO contents(content_key,scope_key,resource_id,etag,protection,byte_len,sha256,relative_path,last_accessed,retention) VALUES(?1,?2,?3,?4,0,?5,?6,?7,?8,1)",params![key,scope.key,content.resource_id,content.etag,i64_from_u64(len)?,digest,relative,now_unix()]).map_err(db_error)?;
        tx.execute("INSERT INTO writes(scope_key,parent_id,name,path,resource_id,base_kind,base_etag,content_key,state,created_at) VALUES(?1,?2,?3,?4,NULL,0,'',?5,0,?6)",params![scope.key,request.parent_resource_id,request.name,request.logical_path,key,now_unix()]).map_err(db_error)?;
        let id = tx.last_insert_rowid();
        tx.execute("INSERT INTO ordinary_create_handoffs(write_id,scope_key,handoff_id,path,content_key,state,updated_at,body_len,body_sha256) VALUES(?1,?2,?3,?4,?5,0,?6,?7,?8)",params![id,scope.key,request.handoff_id,request.logical_path,key,now_unix(),i64_from_u64(len)?,digest]).map_err(db_error)?;
        let receipt = load(&tx, scope, id)?.ok_or(CacheError::Corrupt)?;
        tx.commit().map_err(db_error)?;
        Ok(receipt)
    }
    pub fn ordinary_create_for_handoff(
        &self,
        scope: &CacheScope,
        handoff_id: &str,
    ) -> Result<Option<OrdinaryCreateReceipt>, CacheError> {
        plain(scope)?;
        if !hex(handoff_id, 32) {
            return Err(CacheError::InvalidEntry);
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let id:Option<i64>=db.query_row("SELECT write_id FROM ordinary_create_handoffs WHERE scope_key=?1 AND handoff_id=?2",params![scope.key,handoff_id],|r|r.get(0)).optional().map_err(db_error)?;
        id.map(|id| load(&db, scope, id)?.ok_or(CacheError::Corrupt))
            .transpose()
    }
    pub fn ordinary_create_for_write(
        &self,
        scope: &CacheScope,
        write_id: i64,
    ) -> Result<Option<OrdinaryCreateReceipt>, CacheError> {
        plain(scope)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        load(&db, scope, write_id)
    }

    /// Find the retained body for one exact remotely verified file version.
    /// This is a lookup only: it never adopts an unreferenced blob or grants
    /// dispatch authority. A missing or evicted body is an ordinary cache miss.
    pub fn verified_ordinary_create_for_remote(
        &self,
        scope: &CacheScope,
        logical_path: &str,
        remote_resource_id: &str,
        remote_etag: &str,
    ) -> Result<Option<OrdinaryCreateReceipt>, CacheError> {
        plain(scope)?;
        validate_path(logical_path)?;
        validate_id(remote_resource_id)?;
        if !strong_etag(remote_etag) {
            return Err(CacheError::InvalidEntry);
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let mut statement = db
            .prepare("SELECT write_id FROM ordinary_create_handoffs WHERE scope_key=?1 AND path=?2 AND remote_id=?3 AND remote_etag=?4 ORDER BY write_id DESC LIMIT 2")
            .map_err(db_error)?;
        let ids = statement
            .query_map(
                params![scope.key, logical_path, remote_resource_id, remote_etag],
                |row| row.get::<_, i64>(0),
            )
            .map_err(db_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_error)?;
        if ids.len() > 1 {
            return Err(CacheError::Corrupt);
        }
        let Some(id) = ids.first() else {
            return Ok(None);
        };
        let receipt = load(&db, scope, *id)?.ok_or(CacheError::Corrupt)?;
        let remote_matches = receipt.remote.as_ref().is_some_and(|remote| {
            remote.resource_id == remote_resource_id
                && remote.etag == remote_etag
                && remote.protection == ContentProtection::Plaintext
        });
        if receipt.state != OrdinaryCreateState::Verified
            || receipt.write.logical_path != logical_path
            || !remote_matches
        {
            return Err(CacheError::Corrupt);
        }
        if receipt.body_evicted {
            return Ok(None);
        }
        Ok(Some(receipt))
    }
    pub fn admit_ordinary_create(
        &self,
        scope: &CacheScope,
        staged: &OrdinaryCreateReceipt,
    ) -> Result<OrdinaryCreateReceipt, CacheError> {
        if !matches!(
            staged.state,
            OrdinaryCreateState::Staged | OrdinaryCreateState::Ready
        ) {
            return Err(CacheError::Conflict);
        }
        let db = self.lock_db()?;
        let tx =
            Transaction::new_unchecked(&db, TransactionBehavior::Immediate).map_err(db_error)?;
        let found = current(&tx, scope, staged)?;
        if found.state == OrdinaryCreateState::Ready {
            return Ok(found);
        }
        if found.state != OrdinaryCreateState::Staged {
            return Err(CacheError::Conflict);
        }
        transition(&tx, scope, staged.write.id, 0, 1, "", None)?;
        let out = load(&tx, scope, staged.write.id)?.ok_or(CacheError::Corrupt)?;
        tx.commit().map_err(db_error)?;
        Ok(out)
    }
    pub fn claim_ordinary_create(
        &self,
        scope: &CacheScope,
        ready: &OrdinaryCreateReceipt,
    ) -> Result<Option<OrdinaryCreateClaim>, CacheError> {
        if ready.state != OrdinaryCreateState::Ready {
            return Err(CacheError::Conflict);
        }
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| CacheError::Io("secure random generation failed".into()))?;
        let nonce: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let db = self.lock_db()?;
        let tx =
            Transaction::new_unchecked(&db, TransactionBehavior::Immediate).map_err(db_error)?;
        let found = current(&tx, scope, ready)?;
        if found.state != OrdinaryCreateState::Ready {
            return Ok(None);
        }
        transition(&tx, scope, ready.write.id, 1, 2, &nonce, None)?;
        let receipt = load(&tx, scope, ready.write.id)?.ok_or(CacheError::Corrupt)?;
        tx.commit().map_err(db_error)?;
        Ok(Some(OrdinaryCreateClaim { receipt, nonce }))
    }
    pub fn block_ordinary_create(
        &self,
        scope: &CacheScope,
        receipt: &OrdinaryCreateReceipt,
    ) -> Result<OrdinaryCreateReceipt, CacheError> {
        let db = self.lock_db()?;
        let tx =
            Transaction::new_unchecked(&db, TransactionBehavior::Immediate).map_err(db_error)?;
        let found = current(&tx, scope, receipt)?;
        if found.state != receipt.state
            || !matches!(
                found.state,
                OrdinaryCreateState::Staged | OrdinaryCreateState::Ready
            )
        {
            return Err(CacheError::Conflict);
        }
        transition(
            &tx,
            scope,
            receipt.write.id,
            found.state as i64,
            4,
            "",
            None,
        )?;
        write_state(&tx, scope, receipt.write.id, WriteState::Conflict)?;
        let out = load(&tx, scope, receipt.write.id)?.ok_or(CacheError::Corrupt)?;
        tx.commit().map_err(db_error)?;
        Ok(out)
    }
    pub fn mark_ordinary_create_uncertain(
        &self,
        scope: &CacheScope,
        claim: OrdinaryCreateClaim,
    ) -> Result<OrdinaryCreateReceipt, CacheError> {
        self.finish_create(scope, &claim, None)
    }
    /// Complete a fresh owned create after independent cloud-body verification.
    pub fn complete_ordinary_create(
        &self,
        scope: &CacheScope,
        claim: &OrdinaryCreateClaim,
        verified: &RemoteEntry,
        verified_sha256: &str,
    ) -> Result<OrdinaryCreateReceipt, CacheError> {
        validate_create_completion(&claim.receipt, verified)?;
        if verified_sha256 != claim.receipt.sha256 {
            return Err(CacheError::Conflict);
        }
        self.finish_create(scope, claim, Some(verified))
    }
    /// Complete only the current owned claim after the engine's opted-in
    /// backend confirms the complete upload and validates current metadata.
    /// No remote readback digest is asserted. Local hash/custody stay bound to
    /// the immutable claim; the nonce/state CAS refuses stopped or old claims.
    pub fn complete_server_confirmed_ordinary_create(
        &self,
        scope: &CacheScope,
        claim: &OrdinaryCreateClaim,
        confirmed: &RemoteEntry,
    ) -> Result<OrdinaryCreateReceipt, CacheError> {
        validate_create_completion(&claim.receipt, confirmed)?;
        self.finish_create(scope, claim, Some(confirmed))
    }
    /// Complete a stopped create only after the engine independently reads
    /// and hashes its exact current cloud revision. This never grants send
    /// authority, resets an attempt, acknowledges custody or removes a body.
    pub fn confirm_ordinary_create_readback(
        &self,
        scope: &CacheScope,
        receipt: &OrdinaryCreateReceipt,
        verified: &RemoteEntry,
        verified_sha256: &str,
    ) -> Result<OrdinaryCreateReceipt, CacheError> {
        validate_entry(verified)?;
        if !matches!(
            receipt.state,
            OrdinaryCreateState::Uncertain | OrdinaryCreateState::Conflict
        ) || verified.directory
            || verified.encrypted
            || !verified.writable
            || verified.path != receipt.write.logical_path
            || verified.size != receipt.byte_len
            || verified_sha256 != receipt.sha256
            || !strong_etag(&verified.etag)
            || verified.id == receipt.write.content.resource_id
        {
            return Err(CacheError::Conflict);
        }
        let db = self.lock_db()?;
        let tx =
            Transaction::new_unchecked(&db, TransactionBehavior::Immediate).map_err(db_error)?;
        let found = current(&tx, scope, receipt)?;
        if found.state != receipt.state || found.body_evicted {
            return Err(CacheError::Conflict);
        }
        transition(&tx, scope, found.write.id, found.state as i64, 5, "", None)?;
        let n = tx.execute(
            "UPDATE ordinary_create_handoffs SET remote_id=?3,remote_etag=?4 WHERE scope_key=?1 AND write_id=?2 AND state=5",
            params![scope.key, found.write.id, verified.id, verified.etag],
        ).map_err(db_error)?;
        if n != 1 {
            return Err(CacheError::Corrupt);
        }
        write_state(&tx, scope, found.write.id, WriteState::Verified)?;
        let out = load(&tx, scope, found.write.id)?.ok_or(CacheError::Corrupt)?;
        tx.commit().map_err(db_error)?;
        Ok(out)
    }
    fn finish_create(
        &self,
        scope: &CacheScope,
        claim: &OrdinaryCreateClaim,
        remote: Option<&RemoteEntry>,
    ) -> Result<OrdinaryCreateReceipt, CacheError> {
        let db = self.lock_db()?;
        let tx =
            Transaction::new_unchecked(&db, TransactionBehavior::Immediate).map_err(db_error)?;
        let found = current(&tx, scope, &claim.receipt)?;
        if found.state != OrdinaryCreateState::Claimed
            || claim.receipt.state != OrdinaryCreateState::Claimed
        {
            return Err(CacheError::Conflict);
        }
        let target = if remote.is_some() { 5 } else { 3 };
        transition(
            &tx,
            scope,
            found.write.id,
            2,
            target,
            "",
            Some(&claim.nonce),
        )?;
        if let Some(remote) = remote {
            let n=tx.execute("UPDATE ordinary_create_handoffs SET remote_id=?3,remote_etag=?4 WHERE scope_key=?1 AND write_id=?2 AND state=5",params![scope.key,found.write.id,remote.id,remote.etag]).map_err(db_error)?;
            if n != 1 {
                return Err(CacheError::Corrupt);
            }
        }
        write_state(
            &tx,
            scope,
            found.write.id,
            if remote.is_some() {
                WriteState::Verified
            } else {
                WriteState::Conflict
            },
        )?;
        let out = load(&tx, scope, found.write.id)?.ok_or(CacheError::Corrupt)?;
        tx.commit().map_err(db_error)?;
        Ok(out)
    }
    /// Call only after sole-uploader ownership and all prior workers are terminal.
    pub fn recover_interrupted_ordinary_creates(
        &self,
        scope: &CacheScope,
    ) -> Result<usize, CacheError> {
        plain(scope)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let tx =
            Transaction::new_unchecked(&db, TransactionBehavior::Immediate).map_err(db_error)?;
        let ids = ids(
            &tx,
            scope,
            "SELECT write_id FROM ordinary_create_handoffs WHERE scope_key=?1 AND state=2 ORDER BY write_id",
            MAX_JOURNAL_RECORDS,
        )?;
        for id in &ids {
            let found = load(&tx, scope, *id)?.ok_or(CacheError::Corrupt)?;
            if found.state != OrdinaryCreateState::Claimed {
                return Err(CacheError::Corrupt);
            }
            transition(&tx, scope, *id, 2, 3, "", None)?;
            write_state(&tx, scope, *id, WriteState::Conflict)?;
        }
        tx.commit().map_err(db_error)?;
        Ok(ids.len())
    }
    pub fn ordinary_create_path_blocked(
        &self,
        scope: &CacheScope,
        logical_path: &str,
    ) -> Result<bool, CacheError> {
        plain(scope)?;
        validate_path(logical_path)?;
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        db.query_row("SELECT EXISTS(SELECT 1 FROM writes WHERE scope_key=?1 AND state IN(0,1) AND (path=?2 OR ?2='/' OR substr(path,1,length(?2)+1)=?2||'/' OR substr(?2,1,length(path)+1)=path||'/'))",params![scope.key,logical_path],|r|r.get(0)).map_err(db_error)
    }
    pub fn ordinary_creates(
        &self,
        scope: &CacheScope,
        after_write_id: Option<i64>,
        limit: usize,
    ) -> Result<OrdinaryCreatePage, CacheError> {
        plain(scope)?;
        if !(1..=256).contains(&limit) || after_write_id.is_some_and(|n| n < 0) {
            return Err(CacheError::LimitExceeded);
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let mut statement=db.prepare("SELECT write_id FROM ordinary_create_handoffs WHERE scope_key=?1 AND write_id>?2 ORDER BY write_id LIMIT ?3").map_err(db_error)?;
        let ids = statement
            .query_map(
                params![scope.key, after_write_id.unwrap_or(0), limit as i64 + 1],
                |r| r.get::<_, i64>(0),
            )
            .map_err(db_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_error)?;
        let more = ids.len() > limit;
        let mut items = Vec::new();
        for id in ids.into_iter().take(limit) {
            items.push(load(&db, scope, id)?.ok_or(CacheError::Corrupt)?);
        }
        let mut counts = OrdinaryCreateCounts::default();
        let mut statement=db.prepare("SELECT state,COUNT(*) FROM ordinary_create_handoffs WHERE scope_key=?1 GROUP BY state").map_err(db_error)?;
        let groups = statement
            .query_map(params![scope.key], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
            })
            .map_err(db_error)?;
        for group in groups {
            let (raw, n) = group.map_err(db_error)?;
            let n = u64::try_from(n).map_err(|_| CacheError::Corrupt)?;
            match state(raw)? {
                OrdinaryCreateState::Staged => counts.staged = n,
                OrdinaryCreateState::Ready => counts.ready = n,
                OrdinaryCreateState::Claimed => counts.claimed = n,
                OrdinaryCreateState::Uncertain => counts.uncertain = n,
                OrdinaryCreateState::Conflict => counts.conflict = n,
                OrdinaryCreateState::Verified => counts.verified = n,
            }
        }
        counts.legacy_unclassified = count(
            &db,
            "SELECT COUNT(*) FROM writes w WHERE scope_key=?1 AND base_kind=0 AND state IN(0,1) AND NOT EXISTS(SELECT 1 FROM ordinary_create_handoffs h WHERE h.write_id=w.id)",
            scope,
        )?;
        let next_after = if more {
            items.last().map(|r| r.write.id)
        } else {
            None
        };
        Ok(OrdinaryCreatePage {
            items,
            counts,
            next_after,
        })
    }
    pub fn ready_ordinary_creates(
        &self,
        scope: &CacheScope,
        limit: usize,
    ) -> Result<Vec<OrdinaryCreateReceipt>, CacheError> {
        self.ready_ordinary_create_discovery(scope, limit, &[])
            .map(|(_, receipts)| receipts)
    }

    /// Return the original bounded Ready ID window and hydrate only candidates
    /// not already owned by this scope's in-process preparation workers. IDs
    /// are discovery hints only; callers still need fresh receipt validation
    /// and the durable one-use claim before sending anything.
    pub fn ready_ordinary_create_discovery(
        &self,
        scope: &CacheScope,
        limit: usize,
        preparing_write_ids: &[i64],
    ) -> Result<(Vec<i64>, Vec<OrdinaryCreateReceipt>), CacheError> {
        plain(scope)?;
        if !(1..=64).contains(&limit) || preparing_write_ids.len() > 4 {
            return Err(CacheError::LimitExceeded);
        }
        if preparing_write_ids.iter().any(|id| *id <= 0) {
            return Err(CacheError::InvalidEntry);
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        let mut statement=db.prepare("SELECT write_id FROM ordinary_create_handoffs WHERE scope_key=?1 AND state=1 ORDER BY write_id LIMIT ?2").map_err(db_error)?;
        let ids = statement
            .query_map(params![scope.key, limit as i64], |r| r.get::<_, i64>(0))
            .map_err(db_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_error)?;
        let mut receipts = Vec::with_capacity(ids.len());
        for id in &ids {
            if !preparing_write_ids.contains(id) {
                receipts.push(load(&db, scope, *id)?.ok_or(CacheError::Corrupt)?);
            }
        }
        // Do not refill the window after filtering: workers use all observed
        // IDs to retain the same bounded deferral/retry bookkeeping.
        Ok((ids, receipts))
    }
}
fn ids(db: &Connection, scope: &CacheScope, sql: &str, max: usize) -> Result<Vec<i64>, CacheError> {
    let mut statement = db.prepare(sql).map_err(db_error)?;
    let mut out = Vec::new();
    let rows = statement
        .query_map(params![scope.key], |r| r.get::<_, i64>(0))
        .map_err(db_error)?;
    for row in rows {
        if out.len() >= max {
            return Err(CacheError::LimitExceeded);
        }
        out.push(row.map_err(db_error)?);
    }
    Ok(out)
}
fn transition(
    db: &Connection,
    scope: &CacheScope,
    id: i64,
    from: i64,
    to: i64,
    nonce: &str,
    expected_nonce: Option<&str>,
) -> Result<(), CacheError> {
    let n=db.execute("UPDATE ordinary_create_handoffs SET state=?4,claim_id=?5,updated_at=?6 WHERE scope_key=?1 AND write_id=?2 AND state=?3 AND (?7 IS NULL OR claim_id=?7)",params![scope.key,id,from,to,nonce,now_unix(),expected_nonce]).map_err(db_error)?;
    if n != 1 {
        Err(CacheError::Conflict)
    } else {
        Ok(())
    }
}
fn write_state(
    db: &Connection,
    scope: &CacheScope,
    id: i64,
    state: WriteState,
) -> Result<(), CacheError> {
    let n = db
        .execute(
            "UPDATE writes SET state=?3 WHERE scope_key=?1 AND id=?2",
            params![scope.key, id, state as i64],
        )
        .map_err(db_error)?;
    if n != 1 {
        Err(CacheError::Corrupt)
    } else {
        Ok(())
    }
}
#[cfg(all(test, unix))]
#[path = "ordinary_create_tests.rs"]
mod tests;

// Migration validates all retained bindings, not just successful backfill row counts.
pub(super) fn validate_migration(db: &Connection) -> Result<(), CacheError> {
    let mut statement=db.prepare("SELECT h.write_id,s.origin,s.account_id,s.space_id,s.root_resource_id,s.protection,h.scope_key FROM ordinary_create_handoffs h LEFT JOIN scopes s ON s.scope_key=h.scope_key ORDER BY h.write_id").map_err(db_error)?;
    let rows = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, String>(6)?,
            ))
        })
        .map_err(db_error)?;
    let mut count = 0;
    for row in rows {
        count += 1;
        if count > MAX_JOURNAL_RECORDS {
            return Err(CacheError::LimitExceeded);
        }
        let (id, origin, account, space, root, protection, key) = row.map_err(db_error)?;
        if protection != ScopeProtection::PlaintextAllowed as i64 {
            return Err(CacheError::Corrupt);
        }
        let scope = CacheScope::new(
            &origin,
            &account,
            &space,
            &root,
            ScopeProtection::PlaintextAllowed,
        )?;
        if scope.key != key || load(db, &scope, id)?.is_none() {
            return Err(CacheError::Corrupt);
        }
    }
    Ok(())
}

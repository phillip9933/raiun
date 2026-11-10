//! Confirmed local-only discard. No startup cleanup or remote authority.
use super::*;
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};

#[derive(PartialEq, Eq)]
struct Discard {
    handoff: String,
    parent: String,
    name: String,
    path: String,
    key: String,
    created: i64,
    len: i64,
    digest: String,
    state: i64,
    completed: bool,
}

fn intent(db: &Connection, scope: &CacheScope, id: i64) -> Result<Option<Discard>, CacheError> {
    db.query_row(
        "SELECT handoff_id,parent_id,name,path,content_key,created_at,body_len,body_sha256,create_state,completed FROM ordinary_create_discards WHERE scope_key=?1 AND write_id=?2",
        params![scope.key, id],
        |row| Ok(Discard {
            handoff: row.get(0)?, parent: row.get(1)?, name: row.get(2)?, path: row.get(3)?,
            key: row.get(4)?, created: row.get(5)?, len: row.get(6)?, digest: row.get(7)?,
            state: row.get(8)?, completed: row.get(9)?,
        }),
    ).optional().map_err(db_error)
}

fn from_receipt(receipt: &OrdinaryCreateReceipt) -> Result<Discard, CacheError> {
    if !matches!(
        receipt.state,
        OrdinaryCreateState::Uncertain | OrdinaryCreateState::Conflict
    ) || receipt.write.state != WriteState::Conflict
        || receipt.body_evicted
        || receipt.remote.is_some()
    {
        return Err(CacheError::Conflict);
    }
    Ok(Discard {
        handoff: receipt.handoff_id.clone(),
        parent: receipt.write.parent_resource_id.clone(),
        name: receipt.write.name.clone(),
        path: receipt.write.logical_path.clone(),
        key: String::new(),
        created: receipt.write.created_at_unix,
        len: i64_from_u64(receipt.byte_len)?,
        digest: receipt.sha256.clone(),
        state: receipt.state as i64,
        completed: false,
    })
}

fn bound_receipt(
    db: &Connection,
    scope: &CacheScope,
    id: i64,
    expected: &Discard,
) -> Result<OrdinaryCreateReceipt, CacheError> {
    validate_registered_scope(db, scope)?;
    let receipt = load(db, scope, id)?.ok_or(CacheError::Conflict)?;
    let mut found = from_receipt(&receipt)?;
    found.key = content_key(scope, &receipt.write.content);
    if found != *expected {
        return Err(CacheError::Conflict);
    }
    // Explicit discard never deletes a body shared with another operation or
    // retained by independent offline intent. Do not broaden cleanup by scope.
    let held: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM writes WHERE content_key=?1 AND id<>?2) OR EXISTS(SELECT 1 FROM ordinary_create_handoffs WHERE content_key=?1 AND write_id<>?2) OR EXISTS(SELECT 1 FROM ciphertext_writes WHERE content_key=?1) OR EXISTS(SELECT 1 FROM ciphertext_pin_items WHERE content_key=?1) OR EXISTS(SELECT 1 FROM contents WHERE content_key=?1 AND retention<>1) OR EXISTS(SELECT 1 FROM pins WHERE scope_key=?3) OR EXISTS(SELECT 1 FROM folder_pin_roles WHERE scope_key=?3) OR EXISTS(SELECT 1 FROM policies WHERE scope_key=?3 AND policy NOT IN(0,2))",
        params![expected.key, id, scope.key], |row| row.get(0),
    ).map_err(db_error)?;
    if held {
        return Err(CacheError::Conflict);
    }
    Ok(receipt)
}

fn absent(path: &Path) -> Result<(), CacheError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
        Ok(_) => Err(CacheError::Conflict),
    }
}

fn spool_absent(directory: &Path, scope: &CacheScope, path: &str) -> Result<(), CacheError> {
    let spool = directory.join("provider-spool");
    match fs::symlink_metadata(&spool) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error(error)),
        Ok(_) => validate_private_dir(&spool)?,
    }
    // Same filename binding as FUSE's spool_paths. Presence grants no deletion
    // authority: even an exact V3 copy needs its own future coordinated flow.
    let key = format!("{}\0{path}", scope.space_id());
    let hash = key
        .as_bytes()
        .iter()
        .fold(0xcbf29ce484222325_u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        });
    absent(&spool.join(format!("{hash:016x}.data")))?;
    absent(&spool.join(format!("{hash:016x}.meta")))
}

fn disconnected(root: &Path) -> Result<(), CacheError> {
    if !root.is_absolute()
        || root
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
        || fs::canonicalize(root).map_err(io_error)? != root
    {
        return Err(CacheError::UnsafeDirectory);
    }
    let mut escaped = Vec::new();
    for byte in root.as_os_str().as_bytes() {
        match byte {
            b' ' => escaped.extend_from_slice(b"\\040"),
            b'\t' => escaped.extend_from_slice(b"\\011"),
            b'\n' => escaped.extend_from_slice(b"\\012"),
            b'\\' => escaped.extend_from_slice(b"\\134"),
            byte => escaped.push(*byte),
        }
    }
    let mountinfo = fs::read("/proc/self/mountinfo").map_err(io_error)?;
    if mountinfo.is_empty() {
        return Err(CacheError::UnsafeDirectory);
    }
    for line in mountinfo
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let mount = line
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty())
            .nth(4)
            .ok_or(CacheError::UnsafeDirectory)?;
        if mount == escaped {
            return Err(CacheError::Conflict);
        }
    }
    Ok(())
}

fn validate_owner_directory(directory: &File, expected_uid: u32) -> Result<(), CacheError> {
    let metadata = directory.metadata().map_err(io_error)?;
    // The engine's parent directory may be readable (normally 0755). Only
    // its lock and recovery storage contain private data. Never accept a
    // directory another user can modify, or a different storage owner.
    if !metadata.is_dir() || metadata.uid() != expected_uid || metadata.mode() & 0o022 != 0 {
        return Err(CacheError::UnsafeDirectory);
    }
    Ok(())
}

fn owner_lease(directory: &Path, expected_uid: u32) -> Result<(File, File), CacheError> {
    let directory = File::from(
        rustix::fs::open(
            directory,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| io_error(error.into()))?,
    );
    validate_owner_directory(&directory, expected_uid)?;
    // Never create an ownership record for an unknown/legacy uploader.
    let lock = File::from(
        rustix::fs::openat(
            &directory,
            ".ordinary-create-uploader.lock",
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| io_error(error.into()))?,
    );
    let metadata = lock.metadata().map_err(io_error)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != directory.metadata().map_err(io_error)?.uid()
        || metadata.mode() & 0o077 != 0
    {
        return Err(CacheError::UnsafeDirectory);
    }
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| CacheError::Conflict)?;
    Ok((directory, lock))
}

fn same_open_path(file: &File, path: &Path, directory: bool) -> Result<(), CacheError> {
    let opened = file.metadata().map_err(io_error)?;
    let named = fs::symlink_metadata(path).map_err(io_error)?;
    if named.file_type().is_symlink()
        || named.is_dir() != directory
        || opened.dev() != named.dev()
        || opened.ino() != named.ino()
    {
        return Err(CacheError::Conflict);
    }
    Ok(())
}

impl Cache {
    /// Open existing recovery storage without ordinary cache-open orphan GC.
    /// A selected discard must never clean up unrelated unindexed bodies.
    pub fn open_for_saved_upload_discard(
        state_dir: &Path,
        quota_bytes: u64,
    ) -> Result<Self, CacheError> {
        validate_private_dir(state_dir)?;
        let root = state_dir.join("cache-v1");
        validate_private_dir(&root)?;
        let content_dir = root.join(CONTENT_DIR);
        validate_private_dir(&content_dir)?;
        let db_path = root.join(DB_FILE);
        let _db_identity = open_private_file(&db_path)?;
        let db = Connection::open(&db_path).map_err(db_error)?;
        schema::initialize(&db, schema::JournalMode::Wal)?;
        let quota_bytes = load_or_seed_quota(&db, quota_bytes)?;
        Ok(Self {
            inner: Arc::new(Inner {
                root,
                content_dir,
                db: Mutex::new(DbOwner::Portable(db)),
                quota_bytes: AtomicU64::new(quota_bytes),
            }),
        })
    }

    /// Explicitly confirmed, disconnected-only discard of one stopped create.
    /// Caller must hold its mount/settings/auth serialization until return.
    /// Returns its byte length only after durable removal of body and review row.
    /// A failed operation retains its intent and review entry for another
    /// confirmed request; startup never resumes deletion automatically.
    pub fn discard_stopped_ordinary_create(
        &self,
        scope: &CacheScope,
        write_id: i64,
        cloud_root: &Path,
        current: &dyn Fn() -> bool,
    ) -> Result<u64, CacheError> {
        plain(scope)?;
        if write_id <= 0 || !current() {
            return Err(CacheError::Conflict);
        }
        if self.inner.root.file_name() != Some(std::ffi::OsStr::new("cache-v1")) {
            return Err(CacheError::UnsafeDirectory);
        }
        let state = self
            .inner
            .root
            .parent()
            .ok_or(CacheError::UnsafeDirectory)?;
        if state.file_name() != Some(std::ffi::OsStr::new("offline-cache-state")) {
            return Err(CacheError::UnsafeDirectory);
        }
        let directory = state.parent().ok_or(CacheError::UnsafeDirectory)?;
        if fs::canonicalize(directory).map_err(io_error)? != directory {
            return Err(CacheError::UnsafeDirectory);
        }
        let storage_uid = fs::symlink_metadata(&self.inner.root)
            .map_err(io_error)?
            .uid();
        let (owner_directory, owner) = owner_lease(directory, storage_uid)?;
        let ownership_current = || -> Result<(), CacheError> {
            validate_owner_directory(&owner_directory, storage_uid)?;
            same_open_path(&owner_directory, directory, true)?;
            same_open_path(
                &owner,
                &directory.join(".ordinary-create-uploader.lock"),
                false,
            )
        };
        ownership_current()?;
        disconnected(cloud_root)?;
        if self
            .find_plaintext_scope(scope.origin(), scope.account_id(), scope.space_id())?
            .as_ref()
            != Some(scope)
        {
            return Err(CacheError::Conflict);
        }
        let _deletion = self.lock_content_deletion()?;
        let (expected, existed) = {
            let db = self.lock_db()?;
            validate_registered_scope(&db, scope)?;
            match intent(&db, scope, write_id)? {
                Some(discard) => (discard, true),
                None => {
                    let receipt = load(&db, scope, write_id)?.ok_or(CacheError::NotFound)?;
                    let mut discard = from_receipt(&receipt)?;
                    discard.key = content_key(scope, &receipt.write.content);
                    (discard, false)
                }
            }
        };
        validate_path(&expected.path)?;
        validate_name(&expected.name)?;
        validate_id(&expected.parent)?;
        if leaf_name(&expected.path)? != expected.name
            || !hex(&expected.handoff, 32)
            || !hex(&expected.key, 64)
            || !hex(&expected.digest, 64)
            || expected.len < 0
            || expected.len as u64 > MAX_CONTENT_BYTES
            || !matches!(expected.state, 3 | 4)
        {
            return Err(CacheError::Corrupt);
        }
        let content = ContentVersion {
            resource_id: hash_fields(&[
                &scope.key,
                &expected.parent,
                &expected.name,
                &expected.path,
            ]),
            etag: format!("journal-create-{}", expected.handoff),
            protection: ContentProtection::Plaintext,
        };
        if content_key(scope, &content) != expected.key {
            return Err(CacheError::Corrupt);
        }
        spool_absent(directory, scope, &expected.path)?;
        let name = format!("{}.blob", expected.key);
        if expected.completed {
            let db = self.lock_db()?;
            let residual: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM writes WHERE id=?1) OR EXISTS(SELECT 1 FROM ordinary_create_handoffs WHERE write_id=?1) OR EXISTS(SELECT 1 FROM contents WHERE content_key=?2)",
                params![write_id, expected.key], |row| row.get(0),
            ).map_err(db_error)?;
            if residual || !current() {
                return Err(CacheError::Conflict);
            }
            ownership_current()?;
            absent(&self.inner.content_dir.join(&name))?;
            return Ok(expected.len as u64);
        }
        let receipt = {
            let db = self.lock_db()?;
            bound_receipt(&db, scope, write_id, &expected)?
        };
        let candidate = clean::prepare_portable(self, &name, &receipt)?;
        if candidate.is_none() && !existed {
            return Err(CacheError::Corrupt);
        }
        {
            let db = self.lock_db()?;
            let tx = Transaction::new_unchecked(&db, TransactionBehavior::Immediate)
                .map_err(db_error)?;
            bound_receipt(&tx, scope, write_id, &expected)?;
            if !current() {
                return Err(CacheError::Conflict);
            }
            ownership_current()?;
            if !existed {
                let count: i64 = tx
                    .query_row("SELECT COUNT(*) FROM ordinary_create_discards", [], |row| {
                        row.get(0)
                    })
                    .map_err(db_error)?;
                if count >= MAX_CONTENT_RECORDS as i64 {
                    return Err(CacheError::LimitExceeded);
                }
                tx.execute(
                    "INSERT INTO ordinary_create_discards(write_id,scope_key,handoff_id,parent_id,name,path,content_key,created_at,body_len,body_sha256,create_state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                    params![write_id,scope.key,expected.handoff,expected.parent,expected.name,expected.path,expected.key,expected.created,expected.len,expected.digest,expected.state],
                ).map_err(db_error)?;
            } else if intent(&tx, scope, write_id)?.as_ref() != Some(&expected) {
                return Err(CacheError::Conflict);
            }
            tx.commit().map_err(db_error)?;
        }
        // FULL-synchronous durable intent precedes unlink. Keep the body indexed
        // and charged, and the review visible, until directory sync and final CAS.
        let db = self.lock_db()?;
        let tx =
            Transaction::new_unchecked(&db, TransactionBehavior::Immediate).map_err(db_error)?;
        bound_receipt(&tx, scope, write_id, &expected)?;
        if intent(&tx, scope, write_id)?.as_ref() != Some(&expected) || !current() {
            return Err(CacheError::Conflict);
        }
        disconnected(cloud_root)?;
        ownership_current()?;
        spool_absent(directory, scope, &expected.path)?;
        clean::unlink_portable(self, &name, candidate)?;
        sync_directory(&self.inner.content_dir)?;
        for sql in [
            "DELETE FROM ordinary_create_handoffs WHERE scope_key=?1 AND write_id=?2 AND state IN(3,4)",
            "DELETE FROM writes WHERE scope_key=?1 AND id=?2 AND state=1",
        ] {
            if tx
                .execute(sql, params![scope.key, write_id])
                .map_err(db_error)?
                != 1
            {
                return Err(CacheError::Conflict);
            }
        }
        if tx.execute("DELETE FROM contents WHERE scope_key=?1 AND content_key=?2 AND retention=1", params![scope.key,expected.key]).map_err(db_error)? != 1
            || tx.execute("UPDATE ordinary_create_discards SET completed=1 WHERE scope_key=?1 AND write_id=?2 AND completed=0", params![scope.key,write_id]).map_err(db_error)? != 1
        { return Err(CacheError::Conflict); }
        tx.commit().map_err(db_error)?;
        Ok(expected.len as u64)
    }
}

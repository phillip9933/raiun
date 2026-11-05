//! Provider-side durable custody markers. Persisted fields are untrusted projections,
//! never constructors for Engine receipts or remote mutation authority.
use super::*;
use raiun_engine::{CreateHandoffRequest, DurableCreateReceipt, VerifiedCreateParent};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    pub id: String,
    pub parent_id: String,
    pub len: u64,
    pub sha256: String,
    pub receipt: Option<ReceiptProjection>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReceiptProjection {
    write_id: i64,
    content_resource_id: String,
    content_etag: String,
}

impl Intent {
    pub fn valid(&self) -> bool {
        hex(&self.id, 32)
            && hex(&self.sha256, 64)
            && !self.parent_id.is_empty()
            && self.parent_id.len() <= 4096
            && !self.parent_id.chars().any(char::is_control)
            && self.receipt.as_ref().is_none_or(|r| {
                r.write_id > 0
                    && !r.content_resource_id.is_empty()
                    && r.content_resource_id.len() <= 4096
                    && r.content_etag.len() <= 4096
                    && !r.content_resource_id.chars().any(char::is_control)
                    && !r.content_etag.chars().any(char::is_control)
            })
    }

    pub fn matches(&self, receipt: &DurableCreateReceipt) -> bool {
        self.matches_storage(receipt.storage_receipt())
    }

    fn matches_storage(&self, r: &raiun_cache::OrdinaryCreateReceipt) -> bool {
        self.id == r.handoff_id
            && self.parent_id == r.write.parent_resource_id
            && self.len == r.byte_len
            && self.sha256 == r.sha256
            && self
                .receipt
                .as_ref()
                .is_none_or(|p| *p == storage_projection(r))
    }
}

fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn storage_projection(r: &raiun_cache::OrdinaryCreateReceipt) -> ReceiptProjection {
    ReceiptProjection {
        write_id: r.write.id,
        content_resource_id: r.write.content.resource_id.clone(),
        content_etag: r.write.content.etag.clone(),
    }
}

pub(super) const MAX_WORKING_BYTES: u64 = 1 << 40;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkingCopy {
    pub id: String,
    pub parent_id: String,
    pub device: u64,
    pub inode: u64,
    /// Last synced size only; later edits may legitimately change it.
    pub synced_len: u64,
    pub closing: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub cancelled: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

impl WorkingCopy {
    pub fn valid(&self) -> bool {
        hex(&self.id, 32)
            && !self.parent_id.is_empty()
            && self.parent_id.len() <= 4096
            && !self.parent_id.chars().any(char::is_control)
            && self.inode != 0
            && self.synced_len <= MAX_WORKING_BYTES
            && (!self.cancelled || self.closing)
    }
}

pub(super) struct NewCreate {
    pub parent: VerifiedCreateParent,
    pub working_id: String,
    pub closing: bool,
    pub cancelled: bool,
    pub intent: Option<Intent>,
}

fn random_id() -> Result<String, CloudError> {
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .map_err(io_cloud)?;
    Ok(random.iter().map(|b| format!("{b:02x}")).collect())
}

fn current(fs: &RaiunFilesystem) -> Result<(), CloudError> {
    if fs
        .create_handoff
        .as_ref()
        .is_some_and(|capability| (capability.current)())
    {
        Ok(())
    } else {
        Err(CloudError::new(
            ErrorKind::Unauthorized,
            "create owner is no longer current; local copy retained",
        ))
    }
}

fn pinned_source(write: &WriteHandle) -> Result<std::fs::Metadata, CloudError> {
    let path = fs::symlink_metadata(&write.spool).map_err(io_cloud)?;
    let open = write.file.metadata().map_err(io_cloud)?;
    if !path.is_file()
        || path.file_type().is_symlink()
        || path.dev() != open.dev()
        || path.ino() != open.ino()
        || open.len() > MAX_WORKING_BYTES
    {
        return Err(invalid("working copy identity or size changed"));
    }
    Ok(open)
}

fn working_marker(write: &WriteHandle) -> Result<WorkingCopy, CloudError> {
    let create = write
        .create
        .as_ref()
        .ok_or_else(|| invalid("working create is missing"))?;
    let bytes = recovery::read_manifest_bytes(&write.manifest)
        .map_err(|_| invalid("working marker is unsafe"))?;
    let marker: OrdinaryWriteManifest =
        serde_json::from_slice(&bytes).map_err(|_| invalid("working marker is malformed"))?;
    if marker.version != 4
        || marker.handoff.is_some()
        || !marker.matches_scope(&write.scope, &write.path)
    {
        return Err(invalid("working marker scope changed"));
    }
    let working = marker
        .working
        .filter(|working| working.valid())
        .ok_or_else(|| invalid("working marker is missing"))?;
    let metadata = pinned_source(write)?;
    if working.id != create.working_id
        || working.parent_id != create.parent.parent_resource_id()
        || working.device != metadata.dev()
        || working.inode != metadata.ino()
    {
        return Err(invalid("working marker does not own these bytes"));
    }
    Ok(working)
}

pub(super) fn initialize(
    fs: &RaiunFilesystem,
    write: &mut WriteHandle,
    parent: VerifiedCreateParent,
) -> Result<(), CloudError> {
    current(fs)?;
    // Only the newly created empty V2 spool can be converted here. Existing
    // recovery spools are excluded by create_ordinary_file before prepare_write.
    let bytes = recovery::read_manifest_bytes(&write.manifest)
        .map_err(|_| invalid("initial create marker is unsafe"))?;
    let marker: OrdinaryWriteManifest = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("initial create marker is malformed"))?;
    if marker.version != 2
        || marker.handoff.is_some()
        || marker.working.is_some()
        || !marker.matches_scope(&write.scope, &write.path)
        || pinned_source(write)?.len() != 0
    {
        return Err(invalid("legacy spool cannot become an editable create"));
    }
    write.create = Some(NewCreate {
        parent,
        working_id: random_id()?,
        closing: false,
        cancelled: false,
        intent: None,
    });
    write.file.sync_all().map_err(io_cloud)?;
    persist_working(write, false)?;
    current(fs)
}

fn persist_working(write: &WriteHandle, validate_previous: bool) -> Result<(), CloudError> {
    let create = write
        .create
        .as_ref()
        .ok_or_else(|| invalid("working create is missing"))?;
    if validate_previous {
        let previous = working_marker(write)?;
        if previous.closing && !create.closing {
            return Err(invalid("closed working copy cannot become editable"));
        }
        if previous.cancelled != create.cancelled
            && !(create.cancelled && create.closing && !previous.cancelled && !previous.closing)
        {
            return Err(invalid("working copy cancellation state changed"));
        }
    }
    let metadata = pinned_source(write)?;
    let marker = OrdinaryWriteManifest {
        version: 4,
        origin: write.scope.origin().to_owned(),
        account_id: write.scope.account_id().to_owned(),
        space_id: write.scope.space_id().to_owned(),
        root_resource_id: write.scope.root_resource_id().to_owned(),
        resource_id: None,
        path: write.path.clone(),
        condition: "absent".into(),
        etag: String::new(),
        handoff: None,
        working: Some(WorkingCopy {
            id: create.working_id.clone(),
            parent_id: create.parent.parent_resource_id().to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
            synced_len: metadata.len(),
            closing: create.closing,
            cancelled: create.cancelled,
        }),
    };
    let bytes =
        serde_json::to_vec(&marker).map_err(|_| invalid("could not encode working marker"))?;
    if bytes.len() > 16 * 1024 {
        return Err(invalid("working marker exceeds bound"));
    }
    persist_manifest(&write.manifest, &bytes)
}

pub(super) fn ensure_mutable(write: &WriteHandle) -> Result<(), CloudError> {
    if write
        .create
        .as_ref()
        .is_some_and(|c| c.closing || c.intent.is_some())
    {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "create handle is closing or frozen; retained bytes cannot be edited",
        ));
    }
    Ok(())
}

pub(super) fn ensure_editable(fs: &RaiunFilesystem, write: &WriteHandle) -> Result<(), CloudError> {
    ensure_mutable(write)?;
    if write.create.is_some() {
        current(fs)?;
        let marker = working_marker(write)?;
        if marker.cancelled != write.create.as_ref().is_some_and(|create| create.cancelled) {
            return Err(invalid("working copy cancellation state changed"));
        }
        if marker.closing {
            return Err(invalid("working marker is closed"));
        }
    }
    Ok(())
}

pub(super) fn write_bytes(
    fs: &RaiunFilesystem,
    write: &mut WriteHandle,
    offset: u64,
    data: &[u8],
    append: bool,
) -> Result<(u32, u64), CloudError> {
    ensure_editable(fs, write)?;
    let offset = if append {
        write.file.metadata().map_err(io_cloud)?.len()
    } else {
        offset
    };
    if write.create.is_some()
        && offset
            .checked_add(data.len() as u64)
            .is_none_or(|end| end > MAX_WORKING_BYTES)
    {
        return Err(invalid("working copy exceeds per-file bound"));
    }
    // A failing write can already have changed a prefix; never retain an old
    // verified cleanup permission across a potentially partial mutation.
    write.dirty = true;
    write.cleanup_on_release = false;
    write.file.seek(SeekFrom::Start(offset)).map_err(io_cloud)?;
    write.file.write_all(data).map_err(io_cloud)?;
    if write.create.is_some() {
        current(fs)?;
    }
    let count = u32::try_from(data.len())
        .map_err(|_| CloudError::new(ErrorKind::Unsupported, "write request is too large"))?;
    Ok((count, offset.saturating_add(u64::from(count))))
}

pub(super) fn truncate(
    fs: &RaiunFilesystem,
    write: &mut WriteHandle,
    size: u64,
) -> Result<u64, CloudError> {
    ensure_editable(fs, write)?;
    if write.create.is_some() && size > MAX_WORKING_BYTES {
        return Err(invalid("working copy exceeds per-file bound"));
    }
    write.dirty = true;
    write.cleanup_on_release = false;
    write.file.set_len(size).map_err(io_cloud)?;
    if write.create.is_some() {
        current(fs)?;
    }
    Ok(size)
}

/// Cancel only a live, never-admitted create owned by this exact handle.
/// The closed V4 working marker/body remain recovery-only across restart.
/// There is no cloud mutation or durable claim reset here.
pub(super) fn cancel_before_handoff(
    fs: &RaiunFilesystem,
    write: &mut WriteHandle,
) -> Result<(), CloudError> {
    current(fs)?;
    let marker = working_marker(write)?;
    let create = write
        .create
        .as_mut()
        .ok_or_else(|| invalid("create is missing"))?;
    if marker.closing || create.closing || create.intent.is_some() {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "create is already closing or admitted",
        ));
    }
    // Make failure terminal before filesystem I/O: a failed retention sync may
    // not cause release to admit the cancelled bytes later.
    create.closing = true;
    create.cancelled = true;
    write.cleanup_on_release = false;
    write.file.sync_all().map_err(io_cloud)?;
    persist_working(write, true)
}

pub(super) fn sync_editable(
    fs: &RaiunFilesystem,
    write: &mut WriteHandle,
) -> Result<(), CloudError> {
    if write.create.as_ref().is_some_and(|create| create.cancelled) {
        // A caller unlinked its own still-open create. Sync retained recovery
        // bytes, but never convert that cancelled intent into an upload.
        return write.file.sync_all().map_err(io_cloud);
    }
    ensure_editable(fs, write)?;
    write.file.flush().map_err(io_cloud)?;
    write.file.sync_all().map_err(io_cloud)?;
    persist_working(write, true)?;
    current(fs)
}

pub(super) fn close_and_commit(
    fs: &RaiunFilesystem,
    write: &mut WriteHandle,
) -> Result<(), CloudError> {
    if write.create.as_ref().is_some_and(|create| create.cancelled) {
        return write.file.sync_all().map_err(io_cloud);
    }
    let marker = working_marker(write)?;
    if marker.cancelled {
        return Err(invalid("cancelled working copy cannot be admitted"));
    }
    let create = write
        .create
        .as_mut()
        .ok_or_else(|| invalid("create handle is missing"))?;
    create.closing = true; // terminal even when local sync/admission later fails
    write.file.flush().map_err(io_cloud)?;
    write.file.sync_all().map_err(io_cloud)?;
    if write
        .create
        .as_ref()
        .is_some_and(|create| create.intent.is_none())
    {
        // Retention sync is allowed after owner stop; it grants no new remote
        // authority and publishes a durable closed/recovery attention marker.
        persist_working(write, true)?;
    }
    let result = commit(fs, write);
    if result.is_err() {
        // Retained local custody is independent of this best-effort UI row.
        // Keep the original admission error even if the transfer DB is full.
        let _ = fs
            .engine
            .record_create_handoff_failure(&write.scope, &write.path);
    }
    result
}

fn file_digest(file: &File) -> Result<(u64, String), CloudError> {
    let mut source = file.try_clone().map_err(io_cloud)?;
    source.seek(SeekFrom::Start(0)).map_err(io_cloud)?;
    let mut hash = Sha256::new();
    let mut len = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = source.read(&mut buffer).map_err(io_cloud)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        len = len
            .checked_add(count as u64)
            .ok_or_else(|| invalid("create body is too large"))?;
    }
    Ok((len, format!("{:x}", hash.finalize())))
}

pub(super) fn prepare(write: &mut WriteHandle) -> Result<(), CloudError> {
    let create = write
        .create
        .as_mut()
        .ok_or_else(|| invalid("create binding is missing"))?;
    create.closing = true;
    if create.intent.is_none() {
        let id = random_id()?;
        let (len, digest) = file_digest(&write.file)?;
        // Freeze before even attempting the durable marker: an fsync error may
        // still have published the ID. A later retry must retain these bytes.
        create.intent = Some(Intent {
            id,
            parent_id: create.parent.parent_resource_id().to_owned(),
            len,
            sha256: digest,
            receipt: None,
        });
    }
    if recovery::read_manifest_bytes(&write.manifest)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<OrdinaryWriteManifest>(&bytes).ok())
        .is_some_and(|marker| marker.version == 4)
    {
        persist_working(write, true)?;
    }
    persist(write)
}

pub(super) fn persist(write: &WriteHandle) -> Result<(), CloudError> {
    let intent = write
        .create
        .as_ref()
        .and_then(|c| c.intent.as_ref())
        .ok_or_else(|| invalid("create intent is missing"))?;
    let manifest = OrdinaryWriteManifest {
        version: 3,
        origin: write.scope.origin().to_owned(),
        account_id: write.scope.account_id().to_owned(),
        space_id: write.scope.space_id().to_owned(),
        root_resource_id: write.scope.root_resource_id().to_owned(),
        resource_id: None,
        path: write.path.clone(),
        condition: "absent".into(),
        etag: String::new(),
        handoff: Some(intent.clone()),
        working: None,
    };
    let previous_bytes = recovery::read_manifest_bytes(&write.manifest)
        .map_err(|_| invalid("create marker is unsafe or missing"))?;
    let previous: OrdinaryWriteManifest = serde_json::from_slice(&previous_bytes)
        .map_err(|_| invalid("create marker is malformed"))?;
    if !previous.matches_scope(&write.scope, &write.path) {
        return Err(invalid("create marker scope or destination changed"));
    }
    match (previous.version, previous.handoff, previous.working) {
        (4, None, Some(old))
            if old.valid()
                && old.closing
                && old.id == write.create.as_ref().expect("create").working_id
                && old.parent_id == intent.parent_id => {}
        (3, Some(old), None)
            if old.id == intent.id
                && old.parent_id == intent.parent_id
                && old.len == intent.len
                && old.sha256 == intent.sha256
                && (old.receipt.is_none() || old.receipt == intent.receipt) => {}
        _ => return Err(invalid("create marker no longer belongs to this handle")),
    }
    let source_path = fs::symlink_metadata(&write.spool).map_err(io_cloud)?;
    let source_open = write.file.metadata().map_err(io_cloud)?;
    if !source_path.is_file()
        || source_path.file_type().is_symlink()
        || source_path.dev() != source_open.dev()
        || source_path.ino() != source_open.ino()
        || source_open.len() != intent.len
    {
        return Err(invalid("create spool no longer belongs to this handle"));
    }
    let bytes =
        serde_json::to_vec(&manifest).map_err(|_| invalid("could not encode create handoff"))?;
    if bytes.len() > 16 * 1024 {
        return Err(invalid("create handoff marker exceeds bound"));
    }
    persist_manifest(&write.manifest, &bytes)
}

pub(super) fn commit(fs: &RaiunFilesystem, write: &mut WriteHandle) -> Result<(), CloudError> {
    let capability = fs
        .create_handoff
        .as_ref()
        .ok_or_else(|| invalid("create handoff is disabled"))?;
    if !(capability.current)() {
        return Err(CloudError::new(
            ErrorKind::Unauthorized,
            "create owner is no longer current",
        ));
    }
    let preparation = prepare(write);
    if write
        .create
        .as_ref()
        .is_some_and(|create| create.intent.is_some())
    {
        let mut state = fs
            .state
            .lock()
            .map_err(|_| io_error("provider state is unavailable"))?;
        if let Some(node) = state.nodes.get_mut(&write.ino) {
            if let NodeKind::Remote { entry, .. } = &mut node.kind {
                entry.writable = false;
            }
        }
    }
    preparation?;
    let create = write.create.as_ref().expect("prepared create");
    let intent = create.intent.as_ref().expect("prepared intent");
    let receipt =
        match fs
            .engine
            .create_handoff_receipt_metadata(&write.scope, &write.path, &intent.id)?
        {
            Some(receipt) => receipt,
            None if intent.receipt.is_some() => {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "previous handoff receipt disappeared; refusing another admission",
                ));
            }
            None => fs
                .engine
                .queue_new_plaintext_create_scoped(
                    CreateHandoffRequest {
                        parent: &create.parent,
                        source: &write.file,
                        expected_len: intent.len,
                        expected_sha256: &intent.sha256,
                        handoff_id: &intent.id,
                        max_pending_bytes: capability.max_pending_bytes,
                    },
                    capability.current.as_ref(),
                )?
                .storage_receipt()
                .clone(),
        };
    if !intent.matches_storage(&receipt) {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "create handoff receipt does not own these bytes",
        ));
    }
    write
        .create
        .as_mut()
        .expect("prepared create")
        .intent
        .as_mut()
        .expect("prepared intent")
        .receipt = Some(storage_projection(&receipt));
    persist(write)?;
    let intent = write
        .create
        .as_ref()
        .and_then(|create| create.intent.as_ref())
        .expect("persisted create intent");
    let acknowledged = fs.engine.acknowledge_create_handoff(
        &write.scope,
        &write.path,
        &intent.id,
        &receipt,
        capability.current.as_ref(),
    )?;
    if !intent.matches(&acknowledged) || !acknowledged.storage_receipt().local_handoff_acknowledged
    {
        return Err(invalid("create handoff acknowledgment changed custody"));
    }
    if !(capability.current)() {
        return Err(CloudError::new(
            ErrorKind::Unauthorized,
            "create owner changed before local acknowledgment",
        ));
    }
    // The receipt marker is durable before local success; wake is only a hint.
    capability.handle.wake_scope(&write.scope)?;
    write.dirty = false;
    write.cleanup_on_release = true;
    let pending = fs.engine.pending_create(&write.scope, &write.path)?;
    if let Some(view) = pending {
        fs.publish_pending(write.ino, &write.space, &write.scope, view)?;
    }
    Ok(())
}

pub(super) fn cleanup(fs: &RaiunFilesystem, write: &WriteHandle) -> Result<(), CloudError> {
    let intent = write
        .create
        .as_ref()
        .and_then(|c| c.intent.as_ref())
        .ok_or_else(|| invalid("create intent is missing"))?;
    if intent.receipt.is_none() {
        return Err(invalid("create receipt is not durable"));
    }
    let receipt = fs
        .engine
        .create_receipt_for_handoff(&write.scope, &write.path, &intent.id)?
        .ok_or_else(|| invalid("create receipt disappeared"))?;
    if !intent.matches(&receipt) || !receipt.storage_receipt().local_handoff_acknowledged {
        return Err(invalid(
            "create receipt changed or custody was not acknowledged",
        ));
    }
    // The lookup above already verified the exact cache body (or committed
    // Verified+ACK tombstone). Retain the independent marker/spool checks below.
    let bytes = recovery::read_manifest_bytes(&write.manifest)
        .map_err(|_| invalid("create marker is unsafe"))?;
    let marker: OrdinaryWriteManifest =
        serde_json::from_slice(&bytes).map_err(|_| invalid("create marker is malformed"))?;
    if marker.version != 3
        || marker.handoff.as_ref() != Some(intent)
        || !marker.matches_scope(&write.scope, &write.path)
    {
        return Err(invalid("create marker no longer belongs to this handle"));
    }
    let before = fs::symlink_metadata(&write.spool).map_err(io_cloud)?;
    let open = write.file.metadata().map_err(io_cloud)?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.dev() != open.dev()
        || before.ino() != open.ino()
        || before.len() != intent.len
    {
        return Err(invalid("create spool identity changed"));
    }
    let (len, digest) = file_digest(&write.file)?;
    if len != intent.len || digest != intent.sha256 {
        return Err(invalid(
            "create spool changed after handoff; preserving recovery bytes",
        ));
    }
    // Remove data first: a crash leaves the durable marker for exact recovery.
    fs::remove_file(&write.spool).map_err(io_cloud)?;
    fs::remove_file(&write.manifest).map_err(io_cloud)?;
    File::open(
        write
            .manifest
            .parent()
            .ok_or_else(|| invalid("create marker has no directory"))?,
    )
    .and_then(|f| f.sync_all())
    .map_err(io_cloud)
}

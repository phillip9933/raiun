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
        let r = receipt.storage_receipt();
        self.id == r.handoff_id
            && self.parent_id == r.write.parent_resource_id
            && self.len == r.byte_len
            && self.sha256 == r.sha256
            && self
                .receipt
                .as_ref()
                .is_none_or(|p| *p == projection(receipt))
    }
}

fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn projection(receipt: &DurableCreateReceipt) -> ReceiptProjection {
    let r = receipt.storage_receipt();
    ReceiptProjection {
        write_id: r.write.id,
        content_resource_id: r.write.content.resource_id.clone(),
        content_etag: r.write.content.etag.clone(),
    }
}

pub(super) struct NewCreate {
    pub parent: VerifiedCreateParent,
    pub intent: Option<Intent>,
}

pub(super) fn ensure_mutable(write: &WriteHandle) -> Result<(), CloudError> {
    if write.create.as_ref().is_some_and(|c| c.intent.is_some()) {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "create handoff is immutable; retained bytes cannot be edited",
        ));
    }
    Ok(())
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
    if create.intent.is_none() {
        let mut random = [0_u8; 16];
        File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut random))
            .map_err(io_cloud)?;
        let id = random.iter().map(|b| format!("{b:02x}")).collect();
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
    };
    let previous_bytes = recovery::read_manifest_bytes(&write.manifest)
        .map_err(|_| invalid("create marker is unsafe or missing"))?;
    let previous: OrdinaryWriteManifest = serde_json::from_slice(&previous_bytes)
        .map_err(|_| invalid("create marker is malformed"))?;
    if !previous.matches_scope(&write.scope, &write.path) {
        return Err(invalid("create marker scope or destination changed"));
    }
    match (previous.version, previous.handoff) {
        (2, None) => {}
        (3, Some(old))
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
            .create_receipt_for_handoff(&write.scope, &write.path, &intent.id)?
        {
            Some(receipt) => receipt,
            None => fs.engine.queue_new_plaintext_create_scoped(
                CreateHandoffRequest {
                    parent: &create.parent,
                    source: &write.file,
                    expected_len: intent.len,
                    expected_sha256: &intent.sha256,
                    handoff_id: &intent.id,
                    max_pending_bytes: capability.max_pending_bytes,
                },
                capability.current.as_ref(),
            )?,
        };
    if !intent.matches(&receipt) {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "create handoff receipt does not own these bytes",
        ));
    }
    let receipt = fs.engine.validate_create_receipt(
        &write.scope,
        &write.path,
        &intent.id,
        receipt.storage_receipt(),
    )?;
    write
        .create
        .as_mut()
        .expect("prepared create")
        .intent
        .as_mut()
        .expect("prepared intent")
        .receipt = Some(projection(&receipt));
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
        receipt.storage_receipt(),
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
    fs.engine.validate_create_receipt(
        &write.scope,
        &write.path,
        &intent.id,
        receipt.storage_receipt(),
    )?;
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

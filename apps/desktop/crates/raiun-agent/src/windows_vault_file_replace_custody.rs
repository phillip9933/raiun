//! Separate protected replacement history. Original placeholder and new body
//! identities stay distinct. No record can restore a native owner or unlock.
use super::{
    vault_custody::{Entry, Hydration, Scope},
    windows_vault_custody::Storage,
};
use raiun_cloudfiles_windows::{
    BackendError, ConfiguredRootIdentity, EditRecordProtector, JournalError,
    streamed_snapshot::SnapshotBinding,
    streamed_store::{CaptureReservation, SnapshotStore, StagedSnapshot, StorePolicy},
    vault_file_replace::{
        VaultFileReplaceCapture, VaultFileReplaceDescriptor, VaultFileReplaceFacts,
        VaultFileReplaceNativeProof, VaultFileReplaceRecord, VaultFileReplaceRemoteProof,
        VaultFileReplaceStaged,
    },
};
use raiun_control_windows::{DpapiSessionStore, PinnedDirectory, PrivateDirectory};
use raiun_core::backend::RemoteEntry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    io::Read,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use zeroize::Zeroizing;
const DOMAIN: &[u8] = b"raiun/windows-vault-file-replace/v1\0";
const LIMIT: usize = 1024;
const MAX_INDEX: usize = 16 << 20;
fn unavailable() -> BackendError {
    BackendError::Unavailable
}
fn binding(scope: &Scope) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    let scope = scope
        .authenticated_store_binding()
        .map_err(|_| unavailable())?;
    let mut b = Zeroizing::new(DOMAIN.to_vec());
    b.extend_from_slice(&(scope.len() as u64).to_le_bytes());
    b.extend_from_slice(&scope);
    Ok(b)
}
fn directory(scope: &Scope) -> Result<PathBuf, BackendError> {
    Ok(DpapiSessionStore::current_user()
        .map_err(|_| unavailable())?
        .local_edit_state_directory()
        .join(format!(
            "vault-file-replace-v1-{:x}",
            Sha256::digest(&*binding(scope)?)
        )))
}
struct Protector {
    inner: raiun_cloudfiles_windows::DpapiEditRecordProtector,
    binding: Zeroizing<Vec<u8>>,
}
impl Protector {
    fn aad(&self, aad: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut b = Zeroizing::new(self.binding.to_vec());
        b.extend_from_slice(aad);
        b
    }
}
impl EditRecordProtector for Protector {
    fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, JournalError> {
        self.inner.seal(&self.aad(aad), plain)
    }
    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, JournalError> {
        self.inner.open(&self.aad(aad), sealed)
    }
}
fn snapshots(scope: &Scope, create: bool) -> Result<Arc<SnapshotStore>, BackendError> {
    let path = directory(scope)?;
    let storage = DpapiSessionStore::current_user().map_err(|_| unavailable())?;
    let parent =
        PinnedDirectory::open(storage.local_edit_state_directory()).map_err(|_| unavailable())?;
    let name = path.file_name().ok_or_else(unavailable)?;
    let private = Arc::new(
        if create {
            PrivateDirectory::create_or_open_under(&parent, OsStr::new(name))
        } else {
            PrivateDirectory::open_under(&parent, OsStr::new(name))
        }
        .map_err(|_| unavailable())?,
    );
    let protector = Arc::new(Protector {
        inner: raiun_cloudfiles_windows::DpapiEditRecordProtector::from_existing_private_directory(
            private.clone(),
        )
        .map_err(|_| unavailable())?,
        binding: binding(scope)?,
    });
    let policy = StorePolicy {
        max_content_bytes:
            raiun_cloudfiles_windows::vault_file_replace::MAX_VAULT_FILE_REPLACE_BYTES,
        max_state_bytes: 4 << 30,
        max_entries: 4096,
        max_metadata_bytes_per_scan: 64 << 20,
    };
    let scope = scope.streamed_storage_scope().map_err(|_| unavailable())?;
    if create {
        SnapshotStore::create_or_open(private, scope, protector, policy)
    } else {
        SnapshotStore::open_existing(private, scope, protector, policy)
    }
    .map_err(|_| unavailable())
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    scope: Scope,
    generation: u64,
    facts: VaultFileReplaceFacts,
}
impl Descriptor {
    fn from(scope: &Scope, d: &VaultFileReplaceDescriptor) -> Result<Self, BackendError> {
        d.validate()?;
        let storage = scope.streamed_storage_scope().map_err(|_| unavailable())?;
        if scope.native_root() != (d.root.volume_serial, d.root.file_index)
            || d.owner.profile_id() != storage.profile_id
            || d.owner.server_origin() != storage.server_origin
            || d.owner.account_id() != storage.account_subject
            || d.vault.space_id() != storage.space_id
            || d.vault.resource_id() != storage.root_resource_id
            || d.remote_root != scope.remote_root()
        {
            return Err(unavailable());
        }
        let v = Self {
            scope: scope.clone(),
            generation: d.owner.token_generation(),
            facts: d.facts(),
        };
        v.validate(scope)?;
        Ok(v)
    }
    fn validate(&self, scope: &Scope) -> Result<(), BackendError> {
        let (v, f) = scope.native_root();
        self.facts.validate(ConfiguredRootIdentity {
            volume_serial: v,
            file_index: f,
        })?;
        if self.scope != *scope
            || self.generation == 0
            || self.facts.remote_root != scope.remote_root()
        {
            return Err(unavailable());
        }
        Ok(())
    }
    fn id(&self) -> Result<String, BackendError> {
        let raw = Zeroizing::new(serde_json::to_vec(self).map_err(|_| unavailable())?);
        Ok(format!("{:x}", Sha256::digest(&*raw)))
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Capturing,
    Ready,
    Attempted,
    RemoteVerified,
    NativeCompleted,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    descriptor: Descriptor,
    snapshot: SnapshotBinding,
    phase: Phase,
    sha256: Option<[u8; 32]>,
    remote: Option<RemoteEntry>,
    native_usn: Option<i64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u32,
    scope: Scope,
    rows: Vec<Row>,
}
fn validate_remote(f: &VaultFileReplaceFacts, e: &RemoteEntry) -> Result<(), BackendError> {
    if e.id != f.original.id
        || e.path != f.original.path
        || e.directory
        || e.size != f.plaintext_len
        || !super::vault_edit_capture::strong_etag(&e.etag)
    {
        return Err(unavailable());
    }
    Ok(())
}
fn load(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<(Option<Zeroizing<Vec<u8>>>, Index), BackendError> {
    let raw = store.load(&binding(scope)?).map_err(|_| unavailable())?;
    let index = if let Some(raw) = &raw {
        if raw.is_empty() || raw.len() > MAX_INDEX {
            return Err(unavailable());
        }
        let index: Index = serde_json::from_slice(raw).map_err(|_| unavailable())?;
        if index.version != 1
            || index.scope != *scope
            || index.rows.is_empty()
            || index.rows.len() > LIMIT
        {
            return Err(unavailable());
        }
        let mut ids = std::collections::BTreeSet::new();
        for row in &index.rows {
            row.descriptor.validate(scope)?;
            let d = &row.descriptor;
            let f = &d.facts;
            let b = &row.snapshot;
            if !ids.insert(d.id()?)
                || b.record_id.len() != 32
                || !b.record_id.bytes().all(|c| c.is_ascii_hexdigit())
                || b.scope != scope.streamed_storage_scope().map_err(|_| unavailable())?
                || b.generation != d.generation
                || b.local_file != f.replacement_file
                || b.relative_path != f.components.join("/")
                || b.content_len != f.plaintext_len
                || b.remote.as_ref().is_none_or(|r| {
                    r.resource_id != f.original.id
                        || r.etag != f.original.etag
                        || r.byte_len != f.original.size
                })
                || (row.phase != Phase::Capturing) != row.sha256.is_some()
                || row.sha256 == Some([0; 32])
                || matches!(row.phase, Phase::RemoteVerified | Phase::NativeCompleted)
                    != row.remote.is_some()
                || (row.phase == Phase::NativeCompleted) != row.native_usn.is_some()
                || row.native_usn.is_some_and(|u| u <= 0)
            {
                return Err(unavailable());
            }
            if let Some(e) = &row.remote {
                validate_remote(f, e)?;
            }
        }
        index
    } else {
        match std::fs::symlink_metadata(directory(scope)?) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err(unavailable()),
        }
        Index {
            version: 1,
            scope: scope.clone(),
            rows: vec![],
        }
    };
    Ok((raw, index))
}
fn commit(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    old: Option<&[u8]>,
    index: &Index,
) -> Result<(), BackendError> {
    let raw = Zeroizing::new(serde_json::to_vec(index).map_err(|_| unavailable())?);
    if raw.len() > MAX_INDEX || index.rows.len() > LIMIT {
        return Err(unavailable());
    }
    store
        .cas(&binding(scope)?, old, &raw)
        .map_err(|_| unavailable())?;
    if store
        .load(&binding(scope)?)
        .map_err(|_| unavailable())?
        .is_none_or(|v| v.as_slice() != raw.as_slice())
    {
        return Err(unavailable());
    }
    Ok(())
}
struct Record {
    store: Arc<dyn Storage>,
    scope: Scope,
    descriptor: VaultFileReplaceDescriptor,
    stored: Descriptor,
    id: String,
    sha256: [u8; 32],
    send: AtomicBool,
    refresh: Arc<dyn Fn() -> Result<(), BackendError> + Send + Sync>,
}
impl Record {
    fn row(&self) -> Result<Row, BackendError> {
        let (_, i) = load(&self.store, &self.scope)?;
        let mut rows = i
            .rows
            .into_iter()
            .filter(|r| r.descriptor.id().ok().as_deref() == Some(self.id.as_str()));
        let r = rows.next().ok_or_else(unavailable)?;
        if rows.next().is_some() || r.descriptor != self.stored || r.sha256 != Some(self.sha256) {
            return Err(unavailable());
        }
        Ok(r)
    }
    fn update(
        &self,
        from: Phase,
        to: Phase,
        remote: Option<RemoteEntry>,
        usn: Option<i64>,
    ) -> Result<(), BackendError> {
        let (raw, mut i) = load(&self.store, &self.scope)?;
        let r = i
            .rows
            .iter_mut()
            .find(|r| r.descriptor.id().ok().as_deref() == Some(self.id.as_str()))
            .ok_or_else(unavailable)?;
        if r.descriptor != self.stored || r.phase != from || r.sha256 != Some(self.sha256) {
            return Err(unavailable());
        }
        r.phase = to;
        if remote.is_some() {
            r.remote = remote;
        }
        if usn.is_some() {
            r.native_usn = usn;
        }
        commit(
            &self.store,
            &self.scope,
            raw.as_deref().map(Vec::as_slice),
            &i,
        )
    }
}
impl VaultFileReplaceRecord for Record {
    fn descriptor(&self) -> &VaultFileReplaceDescriptor {
        &self.descriptor
    }
    fn plaintext_sha256(&self) -> [u8; 32] {
        self.sha256
    }
    fn open_reader(
        &self,
        stop: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Box<dyn Read + Send>, BackendError> {
        let row = self.row()?;
        if !matches!(
            row.phase,
            Phase::Ready | Phase::Attempted | Phase::RemoteVerified
        ) {
            return Err(unavailable());
        }
        let body = snapshots(&self.scope, false)?
            .open_verified(&row.snapshot.record_id, &mut || stop())
            .map_err(|_| unavailable())?;
        if body.manifest().binding() != &row.snapshot
            || body.local_check().content_sha256() != &self.sha256
            || body.local_check().content_len() != self.descriptor.plaintext_len
        {
            return Err(unavailable());
        }
        Ok(Box::new(body.into_reader(stop).map_err(|_| unavailable())?))
    }
    fn claim_send(&self) -> Result<(), BackendError> {
        if self.send.swap(true, Ordering::AcqRel) {
            return Err(unavailable());
        }
        self.update(Phase::Ready, Phase::Attempted, None, None)
    }
    fn record_remote(&self, p: &VaultFileReplaceRemoteProof) -> Result<(), BackendError> {
        if Descriptor::from(&self.scope, p.descriptor())? != self.stored
            || p.plaintext_sha256() != self.sha256
        {
            return Err(unavailable());
        }
        validate_remote(&self.stored.facts, p.entry())?;
        self.update(
            Phase::Attempted,
            Phase::RemoteVerified,
            Some(p.entry().clone()),
            None,
        )
    }
    fn record_native_completed(&self, p: &VaultFileReplaceNativeProof) -> Result<(), BackendError> {
        if Descriptor::from(&self.scope, p.descriptor())? != self.stored
            || p.plaintext_sha256() != self.sha256
            || p.completed_usn() <= 0
        {
            return Err(unavailable());
        }
        self.update(
            Phase::RemoteVerified,
            Phase::NativeCompleted,
            None,
            Some(p.completed_usn()),
        )?;
        (self.refresh)()
    }
}
struct Capture {
    store: Arc<dyn Storage>,
    scope: Scope,
    descriptor: VaultFileReplaceDescriptor,
    stored: Descriptor,
    id: String,
    reservation: CaptureReservation,
    refresh: Arc<dyn Fn() -> Result<(), BackendError> + Send + Sync>,
}
struct Staged {
    capture: CaptureMetadata,
    stage: StagedSnapshot,
}
struct CaptureMetadata {
    store: Arc<dyn Storage>,
    scope: Scope,
    descriptor: VaultFileReplaceDescriptor,
    stored: Descriptor,
    id: String,
    refresh: Arc<dyn Fn() -> Result<(), BackendError> + Send + Sync>,
}
impl VaultFileReplaceCapture for Capture {
    fn stage(
        self: Box<Self>,
        source: &mut dyn Read,
        stop: &dyn Fn() -> bool,
    ) -> Result<Box<dyn VaultFileReplaceStaged>, BackendError> {
        let Self {
            store,
            scope,
            descriptor,
            stored,
            id,
            reservation,
            refresh,
        } = *self;
        if stop() {
            return Err(unavailable());
        }
        let stage = reservation
            .capture(source, &mut || stop())
            .map_err(|_| unavailable())?;
        Ok(Box::new(Staged {
            capture: CaptureMetadata {
                store,
                scope,
                descriptor,
                stored,
                id,
                refresh,
            },
            stage,
        }))
    }
}
impl VaultFileReplaceStaged for Staged {
    fn commit(
        self: Box<Self>,
        sha: [u8; 32],
        verify: &mut dyn FnMut() -> Result<(), BackendError>,
        stop: &dyn Fn() -> bool,
    ) -> Result<Arc<dyn VaultFileReplaceRecord>, BackendError> {
        let Self { capture: c, stage } = *self;
        if stop() || sha == [0; 32] {
            return Err(unavailable());
        }
        verify()?;
        let body = stage
            .verify_and_commit(&mut || stop())
            .map_err(|_| unavailable())?;
        if body.manifest().content_sha256() != &sha
            || body.manifest().binding().content_len != c.descriptor.plaintext_len
        {
            return Err(unavailable());
        }
        if stop() {
            return Err(unavailable());
        }
        verify()?;
        let (raw, mut i) = load(&c.store, &c.scope)?;
        let row = i
            .rows
            .iter_mut()
            .find(|r| r.descriptor.id().ok().as_deref() == Some(c.id.as_str()))
            .ok_or_else(unavailable)?;
        if row.descriptor != c.stored
            || row.phase != Phase::Capturing
            || &row.snapshot != body.manifest().binding()
        {
            return Err(unavailable());
        }
        row.phase = Phase::Ready;
        row.sha256 = Some(sha);
        commit(&c.store, &c.scope, raw.as_deref().map(Vec::as_slice), &i)?;
        Ok(Arc::new(Record {
            store: c.store,
            scope: c.scope,
            descriptor: c.descriptor,
            stored: c.stored,
            id: c.id,
            sha256: sha,
            send: AtomicBool::new(false),
            refresh: c.refresh,
        }))
    }
}
pub(super) fn begin(
    store: Arc<dyn Storage>,
    scope: &Scope,
    d: &VaultFileReplaceDescriptor,
    refresh: Arc<dyn Fn() -> Result<(), BackendError> + Send + Sync>,
) -> Result<Box<dyn VaultFileReplaceCapture>, BackendError> {
    let stored = Descriptor::from(scope, d)?;
    let id = stored.id()?;
    let (raw, mut i) = load(&store, scope)?;
    if i.rows.len() >= LIMIT
        || i.rows.iter().any(|r| {
            r.phase != Phase::NativeCompleted
                || r.descriptor.id().ok().as_deref() == Some(id.as_str())
        })
    {
        return Err(unavailable());
    }
    let reservation = snapshots(scope, true)?
        .try_begin_capture(SnapshotBinding {
            record_id: String::new(),
            scope: scope.streamed_storage_scope().map_err(|_| unavailable())?,
            generation: d.owner.token_generation(),
            local_file: d.replacement_file,
            relative_path: d.components.join("/"),
            remote: Some(raiun_cloudfiles_windows::RemoteEditBaseline {
                resource_id: d.original.id.clone(),
                etag: d.original.etag.clone(),
                byte_len: d.original.size,
            }),
            content_len: d.plaintext_len,
        })
        .map_err(|_| unavailable())?;
    i.rows.push(Row {
        descriptor: stored.clone(),
        snapshot: reservation.binding().clone(),
        phase: Phase::Capturing,
        sha256: None,
        remote: None,
        native_usn: None,
    });
    commit(&store, scope, raw.as_deref().map(Vec::as_slice), &i)?;
    Ok(Box::new(Capture {
        store,
        scope: scope.clone(),
        descriptor: d.clone(),
        stored,
        id,
        reservation,
        refresh,
    }))
}
pub(super) fn verify_no_unresolved(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<(), BackendError> {
    let (_, i) = load(store, scope)?;
    if i.rows.iter().any(|r| r.phase != Phase::NativeCompleted) {
        return Err(unavailable());
    }
    Ok(())
}
// Startup/restore only, outside route/token/unlock publication fences. Runtime
// factual completion refresh uses authenticated metadata, never rereads bodies.
pub(super) fn verify_retained_bodies(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<(), BackendError> {
    verify_no_unresolved(store, scope)?;
    let (_, i) = load(store, scope)?;
    for r in &i.rows {
        let body = snapshots(scope, false)?
            .open_verified(&r.snapshot.record_id, &mut || false)
            .map_err(|_| unavailable())?;
        if body.manifest().binding() != &r.snapshot
            || Some(*body.local_check().content_sha256()) != r.sha256
        {
            return Err(unavailable());
        }
    }
    Ok(())
}
// Completed facts change current-location clones only. Original descriptors,
// captures and dispositions remain byte-for-byte bound to their own history.
pub(super) fn entry(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    e: &Entry,
) -> Result<Entry, BackendError> {
    let (_, i) = load(store, scope)?;
    let mut next = e.clone();
    for r in &i.rows {
        if r.phase != Phase::NativeCompleted {
            continue;
        }
        let f = &r.descriptor.facts;
        if next.opaque() == f.original_identity
            && next.remote_id() == f.original.id
            && next.root_relative_path() == f.original.path
            && next.etag() == f.original.etag
            && next.length() == f.original.size
            && !next.is_directory()
        {
            let remote = r.remote.as_ref().ok_or_else(unavailable)?;
            next = Entry::new(
                next.opaque(),
                &remote.id,
                &remote.path,
                &remote.etag,
                false,
                remote.size,
            )
            .map_err(|_| unavailable())?;
        }
    }
    Ok(next)
}
pub(super) fn hydration(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    h: &Hydration,
) -> Result<Hydration, BackendError> {
    let (_, i) = load(store, scope)?;
    let mut next = h.clone();
    for r in &i.rows {
        if r.phase != Phase::NativeCompleted {
            continue;
        }
        let f = &r.descriptor.facts;
        if next.opaque() == f.original_identity
            && next.file_index() == f.original_file.file_index
            && next.length() == f.original.size
            && next.components() == f.components
        {
            next = next.with_replacement(f.replacement_file.file_index, f.plaintext_len);
        }
    }
    Ok(next)
}

/// Completed exact-native lineage only. This is historical continuity evidence,
/// never a source pin, mutation permit or permission to adopt a different file.
pub(super) fn file_lineage(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    identity: [u8; 16],
    resource_id: &str,
    old_file: u64,
    new_file: u64,
) -> Result<bool, BackendError> {
    if identity == [0; 16] || old_file == 0 || new_file == 0 {
        return Err(unavailable());
    }
    let (_, index) = load(store, scope)?;
    if index.rows.iter().any(|r| r.phase != Phase::NativeCompleted) {
        return Err(unavailable());
    }
    let mut current = old_file;
    for row in &index.rows {
        let f = &row.descriptor.facts;
        if f.original_identity == identity
            && f.original.id == resource_id
            && f.original_file.file_index == current
        {
            current = f.replacement_file.file_index;
        }
    }
    Ok(current == new_file)
}

//! Vault-only original-byte custody for one live child-create attempt. No
//! ordinary recovery registration, discovery dispatch or serialized unlock.
use super::{vault_custody::Scope, windows_vault_custody::Storage};
use raiun_cloudfiles_windows::{
    BackendError, EditRecordProtector, JournalError, VaultChildCreateDescriptor,
    VaultChildCreateRecord, VaultChildCreateRemoteProof, VaultChildCreateSource,
    streamed_snapshot::SnapshotBinding,
    streamed_store::{SnapshotStore, StorePolicy},
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
const DOMAIN: &[u8] = b"raiun/windows-vault-child-create/v1\0";
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
    let storage = DpapiSessionStore::current_user().map_err(|_| unavailable())?;
    Ok(storage.local_edit_state_directory().join(format!(
        "vault-child-create-v1-{:x}",
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
        max_content_bytes: 1 << 30,
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
    token_generation: u64,
    historical_epoch: u64,
    parent_identity: [u8; 16],
    parent: RemoteEntry,
    logical_path: String,
    encoded_target: String,
    integrity_token: String,
    source: VaultChildCreateSource,
}
impl Descriptor {
    fn from(scope: &Scope, d: &VaultChildCreateDescriptor) -> Result<Self, BackendError> {
        d.validate()?;
        let target_scope = scope.streamed_storage_scope().map_err(|_| unavailable())?;
        if scope.native_root() != (d.root.volume_serial, d.root.file_index)
            || d.owner.profile_id() != target_scope.profile_id
            || d.owner.server_origin() != target_scope.server_origin
            || d.owner.account_id() != target_scope.account_subject
            || d.vault.space_id() != target_scope.space_id
            || d.vault.resource_id() != target_scope.root_resource_id
        {
            return Err(unavailable());
        }
        let value = Self {
            scope: scope.clone(),
            token_generation: d.owner.token_generation(),
            historical_epoch: d.historical_unlock_epoch,
            parent_identity: d.parent_identity,
            parent: d.parent.clone(),
            logical_path: d.logical_path.clone(),
            encoded_target: d.encoded_target.clone(),
            integrity_token: d.integrity_token.clone(),
            source: d.source.clone(),
        };
        value.validate(scope)?;
        Ok(value)
    }
    fn validate(&self, scope: &Scope) -> Result<(), BackendError> {
        let (volume, file) = scope.native_root();
        self.source
            .validate(raiun_cloudfiles_windows::ConfiguredRootIdentity {
                volume_serial: volume,
                file_index: file,
            })?;
        let bounded = |s: &str, max: usize| {
            !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
        };
        if self.scope != *scope
            || self.token_generation == 0
            || self.historical_epoch == 0
            || self.parent_identity == [0; 16]
            || !self.parent.directory
            || !bounded(&self.parent.id, 4096)
            || raiun_core::validate_remote_path(&self.parent.path).is_err()
            || !super::vault_edit_capture::strong_etag(&self.parent.etag)
            || self.logical_path == "/"
            || self.logical_path.len() > 32000
            || raiun_core::validate_remote_path(&self.logical_path).is_err()
            || self.logical_path
                != format!(
                    "{}/{}",
                    self.parent.path.trim_end_matches('/'),
                    self.source.components.last().ok_or_else(unavailable)?
                )
            || !bounded(&self.encoded_target, 32000)
            || self.encoded_target.starts_with('/')
            || self.encoded_target.contains('\\')
            || self
                .encoded_target
                .split('/')
                .any(|c| c.is_empty() || c == "." || c == "..")
            || !bounded(&self.integrity_token, 65536)
            || (self.parent.path == "/"
                && self.parent.id
                    != scope
                        .streamed_storage_scope()
                        .map_err(|_| unavailable())?
                        .root_resource_id)
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
    LocalQueued,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    descriptor: Descriptor,
    snapshot: Option<SnapshotBinding>,
    phase: Phase,
    remote: Option<RemoteEntry>,
    identity: Option<[u8; 16]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    queued: Option<super::windows_vault_namespace_queued::Queued>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u32,
    scope: Scope,
    rows: Vec<Row>,
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
            if (row.phase == Phase::LocalQueued) != row.queued.is_some() {
                return Err(unavailable());
            }
            if let Some(q) = &row.queued {
                validate_queued(&row.descriptor, q)?;
            }

            let remote_expected =
                matches!(row.phase, Phase::RemoteVerified | Phase::NativeCompleted);
            if remote_expected != row.remote.is_some()
                || row
                    .identity
                    .is_some_and(|id| id == [0; 16] || id == row.descriptor.parent_identity)
            {
                return Err(unavailable());
            }
            if let Some(remote) = &row.remote {
                if remote.id.is_empty() || remote.id.len()>4096 || remote.id.chars().any(char::is_control)
                    || remote.id==row.descriptor.parent.id || remote.id==scope.streamed_storage_scope().map_err(|_|unavailable())?.root_resource_id
                    || remote.path!=row.descriptor.logical_path || remote.directory!=(row.descriptor.source.kind==raiun_cloudfiles_windows::namespace_intent::NamespaceObjectKind::Directory)
                    || remote.size!=row.descriptor.source.plaintext_len || !super::vault_edit_capture::strong_etag(&remote.etag)
                {return Err(unavailable());}
            }
            if row.descriptor.scope != *scope
                || !ids.insert(row.descriptor.id()?)
                || (row.descriptor.source.kind
                    == raiun_cloudfiles_windows::namespace_intent::NamespaceObjectKind::File)
                    != row.snapshot.is_some()
                || (row.phase == Phase::NativeCompleted
                    && (row.identity.is_none() || row.remote.is_none()))
                || (row.phase == Phase::RemoteVerified && row.remote.is_none())
                || (row.phase != Phase::NativeCompleted && row.identity.is_some())
            {
                return Err(unavailable());
            }
            if let Some(body) = &row.snapshot {
                let source = &row.descriptor.source;
                if body.record_id.len() != 32
                    || !body.record_id.bytes().all(|b| b.is_ascii_hexdigit())
                    || body.scope != scope.streamed_storage_scope().map_err(|_| unavailable())?
                    || body.generation != row.descriptor.token_generation
                    || body.local_file.volume_serial != source.volume
                    || body.local_file.file_index != source.file
                    || body.relative_path != source.components.join("/")
                    || body.remote.is_some()
                    || body.content_len != source.plaintext_len
                {
                    return Err(unavailable());
                }
            }
        }
        index
    } else {
        // An existing private namespace without its index is never adopted as
        // a fresh create store, including after uncertain first publication.
        match std::fs::symlink_metadata(directory(scope)?) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err(unavailable()),
        }
        Index {
            version: 1,
            scope: scope.clone(),
            rows: Vec::new(),
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
    let check = store
        .load(&binding(scope)?)
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
    if check.as_slice() != raw.as_slice() {
        return Err(unavailable());
    }
    Ok(())
}
/// Startup/cleanup history qualification only. Unknown or unfinished creates
/// must not become an implicitly clean vault after a process restart.
pub(super) fn verify_no_unresolved(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<(), BackendError> {
    let (_, index) = load(store, scope)?;
    if index.rows.iter().any(|r| {
        r.phase != Phase::NativeCompleted
            && !(r.phase == Phase::LocalQueued
                && r.queued.as_ref().is_some_and(|q| q.native.is_some()))
    }) {
        return Err(unavailable());
    }
    for row in &index.rows {
        if let Some(expected) = &row.snapshot {
            let pinned = snapshots(scope, false)?
                .open_verified(&expected.record_id, &mut || false)
                .map_err(|_| unavailable())?;
            if pinned.manifest().binding() != expected
                || pinned.local_check().content_len() != row.descriptor.source.plaintext_len
                || Some(*pinned.local_check().content_sha256())
                    != row.descriptor.source.plaintext_sha256
            {
                return Err(unavailable());
            }
        }
    }
    Ok(())
}
struct Record {
    store: Arc<dyn Storage>,
    scope: Scope,
    descriptor: VaultChildCreateDescriptor,
    stored: Descriptor,
    id: String,
    send_claimed: AtomicBool,
}
impl Record {
    fn row(&self) -> Result<Row, BackendError> {
        let (_, index) = load(&self.store, &self.scope)?;
        let mut found = index
            .rows
            .into_iter()
            .filter(|r| r.descriptor.id().ok().as_deref() == Some(self.id.as_str()));
        let row = found.next().ok_or_else(unavailable)?;
        if found.next().is_some() || row.descriptor != self.stored {
            return Err(unavailable());
        }
        Ok(row)
    }
    fn update(
        &self,
        from: Phase,
        to: Phase,
        remote: Option<RemoteEntry>,
        identity: Option<[u8; 16]>,
    ) -> Result<(), BackendError> {
        let (old, mut index) = load(&self.store, &self.scope)?;
        let row = index
            .rows
            .iter_mut()
            .find(|r| r.descriptor.id().ok().as_deref() == Some(self.id.as_str()))
            .ok_or_else(unavailable)?;
        if row.descriptor != self.stored || row.phase != from {
            return Err(unavailable());
        }
        row.phase = to;
        if let Some(e) = remote {
            row.remote = Some(e);
        }
        if let Some(id) = identity {
            row.identity = Some(id);
        }
        commit(
            &self.store,
            &self.scope,
            old.as_ref().map(|v| v.as_slice()),
            &index,
        )
    }
}
impl VaultChildCreateRecord for Record {
    fn descriptor(&self) -> &VaultChildCreateDescriptor {
        &self.descriptor
    }
    fn open_reader(
        &self,
        cancel: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Box<dyn Read + Send>, BackendError> {
        let row = self.row()?;
        if !matches!(
            row.phase,
            Phase::Ready | Phase::Attempted | Phase::RemoteVerified
        ) {
            return Err(unavailable());
        }
        let binding = row.snapshot.ok_or_else(unavailable)?;
        let snapshot = snapshots(&self.scope, false)?
            .open_verified(&binding.record_id, &mut || cancel())
            .map_err(|_| unavailable())?;
        if snapshot.manifest().binding() != &binding
            || snapshot.local_check().content_len() != self.descriptor.source.plaintext_len
            || Some(*snapshot.local_check().content_sha256())
                != self.descriptor.source.plaintext_sha256
        {
            return Err(unavailable());
        }
        Ok(Box::new(
            snapshot.into_reader(cancel).map_err(|_| unavailable())?,
        ))
    }
    fn record_local_queued(
        &self,
        r: &raiun_cloudfiles_windows::VaultCachedNamespaceQueued,
    ) -> Result<(), BackendError> {
        let raiun_cloudfiles_windows::VaultCachedNamespaceDescriptor::ChildCreate(d) =
            r.descriptor()
        else {
            return Err(unavailable());
        };
        if Descriptor::from(&self.scope, d)? != self.stored {
            return Err(unavailable());
        }
        let q = super::windows_vault_namespace_queued::Queued::from(r)?;
        validate_queued(&self.stored, &q)?;
        let (old, mut index) = load(&self.store, &self.scope)?;
        let row = index
            .rows
            .iter_mut()
            .find(|v| v.descriptor == self.stored)
            .ok_or_else(unavailable)?;
        if row.phase != Phase::Ready
            || row.queued.is_some()
            || self.send_claimed.load(Ordering::Acquire)
        {
            return Err(unavailable());
        }
        row.phase = Phase::LocalQueued;
        row.queued = Some(q);
        commit(
            &self.store,
            &self.scope,
            old.as_ref().map(|v| v.as_slice()),
            &index,
        )
    }
    fn record_local_queued_native(
        &self,
        r: &raiun_cloudfiles_windows::VaultCachedNamespaceQueued,
        identity: [u8; 16],
        file: u64,
        usn: i64,
    ) -> Result<(), BackendError> {
        let raiun_cloudfiles_windows::VaultCachedNamespaceDescriptor::ChildCreate(d) =
            r.descriptor()
        else {
            return Err(unavailable());
        };
        if Descriptor::from(&self.scope, d)? != self.stored
            || file != self.descriptor.source.file
            || identity == self.descriptor.parent_identity
        {
            return Err(unavailable());
        }
        let (old, mut index) = load(&self.store, &self.scope)?;
        let row = index
            .rows
            .iter_mut()
            .find(|v| v.descriptor == self.stored)
            .ok_or_else(unavailable)?;
        if row.phase != Phase::LocalQueued {
            return Err(unavailable());
        }
        let q = row.queued.as_mut().ok_or_else(unavailable)?;
        if !q.matches_receipt(r)? {
            return Err(unavailable());
        }
        q.record_native(identity, file, usn)?;
        validate_queued(&self.stored, q)?;
        commit(
            &self.store,
            &self.scope,
            old.as_ref().map(|v| v.as_slice()),
            &index,
        )
    }
    fn claim_send(&self) -> Result<(), BackendError> {
        if self.send_claimed.swap(true, Ordering::AcqRel) {
            return Err(unavailable());
        }
        self.update(Phase::Ready, Phase::Attempted, None, None)
    }
    fn record_remote(&self, proof: &VaultChildCreateRemoteProof) -> Result<(), BackendError> {
        if Descriptor::from(&self.scope, proof.descriptor())? != self.stored {
            return Err(unavailable());
        }
        self.update(
            Phase::Attempted,
            Phase::RemoteVerified,
            Some(proof.entry().clone()),
            None,
        )
    }
    fn record_native_completed(&self, identity: [u8; 16]) -> Result<(), BackendError> {
        if identity == [0; 16] {
            return Err(unavailable());
        }
        self.update(
            Phase::RemoteVerified,
            Phase::NativeCompleted,
            None,
            Some(identity),
        )
    }
}
pub(super) fn prepare(
    store: Arc<dyn Storage>,
    scope: &Scope,
    descriptor: &VaultChildCreateDescriptor,
    source: Option<&mut dyn Read>,
    verify_source: &mut dyn FnMut() -> Result<(), BackendError>,
    cancel: &dyn Fn() -> bool,
) -> Result<Arc<dyn VaultChildCreateRecord>, BackendError> {
    let stored = Descriptor::from(scope, descriptor)?;
    let id = stored.id()?;
    let (old, mut index) = load(&store, scope)?;
    if cancel()
        || index.rows.len() >= LIMIT
        || index
            .rows
            .iter()
            .any(|r| !settled(r) || r.descriptor.id().ok().as_deref() == Some(id.as_str()))
    {
        return Err(unavailable());
    }
    verify_source()?;
    let snapshots = snapshots(scope, true)?; // also leaves a durable namespace sentinel for DIR
    let mut reservation = if descriptor.source.kind
        == raiun_cloudfiles_windows::namespace_intent::NamespaceObjectKind::File
    {
        Some(
            snapshots
                .try_begin_capture(SnapshotBinding {
                    record_id: String::new(),
                    scope: scope.streamed_storage_scope().map_err(|_| unavailable())?,
                    generation: descriptor.owner.token_generation(),
                    local_file: raiun_cloudfiles_windows::LocalFileIdentity {
                        volume_serial: descriptor.source.volume,
                        file_index: descriptor.source.file,
                    },
                    relative_path: descriptor.source.components.join("/"),
                    remote: None,
                    content_len: descriptor.source.plaintext_len,
                })
                .map_err(|_| unavailable())?,
        )
    } else {
        None
    };
    index.rows.push(Row {
        descriptor: stored.clone(),
        snapshot: reservation.as_ref().map(|r| r.binding().clone()),
        phase: Phase::Capturing,
        remote: None,
        identity: None,
        queued: None,
    });
    commit(&store, scope, old.as_ref().map(|v| v.as_slice()), &index)?;
    if let Some(reservation) = reservation.take() {
        let reader = source.ok_or_else(unavailable)?;
        let stage = reservation
            .capture(reader, &mut || cancel())
            .map_err(|_| unavailable())?;
        verify_source()?;
        let body = stage
            .verify_and_commit(&mut || cancel())
            .map_err(|_| unavailable())?;
        if body.manifest().binding()
            != index
                .rows
                .last()
                .and_then(|r| r.snapshot.as_ref())
                .ok_or_else(unavailable)?
            || Some(*body.manifest().content_sha256()) != descriptor.source.plaintext_sha256
        {
            return Err(unavailable());
        }
    } else if source.is_some() {
        return Err(unavailable());
    }
    if cancel() {
        return Err(unavailable());
    }
    verify_source()?;
    let record = Arc::new(Record {
        store,
        scope: scope.clone(),
        descriptor: descriptor.clone(),
        stored,
        id,
        send_claimed: AtomicBool::new(false),
    });
    record.update(Phase::Capturing, Phase::Ready, None, None)?;
    Ok(record)
}

fn validate_queued(
    d: &Descriptor,
    q: &super::windows_vault_namespace_queued::Queued,
) -> Result<(), BackendError> {
    use raiun_cloudfiles_windows::VaultCachedNamespaceOperation as O;
    q.validate()?;
    let directory =
        d.source.kind == raiun_cloudfiles_windows::namespace_intent::NamespaceObjectKind::Directory;
    if q.operation
        != if directory {
            O::CreateDirectory
        } else {
            O::CreateFile
        }
        || q.original.is_some()
        || q.parent != d.parent
        || q.entry.as_ref().is_none_or(|e| {
            e.path != d.logical_path || e.directory != directory || e.size != d.source.plaintext_len
        })
        || q.plaintext_len != d.source.plaintext_len
        || q.source_sha256 != d.source.plaintext_sha256
        || q.native
            .as_ref()
            .is_some_and(|n| n.file != d.source.file || n.identity == d.parent_identity)
    {
        return Err(unavailable());
    }
    Ok(())
}
pub(super) fn pending_native_facts(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<Vec<super::windows_vault_namespace_queued::PendingFacts>, BackendError> {
    verify_no_unresolved(store, scope)?;
    let (_, i) = load(store, scope)?;
    i.rows
        .iter()
        .filter(|r| r.phase == Phase::LocalQueued)
        .map(|r| {
            r.queued
                .as_ref()
                .ok_or_else(unavailable)?
                .pending_facts(r.descriptor.source.components.clone())
        })
        .collect()
}
pub(super) fn pending_catalogue(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<Vec<raiun_cloudfiles_windows::VaultCatalogueEntry>, BackendError> {
    pending_native_facts(store, scope)?
        .into_iter()
        .map(|p| {
            let mut entry = p.entry.ok_or_else(unavailable)?;
            entry.writable = false;
            Ok(raiun_cloudfiles_windows::VaultCatalogueEntry {
                identity: p.identity,
                metadata: entry,
            })
        })
        .collect()
}
pub(super) fn has_local_queued(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<bool, BackendError> {
    let (_, i) = load(store, scope)?;
    Ok(i.rows.iter().any(|r| r.phase == Phase::LocalQueued))
}

fn settled(r: &Row) -> bool {
    r.phase == Phase::NativeCompleted
        || (r.phase == Phase::LocalQueued && r.queued.as_ref().is_some_and(|q| q.native.is_some()))
}

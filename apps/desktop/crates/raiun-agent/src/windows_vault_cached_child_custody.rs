//! Local-only custody for a child below a never-attempted queued directory.
//! Synthetic parent facts cannot enter the online child-create record.
use super::{vault_custody::Scope, windows_vault_custody::Storage};
use raiun_cloudfiles_windows::{
    BackendError, EditRecordProtector, JournalError, VaultCachedChildCreateDescriptor,
    VaultCachedChildCreateRecord, VaultCachedNamespaceDescriptor, VaultCachedNamespaceQueued,
    namespace_intent::NamespaceObjectKind,
    streamed_snapshot::SnapshotBinding,
    streamed_store::{SnapshotStore, StorePolicy},
};
use raiun_control_windows::{DpapiSessionStore, PinnedDirectory, PrivateDirectory};
use raiun_core::backend::RemoteEntry;
use raiun_opencloud::vault_cache::VaultPendingParentRef;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read, path::PathBuf, sync::Arc};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"raiun/windows-vault-cached-child-create/v1\0";
const LIMIT: usize = 1024;
fn no() -> BackendError {
    BackendError::Unavailable
}
fn binding(scope: &Scope) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    let s = scope.authenticated_store_binding().map_err(|_| no())?;
    let mut b = Zeroizing::new(DOMAIN.to_vec());
    b.extend_from_slice(&(s.len() as u64).to_le_bytes());
    b.extend_from_slice(&s);
    Ok(b)
}
fn directory(scope: &Scope) -> Result<PathBuf, BackendError> {
    Ok(DpapiSessionStore::current_user()
        .map_err(|_| no())?
        .local_edit_state_directory()
        .join(format!(
            "vault-cached-child-create-v1-{:x}",
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
    let storage = DpapiSessionStore::current_user().map_err(|_| no())?;
    let parent = PinnedDirectory::open(storage.local_edit_state_directory()).map_err(|_| no())?;
    let name = path.file_name().ok_or_else(no)?;
    let private = Arc::new(
        if create {
            PrivateDirectory::create_or_open_under(&parent, name)
        } else {
            PrivateDirectory::open_under(&parent, name)
        }
        .map_err(|_| no())?,
    );
    let protector = Arc::new(Protector {
        inner: raiun_cloudfiles_windows::DpapiEditRecordProtector::from_existing_private_directory(
            private.clone(),
        )
        .map_err(|_| no())?,
        binding: binding(scope)?,
    });
    let policy = StorePolicy {
        max_content_bytes: 1 << 30,
        max_state_bytes: 4 << 30,
        max_entries: 4096,
        max_metadata_bytes_per_scan: 64 << 20,
    };
    let target = scope.streamed_storage_scope().map_err(|_| no())?;
    if create {
        SnapshotStore::create_or_open(private, target, protector, policy)
    } else {
        SnapshotStore::open_existing(private, target, protector, policy)
    }
    .map_err(|_| no())
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    scope: Scope,
    generation: u64,
    historical_epoch: u64,
    parent_identity: [u8; 16],
    parent: RemoteEntry,
    parent_write_id: String,
    parent_revision: u64,
    logical_path: String,
    encoded_target: String,
    integrity_token: String,
    source: raiun_cloudfiles_windows::VaultChildCreateSource,
}
impl Descriptor {
    fn from(scope: &Scope, d: &VaultCachedChildCreateDescriptor) -> Result<Self, BackendError> {
        d.validate()?;
        let s = scope.streamed_storage_scope().map_err(|_| no())?;
        let VaultPendingParentRef::PendingCreate { write_id, revision } = &d.parent_ref else {
            return Err(no());
        };
        if scope.native_root() != (d.root.volume_serial, d.root.file_index)
            || d.remote_root != scope.remote_root()
            || d.owner.profile_id() != s.profile_id
            || d.owner.server_origin() != s.server_origin
            || d.owner.account_id() != s.account_subject
            || d.vault.space_id() != s.space_id
            || d.vault.resource_id() != s.root_resource_id
        {
            return Err(no());
        }
        let value = Self {
            scope: scope.clone(),
            generation: d.owner.token_generation(),
            historical_epoch: d.historical_unlock_epoch,
            parent_identity: d.parent_identity,
            parent: d.parent.clone(),
            parent_write_id: write_id.clone(),
            parent_revision: *revision,
            logical_path: d.logical_path.clone(),
            encoded_target: d.encoded_target.clone(),
            integrity_token: d.integrity_token.clone(),
            source: d.source.clone(),
        };
        value.validate(scope)?;
        Ok(value)
    }
    fn validate(&self, scope: &Scope) -> Result<(), BackendError> {
        let (volume_serial, file_index) = scope.native_root();
        self.source
            .validate(raiun_cloudfiles_windows::ConfiguredRootIdentity {
                volume_serial,
                file_index,
            })?;
        let id = &self.parent_write_id;
        if self.scope != *scope
            || self.generation == 0
            || self.historical_epoch == 0
            || self.parent_identity == [0; 16]
            || self.parent_revision == 0
            || id.len() != 32
            || !id.bytes().all(|b| b.is_ascii_hexdigit())
            || self.parent.id != format!("raiun-pending-directory:{id}")
            || self.parent.etag != format!("raiun-pending-v1:{id}:{}", self.parent_revision)
            || !self.parent.directory
            || self.parent.size != 0
            || self.parent.path.len() > 32000
            || raiun_core::validate_remote_path(&self.parent.path).is_err()
            || self.source.file == self.source.parent_file
            || self.source.parent_file == file_index
            || self.logical_path
                != format!(
                    "{}/{}",
                    self.parent.path.trim_end_matches('/'),
                    self.source.components.last().ok_or_else(no)?
                )
            || self.logical_path.len() > 32000
            || raiun_core::validate_remote_path(&self.logical_path).is_err()
            || self.encoded_target.is_empty()
            || self.encoded_target.len() > 32000
            || self.encoded_target.starts_with('/')
            || self.encoded_target.contains('\\')
            || self.encoded_target.chars().any(char::is_control)
            || self
                .encoded_target
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
            || self.integrity_token.is_empty()
            || self.integrity_token.len() > 65536
        {
            return Err(no());
        }
        Ok(())
    }
    fn id(&self) -> Result<String, BackendError> {
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(self).map_err(|_| no())?)
        ))
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    Capturing,
    Ready,
    LocalQueued,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    descriptor: Descriptor,
    snapshot: Option<SnapshotBinding>,
    phase: Phase,
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
    let raw = store.load(&binding(scope)?).map_err(|_| no())?;
    let index = if let Some(raw) = &raw {
        if !std::fs::symlink_metadata(directory(scope)?)
            .map(|m| m.is_dir() && !m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(no());
        }
        if raw.is_empty() || raw.len() > 16 << 20 {
            return Err(no());
        }
        let index: Index = serde_json::from_slice(raw).map_err(|_| no())?;
        if index.version != 1
            || index.scope != *scope
            || index.rows.is_empty()
            || index.rows.len() > LIMIT
        {
            return Err(no());
        }
        let mut ids = std::collections::BTreeSet::new();
        for row in &index.rows {
            row.descriptor.validate(scope)?;
            if !ids.insert(row.descriptor.id()?)
                || (row.phase == Phase::LocalQueued) != row.queued.is_some()
                || (row.descriptor.source.kind == NamespaceObjectKind::File)
                    != row.snapshot.is_some()
            {
                return Err(no());
            }
            if let Some(q) = &row.queued {
                validate_queued(&row.descriptor, q)?;
            }
            if let Some(body) = &row.snapshot {
                let source = &row.descriptor.source;
                if body.record_id.len() != 32
                    || !body.record_id.bytes().all(|b| b.is_ascii_hexdigit())
                    || body.scope != scope.streamed_storage_scope().map_err(|_| no())?
                    || body.generation != row.descriptor.generation
                    || body.local_file.volume_serial != source.volume
                    || body.local_file.file_index != source.file
                    || body.relative_path != source.components.join("/")
                    || body.remote.is_some()
                    || body.content_len != source.plaintext_len
                {
                    return Err(no());
                }
            }
        }
        index
    } else {
        match std::fs::symlink_metadata(directory(scope)?) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err(no()),
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
    let raw = Zeroizing::new(serde_json::to_vec(index).map_err(|_| no())?);
    if raw.len() > 16 << 20 || index.rows.len() > LIMIT {
        return Err(no());
    }
    store.cas(&binding(scope)?, old, &raw).map_err(|_| no())?;
    if store
        .load(&binding(scope)?)
        .map_err(|_| no())?
        .is_none_or(|v| v.as_slice() != raw.as_slice())
    {
        return Err(no());
    }
    Ok(())
}
fn validate_queued(
    d: &Descriptor,
    q: &super::windows_vault_namespace_queued::Queued,
) -> Result<(), BackendError> {
    use raiun_cloudfiles_windows::VaultCachedNamespaceOperation as O;
    q.validate()?;
    let directory = d.source.kind == NamespaceObjectKind::Directory;
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
        return Err(no());
    }
    Ok(())
}
pub(super) fn verify_no_unresolved(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<(), BackendError> {
    let (_, index) = load(store, scope)?;
    if index.rows.iter().any(|r| {
        r.phase != Phase::LocalQueued || r.queued.as_ref().is_none_or(|q| q.native.is_none())
    }) {
        return Err(no());
    }
    for row in &index.rows {
        if let Some(expected) = &row.snapshot {
            let pinned = snapshots(scope, false)?
                .open_verified(&expected.record_id, &mut || false)
                .map_err(|_| no())?;
            if pinned.manifest().binding() != expected
                || pinned.local_check().content_len() != row.descriptor.source.plaintext_len
                || Some(*pinned.local_check().content_sha256())
                    != row.descriptor.source.plaintext_sha256
            {
                return Err(no());
            }
        }
    }
    Ok(())
}
struct Record {
    store: Arc<dyn Storage>,
    scope: Scope,
    descriptor: VaultCachedChildCreateDescriptor,
    stored: Descriptor,
    id: String,
}
impl Record {
    fn row(&self) -> Result<Row, BackendError> {
        let (_, index) = load(&self.store, &self.scope)?;
        let mut found = index
            .rows
            .into_iter()
            .filter(|r| r.descriptor.id().ok().as_deref() == Some(self.id.as_str()));
        let row = found.next().ok_or_else(no)?;
        if found.next().is_some() || row.descriptor != self.stored {
            return Err(no());
        }
        Ok(row)
    }
}
impl VaultCachedChildCreateRecord for Record {
    fn descriptor(&self) -> &VaultCachedChildCreateDescriptor {
        &self.descriptor
    }
    fn open_reader(
        &self,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Box<dyn Read + Send>, BackendError> {
        let row = self.row()?;
        if row.phase != Phase::Ready {
            return Err(no());
        }
        let expected = row.snapshot.ok_or_else(no)?;
        let pinned = snapshots(&self.scope, false)?
            .open_verified(&expected.record_id, &mut || cancelled())
            .map_err(|_| no())?;
        if pinned.manifest().binding() != &expected
            || pinned.local_check().content_len() != self.descriptor.source.plaintext_len
            || Some(*pinned.local_check().content_sha256())
                != self.descriptor.source.plaintext_sha256
        {
            return Err(no());
        }
        Ok(Box::new(pinned.into_reader(cancelled).map_err(|_| no())?))
    }
    fn record_local_queued(
        &self,
        receipt: &VaultCachedNamespaceQueued,
    ) -> Result<(), BackendError> {
        let VaultCachedNamespaceDescriptor::CachedChildCreate(d) = receipt.descriptor() else {
            return Err(no());
        };
        if Descriptor::from(&self.scope, d)? != self.stored {
            return Err(no());
        }
        let q = super::windows_vault_namespace_queued::Queued::from(receipt)?;
        validate_queued(&self.stored, &q)?;
        let (old, mut index) = load(&self.store, &self.scope)?;
        let row = index
            .rows
            .iter_mut()
            .find(|r| r.descriptor == self.stored)
            .ok_or_else(no)?;
        if row.phase != Phase::Ready || row.queued.is_some() {
            return Err(no());
        }
        row.phase = Phase::LocalQueued;
        row.queued = Some(q);
        commit(
            &self.store,
            &self.scope,
            old.as_deref().map(Vec::as_slice),
            &index,
        )
    }
    fn record_local_queued_native(
        &self,
        receipt: &VaultCachedNamespaceQueued,
        identity: [u8; 16],
        file: u64,
        usn: i64,
    ) -> Result<(), BackendError> {
        let VaultCachedNamespaceDescriptor::CachedChildCreate(d) = receipt.descriptor() else {
            return Err(no());
        };
        if Descriptor::from(&self.scope, d)? != self.stored
            || file != self.descriptor.source.file
            || identity == self.descriptor.parent_identity
        {
            return Err(no());
        }
        let (old, mut index) = load(&self.store, &self.scope)?;
        let row = index
            .rows
            .iter_mut()
            .find(|r| r.descriptor == self.stored)
            .ok_or_else(no)?;
        if row.phase != Phase::LocalQueued {
            return Err(no());
        }
        let q = row.queued.as_mut().ok_or_else(no)?;
        if !q.matches_receipt(receipt)? {
            return Err(no());
        }
        q.record_native(identity, file, usn)?;
        validate_queued(&self.stored, q)?;
        commit(
            &self.store,
            &self.scope,
            old.as_deref().map(Vec::as_slice),
            &index,
        )
    }
}
pub(super) fn prepare(
    store: Arc<dyn Storage>,
    scope: &Scope,
    descriptor: &VaultCachedChildCreateDescriptor,
    source: Option<&mut dyn Read>,
    verify_source: &mut dyn FnMut() -> Result<(), BackendError>,
    cancel: &dyn Fn() -> bool,
) -> Result<Arc<dyn VaultCachedChildCreateRecord>, BackendError> {
    let stored = Descriptor::from(scope, descriptor)?;
    let parent = super::windows_vault_namespace_queued::current_created_facts(&store, scope)?
        .into_iter()
        .find(|r| r.identity == stored.parent_identity)
        .ok_or_else(no)?;
    if parent.file != stored.source.parent_file
        || parent.usn != stored.source.parent_usn
        || parent.write_id != stored.parent_write_id
        || parent.revision != stored.parent_revision
        || parent.entry.as_ref() != Some(&stored.parent)
        || !stored.parent.directory
    {
        return Err(no());
    }
    let id = stored.id()?;
    let (old, mut index) = load(&store, scope)?;
    if cancel()
        || index.rows.len() >= LIMIT
        || index.rows.iter().any(|r| {
            r.phase != Phase::LocalQueued
                || r.queued.as_ref().is_none_or(|q| q.native.is_none())
                || r.descriptor.id().ok().as_deref() == Some(id.as_str())
        })
    {
        return Err(no());
    }
    verify_source()?;
    let snapshots = snapshots(scope, true)?;
    let mut reservation = if descriptor.source.kind == NamespaceObjectKind::File {
        Some(
            snapshots
                .try_begin_capture(SnapshotBinding {
                    record_id: String::new(),
                    scope: scope.streamed_storage_scope().map_err(|_| no())?,
                    generation: descriptor.owner.token_generation(),
                    local_file: raiun_cloudfiles_windows::LocalFileIdentity {
                        volume_serial: descriptor.source.volume,
                        file_index: descriptor.source.file,
                    },
                    relative_path: descriptor.source.components.join("/"),
                    remote: None,
                    content_len: descriptor.source.plaintext_len,
                })
                .map_err(|_| no())?,
        )
    } else {
        None
    };
    index.rows.push(Row {
        descriptor: stored.clone(),
        snapshot: reservation.as_ref().map(|r| r.binding().clone()),
        phase: Phase::Capturing,
        queued: None,
    });
    commit(&store, scope, old.as_deref().map(Vec::as_slice), &index)?;
    if let Some(reservation) = reservation.take() {
        let reader = source.ok_or_else(no)?;
        let stage = reservation
            .capture(reader, &mut || cancel())
            .map_err(|_| no())?;
        verify_source()?;
        let body = stage
            .verify_and_commit(&mut || cancel())
            .map_err(|_| no())?;
        if body.manifest().binding()
            != index
                .rows
                .last()
                .and_then(|r| r.snapshot.as_ref())
                .ok_or_else(no)?
            || Some(*body.manifest().content_sha256()) != descriptor.source.plaintext_sha256
        {
            return Err(no());
        }
    } else if source.is_some() {
        return Err(no());
    }
    if cancel() {
        return Err(no());
    }
    verify_source()?;
    let (old, mut ready) = load(&store, scope)?;
    let row = ready
        .rows
        .iter_mut()
        .find(|r| r.descriptor == stored)
        .ok_or_else(no)?;
    if row.phase != Phase::Capturing {
        return Err(no());
    }
    row.phase = Phase::Ready;
    commit(&store, scope, old.as_deref().map(Vec::as_slice), &ready)?;
    Ok(Arc::new(Record {
        store,
        scope: scope.clone(),
        descriptor: descriptor.clone(),
        stored,
        id,
    }))
}
pub(super) fn pending_native_facts(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<Vec<super::windows_vault_namespace_queued::PendingFacts>, BackendError> {
    verify_no_unresolved(store, scope)?;
    let (_, index) = load(store, scope)?;
    index
        .rows
        .iter()
        .map(|r| {
            r.queued
                .as_ref()
                .ok_or_else(no)?
                .pending_facts(r.descriptor.source.components.clone())
        })
        .collect()
}
pub(super) fn catalogue_updates(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<Vec<super::windows_vault_namespace_queued::CatalogueDelta>, BackendError> {
    Ok(pending_native_facts(store, scope)?
        .into_iter()
        .map(Into::into)
        .collect())
}
pub(super) fn has_local_queued(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<bool, BackendError> {
    let (_, index) = load(store, scope)?;
    Ok(index.rows.iter().any(|r| r.phase == Phase::LocalQueued))
}

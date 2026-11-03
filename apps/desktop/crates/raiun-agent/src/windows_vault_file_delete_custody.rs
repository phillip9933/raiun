//! Protected exact-object tombstones. Historical catalogues, captures and body
//! bindings are preserved; completion hides only the deleted current object.
use super::{
    vault_custody::{Entry, Hydration, Scope},
    windows_vault_custody::Storage,
};
use raiun_cloudfiles_windows::{
    BackendError, ConfiguredRootIdentity,
    vault_file_delete::{
        VaultFileDeleteDescriptor, VaultFileDeleteFacts, VaultFileDeleteNativeProof,
        VaultFileDeleteRecord, VaultFileDeleteRemoteProof,
    },
};
use raiun_control_windows::{DpapiSessionStore, PinnedDirectory, PrivateDirectory};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroizing;
const LIMIT: usize = 1024;
fn no() -> BackendError {
    BackendError::Unavailable
}
fn key(scope: &Scope) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    let s = scope.authenticated_store_binding().map_err(|_| no())?;
    let mut b = Zeroizing::new(b"raiun/windows-vault-file-delete/v1\0".to_vec());
    b.extend_from_slice(&(s.len() as u64).to_le_bytes());
    b.extend_from_slice(&s);
    Ok(b)
}
fn directory(scope: &Scope) -> Result<std::path::PathBuf, BackendError> {
    Ok(DpapiSessionStore::current_user()
        .map_err(|_| no())?
        .local_edit_state_directory()
        .join(format!(
            "vault-file-delete-v1-{:x}",
            Sha256::digest(&*key(scope)?)
        )))
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    scope: Scope,
    generation: u64,
    facts: VaultFileDeleteFacts,
}
impl Descriptor {
    fn from(scope: &Scope, d: &VaultFileDeleteDescriptor) -> Result<Self, BackendError> {
        d.validate()?;
        let a = scope.streamed_storage_scope().map_err(|_| no())?;
        if scope.native_root() != (d.root.volume_serial, d.root.file_index)
            || d.remote_root != scope.remote_root()
            || d.owner.profile_id() != a.profile_id
            || d.owner.account_id() != a.account_subject
            || d.owner.server_origin() != a.server_origin
            || d.vault.space_id() != a.space_id
            || d.vault.resource_id() != a.root_resource_id
        {
            return Err(no());
        }
        Ok(Self {
            scope: scope.clone(),
            generation: d.owner.token_generation(),
            facts: d.facts(),
        })
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
            return Err(no());
        }
        Ok(())
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Ready,
    Attempted,
    RemoteVerified,
    NativeCompleted,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    descriptor: Descriptor,
    phase: Phase,
    parent_usn_after: Option<i64>,
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
    let raw = store.load(&key(scope)?).map_err(|_| no())?;
    let i = if let Some(raw) = &raw {
        if raw.is_empty() || raw.len() > 16 << 20 {
            return Err(no());
        }
        let i: Index = serde_json::from_slice(raw).map_err(|_| no())?;
        if i.version != 1 || i.scope != *scope || i.rows.is_empty() || i.rows.len() > LIMIT {
            return Err(no());
        }
        let mut objects = std::collections::BTreeSet::new();
        for r in &i.rows {
            r.descriptor.validate(scope)?;
            if !objects.insert(r.descriptor.facts.original_identity)
                || (r.phase == Phase::NativeCompleted) != r.parent_usn_after.is_some()
                || r.parent_usn_after.is_some_and(|v| v <= 0)
            {
                return Err(no());
            }
        }
        i
    } else {
        match std::fs::symlink_metadata(directory(scope)?) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err(no()),
        }
        Index {
            version: 1,
            scope: scope.clone(),
            rows: vec![],
        }
    };
    Ok((raw, i))
}
fn commit(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    old: Option<&[u8]>,
    i: &Index,
) -> Result<(), BackendError> {
    let raw = Zeroizing::new(serde_json::to_vec(i).map_err(|_| no())?);
    if raw.len() > 16 << 20 || i.rows.len() > LIMIT {
        return Err(no());
    }
    store.cas(&key(scope)?, old, &raw).map_err(|_| no())?;
    if store
        .load(&key(scope)?)
        .map_err(|_| no())?
        .is_none_or(|v| v.as_slice() != raw.as_slice())
    {
        return Err(no());
    }
    Ok(())
}
struct Record {
    store: Arc<dyn Storage>,
    scope: Scope,
    descriptor: VaultFileDeleteDescriptor,
    stored: Descriptor,
    claimed: AtomicBool,
    serial: Mutex<()>,
}
impl Record {
    fn transition(&self, from: Phase, to: Phase, after: Option<i64>) -> Result<(), BackendError> {
        let _serial = self.serial.lock().map_err(|_| no())?;
        let (raw, mut i) = load(&self.store, &self.scope)?;
        let row = i
            .rows
            .iter_mut()
            .find(|r| r.descriptor == self.stored)
            .ok_or_else(no)?;
        if row.phase != from {
            return Err(no());
        }
        row.phase = to;
        row.parent_usn_after = after;
        commit(
            &self.store,
            &self.scope,
            raw.as_deref().map(Vec::as_slice),
            &i,
        )
    }
}
impl VaultFileDeleteRecord for Record {
    fn descriptor(&self) -> &VaultFileDeleteDescriptor {
        &self.descriptor
    }
    fn claim_send(&self) -> Result<(), BackendError> {
        if self.claimed.swap(true, Ordering::AcqRel) {
            return Err(no());
        }
        self.transition(Phase::Ready, Phase::Attempted, None)
    }
    fn record_remote(&self, p: &VaultFileDeleteRemoteProof) -> Result<(), BackendError> {
        let v = p.verified();
        let f = &self.stored.facts;
        if Descriptor::from(&self.scope, p.descriptor())? != self.stored
            || v.original().id != f.original.id
            || v.original().path != f.original.path
            || v.original().etag != f.original.etag
            || v.original().size != f.original.size
            || v.original().directory
            || v.parent().id != f.parent.id
            || v.parent().path != f.parent.path
            || v.parent().etag != f.parent.etag
            || v.scope() != &self.descriptor.vault
            || v.root_path() != self.descriptor.remote_root
            || v.token_generation() != self.stored.generation
        {
            return Err(no());
        }
        self.transition(Phase::Attempted, Phase::RemoteVerified, None)
    }
    fn record_native_completed(&self, p: &VaultFileDeleteNativeProof) -> Result<(), BackendError> {
        if Descriptor::from(&self.scope, p.descriptor())? != self.stored
            || p.parent_usn_after() <= 0
        {
            return Err(no());
        }
        self.transition(
            Phase::RemoteVerified,
            Phase::NativeCompleted,
            Some(p.parent_usn_after()),
        )
    }
}
pub(super) fn begin(
    store: Arc<dyn Storage>,
    scope: &Scope,
    d: &VaultFileDeleteDescriptor,
) -> Result<Arc<dyn VaultFileDeleteRecord>, BackendError> {
    let stored = Descriptor::from(scope, d)?;
    let (raw, mut i) = load(&store, scope)?;
    if i.rows.len() >= LIMIT
        || i.rows.iter().any(|r| {
            r.phase != Phase::NativeCompleted
                || r.descriptor.facts.original_identity == d.original_identity
        })
    {
        return Err(no());
    }
    let storage = DpapiSessionStore::current_user().map_err(|_| no())?;
    let parent = PinnedDirectory::open(storage.local_edit_state_directory()).map_err(|_| no())?;
    let path = directory(scope)?;
    let _sentinel =
        PrivateDirectory::create_or_open_under(&parent, path.file_name().ok_or_else(no)?)
            .map_err(|_| no())?;
    i.rows.push(Row {
        descriptor: stored.clone(),
        phase: Phase::Ready,
        parent_usn_after: None,
    });
    commit(&store, scope, raw.as_deref().map(Vec::as_slice), &i)?;
    Ok(Arc::new(Record {
        store,
        scope: scope.clone(),
        descriptor: d.clone(),
        stored,
        claimed: AtomicBool::new(false),
        serial: Mutex::new(()),
    }))
}
pub(super) fn verify_no_unresolved(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<(), BackendError> {
    let (_, i) = load(store, scope)?;
    if i.rows.iter().any(|r| r.phase != Phase::NativeCompleted) {
        return Err(no());
    }
    Ok(())
}
pub(super) fn entry_deleted(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    e: &Entry,
) -> Result<bool, BackendError> {
    let (_, i) = load(store, scope)?;
    Ok(i.rows.iter().any(|r| {
        r.phase == Phase::NativeCompleted && {
            let f = &r.descriptor.facts;
            e.opaque() == f.original_identity
                && e.remote_id() == f.original.id
                && e.root_relative_path() == f.original.path
                && e.etag() == f.original.etag
                && e.length() == f.original.size
                && !e.is_directory()
        }
    }))
}
pub(super) fn hydration_deleted(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    h: &Hydration,
) -> Result<bool, BackendError> {
    let (_, i) = load(store, scope)?;
    Ok(i.rows.iter().any(|r| {
        r.phase == Phase::NativeCompleted && {
            let f = &r.descriptor.facts;
            h.opaque() == f.original_identity
                && h.file_index() == f.original_file.file_index
                && h.length() == f.original.size
                && h.components() == f.components
        }
    }))
}

pub(super) fn intent_deleted(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    identity: [u8; 16],
    file: u64,
    len: u64,
    components: &[String],
) -> Result<bool, BackendError> {
    let (_, i) = load(store, scope)?;
    Ok(i.rows.iter().any(|r| {
        r.phase == Phase::NativeCompleted && {
            let f = &r.descriptor.facts;
            identity == f.original_identity
                && file == f.original_file.file_index
                && len == f.original.size
                && components == f.components
        }
    }))
}

//! One-attempt DPAPI vault rename ledger. Discovery projects only completed facts.
use super::{vault_custody::Scope, windows_vault_custody::Storage};
use raiun_cloudfiles_windows::{
    BackendError, ConfiguredRootIdentity, VaultFileRenameDescriptor, VaultFileRenameFacts,
    VaultFileRenameRecord,
};
use raiun_control_windows::{DpapiSessionStore, PinnedDirectory, PrivateDirectory};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use zeroize::Zeroizing;
fn no() -> BackendError {
    BackendError::Unavailable
}
const DOMAIN: &[u8] = b"raiun/windows-vault-file-rename/v1\0";
fn key(scope: &Scope) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    let s = scope.authenticated_store_binding().map_err(|_| no())?;
    let mut k = Zeroizing::new(DOMAIN.to_vec());
    k.extend_from_slice(&(s.len() as u64).to_le_bytes());
    k.extend_from_slice(&s);
    Ok(k)
}
fn directory(scope: &Scope) -> Result<PathBuf, BackendError> {
    Ok(DpapiSessionStore::current_user()
        .map_err(|_| no())?
        .local_edit_state_directory()
        .join(format!(
            "vault-file-rename-v1-{:x}",
            Sha256::digest(&*key(scope)?)
        )))
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    facts: VaultFileRenameFacts,
    phase: Phase,
    native_usn: Option<i64>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    Ready,
    Attempted,
    RemoteVerified,
    NativeCompleted,
}
#[derive(Clone, Serialize, Deserialize)]
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
    let index = if let Some(raw) = &raw {
        if raw.is_empty() || raw.len() > 16 << 20 {
            return Err(no());
        }
        let i: Index = serde_json::from_slice(raw).map_err(|_| no())?;
        if i.version != 1 || i.scope != *scope || i.rows.is_empty() || i.rows.len() > 1024 {
            return Err(no());
        }
        let (v, f) = scope.native_root();
        let mut ids = std::collections::BTreeSet::new();
        for r in &i.rows {
            r.facts.validate(ConfiguredRootIdentity {
                volume_serial: v,
                file_index: f,
            })?;
            if r.facts.original.id
                == scope
                    .streamed_storage_scope()
                    .map_err(|_| no())?
                    .root_resource_id
                || !ids.insert(serde_json::to_vec(&r.facts).map_err(|_| no())?)
                || (r.phase == Phase::NativeCompleted) != r.native_usn.is_some()
                || r.native_usn.is_some_and(|u| u <= 0)
            {
                return Err(no());
            }
        }
        let mut tails = std::collections::BTreeMap::<[u8; 16], &VaultFileRenameFacts>::new();
        for row in &i.rows {
            let f = &row.facts;
            if let Some(previous) = tails.insert(f.identity, f) {
                if previous.original.id != f.original.id
                    || previous.file != f.file
                    || previous.volume != f.volume
                    || previous.parent_file != f.parent_file
                    || previous.parent_identity != f.parent_identity
                    || previous.parent.id != f.parent.id
                    || previous.destination != f.original.path
                    || previous.new_components != f.old_components
                {
                    return Err(no());
                }
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
    Ok((raw, index))
}
fn commit(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    old: Option<&[u8]>,
    index: &Index,
) -> Result<(), BackendError> {
    let raw = Zeroizing::new(serde_json::to_vec(index).map_err(|_| no())?);
    if raw.len() > 16 << 20 || index.rows.len() > 1024 {
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
    facts: VaultFileRenameFacts,
    claim: AtomicBool,
    serial: Mutex<()>,
    refresh: Arc<dyn Fn() -> Result<(), BackendError> + Send + Sync>,
}
impl Record {
    fn transition(&self, from: Phase, to: Phase, usn: Option<i64>) -> Result<(), BackendError> {
        let _serial = self.serial.lock().map_err(|_| no())?;
        let (old, mut i) = load(&self.store, &self.scope)?;
        let row = i
            .rows
            .iter_mut()
            .find(|r| r.facts == self.facts)
            .ok_or_else(no)?;
        if row.phase != from {
            return Err(no());
        }
        row.phase = to;
        row.native_usn = usn;
        commit(
            &self.store,
            &self.scope,
            old.as_ref().map(|v| v.as_slice()),
            &i,
        )
    }
}
impl VaultFileRenameRecord for Record {
    fn claim_send(&self) -> Result<(), BackendError> {
        if self.claim.swap(true, Ordering::AcqRel) {
            return Err(no());
        }
        self.transition(Phase::Ready, Phase::Attempted, None)
    }
    fn record_remote(
        &self,
        p: &raiun_opencloud::vault_backend::VaultVerifiedFileRename,
    ) -> Result<(), BackendError> {
        let f = &self.facts;
        if p.original().id != f.original.id
            || p.original().path != f.original.path
            || p.original().etag != f.original.etag
            || p.entry().id != f.original.id
            || p.entry().etag != f.original.etag
            || p.entry().size != f.original.size
            || p.entry().path != f.destination
            || p.entry().directory
            || p.parent().id != f.parent.id
        {
            return Err(no());
        }
        self.transition(Phase::Attempted, Phase::RemoteVerified, None)
    }
    fn record_native(&self, file: u64, usn: i64) -> Result<(), BackendError> {
        if file != self.facts.file || usn <= 0 {
            return Err(no());
        }
        self.transition(Phase::RemoteVerified, Phase::NativeCompleted, Some(usn))?;
        (self.refresh)()
    }
}
pub(super) fn prepare(
    store: Arc<dyn Storage>,
    scope: &Scope,
    d: &VaultFileRenameDescriptor,
    refresh: Arc<dyn Fn() -> Result<(), BackendError> + Send + Sync>,
) -> Result<Arc<dyn VaultFileRenameRecord>, BackendError> {
    d.validate()?;
    let s = scope.streamed_storage_scope().map_err(|_| no())?;
    if scope.native_root() != (d.root.volume_serial, d.root.file_index)
        || s.profile_id != d.owner.profile_id()
        || s.account_subject != d.owner.account_id()
        || s.server_origin != d.owner.server_origin()
        || s.space_id != d.vault.space_id()
        || s.root_resource_id != d.vault.resource_id()
    {
        return Err(no());
    }
    let (old, mut i) = load(&store, scope)?;
    if i.rows
        .iter()
        .any(|r| r.phase != Phase::NativeCompleted || r.facts == d.facts)
    {
        return Err(no());
    }
    // A missing index beside this sentinel is never initialized/adopted later.
    let storage = DpapiSessionStore::current_user().map_err(|_| no())?;
    let parent = PinnedDirectory::open(storage.local_edit_state_directory()).map_err(|_| no())?;
    let path = directory(scope)?;
    let _sentinel =
        PrivateDirectory::create_or_open_under(&parent, path.file_name().ok_or_else(no)?)
            .map_err(|_| no())?;
    i.rows.push(Row {
        facts: d.facts.clone(),
        phase: Phase::Ready,
        native_usn: None,
    });
    commit(&store, scope, old.as_ref().map(|v| v.as_slice()), &i)?;
    Ok(Arc::new(Record {
        store,
        scope: scope.clone(),
        facts: d.facts.clone(),
        claim: AtomicBool::new(false),
        serial: Mutex::new(()),
        refresh,
    }))
}
fn completed(store: &Arc<dyn Storage>, scope: &Scope) -> Result<Vec<Row>, BackendError> {
    let (_, i) = load(store, scope)?;
    if i.rows.iter().any(|r| r.phase != Phase::NativeCompleted) {
        return Err(no());
    }
    Ok(i.rows)
}
/// Pure historical location mapping under authenticated scoped completed rows.
/// Nonmatching revisions remain untouched; a receipt never changes ID/EF/size.
pub(super) fn entry(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    value: &super::vault_custody::Entry,
) -> Result<super::vault_custody::Entry, BackendError> {
    let mut next = value.clone();
    for r in completed(store, scope)? {
        let f = r.facts;
        if next.opaque() == f.identity
            && next.remote_id() == f.original.id
            && next.etag() == f.original.etag
            && next.length() == f.original.size
            && next.root_relative_path() == f.original.path
        {
            next = super::vault_custody::Entry::new(
                next.opaque(),
                next.remote_id(),
                &f.destination,
                next.etag(),
                false,
                next.length(),
            )
            .map_err(|_| no())?;
        }
    }
    Ok(next)
}
pub(super) fn hydration(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    value: &super::vault_custody::Hydration,
) -> Result<super::vault_custody::Hydration, BackendError> {
    let mut next = value.clone();
    for r in completed(store, scope)? {
        let f = r.facts;
        if next.opaque() == f.identity
            && next.file_index() == f.file
            && next.length() == f.original.size
            && next.components() == f.old_components
        {
            next = next.with_rename_components(f.new_components);
        }
    }
    Ok(next)
}

/// Even an empty legacy catalogue must not hide unfinished location evidence.
pub(super) fn verify_no_unresolved(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<(), BackendError> {
    completed(store, scope).map(|_| ())
}

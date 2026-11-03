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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_children: Option<Vec<(u64, i64)>>,
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
        let mut tails = std::collections::BTreeMap::<[u8; 16], Event>::new();
        for row in &i.rows {
            for event in events(&row.facts)? {
                if let Some(p) = tails.insert(event.identity, event.clone()) {
                    if p.id != event.id
                        || (p.file != event.file
                            && !store
                                .completed_file_lineage(
                                    scope,
                                    event.identity,
                                    &event.id,
                                    p.file,
                                    event.file,
                                )
                                .map_err(|_| no())?)
                        || p.new_path != event.original.path
                        || p.new_components != event.old_components
                        || p.destination_parent != event.source_parent
                        || p.destination_parent_file != event.source_parent_file
                        || p.destination_parent_id != event.source_parent_id
                    {
                        return Err(no());
                    }
                }
            }
            let children = row.facts.children.as_ref();
            if row.phase == Phase::NativeCompleted && children.is_some() {
                let proof = row.native_children.as_ref().ok_or_else(no)?;
                if proof.len() != children.unwrap().len()
                    || children.unwrap().iter().any(|n| {
                        proof
                            .iter()
                            .filter(|(file, usn)| n.file == *file && n.usn == *usn)
                            .count()
                            != 1
                    })
                    || row.native_usn != Some(row.facts.usn)
                {
                    return Err(no());
                }
            } else if row.native_children.is_some() {
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
    fn transition(
        &self,
        from: Phase,
        to: Phase,
        usn: Option<i64>,
        children: Option<Vec<(u64, i64)>>,
    ) -> Result<(), BackendError> {
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
        row.native_children = children;
        commit(
            &self.store,
            &self.scope,
            old.as_ref().map(|v| v.as_slice()),
            &i,
        )
    }
}
impl VaultFileRenameRecord for Record {
    fn record_directory_remote(
        &self,
        p: &raiun_opencloud::vault_backend::VaultVerifiedDirectoryRename,
    ) -> Result<(), BackendError> {
        if self.facts.children.is_none() {
            return Err(no());
        }
        let root = p.root_proof();
        let f = &self.facts;
        if root.parent().id != f.parent.id
            || root.parent().path != f.parent.path
            || root.parent().etag != f.parent.etag
            || root.destination_parent().id
                != f.destination_parent
                    .as_ref()
                    .map(|p| p.parent.id.as_str())
                    .unwrap_or(&f.parent.id)
            || root.destination_parent().etag
                != f.destination_parent
                    .as_ref()
                    .map(|p| p.parent.etag.as_str())
                    .unwrap_or(&f.parent.etag)
        {
            return Err(no());
        }

        let e = events(&self.facts)?;
        if e.len() != p.original_tree().len() || e.len() != p.entries().len() {
            return Err(no());
        }
        for n in &e {
            if !p.original_tree().iter().any(|v| {
                v.id == n.id
                    && v.path == n.original.path
                    && v.etag == n.original.etag
                    && v.size == n.original.size
                    && v.directory == n.original.directory
            }) || !p.entries().iter().any(|v| {
                v.id == n.id
                    && v.path == n.new_path
                    && (v.directory || v.etag == n.original.etag)
                    && v.size == n.original.size
                    && v.directory == n.original.directory
            }) {
                return Err(no());
            }
        }
        self.transition(Phase::Attempted, Phase::RemoteVerified, None, None)
    }
    fn record_directory_native(&self, nodes: &[(u64, i64)]) -> Result<(), BackendError> {
        let children = self.facts.children.as_ref().ok_or_else(no)?;
        if nodes.len() != children.len() + 1
            || nodes
                .iter()
                .filter(|(f, u)| *f == self.facts.file && *u == self.facts.usn)
                .count()
                != 1
            || children.iter().any(|n| {
                nodes
                    .iter()
                    .filter(|(f, u)| *f == n.file && *u == n.usn)
                    .count()
                    != 1
            })
        {
            return Err(no());
        }
        let children = nodes
            .iter()
            .copied()
            .filter(|(f, _)| *f != self.facts.file)
            .collect();
        self.transition(
            Phase::RemoteVerified,
            Phase::NativeCompleted,
            Some(self.facts.usn),
            Some(children),
        )?;
        (self.refresh)()
    }

    fn claim_send(&self) -> Result<(), BackendError> {
        if self.claim.swap(true, Ordering::AcqRel) {
            return Err(no());
        }
        self.transition(Phase::Ready, Phase::Attempted, None, None)
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
            || p.parent().path != f.parent.path
            || p.parent().etag != f.parent.etag
            || p.destination_parent().id
                != f.destination_parent
                    .as_ref()
                    .map(|p| p.parent.id.as_str())
                    .unwrap_or(&f.parent.id)
        {
            return Err(no());
        }
        self.transition(Phase::Attempted, Phase::RemoteVerified, None, None)
    }
    fn record_native(&self, file: u64, usn: i64) -> Result<(), BackendError> {
        if self.facts.children.is_some() || file != self.facts.file || usn <= 0 {
            return Err(no());
        }
        self.transition(
            Phase::RemoteVerified,
            Phase::NativeCompleted,
            Some(usn),
            None,
        )?;
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
        native_children: None,
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

#[derive(Clone)]
struct Event {
    identity: [u8; 16],
    id: String,
    file: u64,
    original: raiun_core::backend::RemoteEntry,
    new_path: String,
    old_components: Vec<String>,
    new_components: Vec<String>,
    source_parent: [u8; 16],
    source_parent_file: u64,
    source_parent_id: String,
    destination_parent: [u8; 16],
    destination_parent_file: u64,
    destination_parent_id: String,
}
fn events(f: &VaultFileRenameFacts) -> Result<Vec<Event>, BackendError> {
    let destination_parent = f.destination_parent.as_ref();
    let mut rows = vec![Event {
        identity: f.identity,
        id: f.original.id.clone(),
        file: f.file,
        original: f.original.clone(),
        new_path: f.destination.clone(),
        old_components: f.old_components.clone(),
        new_components: f.new_components.clone(),
        source_parent: f.parent_identity,
        source_parent_file: f.parent_file,
        source_parent_id: f.parent.id.clone(),
        destination_parent: destination_parent
            .map(|p| p.identity)
            .unwrap_or(f.parent_identity),
        destination_parent_file: destination_parent.map(|p| p.file).unwrap_or(f.parent_file),
        destination_parent_id: destination_parent
            .map(|p| p.parent.id.clone())
            .unwrap_or_else(|| f.parent.id.clone()),
    }];
    if let Some(children) = &f.children {
        for n in children {
            let suffix = n
                .original
                .path
                .strip_prefix(&format!("{}/", f.original.path))
                .ok_or_else(no)?;
            let mut old = f.old_components.clone();
            old.extend(suffix.split('/').map(str::to_owned));
            let parent_path = n
                .original
                .path
                .rsplit_once('/')
                .map(|(p, _)| p)
                .ok_or_else(no)?;
            let (parent_identity, parent_file, parent_id) = if parent_path == f.original.path {
                (f.identity, f.file, f.original.id.clone())
            } else {
                let p = children
                    .iter()
                    .find(|p| p.original.directory && p.original.path == parent_path)
                    .ok_or_else(no)?;
                (p.identity, p.file, p.original.id.clone())
            };
            rows.push(Event {
                identity: n.identity,
                id: n.original.id.clone(),
                file: n.file,
                original: n.original.clone(),
                new_path: format!("{}/{suffix}", f.destination),
                old_components: old,
                new_components: n.new_components.clone(),
                source_parent: parent_identity,
                source_parent_file: parent_file,
                source_parent_id: parent_id.clone(),
                destination_parent: parent_identity,
                destination_parent_file: parent_file,
                destination_parent_id: parent_id,
            });
        }
    }
    Ok(rows)
}
/// Only exact independently recorded nodes translate. IDs, revisions, kinds,
/// lengths and immutable frame/body bindings never change through this mapper.
pub(super) fn entry(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    value: &super::vault_custody::Entry,
) -> Result<super::vault_custody::Entry, BackendError> {
    let mut next = value.clone();
    for r in completed(store, scope)? {
        for e in events(&r.facts)? {
            if next.opaque() == e.identity
                && next.remote_id() == e.id
                && (next.is_directory() || next.etag() == e.original.etag)
                && next.length() == e.original.size
                && next.is_directory() == e.original.directory
                && next.root_relative_path() == e.original.path
            {
                next = super::vault_custody::Entry::new(
                    next.opaque(),
                    next.remote_id(),
                    &e.new_path,
                    next.etag(),
                    next.is_directory(),
                    next.length(),
                )
                .map_err(|_| no())?;
            }
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
        for e in events(&r.facts)?
            .into_iter()
            .filter(|e| !e.original.directory)
        {
            if next.opaque() == e.identity
                && next.file_index() == e.file
                && next.length() == e.original.size
                && next.components() == e.old_components
            {
                next = next.with_rename_components(e.new_components);
            }
        }
    }
    Ok(next)
}
/// Even an empty legacy catalogue cannot hide unfinished location evidence.
pub(super) fn verify_no_unresolved(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<(), BackendError> {
    completed(store, scope).map(|_| ())
}

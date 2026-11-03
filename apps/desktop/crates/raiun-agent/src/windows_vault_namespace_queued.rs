//! Persisted local journal facts. These values never prove remote sync, grant
//! dispatch, restore an epoch or qualify native cleanup.
use raiun_cloudfiles_windows::{
    BackendError, VaultCachedNamespaceOperation as Operation, VaultCachedNamespaceQueued,
};
use raiun_core::backend::RemoteEntry;
use serde::{Deserialize, Serialize};
fn no() -> BackendError {
    BackendError::Unavailable
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Native {
    pub identity: [u8; 16],
    pub file: u64,
    pub usn: i64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Queued {
    pub operation: Operation,
    pub write_id: String,
    pub revision: u64,
    pub original: Option<RemoteEntry>,
    pub parent: RemoteEntry,
    pub entry: Option<RemoteEntry>,
    pub source_sha256: Option<[u8; 32]>,
    pub plaintext_len: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native: Option<Native>,
}
impl Queued {
    pub fn from(receipt: &VaultCachedNamespaceQueued) -> Result<Self, BackendError> {
        let q = Self {
            operation: receipt.operation(),
            write_id: receipt.write_id().into(),
            revision: receipt.revision(),
            original: receipt.original().cloned(),
            parent: receipt.parent().clone(),
            entry: receipt.entry().cloned(),
            source_sha256: receipt.source_sha256(),
            plaintext_len: receipt.plaintext_len(),
            native: None,
        };
        q.validate()?;
        Ok(q)
    }
    pub fn validate(&self) -> Result<(), BackendError> {
        let bounded =
            |s: &str, n: usize| !s.is_empty() && s.len() <= n && !s.chars().any(char::is_control);
        let entry = |e: &RemoteEntry| {
            bounded(&e.id, 4096)
                && bounded(&e.etag, 4096)
                && e.path.len() <= 32000
                && raiun_core::validate_remote_path(&e.path).is_ok()
        };
        if !bounded(&self.write_id, 512)
            || self.revision == 0
            || self.plaintext_len > 1 << 30
            || !self.parent.directory
            || !entry(&self.parent)
            || self.source_sha256 == Some([0; 32])
            || self
                .native
                .as_ref()
                .is_some_and(|n| n.identity == [0; 16] || n.file == 0 || n.usn <= 0)
        {
            return Err(no());
        }
        if let Some(original) = &self.original {
            if !entry(original) {
                return Err(no());
            }
        }
        let delete = self.operation == Operation::DeleteFile;
        if delete != self.entry.is_none() {
            return Err(no());
        }
        if let Some(e) = &self.entry {
            if !entry(e)
                || e.path == "/"
                || e.etag != format!("raiun-pending-v1:{}:{}", self.write_id, self.revision)
                || e.size != self.plaintext_len
            {
                return Err(no());
            }
            match self.operation {
                Operation::CreateFile => {
                    if e.directory
                        || e.id != format!("raiun-pending-create:{}", self.write_id)
                        || self.original.is_some()
                        || self.source_sha256.is_none()
                    {
                        return Err(no());
                    }
                }
                Operation::CreateDirectory => {
                    if !e.directory
                        || e.id != format!("raiun-pending-directory:{}", self.write_id)
                        || self.original.is_some()
                        || self.source_sha256.is_some()
                        || self.plaintext_len != 0
                    {
                        return Err(no());
                    }
                }
                Operation::RenameFile => {
                    if e.directory
                        || self
                            .original
                            .as_ref()
                            .is_none_or(|o| o.directory || o.id != e.id || o.size != e.size)
                    {
                        return Err(no());
                    }
                }
                Operation::RetargetNeverAttemptedFile => {
                    if e.directory
                        || !e.id.starts_with("raiun-pending-create:")
                        || self
                            .original
                            .as_ref()
                            .is_none_or(|o| o.directory || o.id != e.id || o.size != e.size)
                    {
                        return Err(no());
                    }
                }
                Operation::RetargetNeverAttemptedDirectory => {
                    if !e.directory
                        || !e.id.starts_with("raiun-pending-directory:")
                        || self
                            .original
                            .as_ref()
                            .is_none_or(|o| !o.directory || o.id != e.id || o.size != 0)
                        || e.size != 0
                        || self.plaintext_len != 0
                    {
                        return Err(no());
                    }
                }
                Operation::DeleteFile => return Err(no()),
            }
        } else if self
            .original
            .as_ref()
            .is_none_or(|e| e.directory || e.size != self.plaintext_len)
        {
            return Err(no());
        }
        Ok(())
    }
    pub fn matches_receipt(&self, r: &VaultCachedNamespaceQueued) -> Result<bool, BackendError> {
        let mut q = self.clone();
        q.native = None;
        Ok(q == Self::from(r)?)
    }
    pub fn record_native(
        &mut self,
        identity: [u8; 16],
        file: u64,
        usn: i64,
    ) -> Result<(), BackendError> {
        if self.native.is_some() || identity == [0; 16] || file == 0 || usn <= 0 {
            return Err(no());
        }
        self.native = Some(Native {
            identity,
            file,
            usn,
        });
        self.validate()
    }
}
#[derive(Clone)]
pub(super) struct PendingFacts {
    pub operation: Operation,
    pub write_id: String,
    pub revision: u64,
    pub original: Option<RemoteEntry>,
    pub parent: RemoteEntry,
    pub entry: Option<RemoteEntry>,
    pub identity: [u8; 16],
    pub file: u64,
    pub usn: i64,
    pub components: Vec<String>,
    pub plaintext_len: u64,
    pub source_sha256: Option<[u8; 32]>,
}
impl Queued {
    pub fn pending_facts(&self, components: Vec<String>) -> Result<PendingFacts, BackendError> {
        self.validate()?;
        let n = self.native.as_ref().ok_or_else(no)?;
        Ok(PendingFacts {
            operation: self.operation,
            write_id: self.write_id.clone(),
            revision: self.revision,
            original: self.original.clone(),
            parent: self.parent.clone(),
            entry: self.entry.clone(),
            identity: n.identity,
            file: n.file,
            usn: n.usn,
            components,
            plaintext_len: self.plaintext_len,
            source_sha256: self.source_sha256,
        })
    }
}

use super::{vault_custody::Scope, windows_vault_custody::Storage};
use raiun_cloudfiles_windows::{VaultCachedNamespaceDescriptor, VaultCachedRetargetDescriptor};
use raiun_control_windows::{DpapiSessionStore, PinnedDirectory, PrivateDirectory};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use zeroize::Zeroizing;
const RETARGET_DOMAIN: &[u8] = b"raiun/windows-vault-cached-retarget/v1\0";
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Retarget {
    scope: Scope,
    generation: u64,
    historical_epoch: u64,
    identity: [u8; 16],
    original: RemoteEntry,
    parent_identity: [u8; 16],
    parent: RemoteEntry,
    destination_parent_identity: [u8; 16],
    destination_parent: RemoteEntry,
    file: u64,
    usn: i64,
    parent_file: u64,
    parent_usn: i64,
    destination_parent_file: u64,
    destination_parent_usn: i64,
    old_components: Vec<String>,
    new_components: Vec<String>,
}
impl Retarget {
    fn from(scope: &Scope, d: &VaultCachedRetargetDescriptor) -> Result<Self, BackendError> {
        d.validate()?;
        let s = scope.streamed_storage_scope().map_err(|_| no())?;
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
        let f = Self {
            scope: scope.clone(),
            generation: d.owner.token_generation(),
            historical_epoch: d.historical_unlock_epoch,
            identity: d.identity,
            original: d.original.clone(),
            parent_identity: d.parent_identity,
            parent: d.parent.clone(),
            destination_parent_identity: d.destination_parent_identity,
            destination_parent: d.destination_parent.clone(),
            file: d.original_file.file_index,
            usn: d.original_usn,
            parent_file: d.parent_file.file_index,
            parent_usn: d.parent_usn,
            destination_parent_file: d.destination_parent_file.file_index,
            destination_parent_usn: d.destination_parent_usn,
            old_components: d.old_components.clone(),
            new_components: d.new_components.clone(),
        };
        f.validate(scope)?;
        Ok(f)
    }
    fn validate(&self, scope: &Scope) -> Result<(), BackendError> {
        let components = |c: &Vec<String>| {
            c.len() >= 2
                && c.len() <= 256
                && c.iter().map(String::len).sum::<usize>() <= 32000
                && c.iter().all(|s| {
                    !s.is_empty()
                        && s.len() <= 255
                        && !s.chars().any(|c| {
                            c.is_control()
                                || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
                        })
                        && s != "."
                        && s != ".."
                })
        };
        let entry = |e: &RemoteEntry| {
            !e.id.is_empty()
                && e.id.len() <= 4096
                && !e.etag.is_empty()
                && e.etag.len() <= 4096
                && e.path.len() <= 32000
                && raiun_core::validate_remote_path(&e.path).is_ok()
        };
        if self.scope != *scope
            || self.generation == 0
            || self.historical_epoch == 0
            || self.identity == [0; 16]
            || self.parent_identity == [0; 16]
            || self.destination_parent_identity == [0; 16]
            || self.file == 0
            || self.parent_file == 0
            || self.destination_parent_file == 0
            || self.file == self.parent_file
            || self.file == self.destination_parent_file
            || self.usn <= 0
            || self.parent_usn <= 0
            || self.destination_parent_usn <= 0
            || !components(&self.old_components)
            || !components(&self.new_components)
            || self.old_components == self.new_components
            || !entry(&self.original)
            || !entry(&self.parent)
            || !entry(&self.destination_parent)
            || !self.parent.directory
            || !self.destination_parent.directory
            || (self.original.directory && self.original.size != 0)
            || self.original.path
                != format!(
                    "{}/{}",
                    self.parent.path.trim_end_matches('/'),
                    self.old_components.last().ok_or_else(no)?
                )
            || self.original.path == self.destination_parent.path
        {
            return Err(no());
        }
        let prefix = if self.original.directory {
            "raiun-pending-directory:"
        } else {
            "raiun-pending-create:"
        };
        let id = self.original.id.strip_prefix(prefix).ok_or_else(no)?;
        if id.is_empty()
            || !self
                .original
                .etag
                .starts_with(&format!("raiun-pending-v1:{id}:"))
        {
            return Err(no());
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum ParentRef {
    Stable { resource_id: String },
    PendingCreate { write_id: String, revision: u64 },
}
impl ParentRef {
    fn from(p: &raiun_opencloud::vault_cache::VaultPendingParentRef) -> Self {
        match p {
            raiun_opencloud::vault_cache::VaultPendingParentRef::Stable { resource_id } => {
                Self::Stable {
                    resource_id: resource_id.clone(),
                }
            }
            raiun_opencloud::vault_cache::VaultPendingParentRef::PendingCreate {
                write_id,
                revision,
            } => Self::PendingCreate {
                write_id: write_id.clone(),
                revision: *revision,
            },
        }
    }
    fn validate(&self) -> Result<(), BackendError> {
        let bounded =
            |s: &str| !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control);
        if match self {
            Self::Stable { resource_id } => !bounded(resource_id),
            Self::PendingCreate { write_id, revision } => !bounded(write_id) || *revision == 0,
        } {
            return Err(no());
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalRow {
    write_id: String,
    previous_revision: u64,
    revision: u64,
    directory: bool,
    old_path: String,
    path: String,
    old_encoded_target: String,
    encoded_target: String,
    old_parent_ref: ParentRef,
    parent_ref: ParentRef,
    plaintext_len: u64,
    plaintext_sha256: String,
}
impl JournalRow {
    fn from(r: &raiun_opencloud::vault_cache::VaultPendingDirectorySubtreeRetargetRow) -> Self {
        Self {
            write_id: r.write_id.clone(),
            previous_revision: r.previous_revision,
            revision: r.revision,
            directory: r.operation
                == raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateDirectory,
            old_path: r.old_path.clone(),
            path: r.path.clone(),
            old_encoded_target: r.old_encoded_target.clone(),
            encoded_target: r.encoded_target.clone(),
            old_parent_ref: ParentRef::from(&r.old_parent_ref),
            parent_ref: ParentRef::from(&r.parent_ref),
            plaintext_len: r.plaintext_len,
            plaintext_sha256: r.plaintext_sha256.clone(),
        }
    }
    fn validate(&self, n: &RetargetNode) -> Result<(), BackendError> {
        self.old_parent_ref.validate()?;
        self.parent_ref.validate()?;
        // Encrypted DAV targets are relative paths. The plaintext remote-path
        // validator requires a leading slash and would reject every target.
        let target = |p: &str| {
            !p.is_empty()
                && p.len() <= 32000
                && !p.starts_with('/')
                && !p.contains('\\')
                && !p.chars().any(char::is_control)
                && p.split('/').all(|s| !s.is_empty() && s != "." && s != "..")
        };
        if self.write_id != n.write_id
            || self.previous_revision != n.previous_revision
            || self.revision != n.revision
            || self.directory != n.original.directory
            || self.old_path != n.original.path
            || self.path != n.entry.path
            || self.plaintext_len != n.original.size
            || !target(&self.old_encoded_target)
            || !target(&self.encoded_target)
            || (!self.directory
                && n.source_sha256
                    .map(|h| h.iter().map(|b| format!("{b:02x}")).collect::<String>())
                    .as_deref()
                    != Some(self.plaintext_sha256.as_str()))
        {
            return Err(no());
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetargetNode {
    identity: [u8; 16],
    file: u64,
    usn: i64,
    old_components: Vec<String>,
    new_components: Vec<String>,
    original: RemoteEntry,
    entry: RemoteEntry,
    write_id: String,
    previous_revision: u64,
    revision: u64,
    source_sha256: Option<[u8; 32]>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetargetRow {
    descriptor: Retarget,
    queued: Queued,
    nodes: Vec<RetargetNode>,
    native: Option<Vec<Native>>,
    destination_parent_ref: ParentRef,
    journal: Vec<JournalRow>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetargetIndex {
    version: u32,
    scope: Scope,
    rows: Vec<RetargetRow>,
}
fn retarget_key(scope: &Scope) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    let s = scope.authenticated_store_binding().map_err(|_| no())?;
    let mut k = Zeroizing::new(RETARGET_DOMAIN.to_vec());
    k.extend_from_slice(&(s.len() as u64).to_le_bytes());
    k.extend_from_slice(&s);
    Ok(k)
}
fn retarget_directory(scope: &Scope) -> Result<std::path::PathBuf, BackendError> {
    Ok(DpapiSessionStore::current_user()
        .map_err(|_| no())?
        .local_edit_state_directory()
        .join(format!(
            "vault-cached-retarget-v1-{:x}",
            Sha256::digest(&*retarget_key(scope)?)
        )))
}
fn load_retargets(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<(Option<Zeroizing<Vec<u8>>>, RetargetIndex), BackendError> {
    let raw = store.load(&retarget_key(scope)?).map_err(|_| no())?;
    let i = if let Some(raw) = &raw {
        if !std::fs::symlink_metadata(retarget_directory(scope)?)
            .map(|m| m.is_dir() && !m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(no());
        }
        if raw.is_empty() || raw.len() > 16 << 20 {
            return Err(no());
        }
        let i: RetargetIndex = serde_json::from_slice(raw).map_err(|_| no())?;
        if i.version != 1 || i.scope != *scope || i.rows.is_empty() || i.rows.len() > 1024 {
            return Err(no());
        }
        let mut receipts = std::collections::BTreeSet::new();
        for r in &i.rows {
            r.descriptor.validate(scope)?;
            r.destination_parent_ref.validate()?;
            if r.descriptor.original.directory {
                if r.journal.len() != r.nodes.len() {
                    return Err(no());
                }
                let root_journal = r
                    .journal
                    .iter()
                    .find(|j| j.write_id == r.queued.write_id)
                    .ok_or_else(no)?;
                if root_journal.parent_ref != r.destination_parent_ref {
                    return Err(no());
                }
                for n in &r.nodes {
                    let mut v = r.journal.iter().filter(|j| j.write_id == n.write_id);
                    let j = v.next().ok_or_else(no)?;
                    if v.next().is_some() {
                        return Err(no());
                    }
                    j.validate(n)?;
                }
            } else if !r.journal.is_empty() {
                return Err(no());
            }
            r.queued.validate()?;
            if !receipts.insert((r.queued.write_id.clone(), r.queued.revision))
                || r.queued.native.is_some()
                || r.queued.original.as_ref() != Some(&r.descriptor.original)
                || r.queued.parent != r.descriptor.destination_parent
                || r.nodes.is_empty()
                || r.nodes.len() > 64
                || r.nodes
                    .iter()
                    .map(|n| n.entry.size)
                    .try_fold(0u64, u64::checked_add)
                    .is_none_or(|s| s > 64 << 20)
            {
                return Err(no());
            }
            let mut ids = std::collections::BTreeSet::new();
            let mut files = std::collections::BTreeSet::new();
            for n in &r.nodes {
                if n.identity == [0; 16]
                    || n.file == 0
                    || n.usn <= 0
                    || !ids.insert(n.identity)
                    || !files.insert(n.file)
                    || n.old_components.len() < r.descriptor.old_components.len()
                    || !n.old_components.starts_with(&r.descriptor.old_components)
                    || n.new_components
                        != r.descriptor
                            .new_components
                            .iter()
                            .chain(&n.old_components[r.descriptor.old_components.len()..])
                            .cloned()
                            .collect::<Vec<_>>()
                    || n.original.id != n.entry.id
                    || n.original.directory != n.entry.directory
                    || n.original.size != n.entry.size
                    || n.entry.path
                        != format!(
                            "{}{}",
                            r.queued.entry.as_ref().ok_or_else(no)?.path,
                            n.original
                                .path
                                .strip_prefix(&r.descriptor.original.path)
                                .ok_or_else(no)?
                        )
                    || n.previous_revision == 0
                    || n.revision <= n.previous_revision
                    || n.original.etag
                        != format!("raiun-pending-v1:{}:{}", n.write_id, n.previous_revision)
                    || n.entry.etag != format!("raiun-pending-v1:{}:{}", n.write_id, n.revision)
                    || raiun_core::validate_remote_path(&n.entry.path).is_err()
                {
                    return Err(no());
                }
            }
            let root = r
                .nodes
                .iter()
                .find(|n| n.identity == r.descriptor.identity)
                .ok_or_else(no)?;
            if root.file != r.descriptor.file
                || root.usn != r.descriptor.usn
                || root.original != r.descriptor.original
                || Some(&root.entry) != r.queued.entry.as_ref()
                || root.write_id != r.queued.write_id
                || root.revision != r.queued.revision
                || r.native.as_ref().is_some_and(|v| {
                    v.len() != r.nodes.len()
                        || v.iter().zip(&r.nodes).any(|(a, n)| {
                            a.identity != n.identity || a.file != n.file || a.usn <= 0
                        })
                })
            {
                return Err(no());
            }
        }
        i
    } else {
        match std::fs::symlink_metadata(retarget_directory(scope)?) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err(no()),
        }
        RetargetIndex {
            version: 1,
            scope: scope.clone(),
            rows: vec![],
        }
    };
    Ok((raw, i))
}
fn commit_retargets(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    old: Option<&[u8]>,
    i: &RetargetIndex,
) -> Result<(), BackendError> {
    let raw = Zeroizing::new(serde_json::to_vec(i).map_err(|_| no())?);
    if raw.len() > 16 << 20 || i.rows.len() > 1024 {
        return Err(no());
    }
    store
        .cas(&retarget_key(scope)?, old, &raw)
        .map_err(|_| no())?;
    if store
        .load(&retarget_key(scope)?)
        .map_err(|_| no())?
        .is_none_or(|v| v.as_slice() != raw.as_slice())
    {
        return Err(no());
    }
    Ok(())
}

fn initial_pending(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<Vec<PendingFacts>, BackendError> {
    let mut rows = super::windows_vault_child_create_custody::pending_native_facts(store, scope)?;
    rows.extend(super::windows_vault_cached_child_custody::pending_native_facts(store, scope)?);
    let mut ids = std::collections::BTreeSet::new();
    let mut files = std::collections::BTreeSet::new();
    if rows
        .iter()
        .any(|r| !ids.insert(r.identity) || !files.insert(r.file))
    {
        return Err(no());
    }
    Ok(rows)
}
fn apply_retargets(rows: &mut [PendingFacts], index: &RetargetIndex) -> Result<(), BackendError> {
    for row in &index.rows {
        let proof = row.native.as_ref().ok_or_else(no)?;
        for (node, native) in row.nodes.iter().zip(proof) {
            let p = rows
                .iter_mut()
                .find(|p| p.identity == node.identity)
                .ok_or_else(no)?;
            if p.file != node.file
                || p.usn != node.usn
                || p.entry.as_ref() != Some(&node.original)
                || p.components != node.old_components
                || p.write_id != node.write_id
                || p.revision != node.previous_revision
                || p.source_sha256 != node.source_sha256
                || (node.identity == row.descriptor.identity && p.parent != row.descriptor.parent)
            {
                return Err(no());
            }
            p.original = Some(node.original.clone());
            p.entry = Some(node.entry.clone());
            p.components = node.new_components.clone();
            p.revision = node.revision;
            p.usn = native.usn;
            p.operation = if node.entry.directory {
                Operation::RetargetNeverAttemptedDirectory
            } else {
                Operation::RetargetNeverAttemptedFile
            };
            if node.identity == row.descriptor.identity {
                p.parent = row.descriptor.destination_parent.clone();
            }
        }
        for p in rows.iter_mut() {
            if let Some(n) = row
                .nodes
                .iter()
                .find(|n| n.entry.directory && n.entry.id == p.parent.id)
            {
                p.parent = n.entry.clone();
            }
        }
        let mut paths = std::collections::BTreeSet::new();
        if rows.iter().any(|p| {
            p.entry
                .as_ref()
                .is_none_or(|e| !paths.insert(e.path.clone()))
        }) {
            return Err(no());
        }
    }
    Ok(())
}
fn current_pending(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    index: &RetargetIndex,
) -> Result<Vec<PendingFacts>, BackendError> {
    let mut rows = initial_pending(store, scope)?;
    apply_retargets(&mut rows, index)?;
    Ok(rows)
}
/// Current protected child facts, including exact retargeted descendants.
pub(super) fn current_created_facts(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<Vec<PendingFacts>, BackendError> {
    let (_, index) = load_retargets(store, scope)?;
    current_pending(store, scope, &index)
}
fn parent_ref_matches(
    reference: &ParentRef,
    parent: &RemoteEntry,
    current: &[PendingFacts],
) -> bool {
    if let Some(row) = current.iter().find(|row| {
        row.entry
            .as_ref()
            .is_some_and(|entry| entry.id == parent.id)
    }) {
        return row.entry.as_ref() == Some(parent)
            && row.operation != Operation::DeleteFile
            && matches!(reference, ParentRef::PendingCreate { write_id, revision }
                if write_id == &row.write_id && *revision == row.revision);
    }
    matches!(reference, ParentRef::Stable { resource_id } if resource_id == &parent.id)
}
fn receipt_nodes(
    d: &Retarget,
    q: &Queued,
    receipt: &VaultCachedNamespaceQueued,
    current: &[PendingFacts],
) -> Result<Vec<RetargetNode>, BackendError> {
    let prefix = &d.original.path;
    let candidates: Vec<_> = current
        .iter()
        .filter(|p| {
            p.entry.as_ref().is_some_and(|e| {
                e.path == *prefix
                    || e.path
                        .strip_prefix(prefix)
                        .is_some_and(|s| s.starts_with('/'))
            })
        })
        .collect();
    if candidates.is_empty()
        || candidates.len() > 64
        || (!d.original.directory && candidates.len() != 1)
    {
        return Err(no());
    }
    let root = current
        .iter()
        .find(|p| p.identity == d.identity)
        .ok_or_else(no)?;
    if root.file != d.file
        || root.usn != d.usn
        || root.components != d.old_components
        || root.entry.as_ref() != Some(&d.original)
        || root.parent != d.parent
    {
        return Err(no());
    }
    let mut out = Vec::new();
    for p in candidates {
        let original = p.entry.as_ref().ok_or_else(no)?;
        if !p.components.starts_with(&d.old_components) {
            return Err(no());
        }
        let (write_id, previous_revision, revision, path) = if d.original.directory {
            let all = receipt.retarget_rows().ok_or_else(no)?;
            if all.len()
                != current
                    .iter()
                    .filter(|p| {
                        p.entry.as_ref().is_some_and(|e| {
                            e.path == *prefix
                                || e.path
                                    .strip_prefix(prefix)
                                    .is_some_and(|s| s.starts_with('/'))
                        })
                    })
                    .count()
            {
                return Err(no());
            }
            let mut r = all.iter().filter(|r| r.write_id == p.write_id);
            let r1 = r.next().ok_or_else(no)?;
            if r.next().is_some()
                || r1.old_path != original.path
                || r1.previous_revision != p.revision
                || !parent_ref_matches(&ParentRef::from(&r1.old_parent_ref), &p.parent, current)
                || r1.plaintext_len != p.plaintext_len
                || r1.revision <= r1.previous_revision
                || r1.state != raiun_cache::CiphertextWriteState::NeverAttempted
                || r1.operation
                    != if original.directory {
                        raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateDirectory
                    } else {
                        raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateFile
                    }
            {
                return Err(no());
            }
            if !original.directory
                && p.source_sha256
                    .map(|h| h.iter().map(|b| format!("{b:02x}")).collect::<String>())
                    .as_deref()
                    != Some(r1.plaintext_sha256.as_str())
            {
                return Err(no());
            }
            (
                r1.write_id.clone(),
                r1.previous_revision,
                r1.revision,
                r1.path.clone(),
            )
        } else {
            if receipt.retarget_rows().is_some() {
                return Err(no());
            }
            (
                q.write_id.clone(),
                p.revision,
                q.revision,
                q.entry.as_ref().ok_or_else(no)?.path.clone(),
            )
        };
        let entry = RemoteEntry {
            path,
            etag: format!("raiun-pending-v1:{write_id}:{revision}"),
            ..original.clone()
        };
        out.push(RetargetNode {
            identity: p.identity,
            file: p.file,
            usn: p.usn,
            old_components: p.components.clone(),
            new_components: d
                .new_components
                .iter()
                .chain(&p.components[d.old_components.len()..])
                .cloned()
                .collect(),
            original: original.clone(),
            entry,
            write_id,
            previous_revision,
            revision,
            source_sha256: p.source_sha256,
        });
    }
    out.sort_by_key(|n| n.identity);
    Ok(out)
}
/// Durable local-only receipt. The SDK journal already changed, so any later
/// error retains unresolved custody; this function never dispatches or retries.
pub(super) fn record_retarget_queued(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    receipt: &VaultCachedNamespaceQueued,
) -> Result<(), BackendError> {
    // The SDK mutation has already happened. Persist a fail-closed marker
    // before any receipt validation that could reject the new journal state.
    let (old, mut index) = load_retargets(store, scope)?;
    let storage = DpapiSessionStore::current_user().map_err(|_| no())?;
    let parent = PinnedDirectory::open(storage.local_edit_state_directory()).map_err(|_| no())?;
    let path = retarget_directory(scope)?;
    let _sentinel =
        PrivateDirectory::create_or_open_under(&parent, path.file_name().ok_or_else(no)?)
            .map_err(|_| no())?;
    let VaultCachedNamespaceDescriptor::PendingRetarget(d) = receipt.descriptor() else {
        return Err(no());
    };
    let destination_parent_ref = ParentRef::from(&d.destination_parent_ref);
    let d = Retarget::from(scope, d)?;
    let q = Queued::from(receipt)?;
    if q.original.as_ref() != Some(&d.original)
        || q.parent != d.destination_parent
        || q.operation
            != if d.original.directory {
                Operation::RetargetNeverAttemptedDirectory
            } else {
                Operation::RetargetNeverAttemptedFile
            }
    {
        return Err(no());
    }
    if index.rows.len() >= 1024 {
        return Err(no());
    }
    let current = current_pending(store, scope, &index)?;
    let parent_ref = destination_parent_ref;
    if !parent_ref_matches(&parent_ref, &d.destination_parent, &current) {
        return Err(no());
    }
    if let Some(parent) = current.iter().find(|p| p.identity == d.parent_identity) {
        if parent.file != d.parent_file
            || parent.usn != d.parent_usn
            || parent.entry.as_ref() != Some(&d.parent)
        {
            return Err(no());
        }
    }
    if let Some(parent) = current
        .iter()
        .find(|p| p.identity == d.destination_parent_identity)
    {
        if parent.file != d.destination_parent_file
            || parent.usn != d.destination_parent_usn
            || parent.entry.as_ref() != Some(&d.destination_parent)
        {
            return Err(no());
        }
    }
    let nodes = receipt_nodes(&d, &q, receipt, &current)?;
    if nodes
        .iter()
        .map(|n| n.entry.size)
        .try_fold(0u64, u64::checked_add)
        .is_none_or(|n| n > 64 << 20)
    {
        return Err(no());
    }
    index.rows.push(RetargetRow {
        descriptor: d,
        queued: q,
        nodes,
        native: None,
        destination_parent_ref: parent_ref,
        journal: receipt
            .retarget_rows()
            .map(|r| r.iter().map(JournalRow::from).collect())
            .unwrap_or_default(),
    });
    commit_retargets(store, scope, old.as_deref().map(Vec::as_slice), &index)
}
/// Every actual native subtree member must match the originally staged node.
/// Positive mappings are history only and never restore a live route/epoch.
pub(super) fn record_retarget_native(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    receipt: &VaultCachedNamespaceQueued,
    nodes: &[([u8; 16], u64, i64)],
) -> Result<(), BackendError> {
    let VaultCachedNamespaceDescriptor::PendingRetarget(d) = receipt.descriptor() else {
        return Err(no());
    };
    let d = Retarget::from(scope, d)?;
    let (old, mut index) = load_retargets(store, scope)?;
    let row = index.rows.last_mut().ok_or_else(no)?;
    if row.descriptor != d
        || row.native.is_some()
        || !row.queued.matches_receipt(receipt)?
        || nodes.len() != row.nodes.len()
        || nodes.is_empty()
        || nodes.len() > 64
    {
        return Err(no());
    }
    let mut supplied = std::collections::BTreeMap::new();
    for &(id, file, usn) in nodes {
        if id == [0; 16] || file == 0 || usn <= 0 || supplied.insert(id, (file, usn)).is_some() {
            return Err(no());
        }
    }
    let mut proof = Vec::new();
    for n in &row.nodes {
        let (file, usn) = supplied.remove(&n.identity).ok_or_else(no)?;
        if file != n.file {
            return Err(no());
        }
        proof.push(Native {
            identity: n.identity,
            file,
            usn,
        })
    }
    if !supplied.is_empty() {
        return Err(no());
    }
    row.native = Some(proof);
    // Authenticate the complete old→new chain before committing its terminal fact.
    current_pending(store, scope, &index)?;
    commit_retargets(store, scope, old.as_deref().map(Vec::as_slice), &index)
}
pub(super) fn pending_native_facts(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<Vec<PendingFacts>, BackendError> {
    let (_, i) = load_retargets(store, scope)?;
    let rows = current_pending(store, scope, &i)?;
    let changed: std::collections::BTreeSet<_> = i
        .rows
        .iter()
        .flat_map(|r| r.nodes.iter().map(|n| n.identity))
        .collect();
    Ok(rows
        .into_iter()
        .filter(|r| changed.contains(&r.identity))
        .collect())
}
pub(super) fn verify_no_unresolved(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<(), BackendError> {
    let (_, i) = load_retargets(store, scope)?;
    current_pending(store, scope, &i)?;
    Ok(())
}
pub(super) fn has_local_queued(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<bool, BackendError> {
    let (_, i) = load_retargets(store, scope)?;
    Ok(!i.rows.is_empty())
}

/// A protected local journal transition, used only to project the current
/// catalogue. It grants no remote or native mutation authority.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct CatalogueDelta {
    pub write_id: String,
    pub revision: u64,
    pub identity: [u8; 16],
    pub file: u64,
    pub usn: i64,
    pub components: Vec<String>,
    pub original: Option<RemoteEntry>,
    pub entry: Option<RemoteEntry>,
    pub plaintext_len: u64,
    pub source_sha256: Option<[u8; 32]>,
    /// Only a separate typed SDK+native terminal receipt may set this.
    pub verified_native: bool,
}
impl From<PendingFacts> for CatalogueDelta {
    fn from(f: PendingFacts) -> Self {
        Self {
            write_id: f.write_id,
            revision: f.revision,
            identity: f.identity,
            file: f.file,
            usn: f.usn,
            components: f.components,
            original: f.original,
            entry: f.entry,
            plaintext_len: f.plaintext_len,
            source_sha256: f.source_sha256,
            verified_native: false,
        }
    }
}
fn retarget_catalogue_deltas(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<Vec<CatalogueDelta>, BackendError> {
    let (_, index) = load_retargets(store, scope)?;
    // Authenticate every transition against the original child ledger before
    // exposing any row. The final pending facts alone omit intermediate moves.
    current_pending(store, scope, &index)?;
    let mut result = Vec::new();
    for row in &index.rows {
        let proof = row.native.as_ref().ok_or_else(no)?;
        for (node, native) in row.nodes.iter().zip(proof) {
            result.push(CatalogueDelta {
                write_id: node.write_id.clone(),
                revision: node.revision,
                identity: node.identity,
                file: native.file,
                usn: native.usn,
                components: node.new_components.clone(),
                original: Some(node.original.clone()),
                entry: Some(node.entry.clone()),
                plaintext_len: node.entry.size,
                source_sha256: node.source_sha256,
                verified_native: false,
            });
        }
    }
    Ok(result)
}
fn all_catalogue_deltas(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    extra: &[CatalogueDelta],
) -> Result<Vec<CatalogueDelta>, BackendError> {
    let mut rows = Vec::new();
    rows.extend(
        super::windows_vault_child_create_custody::pending_native_facts(store, scope)?
            .into_iter()
            .map(CatalogueDelta::from),
    );
    rows.extend(super::windows_vault_cached_child_custody::catalogue_updates(store, scope)?);
    rows.extend(
        super::windows_vault_file_rename_custody::pending_native_facts(store, scope)?
            .into_iter()
            .map(CatalogueDelta::from),
    );
    rows.extend(
        super::windows_vault_file_delete_custody::pending_native_facts(store, scope)?
            .into_iter()
            .map(CatalogueDelta::from),
    );
    rows.extend(retarget_catalogue_deltas(store, scope)?);
    if extra.iter().any(|row| row.verified_native) {
        return Err(no());
    }
    rows.extend_from_slice(extra);
    if rows.len() > 4096 {
        return Err(no());
    }
    let mut unique = std::collections::BTreeMap::new();
    for row in rows {
        validate_delta(&row)?;
        let key = (row.write_id.clone(), row.revision);
        if let Some(previous) = unique.insert(key, row.clone()) {
            if previous != row {
                return Err(no());
            }
        }
    }
    Ok(unique.into_values().collect())
}
pub(super) fn protected_catalogue_deltas(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<Vec<CatalogueDelta>, BackendError> {
    let extra = super::windows_vault_cached_capture::catalogue_updates(store, scope)?;
    all_catalogue_deltas(store, scope, &extra)
}
fn same_presentation(a: &RemoteEntry, b: &RemoteEntry) -> bool {
    a.id == b.id
        && a.path == b.path
        && a.directory == b.directory
        && a.size == b.size
        && a.etag == b.etag
}
fn validate_delta(d: &CatalogueDelta) -> Result<(), BackendError> {
    let entry = |e: &RemoteEntry| {
        !e.id.is_empty()
            && e.id.len() <= 4096
            && !e.etag.is_empty()
            && e.etag.len() <= 4096
            && e.path.len() <= 32000
            && raiun_core::validate_remote_path(&e.path).is_ok()
    };
    if d.write_id.is_empty()
        || d.write_id.len() > 512
        || d.write_id.chars().any(char::is_control)
        || d.revision == 0
        || d.identity == [0; 16]
        || d.file == 0
        || d.usn <= 0
        || d.components.len() < 2
        || d.components.len() > 256
        || d.components.iter().map(String::len).sum::<usize>() > 32000
        || d.components.iter().any(|c| {
            c.is_empty()
                || c.len() > 255
                || c == "."
                || c == ".."
                || c.chars().any(|c| {
                    c.is_control()
                        || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
                })
        })
        || !d.verified_native && d.original.is_none() && d.entry.is_none()
        || d.original.as_ref().is_some_and(|e| !entry(e))
        || d.entry.as_ref().is_some_and(|e| !entry(e))
        || !d.verified_native
            && d.entry.as_ref().is_some_and(|e| {
                e.path == "/"
                    || e.size != d.plaintext_len
                    || (e.directory && (e.size != 0 || d.plaintext_len != 0))
                    || e.etag != format!("raiun-pending-v1:{}:{}", d.write_id, d.revision)
            })
        || !d.verified_native
            && d.entry.is_none()
            && d.original
                .as_ref()
                .is_none_or(|e| e.directory || e.size != d.plaintext_len)
        || d.source_sha256 == Some([0; 32])
    {
        return Err(no());
    }
    if d.verified_native {
        if d.entry
            .as_ref()
            .is_some_and(|e| !super::vault_edit_capture::strong_etag(&e.etag))
        {
            return Err(no());
        }
        return Ok(());
    }
    if let Some(original) = &d.original {
        if let Some(entry) = &d.entry {
            if original.id != entry.id || original.directory != entry.directory {
                return Err(no());
            }
        }
        let prefix = format!("raiun-pending-v1:{}:", d.write_id);
        if let Some(previous) = original.etag.strip_prefix(&prefix) {
            let previous = previous.parse::<u64>().map_err(|_| no())?;
            if previous.checked_add(1) != Some(d.revision) {
                return Err(no());
            }
        } else if original.etag.starts_with("raiun-pending-v1:") || d.revision != 1 {
            return Err(no());
        }
    } else if d.revision != 1 {
        return Err(no());
    }
    Ok(())
}

/// Project exact protected journal transitions onto an authenticated base
/// catalogue. No prefix rewrite or history mutation is performed.
pub(super) fn current_catalogue(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    base: &[raiun_cloudfiles_windows::vault_custody::VaultCatalogueEntry],
    extra: &[CatalogueDelta],
) -> Result<Vec<raiun_cloudfiles_windows::vault_custody::VaultCatalogueEntry>, BackendError> {
    let mut current = std::collections::BTreeMap::new();
    for row in base {
        let mut metadata = row.metadata.clone();
        metadata.writable = false;
        metadata.encrypted = true;
        if row.identity == [0; 16]
            || raiun_core::validate_remote_path(&metadata.path).is_err()
            || current.insert(row.identity, metadata).is_some()
        {
            return Err(no());
        }
    }
    if current.len() > super::vault_custody::MAX_CATALOGUE {
        return Err(no());
    }
    unique_catalogue_paths(&current)?;
    let mut remaining = Vec::new();
    for delta in all_catalogue_deltas(store, scope, extra)? {
        if !super::windows_vault_reconciled_custody::is_reconciled(
            store,
            scope,
            &delta.write_id,
            delta.revision,
            delta.identity,
            delta.file,
        )? {
            remaining.push(delta);
        }
    }
    let terminal = super::windows_vault_reconciled_custody::catalogue_updates(store, scope)?;
    if terminal.iter().any(|row| {
        terminal
            .iter()
            .any(|other| row.identity == other.identity && row.file != other.file)
    }) {
        return Err(no());
    }
    // A completed earlier write may be the exact strong baseline for a later
    // local queue on the same opaque. Apply proven terminal facts first.
    for delta in &terminal {
        validate_delta(delta)?;
        if !delta.verified_native {
            return Err(no());
        }
        let already = match (current.get(&delta.identity), delta.entry.as_ref()) {
            (Some(now), Some(target)) => same_presentation(now, target),
            (None, None) => true,
            _ => false,
        };
        if already
            || current.get(&delta.identity).is_some_and(|now| {
                terminal.iter().any(|later| {
                    later.identity == delta.identity
                        && later
                            .entry
                            .as_ref()
                            .is_some_and(|target| same_presentation(now, target))
                })
            })
        {
            continue;
        }
        let source = match (&delta.original, current.get(&delta.identity)) {
            (None, None) => true,
            (Some(original), Some(now)) => same_presentation(original, now),
            _ => false,
        };
        if !source {
            return Err(no());
        }
        if let Some(mut entry) = delta.entry.clone() {
            entry.writable = false;
            entry.encrypted = true;
            current.insert(delta.identity, entry);
        } else {
            current.remove(&delta.identity);
        }
        unique_catalogue_paths(&current)?;
        if current.len() > super::vault_custody::MAX_CATALOGUE {
            return Err(no());
        }
    }
    let mut files = std::collections::BTreeMap::<[u8; 16], u64>::new();
    let mut seen_revisions = std::collections::BTreeMap::<String, u64>::new();
    let mut tombstones = terminal
        .iter()
        .filter(|delta| delta.entry.is_none())
        .map(|delta| delta.identity)
        .collect::<std::collections::BTreeSet<_>>();
    while !remaining.is_empty() {
        let eligible = remaining
            .iter()
            .enumerate()
            .filter(|(_, d)| {
                if tombstones.contains(&d.identity) {
                    return false;
                }
                match (&d.original, current.get(&d.identity)) {
                    (None, None) => true,
                    (Some(before), Some(now)) => same_presentation(before, now),
                    _ => false,
                }
            })
            .map(|(n, _)| n)
            .collect::<Vec<_>>();
        if eligible.is_empty() {
            return Err(no());
        }
        // More than one transition from the same presentation is ambiguous.
        let mut per_identity = std::collections::BTreeSet::new();
        for &index in &eligible {
            if !per_identity.insert(remaining[index].identity) {
                return Err(no());
            }
        }
        let index = eligible[0];
        let d = remaining.remove(index);
        if files
            .insert(d.identity, d.file)
            .is_some_and(|f| f != d.file)
            || seen_revisions
                .insert(d.write_id.clone(), d.revision)
                .is_some_and(|previous| previous.checked_add(1) != Some(d.revision))
        {
            return Err(no());
        }
        if let Some(mut entry) = d.entry {
            entry.writable = false;
            entry.encrypted = true;
            current.insert(d.identity, entry);
        } else {
            current.remove(&d.identity);
            tombstones.insert(d.identity);
        }
        unique_catalogue_paths(&current)?;
        if current.len() > super::vault_custody::MAX_CATALOGUE {
            return Err(no());
        }
    }
    Ok(current
        .into_iter()
        .map(
            |(identity, metadata)| raiun_cloudfiles_windows::vault_custody::VaultCatalogueEntry {
                identity,
                metadata,
            },
        )
        .collect())
}
fn unique_catalogue_paths(
    rows: &std::collections::BTreeMap<[u8; 16], RemoteEntry>,
) -> Result<(), BackendError> {
    let mut paths = std::collections::BTreeSet::new();
    let mut ids = std::collections::BTreeSet::new();
    for row in rows.values() {
        if !paths.insert(row.path.to_lowercase()) || !ids.insert(row.id.clone()) {
            return Err(no());
        }
    }
    Ok(())
}
/// Includes tombstones so catalogue persistence can identify every protected
/// pending identity without interpreting a missing entry as remote deletion.
pub(super) fn pending_identities(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    extra: &[CatalogueDelta],
) -> Result<std::collections::BTreeSet<[u8; 16]>, BackendError> {
    let mut identities = std::collections::BTreeSet::new();
    for delta in all_catalogue_deltas(store, scope, extra)? {
        if !super::windows_vault_reconciled_custody::is_reconciled(
            store,
            scope,
            &delta.write_id,
            delta.revision,
            delta.identity,
            delta.file,
        )? {
            identities.insert(delta.identity);
        }
    }
    Ok(identities)
}

/// Native facts for the current protected result of each affected opaque.
/// A terminal result is distinct from a still queued local result, including
/// when the terminal entry has no original catalogue row (new child).
pub(super) struct NativeIntent {
    pub identity: [u8; 16],
    pub file: u64,
    pub usn: i64,
    pub components: Vec<String>,
    pub entry: Option<RemoteEntry>,
    pub plaintext_len: u64,
    pub source_sha256: Option<[u8; 32]>,
    pub terminal_verified: bool,
    pub write_id: String,
    pub revision: u64,
}
pub(super) fn current_native_intents(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<Vec<NativeIntent>, BackendError> {
    let mut rows = Vec::new();
    for delta in protected_catalogue_deltas(store, scope)? {
        if !super::windows_vault_reconciled_custody::is_reconciled(
            store,
            scope,
            &delta.write_id,
            delta.revision,
            delta.identity,
            delta.file,
        )? {
            rows.push(delta);
        }
    }
    rows.extend(super::windows_vault_reconciled_custody::catalogue_updates(
        store, scope,
    )?);
    let mut result = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let mut superseded = false;
        for (other_index, next) in rows.iter().enumerate() {
            if index == other_index || row.identity != next.identity {
                continue;
            }
            if row.file != next.file {
                return Err(no());
            }
            if row.entry.as_ref().is_some_and(|entry| {
                next.original
                    .as_ref()
                    .is_some_and(|original| same_presentation(entry, original))
            }) {
                superseded = true;
            }
        }
        if !superseded {
            result.push(NativeIntent {
                identity: row.identity,
                file: row.file,
                usn: row.usn,
                components: row.components.clone(),
                entry: row.entry.clone(),
                plaintext_len: row.plaintext_len,
                source_sha256: row.source_sha256,
                terminal_verified: row.verified_native,
                write_id: row.write_id.clone(),
                revision: row.revision,
            });
        }
    }
    let mut identities = std::collections::BTreeSet::new();
    if result.iter().any(|row| !identities.insert(row.identity)) {
        return Err(no());
    }
    Ok(result)
}

//! Separate factual terminal state for a guarded SDK and native completion.
//! Original capture and queued history remain unchanged and retain their bodies.
use super::{
    vault_custody::{Entry, Hydration, Scope},
    windows_vault_custody::Storage,
};
use raiun_cloudfiles_windows::{
    BackendError, VaultCachedNativeCompleted, VaultCachedNativeExpectation,
};
use raiun_control_windows::{DpapiSessionStore, PinnedDirectory, PrivateDirectory};
use raiun_core::backend::RemoteEntry;
use raiun_opencloud::{
    vault_backend::VaultReconciledPending, vault_cache::VaultPendingOperationKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"raiun/windows-vault-cached-reconciled/v1\0";
fn no() -> BackendError {
    BackendError::Unavailable
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Operation {
    CreateFile,
    CreateDirectory,
    CopyFile,
    Overwrite,
    RenameFile,
    DeleteFile,
}
impl Operation {
    fn from(o: VaultPendingOperationKind) -> Result<Self, BackendError> {
        Ok(match o {
            VaultPendingOperationKind::CreateFile => Self::CreateFile,
            VaultPendingOperationKind::CreateDirectory => Self::CreateDirectory,
            VaultPendingOperationKind::CopyFile => Self::CopyFile,
            VaultPendingOperationKind::Overwrite => Self::Overwrite,
            VaultPendingOperationKind::RenameFile => Self::RenameFile,
            VaultPendingOperationKind::DeleteFile => Self::DeleteFile,
        })
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Terminal {
    scope: Scope,
    operation: Operation,
    write_id: String,
    revision: u64,
    covered_revisions: Vec<u64>,
    identity: [u8; 16],
    file: u64,
    original_usn: i64,
    completed_usn: i64,
    components: Vec<String>,
    original: Option<RemoteEntry>,
    pending: Option<RemoteEntry>,
    result: Option<RemoteEntry>,
    plaintext_len: u64,
    source_sha256: Option<[u8; 32]>,
    remote_sha256: Option<[u8; 32]>,
}
impl Terminal {
    fn validate(&self, scope: &Scope) -> Result<(), BackendError> {
        let entry = |e: &RemoteEntry| {
            !e.id.is_empty()
                && e.id.len() <= 4096
                && !e.etag.is_empty()
                && e.etag.len() <= 4096
                && e.path.len() <= 32000
                && raiun_core::validate_remote_path(&e.path).is_ok()
        };
        if self.scope != *scope
            || self.write_id.len() != 32
            || !self.write_id.bytes().all(|b| b.is_ascii_hexdigit())
            || self.revision == 0
            || self.identity == [0; 16]
            || self.file == 0
            || self.original_usn <= 0
            || self.completed_usn < self.original_usn
            || self.components.len() < 2
            || self.components.len() > 256
            || self.components.iter().map(String::len).sum::<usize>() > 32000
            || self.components.iter().any(|c| {
                c.is_empty()
                    || c.len() > 255
                    || c == "."
                    || c == ".."
                    || c.chars().any(|x| {
                        x.is_control()
                            || matches!(x, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
                    })
            })
            || self.covered_revisions.is_empty()
            || self.covered_revisions.len() > 1024
            || self.covered_revisions.last() != Some(&self.revision)
            || self
                .covered_revisions
                .iter()
                .enumerate()
                .any(|(i, r)| *r != i as u64 + 1)
            || self.original.as_ref().is_some_and(|e| !entry(e))
            || self.pending.as_ref().is_some_and(|e| !entry(e))
            || self
                .result
                .as_ref()
                .is_some_and(|e| !entry(e) || !super::vault_edit_capture::strong_etag(&e.etag))
            || (self.operation == Operation::DeleteFile) != self.result.is_none()
            || self.pending.as_ref().is_some_and(|e| {
                e.etag != format!("raiun-pending-v1:{}:{}", self.write_id, self.revision)
            })
            || self
                .pending
                .as_ref()
                .is_some_and(|e| e.directory && (e.size != 0 || self.plaintext_len != 0))
            || self
                .result
                .as_ref()
                .is_some_and(|e| !e.directory && e.size != self.plaintext_len)
            || self.source_sha256 == Some([0; 32])
            || self.remote_sha256 == Some([0; 32])
        {
            return Err(no());
        }
        if let Some(result) = &self.result {
            if result.path != self.pending.as_ref().ok_or_else(no)?.path
                || result.directory != self.pending.as_ref().ok_or_else(no)?.directory
            {
                return Err(no());
            }
            if self.strong_original().is_some()
                && !matches!(
                    self.operation,
                    Operation::CreateFile | Operation::CreateDirectory | Operation::CopyFile
                )
                && result.id != self.pending.as_ref().ok_or_else(no)?.id
            {
                return Err(no());
            }
        }
        Ok(())
    }
    fn strong_original(&self) -> Option<&RemoteEntry> {
        self.original
            .as_ref()
            .filter(|e| super::vault_edit_capture::strong_etag(&e.etag))
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u32,
    scope: Scope,
    rows: Vec<Terminal>,
}
fn key(scope: &Scope) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    let s = scope.authenticated_store_binding().map_err(|_| no())?;
    let mut key = Zeroizing::new(DOMAIN.to_vec());
    key.extend_from_slice(&(s.len() as u64).to_le_bytes());
    key.extend_from_slice(&s);
    Ok(key)
}
fn directory(scope: &Scope) -> Result<PathBuf, BackendError> {
    Ok(DpapiSessionStore::current_user()
        .map_err(|_| no())?
        .local_edit_state_directory()
        .join(format!(
            "vault-cached-reconciled-v1-{:x}",
            Sha256::digest(&*key(scope)?)
        )))
}
fn load(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<(Option<Zeroizing<Vec<u8>>>, Index), BackendError> {
    let raw = store.load(&key(scope)?).map_err(|_| no())?;
    let index = if let Some(raw) = &raw {
        if raw.is_empty()
            || raw.len() > 16 << 20
            || !std::fs::symlink_metadata(directory(scope)?)
                .map(|m| m.is_dir() && !m.file_type().is_symlink())
                .unwrap_or(false)
        {
            return Err(no());
        }
        let i: Index = serde_json::from_slice(raw).map_err(|_| no())?;
        if i.version != 1 || i.scope != *scope || i.rows.is_empty() || i.rows.len() > 1024 {
            return Err(no());
        }
        let mut ids = std::collections::BTreeSet::new();
        let history =
            super::windows_vault_namespace_queued::protected_catalogue_deltas(store, scope)?;
        for row in &i.rows {
            row.validate(scope)?;
            if !ids.insert(row.write_id.clone()) || !history_matches(row, &history) {
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
fn history_matches(
    terminal: &Terminal,
    history: &[super::windows_vault_namespace_queued::CatalogueDelta],
) -> bool {
    let mut rows = history
        .iter()
        .filter(|row| row.write_id == terminal.write_id)
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| row.revision);
    if rows.len() != terminal.covered_revisions.len()
        || rows.iter().enumerate().any(|(index, row)| {
            row.revision != terminal.covered_revisions[index]
                || row.identity != terminal.identity
                || row.file != terminal.file
                || index > 0 && rows[index - 1].entry.as_ref() != row.original.as_ref()
        })
    {
        return false;
    }
    rows.last().is_some_and(|last| {
        last.revision == terminal.revision
            && last.usn == terminal.original_usn
            && last.components == terminal.components
            && last.original == terminal.original
            && last.entry == terminal.pending
            && last.plaintext_len == terminal.plaintext_len
            && last.source_sha256 == terminal.source_sha256
    })
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
fn protected_chain(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    e: &VaultCachedNativeExpectation,
) -> Result<Vec<u64>, BackendError> {
    let mut rows = super::windows_vault_namespace_queued::protected_catalogue_deltas(store, scope)?
        .into_iter()
        .filter(|d| d.write_id == e.write_id)
        .collect::<Vec<_>>();
    if rows
        .iter()
        .any(|d| d.identity != e.identity || d.file != e.file || d.revision > e.revision)
    {
        return Err(no());
    }
    rows.sort_by_key(|d| d.revision);
    if rows.len() != usize::try_from(e.revision).map_err(|_| no())? || rows.len() > 1024 {
        return Err(no());
    }
    for (i, row) in rows.iter().enumerate() {
        if row.revision != i as u64 + 1
            || i > 0 && rows[i - 1].entry.as_ref() != row.original.as_ref()
        {
            return Err(no());
        }
    }
    let last = rows.last().ok_or_else(no)?;
    if last.revision != e.revision
        || last.usn != e.usn
        || last.components != e.components
        || last.original != e.original
        || last.entry != e.entry
        || last.plaintext_len != e.plaintext_len
        || last.source_sha256 != e.source_sha256
    {
        return Err(no());
    }
    Ok(rows.iter().map(|r| r.revision).collect())
}
pub(super) fn record(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    expected: &VaultCachedNativeExpectation,
    remote: &VaultReconciledPending,
    native: &VaultCachedNativeCompleted,
) -> Result<(), BackendError> {
    let target = scope.streamed_storage_scope().map_err(|_| no())?;
    let meta = remote.metadata();
    let operation = Operation::from(expected.operation)?;
    if !remote.provider_current()
        || expected.root
            != (raiun_cloudfiles_windows::ConfiguredRootIdentity {
                volume_serial: target.root_volume_serial,
                file_index: target.root_file_index,
            })
        || remote.scope().account_id() != target.profile_id
        || remote.scope().server_origin() != target.server_origin
        || remote.scope().space_id() != target.space_id
        || remote.scope().resource_id() != target.root_resource_id
        || expected.write_id != meta.id
        || expected.revision != meta.revision
        || expected.operation != meta.operation
        || expected.plaintext_len
            != if matches!(
                expected.operation,
                VaultPendingOperationKind::RenameFile | VaultPendingOperationKind::DeleteFile
            ) {
                meta.source_size
            } else {
                meta.plaintext_len
            }
        || remote.plaintext_len() != expected.plaintext_len
        || native.write_id() != expected.write_id
        || native.revision() != expected.revision
        || native.identity() != expected.identity
        || native.file() != expected.file
        || native.usn() < expected.usn
        || native.entry() != remote.entry()
        || expected.identity == [0; 16]
        || expected.file == 0
        || expected.usn <= 0
        || expected.entry.is_none() != remote.entry().is_none()
    {
        return Err(no());
    }
    if expected
        .original
        .as_ref()
        .is_some_and(|o| o.path != meta.path || o.id != meta.base_resource_id)
        || expected.entry.as_ref().is_some_and(|e| {
            e.path.as_str()
                != if operation == Operation::RenameFile {
                    meta.destination_path.as_str()
                } else {
                    meta.path.as_str()
                }
        })
        || expected
            .entry
            .as_ref()
            .zip(remote.entry())
            .is_some_and(|(p, r)| {
                p.path != r.path
                    || p.directory != r.directory
                    || (p.directory && (p.size != 0 || expected.plaintext_len != 0))
                    || (!p.directory && p.size != r.size)
            })
        || remote
            .plaintext_sha256()
            .is_some_and(|hash| expected.source_sha256.is_some_and(|source| source != hash))
    {
        return Err(no());
    }
    let covered = protected_chain(store, scope, expected)?;
    let terminal = Terminal {
        scope: scope.clone(),
        operation,
        write_id: expected.write_id.clone(),
        revision: expected.revision,
        covered_revisions: covered,
        identity: expected.identity,
        file: expected.file,
        original_usn: expected.usn,
        completed_usn: native.usn(),
        components: expected.components.clone(),
        original: expected.original.clone(),
        pending: expected.entry.clone(),
        result: remote.entry().cloned(),
        plaintext_len: expected.plaintext_len,
        source_sha256: expected.source_sha256,
        remote_sha256: remote.plaintext_sha256(),
    };
    terminal.validate(scope)?;
    let (old, mut index) = load(store, scope)?;
    if index.rows.iter().any(|r| r.write_id == terminal.write_id) || index.rows.len() >= 1024 {
        return Err(no());
    }
    let storage = DpapiSessionStore::current_user().map_err(|_| no())?;
    let parent = PinnedDirectory::open(storage.local_edit_state_directory()).map_err(|_| no())?;
    let path = directory(scope)?;
    let _sentinel =
        PrivateDirectory::create_or_open_under(&parent, path.file_name().ok_or_else(no)?)
            .map_err(|_| no())?;
    index.rows.push(terminal);
    commit(store, scope, old.as_deref().map(Vec::as_slice), &index)
}
pub(super) fn is_reconciled(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    write_id: &str,
    revision: u64,
    identity: [u8; 16],
    file: u64,
) -> Result<bool, BackendError> {
    let (_, i) = load(store, scope)?;
    Ok(i.rows.iter().any(|r| {
        r.write_id == write_id
            && r.identity == identity
            && r.file == file
            && r.covered_revisions.contains(&revision)
    }))
}
pub(super) fn catalogue_updates(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<Vec<super::windows_vault_namespace_queued::CatalogueDelta>, BackendError> {
    let (_, i) = load(store, scope)?;
    i.rows
        .into_iter()
        .map(|r| {
            let original = r.strong_original().cloned();
            let mut result = r.result;
            if let Some(entry) = &mut result {
                if entry.directory {
                    entry.size = 0; // Native/catalogue logical directory body is empty.
                }
            }
            super::windows_vault_namespace_queued::CatalogueDelta {
                write_id: r.write_id,
                revision: r.revision,
                identity: r.identity,
                file: r.file,
                usn: r.completed_usn,
                components: r.components,
                original,
                entry: result,
                plaintext_len: r.plaintext_len,
                source_sha256: r.remote_sha256.or(r.source_sha256),
                verified_native: true,
            }
        })
        .map(Ok)
        .collect()
}
pub(super) fn project_entry(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    value: &Entry,
) -> Result<Entry, BackendError> {
    let (_, i) = load(store, scope)?;
    let mut next = value.clone();
    for r in &i.rows {
        let Some(original) = r.strong_original() else {
            continue;
        };
        if next.opaque() != r.identity {
            continue;
        }
        if i.rows.iter().any(|later| {
            later.identity == r.identity
                && later.result.as_ref().is_some_and(|remote| {
                    next.remote_id() == remote.id
                        && next.root_relative_path() == remote.path
                        && next.etag() == remote.etag
                        && next.length() == remote.size
                        && next.is_directory() == remote.directory
                })
        }) {
            continue;
        }
        if next.opaque() == r.identity
            && next.remote_id() == original.id
            && next.root_relative_path() == original.path
            && next.etag() == original.etag
            && next.length() == original.size
            && next.is_directory() == original.directory
        {
            if let Some(remote) = &r.result {
                next = Entry::new(
                    r.identity,
                    &remote.id,
                    &remote.path,
                    &remote.etag,
                    remote.directory,
                    if remote.directory { 0 } else { remote.size },
                )
                .map_err(|_| no())?;
            }
        } else {
            return Err(no());
        }
    }
    Ok(next)
}
pub(super) fn entry_deleted(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    value: &Entry,
) -> Result<bool, BackendError> {
    let (_, i) = load(store, scope)?;
    Ok(i.rows.iter().any(|r| {
        r.result.is_none()
            && r.strong_original().is_some_and(|o| {
                value.opaque() == r.identity
                    && value.remote_id() == o.id
                    && value.root_relative_path() == o.path
                    && value.etag() == o.etag
                    && value.length() == o.size
                    && value.is_directory() == o.directory
            })
    }))
}
pub(super) fn project_hydration(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    value: &Hydration,
) -> Result<Hydration, BackendError> {
    let (_, i) = load(store, scope)?;
    let mut next = value.clone();
    for r in &i.rows {
        let Some(original) = r.strong_original() else {
            continue;
        };
        if original.directory || r.result.is_none() {
            continue;
        }
        let old = original_components(
            &r.components,
            original.path.as_str(),
            r.pending.as_ref().ok_or_else(no)?.path.as_str(),
        )?;
        if next.opaque() == r.identity
            && next.file_index() == r.file
            && next.length() == original.size
            && next.components() == old
        {
            next = next
                .with_rename_components(r.components.clone())
                .with_verified_length(r.result.as_ref().ok_or_else(no)?.size);
        }
    }
    Ok(next)
}
pub(super) fn hydration_deleted(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    value: &Hydration,
) -> Result<bool, BackendError> {
    let (_, i) = load(store, scope)?;
    for r in &i.rows {
        let Some(original) = r.strong_original() else {
            continue;
        };
        if r.result.is_some() || original.directory {
            continue;
        }
        let old = original_components(&r.components, &original.path, &original.path)?;
        if value.opaque() == r.identity
            && value.file_index() == r.file
            && value.length() == original.size
            && value.components() == old
        {
            return Ok(true);
        }
    }
    Ok(false)
}
fn original_components(
    current: &[String],
    old_path: &str,
    new_path: &str,
) -> Result<Vec<String>, BackendError> {
    raiun_core::validate_remote_path(new_path).map_err(|_| no())?;
    raiun_core::validate_remote_path(old_path).map_err(|_| no())?;
    let new_count = new_path.trim_start_matches('/').split('/').count();
    if new_count > current.len() {
        return Err(no());
    }
    let mut old = current[..current.len() - new_count].to_vec();
    old.extend(
        old_path
            .trim_start_matches('/')
            .split('/')
            .map(str::to_owned),
    );
    Ok(old)
}

//! Cached native captures use the existing protected stream codec with their
//! own full-scope AAD. Facts and receipts are history, never unlock authority.
use super::{vault_custody::Scope, windows_vault_custody::Storage};
use raiun_cloudfiles_windows::{
    BackendError, CachedVaultEditBaselineFacts, EditRecordProtector, JournalError,
    streamed_snapshot::SnapshotBinding,
    streamed_store::{SnapshotStore, StorePolicy, VerifiedPinnedSnapshot},
};
use raiun_control_windows::{DpapiSessionStore, PinnedDirectory, PrivateDirectory};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read, sync::Arc};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"raiun/windows-vault-cached-capture/v1\0";
const LIMIT: usize = 1024;
const MAX_INDEX: usize = 16 << 20;
fn no() -> BackendError {
    BackendError::Unavailable
}
fn key(scope: &Scope) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    let raw = scope.authenticated_store_binding().map_err(|_| no())?;
    let mut key = Zeroizing::new(DOMAIN.to_vec());
    key.extend_from_slice(&(raw.len() as u64).to_le_bytes());
    key.extend_from_slice(&raw);
    Ok(key)
}
struct Protector {
    inner: raiun_cloudfiles_windows::DpapiEditRecordProtector,
    scope: Zeroizing<Vec<u8>>,
}
impl Protector {
    fn aad(&self, aad: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut result = Zeroizing::new(self.scope.to_vec());
        result.extend_from_slice(aad);
        result
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
    let storage = DpapiSessionStore::current_user().map_err(|_| no())?;
    let parent = PinnedDirectory::open(storage.local_edit_state_directory()).map_err(|_| no())?;
    let name = format!(
        "vault-cached-captures-v1-{:x}",
        Sha256::digest(&*key(scope)?)
    );
    let directory = Arc::new(
        if create {
            PrivateDirectory::create_or_open_under(&parent, std::ffi::OsStr::new(&name))
        } else {
            PrivateDirectory::open_under(&parent, std::ffi::OsStr::new(&name))
        }
        .map_err(|_| no())?,
    );
    let protector = Arc::new(Protector {
        inner: raiun_cloudfiles_windows::DpapiEditRecordProtector::from_existing_private_directory(
            directory.clone(),
        )
        .map_err(|_| no())?,
        scope: key(scope)?,
    });
    let policy = StorePolicy {
        max_content_bytes: 1 << 30,
        max_state_bytes: 4 << 30,
        max_entries: 4096,
        max_metadata_bytes_per_scan: 64 << 20,
    };
    let scope = scope.streamed_storage_scope().map_err(|_| no())?;
    if create {
        SnapshotStore::create_or_open(directory, scope, protector, policy)
    } else {
        SnapshotStore::open_existing(directory, scope, protector, policy)
    }
    .map_err(|_| no())
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Capturing,
    Retained,
    LocalQueued,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    scope: Scope,
    pub(super) facts: CachedVaultEditBaselineFacts,
    snapshot: SnapshotBinding,
    id: String,
    phase: Phase,
    pending: Option<(String, u64)>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u32,
    scope: Scope,
    rows: Vec<Record>,
}
fn validate(scope: &Scope, facts: &CachedVaultEditBaselineFacts) -> Result<(), BackendError> {
    let (volume_serial, file_index) = scope.native_root();
    facts.validate(raiun_cloudfiles_windows::ConfiguredRootIdentity {
        volume_serial,
        file_index,
    })?;
    let storage = scope.streamed_storage_scope().map_err(|_| no())?;
    if facts.profile_id != storage.profile_id
        || facts.account_id != storage.account_subject
        || facts.server_origin != storage.server_origin
        || facts.space_id != storage.space_id
        || facts.root_resource_id != storage.root_resource_id
        || facts.remote_root != scope.remote_root()
    {
        return Err(no());
    }
    Ok(())
}
fn capture_id(scope: &Scope, facts: &CachedVaultEditBaselineFacts) -> Result<String, BackendError> {
    let raw = Zeroizing::new(serde_json::to_vec(&(scope, facts)).map_err(|_| no())?);
    Ok(format!("cached_{:x}", Sha256::digest(&*raw)))
}
fn load(
    store: &Arc<dyn Storage>,
    scope: &Scope,
) -> Result<(Option<Zeroizing<Vec<u8>>>, Index), BackendError> {
    let raw = store.load(&key(scope)?).map_err(|_| no())?;
    let index = match &raw {
        None => {
            let storage = DpapiSessionStore::current_user().map_err(|_| no())?;
            let directory = storage.local_edit_state_directory().join(format!(
                "vault-cached-captures-v1-{:x}",
                Sha256::digest(&*key(scope)?)
            ));
            match std::fs::symlink_metadata(directory) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                _ => return Err(no()),
            }
            Index {
                version: 1,
                scope: scope.clone(),
                rows: Vec::new(),
            }
        }
        Some(raw) => {
            if raw.is_empty() || raw.len() > MAX_INDEX {
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
                validate(scope, &row.facts)?;
                if row.scope != *scope
                    || row.id != capture_id(scope, &row.facts)?
                    || !ids.insert(&row.id)
                    || row.snapshot.scope != scope.streamed_storage_scope().map_err(|_| no())?
                    || row.snapshot.generation != row.facts.token_generation
                    || row.snapshot.local_file != row.facts.file
                    || row.snapshot.relative_path != row.facts.components.join("/")
                    || row.snapshot.remote.is_some()
                    || row.snapshot.content_len != row.facts.plaintext_len
                    || (row.phase == Phase::LocalQueued) != row.pending.is_some()
                    || row.pending.as_ref().is_some_and(|(id, revision)| {
                        id.len() != 32
                            || !id.bytes().all(|b| b.is_ascii_hexdigit())
                            || *revision == 0
                    })
                {
                    return Err(no());
                }
            }
            index
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
    let bytes = Zeroizing::new(serde_json::to_vec(index).map_err(|_| no())?);
    if bytes.len() > MAX_INDEX || index.rows.len() > LIMIT {
        return Err(no());
    }
    store.cas(&key(scope)?, old, &bytes).map_err(|_| no())?;
    if store
        .load(&key(scope)?)
        .map_err(|_| no())?
        .as_deref()
        .map(Vec::as_slice)
        != Some(bytes.as_slice())
    {
        return Err(no());
    }
    Ok(())
}
pub(super) fn retain(
    store: Arc<dyn Storage>,
    scope: &Scope,
    facts: CachedVaultEditBaselineFacts,
    source: &mut dyn Read,
    verify: &mut dyn FnMut() -> Result<(), BackendError>,
    cancelled: &dyn Fn() -> bool,
) -> Result<String, BackendError> {
    validate(scope, &facts)?;
    if cancelled() {
        return Err(no());
    }
    verify()?;
    let id = capture_id(scope, &facts)?;
    let (raw, mut index) = load(&store, scope)?;
    if index.rows.iter().any(|r| r.id == id) {
        return Err(no());
    }
    let reservation = snapshots(scope, true)?
        .try_begin_capture(SnapshotBinding {
            record_id: String::new(),
            scope: scope.streamed_storage_scope().map_err(|_| no())?,
            generation: facts.token_generation,
            local_file: facts.file,
            relative_path: facts.components.join("/"),
            remote: None,
            content_len: facts.plaintext_len,
        })
        .map_err(|_| no())?;
    let row = Record {
        scope: scope.clone(),
        facts,
        snapshot: reservation.binding().clone(),
        id: id.clone(),
        phase: Phase::Capturing,
        pending: None,
    };
    index.rows.push(row.clone());
    commit(&store, scope, raw.as_deref().map(Vec::as_slice), &index)?;
    let staged = reservation
        .capture(source, &mut || cancelled())
        .map_err(|_| no())?;
    verify()?;
    let body = staged
        .verify_and_commit(&mut || cancelled())
        .map_err(|_| no())?;
    if body.manifest().binding() != &row.snapshot
        || body.manifest().content_sha256() != &row.facts.plaintext_sha256
        || body.manifest().binding().content_len != row.facts.plaintext_len
        || cancelled()
    {
        return Err(no());
    }
    verify()?;
    let (raw, mut index) = load(&store, scope)?;
    let current = index.rows.iter_mut().find(|r| r.id == id).ok_or_else(no)?;
    if *current != row {
        return Err(no());
    }
    current.phase = Phase::Retained;
    commit(&store, scope, raw.as_deref().map(Vec::as_slice), &index)?;
    Ok(id)
}
pub(super) fn reopen(
    store: &Arc<dyn Storage>,
    scope: &Scope,
    id: &str,
    cancelled: &dyn Fn() -> bool,
) -> Result<(Record, VerifiedPinnedSnapshot), BackendError> {
    let (_, index) = load(store, scope)?;
    let row = index
        .rows
        .into_iter()
        .find(|r| r.id == id && r.phase != Phase::Capturing)
        .ok_or_else(no)?;
    let body = snapshots(scope, false)?
        .open_verified(&row.snapshot.record_id, &mut || cancelled())
        .map_err(|_| no())?;
    if body.manifest().binding() != &row.snapshot
        || body.local_check().content_sha256() != &row.facts.plaintext_sha256
        || body.local_check().content_len() != row.facts.plaintext_len
        || cancelled()
    {
        return Err(no());
    }
    Ok((row, body))
}

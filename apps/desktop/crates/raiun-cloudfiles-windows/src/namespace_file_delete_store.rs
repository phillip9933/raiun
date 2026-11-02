//! Protected metadata for one explicit ordinary clean Personal-file deletion.
//!
//! This typed store is intentionally separate from `namespace-v1`, whose
//! writer, lease and validator are directory-create-only. It shares the
//! enclosing SnapshotStore's persistent quota lock, pinned directory handles,
//! accounting and metadata budget. It grants no remote or native authority.
use super::*;
use crate::namespace_intent::{
    ExistingNamespaceEntry, NamespaceEvent, NamespaceEventKind, NamespaceIntent,
    NamespaceIntentProgress, NamespaceObjectKind, NamespaceOperation, NamespacePhase,
    NamespaceProgressSnapshot,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use zeroize::Zeroizing;

pub(super) const ROOT: &str = "namespace-delete-v1";
const DOMAIN: &[u8] = b"raiun/namespace-delete-store/v1\0";
const MAX_SCOPES: usize = 256;
const MAX_RECORDS: usize = 2000;
const MAX_EVENTS: usize = 128;

#[derive(Clone, Eq, PartialEq)]
struct RecordKey {
    scope: String,
    id: String,
    generation: u64,
    digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    generation: u64,
    digest: String,
    sealed: Vec<u8>,
}

struct Loaded {
    key: RecordKey,
    intent: NamespaceIntent,
    progress: NamespaceProgressSnapshot,
    checker: NamespaceIntentProgress,
    commitment: [u8; 32],
}

/// A verified record returned by read-only discovery. It is not a publication
/// receipt and cannot be upgraded to a fresh delete lease.
#[derive(Clone)]
pub struct FileDeleteHistory {
    pub intent: NamespaceIntent,
    pub progress: NamespaceProgressSnapshot,
}

/// Only a successfully created and authenticated publication yields this
/// receipt. It is consumed when acquiring the operation lease.
pub struct PublishedFileDeleteIntent {
    store: Arc<FileDeleteStore>,
    directory: Arc<dyn Directory>,
    loaded: Box<Loaded>,
    fresh: bool,
}

pub enum FileDeletePublishResult {
    Fresh(PublishedFileDeleteIntent),
    /// Exact duplicate or unresolved same-file/path conflict. No receipt is
    /// minted, including when a duplicate history is pristine Pending/0.
    Retained,
}

/// Store scoped to one explicit, already admitted SnapshotStore. This type has
/// no current-user/default-path constructor and never opens recovery state.
pub struct FileDeleteStore {
    base: Arc<SnapshotStore>,
}

impl FileDeleteStore {
    pub fn new(base: Arc<SnapshotStore>) -> Result<Arc<Self>, StoreError> {
        base.policy.validate()?;
        base.root.verify()?;
        Ok(Arc::new(Self { base }))
    }

    /// Publish a fresh explicit user-delete intent under the existing v2 quota lock. Only the exact
    /// newly created and reopened record returns Fresh; retained history never
    /// supplies dispatch authority.
    pub fn publish_intent(
        self: &Arc<Self>,
        mut intent: NamespaceIntent,
    ) -> Result<FileDeletePublishResult, StoreError> {
        intent.validate().map_err(|_| StoreError::Invalid)?;
        if !supported_intent(&intent) {
            return Err(StoreError::Invalid);
        }
        let source_scope = match &intent.operation {
            NamespaceOperation::DeleteFile { source }
            | NamespaceOperation::DeleteDirectory { source } => &source.local.parent.scope,
            _ => return Err(StoreError::Invalid),
        };
        if source_scope != &self.base.scope {
            return Err(StoreError::Invalid);
        }
        let _quota = self.acquire_quota(true)?;
        let mut budget = scan_budget(self.base.policy)?;
        let histories = self.discover_account_root_while_locked(&mut budget, true)?;
        if histories.iter().any(|history| {
            same_operation(&history.intent, &intent)
                || (!history.progress.recorded_complete
                    && conflicts_with_unresolved(&history.intent, &intent))
        }) {
            return Ok(FileDeletePublishResult::Retained);
        }

        // Caller identity is never accepted as the store-generated record ID.
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| StoreError::Io)?;
        intent.record_id = hex(&random);
        intent.validate().map_err(|_| StoreError::Invalid)?;
        let context = intent.event_context().map_err(|_| StoreError::Invalid)?;
        let key = RecordKey {
            scope: scope_key(&self.base.scope)?,
            id: intent.record_id.clone(),
            generation: intent.record_generation,
            digest: context.intent_sha256,
        };
        let plain = Zeroizing::new(serde_json::to_vec(&intent).map_err(|_| StoreError::Invalid)?);
        let sealed = self.seal(&key, 0, &[0; 32], &plain)?;
        let bytes = serde_json::to_vec(&Envelope {
            generation: key.generation,
            digest: key.digest.clone(),
            sealed,
        })
        .map_err(|_| StoreError::Invalid)?;
        if bytes.len() > META_LIMIT {
            return Err(StoreError::Invalid);
        }

        let inventory = self.base.inventory()?;
        let reserve_bytes = (META_LIMIT as u64)
            .checked_mul(2)
            .ok_or(StoreError::Quota)?;
        if inventory
            .bytes
            .checked_add(reserve_bytes)
            .is_none_or(|bytes| bytes > self.base.policy.max_state_bytes)
        {
            return Err(StoreError::Quota);
        }
        if inventory
            .entries
            .checked_add(6)
            .is_none_or(|entries| entries > self.base.policy.max_entries)
        {
            return Err(StoreError::ScanLimit);
        }

        let root = self.root(true)?;
        let directory = self.ensure_scope(&root, &self.base.scope, &mut budget)?;
        persist_metadata(&*directory, &format!("{}.intent", key.id), &bytes)?;
        let loaded = self.load_record(&*directory, &self.base.scope, &key.id, &mut budget)?;
        if loaded.key != key || loaded.intent != intent || loaded.progress.sequence != 0 {
            return Err(StoreError::PublicationUncertain);
        }
        Ok(FileDeletePublishResult::Fresh(PublishedFileDeleteIntent {
            store: Arc::clone(self),
            directory,
            loaded: Box::new(loaded),
            fresh: true,
        }))
    }

    /// Authenticated, read-only records in the exact physical account/root
    /// group. The caller cannot acquire or mint fresh publication custody from
    /// this result.
    pub fn discover_account_root(&self) -> Result<Vec<FileDeleteHistory>, StoreError> {
        let mut policy = self.base.policy;
        policy.max_entries = policy.max_entries.min(20_000);
        policy.max_metadata_bytes_per_scan =
            policy.max_metadata_bytes_per_scan.min(64 * 1024 * 1024);
        policy.validate()?;
        let root_names = self.base.root.entries(policy.max_entries)?;
        if !root_names.iter().any(|name| name == V2_QUOTA_LOCK) {
            if !root_names.is_empty() {
                return Err(StoreError::IncompleteEvidence);
            }
            return Ok(Vec::new());
        }
        let mut lock = self.base.root.open_quota_lock()?;
        if lock.len()? != 0 {
            return Err(StoreError::CorruptEvidence);
        }
        lock.lock_exclusive()?;
        lock.verify()?;
        let mut budget = scan_budget(policy)?;
        let histories = self.discover_account_root_while_locked(&mut budget, false)?;
        self.base.root.verify()?;
        lock.verify()?;
        Ok(histories)
    }

    /// Authenticated namespace-delete scope catalogs. The shared quota lock is
    /// opened and locked only if it already exists; this method creates none.
    pub fn discover_scopes(&self) -> Result<Vec<EditJournalScope>, StoreError> {
        let names = self.base.root.entries(self.base.policy.max_entries)?;
        if !names.iter().any(|name| name == V2_QUOTA_LOCK) {
            if !names.is_empty() {
                return Err(StoreError::IncompleteEvidence);
            }
            return Ok(Vec::new());
        }
        let mut budget = scan_budget(self.base.policy)?;
        let mut lock = self.base.root.open_quota_lock()?;
        if lock.len()? != 0 {
            return Err(StoreError::CorruptEvidence);
        }
        lock.lock_exclusive()?;
        lock.verify()?;
        let current_names = self.base.root.entries(budget.remaining_entries())?;
        budget.entries(current_names.len())?;
        let scopes = self.validate_global_catalogs(&current_names, &mut budget, false)?;
        self.base.root.verify()?;
        lock.verify()?;
        Ok(scopes)
    }

    fn reserve(&self, bytes: u64, entries: usize) -> Result<Box<dyn Send>, StoreError> {
        let lock = self.acquire_quota(false)?;
        let inventory = self.base.inventory()?;
        if inventory
            .bytes
            .checked_add(bytes)
            .is_none_or(|total| total > self.base.policy.max_state_bytes)
        {
            return Err(StoreError::Quota);
        }
        if inventory
            .entries
            .checked_add(entries)
            .is_none_or(|total| total > self.base.policy.max_entries)
        {
            return Err(StoreError::ScanLimit);
        }
        Ok(Box::new(lock))
    }

    fn acquire_quota(&self, allow_first_use: bool) -> Result<Box<dyn PinnedRead>, StoreError> {
        let names = self.base.root.entries(self.base.policy.max_entries)?;
        if names.iter().any(|name| name == V2_QUOTA_LOCK) {
            if !allow_first_use && !names.iter().any(|name| name == ROOT) {
                return Err(StoreError::IncompleteEvidence);
            }
            let mut lock = self.base.root.open_quota_lock()?;
            if lock.len()? != 0 {
                return Err(StoreError::CorruptEvidence);
            }
            lock.lock_exclusive()?;
            lock.verify()?;
            self.base.root.verify()?;
            return Ok(lock);
        }
        if allow_first_use && names.is_empty() {
            return self.base.acquire_lock();
        }
        Err(StoreError::IncompleteEvidence)
    }

    fn root(&self, create: bool) -> Result<Arc<dyn Directory>, StoreError> {
        let names = self.base.root.entries(self.base.policy.max_entries)?;
        let exists = names.iter().any(|name| name == ROOT);
        self.base.root.child(ROOT, create && !exists)
    }

    fn ensure_scope(
        &self,
        root: &Arc<dyn Directory>,
        scope: &EditJournalScope,
        budget: &mut Budget,
    ) -> Result<Arc<dyn Directory>, StoreError> {
        let key = scope_key(scope)?;
        let catalog_name = format!("{key}.scope");
        let names = root.entries(budget.remaining_entries())?;
        budget.entries(names.len())?;
        let has_catalog = names.contains(&catalog_name);
        let has_directory = names.contains(&key);
        if has_catalog != has_directory {
            return Err(StoreError::IncompleteEvidence);
        }
        if !has_catalog {
            let sealed = self.seal_scope(&key, scope)?;
            persist_metadata(&**root, &catalog_name, &sealed)?;
            root.child(&key, true)?;
        } else {
            let actual = authenticate_scope(&**root, &*self.base.protector, &key, budget)?;
            if actual != *scope {
                return Err(StoreError::CorruptEvidence);
            }
        }
        root.child(&key, false)
    }

    fn seal_scope(&self, key: &str, scope: &EditJournalScope) -> Result<Vec<u8>, StoreError> {
        let aad = scope_aad(key);
        let plaintext = Zeroizing::new(serde_json::to_vec(scope).map_err(|_| StoreError::Invalid)?);
        let sealed = self
            .base
            .protector
            .seal(&aad, &plaintext)
            .map_err(|_| StoreError::CorruptEvidence)?;
        if sealed.is_empty() || sealed.len() > META_LIMIT / 2 {
            return Err(StoreError::Invalid);
        }
        Ok(sealed)
    }

    fn seal(
        &self,
        key: &RecordKey,
        sequence: u64,
        previous: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        if plaintext.len() > META_LIMIT / 2 {
            return Err(StoreError::Invalid);
        }
        let aad = record_aad(&self.base.scope, key, sequence, previous)?;
        let sealed = self
            .base
            .protector
            .seal(&aad, plaintext)
            .map_err(|_| StoreError::CorruptEvidence)?;
        if sealed.is_empty() || sealed.len() > META_LIMIT / 2 {
            return Err(StoreError::Invalid);
        }
        Ok(sealed)
    }

    fn discover_account_root_while_locked(
        &self,
        budget: &mut Budget,
        include_requested_scope: bool,
    ) -> Result<Vec<FileDeleteHistory>, StoreError> {
        let root_names = self.base.root.entries(budget.remaining_entries())?;
        budget.entries(root_names.len())?;
        let delete_scopes =
            self.validate_global_catalogs(&root_names, budget, include_requested_scope)?;
        if !root_names.iter().any(|name| name == ROOT) {
            self.base.root.verify()?;
            return Ok(Vec::new());
        }
        let root = self.base.root.child(ROOT, false)?;

        let mut result = Vec::new();
        for scope in delete_scopes {
            let key = scope_key(&scope)?;
            let directory = root.child(&key, false)?;
            let record_names = record_names(&*directory, budget)?;
            if account_root_matches(&scope, &self.base.scope) {
                let remaining = MAX_RECORDS
                    .checked_sub(result.len())
                    .ok_or(StoreError::ScanLimit)?;
                let records =
                    self.load_records(&*directory, &scope, &record_names, budget, remaining)?;
                result.extend(records.into_iter().map(history));
            }
            directory.verify()?;
        }
        root.verify()?;
        self.base.root.verify()?;
        Ok(result)
    }

    fn validate_global_catalogs(
        &self,
        root_names: &[String],
        budget: &mut Budget,
        include_requested_scope: bool,
    ) -> Result<Vec<EditJournalScope>, StoreError> {
        let mut catalogs = self
            .base
            .validate_root_catalogs_with_scope_union(root_names, budget)?;
        if include_requested_scope {
            catalogs.keys.insert(self.base.key.clone());
        }
        check_scope_union(&catalogs.keys)?;
        Ok(catalogs.delete)
    }

    fn load_records(
        &self,
        directory: &dyn Directory,
        scope: &EditJournalScope,
        names: &[String],
        budget: &mut Budget,
        record_limit: usize,
    ) -> Result<Vec<Loaded>, StoreError> {
        let mut ids = BTreeSet::new();
        for name in names {
            let (id, suffix) = name.split_once('.').ok_or(StoreError::IncompleteEvidence)?;
            if !valid_id(id)
                || !(suffix == "intent"
                    || suffix == "dispatch.lock"
                    || parse_event(suffix).is_some())
                || !names.contains(&format!("{id}.intent"))
            {
                return Err(StoreError::IncompleteEvidence);
            }
            if suffix == "dispatch.lock" && directory.open(name)?.len()? != 0 {
                return Err(StoreError::CorruptEvidence);
            }
            ids.insert(id.to_owned());
        }
        if ids.len() > record_limit {
            return Err(StoreError::ScanLimit);
        }
        ids.into_iter()
            .map(|id| self.load_record_with_names(directory, scope, &id, names, budget))
            .collect()
    }

    fn load_record(
        &self,
        directory: &dyn Directory,
        scope: &EditJournalScope,
        id: &str,
        budget: &mut Budget,
    ) -> Result<Loaded, StoreError> {
        let names = record_names(directory, budget)?;
        self.load_record_with_names(directory, scope, id, &names, budget)
    }

    fn load_record_with_names(
        &self,
        directory: &dyn Directory,
        scope: &EditJournalScope,
        id: &str,
        names: &[String],
        budget: &mut Budget,
    ) -> Result<Loaded, StoreError> {
        load_record_with_names(&*self.base.protector, directory, scope, id, names, budget)
    }
}

impl PublishedFileDeleteIntent {
    /// Consume the publication receipt and acquire this record's exclusive
    /// zero-length operation lock. Any failure loses fresh custody.
    pub fn acquire_dispatch(mut self) -> Result<FileDeleteLease, StoreError> {
        if !self.fresh || !pristine(self.loaded.progress) {
            return Err(StoreError::Invalid);
        }
        let quota = self.store.reserve(0, 1)?;
        let lock_name = format!("{}.dispatch.lock", self.loaded.key.id);
        let names = self.directory.entries(self.store.base.policy.max_entries)?;
        if names.contains(&lock_name) {
            return Err(StoreError::IncompleteEvidence);
        }
        let (file, _) = self.directory.create(&lock_name)?;
        file.sync()?;
        drop(file);
        drop(quota);
        let mut lock = self.directory.open(&lock_name)?;
        if lock.len()? != 0 {
            return Err(StoreError::CorruptEvidence);
        }
        lock.lock_exclusive()?;
        lock.verify()?;
        let loaded = self.store.load_record(
            &*self.directory,
            &self.store.base.scope,
            &self.loaded.key.id,
            &mut Budget::new(self.store.base.policy),
        )?;
        if loaded.key != self.loaded.key
            || loaded.intent != self.loaded.intent
            || !pristine(loaded.progress)
        {
            self.fresh = false;
            return Err(StoreError::CorruptEvidence);
        }
        self.fresh = false;
        Ok(FileDeleteLease {
            store: Arc::clone(&self.store),
            directory: Arc::clone(&self.directory),
            _lock: lock,
            loaded,
            fresh: true,
            poisoned: false,
        })
    }
}

pub struct FileDeleteLease {
    store: Arc<FileDeleteStore>,
    directory: Arc<dyn Directory>,
    _lock: Box<dyn PinnedRead>,
    loaded: Loaded,
    fresh: bool,
    poisoned: bool,
}
impl FileDeleteLease {
    pub fn intent(&self) -> &NamespaceIntent {
        &self.loaded.intent
    }
    pub fn progress(&self) -> NamespaceProgressSnapshot {
        if self.fresh {
            self.loaded.progress
        } else {
            recovered(self.loaded.progress)
        }
    }
    pub fn append_event(&mut self, event: NamespaceEventKind) -> Result<(), StoreError> {
        let result = self.append_event_inner(event);
        if result.is_err() {
            self.fresh = false;
            self.poisoned = true;
        }
        result
    }
    fn append_event_inner(&mut self, kind: NamespaceEventKind) -> Result<(), StoreError> {
        if self.poisoned || !self.fresh {
            return Err(StoreError::PublicationUncertain);
        }
        if !allowed_event(&kind) {
            return Err(StoreError::Invalid);
        }
        let prior = self.progress();
        if prior.attention.is_some()
            || prior.recorded_complete
            || prior.sequence >= MAX_EVENTS as u64
        {
            return Err(StoreError::Invalid);
        }
        let context = self
            .loaded
            .intent
            .event_context()
            .map_err(|_| StoreError::Invalid)?;
        let event = NamespaceEvent {
            context,
            sequence: prior.sequence + 1,
            event: kind,
        };
        let mut checked = self.store.load_record(
            &*self.directory,
            &self.store.base.scope,
            &self.loaded.key.id,
            &mut Budget::new(self.store.base.policy),
        )?;
        if checked.key != self.loaded.key
            || checked.intent != self.loaded.intent
            || checked.commitment != self.loaded.commitment
        {
            return Err(StoreError::CorruptEvidence);
        }
        if !typed_transition_allowed(checked.checker.snapshot(), &event.event) {
            return Err(StoreError::Invalid);
        }
        checked
            .checker
            .record(&event)
            .map_err(|_| StoreError::Invalid)?;
        let plaintext =
            Zeroizing::new(serde_json::to_vec(&event).map_err(|_| StoreError::Invalid)?);
        let bytes = self.store.seal(
            &self.loaded.key,
            event.sequence,
            &self.loaded.commitment,
            &plaintext,
        )?;
        let _quota = self.store.reserve(bytes.len() as u64, 2)?;
        let filename = format!("{}.event.{:020}", self.loaded.key.id, event.sequence);
        persist_metadata(&*self.directory, &filename, &bytes)?;
        let loaded = self.store.load_record(
            &*self.directory,
            &self.store.base.scope,
            &self.loaded.key.id,
            &mut Budget::new(self.store.base.policy),
        )?;
        let expected_commitment = commitment(&self.loaded.commitment, &plaintext);
        if loaded.key != self.loaded.key
            || loaded.intent != self.loaded.intent
            || loaded.progress.sequence != event.sequence
            || loaded.commitment != expected_commitment
        {
            return Err(StoreError::PublicationUncertain);
        }
        self.loaded = loaded;
        Ok(())
    }
}

impl crate::namespace_file_delete::FileDeleteJournal for FileDeleteLease {
    fn owns_fresh_user_delete(&self) -> bool {
        self.fresh && !self.poisoned
    }
    fn intent(&self) -> &NamespaceIntent {
        self.intent()
    }
    fn progress(&self) -> NamespaceProgressSnapshot {
        self.progress()
    }
    fn append_event(&mut self, event: NamespaceEventKind) -> Result<(), StoreError> {
        self.append_event(event).map(|_| ())
    }
}

fn pristine(progress: NamespaceProgressSnapshot) -> bool {
    progress.sequence == 0
        && progress.remote == NamespacePhase::Pending
        && progress.source_removal.is_none()
        && progress.attention.is_none()
        && !progress.local_completed
        && !progress.recorded_complete
}

fn recovered(progress: NamespaceProgressSnapshot) -> NamespaceProgressSnapshot {
    if progress.remote == NamespacePhase::Submitted && progress.attention.is_none() {
        let mut progress = progress;
        progress.attention = Some(crate::namespace_intent::NamespaceAttention::Uncertain);
        progress
    } else {
        progress
    }
}

fn history(loaded: Loaded) -> FileDeleteHistory {
    FileDeleteHistory {
        intent: loaded.intent,
        progress: recovered(loaded.progress),
    }
}

fn allowed_event(event: &NamespaceEventKind) -> bool {
    matches!(
        event,
        NamespaceEventKind::RemoteSubmitted
            | NamespaceEventKind::RemoteDeleted { .. }
            | NamespaceEventKind::LocalDeleted { .. }
            | NamespaceEventKind::Conflict
            | NamespaceEventKind::Deferred
            | NamespaceEventKind::Uncertain
    )
}

fn typed_transition_allowed(
    progress: NamespaceProgressSnapshot,
    event: &NamespaceEventKind,
) -> bool {
    if progress.source_removal.is_some()
        || progress.attention.is_some()
        || progress.recorded_complete
    {
        return false;
    }
    match event {
        NamespaceEventKind::RemoteSubmitted => pristine(progress),
        NamespaceEventKind::RemoteDeleted { .. } => {
            progress.remote == NamespacePhase::Submitted && !progress.local_completed
        }
        NamespaceEventKind::LocalDeleted { .. } => {
            progress.remote == NamespacePhase::Verified && !progress.local_completed
        }
        _ => true,
    }
}

fn supported_intent(intent: &NamespaceIntent) -> bool {
    let Some(source) = delete_source(intent) else {
        return false;
    };
    let parent = &source.local.parent;
    matches!(
        source.local.object_kind,
        NamespaceObjectKind::File | NamespaceObjectKind::Directory
    ) && (source.local.object_kind != NamespaceObjectKind::Directory || source.remote.byte_len == 0)
        && (parent.local_components.first().map(String::as_str) == Some("Personal")
            || (parent.local_components.first().map(String::as_str) == Some("Spaces")
                && parent.local_components.len() >= 2))
        && [
            &source.remote.resource_id,
            &parent.remote.resource_id,
            &parent.scope.root_resource_id,
        ]
        .iter()
        .all(|id| {
            !id.to_ascii_lowercase().starts_with("http://")
                && !id.to_ascii_lowercase().starts_with("https://")
        })
}
fn same_operation(a: &NamespaceIntent, b: &NamespaceIntent) -> bool {
    a.schema_version == b.schema_version
        && a.record_generation == b.record_generation
        && a.operation == b.operation
}
fn conflicts_with_unresolved(existing: &NamespaceIntent, requested: &NamespaceIntent) -> bool {
    let (Some(old), Some(new)) = (delete_source(existing), delete_source(requested)) else {
        return true;
    };
    old.local.local_file == new.local.local_file
        || old.remote.resource_id == new.remote.resource_id
        || (old.local.parent.local_file == new.local.parent.local_file
            && old.local.parent.scope == new.local.parent.scope
            && old.local.name.eq_ignore_ascii_case(&new.local.name))
}
fn delete_source(intent: &NamespaceIntent) -> Option<&ExistingNamespaceEntry> {
    match &intent.operation {
        NamespaceOperation::DeleteFile { source }
        | NamespaceOperation::DeleteDirectory { source } => Some(source),
        _ => None,
    }
}

fn account_root_matches(a: &EditJournalScope, b: &EditJournalScope) -> bool {
    a.profile_id == b.profile_id
        && a.server_origin == b.server_origin
        && a.account_subject == b.account_subject
        && a.root_volume_serial == b.root_volume_serial
        && a.root_file_index == b.root_file_index
}

fn scan_budget(policy: StorePolicy) -> Result<Budget, StoreError> {
    let mut policy = policy;
    policy.max_entries = policy.max_entries.min(20_000);
    policy.max_metadata_bytes_per_scan = policy.max_metadata_bytes_per_scan.min(64 * 1024 * 1024);
    policy.validate()?;
    Ok(Budget::new(policy))
}

fn authenticate_scope(
    root: &dyn Directory,
    protector: &dyn EditRecordProtector,
    key: &str,
    budget: &mut Budget,
) -> Result<EditJournalScope, StoreError> {
    let sealed = read_metadata(root, &format!("{key}.scope"), budget)?;
    let plaintext = Zeroizing::new(
        protector
            .open(&scope_aad(key), &sealed)
            .map_err(|_| StoreError::CorruptEvidence)?,
    );
    if plaintext.len() > META_LIMIT / 2 {
        return Err(StoreError::CorruptEvidence);
    }
    let scope: EditJournalScope =
        serde_json::from_slice(&plaintext).map_err(|_| StoreError::CorruptEvidence)?;
    validate_scope(&scope).map_err(|_| StoreError::CorruptEvidence)?;
    if scope_key(&scope)? != key {
        return Err(StoreError::CorruptEvidence);
    }
    Ok(scope)
}

fn record_names(directory: &dyn Directory, budget: &mut Budget) -> Result<Vec<String>, StoreError> {
    let names = directory.entries(budget.remaining_entries())?;
    budget.entries(names.len())?;
    let mut unique = HashSet::new();
    for name in &names {
        if !unique.insert(name) {
            return Err(StoreError::CorruptEvidence);
        }
        let (id, suffix) = name.split_once('.').ok_or(StoreError::IncompleteEvidence)?;
        if !valid_id(id)
            || !(suffix == "intent" || suffix == "dispatch.lock" || parse_event(suffix).is_some())
            || !names.contains(&format!("{id}.intent"))
        {
            return Err(StoreError::IncompleteEvidence);
        }
        if suffix == "dispatch.lock" && directory.open(name)?.len()? != 0 {
            return Err(StoreError::CorruptEvidence);
        }
    }
    Ok(names)
}

fn scope_aad(key: &str) -> Vec<u8> {
    [DOMAIN, b"scope\0", key.as_bytes()].concat()
}

fn record_aad(
    scope: &EditJournalScope,
    key: &RecordKey,
    sequence: u64,
    previous: &[u8; 32],
) -> Result<Vec<u8>, StoreError> {
    let mut aad = DOMAIN.to_vec();
    aad.extend(
        serde_json::to_vec(&(
            scope,
            &key.id,
            key.generation,
            &key.digest,
            sequence,
            previous,
        ))
        .map_err(|_| StoreError::Invalid)?,
    );
    Ok(aad)
}

fn commitment(previous: &[u8; 32], plaintext: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(previous);
    hash.update(plaintext);
    hash.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_event(suffix: &str) -> Option<u64> {
    let digits = suffix.strip_prefix("event.")?;
    if digits.len() != 20 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let sequence = digits.parse().ok()?;
    (sequence > 0 && sequence <= MAX_EVENTS as u64).then_some(sequence)
}

/// Authenticate every namespace-delete catalog under one aggregate budget.
/// The caller validates the surrounding v2 catalogs separately.
pub(super) fn validate_catalogs(
    root: &dyn Directory,
    protector: &dyn EditRecordProtector,
    budget: &mut Budget,
) -> Result<Vec<EditJournalScope>, StoreError> {
    root.verify()?;
    let names = root.entries(budget.remaining_entries())?;
    budget.entries(names.len())?;
    validate_catalog_names(root, protector, budget, &names)
}

fn validate_catalog_names(
    root: &dyn Directory,
    protector: &dyn EditRecordProtector,
    budget: &mut Budget,
    names: &[String],
) -> Result<Vec<EditJournalScope>, StoreError> {
    let mut unique = HashSet::new();
    let mut scopes = Vec::new();
    for name in names {
        if !unique.insert(name) {
            return Err(StoreError::CorruptEvidence);
        }
        if let Some(key) = name.strip_suffix(".scope") {
            if !valid_key(key) || !names.contains(&key.to_owned()) {
                return Err(StoreError::IncompleteEvidence);
            }
            let scope = authenticate_scope(root, protector, key, budget)?;
            root.child(key, false)?.verify()?;
            scopes.push(scope);
            if scopes.len() > MAX_SCOPES {
                return Err(StoreError::ScanLimit);
            }
        } else if !valid_key(name) || !names.contains(&format!("{name}.scope")) {
            return Err(StoreError::IncompleteEvidence);
        }
    }
    root.verify()?;
    Ok(scopes)
}

/// Count all physical metadata in this subtree. Unknown/stage entries and
/// unsafe child types fail closed; content bytes are never opened or decoded.
pub(super) fn accounted_usage(
    root: &dyn Directory,
    protector: &dyn EditRecordProtector,
    budget: &mut Budget,
) -> Result<Inventory, StoreError> {
    let scopes = validate_catalogs(root, protector, budget)?;
    let mut inventory = Inventory {
        bytes: 0,
        entries: scopes.len().checked_mul(2).ok_or(StoreError::ScanLimit)?,
    };
    let mut records = 0usize;
    for scope in scopes {
        let key = scope_key(&scope)?;
        let catalog = root.open(&format!("{key}.scope"))?;
        inventory.add(catalog.len()?)?;
        catalog.verify()?;
        let directory = root.child(&key, false)?;
        let names = record_names(&*directory, budget)?;
        authenticate_records(
            &*directory,
            protector,
            &scope,
            &names,
            budget,
            &mut records,
            MAX_RECORDS,
        )?;
        inventory.entries = inventory
            .entries
            .checked_add(names.len())
            .ok_or(StoreError::ScanLimit)?;
        for name in names {
            let file = directory.open(&name)?;
            inventory.add(file.len()?)?;
            file.verify()?;
        }
        directory.verify()?;
    }
    root.verify()?;
    Ok(inventory)
}

fn authenticate_records(
    directory: &dyn Directory,
    protector: &dyn EditRecordProtector,
    scope: &EditJournalScope,
    names: &[String],
    budget: &mut Budget,
    records: &mut usize,
    limit: usize,
) -> Result<Vec<Loaded>, StoreError> {
    let ids: BTreeSet<_> = names
        .iter()
        .map(|name| name.split_once('.').map(|(id, _)| id))
        .collect::<Option<_>>()
        .ok_or(StoreError::IncompleteEvidence)?;
    *records = records
        .checked_add(ids.len())
        .ok_or(StoreError::ScanLimit)?;
    if *records > limit {
        return Err(StoreError::ScanLimit);
    }
    ids.into_iter()
        .map(|id| load_record_with_names(protector, directory, scope, id, names, budget))
        .collect()
}

/// Borrowed authenticated health scan under the caller's existing quota lease
/// and cumulative metadata budget. No publication/dispatch custody is created.
pub(super) fn history_counts_existing(
    root: &dyn Directory,
    protector: &dyn EditRecordProtector,
    scopes: &[EditJournalScope],
    provider: &crate::ProviderScope,
    physical: crate::ConfiguredRootIdentity,
    budget: &mut Budget,
    remaining: usize,
) -> Result<(usize, usize), StoreError> {
    let mut total = 0;
    let mut matching = 0;
    let mut unresolved = 0;
    for scope in scopes {
        let directory = root.child(&scope_key(scope)?, false)?;
        let names = record_names(&*directory, budget)?;
        let rows = authenticate_records(
            &*directory,
            protector,
            scope,
            &names,
            budget,
            &mut total,
            MAX_RECORDS,
        )?;
        if scope.profile_id == provider.profile_id()
            && scope.server_origin == provider.server_origin()
            && scope.account_subject == provider.account_id()
            && scope.root_volume_serial == physical.volume_serial
            && scope.root_file_index == physical.file_index
        {
            matching += rows.len();
            if matching > remaining {
                return Err(StoreError::ScanLimit);
            }
            unresolved += rows
                .iter()
                .filter(|row| !row.progress.recorded_complete)
                .count();
        }
        directory.verify()?;
    }
    root.verify()?;
    Ok((matching, unresolved))
}

fn open_record(
    protector: &dyn EditRecordProtector,
    scope: &EditJournalScope,
    key: &RecordKey,
    sequence: u64,
    previous: &[u8; 32],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let aad = record_aad(scope, key, sequence, previous)?;
    let plaintext = Zeroizing::new(
        protector
            .open(&aad, sealed)
            .map_err(|_| StoreError::CorruptEvidence)?,
    );
    if plaintext.len() > META_LIMIT / 2 {
        return Err(StoreError::CorruptEvidence);
    }
    Ok(plaintext)
}

fn load_record_with_names(
    protector: &dyn EditRecordProtector,
    directory: &dyn Directory,
    scope: &EditJournalScope,
    id: &str,
    names: &[String],
    budget: &mut Budget,
) -> Result<Loaded, StoreError> {
    if !valid_id(id) {
        return Err(StoreError::CorruptEvidence);
    }
    let bytes = read_metadata(directory, &format!("{id}.intent"), budget)?;
    let envelope: Envelope =
        serde_json::from_slice(&bytes).map_err(|_| StoreError::CorruptEvidence)?;
    if !valid_key(&envelope.digest) || envelope.generation == 0 {
        return Err(StoreError::CorruptEvidence);
    }
    let key = RecordKey {
        scope: scope_key(scope)?,
        id: id.to_owned(),
        generation: envelope.generation,
        digest: envelope.digest,
    };
    let plaintext = open_record(protector, scope, &key, 0, &[0; 32], &envelope.sealed)?;
    let intent: NamespaceIntent =
        serde_json::from_slice(&plaintext).map_err(|_| StoreError::CorruptEvidence)?;
    if !supported_intent(&intent)
        || delete_source(&intent).is_none_or(|source| &source.local.parent.scope != scope)
        || intent.record_id != key.id
        || intent.record_generation != key.generation
        || intent
            .event_context()
            .map_err(|_| StoreError::CorruptEvidence)?
            .intent_sha256
            != key.digest
    {
        return Err(StoreError::CorruptEvidence);
    }
    let mut checker =
        NamespaceIntentProgress::new(intent.clone()).map_err(|_| StoreError::CorruptEvidence)?;
    let mut chain = commitment(&[0; 32], &plaintext);
    let mut events = Vec::new();
    for name in names {
        if let Some(suffix) = name.strip_prefix(&format!("{id}.")) {
            if suffix == "intent" || suffix == "dispatch.lock" {
                continue;
            }
            events.push((
                parse_event(suffix).ok_or(StoreError::IncompleteEvidence)?,
                name,
            ));
        }
    }
    events.sort_by_key(|(sequence, _)| *sequence);
    if events.len() > MAX_EVENTS {
        return Err(StoreError::ScanLimit);
    }
    for (index, (sequence, name)) in events.into_iter().enumerate() {
        if sequence != index as u64 + 1 {
            return Err(StoreError::IncompleteEvidence);
        }
        let bytes = read_metadata(directory, name, budget)?;
        let plaintext = open_record(protector, scope, &key, sequence, &chain, &bytes)?;
        let event: NamespaceEvent =
            serde_json::from_slice(&plaintext).map_err(|_| StoreError::CorruptEvidence)?;
        if !allowed_event(&event.event)
            || !typed_transition_allowed(checker.snapshot(), &event.event)
        {
            return Err(StoreError::CorruptEvidence);
        }
        checker
            .record(&event)
            .map_err(|_| StoreError::CorruptEvidence)?;
        chain = commitment(&chain, &plaintext);
    }
    Ok(Loaded {
        key,
        intent,
        progress: checker.snapshot(),
        checker,
        commitment: chain,
    })
}

#[cfg(all(test, unix))]
mod tests {
    // Persistent synthetic disk only; this does not qualify Windows ACL/DPAPI.
    use super::*;
    use crate::namespace_file_delete::FileDeleteJournal;
    use crate::namespace_intent::{
        CapturedAuthorization, LocalNamespaceEntry, NamespaceParent, StorageClassification,
    };
    use crate::{LocalFileIdentity, RemoteEditBaseline};
    use std::sync::atomic::{AtomicU8, Ordering};

    fn policy() -> StorePolicy {
        StorePolicy {
            max_content_bytes: 8 * 1024 * 1024,
            max_state_bytes: 32 * 1024 * 1024,
            max_entries: 2048,
            max_metadata_bytes_per_scan: 4 * 1024 * 1024,
        }
    }
    fn fixture() -> (tempfile::TempDir, Arc<SnapshotStore>, Arc<FileDeleteStore>) {
        let (temp, base) = super::super::synthetic_test_store(policy());
        let store = FileDeleteStore::new(Arc::clone(&base)).unwrap();
        (temp, base, store)
    }
    fn intent(base: &SnapshotStore, generation: u64) -> NamespaceIntent {
        NamespaceIntent {
            schema_version: 1,
            record_id: "0".repeat(32),
            record_generation: generation,
            operation: NamespaceOperation::DeleteFile {
                source: ExistingNamespaceEntry {
                    local: LocalNamespaceEntry {
                        parent: NamespaceParent {
                            scope: base.scope.clone(),
                            authorization: CapturedAuthorization {
                                agent_generation: 3,
                                token_generation: 5,
                            },
                            classification: StorageClassification::Ordinary,
                            local_file: LocalFileIdentity {
                                volume_serial: base.scope.root_volume_serial,
                                file_index: 20,
                            },
                            local_components: vec!["Personal".into(), "Documents".into()],
                            remote: RemoteEditBaseline {
                                resource_id: "opaque-parent-id".into(),
                                etag: "\"parent-etag\"".into(),
                                byte_len: 0,
                            },
                        },
                        name: "document.txt".into(),
                        local_file: LocalFileIdentity {
                            volume_serial: base.scope.root_volume_serial,
                            file_index: 40,
                        },
                        object_kind: NamespaceObjectKind::File,
                    },
                    remote: RemoteEditBaseline {
                        resource_id: "opaque-file-id".into(),
                        etag: "\"source-etag\"".into(),
                        byte_len: 19,
                    },
                },
            },
        }
    }
    fn fresh(result: FileDeletePublishResult) -> PublishedFileDeleteIntent {
        match result {
            FileDeletePublishResult::Fresh(value) => value,
            FileDeletePublishResult::Retained => panic!("expected new publication custody"),
        }
    }
    fn reopen(base: &SnapshotStore, policy: StorePolicy) -> Arc<SnapshotStore> {
        SnapshotStore::from_directory(
            Arc::clone(&base.root),
            base.scope.clone(),
            Arc::clone(&base.protector),
            policy,
        )
        .unwrap()
    }
    fn summary(
        base: &SnapshotStore,
    ) -> Result<namespace_rename_store::NamespaceHistorySummary, StoreError> {
        let client = raiun_opencloud::OpenCloudClient::new_with_proxy(
            &base.scope.server_origin,
            "synthetic-token".into(),
            &raiun_opencloud::ProxyConfig::Direct,
        )
        .unwrap();
        let provider = crate::ProviderScope::new(
            &client,
            base.scope.profile_id.clone(),
            base.scope.account_subject.clone(),
            base.scope.server_origin.clone(),
        )
        .unwrap();
        namespace_rename_store::history_summary_existing(
            Some(Arc::clone(&base.root)),
            Arc::clone(&base.protector),
            base.policy,
            &provider,
            crate::ConfiguredRootIdentity {
                volume_serial: base.scope.root_volume_serial,
                file_index: base.scope.root_file_index,
            },
        )
    }
    fn rename_intent(base: &SnapshotStore) -> NamespaceIntent {
        let mut intent = intent(base, 80);
        let source = delete_source(&intent).unwrap().clone();
        let mut destination = source.local.clone();
        destination.name = "renamed.txt".into();
        intent.operation = NamespaceOperation::MoveWithinScope {
            source,
            destination,
        };
        intent
    }

    #[test]
    fn persistent_reopen_authenticates_delete_chain_and_fails_closed_on_corruption_or_unsupported_intent()
     {
        let (temp, base, store) = fixture();
        let publication = fresh(store.publish_intent(intent(&base, 8)).unwrap());
        let mut lease = publication.acquire_dispatch().unwrap();
        let source = delete_source(lease.intent()).unwrap().clone();
        let id = lease.intent().record_id.clone();
        lease
            .append_event(NamespaceEventKind::RemoteSubmitted)
            .unwrap();
        lease
            .append_event(NamespaceEventKind::RemoteDeleted {
                source: source.clone(),
            })
            .unwrap();
        lease
            .append_event(NamespaceEventKind::LocalDeleted { source })
            .unwrap();
        assert!(lease.progress().recorded_complete);
        let key = lease.loaded.key.clone();
        let authenticated_intent = lease.intent().clone();
        drop(lease);
        drop(store);
        let reopened = FileDeleteStore::new(reopen(&base, policy())).unwrap();
        let history = reopened.discover_account_root().unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].intent, authenticated_intent);
        assert!(history[0].progress.recorded_complete);
        let counts = summary(&base).unwrap();
        assert_eq!((counts.delete_records, counts.delete_unresolved), (1, 0));
        assert_eq!(
            namespace_rename_store::history_unresolved(&counts, true),
            Ok(false)
        );
        assert!(namespace_rename_store::history_unresolved(&counts, false).is_err());

        let directory = temp.path().join(ROOT).join(scope_key(&base.scope).unwrap());
        let event_path = directory.join(format!("{id}.event.{:020}", 1));
        let original_event = std::fs::read(&event_path).unwrap();
        let mut corrupt = original_event.clone();
        corrupt[0] ^= 1;
        std::fs::write(&event_path, corrupt).unwrap();
        assert!(reopened.discover_account_root().is_err());
        assert!(base.inventory().is_err());
        assert!(summary(&base).is_err());
        std::fs::write(&event_path, original_event).unwrap();

        // An authenticated but unsupported directory-delete intent also fails
        // shared inventory/health, rather than being counted as clean metadata.
        let mut unsupported = authenticated_intent;
        let mut directory_source = delete_source(&unsupported).unwrap().clone();
        directory_source.local.object_kind = NamespaceObjectKind::Directory;
        unsupported.operation = NamespaceOperation::DeleteDirectory {
            source: directory_source,
        };
        let wrong_key = RecordKey {
            digest: unsupported.event_context().unwrap().intent_sha256,
            ..key
        };
        let sealed = reopened
            .seal(
                &wrong_key,
                0,
                &[0; 32],
                &serde_json::to_vec(&unsupported).unwrap(),
            )
            .unwrap();
        let envelope = serde_json::to_vec(&Envelope {
            generation: wrong_key.generation,
            digest: wrong_key.digest,
            sealed,
        })
        .unwrap();
        std::fs::write(directory.join(format!("{id}.intent")), envelope).unwrap();
        assert!(reopened.discover_account_root().is_err());
        assert!(base.inventory().is_err());
        assert!(summary(&base).is_err());
    }

    #[test]
    fn fresh_receipt_is_consumed_into_exclusive_lease_and_discovery_never_recreates_custody() {
        let (_temp, base, store) = fixture();
        let original = intent(&base, 8);
        let publication = fresh(store.publish_intent(original.clone()).unwrap());
        assert_eq!(
            store.discover_account_root().unwrap()[0].progress.sequence,
            0
        );
        assert!(matches!(
            store.publish_intent(original.clone()).unwrap(),
            FileDeletePublishResult::Retained
        ));
        let mut lease = publication.acquire_dispatch().unwrap();
        assert!(lease.owns_fresh_user_delete());
        let mut contender = lease
            .directory
            .open(&format!("{}.dispatch.lock", lease.intent().record_id))
            .unwrap();
        assert_eq!(contender.lock_exclusive().unwrap_err(), StoreError::Busy);
        drop(contender);
        lease
            .append_event(NamespaceEventKind::RemoteSubmitted)
            .unwrap();
        drop(lease);
        let reopened = FileDeleteStore::new(reopen(&base, policy())).unwrap();
        let history = reopened.discover_account_root().unwrap();
        assert_eq!(history[0].progress.remote, NamespacePhase::Submitted);
        assert_eq!(
            history[0].progress.attention,
            Some(crate::namespace_intent::NamespaceAttention::Uncertain)
        );
        assert!(matches!(
            reopened.publish_intent(original).unwrap(),
            FileDeletePublishResult::Retained
        ));
        assert!(matches!(
            reopened.publish_intent(intent(&base, 9)).unwrap(),
            FileDeletePublishResult::Retained
        ));
        let counts = summary(&base).unwrap();
        assert_eq!((counts.delete_records, counts.delete_unresolved), (1, 1));
        assert_eq!(
            namespace_rename_store::history_unresolved(&counts, true),
            Ok(true)
        );
    }

    // Inject failures AFTER the actual persistent operation. This tests loss of
    // its result rather than merely rejecting a transition before writing.
    struct FaultDirectory {
        inner: Arc<dyn Directory>,
        fault: Arc<AtomicU8>,
    }
    impl Directory for FaultDirectory {
        fn verify(&self) -> Result<(), StoreError> {
            self.inner.verify()
        }
        fn external_recovery_usage(&self, policy: StorePolicy) -> Result<(u64, usize), StoreError> {
            self.inner.external_recovery_usage(policy)
        }
        fn entries(&self, limit: usize) -> Result<Vec<String>, StoreError> {
            self.inner.entries(limit)
        }
        fn child(&self, name: &str, create: bool) -> Result<Arc<dyn Directory>, StoreError> {
            Ok(Arc::new(Self {
                inner: self.inner.child(name, create)?,
                fault: Arc::clone(&self.fault),
            }))
        }
        fn create(&self, name: &str) -> Result<(Box<dyn StageWrite>, Identity), StoreError> {
            let result = self.inner.create(name)?;
            if name.ends_with(".dispatch.lock") && self.fault.load(Ordering::SeqCst) == 2 {
                return Err(StoreError::PublicationUncertain);
            }
            Ok(result)
        }
        fn open(&self, name: &str) -> Result<Box<dyn PinnedRead>, StoreError> {
            self.inner.open(name)
        }
        fn open_quota_lock(&self) -> Result<Box<dyn PinnedRead>, StoreError> {
            self.inner.open_quota_lock()
        }
        fn publish(
            &self,
            stage: &str,
            final_name: &str,
            identity: Identity,
        ) -> Result<(), StoreError> {
            self.inner.publish(stage, final_name, identity)?;
            let fault = self.fault.load(Ordering::SeqCst);
            if (fault == 1 && final_name.ends_with(".intent"))
                || (fault == 3 && final_name.contains(".event."))
            {
                return Err(StoreError::PublicationUncertain);
            }
            Ok(())
        }
    }
    #[test]
    fn uncertain_publication_acquisition_and_append_permanently_lose_fresh_custody() {
        for phase in [1, 2, 3] {
            let (_temp, base, _) = fixture();
            let fault = Arc::new(AtomicU8::new(phase));
            let injected = SnapshotStore::from_directory(
                Arc::new(FaultDirectory {
                    inner: Arc::clone(&base.root),
                    fault: Arc::clone(&fault),
                }),
                base.scope.clone(),
                Arc::clone(&base.protector),
                policy(),
            )
            .unwrap();
            let store = FileDeleteStore::new(injected).unwrap();
            let candidate = intent(&base, 8);
            if phase == 1 {
                assert!(matches!(
                    store.publish_intent(candidate.clone()),
                    Err(StoreError::PublicationUncertain)
                ));
            } else {
                let publication = fresh(store.publish_intent(candidate.clone()).unwrap());
                if phase == 2 {
                    assert!(matches!(
                        publication.acquire_dispatch(),
                        Err(StoreError::PublicationUncertain)
                    ));
                } else {
                    let mut lease = publication.acquire_dispatch().unwrap();
                    assert_eq!(
                        lease.append_event(NamespaceEventKind::RemoteSubmitted),
                        Err(StoreError::PublicationUncertain)
                    );
                    assert!(!lease.owns_fresh_user_delete());
                    assert_eq!(
                        lease.append_event(NamespaceEventKind::RemoteSubmitted),
                        Err(StoreError::PublicationUncertain)
                    );
                }
            }
            fault.store(0, Ordering::SeqCst);
            assert!(matches!(
                store.publish_intent(candidate).unwrap(),
                FileDeletePublishResult::Retained
            ));
            let history = store.discover_account_root().unwrap();
            assert_eq!(history.len(), 1);
            if phase == 3 {
                assert_eq!(
                    history[0].progress.attention,
                    Some(crate::namespace_intent::NamespaceAttention::Uncertain)
                );
            }
        }
    }

    #[test]
    fn delete_metadata_shares_exact_inventory_and_quota_with_existing_namespace_writers() {
        let (temp, base, store) = fixture();
        drop(fresh(store.publish_intent(intent(&base, 8)).unwrap()));
        let inventory = base.inventory().unwrap();
        fn physical(path: &std::path::Path) -> (u64, usize) {
            let mut usage = (0, 0);
            for entry in std::fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                usage.1 += 1;
                if entry.file_type().unwrap().is_dir() {
                    let child = physical(&entry.path());
                    usage.0 += child.0;
                    usage.1 += child.1;
                } else {
                    usage.0 += entry.metadata().unwrap().len();
                }
            }
            usage
        }
        assert_eq!((inventory.bytes, inventory.entries), physical(temp.path()));
        let mut constrained = policy();
        constrained.max_state_bytes = inventory.bytes + 2 * META_LIMIT as u64 - 1;
        let limited_base = reopen(&base, constrained);
        let rename = namespace_rename_store::FileRenameStore::new(limited_base).unwrap();
        assert!(matches!(
            rename.publish_intent(rename_intent(&base)),
            Err(StoreError::Quota)
        ));
        assert!(
            !base
                .root
                .entries(policy().max_entries)
                .unwrap()
                .contains(&namespace_rename_store::ROOT.to_owned())
        );
        // Same quota on an empty state admits the existing rename writer: the
        // refusal above comes from retained delete bytes, not a too-small limit.
        let (_clean_temp, clean_base) = super::super::synthetic_test_store(constrained);
        let rename = namespace_rename_store::FileRenameStore::new(Arc::clone(&clean_base)).unwrap();
        assert!(matches!(
            rename.publish_intent(rename_intent(&clean_base)).unwrap(),
            namespace_rename_store::FileRenamePublishResult::Fresh(_)
        ));
    }
}

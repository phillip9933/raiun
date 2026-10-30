//! Durable metadata for one same-parent Personal file rename.
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

pub(super) const ROOT: &str = "namespace-rename-v1";
const DOMAIN: &[u8] = b"raiun/namespace-rename-store/v1\0";
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
/// receipt and cannot be upgraded to a fresh rename lease.
#[derive(Clone)]
pub struct FileRenameHistory {
    pub intent: NamespaceIntent,
    pub progress: NamespaceProgressSnapshot,
}

/// Only a successfully created and authenticated publication yields this
/// receipt. It is consumed when acquiring the operation lease.
pub struct FreshFileRenamePublication {
    store: Arc<FileRenameStore>,
    directory: Arc<dyn Directory>,
    loaded: Box<Loaded>,
    fresh: bool,
}

pub enum FileRenamePublishResult {
    Fresh(FreshFileRenamePublication),
    /// Exact duplicate or unresolved same-file/path conflict. No receipt is
    /// minted, including when a duplicate history is pristine Pending/0.
    Retained,
}

/// Store scoped to one explicit, already admitted SnapshotStore. This type has
/// no current-user/default-path constructor and never opens recovery state.
pub struct FileRenameStore {
    base: Arc<SnapshotStore>,
}

impl FileRenameStore {
    pub fn new(base: Arc<SnapshotStore>) -> Result<Arc<Self>, StoreError> {
        base.policy.validate()?;
        base.root.verify()?;
        Ok(Arc::new(Self { base }))
    }

    /// Publish a new intent under the existing v2 quota lock. Only the exact
    /// newly created and reopened record returns Fresh; retained history never
    /// supplies dispatch authority.
    pub fn publish_intent(
        self: &Arc<Self>,
        mut intent: NamespaceIntent,
    ) -> Result<FileRenamePublishResult, StoreError> {
        intent.validate().map_err(|_| StoreError::Invalid)?;
        if !supported_intent(&intent) {
            return Err(StoreError::Invalid);
        }
        let source_scope = match &intent.operation {
            NamespaceOperation::MoveWithinScope { source, .. } => &source.local.parent.scope,
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
            return Ok(FileRenamePublishResult::Retained);
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
        Ok(FileRenamePublishResult::Fresh(FreshFileRenamePublication {
            store: Arc::clone(self),
            directory,
            loaded: Box::new(loaded),
            fresh: true,
        }))
    }

    /// Authenticated, read-only records in the exact physical account/root
    /// group. The caller cannot acquire or mint fresh publication custody from
    /// this result.
    pub fn discover_account_root(&self) -> Result<Vec<FileRenameHistory>, StoreError> {
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

    /// Authenticated namespace-rename scope catalogs. The shared quota lock is
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

    fn open(
        &self,
        scope: &EditJournalScope,
        key: &RecordKey,
        sequence: u64,
        previous: &[u8; 32],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let aad = record_aad(scope, key, sequence, previous)?;
        let plaintext = Zeroizing::new(
            self.base
                .protector
                .open(&aad, sealed)
                .map_err(|_| StoreError::CorruptEvidence)?,
        );
        if plaintext.len() > META_LIMIT / 2 {
            return Err(StoreError::CorruptEvidence);
        }
        Ok(plaintext)
    }

    fn discover_account_root_while_locked(
        &self,
        budget: &mut Budget,
        include_requested_scope: bool,
    ) -> Result<Vec<FileRenameHistory>, StoreError> {
        let root_names = self.base.root.entries(budget.remaining_entries())?;
        budget.entries(root_names.len())?;
        let rename_scopes =
            self.validate_global_catalogs(&root_names, budget, include_requested_scope)?;
        if !root_names.iter().any(|name| name == ROOT) {
            self.base.root.verify()?;
            return Ok(Vec::new());
        }
        let root = self.base.root.child(ROOT, false)?;

        let mut result = Vec::new();
        for scope in rename_scopes {
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
        Ok(catalogs.rename)
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
        let plaintext = self.open(scope, &key, 0, &[0; 32], &envelope.sealed)?;
        let intent: NamespaceIntent =
            serde_json::from_slice(&plaintext).map_err(|_| StoreError::CorruptEvidence)?;
        if !supported_intent(&intent)
            || move_entries(&intent).is_none_or(|(source, _)| &source.local.parent.scope != scope)
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
        let mut checker = NamespaceIntentProgress::new(intent.clone())
            .map_err(|_| StoreError::CorruptEvidence)?;
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
            let plaintext = self.open(scope, &key, sequence, &chain, &bytes)?;
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
}

impl FreshFileRenamePublication {
    /// Consume the publication receipt and acquire this record's exclusive
    /// zero-length operation lock. Any failure loses fresh custody.
    pub fn acquire_dispatch(mut self) -> Result<FileRenameLease, StoreError> {
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
        Ok(FileRenameLease {
            store: Arc::clone(&self.store),
            directory: Arc::clone(&self.directory),
            _lock: lock,
            loaded,
            fresh: true,
            poisoned: false,
        })
    }
}

pub struct FileRenameLease {
    store: Arc<FileRenameStore>,
    directory: Arc<dyn Directory>,
    _lock: Box<dyn PinnedRead>,
    loaded: Loaded,
    fresh: bool,
    poisoned: bool,
}
impl FileRenameLease {
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

impl crate::namespace_file_rename::FileRenameJournal for FileRenameLease {
    fn owns_fresh_publication(&self) -> bool {
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
        && progress.source_removal == Some(NamespacePhase::Pending)
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

fn history(loaded: Loaded) -> FileRenameHistory {
    FileRenameHistory {
        intent: loaded.intent,
        progress: recovered(loaded.progress),
    }
}

fn allowed_event(event: &NamespaceEventKind) -> bool {
    matches!(
        event,
        NamespaceEventKind::RemoteSubmitted
            | NamespaceEventKind::RemoteVerified { .. }
            | NamespaceEventKind::LocalCompleted { .. }
            | NamespaceEventKind::SourceRemovalVerified { .. }
            | NamespaceEventKind::Conflict
            | NamespaceEventKind::Deferred
            | NamespaceEventKind::Uncertain
    )
}

fn typed_transition_allowed(
    progress: NamespaceProgressSnapshot,
    event: &NamespaceEventKind,
) -> bool {
    match event {
        NamespaceEventKind::RemoteSubmitted => pristine(progress),
        NamespaceEventKind::RemoteVerified { .. } => {
            progress.remote == NamespacePhase::Submitted
                && progress.source_removal == Some(NamespacePhase::Pending)
                && progress.attention.is_none()
                && !progress.local_completed
                && !progress.recorded_complete
        }
        NamespaceEventKind::LocalCompleted { .. } => {
            progress.remote == NamespacePhase::Verified
                && progress.source_removal == Some(NamespacePhase::Pending)
                && progress.attention.is_none()
                && !progress.local_completed
                && !progress.recorded_complete
        }
        NamespaceEventKind::SourceRemovalVerified { .. } => {
            progress.remote == NamespacePhase::Verified
                && progress.source_removal == Some(NamespacePhase::Pending)
                && progress.local_completed
                && progress.attention.is_none()
                && !progress.recorded_complete
        }
        _ => true,
    }
}

fn supported_intent(intent: &NamespaceIntent) -> bool {
    let NamespaceOperation::MoveWithinScope {
        source,
        destination,
    } = &intent.operation
    else {
        return false;
    };
    source.local.object_kind == NamespaceObjectKind::File
        && destination.object_kind == NamespaceObjectKind::File
        && source.local.parent == destination.parent
        && source
            .local
            .parent
            .local_components
            .first()
            .is_some_and(|part| part.eq_ignore_ascii_case("Personal"))
        && source.local.local_file == destination.local_file
        && !source.local.name.eq_ignore_ascii_case(&destination.name)
        && !source
            .remote
            .resource_id
            .to_ascii_lowercase()
            .starts_with("http://")
        && !source
            .remote
            .resource_id
            .to_ascii_lowercase()
            .starts_with("https://")
}

fn same_operation(a: &NamespaceIntent, b: &NamespaceIntent) -> bool {
    a.schema_version == b.schema_version
        && a.record_generation == b.record_generation
        && a.operation == b.operation
}

fn conflicts_with_unresolved(existing: &NamespaceIntent, requested: &NamespaceIntent) -> bool {
    let (Some((existing_source, existing_destination)), Some((source, destination))) =
        (move_entries(existing), move_entries(requested))
    else {
        return true;
    };
    let same_identity = existing_source.local.local_file == source.local.local_file;
    let endpoint_overlap = [&existing_source.local, existing_destination]
        .iter()
        .any(|old| {
            [&source.local, destination].iter().any(|new| {
                old.parent.local_file == new.parent.local_file
                    && old.parent.scope == new.parent.scope
                    && old.name.eq_ignore_ascii_case(&new.name)
            })
        });
    same_identity || endpoint_overlap
}

fn move_entries(
    intent: &NamespaceIntent,
) -> Option<(
    &ExistingNamespaceEntry,
    &crate::namespace_intent::LocalNamespaceEntry,
)> {
    match &intent.operation {
        NamespaceOperation::MoveWithinScope {
            source,
            destination,
        } => Some((source, destination)),
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

/// Authenticate every namespace-rename catalog under one aggregate budget.
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
    root.verify()?;
    let names = root.entries(budget.remaining_entries())?;
    budget.entries(names.len())?;
    let _scopes = validate_catalog_names(root, protector, budget, &names)?;
    let mut inventory = Inventory {
        bytes: 0,
        entries: names.len(),
    };
    for name in names {
        if valid_key(&name) {
            let directory = root.child(&name, false)?;
            let children = record_names(&*directory, budget)?;
            inventory.entries = inventory
                .entries
                .checked_add(children.len())
                .ok_or(StoreError::ScanLimit)?;
            for child in children {
                let file = directory.open(&child)?;
                inventory.add(file.len()?)?;
                file.verify()?;
            }
            directory.verify()?;
        } else {
            let file = root.open(&name)?;
            inventory.add(file.len()?)?;
            file.verify()?;
        }
    }
    root.verify()?;
    Ok(inventory)
}

#[cfg(all(test, unix))]
#[path = "namespace_rename_store_tests.rs"]
mod tests;

#[cfg(all(
    test,
    windows,
    debug_assertions,
    feature = "synthetic-agent-integration"
))]
#[path = "namespace_rename_store_native_test.rs"]
mod native_proof;

//! Protected local CreateFile/snapshot joins. No network/native permission,
//! existing-resource baseline, adoption, replay or deletion is provided here.
use super::*;
use crate::namespace_intent::{
    ContinuedEditReference, NamespaceAttention, NamespaceEvent, NamespaceEventKind,
    NamespaceIntent, NamespaceIntentProgress, NamespaceOperation, NamespacePhase,
    NamespaceProgressSnapshot,
};

pub(super) const ROOT: &str = "namespace-file-v1";
const DOMAIN: &[u8] = b"raiun/namespace-file-join/v1\0";
const MAX_RECORDS: usize = 2000;
const MAX_SCOPES: usize = 256;

/// Authenticated support metadata grouped without record IDs, paths or report
/// text. These historical categories grant no native or recovery authority.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PendingFileCreateClassification {
    pub phase: &'static str,
    pub attention: &'static str,
    pub sequence: u64,
    pub local_completed: bool,
    pub continued: bool,
    pub snapshot_state: &'static str,
    pub attempt_id: Option<u64>,
    pub attempts: Option<u8>,
    pub eligible: bool,
    pub exclusion: &'static str,
    pub count: usize,
    // Authenticated metadata retained only long enough for the original owner
    // to label the root relation. Neither serialization nor Debug exports IDs.
    #[serde(skip)]
    space_id: String,
    #[serde(skip)]
    root_resource_id: String,
}
impl PendingFileCreateClassification {
    /// Fixed relation only, not an identity accessor or recovery permission.
    /// The caller supplies its original verified Personal identity, not a path.
    pub fn relation_to_verified_space(
        &self,
        space_id: &str,
        root_resource_id: &str,
    ) -> &'static str {
        if [space_id, root_resource_id].iter().any(|value| {
            value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control)
        }) {
            return "unknown";
        }
        match (
            self.space_id == space_id,
            self.root_resource_id == root_resource_id,
        ) {
            (true, true) => "same_space_and_root",
            (false, false) => "different_space_and_root",
            _ => "overlapping_identity",
        }
    }
}
impl std::fmt::Debug for PendingFileCreateClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingFileCreateClassification")
            .field("phase", &self.phase)
            .field("attention", &self.attention)
            .field("sequence", &self.sequence)
            .field("local_completed", &self.local_completed)
            .field("continued", &self.continued)
            .field("snapshot_state", &self.snapshot_state)
            .field("attempt_id", &self.attempt_id)
            .field("attempts", &self.attempts)
            .field("eligible", &self.eligible)
            .field("exclusion", &self.exclusion)
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

fn pending_classification(
    loaded: &Loaded,
    state: StreamedAttemptState,
    eligible: bool,
) -> PendingFileCreateClassification {
    let progress = loaded.record.progress;
    let phase = match progress.remote {
        NamespacePhase::Pending => "pending",
        NamespacePhase::Submitted => "submitted",
        NamespacePhase::Verified => "verified",
    };
    let attention = match progress.attention {
        None => "none",
        Some(NamespaceAttention::Conflict) => "conflict",
        Some(NamespaceAttention::Deferred) => "deferred",
        Some(NamespaceAttention::Uncertain) => "uncertain",
    };
    let (snapshot_state, attempt_id, attempts) = match state {
        StreamedAttemptState::NotAttempted => ("not_attempted", None, None),
        StreamedAttemptState::Uncertain { attempt_id } => ("uncertain", Some(attempt_id), None),
        StreamedAttemptState::VerifiedApplied {
            attempt_id,
            attempts,
        } => ("verified_applied", Some(attempt_id), Some(attempts)),
        StreamedAttemptState::Conflict {
            attempt_id,
            attempts,
        } => ("conflict", Some(attempt_id), Some(attempts)),
        StreamedAttemptState::Ambiguous {
            attempt_id,
            attempts,
        } => ("ambiguous", Some(attempt_id), Some(attempts)),
        StreamedAttemptState::Deferred {
            attempt_id,
            attempts,
        } => ("deferred", Some(attempt_id), Some(attempts)),
        StreamedAttemptState::LocallyAcknowledged {
            attempt_id: 0,
            attempts: 0,
        } => ("acknowledged_zero_attempt", Some(0), Some(0)),
        StreamedAttemptState::LocallyAcknowledged {
            attempt_id,
            attempts,
        } => (
            "acknowledged_nonzero_attempt",
            Some(attempt_id),
            Some(attempts),
        ),
        StreamedAttemptState::Superseded {
            attempt_id,
            attempts,
        } => ("superseded", Some(attempt_id), Some(attempts)),
    };
    // This describes the existing classifier's first exclusion; it never
    // substitutes for that classifier's authenticated eligibility decision.
    let exclusion = if progress.remote != NamespacePhase::Verified {
        "remote_not_verified"
    } else if progress.attention.is_some() {
        "attention_present"
    } else if progress.continued {
        "continued"
    } else if progress.local_completed {
        "local_completed"
    } else if progress.recorded_complete {
        "recorded_complete"
    } else if eligible {
        "eligible"
    } else {
        "snapshot_not_zero_attempt_ack"
    };
    PendingFileCreateClassification {
        phase,
        attention,
        sequence: progress.sequence,
        local_completed: progress.local_completed,
        continued: progress.continued,
        snapshot_state,
        attempt_id,
        attempts,
        eligible,
        exclusion,
        count: 0,
        space_id: loaded.record.key.scope.space_id.clone(),
        root_resource_id: loaded.record.key.scope.root_resource_id.clone(),
    }
}

/// Checked path syntax/correspondence ONLY. It proves no native ancestry,
/// current generation, ordinary classification or authorization.
pub struct CapturedCreatePath {
    local_components: Vec<String>,
    space_relative_path: String,
}
impl CapturedCreatePath {
    pub fn new(
        local_components: Vec<String>,
        space_relative_path: String,
    ) -> Result<Self, StoreError> {
        let path = Self {
            local_components,
            space_relative_path,
        };
        path.validate()?;
        Ok(path)
    }
    fn validate(&self) -> Result<(), StoreError> {
        // Reject caller-supplied sizes before allocating component vectors.
        if self.local_components.len() > 256
            || self.space_relative_path.len() > 32768
            || self.local_components.iter().any(|s| !component(s))
            || self.local_components.iter().map(String::len).sum::<usize>() > 32768
        {
            return Err(StoreError::Invalid);
        }
        let remote = self.space_relative_path.split('/').collect::<Vec<_>>();
        if remote.is_empty()
            || remote.len() > 256
            || remote.iter().any(|s| !component(s))
            || !self
                .local_components
                .ends_with(&remote.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        {
            return Err(StoreError::Invalid);
        }
        let prefix = self
            .local_components
            .len()
            .checked_sub(remote.len())
            .ok_or(StoreError::Invalid)?;
        if !((prefix == 1 && self.local_components[0] == "Personal")
            || (prefix == 2 && self.local_components[0] == "Spaces"))
        {
            return Err(StoreError::Invalid);
        }
        Ok(())
    }
}
fn component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && !matches!(s, "." | "..")
        && !s.ends_with([' ', '.'])
        && !s
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\' | ':'))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotReference {
    id: String,
    generation: u64,
    space_relative_path: String,
    manifest_commitment: [u8; 32],
    container_len: u64,
    container_sha256: [u8; 32],
    content_sha256: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileJoin {
    version: u32,
    intent: NamespaceIntent,
    snapshot: SnapshotReference,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    generation: u64,
    digest: String,
    sealed: Vec<u8>,
}
/// Opaque local storage key, not a dispatch/native capability.
#[derive(Clone, Eq, PartialEq)]
pub struct FileCreateKey {
    scope: EditJournalScope,
    id: String,
    generation: u64,
    digest: String,
}
impl FileCreateKey {
    pub fn record_id(&self) -> &str {
        &self.id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn scope(&self) -> &EditJournalScope {
        &self.scope
    }
}
#[derive(Clone)]
pub struct StoredFileJoin {
    key: FileCreateKey,
    joined: FileJoin,
    progress: NamespaceProgressSnapshot,
    commitment: [u8; 32],
}
impl StoredFileJoin {
    pub fn key(&self) -> &FileCreateKey {
        &self.key
    }
    pub fn intent(&self) -> &NamespaceIntent {
        &self.joined.intent
    }
    pub fn snapshot_id(&self) -> &str {
        &self.joined.snapshot.id
    }
    pub fn manifest_commitment_sha256(&self) -> &[u8; 32] {
        &self.joined.snapshot.manifest_commitment
    }
    /// Recovered Submitted is projected as Uncertain, never a fresh permit.
    pub fn progress(&self) -> NamespaceProgressSnapshot {
        let mut value = self.progress;
        if value.remote == NamespacePhase::Submitted && value.attention.is_none() {
            value.attention = Some(NamespaceAttention::Uncertain);
        }
        value
    }
}
struct Loaded {
    record: StoredFileJoin,
    checked: NamespaceIntentProgress,
    remote: Option<crate::namespace_intent::NamespaceDestinationReport>,
}
/// Complete local byte authentication only. This is not server/native evidence.
pub struct VerifiedFileJoin {
    record: StoredFileJoin,
    snapshot: VerifiedPinnedSnapshot,
    #[cfg(windows)]
    remote_report: Option<crate::namespace_intent::NamespaceDestinationReport>,
}
impl VerifiedFileJoin {
    #[cfg(windows)]
    pub(crate) fn matches_snapshot_key(&self, key: &StreamedRecordKey) -> Result<bool, StoreError> {
        Ok(StreamedRecordKey::from_manifest(self.manifest())? == *key)
    }

    /// Protected historical metadata only, never replay/native authority.
    #[cfg(windows)]
    pub(crate) fn remote_report(
        &self,
    ) -> Option<&crate::namespace_intent::NamespaceDestinationReport> {
        self.remote_report.as_ref()
    }
    pub fn record(&self) -> &StoredFileJoin {
        &self.record
    }
    pub fn manifest(&self) -> &SnapshotManifest {
        self.snapshot.manifest()
    }
    pub fn verify_pin(&self) -> Result<(), StoreError> {
        self.snapshot.verify_pin()
    }
    pub fn into_reader(
        self,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<impl Read + Send, StoreError> {
        self.snapshot.into_reader(cancelled)
    }
}
/// Fresh publication retains a verified body pin, but grants no upload/native
/// authority and cannot be reconstructed from a serialized header.
pub struct PublishedFileJoin {
    verified: VerifiedFileJoin,
}
impl PublishedFileJoin {
    pub fn record(&self) -> &StoredFileJoin {
        self.verified.record()
    }
    pub fn into_verified(self) -> VerifiedFileJoin {
        self.verified
    }
}
pub struct FileCreateStore {
    base: Arc<SnapshotStore>,
}
impl FileCreateStore {
    /// Existing-only authenticated join scopes, including scopes whose
    /// referenced snapshot catalog must still be checked by the caller.
    #[cfg(windows)]
    pub(crate) fn discover_state_scopes_bounded(
        state: Arc<crate::recovery_state::RecoveryStateRoot>,
        protector: Arc<dyn EditRecordProtector>,
        policy: StorePolicy,
        budget: &mut DiscoveryBudget,
    ) -> Result<Vec<EditJournalScope>, StoreError> {
        budget.within_policy(policy, |budget| {
            policy.validate()?;
            let Some(root) = windows::existing_root(Arc::clone(&state), V2_STORE_ROOT)? else {
                return Ok(Vec::new());
            };
            root.verify()?;
            let names = root.entries(budget.remaining_entries())?;
            budget.entries(names.len())?;
            validate_root_catalog_scope_union(&*root, &*protector, &names, budget)?;
            let scopes = if names.iter().any(|name| name == ROOT) {
                let joins = root.child(ROOT, false)?;
                let scopes = catalogs(&*joins, &*protector, budget)?
                    .into_iter()
                    .map(|(_, scope)| scope)
                    .collect();
                joins.verify()?;
                scopes
            } else {
                Vec::new()
            };
            root.verify()?;
            state.verify_path().map_err(io_error)?;
            Ok(scopes)
        })
    }

    /// Reuse the exact admitted snapshot-store Arc. No default state/DPAPI open.
    pub fn new(base: Arc<SnapshotStore>) -> Result<Arc<Self>, StoreError> {
        base.root.verify()?;
        base.policy.validate()?;
        Ok(Arc::new(Self { base }))
    }
    /// Existing local storage context, not native/remote admission.
    pub fn snapshot_store(&self) -> &Arc<SnapshotStore> {
        &self.base
    }
    pub fn scope(&self) -> &EditJournalScope {
        &self.base.scope
    }
    fn reserve(&self, bytes: u64, entries: usize) -> Result<Box<dyn PinnedRead>, StoreError> {
        let lease = self.base.acquire_lock()?;
        let usage = self.base.inventory()?;
        if usage
            .bytes
            .checked_add(bytes)
            .is_none_or(|n| n > self.base.policy.max_state_bytes)
        {
            return Err(StoreError::Quota);
        }
        if usage
            .entries
            .checked_add(entries)
            .is_none_or(|n| n > self.base.policy.max_entries)
        {
            return Err(StoreError::ScanLimit);
        }
        Ok(lease)
    }
    fn directory(&self, create: bool) -> Result<Arc<dyn Directory>, StoreError> {
        if create {
            self.base.validate_requested_catalog_scope()?;
        }
        let names = self.base.root.entries(self.base.policy.max_entries)?;
        let root = self
            .base
            .root
            .child(ROOT, create && !names.contains(&ROOT.to_owned()))?;
        let names = root.entries(self.base.policy.max_entries)?;
        let catalog = format!("{}.scope", self.base.key);
        if !names.contains(&catalog) {
            if !create || names.contains(&self.base.key) {
                return Err(StoreError::IncompleteEvidence);
            }
            let sealed = self
                .base
                .seal_metadata(&catalog_aad(&self.base.key), &self.base.scope)?;
            persist_metadata(&*root, &catalog, &sealed)?;
            root.child(&self.base.key, true)?;
        }
        let scope = read_catalog(
            &*root,
            &*self.base.protector,
            &self.base.key,
            &mut Budget::new(self.base.policy),
        )?;
        if scope != self.base.scope {
            return Err(StoreError::CorruptEvidence);
        }
        root.child(&self.base.key, false)
    }
    pub fn publish_fresh(
        self: &Arc<Self>,
        mut draft: NamespaceIntent,
        committed: CommittedSnapshot,
        path: CapturedCreatePath,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<PublishedFileJoin, StoreError> {
        // Metadata equality cannot prove same-root capture provenance.
        if !Arc::ptr_eq(&committed.store, &self.base) {
            return Err(StoreError::Invalid);
        }
        let manifest = committed.manifest();
        let key = StreamedRecordKey::from_manifest(manifest)?;
        let joined = FileJoin {
            version: 1,
            intent: draft.clone(),
            snapshot: SnapshotReference {
                id: manifest.binding().record_id.clone(),
                generation: manifest.binding().generation,
                space_relative_path: path.space_relative_path.clone(),
                manifest_commitment: *key.commitment_sha256(),
                container_len: manifest.container_len(),
                container_sha256: *manifest.container_sha256(),
                content_sha256: *manifest.content_sha256(),
            },
        };
        validate_join(&joined, &self.base.scope, manifest)?;
        let mut local = destination(&draft)?.parent.local_components.clone();
        local.push(destination(&draft)?.name.clone());
        path.validate()?;
        if path.local_components != local {
            return Err(StoreError::Invalid);
        }
        // Full body authentication is deliberately BEFORE any quota lease.
        let snapshot = self.base.open_verified_key(&key, cancelled)?;
        if StreamedRecordKey::from_manifest(snapshot.manifest())? != key {
            return Err(StoreError::CorruptEvidence);
        }
        if cancelled() {
            return Err(StoreError::Snapshot(SnapshotError::Cancelled));
        }
        let _quota = self.reserve((META_LIMIT as u64) * 4, 7)?;
        let prior = self.discover_all()?;
        let desired = destination(&draft)?;
        for record in prior {
            let old = destination(record.intent())?;
            if record.joined.snapshot.manifest_commitment == joined.snapshot.manifest_commitment
                || (account_root(&old.parent.scope, &desired.parent.scope)
                    && (old.local_file == desired.local_file
                        || (old.parent.local_file == desired.parent.local_file
                            && old.name == desired.name)))
            {
                return Err(StoreError::Invalid);
            }
        }
        snapshot.verify_pin()?;
        if cancelled() {
            return Err(StoreError::Snapshot(SnapshotError::Cancelled));
        }
        let directory = self.directory(true)?;
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| StoreError::Io)?;
        draft.record_id = hex(&random);
        let joined = FileJoin {
            intent: draft,
            ..joined
        };
        let plain = Zeroizing::new(serde_json::to_vec(&joined).map_err(|_| StoreError::Invalid)?);
        let digest = hex(&join_hash(&plain));
        let key = FileCreateKey {
            scope: self.base.scope.clone(),
            id: joined.intent.record_id.clone(),
            generation: joined.intent.record_generation,
            digest,
        };
        let sealed = self.seal(&key, 0, &[0; 32], &plain)?;
        let bytes = serde_json::to_vec(&Envelope {
            generation: key.generation,
            digest: key.digest.clone(),
            sealed,
        })
        .map_err(|_| StoreError::Invalid)?;
        if bytes.len() > META_LIMIT {
            return Err(StoreError::Quota);
        }
        persist_metadata(&*directory, &format!("{}.intent", key.id), &bytes)
            .map_err(|_| StoreError::PublicationUncertain)?;
        let loaded = self.load(
            &*directory,
            &key.id,
            &self.base.scope,
            &mut Budget::new(self.base.policy),
        )?;
        if loaded.record.key != key {
            return Err(StoreError::PublicationUncertain);
        }
        snapshot.verify_pin()?;
        if cancelled() {
            return Err(StoreError::Snapshot(SnapshotError::Cancelled));
        }
        Ok(PublishedFileJoin {
            verified: VerifiedFileJoin {
                record: loaded.record,
                snapshot,
                #[cfg(windows)]
                remote_report: loaded.remote,
            },
        })
    }
    /// Authenticated metadata/reference discovery; no body bytes read.
    pub fn discover(&self) -> Result<Vec<StoredFileJoin>, StoreError> {
        self.discover_bounded(&mut Budget::new(self.base.policy))
    }
    /// Share the caller's remaining allowance with snapshot and join discovery.
    /// References retain the same authentication and existing-body checks.
    pub(crate) fn discover_bounded(
        &self,
        budget: &mut DiscoveryBudget,
    ) -> Result<Vec<StoredFileJoin>, StoreError> {
        budget.within_policy(self.base.policy, |budget| {
            Ok(self
                .discover_all_bounded(budget)?
                .into_iter()
                .filter(|r| r.key.scope == self.base.scope)
                .collect())
        })
    }
    fn discover_all(&self) -> Result<Vec<StoredFileJoin>, StoreError> {
        self.discover_all_bounded(&mut Budget::new(self.base.policy))
    }
    fn discover_all_bounded(
        &self,
        budget: &mut DiscoveryBudget,
    ) -> Result<Vec<StoredFileJoin>, StoreError> {
        let names = self.base.root.entries(budget.remaining_entries())?;
        budget.entries(names.len())?;
        self.base.validate_root_catalogs(&names, budget)?;
        if !names.contains(&ROOT.to_owned()) {
            return Ok(Vec::new());
        }
        let root = self.base.root.child(ROOT, false)?;
        let catalogs = catalogs(&*root, &*self.base.protector, budget)?;
        let mut result = Vec::new();
        for (key, scope) in catalogs {
            let directory = root.child(&key, false)?;
            let names = directory.entries(budget.remaining_entries())?;
            budget.entries(names.len())?;
            let mut ids = std::collections::BTreeSet::new();
            for name in &names {
                let (id, suffix) = record_name(name)?;
                if !names.contains(&format!("{id}.intent")) {
                    return Err(StoreError::IncompleteEvidence);
                }
                if suffix == "dispatch.lock" {
                    let pin = directory.open(name)?;
                    if pin.len()? != 0 {
                        return Err(StoreError::CorruptEvidence);
                    }
                    pin.verify()?;
                }
                ids.insert(id.to_owned());
            }
            if result.len() + ids.len() > MAX_RECORDS {
                return Err(StoreError::ScanLimit);
            }
            for id in ids {
                result.push(
                    self.load_names(&*directory, &id, &scope, &names, budget)?
                        .record,
                );
            }
        }
        Ok(result)
    }
    pub fn open_joined(
        &self,
        key: &FileCreateKey,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<VerifiedFileJoin, StoreError> {
        if key.scope != self.base.scope {
            return Err(StoreError::Invalid);
        }
        let directory = self.directory(false)?;
        let loaded = self.load(
            &*directory,
            &key.id,
            &key.scope,
            &mut Budget::new(self.base.policy),
        )?;
        if loaded.record.key != *key {
            return Err(StoreError::CorruptEvidence);
        }
        let snapshot_key = self.reference_manifest(
            &loaded.record.joined,
            &key.scope,
            &mut Budget::new(self.base.policy),
        )?;
        let snapshot = self
            .base
            .open_verified_key(&StreamedRecordKey::from_manifest(&snapshot_key)?, cancelled)?;
        Ok(VerifiedFileJoin {
            record: loaded.record,
            snapshot,
            #[cfg(windows)]
            remote_report: loaded.remote,
        })
    }
    pub fn acquire_dispatch(
        self: &Arc<Self>,
        key: &FileCreateKey,
    ) -> Result<FileCreateLease, StoreError> {
        if key.scope != self.base.scope {
            return Err(StoreError::Invalid);
        }
        let directory = self.directory(false)?;
        let quota = self.reserve(0, 1)?;
        let checked = self.load(
            &*directory,
            &key.id,
            &key.scope,
            &mut Budget::new(self.base.policy),
        )?;
        if checked.record.key != *key {
            return Err(StoreError::CorruptEvidence);
        }
        let name = format!("{}.dispatch.lock", key.id);
        if let Ok((file, _)) = directory.create(&name) {
            file.sync()?;
            drop(file);
        }
        let mut lock = directory.open(&name)?;
        if lock.len()? != 0 {
            return Err(StoreError::CorruptEvidence);
        }
        drop(quota); // Never acquire a record lock under quota.lock.
        lock.lock_exclusive()?;
        lock.verify()?;
        let loaded = self.load(
            &*directory,
            &key.id,
            &key.scope,
            &mut Budget::new(self.base.policy),
        )?;
        if loaded.record.key != *key {
            return Err(StoreError::CorruptEvidence);
        }
        Ok(FileCreateLease {
            store: Arc::clone(self),
            directory,
            _lock: lock,
            loaded,
            submitted_here: false,
            poisoned: false,
        })
    }
    fn reference_manifest(
        &self,
        joined: &FileJoin,
        scope: &EditJournalScope,
        budget: &mut Budget,
    ) -> Result<SnapshotManifest, StoreError> {
        let (manifest, directory) = self.reference_manifest_metadata(joined, scope, budget)?;
        let body = directory.open(&format!("{}.body", joined.snapshot.id))?;
        if body.len()? != manifest.container_len() {
            return Err(StoreError::IncompleteEvidence);
        }
        body.verify()?;
        Ok(manifest)
    }
    // Same authenticated join/reservation/manifest checks without touching body
    // handles. Only the existing-lock history reader uses this distinction.
    fn reference_manifest_metadata(
        &self,
        joined: &FileJoin,
        scope: &EditJournalScope,
        budget: &mut Budget,
    ) -> Result<(SnapshotManifest, Arc<dyn Directory>), StoreError> {
        let scope_key = scope_key(scope)?;
        if self.base.authenticate_scope(&scope_key, budget)? != *scope {
            return Err(StoreError::CorruptEvidence);
        }
        let directory = self.base.root.child(&scope_key, false)?;
        let reference = &joined.snapshot;
        if joined.version != 1 || !valid_id(&reference.id) || reference.generation == 0 {
            return Err(StoreError::CorruptEvidence);
        }
        let sealed = read_metadata(&*directory, &format!("{}.manifest", reference.id), budget)?;
        let manifest = open_manifest(
            &sealed,
            &*self.base.protector,
            scope,
            &reference.id,
            self.base.policy.codec()?,
        )?;
        let reserve =
            self.base
                .authenticate_reservation(&*directory, &reference.id, scope, budget)?;
        if reserve.binding != *manifest.binding() {
            return Err(StoreError::CorruptEvidence);
        }
        validate_join(joined, scope, &manifest).map_err(|_| StoreError::CorruptEvidence)?;
        Ok((manifest, directory))
    }
    fn load(
        &self,
        directory: &dyn Directory,
        id: &str,
        scope: &EditJournalScope,
        budget: &mut Budget,
    ) -> Result<Loaded, StoreError> {
        let names = directory.entries(budget.remaining_entries())?;
        budget.entries(names.len())?;
        self.load_names(directory, id, scope, &names, budget)
    }
    fn load_names(
        &self,
        directory: &dyn Directory,
        id: &str,
        scope: &EditJournalScope,
        names: &[String],
        budget: &mut Budget,
    ) -> Result<Loaded, StoreError> {
        self.load_names_checked(directory, id, scope, names, budget, true)
    }
    fn load_names_checked(
        &self,
        directory: &dyn Directory,
        id: &str,
        scope: &EditJournalScope,
        names: &[String],
        budget: &mut Budget,
        require_body: bool,
    ) -> Result<Loaded, StoreError> {
        self.load_names_with_history(directory, id, scope, names, budget, require_body, None)
    }
    #[allow(clippy::too_many_arguments)]
    fn load_names_with_history(
        &self,
        directory: &dyn Directory,
        id: &str,
        scope: &EditJournalScope,
        names: &[String],
        budget: &mut Budget,
        require_body: bool,
        history: Option<&super::events::NamespaceSnapshotHistories<'_>>,
    ) -> Result<Loaded, StoreError> {
        if !valid_id(id) {
            return Err(StoreError::Invalid);
        }
        let bytes = read_metadata(directory, &format!("{id}.intent"), budget)?;
        let envelope: Envelope =
            serde_json::from_slice(&bytes).map_err(|_| StoreError::CorruptEvidence)?;
        if envelope.generation == 0 || !valid_key(&envelope.digest) {
            return Err(StoreError::CorruptEvidence);
        }
        let key = FileCreateKey {
            scope: scope.clone(),
            id: id.into(),
            generation: envelope.generation,
            digest: envelope.digest,
        };
        let plain = self.open(&key, 0, &[0; 32], &envelope.sealed)?;
        if hex(&join_hash(&plain)) != key.digest {
            return Err(StoreError::CorruptEvidence);
        }
        let joined: FileJoin =
            serde_json::from_slice(&plain).map_err(|_| StoreError::CorruptEvidence)?;
        if joined.version != 1
            || joined.intent.record_id != id
            || joined.intent.record_generation != key.generation
        {
            return Err(StoreError::CorruptEvidence);
        }
        if require_body {
            self.reference_manifest(&joined, scope, budget)?;
        } else {
            self.reference_manifest_metadata(&joined, scope, budget)?;
        }
        let mut remote = None;
        #[cfg(windows)]
        let mut continued_edit = None;
        let mut checked = NamespaceIntentProgress::new(joined.intent.clone())
            .map_err(|_| StoreError::CorruptEvidence)?;
        let mut commitment = join_hash(&plain);
        let mut events = Vec::new();
        let mut unique = std::collections::HashSet::new();
        for name in names {
            if !unique.insert(name) {
                return Err(StoreError::CorruptEvidence);
            }
            let (record, suffix) = record_name(name)?;
            if record != id {
                continue;
            }
            if let Some(seq) = parse_event(suffix) {
                events.push((seq, name));
            }
        }
        events.sort();
        for (index, (seq, name)) in events.into_iter().enumerate() {
            if seq != index as u64 + 1 {
                return Err(StoreError::IncompleteEvidence);
            }
            let bytes = read_metadata(directory, name, budget)?;
            let plain = self.open(&key, seq, &commitment, &bytes)?;
            let event: NamespaceEvent =
                serde_json::from_slice(&plain).map_err(|_| StoreError::CorruptEvidence)?;
            check_transition(checked.snapshot(), &event.event)
                .map_err(|_| StoreError::CorruptEvidence)?;
            checked
                .record(&event)
                .map_err(|_| StoreError::CorruptEvidence)?;
            if let NamespaceEventKind::RemoteVerified { report } = &event.event {
                remote = Some(report.clone());
            }
            #[cfg(windows)]
            if let NamespaceEventKind::LocalContinued { edit, .. } = &event.event {
                continued_edit = Some(edit.clone());
            }
            commitment = event_hash(&commitment, &plain);
        }
        let progress = checked.snapshot();
        if progress.recorded_complete && !progress.continued {
            let (manifest, directory) = self.reference_manifest_metadata(&joined, scope, budget)?;
            let acknowledged = match history {
                Some(history) => {
                    history.original_state(&manifest, budget)?
                        == (StreamedAttemptState::LocallyAcknowledged {
                            attempt_id: 0,
                            attempts: 0,
                        })
                }
                None => self
                    .base
                    .create_acknowledged_metadata(&manifest, &*directory, budget)?,
            };
            if !acknowledged {
                return Err(StoreError::IncompleteEvidence);
            }
        }
        #[cfg(windows)]
        if progress.continued {
            let report = remote.as_ref().ok_or(StoreError::IncompleteEvidence)?;
            let edit = continued_edit
                .as_ref()
                .ok_or(StoreError::IncompleteEvidence)?;
            if scope == &self.base.scope {
                self.validate_continued_edit_with_history(
                    &joined, report, edit, budget, true, history,
                )?;
            } else {
                // Discovery authenticates every retained scope before filtering
                // the caller's rows. Decode this foreign continuation against
                // its own authenticated scope under the same pinned root and
                // cumulative scan budget; never reinterpret it as our scope.
                let decoder = FileCreateStore {
                    base: SnapshotStore::from_directory(
                        Arc::clone(&self.base.root),
                        scope.clone(),
                        Arc::clone(&self.base.protector),
                        self.base.policy,
                    )?,
                };
                decoder.validate_continued_edit_with_history(
                    &joined, report, edit, budget, true, history,
                )?;
            }
        }
        #[cfg(not(windows))]
        if progress.continued {
            return Err(StoreError::CorruptEvidence);
        }
        Ok(Loaded {
            record: StoredFileJoin {
                key,
                joined,
                progress,
                commitment,
            },
            checked,
            remote,
        })
    }

    /// Historical metadata only. This cannot prove current native completion
    /// or authorize any replay, mutation, acknowledgement or cleanup.
    fn acknowledged_original(
        &self,
        loaded: &Loaded,
        budget: &mut DiscoveryBudget,
    ) -> Result<bool, StoreError> {
        self.acknowledged_original_with_history(loaded, budget, None)
    }
    fn acknowledged_original_with_history(
        &self,
        loaded: &Loaded,
        budget: &mut DiscoveryBudget,
        history: Option<&super::events::NamespaceSnapshotHistories<'_>>,
    ) -> Result<bool, StoreError> {
        let progress = loaded.record.progress;
        if progress.remote != NamespacePhase::Verified
            || progress.attention.is_some()
            || progress.continued
            || progress.local_completed
            || progress.recorded_complete
        {
            return Ok(false);
        }
        let report = loaded
            .remote
            .as_ref()
            .ok_or(StoreError::IncompleteEvidence)?;
        let NamespaceOperation::CreateFile {
            destination,
            content,
        } = &loaded.record.joined.intent.operation
        else {
            return Err(StoreError::CorruptEvidence);
        };
        // The event chain already validated this report. Keep the selected
        // original join/report correspondence explicit before checking its ACK.
        if report.destination != *destination
            || report.content.as_ref() != Some(content)
            || report.remote.byte_len != content.byte_len
            || loaded.record.key.scope != self.base.scope
        {
            return Err(StoreError::CorruptEvidence);
        }
        let (manifest, directory) = self.reference_manifest_metadata(
            &loaded.record.joined,
            &loaded.record.key.scope,
            budget,
        )?;
        match history {
            Some(history) => Ok(history.original_state(&manifest, budget)?
                == (StreamedAttemptState::LocallyAcknowledged {
                    attempt_id: 0,
                    attempts: 0,
                })),
            None => self
                .base
                .create_acknowledged_metadata(&manifest, &*directory, budget),
        }
    }
    fn original_snapshot_state(
        &self,
        manifest: &SnapshotManifest,
        directory: &dyn Directory,
        budget: &mut Budget,
        history: Option<&super::events::NamespaceSnapshotHistories<'_>>,
    ) -> Result<StreamedAttemptState, StoreError> {
        match history {
            Some(history) => history.original_state(manifest, budget),
            None => self
                .base
                .create_original_state_metadata(manifest, directory, budget),
        }
    }
    #[cfg(windows)]
    fn validate_continued_edit(
        &self,
        joined: &FileJoin,
        report: &crate::namespace_intent::NamespaceDestinationReport,
        edit: &ContinuedEditReference,
        budget: &mut Budget,
        require_superseded: bool,
    ) -> Result<StreamedRecordKey, StoreError> {
        self.validate_continued_edit_with_history(
            joined,
            report,
            edit,
            budget,
            require_superseded,
            None,
        )
    }
    #[cfg(windows)]
    fn validate_continued_edit_with_history(
        &self,
        joined: &FileJoin,
        report: &crate::namespace_intent::NamespaceDestinationReport,
        edit: &ContinuedEditReference,
        budget: &mut Budget,
        require_superseded: bool,
        history: Option<&super::events::NamespaceSnapshotHistories<'_>>,
    ) -> Result<StreamedRecordKey, StoreError> {
        let original = self
            .reference_manifest_metadata(joined, &self.base.scope, budget)?
            .0;
        let original_key = StreamedRecordKey::from_manifest(&original)?;
        let (key, manifest, state) = match history {
            Some(history) => history.continued_edit_metadata(&edit.record_id, budget)?,
            None => self.base.continued_edit_metadata(&edit.record_id, budget)?,
        };
        let binding = manifest.binding();
        let destination = destination(&joined.intent)?;
        if key.record_id() == original_key.record_id()
            || key.generation() != edit.generation
            || key.commitment_sha256() != &edit.manifest_commitment
            || key.scope() != &self.base.scope
            || binding.local_file != destination.local_file
            || binding.relative_path != joined.snapshot.space_relative_path
            || binding.remote.as_ref() != Some(&report.remote)
            || !matches!(
                state,
                crate::streamed_store::StreamedAttemptState::LocallyAcknowledged { .. }
            )
        {
            return Err(StoreError::CorruptEvidence);
        }
        if require_superseded {
            let superseded = match history {
                Some(history) => history.superseded_metadata(&original_key, budget)?,
                None => self
                    .base
                    .create_superseded_metadata(&original_key, budget)?,
            };
            if superseded.as_ref() != Some(edit) {
                return Err(StoreError::IncompleteEvidence);
            }
        }
        Ok(key)
    }
    fn seal(
        &self,
        key: &FileCreateKey,
        seq: u64,
        previous: &[u8; 32],
        plain: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        if plain.len() > META_LIMIT / 2 {
            return Err(StoreError::Quota);
        }
        let sealed = self
            .base
            .protector
            .seal(&aad(key, seq, previous)?, plain)
            .map_err(|_| StoreError::CorruptEvidence)?;
        if sealed.is_empty() || sealed.len() > META_LIMIT {
            return Err(StoreError::Quota);
        }
        Ok(sealed)
    }
    fn open(
        &self,
        key: &FileCreateKey,
        seq: u64,
        previous: &[u8; 32],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let plain = Zeroizing::new(
            self.base
                .protector
                .open(&aad(key, seq, previous)?, sealed)
                .map_err(|_| StoreError::CorruptEvidence)?,
        );
        if plain.len() > META_LIMIT / 2 {
            return Err(StoreError::CorruptEvidence);
        }
        Ok(plain)
    }
}
/// Exclusive local event custody only. No send/native permit is exposed.
pub struct FileCreateLease {
    store: Arc<FileCreateStore>,
    directory: Arc<dyn Directory>,
    _lock: Box<dyn PinnedRead>,
    loaded: Loaded,
    submitted_here: bool,
    poisoned: bool,
}
impl FileCreateLease {
    /// Read-only classification of the exact selected historical join. A true
    /// result grants no current native authority and must not replay its create.
    #[cfg(windows)]
    pub(crate) fn has_acknowledged_original(&self) -> Result<bool, StoreError> {
        self.store
            .acknowledged_original(&self.loaded, &mut Budget::new(self.store.base.policy))
    }

    #[cfg(windows)]
    pub(crate) fn record_remote_verified(
        &mut self,
        proof: &crate::opencloud::file_create::VerifiedCreateReadback,
    ) -> Result<(), StoreError> {
        if !self.submitted_here {
            return Err(StoreError::Invalid);
        }
        let report = proof
            .report_for(self.loaded.record.intent())
            .map_err(|_| StoreError::Invalid)?;
        self.append(NamespaceEventKind::RemoteVerified { report })
    }
    #[cfg(windows)]
    pub(crate) fn record_local_completed(
        &mut self,
        completion: &crate::native::NativeFileCreateCompletion<'_>,
        acknowledged: &crate::streamed_store::CreateSnapshotAcknowledged,
    ) -> Result<(), StoreError> {
        let report = self.loaded.remote.as_ref().ok_or(StoreError::Invalid)?;
        if !self.submitted_here
            || !acknowledged.matches(completion)
            || !completion.matches(&self.store.base, &self.loaded.record, report)
        {
            return Err(StoreError::Invalid);
        }
        self.append_authorized(NamespaceEventKind::LocalCompleted {
            destination: destination(self.loaded.record.intent())?.clone(),
        })
    }
    /// Continue an already verified create after a distinct conditional edit
    /// and exact native completion. The original 57-byte snapshot is marked
    /// superseded, never acknowledged as the current edited file.
    #[cfg(windows)]
    pub(crate) fn record_continued(
        &mut self,
        proof: &crate::native::NativeFileCreateContinuation<'_>,
    ) -> Result<(), StoreError> {
        let report = self.loaded.remote.as_ref().ok_or(StoreError::Invalid)?;
        let new_key = proof.new_edit_key();
        if self.loaded.record.progress.remote != NamespacePhase::Verified
            || self.loaded.record.progress.recorded_complete
            || self.loaded.record.progress.attention.is_some()
            || !proof.matches(&self.store.base, &self.loaded.record, report, new_key)
        {
            return Err(StoreError::Invalid);
        }
        let edit = ContinuedEditReference {
            record_id: new_key.record_id().to_owned(),
            generation: new_key.generation(),
            manifest_commitment: *new_key.commitment_sha256(),
        };
        let checked = self.store.validate_continued_edit(
            &self.loaded.record.joined,
            report,
            &edit,
            &mut Budget::new(self.store.base.policy),
            false,
        )?;
        if &checked != new_key {
            return Err(StoreError::Invalid);
        }
        let snapshot = self.store.base.open_verified_key(new_key, &mut || false)?;
        snapshot.verify_pin()?;
        if snapshot.manifest().content_sha256() != &proof.body_sha256() {
            return Err(StoreError::Invalid);
        }
        let original = self
            .store
            .reference_manifest_metadata(
                &self.loaded.record.joined,
                &self.store.base.scope,
                &mut Budget::new(self.store.base.policy),
            )?
            .0;
        let old_key = StreamedRecordKey::from_manifest(&original)?;
        let mut old_dispatch = self.store.base.acquire_dispatch(&old_key)?;
        if old_dispatch.current_state()?
            == crate::streamed_store::StreamedAttemptState::NotAttempted
        {
            old_dispatch.supersede_create(&edit)?;
        } else if self
            .store
            .base
            .create_superseded_metadata(&old_key, &mut Budget::new(self.store.base.policy))?
            .as_ref()
            != Some(&edit)
        {
            return Err(StoreError::Invalid);
        }
        drop(old_dispatch);
        self.finish_superseded_existing()
    }
    /// Explicit selected-record closure after a crash between the original
    /// superseded receipt and the join event. Never called by health scans.
    #[cfg(windows)]
    pub(crate) fn finish_superseded_existing(&mut self) -> Result<(), StoreError> {
        let report = self.loaded.remote.as_ref().ok_or(StoreError::Invalid)?;
        if self.loaded.record.progress.remote != NamespacePhase::Verified
            || self.loaded.record.progress.recorded_complete
            || self.loaded.record.progress.attention.is_some()
        {
            return Err(StoreError::Invalid);
        }
        let original = self
            .store
            .reference_manifest_metadata(
                &self.loaded.record.joined,
                &self.store.base.scope,
                &mut Budget::new(self.store.base.policy),
            )?
            .0;
        let old_key = StreamedRecordKey::from_manifest(&original)?;
        let edit = self
            .store
            .base
            .create_superseded_metadata(&old_key, &mut Budget::new(self.store.base.policy))?
            .ok_or(StoreError::IncompleteEvidence)?;
        self.store.validate_continued_edit(
            &self.loaded.record.joined,
            report,
            &edit,
            &mut Budget::new(self.store.base.policy),
            true,
        )?;
        self.append_authorized(NamespaceEventKind::LocalContinued {
            destination: destination(self.loaded.record.intent())?.clone(),
            edit,
        })
    }
    pub fn record(&self) -> &StoredFileJoin {
        &self.loaded.record
    }
    /// Authenticated report from the sealed RemoteVerified event. This is
    /// metadata only and grants neither replay nor native completion authority.
    #[cfg(windows)]
    pub(crate) fn remote_verified_report(
        &self,
    ) -> Option<&crate::namespace_intent::NamespaceDestinationReport> {
        (self.loaded.record.progress.remote == NamespacePhase::Verified)
            .then_some(self.loaded.remote.as_ref())
            .flatten()
    }
    /// Read only: distinguish no crash-gap marker from an authenticated
    /// superseded original. Corrupt or incomplete evidence remains an error.
    #[cfg(windows)]
    pub(crate) fn has_superseded_original(&self) -> Result<bool, StoreError> {
        let original = self
            .store
            .reference_manifest_metadata(
                &self.loaded.record.joined,
                &self.store.base.scope,
                &mut Budget::new(self.store.base.policy),
            )?
            .0;
        let key = StreamedRecordKey::from_manifest(&original)?;
        Ok(self
            .store
            .base
            .create_superseded_metadata(&key, &mut Budget::new(self.store.base.policy))?
            .is_some())
    }
    /// Read-only selection of one successor captured against the original
    /// create's remote baseline. Its state grants no dispatch, remote or native
    /// authority; a selected recovery must authenticate current facts anew.
    #[cfg(windows)]
    pub(crate) fn continuation_candidate(
        &self,
    ) -> Result<
        Option<(
            StreamedRecordKey,
            crate::streamed_store::StreamedAttemptState,
        )>,
        StoreError,
    > {
        let report = self.loaded.remote.as_ref().ok_or(StoreError::Invalid)?;
        if self.loaded.record.progress.remote != NamespacePhase::Verified
            || self.loaded.record.progress.recorded_complete
            || self.loaded.record.progress.attention.is_some()
        {
            return Err(StoreError::Invalid);
        }
        let original = &self.loaded.record.joined;
        let expected = destination(&original.intent)?;
        let mut selected = None;
        for record in self.store.base.discover_records()? {
            let binding = record.manifest.binding();
            if record.key.record_id() == original.snapshot.id.as_str()
                || binding.scope != self.store.base.scope
                || binding.local_file != expected.local_file
                || binding.relative_path != original.snapshot.space_relative_path
                || binding.remote.as_ref() != Some(&report.remote)
            {
                continue;
            }
            if selected.is_some() {
                return Err(StoreError::IncompleteEvidence);
            }
            selected = Some((record.key, record.state));
        }
        if selected.as_ref().is_some_and(|(_, state)| {
            matches!(
                state,
                crate::streamed_store::StreamedAttemptState::Superseded { .. }
            )
        }) {
            return Err(StoreError::IncompleteEvidence);
        }
        Ok(selected)
    }
    pub fn progress(&self) -> NamespaceProgressSnapshot {
        if self.submitted_here {
            self.loaded.record.progress
        } else {
            self.loaded.record.progress()
        }
    }
    /// Durable bookkeeping only. Historical Submitted can NEVER be resubmitted.
    pub fn mark_submitted(&mut self) -> Result<(), StoreError> {
        self.append(NamespaceEventKind::RemoteSubmitted)
    }
    pub fn record_attention(&mut self, attention: NamespaceAttention) -> Result<(), StoreError> {
        self.append(match attention {
            NamespaceAttention::Conflict => NamespaceEventKind::Conflict,
            NamespaceAttention::Deferred => NamespaceEventKind::Deferred,
            NamespaceAttention::Uncertain => NamespaceEventKind::Uncertain,
        })
    }
    fn append(&mut self, kind: NamespaceEventKind) -> Result<(), StoreError> {
        if matches!(
            kind,
            NamespaceEventKind::LocalCompleted { .. } | NamespaceEventKind::LocalContinued { .. }
        ) {
            return Err(StoreError::Invalid);
        }
        self.append_authorized(kind)
    }
    fn append_authorized(&mut self, kind: NamespaceEventKind) -> Result<(), StoreError> {
        if self.poisoned {
            return Err(StoreError::PublicationUncertain);
        }
        let prior = self.progress();
        check_transition(prior, &kind)?;
        let key = &self.loaded.record.key;
        let mut checked = self.store.load(
            &*self.directory,
            &key.id,
            &key.scope,
            &mut Budget::new(self.store.base.policy),
        )?;
        if checked.record.key != *key || checked.record.commitment != self.loaded.record.commitment
        {
            return Err(StoreError::CorruptEvidence);
        }
        let event = NamespaceEvent {
            context: checked
                .record
                .intent()
                .event_context()
                .map_err(|_| StoreError::Invalid)?,
            sequence: prior.sequence + 1,
            event: kind,
        };
        checked
            .checked
            .record(&event)
            .map_err(|_| StoreError::Invalid)?;
        let plain = Zeroizing::new(serde_json::to_vec(&event).map_err(|_| StoreError::Invalid)?);
        let sealed = self
            .store
            .seal(key, event.sequence, &checked.record.commitment, &plain)?;
        let _quota = self.store.reserve(sealed.len() as u64, 2)?;
        self.poisoned = true;
        persist_metadata(
            &*self.directory,
            &format!("{}.event.{:020}", key.id, event.sequence),
            &sealed,
        )
        .map_err(|_| StoreError::PublicationUncertain)?;
        let loaded = self.store.load(
            &*self.directory,
            &key.id,
            &key.scope,
            &mut Budget::new(self.store.base.policy),
        )?;
        self.submitted_here |= matches!(event.event, NamespaceEventKind::RemoteSubmitted);
        self.loaded = loaded;
        self.poisoned = false;
        Ok(())
    }
}
fn check_transition(
    prior: NamespaceProgressSnapshot,
    kind: &NamespaceEventKind,
) -> Result<(), StoreError> {
    if prior.attention.is_some() || prior.recorded_complete || prior.sequence >= 128 {
        return Err(StoreError::Invalid);
    }
    match kind {
        NamespaceEventKind::LocalCompleted { .. } if prior.remote == NamespacePhase::Verified => {
            Ok(())
        }
        NamespaceEventKind::LocalContinued { .. } if prior.remote == NamespacePhase::Verified => {
            Ok(())
        }
        NamespaceEventKind::RemoteVerified { .. } if prior.remote == NamespacePhase::Submitted => {
            Ok(())
        }
        NamespaceEventKind::RemoteSubmitted
            if prior.sequence == 0 && prior.remote == NamespacePhase::Pending =>
        {
            Ok(())
        }
        NamespaceEventKind::Deferred
        | NamespaceEventKind::Conflict
        | NamespaceEventKind::Uncertain => Ok(()),
        _ => Err(StoreError::Invalid), // No public remote/native-completion claims.
    }
}
fn destination(
    intent: &NamespaceIntent,
) -> Result<&crate::namespace_intent::LocalNamespaceEntry, StoreError> {
    if let NamespaceOperation::CreateFile { destination, .. } = &intent.operation {
        Ok(destination)
    } else {
        Err(StoreError::Invalid)
    }
}
fn validate_join(
    joined: &FileJoin,
    scope: &EditJournalScope,
    manifest: &SnapshotManifest,
) -> Result<(), StoreError> {
    joined.intent.validate().map_err(|_| StoreError::Invalid)?;
    let NamespaceOperation::CreateFile {
        destination,
        content,
    } = &joined.intent.operation
    else {
        return Err(StoreError::Invalid);
    };
    let binding = manifest.binding();
    let reference = &joined.snapshot;
    let mut local = destination.parent.local_components.clone();
    local.push(destination.name.clone());
    CapturedCreatePath::new(local, reference.space_relative_path.clone())?;
    if joined.version != 1
        || &destination.parent.scope != scope
        || &binding.scope != scope
        || binding.remote.is_some()
        || binding.generation != joined.intent.record_generation
        || reference.generation != binding.generation
        || reference.id != binding.record_id
        || !valid_id(&reference.id)
        || destination.local_file != binding.local_file
        || binding.relative_path != reference.space_relative_path
        || content.byte_len != binding.content_len
        || content.sha256 != hex(manifest.content_sha256())
        || reference.content_sha256 != *manifest.content_sha256()
        || reference.container_len != manifest.container_len()
        || reference.container_sha256 != *manifest.container_sha256()
        || reference.manifest_commitment
            != *StreamedRecordKey::from_manifest(manifest)?.commitment_sha256()
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn account_root(a: &EditJournalScope, b: &EditJournalScope) -> bool {
    a.profile_id == b.profile_id
        && a.server_origin == b.server_origin
        && a.account_subject == b.account_subject
        && a.root_volume_serial == b.root_volume_serial
        && a.root_file_index == b.root_file_index
}
fn aad(key: &FileCreateKey, seq: u64, previous: &[u8; 32]) -> Result<Vec<u8>, StoreError> {
    let mut aad = DOMAIN.to_vec();
    aad.extend(
        serde_json::to_vec(&(
            &key.scope,
            &key.id,
            key.generation,
            &key.digest,
            seq,
            previous,
        ))
        .map_err(|_| StoreError::Invalid)?,
    );
    Ok(aad)
}
fn join_hash(plain: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(b"payload\0");
    h.update(plain);
    h.finalize().into()
}
fn event_hash(previous: &[u8; 32], plain: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(b"event\0");
    h.update(previous);
    h.update(plain);
    h.finalize().into()
}
fn catalog_aad(key: &str) -> Vec<u8> {
    [DOMAIN, b"scope\0", key.as_bytes()].concat()
}
fn parse_event(suffix: &str) -> Option<u64> {
    let digits = suffix.strip_prefix("event.")?;
    if digits.len() != 20 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let seq = digits.parse().ok()?;
    (seq > 0 && seq <= 128).then_some(seq)
}
fn record_name(name: &str) -> Result<(&str, &str), StoreError> {
    let (id, suffix) = name.split_once('.').ok_or(StoreError::IncompleteEvidence)?;
    if !valid_id(id)
        || !(suffix == "intent" || suffix == "dispatch.lock" || parse_event(suffix).is_some())
    {
        return Err(StoreError::IncompleteEvidence);
    }
    Ok((id, suffix))
}
fn read_catalog(
    root: &dyn Directory,
    protector: &dyn EditRecordProtector,
    key: &str,
    budget: &mut Budget,
) -> Result<EditJournalScope, StoreError> {
    let sealed = read_metadata(root, &format!("{key}.scope"), budget)?;
    let plain = Zeroizing::new(
        protector
            .open(&catalog_aad(key), &sealed)
            .map_err(|_| StoreError::CorruptEvidence)?,
    );
    if plain.len() > META_LIMIT / 2 {
        return Err(StoreError::CorruptEvidence);
    }
    let scope: EditJournalScope =
        serde_json::from_slice(&plain).map_err(|_| StoreError::CorruptEvidence)?;
    validate_scope(&scope)?;
    if scope_key(&scope)? != key {
        return Err(StoreError::CorruptEvidence);
    }
    Ok(scope)
}
fn catalogs(
    root: &dyn Directory,
    protector: &dyn EditRecordProtector,
    budget: &mut Budget,
) -> Result<Vec<(String, EditJournalScope)>, StoreError> {
    root.verify()?;
    let names = root.entries(budget.remaining_entries())?;
    budget.entries(names.len())?;
    let mut unique = std::collections::HashSet::new();
    let mut scopes = Vec::new();
    for name in &names {
        if !unique.insert(name) {
            return Err(StoreError::CorruptEvidence);
        }
        if let Some(key) = name.strip_suffix(".scope") {
            if !valid_key(key) || !names.contains(&key.to_owned()) {
                return Err(StoreError::IncompleteEvidence);
            }
            if scopes.len() >= MAX_SCOPES {
                return Err(StoreError::ScanLimit);
            }
            let scope = read_catalog(root, protector, key, budget)?;
            root.child(key, false)?.verify()?;
            scopes.push((key.into(), scope));
        } else if !valid_key(name) || !names.contains(&format!("{name}.scope")) {
            return Err(StoreError::IncompleteEvidence);
        }
    }
    Ok(scopes)
}
/// Authenticate every paired file-store scope catalog and return its key for
/// the shared cross-store scope bound. No file-create records or dispatch
/// capability are returned.
pub(super) fn validated_catalog_scope_keys(
    root: &dyn Directory,
    protector: &dyn EditRecordProtector,
    budget: &mut Budget,
) -> Result<Vec<String>, StoreError> {
    Ok(catalogs(root, protector, budget)?
        .into_iter()
        .map(|(key, _scope)| key)
        .collect())
}

/// Count authenticated current-scope joins under the caller's existing quota
/// lease and cumulative budget. No body open, directory creation, lock or
/// writable capability escapes. Completed joins require their exact authenticated
/// snapshot zero-attempt ACK under this same lock and cumulative budget.
#[cfg(test)]
pub(super) fn history_counts_existing(
    root: Arc<dyn Directory>,
    protector: Arc<dyn EditRecordProtector>,
    policy: StorePolicy,
    provider: &crate::ProviderScope,
    physical: crate::ConfiguredRootIdentity,
    budget: &mut Budget,
    remaining: usize,
) -> Result<(usize, usize), StoreError> {
    history_counts_with_acknowledged_gaps_existing(
        root, protector, policy, provider, physical, budget, remaining,
    )
    .map(|(records, unresolved, _)| (records, unresolved))
}

/// Same retained-history scan and allowance, with a separate count of exact
/// zero-attempt ACK gaps. Strict unresolved counts remain unchanged.
pub(super) fn history_counts_with_acknowledged_gaps_existing(
    root: Arc<dyn Directory>,
    protector: Arc<dyn EditRecordProtector>,
    policy: StorePolicy,
    provider: &crate::ProviderScope,
    physical: crate::ConfiguredRootIdentity,
    budget: &mut Budget,
    remaining: usize,
) -> Result<(usize, usize, usize), StoreError> {
    history_counts_existing_inner(
        root, protector, policy, provider, physical, budget, remaining, false, None, None,
    )
    .map(|(records, unresolved, gaps, _, _)| (records, unresolved, gaps))
}

/// Explicit support inspection only. Original snapshot history is authenticated
/// even when the ACK-gap classifier excludes the namespace phase immediately.
pub(super) fn history_counts_detailed_existing(
    root: Arc<dyn Directory>,
    protector: Arc<dyn EditRecordProtector>,
    policy: StorePolicy,
    provider: &crate::ProviderScope,
    physical: crate::ConfiguredRootIdentity,
    budget: &mut Budget,
    remaining: usize,
) -> Result<(usize, usize, usize, Vec<PendingFileCreateClassification>), StoreError> {
    history_counts_existing_inner(
        root, protector, policy, provider, physical, budget, remaining, true, None, None,
    )
    .map(|(records, unresolved, gaps, details, _)| (records, unresolved, gaps, details))
}

/// Caller retains the original quota lease. Keys identify only exact historical
/// originals isolated from the exact fresh target, never replay/native custody.
#[allow(clippy::too_many_arguments)]
pub(super) fn history_counts_for_fresh_create_space_existing(
    root: Arc<dyn Directory>,
    protector: Arc<dyn EditRecordProtector>,
    policy: StorePolicy,
    provider: &crate::ProviderScope,
    physical: crate::ConfiguredRootIdentity,
    budget: &mut Budget,
    remaining: usize,
    candidate_scope: &EditJournalScope,
    candidate_target: Option<&crate::fresh_create_target::FreshCreateTarget>,
) -> Result<(usize, usize, usize, Vec<StreamedRecordKey>), StoreError> {
    history_counts_existing_inner(
        root,
        protector,
        policy,
        provider,
        physical,
        budget,
        remaining,
        false,
        Some(candidate_scope),
        candidate_target,
    )
    .map(|(records, unresolved, gaps, _, keys)| (records, unresolved, gaps, keys))
}

type FileHistoryScan = (
    usize,
    usize,
    usize,
    Vec<PendingFileCreateClassification>,
    Vec<StreamedRecordKey>,
);

#[allow(clippy::too_many_arguments)]
fn history_counts_existing_inner(
    root: Arc<dyn Directory>,
    protector: Arc<dyn EditRecordProtector>,
    policy: StorePolicy,
    provider: &crate::ProviderScope,
    physical: crate::ConfiguredRootIdentity,
    budget: &mut Budget,
    remaining: usize,
    include_details: bool,
    candidate_scope: Option<&EditJournalScope>,
    candidate_target: Option<&crate::fresh_create_target::FreshCreateTarget>,
) -> Result<FileHistoryScan, StoreError> {
    let files = root.child(ROOT, false)?;
    let scopes = catalogs(&*files, &*protector, budget)?;
    let mut records = 0usize;
    let mut unresolved = 0usize;
    let mut acknowledged_join_gaps = 0usize;
    let mut classifications = std::collections::BTreeMap::new();
    let mut space_exemptions = Vec::new();
    for (key, scope) in scopes {
        let directory = files.child(&key, false)?;
        let names = directory.entries(budget.remaining_entries())?;
        budget.entries(names.len())?;
        let mut ids = std::collections::BTreeSet::new();
        let mut unique = std::collections::HashSet::new();
        for name in &names {
            if !unique.insert(name) {
                return Err(StoreError::CorruptEvidence);
            }
            let (id, suffix) = record_name(name)?;
            if !names.contains(&format!("{id}.intent")) {
                return Err(StoreError::IncompleteEvidence);
            }
            if suffix == "dispatch.lock" {
                let pin = directory.open(name)?;
                if pin.len()? != 0 {
                    return Err(StoreError::CorruptEvidence);
                }
                pin.verify()?;
            }
            ids.insert(id.to_owned());
        }
        if scope.profile_id == provider.profile_id()
            && scope.server_origin == provider.server_origin()
            && scope.account_subject == provider.account_id()
            && scope.root_volume_serial == physical.volume_serial
            && scope.root_file_index == physical.file_index
        {
            records = records
                .checked_add(ids.len())
                .ok_or(StoreError::ScanLimit)?;
            if records > remaining {
                return Err(StoreError::ScanLimit);
            }
            // This ephemeral context uses an authenticated real scope and the
            // caller's pinned root; from_directory neither creates nor locks.
            let decoder = FileCreateStore {
                base: SnapshotStore::from_directory(
                    Arc::clone(&root),
                    scope.clone(),
                    Arc::clone(&protector),
                    policy,
                )?,
            };
            // This existing-lock scanner borrows one exact snapshot-scope view.
            // All snapshot/namespace event publication shares the caller's
            // retained quota.lock, so no cooperating writer can change its names.
            // Enumeration is lazy until the first historical state read; empty
            // and noneligible joins gain no new IO or budget charge. Do not
            // retain the view beyond this decoder. Direct readers enumerate.
            let snapshot_history = decoder.base.namespace_snapshot_histories();
            for id in ids {
                let loaded = decoder.load_names_with_history(
                    &*directory,
                    &id,
                    &scope,
                    &names,
                    budget,
                    false,
                    Some(&snapshot_history),
                )?;
                unresolved += usize::from(!loaded.record.progress.recorded_complete);
                let eligible = decoder.acknowledged_original_with_history(
                    &loaded,
                    budget,
                    Some(&snapshot_history),
                )?;
                acknowledged_join_gaps += usize::from(eligible);
                let progress = loaded.record.progress;
                let different_space_root = candidate_scope.is_some_and(|candidate| {
                    scope.space_id != candidate.space_id
                        && scope.root_resource_id != candidate.root_resource_id
                });
                let same_space_root = candidate_scope.is_some_and(|candidate| {
                    scope.space_id == candidate.space_id
                        && scope.root_resource_id == candidate.root_resource_id
                });
                // These closed event histories still own unresolved native
                // work. Only isolation of an independently admitted new target
                // is classified; no old send or completion is authorized.
                let isolated_phase = (progress.remote == NamespacePhase::Submitted
                    && progress.sequence == 1
                    && progress.attention.is_none())
                    || (progress.remote == NamespacePhase::Submitted
                        && progress.sequence == 2
                        && progress.attention == Some(NamespaceAttention::Uncertain)
                        && loaded.remote.is_none())
                    || (progress.remote == NamespacePhase::Verified
                        && progress.sequence == 2
                        && progress.attention.is_none()
                        && loaded.remote.is_some());
                if (different_space_root || (same_space_root && candidate_target.is_some()))
                    && isolated_phase
                    && !progress.local_completed
                    && !progress.continued
                    && !progress.recorded_complete
                    && progress.source_removal.is_none()
                {
                    let (manifest, original_directory) = decoder.reference_manifest_metadata(
                        &loaded.record.joined,
                        &loaded.record.key.scope,
                        budget,
                    )?;
                    if decoder.original_snapshot_state(
                        &manifest,
                        &*original_directory,
                        budget,
                        Some(&snapshot_history),
                    )? == StreamedAttemptState::NotAttempted
                    {
                        // The manifest/reference/reservation join above already
                        // authenticated the exact CreateFile destination, path,
                        // FileID, generation and full snapshot commitment.
                        let old = destination(&loaded.record.joined.intent)
                            .map_err(|_| StoreError::CorruptEvidence)?;
                        let target_disjoint = different_space_root
                            || (same_space_root
                                && candidate_target.is_some_and(|target| {
                                    target.definitely_disjoint_from_file(
                                        &old.parent.remote.resource_id,
                                        &old.name,
                                        &manifest.binding().relative_path,
                                    )
                                }));
                        if target_disjoint {
                            let key = StreamedRecordKey::from_manifest(&manifest)?;
                            if space_exemptions.contains(&key) {
                                return Err(StoreError::CorruptEvidence);
                            }
                            space_exemptions.push(key);
                        }
                    }
                }
                if include_details && !loaded.record.progress.recorded_complete {
                    let (manifest, original_directory) = decoder.reference_manifest_metadata(
                        &loaded.record.joined,
                        &loaded.record.key.scope,
                        budget,
                    )?;
                    let state = decoder.original_snapshot_state(
                        &manifest,
                        &*original_directory,
                        budget,
                        Some(&snapshot_history),
                    )?;
                    let classification = pending_classification(&loaded, state, eligible);
                    let count = classifications.entry(classification).or_insert(0usize);
                    *count = count.checked_add(1).ok_or(StoreError::ScanLimit)?;
                }
            }
        }
        directory.verify()?;
    }
    files.verify()?;
    root.verify()?;
    let classifications = classifications
        .into_iter()
        .map(|(mut row, count)| {
            row.count = count;
            row
        })
        .collect();
    Ok((
        records,
        unresolved,
        acknowledged_join_gaps,
        classifications,
        space_exemptions,
    ))
}

pub(super) fn accounted_usage(
    root: &dyn Directory,
    protector: &dyn EditRecordProtector,
    budget: &mut Budget,
) -> Result<Inventory, StoreError> {
    let scopes = catalogs(root, protector, budget)?;
    let mut usage = Inventory {
        bytes: 0,
        entries: scopes.len().checked_mul(2).ok_or(StoreError::ScanLimit)?,
    };
    for (key, _) in scopes {
        usage.add(root.open(&format!("{key}.scope"))?.len()?)?;
        let directory = root.child(&key, false)?;
        let names = directory.entries(budget.remaining_entries())?;
        budget.entries(names.len())?;
        usage.entries = usage
            .entries
            .checked_add(names.len())
            .ok_or(StoreError::ScanLimit)?;
        for name in names {
            usage.add(directory.open(&name)?.len()?)?;
        }
        directory.verify()?;
    }
    root.verify()?;
    Ok(usage)
}
#[cfg(all(test, unix))]
#[path = "namespace_file_store_tests.rs"]
mod tests;

//! Preserve-only directory reports. Neither keys nor authenticated progress
//! authorize remote mutation, native conversion, clean state or deletion.
use super::*;
use crate::namespace_intent::{
    NamespaceAttention, NamespaceEvent, NamespaceEventKind, NamespaceIntent,
    NamespaceIntentProgress, NamespaceOperation, NamespacePhase, NamespaceProgressSnapshot,
};

pub(super) const ROOT: &str = "namespace-v1";
const DOMAIN: &[u8] = b"raiun/namespace-store/v1\0";
const APPEND_RESERVE_ATTEMPTS: usize = 3;
const APPEND_RESERVE_DELAY: std::time::Duration = std::time::Duration::from_millis(10);
const ADMISSION_LOCK_ATTEMPTS: usize = 3;
const ADMISSION_LOCK_DELAY: std::time::Duration = std::time::Duration::from_millis(10);

macro_rules! observe_history {
    ($stage:literal, $result:expr) => {{ observe_history_result($stage, $result) }};
}

#[derive(Clone, Eq, PartialEq)]
pub struct DirectoryIntentKey {
    scope: String,
    id: String,
    generation: u64,
    digest: String,
}
#[derive(Clone)]
pub struct StoredDirectoryIntent {
    pub key: DirectoryIntentKey,
    pub intent: NamespaceIntent,
    pub progress: NamespaceProgressSnapshot,
    pub commitment: [u8; 32],
}

/// Static authenticated pending-history histogram only. No identifier, path,
/// historical report or recovery/mutation capability is retained or exposed.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct PendingDirectoryCreateClassification {
    pub phase: &'static str,
    pub sequence: u64,
    pub attention: &'static str,
    pub local_completed: bool,
    pub continued: bool,
    pub source_removal: Option<&'static str>,
    pub recorded_complete: bool,
    pub count: usize,
}
impl PendingDirectoryCreateClassification {
    fn from_progress(progress: NamespaceProgressSnapshot) -> Self {
        fn phase(value: NamespacePhase) -> &'static str {
            match value {
                NamespacePhase::Pending => "pending",
                NamespacePhase::Submitted => "submitted",
                NamespacePhase::Verified => "verified",
            }
        }
        Self {
            phase: phase(progress.remote),
            sequence: progress.sequence,
            attention: match progress.attention {
                None => "none",
                Some(NamespaceAttention::Conflict) => "conflict",
                Some(NamespaceAttention::Deferred) => "deferred",
                Some(NamespaceAttention::Uncertain) => "uncertain",
            },
            local_completed: progress.local_completed,
            continued: progress.continued,
            source_removal: progress.source_removal.map(phase),
            recorded_complete: progress.recorded_complete,
            count: 0,
        }
    }
}
pub struct PublishedDirectoryIntent {
    pub record: StoredDirectoryIntent,
    pub created: bool,
}
pub struct DirectoryIntentStore {
    base: Arc<SnapshotStore>,
    #[cfg(windows)]
    admission: crate::recovery_admission::RecoveryAdmission,
}
// Header fields are untrusted until the sealed payload authenticates them.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    generation: u64,
    digest: String,
    sealed: Vec<u8>,
}
struct Loaded {
    record: StoredDirectoryIntent,
    progress: NamespaceIntentProgress,
    remote_verified_child_id: Option<String>,
}
impl DirectoryIntentStore {
    /// Local metadata storage at the current user's admitted recovery root.
    /// Scope validation and storage access grant no remote/native authority.
    #[cfg(windows)]
    pub fn current_user(
        scope: EditJournalScope,
        policy: StorePolicy,
    ) -> Result<Arc<Self>, StoreError> {
        validate_scope(&scope)?;
        policy.validate()?;
        let protector =
            crate::DpapiEditRecordProtector::current_user().map_err(|_| StoreError::Io)?;
        let state = crate::recovery_state::RecoveryStateRoot::existing_gui(
            protector.local_state_directory(),
        )
        .map_err(io_error)?;
        Self::create_or_open_admitted(state, scope, Arc::new(protector), policy)
    }

    #[cfg(windows)]
    pub fn create_or_open(
        state: Arc<raiun_control_windows::PrivateDirectory>,
        scope: EditJournalScope,
        protector: Arc<dyn EditRecordProtector>,
        policy: StorePolicy,
    ) -> Result<Arc<Self>, StoreError> {
        let admission = crate::recovery_admission::RecoveryAdmission::new(
            Arc::clone(&state),
            Arc::clone(&protector),
            policy,
        )?;
        Ok(Arc::new(Self {
            base: SnapshotStore::create_or_open(state, scope, protector, policy)?,
            admission,
        }))
    }
    #[cfg(windows)]
    pub(crate) fn create_or_open_admitted(
        state: Arc<crate::recovery_state::RecoveryStateRoot>,
        scope: EditJournalScope,
        protector: Arc<dyn EditRecordProtector>,
        policy: StorePolicy,
    ) -> Result<Arc<Self>, StoreError> {
        let admission = crate::recovery_admission::RecoveryAdmission::new_admitted(
            Arc::clone(&state),
            Arc::clone(&protector),
            policy,
        )?;
        Ok(Arc::new(Self {
            base: SnapshotStore::create_or_open_admitted(state, scope, protector, policy)?,
            admission,
        }))
    }
    /// Bind only an existing verified v2 root. No quota, catalog, scope or
    /// journal entries are created; absence is distinct from unsafe evidence.
    #[cfg(windows)]
    pub(crate) fn open_existing_admitted(
        state: Arc<crate::recovery_state::RecoveryStateRoot>,
        scope: EditJournalScope,
        protector: Arc<dyn EditRecordProtector>,
        policy: StorePolicy,
    ) -> Result<Option<Arc<Self>>, StoreError> {
        validate_scope(&scope)?;
        policy.validate()?;
        let Some(root) = windows::existing_root(Arc::clone(&state), V2_STORE_ROOT)? else {
            return Ok(None);
        };
        let base = SnapshotStore::from_directory(root, scope, Arc::clone(&protector), policy)?;
        let admission =
            crate::recovery_admission::RecoveryAdmission::new_admitted(state, protector, policy)?;
        Ok(Some(Arc::new(Self { base, admission })))
    }
    fn reserve(&self, bytes: u64, entries: usize) -> Result<Box<dyn Send>, StoreError> {
        #[cfg(windows)]
        {
            Ok(Box::new(self.admission.try_reserve(
                &self.base.scope,
                bytes,
                entries,
            )?))
        }
        #[cfg(not(windows))]
        {
            let lock = self.base.acquire_lock()?;
            let usage = self.base.inventory()?;
            if usage.bytes.checked_add(bytes).ok_or(StoreError::Quota)?
                > self.base.policy.max_state_bytes
                || usage
                    .entries
                    .checked_add(entries)
                    .ok_or(StoreError::Quota)?
                    > self.base.policy.max_entries
            {
                return Err(StoreError::Quota);
            }
            Ok(Box::new(lock))
        }
    }
    fn directory(&self, create: bool) -> Result<Arc<dyn Directory>, StoreError> {
        if create {
            self.base.validate_requested_catalog_scope()?;
        }
        let root_names = self.base.root.entries(self.base.policy.max_entries)?;
        let root = self
            .base
            .root
            .child(ROOT, create && !root_names.contains(&ROOT.to_owned()))?;
        let names = root.entries(self.base.policy.max_entries)?;
        let name = format!("{}.scope", self.base.key);
        let fresh = !names.contains(&name);
        if fresh {
            if !create || names.contains(&self.base.key) {
                return Err(StoreError::IncompleteEvidence);
            }
            let sealed = self
                .base
                .seal_metadata(&catalog_aad(&self.base.key), &self.base.scope)?;
            persist_metadata(&*root, &name, &sealed)?;
        } else if !names.contains(&self.base.key) {
            return Err(StoreError::IncompleteEvidence);
        }
        let mut budget = Budget::new(self.base.policy);
        let bytes = read_metadata(&*root, &name, &mut budget)?;
        let plain = Zeroizing::new(
            self.base
                .protector
                .open(&catalog_aad(&self.base.key), &bytes)
                .map_err(|_| StoreError::CorruptEvidence)?,
        );
        if plain.len() > META_LIMIT / 2 {
            return Err(StoreError::CorruptEvidence);
        }
        let scope: EditJournalScope =
            serde_json::from_slice(&plain).map_err(|_| StoreError::CorruptEvidence)?;
        if scope != self.base.scope {
            return Err(StoreError::CorruptEvidence);
        }
        root.child(&self.base.key, fresh)
    }
    /// A duplicate joins the retained generation. It does not create a fresh
    /// admission or change any captured authorization.
    pub fn publish_intent(
        self: &Arc<Self>,
        intent: NamespaceIntent,
    ) -> Result<PublishedDirectoryIntent, StoreError> {
        self.check_intent(&intent)?;
        let _quota = self.reserve((META_LIMIT as u64) * 2, 6)?;
        let directory = self.directory(true)?;
        self.publish_intent_while_reserved(intent, directory)
    }

    /// Admit only this new publication and its dispatch-lock entry together.
    /// A duplicate remains retained history and never gains a dispatch lease.
    #[cfg(windows)]
    pub(crate) fn publish_intent_for_dispatch(
        self: &Arc<Self>,
        intent: NamespaceIntent,
    ) -> Result<(PublishedDirectoryIntent, Option<DirectoryIntentLease>), StoreError> {
        self.check_intent(&intent)?;
        let quota = self.reserve((META_LIMIT as u64) * 2, 7)?;
        let directory = self.directory(true)?;
        let published = self.publish_intent_while_reserved(intent, Arc::clone(&directory))?;
        if !published.created {
            return Ok((published, None));
        }
        let lease =
            self.acquire_dispatch_while_reserved(&published.record.key, directory, quota)?;
        Ok((published, Some(lease)))
    }

    /// The caller retains the full publication quota lease for this body.
    fn publish_intent_while_reserved(
        self: &Arc<Self>,
        mut intent: NamespaceIntent,
        directory: Arc<dyn Directory>,
    ) -> Result<PublishedDirectoryIntent, StoreError> {
        for loaded in self.load_all(&*directory)? {
            // A renamed or reparented unfinished native directory still owns
            // its original recovery record; a new spelling cannot republish it.
            if !loaded.record.progress.recorded_complete
                && matches!(
                    (&intent.operation, &loaded.record.intent.operation),
                    (
                        NamespaceOperation::CreateDirectory { destination: incoming },
                        NamespaceOperation::CreateDirectory { destination: prior },
                    ) if incoming.local_file == prior.local_file
                )
            {
                return Ok(PublishedDirectoryIntent {
                    record: recovered(loaded.record),
                    created: false,
                });
            }
            if same_entry(&loaded.record.intent, &intent) {
                return Ok(PublishedDirectoryIntent {
                    record: recovered(loaded.record),
                    created: false,
                });
            }
        }
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| StoreError::Io)?;
        intent.record_id = hex(&random);
        self.check_intent(&intent)?;
        let digest = intent
            .event_context()
            .map_err(|_| StoreError::Invalid)?
            .intent_sha256;
        let key = DirectoryIntentKey {
            scope: self.base.key.clone(),
            id: intent.record_id.clone(),
            generation: intent.record_generation,
            digest,
        };
        let plain = Zeroizing::new(serde_json::to_vec(&intent).map_err(|_| StoreError::Invalid)?);
        let sealed = self.seal(&key, 0, &[0; 32], &plain)?;
        let envelope = Envelope {
            generation: key.generation,
            digest: key.digest.clone(),
            sealed,
        };
        let bytes = serde_json::to_vec(&envelope).map_err(|_| StoreError::Invalid)?;
        if bytes.len() > META_LIMIT {
            return Err(StoreError::Invalid);
        }
        persist_metadata(&*directory, &format!("{}.intent", key.id), &bytes)?;
        let loaded = self.load(&*directory, &key.id, &mut Budget::new(self.base.policy))?;
        if loaded.record.key != key || loaded.record.intent != intent {
            return Err(StoreError::PublicationUncertain);
        }
        Ok(PublishedDirectoryIntent {
            record: loaded.record,
            created: true,
        })
    }
    pub fn discover(&self) -> Result<Vec<StoredDirectoryIntent>, StoreError> {
        let mut budget = Budget::new(self.base.policy);
        let names = self.base.root.entries(budget.remaining_entries())?;
        budget.entries(names.len())?;
        if !names.contains(&ROOT.to_owned()) {
            return Ok(Vec::new());
        }
        let root = self.base.root.child(ROOT, false)?;
        let names = root.entries(budget.remaining_entries())?;
        budget.entries(names.len())?;
        for name in &names {
            if let Some(key) = name.strip_suffix(".scope") {
                if !valid_key(key) || !names.contains(&key.to_owned()) {
                    return Err(StoreError::IncompleteEvidence);
                }
                let bytes = read_metadata(&*root, name, &mut budget)?;
                let plain = Zeroizing::new(
                    self.base
                        .protector
                        .open(&catalog_aad(key), &bytes)
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
                root.child(key, false)?.verify()?;
            } else if !valid_key(name) || !names.contains(&format!("{name}.scope")) {
                return Err(StoreError::IncompleteEvidence);
            }
        }
        if !names.contains(&format!("{}.scope", self.base.key)) {
            return Ok(Vec::new());
        }
        self.load_all_bounded(&*root.child(&self.base.key, false)?, &mut budget)?
            .into_iter()
            .map(|item| Ok(recovered(item.record)))
            .collect()
    }
    /// Authenticated reports across Spaces of this exact admitted account and
    /// physical root. No body reads, new state/lock files, quota reservation,
    /// replay, native admission or adoption authority is granted.
    pub fn discover_account_root(&self) -> Result<Vec<StoredDirectoryIntent>, StoreError> {
        let mut policy = self.base.policy;
        policy.max_entries = policy.max_entries.min(20_000);
        policy.max_metadata_bytes_per_scan =
            policy.max_metadata_bytes_per_scan.min(64 * 1024 * 1024);
        policy.validate()?;
        self.discover_account_root_bounded(&mut Budget::new(policy))
    }
    fn discover_account_root_bounded(
        &self,
        budget: &mut Budget,
    ) -> Result<Vec<StoredDirectoryIntent>, StoreError> {
        self.discover_account_root_bounded_for(budget, None)
    }
    fn discover_account_root_bounded_for(
        &self,
        budget: &mut Budget,
        required_scope: Option<&EditJournalScope>,
    ) -> Result<Vec<StoredDirectoryIntent>, StoreError> {
        observe_history!("history_root_verify", self.base.root.verify())?;
        let names = observe_history!(
            "history_root_enumerate",
            self.base.root.entries(budget.remaining_entries())
        )?;
        observe_history!("history_root_budget", budget.entries(names.len()))?;
        let _lock = if names.iter().any(|name| name == V2_QUOTA_LOCK) {
            let mut lock =
                observe_history!("history_quota_open", self.base.root.open_quota_lock())?;
            if observe_history!("history_quota_length", lock.len())? != 0 {
                return Err(observe_history_error(
                    "history_quota_length_invalid",
                    StoreError::CorruptEvidence,
                ));
            }
            let mut attempts = 0;
            loop {
                attempts += 1;
                match lock.lock_exclusive() {
                    Ok(()) => break,
                    Err(StoreError::Busy)
                        if required_scope.is_none() && attempts < ADMISSION_LOCK_ATTEMPTS =>
                    {
                        admission_diagnostic("history_quota_lock", &StoreError::Busy);
                        std::thread::sleep(ADMISSION_LOCK_DELAY);
                    }
                    Err(error) => {
                        admission_diagnostic("history_quota_lock", &error);
                        return Err(error);
                    }
                }
            }
            observe_history!("history_quota_verify", lock.verify())?;
            Some(lock)
        } else {
            None
        };
        // Re-enumerate only under an existing shared lock. A first-use empty
        // namespace is valid without creating the lock or reserving any bytes.
        let names = if _lock.is_some() {
            let names = observe_history!(
                "history_root_reenumerate",
                self.base.root.entries(budget.remaining_entries())
            )?;
            observe_history!(
                "history_root_reenumerate_budget",
                budget.entries(names.len())
            )?;
            names
        } else {
            names
        };
        if names.iter().collect::<std::collections::HashSet<_>>().len() != names.len() {
            return Err(observe_history_error(
                "history_duplicate_root_entry",
                StoreError::CorruptEvidence,
            ));
        }
        let catalogs = observe_history!(
            "history_catalog_validation",
            self.base
                .validate_root_catalogs_with_scope_union(&names, budget)
        )?;
        let mut scopes = catalogs.keys;
        if !names.iter().any(|name| name == ROOT) {
            observe_history!("history_empty_root_verify", self.base.root.verify())?;
            if let Some(lock) = &_lock {
                observe_history!("history_empty_quota_verify", lock.verify())?;
            }
            if required_scope.is_some() {
                return Err(StoreError::IncompleteEvidence);
            }
            return Ok(Vec::new());
        }
        let root = observe_history!(
            "history_namespace_root_open",
            self.base.root.child(ROOT, false)
        )?;
        let names = observe_history!(
            "history_namespace_enumerate",
            root.entries(budget.remaining_entries())
        )?;
        observe_history!("history_namespace_budget", budget.entries(names.len()))?;
        if _lock.is_none() && !names.is_empty() {
            return Err(observe_history_error(
                "history_namespace_without_lock",
                StoreError::IncompleteEvidence,
            ));
        }
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        let mut required_scope_found = required_scope.is_none();
        for name in &names {
            if !seen.insert(name) {
                return Err(observe_history_error(
                    "history_duplicate_namespace_entry",
                    StoreError::CorruptEvidence,
                ));
            }
            if let Some(key) = name.strip_suffix(".scope") {
                if !valid_key(key) || !names.contains(&key.to_owned()) {
                    return Err(observe_history_error(
                        "history_namespace_catalog_incomplete",
                        StoreError::IncompleteEvidence,
                    ));
                }
                scopes.insert(key.to_owned());
                if scopes.len() > 256 {
                    return Err(observe_history_error(
                        "history_scope_limit",
                        StoreError::ScanLimit,
                    ));
                }
                let scope = observe_history!(
                    "history_scope_authentication",
                    authenticate_namespace_scope(&*root, &*self.base.protector, key, budget)
                )?;
                if required_scope.is_some_and(|required| required == &scope) {
                    required_scope_found = true;
                }
                let directory = observe_history!("history_scope_open", root.child(key, false))?;
                observe_history!("history_scope_verify", directory.verify())?;
                // Authenticate before filtering. Space and remote root IDs
                // intentionally differ when a physical child moves Spaces.
                if account_root_matches(&scope, &self.base.scope) {
                    let remaining = 2000usize.checked_sub(result.len()).ok_or_else(|| {
                        observe_history_error("history_record_limit", StoreError::ScanLimit)
                    })?;
                    let loaded = observe_history!(
                        "history_scope_records",
                        self.load_scope_bounded(&*directory, budget, &scope, remaining)
                    )?;
                    result.extend(loaded.into_iter().map(|item| recovered(item.record)));
                }
            } else if !valid_key(name) || !names.contains(&format!("{name}.scope")) {
                return Err(observe_history_error(
                    "history_orphan_catalog_entry",
                    StoreError::IncompleteEvidence,
                ));
            }
        }
        observe_history!("history_namespace_root_final_verify", root.verify())?;
        observe_history!("history_root_final_verify", self.base.root.verify())?;
        if let Some(lock) = _lock {
            observe_history!("history_quota_final_verify", lock.verify())?;
        }
        if !required_scope_found {
            return Err(StoreError::IncompleteEvidence);
        }
        Ok(result)
    }
    pub fn acquire_dispatch(
        self: &Arc<Self>,
        key: &DirectoryIntentKey,
    ) -> Result<DirectoryIntentLease, StoreError> {
        if key.scope != self.base.key {
            return Err(StoreError::Invalid);
        }
        let directory = self.directory(false)?;
        // Creation of the persistent lock is itself quota-admitted.
        let mut reserve_attempts = 0;
        let quota = loop {
            reserve_attempts += 1;
            match self.reserve(0, 1) {
                Ok(quota) => break quota,
                Err(StoreError::Busy) if reserve_attempts < ADMISSION_LOCK_ATTEMPTS => {
                    admission_diagnostic("dispatch_quota_reserve", &StoreError::Busy);
                    std::thread::sleep(ADMISSION_LOCK_DELAY);
                }
                Err(error) => {
                    admission_diagnostic("dispatch_quota_reserve", &error);
                    return Err(error);
                }
            }
        };
        self.acquire_dispatch_while_reserved(key, directory, quota)
    }

    /// The caller has admitted this dispatch-lock entry under the quota lease.
    fn acquire_dispatch_while_reserved(
        self: &Arc<Self>,
        key: &DirectoryIntentKey,
        directory: Arc<dyn Directory>,
        quota: Box<dyn Send>,
    ) -> Result<DirectoryIntentLease, StoreError> {
        let name = format!("{}.dispatch.lock", key.id);
        if let Ok((file, _)) = directory.create(&name) {
            file.sync()?;
            drop(file);
        }
        let mut lock = directory.open(&name)?;
        if lock.len()? != 0 {
            return Err(StoreError::CorruptEvidence);
        }
        drop(quota);
        if let Err(error) = lock.lock_exclusive() {
            admission_diagnostic("dispatch_operation_lock", &error);
            return Err(error);
        }
        lock.verify()?;
        let loaded = self.load(&*directory, &key.id, &mut Budget::new(self.base.policy))?;
        if &loaded.record.key != key {
            return Err(StoreError::CorruptEvidence);
        }
        Ok(DirectoryIntentLease {
            store: Arc::clone(self),
            directory,
            _lock: lock,
            loaded,
            submitted_here: false,
            poisoned: false,
            #[cfg(all(test, windows))]
            last_append_reserve_attempts: 0,
        })
    }
    fn check_intent(&self, intent: &NamespaceIntent) -> Result<(), StoreError> {
        check_scoped_intent(intent, &self.base.scope)
    }
    fn aad(
        &self,
        key: &DirectoryIntentKey,
        seq: u64,
        previous: &[u8; 32],
    ) -> Result<Vec<u8>, StoreError> {
        record_aad(&self.base.scope, key, seq, previous)
    }

    fn seal(
        &self,
        key: &DirectoryIntentKey,
        seq: u64,
        previous: &[u8; 32],
        plain: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        if plain.len() > META_LIMIT / 2 {
            return Err(StoreError::Invalid);
        }
        let sealed = self
            .base
            .protector
            .seal(&self.aad(key, seq, previous)?, plain)
            .map_err(|_| StoreError::CorruptEvidence)?;
        if sealed.is_empty() || sealed.len() > META_LIMIT / 2 {
            return Err(StoreError::Invalid);
        }
        Ok(sealed)
    }
    fn load_all(&self, directory: &dyn Directory) -> Result<Vec<Loaded>, StoreError> {
        let mut budget = Budget::new(self.base.policy);
        self.load_all_bounded(directory, &mut budget)
    }
    fn load_all_bounded(
        &self,
        directory: &dyn Directory,
        budget: &mut Budget,
    ) -> Result<Vec<Loaded>, StoreError> {
        self.load_scope_bounded(directory, budget, &self.base.scope, usize::MAX)
    }
    fn load_scope_bounded(
        &self,
        directory: &dyn Directory,
        budget: &mut Budget,
        scope: &EditJournalScope,
        record_limit: usize,
    ) -> Result<Vec<Loaded>, StoreError> {
        DirectoryHistoryDecoder {
            protector: &*self.base.protector,
        }
        .load_scope_bounded(directory, budget, scope, record_limit)
    }
    fn load(
        &self,
        directory: &dyn Directory,
        id: &str,
        budget: &mut Budget,
    ) -> Result<Loaded, StoreError> {
        let names = directory.entries(budget.remaining_entries())?;
        budget.entries(names.len())?;
        self.load_scoped(directory, id, budget, &self.base.scope, &names)
    }
    fn load_scoped(
        &self,
        directory: &dyn Directory,
        id: &str,
        budget: &mut Budget,
        scope: &EditJournalScope,
        names: &[String],
    ) -> Result<Loaded, StoreError> {
        DirectoryHistoryDecoder {
            protector: &*self.base.protector,
        }
        .load_scoped(directory, id, budget, scope, names)
    }
}

/// Borrowed metadata decoder shared with the original writer's reopen paths.
/// No root, admission, storage reservation, writer or dispatch lease is held.
struct DirectoryHistoryDecoder<'a> {
    protector: &'a dyn EditRecordProtector,
}
impl DirectoryHistoryDecoder<'_> {
    fn open(
        &self,
        scope: &EditJournalScope,
        key: &DirectoryIntentKey,
        seq: u64,
        previous: &[u8; 32],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let plain = Zeroizing::new(
            self.protector
                .open(&record_aad(scope, key, seq, previous)?, sealed)
                .map_err(|_| StoreError::CorruptEvidence)?,
        );
        if plain.len() > META_LIMIT / 2 {
            return Err(StoreError::CorruptEvidence);
        }
        Ok(plain)
    }
    fn record_names(
        &self,
        directory: &dyn Directory,
        budget: &mut Budget,
    ) -> Result<(Vec<String>, std::collections::BTreeSet<String>), StoreError> {
        let names = directory.entries(budget.remaining_entries())?;
        budget.entries(names.len())?;
        let mut ids = std::collections::BTreeSet::new();
        for name in &names {
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
        Ok((names, ids))
    }
    fn load_scope_bounded(
        &self,
        directory: &dyn Directory,
        budget: &mut Budget,
        scope: &EditJournalScope,
        record_limit: usize,
    ) -> Result<Vec<Loaded>, StoreError> {
        let (names, ids) = self.record_names(directory, budget)?;
        if ids.len() > record_limit {
            return Err(StoreError::ScanLimit);
        }
        ids.into_iter()
            .map(|id| self.load_scoped(directory, &id, budget, scope, &names))
            .collect()
    }
    fn load_scoped(
        &self,
        directory: &dyn Directory,
        id: &str,
        budget: &mut Budget,
        scope: &EditJournalScope,
        names: &[String],
    ) -> Result<Loaded, StoreError> {
        let bytes = read_metadata(directory, &format!("{id}.intent"), budget)?;
        let envelope: Envelope =
            serde_json::from_slice(&bytes).map_err(|_| StoreError::CorruptEvidence)?;
        if !valid_id(id) || !valid_key(&envelope.digest) || envelope.generation == 0 {
            return Err(StoreError::CorruptEvidence);
        }
        let key = DirectoryIntentKey {
            scope: scope_key(scope)?,
            id: id.to_owned(),
            generation: envelope.generation,
            digest: envelope.digest,
        };
        let plain = self.open(scope, &key, 0, &[0; 32], &envelope.sealed)?;
        let intent: NamespaceIntent =
            serde_json::from_slice(&plain).map_err(|_| StoreError::CorruptEvidence)?;
        check_scoped_intent(&intent, scope).map_err(|_| StoreError::CorruptEvidence)?;
        if intent.record_id != key.id
            || intent.record_generation != key.generation
            || intent
                .event_context()
                .map_err(|_| StoreError::CorruptEvidence)?
                .intent_sha256
                != key.digest
        {
            return Err(StoreError::CorruptEvidence);
        }
        let mut commitment = commitment(&[0; 32], &plain);
        let mut progress = NamespaceIntentProgress::new(intent.clone())
            .map_err(|_| StoreError::CorruptEvidence)?;
        let mut remote_verified_child_id = None;
        let mut events = Vec::new();
        for name in names {
            if let Some(suffix) = name.strip_prefix(&format!("{id}.")) {
                if suffix == "intent" || suffix == "dispatch.lock" {
                    continue;
                }
                events.push((
                    parse_event(suffix).ok_or(StoreError::IncompleteEvidence)?,
                    name.clone(),
                ));
            }
        }
        events.sort();
        if events.len() > 128 {
            return Err(StoreError::ScanLimit);
        }
        for (index, (seq, name)) in events.into_iter().enumerate() {
            if seq != index as u64 + 1 {
                return Err(StoreError::IncompleteEvidence);
            }
            let bytes = read_metadata(directory, &name, budget)?;
            let plain = self.open(scope, &key, seq, &commitment, &bytes)?;
            let event: NamespaceEvent =
                serde_json::from_slice(&plain).map_err(|_| StoreError::CorruptEvidence)?;
            validate_transition(progress.snapshot(), &event.event)?;
            progress
                .record(&event)
                .map_err(|_| StoreError::CorruptEvidence)?;
            if let NamespaceEventKind::RemoteVerified { report } = &event.event {
                remote_verified_child_id = Some(report.remote.resource_id.clone());
            }
            commitment = commitment_fn(&commitment, &plain);
        }
        let snapshot = progress.snapshot();
        Ok(Loaded {
            record: StoredDirectoryIntent {
                key,
                intent,
                progress: snapshot,
                commitment,
            },
            progress,
            remote_verified_child_id,
        })
    }
}

/// Read one catalog-authenticated directory scope under the caller's existing
/// quota lease and cumulative budget. Foreign scopes are structurally checked,
/// never reinterpreted as selected records or granted any mutation authority.
pub(super) fn history_counts_existing(
    directory: &dyn Directory,
    protector: &dyn EditRecordProtector,
    scope: &EditJournalScope,
    provider: &crate::ProviderScope,
    physical: crate::ConfiguredRootIdentity,
    budget: &mut Budget,
    remaining: usize,
) -> Result<(usize, usize), StoreError> {
    history_counts_existing_with_classifications(
        directory, protector, scope, provider, physical, budget, remaining, None,
    )
}

/// Explicit diagnostics may aggregate static progress inline from the exact
/// rows already authenticated by the existing count scan. None is the normal
/// health path, with no additional classification or IO.
#[allow(clippy::too_many_arguments)]
pub(super) fn history_counts_existing_with_classifications(
    directory: &dyn Directory,
    protector: &dyn EditRecordProtector,
    scope: &EditJournalScope,
    provider: &crate::ProviderScope,
    physical: crate::ConfiguredRootIdentity,
    budget: &mut Budget,
    remaining: usize,
    classifications: Option<
        &mut std::collections::BTreeMap<PendingDirectoryCreateClassification, usize>,
    >,
) -> Result<(usize, usize), StoreError> {
    let (records, unresolved, _) = history_counts_existing_inner(
        directory,
        protector,
        scope,
        provider,
        physical,
        budget,
        remaining,
        classifications,
        None,
    )?;
    Ok((records, unresolved))
}

/// Classify only an independently admitted new target under the caller's
/// existing lock. Retained history remains unresolved and grants no authority.
#[allow(clippy::too_many_arguments)]
pub(super) fn history_counts_for_fresh_create_existing(
    directory: &dyn Directory,
    protector: &dyn EditRecordProtector,
    scope: &EditJournalScope,
    provider: &crate::ProviderScope,
    physical: crate::ConfiguredRootIdentity,
    budget: &mut Budget,
    remaining: usize,
    candidate_scope: &EditJournalScope,
    candidate_target: Option<&crate::fresh_create_target::FreshCreateTarget>,
) -> Result<(usize, usize, usize), StoreError> {
    history_counts_existing_inner(
        directory,
        protector,
        scope,
        provider,
        physical,
        budget,
        remaining,
        None,
        candidate_target.map(|target| (candidate_scope, target)),
    )
}

#[allow(clippy::too_many_arguments)]
fn history_counts_existing_inner(
    directory: &dyn Directory,
    protector: &dyn EditRecordProtector,
    scope: &EditJournalScope,
    provider: &crate::ProviderScope,
    physical: crate::ConfiguredRootIdentity,
    budget: &mut Budget,
    remaining: usize,
    mut classifications: Option<
        &mut std::collections::BTreeMap<PendingDirectoryCreateClassification, usize>,
    >,
    fresh_create: Option<(
        &EditJournalScope,
        &crate::fresh_create_target::FreshCreateTarget,
    )>,
) -> Result<(usize, usize, usize), StoreError> {
    validate_scope(scope)?;
    directory.verify()?;
    let decoder = DirectoryHistoryDecoder { protector };
    let (names, ids) = decoder.record_names(directory, budget)?;
    let selected = scope.profile_id == provider.profile_id()
        && scope.server_origin == provider.server_origin()
        && scope.account_subject == provider.account_id()
        && scope.root_volume_serial == physical.volume_serial
        && scope.root_file_index == physical.file_index;
    if !selected {
        directory.verify()?;
        return Ok((0, 0, 0));
    }
    if ids.len() > remaining {
        return Err(StoreError::ScanLimit);
    }
    let mut unresolved = 0;
    let mut independent = 0;
    for id in &ids {
        let row = decoder.load_scoped(directory, id, budget, scope, &names)?;
        unresolved += usize::from(!row.record.progress.recorded_complete);
        let progress = row.record.progress;
        let closed_submitted = progress.remote == NamespacePhase::Submitted
            && progress.sequence == 1
            && row.remote_verified_child_id.is_none();
        let closed_verified = progress.remote == NamespacePhase::Verified
            && progress.sequence == 2
            && row.remote_verified_child_id.is_some();
        if (closed_submitted || closed_verified)
            && progress.attention.is_none()
            && !progress.local_completed
            && !progress.continued
            && progress.source_removal.is_none()
            && !progress.recorded_complete
            && let Some((candidate_scope, target)) = fresh_create
            && scope == candidate_scope
            && let NamespaceOperation::CreateDirectory { destination } =
                &row.record.intent.operation
            && target.permits_additive_beside_directory(
                &destination.parent.local_components,
                &destination.parent.remote.resource_id,
                &destination.name,
                destination.local_file,
                &scope.root_resource_id,
            )
            && (closed_submitted
                || row
                    .remote_verified_child_id
                    .as_deref()
                    .is_some_and(|child_id| {
                        target.definitely_disjoint_from_verified_directory(
                            &destination.parent.local_components,
                            &destination.parent.remote.resource_id,
                            &destination.name,
                            child_id,
                            &scope.root_resource_id,
                        )
                    }))
        {
            independent += 1;
        }
        if !row.record.progress.recorded_complete
            && let Some(classifications) = classifications.as_deref_mut()
        {
            let classification =
                PendingDirectoryCreateClassification::from_progress(row.record.progress);
            let count = classifications.entry(classification).or_insert(0usize);
            *count = count.checked_add(1).ok_or(StoreError::ScanLimit)?;
        }
    }
    directory.verify()?;
    Ok((ids.len(), unresolved, independent))
}

#[cfg(all(test, unix))]
pub(super) fn synthetic_history_store(base: Arc<SnapshotStore>) -> Arc<DirectoryIntentStore> {
    Arc::new(DirectoryIntentStore { base })
}

/// Existing-only metadata reader for namespace catalogs and authenticated
/// directory history. Its internal store is never exposed as a writer.
#[cfg(windows)]
pub struct NamespaceHistoryReader {
    state: Arc<raiun_control_windows::PrivateDirectory>,
    root: Option<Arc<dyn Directory>>,
    protector: Arc<dyn EditRecordProtector>,
    policy: StorePolicy,
}

#[cfg(all(
    windows,
    test,
    debug_assertions,
    feature = "synthetic-agent-integration"
))]
#[path = "namespace_store_inspector.rs"]
mod retained_fixture_inspector;

#[cfg(windows)]
impl NamespaceHistoryReader {
    /// Open a previously admitted private state directory and its existing v2
    /// store. This constructor does not consult environment or create entries.
    pub fn open_existing(
        state: Arc<raiun_control_windows::PrivateDirectory>,
        protector: Arc<dyn EditRecordProtector>,
        policy: StorePolicy,
    ) -> Result<Self, StoreError> {
        policy.validate()?;
        state.verify_path().map_err(io_error)?;
        let root = crate::streamed_store::windows::existing_root(
            crate::recovery_state::RecoveryStateRoot::modern(Arc::clone(&state)),
            crate::streamed_store::V2_STORE_ROOT,
        )?;
        Ok(Self {
            state,
            root,
            protector,
            policy,
        })
    }

    fn current_root(&self) -> Result<Option<Arc<dyn Directory>>, StoreError> {
        self.state.verify_path().map_err(io_error)?;
        let current = crate::streamed_store::windows::existing_root(
            crate::recovery_state::RecoveryStateRoot::modern(Arc::clone(&self.state)),
            crate::streamed_store::V2_STORE_ROOT,
        )?;
        match (&self.root, current) {
            (Some(pinned), Some(_)) => {
                pinned.verify()?;
                Ok(Some(Arc::clone(pinned)))
            }
            (Some(pinned), None) => {
                pinned.verify()?;
                Err(StoreError::IncompleteEvidence)
            }
            (None, current) => Ok(current),
        }
    }

    /// Authenticate namespace-v1 scope catalogs and their directory pairs.
    /// The scan is bounded and uses only an existing quota lock, if present.
    pub fn discover_scopes(&self) -> Result<Vec<EditJournalScope>, StoreError> {
        let Some(root) = self.current_root()? else {
            return Ok(Vec::new());
        };
        let mut policy = self.policy;
        policy.max_entries = policy.max_entries.min(20_000);
        policy.max_metadata_bytes_per_scan =
            policy.max_metadata_bytes_per_scan.min(64 * 1024 * 1024);
        policy.validate()?;
        let mut budget = Budget::new(policy);
        root.verify()?;
        let names = root.entries(budget.remaining_entries())?;
        budget.entries(names.len())?;
        let lock = if names.iter().any(|name| name == V2_QUOTA_LOCK) {
            let mut lock = root.open_quota_lock()?;
            if lock.len()? != 0 {
                return Err(StoreError::CorruptEvidence);
            }
            // Read-only discovery never waits, creates a lock or rewrites it.
            lock.lock_exclusive()?;
            lock.verify()?;
            Some(lock)
        } else {
            None
        };
        let names = if lock.is_some() {
            let names = root.entries(budget.remaining_entries())?;
            budget.entries(names.len())?;
            names
        } else {
            names
        };
        if names.iter().collect::<std::collections::HashSet<_>>().len() != names.len() {
            return Err(StoreError::CorruptEvidence);
        }
        // Validate every upper v2 catalog before treating an absent namespace
        // root as empty. This reuses the caller's budget and requires no scope.
        let mut scopes =
            validate_root_catalog_scope_union(&*root, &*self.protector, &names, &mut budget)?.keys;
        let Some(_) = names.iter().find(|name| name.as_str() == ROOT) else {
            root.verify()?;
            if let Some(lock) = &lock {
                lock.verify()?;
            }
            return Ok(Vec::new());
        };
        let namespace_root = root.child(ROOT, false)?;
        let names = namespace_root.entries(budget.remaining_entries())?;
        budget.entries(names.len())?;
        if lock.is_none() && !names.is_empty() {
            return Err(StoreError::IncompleteEvidence);
        }
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for name in &names {
            if !seen.insert(name) {
                return Err(StoreError::CorruptEvidence);
            }
            if let Some(key) = name.strip_suffix(".scope") {
                if !valid_key(key) || !names.contains(&key.to_owned()) {
                    return Err(StoreError::IncompleteEvidence);
                }
                scopes.insert(key.to_owned());
                if scopes.len() > 256 {
                    return Err(StoreError::ScanLimit);
                }
                let scope = authenticate_namespace_scope(
                    &*namespace_root,
                    &*self.protector,
                    key,
                    &mut budget,
                )?;
                namespace_root.child(key, false)?.verify()?;
                result.push(scope);
            } else if !valid_key(name) || !names.contains(&format!("{name}.scope")) {
                return Err(StoreError::IncompleteEvidence);
            }
        }
        namespace_root.verify()?;
        root.verify()?;
        if let Some(lock) = lock {
            lock.verify()?;
        }
        Ok(result)
    }

    /// Read one authenticated account-root group. The supplied scope must
    /// exactly match a namespace catalog authenticated during this same
    /// bounded scan; it is never used to create a store or choose new authority.
    pub fn discover_account_root(
        &self,
        scope: &EditJournalScope,
    ) -> Result<Vec<StoredDirectoryIntent>, StoreError> {
        let root = self.current_root()?.ok_or(StoreError::IncompleteEvidence)?;
        let mut policy = self.policy;
        policy.max_entries = policy.max_entries.min(20_000);
        policy.max_metadata_bytes_per_scan =
            policy.max_metadata_bytes_per_scan.min(64 * 1024 * 1024);
        policy.validate()?;
        let base = SnapshotStore::from_directory(
            root,
            scope.clone(),
            Arc::clone(&self.protector),
            policy,
        )?;
        let admission = crate::recovery_admission::RecoveryAdmission::new(
            Arc::clone(&self.state),
            Arc::clone(&self.protector),
            policy,
        )?;
        let store = DirectoryIntentStore { base, admission };
        store.discover_account_root_bounded_for(&mut Budget::new(policy), Some(scope))
    }
}

pub struct DirectoryIntentLease {
    store: Arc<DirectoryIntentStore>,
    directory: Arc<dyn Directory>,
    _lock: Box<dyn PinnedRead>,
    loaded: Loaded,
    submitted_here: bool,
    poisoned: bool,
    #[cfg(all(test, windows))]
    last_append_reserve_attempts: usize,
}

#[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
fn admission_diagnostic(stage: &'static str, error: &StoreError) {
    static COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    use std::sync::atomic::Ordering;

    let mut count = COUNT.load(Ordering::Relaxed);
    loop {
        if count >= 128 {
            return;
        }
        match COUNT.compare_exchange_weak(count, count + 1, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(current) => count = current,
        }
    }
    let error_class = match error {
        StoreError::Io => "io",
        StoreError::Busy => "busy",
        StoreError::Invalid => "invalid",
        StoreError::Quota => "quota",
        StoreError::ScanLimit => "scan_limit",
        StoreError::IncompleteEvidence => "incomplete_evidence",
        StoreError::CorruptEvidence => "corrupt_evidence",
        StoreError::PublicationUncertain => "publication_uncertain",
        StoreError::Snapshot(_) => "snapshot",
    };
    use std::io::Write;
    let _ = writeln!(
        std::io::stderr().lock(),
        "namespace_store stage={stage} error={error_class}"
    );
}

#[cfg(not(all(debug_assertions, feature = "synthetic-agent-integration")))]
fn admission_diagnostic(_stage: &'static str, _error: &StoreError) {}

fn observe_history_result<T>(
    stage: &'static str,
    result: Result<T, StoreError>,
) -> Result<T, StoreError> {
    if let Err(error) = &result {
        admission_diagnostic(stage, error);
    }
    result
}

fn observe_history_error(stage: &'static str, error: StoreError) -> StoreError {
    admission_diagnostic(stage, &error);
    error
}

#[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
fn namespace_event_diagnostic(stage: &'static str, kind: &NamespaceEventKind, error: &StoreError) {
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    use std::sync::atomic::Ordering;

    let mut count = COUNT.load(Ordering::Relaxed);
    loop {
        if count >= 128 {
            return;
        }
        match COUNT.compare_exchange_weak(count, count + 1, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(current) => count = current,
        }
    }
    let event_kind = match kind {
        NamespaceEventKind::RemoteSubmitted => "remote_submitted",
        NamespaceEventKind::RemoteVerified { .. } => "remote_verified",
        NamespaceEventKind::RemoteDeleted { .. } => "remote_deleted",
        NamespaceEventKind::LocalCompleted { .. } => "local_completed",
        NamespaceEventKind::LocalDeleted { .. } => "local_deleted",
        NamespaceEventKind::SourceRemovalSubmitted { .. } => "source_removal_submitted",
        NamespaceEventKind::SourceRemovalVerified { .. } => "source_removal_verified",
        NamespaceEventKind::Conflict => "conflict",
        NamespaceEventKind::Deferred => "deferred",
        NamespaceEventKind::Uncertain => "uncertain",
    };
    let error_class = match error {
        StoreError::Io => "io",
        StoreError::Busy => "busy",
        StoreError::Invalid => "invalid",
        StoreError::Quota => "quota",
        StoreError::ScanLimit => "scan_limit",
        StoreError::IncompleteEvidence => "incomplete_evidence",
        StoreError::CorruptEvidence => "corrupt_evidence",
        StoreError::PublicationUncertain => "publication_uncertain",
        StoreError::Snapshot(_) => "snapshot",
    };
    use std::io::Write;
    let _ = writeln!(
        std::io::stderr().lock(),
        "namespace_store stage={stage} event={event_kind} error={error_class}"
    );
}

macro_rules! observe_namespace_event {
    ($stage:literal, $kind:expr, $result:expr) => {{
        let result = $result;
        #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
        if let Err(error) = &result {
            namespace_event_diagnostic($stage, $kind, error);
        }
        result
    }};
}

impl DirectoryIntentLease {
    pub fn intent(&self) -> &NamespaceIntent {
        &self.loaded.record.intent
    }
    pub fn progress(&self) -> NamespaceProgressSnapshot {
        let record = self.loaded.record.clone();
        if self.submitted_here {
            record.progress
        } else {
            recovered(record).progress
        }
    }
    pub fn append_event(
        &mut self,
        kind: NamespaceEventKind,
    ) -> Result<StoredDirectoryIntent, StoreError> {
        if self.poisoned {
            #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
            namespace_event_diagnostic(
                "initial_poisoned",
                &kind,
                &StoreError::PublicationUncertain,
            );
            return Err(StoreError::PublicationUncertain);
        }
        let prior = self.progress();
        observe_namespace_event!("transition", &kind, validate_transition(prior, &kind))?;
        let context = observe_namespace_event!(
            "context",
            &kind,
            self.intent()
                .event_context()
                .map_err(|_| StoreError::Invalid)
        )?;
        let event = NamespaceEvent {
            context,
            sequence: prior.sequence + 1,
            event: kind,
        };
        // Validate before writing, but do not advance in-memory state until
        // immutable publication and authenticated reopen both succeed.
        let mut checked = observe_namespace_event!(
            "pre_append_load",
            &event.event,
            self.store.load(
                &*self.directory,
                &self.loaded.record.key.id,
                &mut Budget::new(self.store.base.policy),
            )
        )?;
        if checked.record.key != self.loaded.record.key
            || checked.record.commitment != self.loaded.record.commitment
        {
            #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
            namespace_event_diagnostic("binding_check", &event.event, &StoreError::CorruptEvidence);
            return Err(StoreError::CorruptEvidence);
        }
        observe_namespace_event!(
            "check_event",
            &event.event,
            checked
                .progress
                .record(&event)
                .map_err(|_| StoreError::Invalid)
        )?;
        let plain = Zeroizing::new(observe_namespace_event!(
            "serialize_event",
            &event.event,
            serde_json::to_vec(&event).map_err(|_| StoreError::Invalid)
        )?);
        let bytes = observe_namespace_event!(
            "seal_event",
            &event.event,
            self.store.seal(
                &checked.record.key,
                event.sequence,
                &checked.record.commitment,
                &plain,
            )
        )?;
        let mut reserve_attempts = 0;
        let _quota = loop {
            reserve_attempts += 1;
            #[cfg(all(test, windows))]
            {
                self.last_append_reserve_attempts = reserve_attempts;
            }
            match observe_namespace_event!(
                "reserve_publication",
                &event.event,
                self.store.reserve(bytes.len() as u64, 2)
            ) {
                Ok(quota) => break quota,
                Err(StoreError::Busy) if reserve_attempts < APPEND_RESERVE_ATTEMPTS => {
                    std::thread::sleep(APPEND_RESERVE_DELAY);
                }
                Err(error) => return Err(error),
            }
        };
        self.poisoned = true;
        observe_namespace_event!(
            "persist_event",
            &event.event,
            persist_metadata(
                &*self.directory,
                &format!("{}.event.{:020}", checked.record.key.id, event.sequence),
                &bytes,
            )
        )?;
        self.loaded = observe_namespace_event!(
            "reopen_published_event",
            &event.event,
            self.store.load(
                &*self.directory,
                &checked.record.key.id,
                &mut Budget::new(self.store.base.policy),
            )
        )?;
        self.submitted_here |= matches!(event.event, NamespaceEventKind::RemoteSubmitted);
        self.poisoned = false;
        Ok(self.loaded.record.clone())
    }
}
fn account_root_matches(scope: &EditJournalScope, binding: &EditJournalScope) -> bool {
    scope.profile_id == binding.profile_id
        && scope.server_origin == binding.server_origin
        && scope.account_subject == binding.account_subject
        && scope.root_volume_serial == binding.root_volume_serial
        && scope.root_file_index == binding.root_file_index
}
fn check_scoped_intent(
    intent: &NamespaceIntent,
    scope: &EditJournalScope,
) -> Result<(), StoreError> {
    intent.validate().map_err(|_| StoreError::Invalid)?;
    match &intent.operation {
        NamespaceOperation::CreateDirectory { destination }
            if &destination.parent.scope == scope =>
        {
            Ok(())
        }
        _ => Err(StoreError::Invalid),
    }
}
fn record_aad(
    scope: &EditJournalScope,
    key: &DirectoryIntentKey,
    seq: u64,
    previous: &[u8; 32],
) -> Result<Vec<u8>, StoreError> {
    let mut aad = DOMAIN.to_vec();
    aad.extend(
        serde_json::to_vec(&(scope, &key.id, key.generation, &key.digest, seq, previous))
            .map_err(|_| StoreError::Invalid)?,
    );
    Ok(aad)
}
fn authenticate_namespace_scope(
    root: &dyn Directory,
    protector: &dyn EditRecordProtector,
    key: &str,
    budget: &mut Budget,
) -> Result<EditJournalScope, StoreError> {
    let bytes = read_metadata(root, &format!("{key}.scope"), budget)?;
    let plain = Zeroizing::new(
        protector
            .open(&catalog_aad(key), &bytes)
            .map_err(|_| StoreError::CorruptEvidence)?,
    );
    if plain.len() > META_LIMIT / 2 {
        return Err(StoreError::CorruptEvidence);
    }
    let scope: EditJournalScope =
        serde_json::from_slice(&plain).map_err(|_| StoreError::CorruptEvidence)?;
    validate_scope(&scope).map_err(|_| StoreError::CorruptEvidence)?;
    if scope_key(&scope)? != key {
        return Err(StoreError::CorruptEvidence);
    }
    Ok(scope)
}

/// Catalog-only validation for a neighboring typed store's shared scope
/// budget. This never returns mkdir intents or grants a dispatch lease.
// Retain the key-only compatibility seam; Windows health now keeps full
// authenticated scopes, so invoking this wrapper there would duplicate a scan.
#[cfg_attr(windows, allow(dead_code))]
pub(super) fn validated_catalog_scope_keys(
    root: &dyn Directory,
    protector: &dyn EditRecordProtector,
    budget: &mut Budget,
) -> Result<Vec<String>, StoreError> {
    validated_catalog_scopes(root, protector, budget)?
        .iter()
        .map(scope_key)
        .collect()
}

/// Authenticate actual typed scopes once, retaining their immutable bindings
/// for the caller's same-lock existing-only metadata scan.
pub(super) fn validated_catalog_scopes(
    root: &dyn Directory,
    protector: &dyn EditRecordProtector,
    budget: &mut Budget,
) -> Result<Vec<EditJournalScope>, StoreError> {
    root.verify()?;
    let names = root.entries(budget.remaining_entries())?;
    budget.entries(names.len())?;
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for name in &names {
        if !seen.insert(name) {
            return Err(StoreError::CorruptEvidence);
        }
        if let Some(key) = name.strip_suffix(".scope") {
            if !valid_key(key) || !names.contains(&key.to_owned()) {
                return Err(StoreError::IncompleteEvidence);
            }
            let scope = authenticate_namespace_scope(root, protector, key, budget)?;
            root.child(key, false)?.verify()?;
            result.push(scope);
            if result.len() > 256 {
                return Err(StoreError::ScanLimit);
            }
        } else if !valid_key(name) || !names.contains(&format!("{name}.scope")) {
            return Err(StoreError::IncompleteEvidence);
        }
    }
    root.verify()?;
    Ok(result)
}
fn validate_transition(
    prior: NamespaceProgressSnapshot,
    kind: &NamespaceEventKind,
) -> Result<(), StoreError> {
    check_event(kind)?;
    if prior.attention.is_some() || prior.recorded_complete || prior.sequence >= 128 {
        return Err(StoreError::Invalid);
    }
    if matches!(kind, NamespaceEventKind::RemoteSubmitted)
        && (prior.sequence != 0 || prior.remote != NamespacePhase::Pending)
    {
        return Err(StoreError::Invalid);
    }
    if matches!(kind, NamespaceEventKind::LocalCompleted { .. })
        && prior.remote != NamespacePhase::Verified
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn check_event(kind: &NamespaceEventKind) -> Result<(), StoreError> {
    match kind {
        NamespaceEventKind::RemoteSubmitted
        | NamespaceEventKind::RemoteVerified { .. }
        | NamespaceEventKind::LocalCompleted { .. }
        | NamespaceEventKind::Conflict
        | NamespaceEventKind::Deferred
        | NamespaceEventKind::Uncertain => Ok(()),
        _ => Err(StoreError::Invalid),
    }
}
fn recovered(mut record: StoredDirectoryIntent) -> StoredDirectoryIntent {
    if record.progress.remote == NamespacePhase::Submitted && record.progress.attention.is_none() {
        record.progress.attention = Some(NamespaceAttention::Uncertain);
    }
    record
}
fn same_entry(a: &NamespaceIntent, b: &NamespaceIntent) -> bool {
    match (&a.operation, &b.operation) {
        (
            NamespaceOperation::CreateDirectory { destination: a },
            NamespaceOperation::CreateDirectory { destination: b },
        ) => {
            a.parent.scope == b.parent.scope
                && a.parent.local_file == b.parent.local_file
                && a.name == b.name
                && a.local_file == b.local_file
        }
        _ => false,
    }
}
fn catalog_aad(key: &str) -> Vec<u8> {
    [DOMAIN, b"scope\0", key.as_bytes()].concat()
}
fn commitment(previous: &[u8; 32], plain: &[u8]) -> [u8; 32] {
    commitment_fn(previous, plain)
}
fn commitment_fn(previous: &[u8; 32], plain: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(previous);
    hash.update(plain);
    hash.finalize().into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
fn parse_event(suffix: &str) -> Option<u64> {
    let digits = suffix.strip_prefix("event.")?;
    if digits.len() != 20 || !digits.bytes().all(|v| v.is_ascii_digit()) {
        return None;
    }
    let seq = digits.parse().ok()?;
    (seq > 0 && seq <= 128).then_some(seq)
}

/// Conservative physical metadata accounting only: no decrypted report is
/// inferred from lengths. Unknown files count; unsafe/unknown directories fail.
pub(super) fn accounted_usage(
    root: &dyn Directory,
    budget: &mut Budget,
) -> Result<Inventory, StoreError> {
    root.verify()?;
    let names = root.entries(budget.remaining_entries())?;
    budget.entries(names.len())?;
    let mut result = Inventory {
        bytes: 0,
        entries: names.len(),
    };
    for name in names {
        if valid_key(&name) {
            let directory = root.child(&name, false)?;
            let children = directory.entries(budget.remaining_entries())?;
            budget.entries(children.len())?;
            result.entries = result
                .entries
                .checked_add(children.len())
                .ok_or(StoreError::ScanLimit)?;
            for length in metadata_sizes_checked(&*directory, &children)? {
                result.add(length)?;
            }
            directory.verify()?;
        } else {
            result.add(root.open(&name)?.len()?)?;
        }
    }
    root.verify()?;
    Ok(result)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::namespace_intent::{
        CapturedAuthorization, LocalNamespaceEntry, NamespaceObjectKind, NamespaceParent,
        StorageClassification,
    };
    use crate::{LocalFileIdentity, RemoteEditBaseline};
    fn policy() -> StorePolicy {
        StorePolicy {
            max_content_bytes: 32 * 1024 * 1024,
            max_state_bytes: 64 * 1024 * 1024,
            max_entries: 2000,
            max_metadata_bytes_per_scan: 8 * 1024 * 1024,
        }
    }
    fn fixture() -> (tempfile::TempDir, Arc<DirectoryIntentStore>) {
        let (temp, base) = synthetic_test_store(policy());
        (temp, Arc::new(DirectoryIntentStore { base }))
    }
    fn intent(store: &DirectoryIntentStore) -> NamespaceIntent {
        let scope = store.base.scope.clone();
        NamespaceIntent {
            schema_version: 1,
            record_id: "a".repeat(32),
            record_generation: 9,
            operation: NamespaceOperation::CreateDirectory {
                destination: LocalNamespaceEntry {
                    parent: NamespaceParent {
                        scope: scope.clone(),
                        authorization: CapturedAuthorization {
                            agent_generation: 3,
                            token_generation: 2,
                        },
                        classification: StorageClassification::Ordinary,
                        local_file: LocalFileIdentity {
                            volume_serial: scope.root_volume_serial,
                            file_index: 3,
                        },
                        local_components: vec!["parent".into()],
                        remote: RemoteEditBaseline {
                            resource_id: "parent".into(),
                            etag: "\"etag\"".into(),
                            byte_len: 0,
                        },
                    },
                    name: "new".into(),
                    local_file: LocalFileIdentity {
                        volume_serial: scope.root_volume_serial,
                        file_index: 4,
                    },
                    object_kind: NamespaceObjectKind::Directory,
                },
            },
        }
    }
    #[test]
    fn durable_submission_restart_is_uncertain_and_duplicate_joins_generation() {
        let (_temp, store) = fixture();
        let input = intent(&store);
        let published = store.publish_intent(input.clone()).unwrap();
        assert!(published.created);
        assert_ne!(published.record.intent.record_id, input.record_id);
        let mut lease = store.acquire_dispatch(&published.record.key).unwrap();
        lease
            .append_event(NamespaceEventKind::RemoteSubmitted)
            .unwrap();
        assert_eq!(lease.progress().attention, None);
        assert!(matches!(
            store.acquire_dispatch(&published.record.key),
            Err(StoreError::Busy)
        ));
        drop(lease);
        let mut lease = store.acquire_dispatch(&published.record.key).unwrap();
        assert_eq!(
            lease.progress().attention,
            Some(NamespaceAttention::Uncertain)
        );
        assert_eq!(
            lease
                .append_event(NamespaceEventKind::RemoteSubmitted)
                .err(),
            Some(StoreError::Invalid)
        );
        let mut changed = input;
        changed.record_generation += 100;
        let duplicate = store.publish_intent(changed).unwrap();
        assert!(!duplicate.created);
        assert_eq!(duplicate.record.intent.record_generation, 9);
        assert_eq!(
            store.discover().unwrap()[0].progress.attention,
            Some(NamespaceAttention::Uncertain)
        );
    }
    #[test]
    fn quota_counts_namespace_and_serializes_all_writers() {
        let (_temp, store) = fixture();
        let record = store.publish_intent(intent(&store)).unwrap().record;
        let before = store.base.accounted_usage_while_locked().unwrap();
        assert!(before.0 > 0);
        assert!(before.1 >= 5);
        let lock = store.base.acquire_lock().unwrap();
        assert!(matches!(
            store.acquire_dispatch(&record.key),
            Err(StoreError::Busy)
        ));
        assert!(matches!(
            store.publish_intent(intent(&store)),
            Err(StoreError::Busy)
        ));
        drop(lock);
        let mut limited = policy();
        limited.max_state_bytes = before.0;
        let base = SnapshotStore::from_directory(
            Arc::clone(&store.base.root),
            store.base.scope.clone(),
            Arc::clone(&store.base.protector),
            limited,
        )
        .unwrap();
        let limited = Arc::new(DirectoryIntentStore { base });
        assert!(matches!(
            limited.publish_intent(intent(&limited)),
            Err(StoreError::Quota)
        ));
        assert_eq!(store.base.discover_metadata().unwrap().len(), 0);
    }
    #[test]
    fn tampered_header_and_torn_event_preserved_and_not_adopted() {
        let (_temp, store) = fixture();
        let record = store.publish_intent(intent(&store)).unwrap().record;
        let directory = store.directory(false).unwrap();
        let name = format!("{}.event.{:020}.stage", record.key.id, 1);
        let (mut file, _) = directory.create(&name).unwrap();
        file.write_all(b"partial").unwrap();
        file.sync().unwrap();
        drop(file);
        assert!(matches!(
            store.discover(),
            Err(StoreError::IncompleteEvidence)
        ));
        assert_eq!(directory.open(&name).unwrap().len().unwrap(), 7);
        assert!(store.base.accounted_usage_while_locked().unwrap().0 > 7);
        assert!(store.publish_intent(intent(&store)).is_err());
        let (_temp2, other) = fixture();
        let second = other.publish_intent(intent(&other)).unwrap().record;
        let mut foreign = second.key.clone();
        foreign.generation += 1;
        assert!(matches!(
            other.acquire_dispatch(&foreign),
            Err(StoreError::CorruptEvidence)
        ));
    }
    #[test]
    fn swaps_and_event_chain_gaps_are_rejected() {
        let (_temp, store) = fixture();
        let first = store.publish_intent(intent(&store)).unwrap().record;
        let mut next = intent(&store);
        if let NamespaceOperation::CreateDirectory { destination } = &mut next.operation {
            destination.name = "second".into();
            destination.local_file.file_index += 1;
        }
        let second = store.publish_intent(next).unwrap().record;
        let directory = store.directory(false).unwrap();
        let mut lease = store.acquire_dispatch(&first.key).unwrap();
        lease
            .append_event(NamespaceEventKind::RemoteSubmitted)
            .unwrap();
        drop(lease);
        let bytes = read_metadata(
            &*directory,
            &format!("{}.event.{:020}", first.key.id, 1),
            &mut Budget::new(policy()),
        )
        .unwrap();
        persist_metadata(
            &*directory,
            &format!("{}.event.{:020}", second.key.id, 1),
            &bytes,
        )
        .unwrap();
        assert!(matches!(
            store.acquire_dispatch(&second.key),
            Err(StoreError::CorruptEvidence)
        ));
        let (_temp, store) = fixture();
        let record = store.publish_intent(intent(&store)).unwrap().record;
        persist_metadata(
            &*store.directory(false).unwrap(),
            &format!("{}.event.{:020}", record.key.id, 2),
            b"broken",
        )
        .unwrap();
        assert!(matches!(
            store.discover(),
            Err(StoreError::IncompleteEvidence)
        ));
    }
    #[test]
    fn physical_header_scope_swap_and_incomplete_catalog_are_not_repaired() {
        let (temp, store) = fixture();
        let record = store.publish_intent(intent(&store)).unwrap().record;
        let path = temp
            .path()
            .join(ROOT)
            .join(&store.base.key)
            .join(format!("{}.intent", record.key.id));
        let original = std::fs::read(&path).unwrap();
        let mut header: Envelope = serde_json::from_slice(&original).unwrap();
        header.generation += 1;
        std::fs::write(&path, serde_json::to_vec(&header).unwrap()).unwrap();
        assert!(matches!(store.discover(), Err(StoreError::CorruptEvidence)));
        std::fs::write(&path, &original).unwrap();
        let mut scope = store.base.scope.clone();
        scope.space_id = "other".into();
        let base = SnapshotStore::from_directory(
            Arc::clone(&store.base.root),
            scope,
            Arc::clone(&store.base.protector),
            policy(),
        )
        .unwrap();
        let other = Arc::new(DirectoryIntentStore { base });
        let quota = other.reserve(META_LIMIT as u64, 4).unwrap();
        let dir = other.directory(true).unwrap();
        drop(quota);
        persist_metadata(&*dir, &format!("{}.intent", record.key.id), &original).unwrap();
        assert!(matches!(other.discover(), Err(StoreError::CorruptEvidence)));
        let (temp, store) = fixture();
        store.publish_intent(intent(&store)).unwrap();
        let scope_dir = temp.path().join(ROOT).join(&store.base.key);
        // The synthetic backend permits external tampering; production pins do
        // not grant this operation. No store operation repairs the missing pair.
        for item in std::fs::read_dir(&scope_dir).unwrap() {
            std::fs::remove_file(item.unwrap().path()).unwrap();
        }
        std::fs::remove_dir(&scope_dir).unwrap();
        assert!(matches!(
            store.publish_intent(intent(&store)),
            Err(StoreError::IncompleteEvidence)
        ));
        assert!(!scope_dir.exists());
    }
    #[test]
    fn namespace_usage_reduces_snapshot_admission_under_same_quota() {
        fn binding(store: &SnapshotStore) -> SnapshotBinding {
            SnapshotBinding {
                record_id: String::new(),
                scope: store.scope.clone(),
                generation: 1,
                local_file: LocalFileIdentity {
                    volume_serial: store.scope.root_volume_serial,
                    file_index: 5,
                },
                relative_path: "empty".into(),
                remote: None,
                content_len: 0,
            }
        }
        let (_temp, store) = fixture();
        store.publish_intent(intent(&store)).unwrap();
        let mut narrow = policy();
        narrow.max_state_bytes = reservation_bound(0).unwrap() * 2 + (META_LIMIT * 2) as u64;
        let base = SnapshotStore::from_directory(
            Arc::clone(&store.base.root),
            store.base.scope.clone(),
            Arc::clone(&store.base.protector),
            narrow,
        )
        .unwrap();
        assert!(matches!(
            base.try_begin_capture(binding(&base)),
            Err(StoreError::Quota)
        ));
        let (_temp, empty) = synthetic_test_store(narrow);
        assert!(empty.try_begin_capture(binding(&empty)).is_ok());
    }
    fn in_scope(
        store: &Arc<DirectoryIntentStore>,
        scope: EditJournalScope,
    ) -> Arc<DirectoryIntentStore> {
        let base = SnapshotStore::from_directory(
            Arc::clone(&store.base.root),
            scope,
            Arc::clone(&store.base.protector),
            store.base.policy,
        )
        .unwrap();
        Arc::new(DirectoryIntentStore { base })
    }
    #[test]
    fn account_root_discovery_retains_cross_space_physical_identity_and_filters_authenticated_foreign_scopes()
     {
        let (temp, store) = fixture();
        let first = store.publish_intent(intent(&store)).unwrap().record;
        let mut lease = store.acquire_dispatch(&first.key).unwrap();
        lease
            .append_event(NamespaceEventKind::RemoteSubmitted)
            .unwrap();
        drop(lease);
        let mut scope = store.base.scope.clone();
        scope.space_id = "projects".into();
        scope.root_resource_id = "project-root".into();
        let space = in_scope(&store, scope);
        space.publish_intent(intent(&space)).unwrap();
        for variant in 0..5 {
            let mut scope = store.base.scope.clone();
            match variant {
                0 => scope.profile_id.push('x'),
                1 => scope.account_subject.push('x'),
                2 => scope.server_origin = "https://foreign.invalid".into(),
                3 => scope.root_volume_serial += 1,
                _ => scope.root_file_index += 100,
            }
            let other = in_scope(&store, scope);
            let record = other.publish_intent(intent(&other)).unwrap().record;
            // Authenticated unrelated scope is enough to exclude its records;
            // record payload is deliberately corrupt and MUST NOT be read.
            std::fs::write(
                temp.path()
                    .join(ROOT)
                    .join(&other.base.key)
                    .join(format!("{}.intent", record.key.id)),
                b"foreign-unread",
            )
            .unwrap();
        }
        let records = space.discover_account_root().unwrap();
        assert_eq!(records.len(), 2);
        let mut ids = Vec::new();
        let mut spaces = std::collections::HashSet::new();
        for record in records {
            if let NamespaceOperation::CreateDirectory { destination } = record.intent.operation {
                ids.push(destination.local_file);
                spaces.insert(destination.parent.scope.space_id);
            }
        }
        assert_eq!(ids[0], ids[1]);
        assert_eq!(spaces.len(), 2);
        assert_eq!(
            store
                .discover_account_root()
                .unwrap()
                .iter()
                .find(|r| r.key == first.key)
                .unwrap()
                .progress
                .attention,
            Some(NamespaceAttention::Uncertain)
        );
    }
    #[test]
    fn global_metadata_budget_is_shared_and_relevant_corruption_and_lock_contention_fail_closed() {
        let (temp, store) = fixture();
        let first = store.publish_intent(intent(&store)).unwrap().record;
        let mut scope = store.base.scope.clone();
        scope.space_id = "other-space".into();
        scope.root_resource_id = "other-root".into();
        let other = in_scope(&store, scope);
        other.publish_intent(intent(&other)).unwrap();
        let bytes = std::fs::read_dir(temp.path().join(ROOT))
            .unwrap()
            .map(|e| e.unwrap().path())
            .map(|p| {
                if p.is_file() {
                    p.metadata().unwrap().len()
                } else {
                    std::fs::read_dir(p)
                        .unwrap()
                        .map(|e| e.unwrap().metadata().unwrap().len())
                        .sum()
                }
            })
            .sum::<u64>();
        let mut budget = Budget::new(policy());
        budget.bytes = bytes - 1;
        assert!(matches!(
            store.discover_account_root_bounded(&mut budget),
            Err(StoreError::ScanLimit)
        ));
        let lock = store.base.acquire_lock().unwrap();
        assert!(matches!(
            store.discover_account_root(),
            Err(StoreError::Busy)
        ));
        drop(lock);
        let path = temp
            .path()
            .join(ROOT)
            .join(&store.base.key)
            .join(format!("{}.intent", first.key.id));
        std::fs::write(path, b"corrupt-relevant").unwrap();
        assert!(matches!(
            other.discover_account_root(),
            Err(StoreError::CorruptEvidence)
        ));
    }
    #[test]
    fn first_use_and_empty_namespace_do_not_create_quota_but_retained_catalog_without_lock_is_attention()
     {
        let (temp, store) = fixture();
        assert!(store.discover_account_root().unwrap().is_empty());
        assert!(!temp.path().join(V2_QUOTA_LOCK).exists());
        // Valid snapshot bootstrap scope markers are not namespace evidence.
        store.base.ensure_scope().unwrap();
        assert!(store.discover_account_root().unwrap().is_empty());
        let root = store.base.root.child(ROOT, true).unwrap();
        assert!(store.discover_account_root().unwrap().is_empty());
        assert!(!temp.path().join(V2_QUOTA_LOCK).exists());
        let sealed = store
            .base
            .seal_metadata(&catalog_aad(&store.base.key), &store.base.scope)
            .unwrap();
        persist_metadata(&*root, &format!("{}.scope", store.base.key), &sealed).unwrap();
        root.child(&store.base.key, true).unwrap();
        assert!(matches!(
            store.discover_account_root(),
            Err(StoreError::IncompleteEvidence)
        ));
        assert!(!temp.path().join(V2_QUOTA_LOCK).exists());
    }
    #[test]
    fn global_scope_and_record_limits_are_aggregate() {
        let (_temp, store) = fixture();
        store.publish_intent(intent(&store)).unwrap();
        let root = store.base.root.child(ROOT, false).unwrap();
        for index in 0..256 {
            let mut scope = store.base.scope.clone();
            scope.space_id = format!("space-{index}");
            scope.root_resource_id = format!("root-{index}");
            let key = scope_key(&scope).unwrap();
            let sealed = store
                .base
                .seal_metadata(&catalog_aad(&key), &scope)
                .unwrap();
            persist_metadata(&*root, &format!("{key}.scope"), &sealed).unwrap();
            root.child(&key, true).unwrap();
        }
        assert!(matches!(
            store.discover_account_root(),
            Err(StoreError::ScanLimit)
        ));
        let (_temp, store) = fixture();
        for index in 0..257 {
            let mut scope = store.base.scope.clone();
            scope.space_id = format!("snapshot-{index}");
            scope.root_resource_id = format!("snapshot-root-{index}");
            let base = SnapshotStore::from_directory(
                Arc::clone(&store.base.root),
                scope,
                Arc::clone(&store.base.protector),
                store.base.policy,
            )
            .unwrap();
            // Seed retained over-bound catalogs directly: ordinary publication
            // now refuses the prospective 257th key before creating anything.
            let sealed = base
                .seal_metadata(&scope_aad(&base.key), &base.scope)
                .unwrap();
            persist_metadata(&*base.root, &format!("{}.scope", base.key), &sealed).unwrap();
            base.root.child(&base.key, true).unwrap();
        }
        assert!(matches!(
            store.discover_account_root(),
            Err(StoreError::ScanLimit)
        ));
        let (_temp, store) = fixture();
        store.publish_intent(intent(&store)).unwrap();
        let directory = store.directory(false).unwrap();
        for index in 0..2000u64 {
            let (mut file, _) = directory.create(&format!("{index:032x}.intent")).unwrap();
            file.write_all(b"not-authenticated").unwrap();
            file.sync().unwrap();
        }
        let mut larger = store.base.policy;
        larger.max_entries = 20_000;
        let base = SnapshotStore::from_directory(
            Arc::clone(&store.base.root),
            store.base.scope.clone(),
            Arc::clone(&store.base.protector),
            larger,
        )
        .unwrap();
        let scan = DirectoryIntentStore { base };
        assert!(matches!(
            scan.discover_account_root(),
            Err(StoreError::ScanLimit)
        ));
    }
    struct MetadataOnly(Arc<dyn Directory>);
    impl Directory for MetadataOnly {
        fn verify(&self) -> Result<(), StoreError> {
            self.0.verify()
        }
        fn entries(&self, limit: usize) -> Result<Vec<String>, StoreError> {
            self.0.entries(limit)
        }
        fn child(&self, name: &str, create: bool) -> Result<Arc<dyn Directory>, StoreError> {
            assert!(!create, "discovery cannot create directories");
            Ok(Arc::new(Self(self.0.child(name, false)?)))
        }
        fn create(&self, _: &str) -> Result<(Box<dyn StageWrite>, Identity), StoreError> {
            panic!("discovery cannot create files")
        }
        fn open(&self, name: &str) -> Result<Box<dyn PinnedRead>, StoreError> {
            assert!(
                !name.ends_with(".body") && !name.ends_with(".body.stage"),
                "discovery cannot open snapshot bodies"
            );
            self.0.open(name)
        }
        fn publish(&self, _: &str, _: &str, _: Identity) -> Result<(), StoreError> {
            panic!("discovery cannot publish files")
        }
    }
    #[test]
    fn account_root_discovery_opens_metadata_only_and_changes_no_quota_or_entries() {
        let (temp, store) = fixture();
        store.publish_intent(intent(&store)).unwrap();
        let binding = SnapshotBinding {
            record_id: String::new(),
            scope: store.base.scope.clone(),
            generation: 1,
            local_file: LocalFileIdentity {
                volume_serial: 1,
                file_index: 5,
            },
            relative_path: "body.bin".into(),
            remote: None,
            content_len: 3,
        };
        store
            .base
            .try_begin_capture(binding)
            .unwrap()
            .capture(&mut &b"abc"[..], &mut || false)
            .unwrap()
            .verify_and_commit(&mut || false)
            .unwrap();
        let before = store.base.accounted_usage_while_locked().unwrap();
        let lock_bytes = std::fs::read(temp.path().join(V2_QUOTA_LOCK)).unwrap();
        let root: Arc<dyn Directory> = Arc::new(MetadataOnly(Arc::clone(&store.base.root)));
        let base = SnapshotStore::from_directory(
            root,
            store.base.scope.clone(),
            Arc::clone(&store.base.protector),
            store.base.policy,
        )
        .unwrap();
        let scan = DirectoryIntentStore { base };
        assert_eq!(scan.discover_account_root().unwrap().len(), 1);
        assert_eq!(before, store.base.accounted_usage_while_locked().unwrap());
        assert_eq!(
            lock_bytes,
            std::fs::read(temp.path().join(V2_QUOTA_LOCK)).unwrap()
        );
    }
}

#[cfg(all(test, windows))]
mod native_first_use_tests {
    use super::*;
    use std::ffi::OsStr;
    struct SyntheticProtector;
    impl EditRecordProtector for SyntheticProtector {
        fn seal(&self, aad: &[u8], bytes: &[u8]) -> Result<Vec<u8>, crate::JournalError> {
            let mut hash = Sha256::new();
            hash.update(aad);
            hash.update(bytes);
            let mut result = hash.finalize().to_vec();
            result.extend_from_slice(bytes);
            Ok(result)
        }
        fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, crate::JournalError> {
            if sealed.len() < 32 {
                return Err(crate::JournalError::ProtectionFailed);
            }
            let mut hash = Sha256::new();
            hash.update(aad);
            hash.update(&sealed[32..]);
            if hash.finalize().as_slice() != &sealed[..32] {
                return Err(crate::JournalError::ProtectionFailed);
            }
            Ok(sealed[32..].to_vec())
        }
    }
    #[test]
    #[ignore = "explicit fresh-owned Windows private-directory constructor fixture; no DPAPI/default state/network/provider"]
    fn actual_constructor_first_use_discovery_creates_no_quota_lock() {
        assert_eq!(
            std::env::var("RAIUN_RUN_NAMESPACE_FIRST_USE").as_deref(),
            Ok("fresh-owned-state")
        );
        let directory = tempfile::Builder::new()
            .prefix("raiun-namespace-first-use-")
            .tempdir()
            .unwrap()
            .keep();
        let parent = raiun_control_windows::PinnedDirectory::open(&directory).unwrap();
        let state = Arc::new(
            raiun_control_windows::PrivateDirectory::create_or_open_under(
                &parent,
                OsStr::new("state"),
            )
            .unwrap(),
        );
        let root = state.path().join(V2_STORE_ROOT);
        let scope = EditJournalScope {
            profile_id: "synthetic".into(),
            server_origin: "https://synthetic.invalid".into(),
            account_subject: "synthetic".into(),
            space_id: "personal".into(),
            root_resource_id: "root".into(),
            root_volume_serial: 1,
            root_file_index: 2,
        };
        let policy = StorePolicy {
            max_content_bytes: 32 * 1024 * 1024,
            max_state_bytes: 64 * 1024 * 1024,
            max_entries: 2000,
            max_metadata_bytes_per_scan: 8 * 1024 * 1024,
        };
        let store = DirectoryIntentStore::create_or_open(
            state,
            scope,
            Arc::new(SyntheticProtector),
            policy,
        )
        .unwrap();
        assert!(store.discover_account_root().unwrap().is_empty());
        assert!(!root.join(V2_QUOTA_LOCK).exists());
        store.base.ensure_scope().unwrap();
        assert!(store.discover_account_root().unwrap().is_empty());
        assert!(!root.join(V2_QUOTA_LOCK).exists());
        store.base.root.child(ROOT, true).unwrap();
        assert!(store.discover_account_root().unwrap().is_empty());
        assert!(!root.join(V2_QUOTA_LOCK).exists());
    }

    #[test]
    #[ignore = "explicit fresh-owned Windows private-store quota contention fixture; no DPAPI/default state/network/provider"]
    fn append_event_quota_busy_is_bounded_and_lease_remains_usable() {
        use crate::namespace_intent::{
            CapturedAuthorization, LocalNamespaceEntry, NamespaceObjectKind, NamespaceParent,
            StorageClassification,
        };
        use crate::{LocalFileIdentity, RemoteEditBaseline};
        use std::{path::PathBuf, time::Instant};

        assert_eq!(
            std::env::var("RAIUN_RUN_NAMESPACE_APPEND_BUSY").as_deref(),
            Ok("fresh-owned-state")
        );
        let root = PathBuf::from(
            std::env::var_os("RAIUN_NAMESPACE_APPEND_BUSY_ROOT")
                .expect("explicit fresh evidence root"),
        );
        assert!(root.is_absolute());
        std::fs::create_dir(&root).expect("never reuse or overwrite a fixture root");
        let owner = root.join("OWNER.txt");
        std::fs::write(&owner, b"raiun-namespace-append-busy-v1\n").unwrap();

        let parent = raiun_control_windows::PinnedDirectory::open(&root).unwrap();
        let state = Arc::new(
            raiun_control_windows::PrivateDirectory::create_or_open_under(
                &parent,
                OsStr::new("state"),
            )
            .unwrap(),
        );
        let scope = EditJournalScope {
            profile_id: "synthetic-profile".into(),
            server_origin: "https://synthetic.invalid".into(),
            account_subject: "synthetic-account".into(),
            space_id: "synthetic-personal-space".into(),
            root_resource_id: "synthetic-root".into(),
            root_volume_serial: 1,
            root_file_index: 2,
        };
        let policy = StorePolicy {
            max_content_bytes: 32 * 1024 * 1024,
            max_state_bytes: 64 * 1024 * 1024,
            max_entries: 2000,
            max_metadata_bytes_per_scan: 8 * 1024 * 1024,
        };
        let store = DirectoryIntentStore::create_or_open(
            state,
            scope.clone(),
            Arc::new(SyntheticProtector),
            policy,
        )
        .unwrap();
        let intent = NamespaceIntent {
            schema_version: 1,
            record_id: "a".repeat(32),
            record_generation: 1,
            operation: NamespaceOperation::CreateDirectory {
                destination: LocalNamespaceEntry {
                    parent: NamespaceParent {
                        scope: scope.clone(),
                        authorization: CapturedAuthorization {
                            agent_generation: 1,
                            token_generation: 1,
                        },
                        classification: StorageClassification::Ordinary,
                        local_file: LocalFileIdentity {
                            volume_serial: 1,
                            file_index: 3,
                        },
                        local_components: vec!["Personal".into()],
                        remote: RemoteEditBaseline {
                            resource_id: "synthetic-parent".into(),
                            etag: "\"synthetic-etag\"".into(),
                            byte_len: 0,
                        },
                    },
                    name: "synthetic-directory".into(),
                    object_kind: NamespaceObjectKind::Directory,
                    local_file: LocalFileIdentity {
                        volume_serial: 1,
                        file_index: 4,
                    },
                },
            },
        };
        let published = store.publish_intent(intent).unwrap();
        assert!(published.created);
        let mut lease = store.acquire_dispatch(&published.record.key).unwrap();

        // Hold the real state-wide quota lock only after acquiring the record
        // lease, matching the production lock order.
        let mut entries_before = lease
            .directory
            .entries(store.base.policy.max_entries)
            .unwrap();
        entries_before.sort();
        let quota = store.reserve(0, 0).unwrap();
        let started = Instant::now();
        let first = lease.append_event(NamespaceEventKind::RemoteSubmitted);
        let first_elapsed_ms = started.elapsed().as_millis() as u64;
        let first_reserve_attempts = lease.last_append_reserve_attempts;
        let first_busy = matches!(&first, Err(StoreError::Busy));
        let first_progress = lease.progress();
        let mut entries_after_busy = lease
            .directory
            .entries(store.base.policy.max_entries)
            .unwrap();
        entries_after_busy.sort();
        let first_has_no_partial_event = entries_after_busy == entries_before;
        let first_unpoisoned = !lease.poisoned && !lease.submitted_here;
        drop(quota);

        let second = if first_busy {
            Some(lease.append_event(NamespaceEventKind::RemoteSubmitted))
        } else {
            None
        };
        let second_succeeded = second.as_ref().is_some_and(|result| result.is_ok());
        let second_sequence = second
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map_or(0, |record| record.progress.sequence);
        let entries_after_retry = lease
            .directory
            .entries(store.base.policy.max_entries)
            .unwrap();
        let event_artifacts_after_retry = entries_after_retry
            .iter()
            .filter(|name| name.contains(".event."))
            .count();
        drop(lease);

        let history = store.discover_account_root();
        let history_count = history.as_ref().map_or(0, |records| records.len());
        let authenticated_submitted_uncertain = history.as_ref().is_ok_and(|records| {
            records.len() == 1
                && records[0].intent == published.record.intent
                && records[0].progress.sequence == 1
                && records[0].progress.remote == NamespacePhase::Submitted
                && records[0].progress.attention == Some(NamespaceAttention::Uncertain)
                && !records[0].progress.local_completed
        });
        let roots_retained = root.is_dir() && owner.is_file();
        let no_partial_event = first_progress.sequence == 0
            && first_progress.remote == NamespacePhase::Pending
            && first_has_no_partial_event;
        let bounded_busy = first_busy
            && first_reserve_attempts == APPEND_RESERVE_ATTEMPTS
            && first_elapsed_ms <= 5_000;
        let same_lease_submitted_after_release = second_succeeded && second_sequence == 1;
        let passed = bounded_busy
            && no_partial_event
            && first_unpoisoned
            && same_lease_submitted_after_release
            && event_artifacts_after_retry == 1
            && authenticated_submitted_uncertain
            && roots_retained;
        let result = serde_json::json!({
            "fixture": "namespace-append-busy-v1",
            "passed": passed,
            "bounded_busy": bounded_busy,
            "reserve_attempt_limit": APPEND_RESERVE_ATTEMPTS,
            "first_reserve_attempts": first_reserve_attempts,
            "first_append_elapsed_ms": first_elapsed_ms,
            "no_partial_event": no_partial_event,
            "first_sequence": first_progress.sequence,
            "unpoisoned_after_busy": first_unpoisoned,
            "same_lease_submitted_after_release": same_lease_submitted_after_release,
            "second_sequence": second_sequence,
            "event_artifacts_after_retry": event_artifacts_after_retry,
            "authenticated_history_count": history_count,
            "authenticated_submitted_uncertain": authenticated_submitted_uncertain,
            "roots_retained": roots_retained,
            "network_used": false,
            "provider_used": false,
        });
        std::fs::write(
            root.join("RESULT.json"),
            serde_json::to_vec_pretty(&result).unwrap(),
        )
        .unwrap();
        assert!(
            passed,
            "C28 append quota contention fixture failed; preserve evidence"
        );
    }

    #[test]
    #[ignore = "explicit fresh-owned Windows private-store admission contention fixture; no DPAPI/default state/network/provider"]
    fn quota_admission_is_bounded_and_operation_lock_remains_exclusive() {
        use crate::namespace_intent::{
            CapturedAuthorization, LocalNamespaceEntry, NamespaceObjectKind, NamespaceParent,
            StorageClassification,
        };
        use crate::{LocalFileIdentity, RemoteEditBaseline};
        use std::{path::PathBuf, time::Instant};

        assert_eq!(
            std::env::var("RAIUN_RUN_NAMESPACE_ADMISSION").as_deref(),
            Ok("fresh-owned-state")
        );
        let root = PathBuf::from(
            std::env::var_os("RAIUN_NAMESPACE_ADMISSION_ROOT")
                .expect("explicit fresh evidence root"),
        );
        assert!(root.is_absolute());
        std::fs::create_dir(&root).expect("never reuse or overwrite a fixture root");
        let owner = root.join("OWNER.txt");
        std::fs::write(&owner, b"raiun-namespace-admission-busy-v1\n").unwrap();

        let parent = raiun_control_windows::PinnedDirectory::open(&root).unwrap();
        let state = Arc::new(
            raiun_control_windows::PrivateDirectory::create_or_open_under(
                &parent,
                OsStr::new("state"),
            )
            .unwrap(),
        );
        let scope = EditJournalScope {
            profile_id: "synthetic-profile".into(),
            server_origin: "https://synthetic.invalid".into(),
            account_subject: "synthetic-account".into(),
            space_id: "synthetic-personal-space".into(),
            root_resource_id: "synthetic-root".into(),
            root_volume_serial: 1,
            root_file_index: 2,
        };
        let policy = StorePolicy {
            max_content_bytes: 32 * 1024 * 1024,
            max_state_bytes: 64 * 1024 * 1024,
            max_entries: 2000,
            max_metadata_bytes_per_scan: 8 * 1024 * 1024,
        };
        let store = DirectoryIntentStore::create_or_open(
            state,
            scope.clone(),
            Arc::new(SyntheticProtector),
            policy,
        )
        .unwrap();
        let intent = NamespaceIntent {
            schema_version: 1,
            record_id: "a".repeat(32),
            record_generation: 1,
            operation: NamespaceOperation::CreateDirectory {
                destination: LocalNamespaceEntry {
                    parent: NamespaceParent {
                        scope: scope.clone(),
                        authorization: CapturedAuthorization {
                            agent_generation: 1,
                            token_generation: 1,
                        },
                        classification: StorageClassification::Ordinary,
                        local_file: LocalFileIdentity {
                            volume_serial: 1,
                            file_index: 3,
                        },
                        local_components: vec!["Personal".into()],
                        remote: RemoteEditBaseline {
                            resource_id: "synthetic-parent".into(),
                            etag: "\"synthetic-etag\"".into(),
                            byte_len: 0,
                        },
                    },
                    name: "synthetic-directory".into(),
                    object_kind: NamespaceObjectKind::Directory,
                    local_file: LocalFileIdentity {
                        volume_serial: 1,
                        file_index: 4,
                    },
                },
            },
        };
        let mut first_use_before = store.base.root.entries(policy.max_entries).unwrap();
        first_use_before.sort();
        let first_use_empty = store.discover_account_root().unwrap().is_empty();
        let mut first_use_after = store.base.root.entries(policy.max_entries).unwrap();
        first_use_after.sort();
        let first_use_no_lock_creation = first_use_empty
            && first_use_before == first_use_after
            && !first_use_after.iter().any(|name| name == V2_QUOTA_LOCK);
        let published = store.publish_intent(intent).unwrap();
        assert!(published.created);
        let record_directory = store.directory(false).unwrap();
        let dispatch_name = format!("{}.dispatch.lock", published.record.key.id);
        assert!(
            !record_directory
                .entries(policy.max_entries)
                .unwrap()
                .contains(&dispatch_name)
        );

        // Real quota lock contention before any dispatch lock file is created.
        let quota = store.reserve(0, 0).unwrap();
        let started = Instant::now();
        let blocked_dispatch = store.acquire_dispatch(&published.record.key);
        let dispatch_elapsed_ms = started.elapsed().as_millis() as u64;
        let dispatch_busy = matches!(&blocked_dispatch, Err(StoreError::Busy));
        let dispatch_no_partial_artifact = !record_directory
            .entries(policy.max_entries)
            .unwrap()
            .contains(&dispatch_name);
        drop(quota);
        let first_lease = if dispatch_busy {
            store.acquire_dispatch(&published.record.key).ok()
        } else {
            None
        };
        let dispatch_quota_bounded = dispatch_busy && dispatch_elapsed_ms <= 5_000;

        let mut first_lease = first_lease;
        let (history_busy, history_unchanged_after_release, operation_lock_fail_fast) =
            if let Some(lease) = first_lease.as_mut() {
                // Keep the actual record lock, then contend on the actual quota
                // lock used by account-root history discovery.
                let mut entries_before = lease.directory.entries(policy.max_entries).unwrap();
                entries_before.sort();
                let quota = store.reserve(0, 0).unwrap();
                let started = Instant::now();
                let blocked_history = store.discover_account_root();
                let history_elapsed_ms = started.elapsed().as_millis() as u64;
                let history_was_busy = matches!(&blocked_history, Err(StoreError::Busy))
                    && history_elapsed_ms <= 5_000
                    && lease.directory.entries(policy.max_entries).is_ok_and(
                        |mut entries_after| {
                            entries_after.sort();
                            entries_after == entries_before
                        },
                    );
                drop(quota);
                let history = store.discover_account_root();
                let history_unchanged = history.as_ref().is_ok_and(|records| {
                    records.len() == 1
                        && records[0].key == published.record.key
                        && records[0].intent == published.record.intent
                        && records[0].commitment == published.record.commitment
                        && records[0].progress.sequence == 0
                        && records[0].progress.remote == NamespacePhase::Pending
                        && records[0].progress.attention.is_none()
                });

                // The second actual operation-lock attempt stays fail-fast even
                // though its quota reservation now succeeds immediately.
                let started = Instant::now();
                let competing_lease = store.acquire_dispatch(&published.record.key);
                let operation_elapsed_ms = started.elapsed().as_millis() as u64;
                let operation_lock_busy = matches!(&competing_lease, Err(StoreError::Busy));
                let operation_lock_fast = operation_lock_busy && operation_elapsed_ms < 1_000;
                (history_was_busy, history_unchanged, operation_lock_fast)
            } else {
                (false, false, false)
            };
        drop(first_lease);

        let roots_retained = root.is_dir() && owner.is_file();
        let passed = dispatch_quota_bounded
            && dispatch_no_partial_artifact
            && history_busy
            && history_unchanged_after_release
            && operation_lock_fail_fast
            && first_use_no_lock_creation
            && roots_retained;
        let result = serde_json::json!({
            "fixture": "namespace-admission-busy-v1",
            "passed": passed,
            "dispatch_quota_bounded": dispatch_quota_bounded,
            "dispatch_elapsed_ms": dispatch_elapsed_ms,
            "dispatch_no_partial_artifact": dispatch_no_partial_artifact,
            "history_quota_bounded": history_busy,
            "history_unchanged_after_release": history_unchanged_after_release,
            "operation_lock_fail_fast": operation_lock_fail_fast,
            "first_use_no_lock_creation": first_use_no_lock_creation,
            "roots_retained": roots_retained,
            "network_used": false,
            "provider_used": false,
        });
        std::fs::write(
            root.join("RESULT.json"),
            serde_json::to_vec_pretty(&result).unwrap(),
        )
        .unwrap();
        assert!(
            passed,
            "C32 admission contention fixture failed; preserve evidence"
        );
    }

    #[test]
    #[ignore = "explicit fresh-owned CurrentUser DPAPI namespace-reader fixture; no default state/network/provider"]
    #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
    fn existing_namespace_reader_authenticates_without_creating_state() {
        use crate::namespace_intent::{
            CapturedAuthorization, LocalNamespaceEntry, NamespaceObjectKind, NamespaceParent,
            StorageClassification,
        };
        use crate::{DpapiEditRecordProtector, LocalFileIdentity, RemoteEditBaseline};
        use std::{io::Read, path::PathBuf, time::UNIX_EPOCH};

        fn metadata_digest(root: &std::path::Path) -> String {
            fn visit(
                root: &std::path::Path,
                current: &std::path::Path,
                hash: &mut Sha256,
                entries_seen: &mut usize,
                bytes_seen: &mut u64,
            ) {
                let remaining = 4096usize.saturating_sub(*entries_seen);
                let mut entries = std::fs::read_dir(current)
                    .unwrap()
                    .take(remaining + 1)
                    .map(|entry| entry.unwrap().path())
                    .collect::<Vec<_>>();
                assert!(
                    entries.len() <= remaining,
                    "fixture tree entry bound exceeded"
                );
                entries.sort();
                for path in entries {
                    *entries_seen = entries_seen.checked_add(1).expect("entry count overflow");
                    assert!(*entries_seen <= 4096, "fixture tree entry bound exceeded");
                    let metadata = std::fs::symlink_metadata(&path).unwrap();
                    assert!(
                        !metadata.file_type().is_symlink(),
                        "fixture tree must not contain symbolic links"
                    );
                    #[cfg(windows)]
                    {
                        use std::os::windows::fs::MetadataExt;
                        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
                        assert_eq!(
                            metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
                            0,
                            "fixture tree must not contain reparse points"
                        );
                    }
                    assert!(
                        metadata.is_dir() || metadata.is_file(),
                        "fixture tree must contain only regular files and directories"
                    );
                    let relative = path.strip_prefix(root).unwrap().to_string_lossy();
                    hash.update((relative.len() as u64).to_le_bytes());
                    hash.update(relative.as_bytes());
                    hash.update(metadata.len().to_le_bytes());
                    hash.update([
                        u8::from(metadata.is_dir()),
                        u8::from(metadata.permissions().readonly()),
                    ]);
                    let modified = metadata
                        .modified()
                        .unwrap_or(UNIX_EPOCH)
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default();
                    hash.update(modified.as_secs().to_le_bytes());
                    hash.update(modified.subsec_nanos().to_le_bytes());
                    if metadata.is_dir() {
                        visit(root, &path, hash, entries_seen, bytes_seen);
                    } else {
                        assert!(metadata.len() <= 64 * 1024 * 1024, "fixture file too large");
                        let mut file = std::fs::File::open(&path).unwrap();
                        let mut buffer = [0u8; 8192];
                        loop {
                            let count = file.read(&mut buffer).unwrap();
                            if count == 0 {
                                break;
                            }
                            *bytes_seen = bytes_seen
                                .checked_add(count as u64)
                                .expect("fixture byte count overflow");
                            assert!(
                                *bytes_seen <= 64 * 1024 * 1024,
                                "fixture byte bound exceeded"
                            );
                            hash.update(&buffer[..count]);
                        }
                    }
                }
            }
            let mut hash = Sha256::new();
            let mut entries_seen = 0;
            let mut bytes_seen = 0;
            visit(root, root, &mut hash, &mut entries_seen, &mut bytes_seen);
            hex(&hash.finalize())
        }

        assert_eq!(
            std::env::var("RAIUN_RUN_EXISTING_NAMESPACE_READER").as_deref(),
            Ok("fresh-owned-state")
        );
        let root = PathBuf::from(
            std::env::var_os("RAIUN_EXISTING_NAMESPACE_READER_ROOT")
                .expect("explicit fresh evidence root"),
        );
        assert!(root.is_absolute());
        std::fs::create_dir(&root).expect("never reuse or overwrite a fixture root");
        let owner = root.join("OWNER.txt");
        std::fs::write(&owner, b"raiun-existing-namespace-reader-v1\n").unwrap();
        let parent = raiun_control_windows::PinnedDirectory::open(&root).unwrap();
        let state = Arc::new(
            raiun_control_windows::PrivateDirectory::create_or_open_under(
                &parent,
                OsStr::new("state"),
            )
            .unwrap(),
        );
        let sessions = Arc::new(
            raiun_control_windows::PrivateDirectory::create_or_open_under(
                &raiun_control_windows::PinnedDirectory::open(state.path()).unwrap(),
                OsStr::new("sessions"),
            )
            .unwrap(),
        );
        let protector = Arc::new(
            DpapiEditRecordProtector::from_existing_private_directory(Arc::clone(&sessions))
                .unwrap(),
        );
        let policy = StorePolicy {
            max_content_bytes: 32 * 1024 * 1024,
            max_state_bytes: 64 * 1024 * 1024,
            max_entries: 2000,
            max_metadata_bytes_per_scan: 8 * 1024 * 1024,
        };
        let v2_path = sessions.path().join(V2_STORE_ROOT);
        let empty_reader =
            NamespaceHistoryReader::open_existing(Arc::clone(&sessions), protector.clone(), policy)
                .unwrap();
        let empty_scopes = empty_reader.discover_scopes().unwrap();
        let missing_root_unchanged = empty_scopes.is_empty() && !v2_path.exists();

        let scope = EditJournalScope {
            profile_id: "synthetic-profile".into(),
            server_origin: "https://synthetic.invalid".into(),
            account_subject: "synthetic-account".into(),
            space_id: "synthetic-personal-space".into(),
            root_resource_id: "synthetic-root".into(),
            root_volume_serial: 1,
            root_file_index: 2,
        };
        let writer = DirectoryIntentStore::create_or_open(
            Arc::clone(&sessions),
            scope.clone(),
            protector.clone(),
            policy,
        )
        .unwrap();
        let intent = NamespaceIntent {
            schema_version: 1,
            record_id: "a".repeat(32),
            record_generation: 1,
            operation: NamespaceOperation::CreateDirectory {
                destination: LocalNamespaceEntry {
                    parent: NamespaceParent {
                        scope: scope.clone(),
                        authorization: CapturedAuthorization {
                            agent_generation: 1,
                            token_generation: 1,
                        },
                        classification: StorageClassification::Ordinary,
                        local_file: LocalFileIdentity {
                            volume_serial: 1,
                            file_index: 3,
                        },
                        local_components: vec!["Personal".into()],
                        remote: RemoteEditBaseline {
                            resource_id: "synthetic-parent".into(),
                            etag: "\"synthetic-etag\"".into(),
                            byte_len: 0,
                        },
                    },
                    name: "synthetic-directory".into(),
                    object_kind: NamespaceObjectKind::Directory,
                    local_file: LocalFileIdentity {
                        volume_serial: 1,
                        file_index: 4,
                    },
                },
            },
        };
        let published = writer.publish_intent(intent).unwrap();
        assert!(published.created);
        let stale_reader_scopes = empty_reader.discover_scopes().unwrap();
        let stale_absence_rechecked = stale_reader_scopes == vec![scope.clone()];
        let upper_scopes =
            SnapshotStore::discover_state_scopes(Arc::clone(&sessions), protector.clone(), policy)
                .unwrap();
        let before_reader = metadata_digest(&root);
        let reader =
            NamespaceHistoryReader::open_existing(Arc::clone(&sessions), protector.clone(), policy)
                .unwrap();
        let scopes = reader.discover_scopes().unwrap();
        let records = if scopes.len() == 1 && scopes[0] == scope {
            reader.discover_account_root(&scopes[0]).unwrap()
        } else {
            Vec::new()
        };
        let authenticated_pending = records.len() == 1
            && records[0].key == published.record.key
            && records[0].intent == published.record.intent
            && records[0].progress.sequence == 0
            && records[0].progress.remote == NamespacePhase::Pending
            && records[0].progress.attention.is_none()
            && !records[0].progress.local_completed;
        let after_reader = metadata_digest(&root);
        let no_reader_writes = before_reader == after_reader
            && sessions.verify_path().is_ok()
            && state.verify_path().is_ok();

        // The same authenticated scope may legitimately have both an upper
        // snapshot catalog and a namespace catalog; count their key once.
        let shared_quota = writer.reserve((META_LIMIT as u64) * 2, 4).unwrap();
        writer.base.ensure_scope().unwrap();
        drop(shared_quota);
        let before_shared_read = metadata_digest(&root);
        let shared_catalog_scope_accepted = reader.discover_scopes().unwrap() == scopes;
        let after_shared_read = metadata_digest(&root);

        let before_busy_read = metadata_digest(&root);
        let quota = writer.reserve(0, 0).unwrap();
        let quota_busy_fails_closed = matches!(reader.discover_scopes(), Err(StoreError::Busy));
        let quota_history_busy_fails_closed = matches!(
            reader.discover_account_root(&scopes[0]),
            Err(StoreError::Busy)
        );
        drop(quota);
        let after_busy_read = metadata_digest(&root);

        let namespace_root = writer.base.root.child(ROOT, false).unwrap();
        let corrupt_key = "f".repeat(64);
        let (mut corrupt, _) = namespace_root
            .create(&format!("{corrupt_key}.scope"))
            .unwrap();
        corrupt.write_all(b"owned-corrupt-catalog").unwrap();
        corrupt.sync().unwrap();
        drop(corrupt);
        namespace_root.child(&corrupt_key, true).unwrap();
        let before_corrupt_read = metadata_digest(&root);
        let corrupt_fails_closed = reader.discover_scopes().is_err();
        let after_corrupt_read = metadata_digest(&root);

        // Use a separate owned store so this refusal cannot be explained by
        // the deliberately corrupt namespace catalog in the first store.
        let upper_sessions = Arc::new(
            raiun_control_windows::PrivateDirectory::create_or_open_under(
                &raiun_control_windows::PinnedDirectory::open(state.path()).unwrap(),
                OsStr::new("upper-only-sessions"),
            )
            .unwrap(),
        );
        let upper_protector = Arc::new(
            DpapiEditRecordProtector::from_existing_private_directory(Arc::clone(&upper_sessions))
                .unwrap(),
        );
        let upper_writer = SnapshotStore::create_or_open(
            Arc::clone(&upper_sessions),
            scope.clone(),
            upper_protector.clone(),
            policy,
        )
        .unwrap();
        let upper_reader =
            NamespaceHistoryReader::open_existing(upper_sessions, upper_protector, policy).unwrap();
        let corrupt_upper_key = "e".repeat(64);
        let (mut upper_corrupt, _) = upper_writer
            .root
            .create(&format!("{corrupt_upper_key}.scope"))
            .unwrap();
        upper_corrupt
            .write_all(b"owned-corrupt-upper-catalog")
            .unwrap();
        upper_corrupt.sync().unwrap();
        drop(upper_corrupt);
        upper_writer.root.child(&corrupt_upper_key, true).unwrap();
        let before_upper_corrupt_read = metadata_digest(&root);
        let upper_catalog_fails_closed = upper_reader.discover_scopes().is_err();
        let after_upper_corrupt_read = metadata_digest(&root);
        let roots_retained = root.is_dir() && owner.is_file();
        let passed = missing_root_unchanged
            && upper_scopes.is_empty()
            && stale_absence_rechecked
            && scopes == vec![scope]
            && authenticated_pending
            && no_reader_writes
            && shared_catalog_scope_accepted
            && before_shared_read == after_shared_read
            && corrupt_fails_closed
            && before_corrupt_read == after_corrupt_read
            && upper_catalog_fails_closed
            && before_upper_corrupt_read == after_upper_corrupt_read
            && quota_busy_fails_closed
            && quota_history_busy_fails_closed
            && before_busy_read == after_busy_read
            && roots_retained;
        let result = serde_json::json!({
            "fixture": "existing-namespace-reader-v1",
            "passed": passed,
            "missing_root_unchanged": missing_root_unchanged,
            "stale_absence_rechecked": stale_absence_rechecked,
            "upper_snapshot_scopes_empty": upper_scopes.is_empty(),
            "namespace_scope_count": scopes.len(),
            "authenticated_pending_record": authenticated_pending,
            "reader_metadata_unchanged": no_reader_writes,
            "shared_catalog_scope_accepted": shared_catalog_scope_accepted,
            "shared_catalog_reader_unchanged": before_shared_read == after_shared_read,
            "corrupt_catalog_fails_closed": corrupt_fails_closed,
            "corrupt_catalog_preserved": before_corrupt_read == after_corrupt_read,
            "upper_catalog_fails_closed": upper_catalog_fails_closed,
            "upper_catalog_preserved": before_upper_corrupt_read == after_upper_corrupt_read,
            "quota_busy_fails_closed": quota_busy_fails_closed,
            "quota_history_busy_fails_closed": quota_history_busy_fails_closed,
            "quota_busy_metadata_unchanged": before_busy_read == after_busy_read,
            "roots_retained": roots_retained,
            "network_used": false,
            "provider_used": false,
        });
        std::fs::write(
            root.join("RESULT.json"),
            serde_json::to_vec_pretty(&result).unwrap(),
        )
        .unwrap();
        assert!(
            passed,
            "existing namespace reader fixture failed; preserve evidence"
        );
    }

    #[test]
    #[ignore = "explicit fresh synthetic inspector proof; no CloudFiles/default state/network"]
    #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
    fn retained_history_inspector_qualifies_on_fresh_owned_state() {
        use crate::namespace_intent::{
            CapturedAuthorization, LocalNamespaceEntry, NamespaceObjectKind, NamespaceParent,
            StorageClassification,
        };
        use crate::{DpapiEditRecordProtector, LocalFileIdentity, RemoteEditBaseline};

        assert_eq!(
            std::env::var("RAIUN_RUN_RETAINED_HISTORY_INSPECTOR").as_deref(),
            Ok("fresh-owned-fixture")
        );
        let root = std::path::PathBuf::from(
            std::env::var_os("RAIUN_RETAINED_HISTORY_INSPECTOR_ROOT")
                .expect("explicit fresh synthetic fixture root"),
        );
        assert!(root.is_absolute());
        std::fs::create_dir(&root).expect("never reuse a retained fixture");
        std::fs::write(
            root.join("OWNER.txt"),
            b"raiun-headless-automatic-directory-v1\n",
        )
        .unwrap();
        let fixture_pin = raiun_control_windows::PinnedDirectory::open(&root).unwrap();
        let cloud = fixture_pin
            .create_child_directory(OsStr::new("cloud-root"))
            .unwrap();
        let identity = cloud.identity();
        let personal = cloud
            .create_child_directory(OsStr::new("Personal"))
            .unwrap();
        let destination = personal
            .create_child_directory(OsStr::new("synthetic-directory"))
            .unwrap();
        let parent_identity = personal.identity();
        let destination_identity = destination.identity();
        assert_eq!(identity.volume_serial, parent_identity.volume_serial);
        assert_eq!(identity.volume_serial, destination_identity.volume_serial);
        assert_ne!(identity.file_index, parent_identity.file_index);
        assert_ne!(identity.file_index, destination_identity.file_index);
        assert_ne!(parent_identity.file_index, destination_identity.file_index);
        let state = raiun_control_windows::PrivateDirectory::create_or_open_under(
            &fixture_pin,
            OsStr::new("state"),
        )
        .unwrap();
        let sessions = Arc::new(
            raiun_control_windows::PrivateDirectory::create_or_open_under(
                &raiun_control_windows::PinnedDirectory::open(state.path()).unwrap(),
                OsStr::new("sessions"),
            )
            .unwrap(),
        );
        let protector = Arc::new(
            DpapiEditRecordProtector::from_existing_private_directory(Arc::clone(&sessions))
                .unwrap(),
        );
        let policy = StorePolicy {
            max_content_bytes: 32 * 1024 * 1024,
            max_state_bytes: 64 * 1024 * 1024,
            max_entries: 2000,
            max_metadata_bytes_per_scan: 8 * 1024 * 1024,
        };
        let scope = EditJournalScope {
            profile_id: "default".into(),
            server_origin: "https://synthetic.invalid".into(),
            account_subject: "synthetic-inspector-account".into(),
            space_id: "synthetic-personal-space".into(),
            root_resource_id: "synthetic-root".into(),
            root_volume_serial: identity.volume_serial,
            root_file_index: identity.file_index,
        };
        let make_intent = |scope: EditJournalScope, id: &str| NamespaceIntent {
            schema_version: 1,
            record_id: id.repeat(32),
            record_generation: 1,
            operation: NamespaceOperation::CreateDirectory {
                destination: LocalNamespaceEntry {
                    parent: NamespaceParent {
                        scope,
                        authorization: CapturedAuthorization {
                            agent_generation: 1,
                            token_generation: 1,
                        },
                        classification: StorageClassification::Ordinary,
                        local_file: LocalFileIdentity {
                            volume_serial: parent_identity.volume_serial,
                            file_index: parent_identity.file_index,
                        },
                        local_components: vec!["Personal".into()],
                        remote: RemoteEditBaseline {
                            resource_id: "synthetic-parent".into(),
                            etag: "\"synthetic-etag\"".into(),
                            byte_len: 0,
                        },
                    },
                    name: "synthetic-directory".into(),
                    object_kind: NamespaceObjectKind::Directory,
                    local_file: LocalFileIdentity {
                        volume_serial: destination_identity.volume_serial,
                        file_index: destination_identity.file_index,
                    },
                },
            },
        };
        let writer = DirectoryIntentStore::create_or_open(
            Arc::clone(&sessions),
            scope.clone(),
            protector.clone(),
            policy,
        )
        .unwrap();
        assert!(
            writer
                .publish_intent(make_intent(scope.clone(), "a"))
                .unwrap()
                .created
        );
        let observed = super::retained_fixture_inspector::inspect_existing_fixture(&root)
            .expect("fresh inspector refused; preserve fixture");
        let observed_one = observed["status"] == "observed"
            && observed["record_count"] == 1
            && observed["v2_metadata_unchanged"] == true
            && observed["root_identity_matches"] == true;

        // Deliberate fresh-only setup changes, never performed by the inspector.
        let mut other_scope = scope;
        other_scope.account_subject = "synthetic-other-account".into();
        let other_writer = DirectoryIntentStore::create_or_open(
            Arc::clone(&sessions),
            other_scope.clone(),
            protector,
            policy,
        )
        .unwrap();
        assert!(
            other_writer
                .publish_intent(make_intent(other_scope, "b"))
                .unwrap()
                .created
        );
        let ambiguity = super::retained_fixture_inspector::inspect_existing_fixture(&root)
            .expect("fresh ambiguity observation unavailable");
        let ambiguity_refused = ambiguity["status"] == "scope_ambiguous"
            && ambiguity["record_count"].is_null()
            && ambiguity["progress"].is_null()
            && ambiguity["v2_metadata_unchanged"] == true;
        let unsupported = sessions
            .path()
            .join(V2_STORE_ROOT)
            .join("unsupported.snapshot-body");
        std::fs::write(&unsupported, b"synthetic-body-must-not-be-read").unwrap();
        let unsupported_layout_refused = matches!(
            super::retained_fixture_inspector::inspect_existing_fixture(&root),
            Err("unsupported_layout")
        );
        let passed = observed_one && ambiguity_refused && unsupported_layout_refused;
        let result = serde_json::json!({
            "fixture": "fresh-retained-history-inspector-v1",
            "passed": passed,
            "observed_one_authenticated_record": observed_one,
            "valid_observation": observed,
            "ambiguous_account_root_refused": ambiguity_refused,
            "unsupported_body_layout_refused": unsupported_layout_refused,
            "roots_retained": true,
            "old_C33_protected_contents_read": false,
            "network_used": false,
            "provider_used": false,
        });
        std::fs::write(
            root.join("RESULT.json"),
            serde_json::to_vec_pretty(&result).unwrap(),
        )
        .unwrap();
        assert!(passed, "fresh inspector proof failed; preserve fixture");
    }

    #[test]
    #[ignore = "explicit fresh-owned quota-open fix fixture; no C33 state/network/provider"]
    #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
    fn quota_open_sharing_conflict_is_busy_without_weakening_other_failures() {
        use crate::DpapiEditRecordProtector;
        use std::path::PathBuf;

        assert_eq!(
            std::env::var("RAIUN_RUN_QUOTA_OPEN_FIX").as_deref(),
            Ok("fresh-owned-state")
        );
        let root = PathBuf::from(
            std::env::var_os("RAIUN_QUOTA_OPEN_FIX_ROOT").expect("explicit fresh fixture root"),
        );
        assert!(root.is_absolute());
        std::fs::create_dir(&root).expect("never reuse a fixture root");
        std::fs::write(root.join("OWNER.txt"), b"raiun-quota-open-fix-v1\n").unwrap();

        let fixture_pin = raiun_control_windows::PinnedDirectory::open(&root).unwrap();
        let state = Arc::new(
            raiun_control_windows::PrivateDirectory::create_or_open_under(
                &fixture_pin,
                OsStr::new("state"),
            )
            .unwrap(),
        );
        let sessions = Arc::new(
            raiun_control_windows::PrivateDirectory::create_or_open_under(
                &raiun_control_windows::PinnedDirectory::open(state.path()).unwrap(),
                OsStr::new("sessions"),
            )
            .unwrap(),
        );
        let protector = Arc::new(
            DpapiEditRecordProtector::from_existing_private_directory(Arc::clone(&sessions))
                .unwrap(),
        );
        let policy = StorePolicy {
            max_content_bytes: 32 * 1024 * 1024,
            max_state_bytes: 64 * 1024 * 1024,
            max_entries: 2000,
            max_metadata_bytes_per_scan: 8 * 1024 * 1024,
        };
        let scope = EditJournalScope {
            profile_id: "default".into(),
            server_origin: "https://synthetic.invalid".into(),
            account_subject: "synthetic-quota-open-account".into(),
            space_id: "synthetic-quota-open-space".into(),
            root_resource_id: "synthetic-quota-open-root".into(),
            root_volume_serial: 1,
            root_file_index: 2,
        };
        let store = DirectoryIntentStore::create_or_open(
            Arc::clone(&sessions),
            scope.clone(),
            protector,
            policy,
        )
        .unwrap();
        let baseline_empty = store
            .discover_account_root()
            .is_ok_and(|records| records.is_empty());
        let v2_path = sessions.path().join(V2_STORE_ROOT);
        let quota_path = v2_path.join(V2_QUOTA_LOCK);
        let baseline_empty_without_quota =
            baseline_empty && v2_path.is_dir() && !quota_path.exists();
        let v2 = Arc::new(
            raiun_control_windows::PrivateDirectory::open_under(
                &raiun_control_windows::PinnedDirectory::open(sessions.path()).unwrap(),
                OsStr::new(V2_STORE_ROOT),
            )
            .unwrap(),
        );

        let (creator, created_identity) = v2.create_new_file(OsStr::new(V2_QUOTA_LOCK)).unwrap();
        creator.sync_all().unwrap();
        let creator_zero_length = creator.metadata().unwrap().len() == 0;
        let direct_open = v2.open_owned_immutable_file(OsStr::new(V2_QUOTA_LOCK));
        let (creator_open_failed_before_lock, open_error_code) = match direct_open {
            Ok(handle) => {
                drop(handle);
                (false, None)
            }
            Err(error) => (true, error.raw_os_error()),
        };
        let creator_history = store.discover_account_root();
        let creator_history_class = match &creator_history {
            Err(StoreError::Io) => "io",
            Err(StoreError::Busy) => "busy",
            Err(StoreError::IncompleteEvidence) => "incomplete_evidence",
            Err(StoreError::CorruptEvidence) => "corrupt_evidence",
            Err(StoreError::Invalid) => "invalid",
            Err(StoreError::Quota) => "quota",
            Err(StoreError::ScanLimit) => "scan_limit",
            Err(StoreError::PublicationUncertain) => "publication_uncertain",
            Err(StoreError::Snapshot(_)) => "snapshot",
            Ok(_) => "ok",
        };
        let creator_history_busy = matches!(creator_history, Err(StoreError::Busy));
        let creator_admission_busy = matches!(store.reserve(0, 0), Err(StoreError::Busy));
        drop(creator);

        let (
            lock_open_succeeded,
            first_lock_succeeded,
            lock_attempt_failed,
            lock_error_code,
            lock_history_busy,
        ) = match (
            v2.open_owned_immutable_file(OsStr::new(V2_QUOTA_LOCK)),
            v2.open_owned_immutable_file(OsStr::new(V2_QUOTA_LOCK)),
        ) {
            (Ok(mut first), Ok(mut second)) => {
                let first_lock_succeeded = first.try_lock_exclusive().is_ok();
                let second_lock = second.try_lock_exclusive();
                let lock_error_code = second_lock
                    .as_ref()
                    .err()
                    .and_then(std::io::Error::raw_os_error);
                let lock_attempt_failed = second_lock.is_err();
                let lock_history_busy = first_lock_succeeded
                    && matches!(store.discover_account_root(), Err(StoreError::Busy));
                drop(second);
                drop(first);
                (
                    true,
                    first_lock_succeeded,
                    lock_attempt_failed,
                    lock_error_code,
                    lock_history_busy,
                )
            }
            _ => (false, false, false, None, false),
        };
        let lock_attempted = lock_open_succeeded;
        let history_under_lock_attempted = lock_open_succeeded && first_lock_succeeded;

        let (quota_identity_preserved, quota_zero_length) =
            match v2.open_owned_immutable_file(OsStr::new(V2_QUOTA_LOCK)) {
                Ok(final_file) => (
                    final_file.identity() == created_identity,
                    final_file
                        .metadata()
                        .is_ok_and(|metadata| metadata.len() == 0),
                ),
                Err(_) => (false, false),
            };
        let after_release_history_empty = store
            .discover_account_root()
            .is_ok_and(|records| records.is_empty());
        let generic_sharing_error_stays_io =
            io_error(std::io::Error::from_raw_os_error(32)) == StoreError::Io;
        let other_open_errors_stay_io = [2, 5, 33].into_iter().all(|code| {
            quota_lock_open_error(std::io::Error::from_raw_os_error(code)) == StoreError::Io
        }) && quota_lock_open_error(std::io::Error::from(
            std::io::ErrorKind::WouldBlock,
        )) == StoreError::Io;

        // Separate fresh state retains an intentionally invalid nonzero lock.
        let nonzero_state = raiun_control_windows::PrivateDirectory::create_or_open_under(
            &fixture_pin,
            OsStr::new("nonzero-state"),
        )
        .unwrap();
        let nonzero_sessions = Arc::new(
            raiun_control_windows::PrivateDirectory::create_or_open_under(
                &raiun_control_windows::PinnedDirectory::open(nonzero_state.path()).unwrap(),
                OsStr::new("sessions"),
            )
            .unwrap(),
        );
        let nonzero_protector = Arc::new(
            DpapiEditRecordProtector::from_existing_private_directory(Arc::clone(
                &nonzero_sessions,
            ))
            .unwrap(),
        );
        let nonzero_store = DirectoryIntentStore::create_or_open(
            Arc::clone(&nonzero_sessions),
            scope,
            nonzero_protector,
            policy,
        )
        .unwrap();
        let (mut nonzero_quota, nonzero_identity) =
            nonzero_store.base.root.create(V2_QUOTA_LOCK).unwrap();
        nonzero_quota.write_all(b"x").unwrap();
        nonzero_quota.sync().unwrap();
        drop(nonzero_quota);
        let nonzero_history_refused = matches!(
            nonzero_store.discover_account_root(),
            Err(StoreError::CorruptEvidence)
        );
        let nonzero_admission_refused = matches!(
            nonzero_store.reserve(0, 0),
            Err(StoreError::CorruptEvidence)
        );
        let nonzero_quota_preserved = nonzero_store.base.root.open_quota_lock().is_ok_and(|file| {
            file.identity() == nonzero_identity
                && file.len().is_ok_and(|length| length == 1)
                && file.verify().is_ok()
        });
        let private_pins_valid = state.verify_path().is_ok()
            && sessions.verify_path().is_ok()
            && v2.verify_path().is_ok()
            && nonzero_state.verify_path().is_ok()
            && nonzero_sessions.verify_path().is_ok()
            && nonzero_store.base.root.verify().is_ok();
        let roots_retained = root.is_dir() && root.join("OWNER.txt").is_file();
        let passed = baseline_empty_without_quota
            && creator_zero_length
            && creator_open_failed_before_lock
            && open_error_code == Some(32)
            && creator_history_busy
            && creator_admission_busy
            && lock_open_succeeded
            && first_lock_succeeded
            && lock_attempt_failed
            && lock_error_code == Some(33)
            && lock_history_busy
            && after_release_history_empty
            && quota_identity_preserved
            && quota_zero_length
            && generic_sharing_error_stays_io
            && other_open_errors_stay_io
            && nonzero_history_refused
            && nonzero_admission_refused
            && nonzero_quota_preserved
            && private_pins_valid
            && roots_retained;
        let result = serde_json::json!({
            "fixture": "fresh-quota-open-fix-v1",
            "passed": passed,
            "baseline_empty_without_quota": baseline_empty_without_quota,
            "direct_immutable_open_attempted": true,
            "direct_creator_lock_attempted": false,
            "creator_open_failed_before_lock": creator_open_failed_before_lock,
            "history_under_creator_attempted": true,
            "creator_history_busy": creator_history_busy,
            "creator_admission_busy": creator_admission_busy,
            "creator_history_class": creator_history_class,
            "lock_open_succeeded": lock_open_succeeded,
            "lock_attempted": lock_attempted,
            "first_lock_succeeded": first_lock_succeeded,
            "lock_attempt_failed": lock_attempt_failed,
            "history_under_lock_attempted": history_under_lock_attempted,
            "lock_history_busy": lock_history_busy,
            "after_release_history_empty": after_release_history_empty,
            "quota_identity_preserved": quota_identity_preserved,
            "quota_zero_length": quota_zero_length,
            "private_pins_valid": private_pins_valid,
            "roots_retained": roots_retained,
            "open_error_code": open_error_code,
            "lock_error_code": lock_error_code,
            "generic_sharing_error_stays_io": generic_sharing_error_stays_io,
            "other_open_errors_stay_io": other_open_errors_stay_io,
            "nonzero_history_refused": nonzero_history_refused,
            "nonzero_admission_refused": nonzero_admission_refused,
            "nonzero_quota_preserved": nonzero_quota_preserved,
            "demonstrated_mechanism_fixed": passed,
            "C33_cause_established": false,
            "network_used": false,
            "provider_used": false
        });
        std::fs::write(
            root.join("RESULT.json"),
            serde_json::to_vec_pretty(&result).unwrap(),
        )
        .unwrap();
        assert!(passed, "quota open fix fixture failed; preserve root");
    }
}

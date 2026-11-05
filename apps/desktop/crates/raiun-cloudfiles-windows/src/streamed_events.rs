//! Authenticated local dispatch evidence. No remote/native authority is minted.
use super::*;
const KEY_DOMAIN: &[u8] = b"raiun/snapshot-store/record-commitment/v2\0";
const EVENT_DOMAIN: &[u8] = b"raiun/snapshot-store/dispatch-event/v2\0";
const EVENT_LIMIT: usize = 16 * 1024;
pub const MAX_STREAMED_HISTORY: usize = 128;

/// A commitment minted only from an authenticated complete manifest. This is
/// metadata selection, not fresh admission, source identity or upload authority.
#[derive(Clone, Eq, PartialEq)]
pub struct StreamedRecordKey {
    binding: SnapshotBinding,
    commitment: [u8; 32],
}
impl std::fmt::Debug for StreamedRecordKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StreamedRecordKey([AUTHENTICATED LOCAL COMMITMENT])")
    }
}
impl StreamedRecordKey {
    pub fn record_id(&self) -> &str {
        &self.binding.record_id
    }
    pub fn generation(&self) -> u64 {
        self.binding.generation
    }
    pub fn scope(&self) -> &EditJournalScope {
        &self.binding.scope
    }
    pub fn commitment_sha256(&self) -> &[u8; 32] {
        &self.commitment
    }
    pub(super) fn from_manifest(manifest: &SnapshotManifest) -> Result<Self, StoreError> {
        // Fixed-order serde struct serialization, no maps/floats. Domain/version
        // changes are required if the canonical manifest schema changes.
        let bytes = Zeroizing::new(serde_json::to_vec(manifest).map_err(|_| StoreError::Invalid)?);
        let mut digest = Sha256::new();
        digest.update(KEY_DOMAIN);
        digest.update(&*bytes);
        Ok(Self {
            binding: manifest.binding().clone(),
            commitment: digest.finalize().into(),
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamedAttemptState {
    NotAttempted,
    Uncertain {
        attempt_id: u64,
    },
    VerifiedApplied {
        attempt_id: u64,
        attempts: u8,
    },
    Conflict {
        attempt_id: u64,
        attempts: u8,
    },
    Ambiguous {
        attempt_id: u64,
        attempts: u8,
    },
    Deferred {
        attempt_id: u64,
        attempts: u8,
    },
    LocallyAcknowledged {
        attempt_id: u64,
        attempts: u8,
    },
    /// Original create body was retained after a separately captured edit
    /// completed; it was never acknowledged as current file contents.
    Superseded {
        attempt_id: u64,
        attempts: u8,
    },
}
impl StreamedAttemptState {
    pub fn attempt_id(self) -> u64 {
        match self {
            Self::NotAttempted => 0,
            Self::Uncertain { attempt_id }
            | Self::VerifiedApplied { attempt_id, .. }
            | Self::Conflict { attempt_id, .. }
            | Self::Ambiguous { attempt_id, .. }
            | Self::Deferred { attempt_id, .. }
            | Self::LocallyAcknowledged { attempt_id, .. }
            | Self::Superseded { attempt_id, .. } => attempt_id,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum StreamedAttemptOutcome {
    VerifiedApplied,
    Conflict,
    Ambiguous,
    Deferred,
}
pub struct StreamedRecoveryMetadata {
    pub key: StreamedRecordKey,
    pub manifest: SnapshotManifest,
    pub state: StreamedAttemptState,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    version: u32,
    commitment: [u8; 32],
    scope: EditJournalScope,
    record_id: String,
    generation: u64,
    sequence: u64,
    dispatch_id: String,
    attempt_id: u64,
    action: EventAction,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum EventAction {
    Attempting {
        ordinal: u8,
    },
    Outcome {
        attempts: u8,
        outcome: StreamedAttemptOutcome,
    },
    LocalAcknowledged {
        attempts: u8,
    },
    Superseded {
        edit: crate::namespace_intent::ContinuedEditReference,
    },
}
struct History {
    state: StreamedAttemptState,
    sequence: u64,
    #[cfg(windows)]
    superseded_edit: Option<crate::namespace_intent::ContinuedEditReference>,
}

impl SnapshotStore {
    /// Authenticate the selected manifest/reservation and current body metadata.
    /// No body bytes are read; possession of this key grants no dispatch admission.
    pub fn record_key(&self, record_id: &str) -> Result<StreamedRecordKey, StoreError> {
        let mut budget = Budget::new(self.policy);
        StreamedRecordKey::from_manifest(&self.selected_manifest(record_id, &mut budget)?)
    }
    pub fn discover_records(&self) -> Result<Vec<StreamedRecoveryMetadata>, StoreError> {
        self.discover_records_bounded(&mut DiscoveryBudget::new(self.policy))
    }
    pub(crate) fn discover_records_bounded(
        &self,
        budget: &mut DiscoveryBudget,
    ) -> Result<Vec<StreamedRecoveryMetadata>, StoreError> {
        budget.within_policy(self.policy, |budget| self.discover_records_inner(budget))
    }
    fn discover_records_inner(
        &self,
        budget: &mut Budget,
    ) -> Result<Vec<StreamedRecoveryMetadata>, StoreError> {
        let (manifests, names) = self.discover_metadata_budgeted(budget)?;
        let directory = if manifests.is_empty() {
            return Ok(Vec::new());
        } else {
            self.root.child(&self.key, false)?
        };
        let mut results = Vec::new();
        for manifest in manifests {
            let key = StreamedRecordKey::from_manifest(&manifest)?;
            let state = self
                .read_history_names(&*directory, &key, &names, budget)?
                .state;
            results.push(StreamedRecoveryMetadata {
                key,
                manifest,
                state,
            });
        }
        Ok(results)
    }
    pub fn open_verified_key(
        &self,
        key: &StreamedRecordKey,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<VerifiedPinnedSnapshot, StoreError> {
        self.check_key(key)?;
        let verified = self.open_verified(key.record_id(), cancelled)?;
        if StreamedRecordKey::from_manifest(verified.manifest())? != *key {
            return Err(StoreError::CorruptEvidence);
        }
        Ok(verified)
    }
    pub fn acquire_dispatch(
        self: &Arc<Self>,
        key: &StreamedRecordKey,
    ) -> Result<StreamedDispatchLease, StoreError> {
        self.check_key(key)?;
        let directory = self.root.child(&self.key, false)?;
        let name = format!("{}.dispatch.lock", key.record_id());
        // If absent, creation/accounting is a short state-only operation. Drop
        // that lease BEFORE acquiring a record lock; no state->record lock edge.
        let file = match directory.open(&name) {
            Ok(file) => file,
            Err(_) => {
                let state_lease = self.acquire_lock()?;
                let inventory = self.inventory()?;
                if inventory
                    .entries
                    .checked_add(1)
                    .is_none_or(|n| n > self.policy.max_entries)
                {
                    return Err(StoreError::ScanLimit);
                }
                if inventory.bytes > self.policy.max_state_bytes {
                    return Err(StoreError::Quota);
                }
                match directory.create(&name) {
                    Ok((file, _)) => {
                        file.sync()?;
                        drop(file);
                    }
                    Err(_) => { /* a concurrent creator must leave a valid lock */ }
                }
                let file = directory.open(&name)?;
                drop(state_lease);
                file
            }
        };
        let mut file = file;
        if file.len()? != 0 {
            return Err(StoreError::CorruptEvidence);
        }
        file.lock_exclusive()?;
        file.verify()?;
        self.check_key(key)?;
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| StoreError::Io)?;
        let lease = StreamedDispatchLease {
            store: Arc::clone(self),
            directory,
            key: key.clone(),
            _record_lock: file,
            dispatch_id: hex(&random),
            puts: 0,
            finished: false,
            poisoned: false,
        };
        lease.current_state()?;
        Ok(lease)
    }
    fn check_key(&self, key: &StreamedRecordKey) -> Result<(), StoreError> {
        if key.scope() != &self.scope || self.record_key(key.record_id())? != *key {
            return Err(StoreError::CorruptEvidence);
        }
        Ok(())
    }
    fn selected_manifest(
        &self,
        id: &str,
        budget: &mut Budget,
    ) -> Result<SnapshotManifest, StoreError> {
        if !valid_id(id) {
            return Err(StoreError::Invalid);
        }
        self.authenticate_scope(&self.key, budget)?;
        let directory = self.root.child(&self.key, false)?;
        let sealed = read_metadata(&*directory, &format!("{id}.manifest"), budget)?;
        let manifest = open_manifest(
            &sealed,
            &*self.protector,
            &self.scope,
            id,
            self.policy.codec()?,
        )?;
        let reservation = self.authenticate_reservation(&*directory, id, &self.scope, budget)?;
        if reservation.binding != *manifest.binding() {
            return Err(StoreError::CorruptEvidence);
        }
        let body = directory.open(&format!("{id}.body"))?;
        if body.len()? != manifest.container_len() {
            return Err(StoreError::IncompleteEvidence);
        }
        body.verify()?;
        Ok(manifest)
    }
    pub(super) fn create_acknowledged_metadata(
        &self,
        manifest: &SnapshotManifest,
        directory: &dyn Directory,
        budget: &mut Budget,
    ) -> Result<bool, StoreError> {
        let key = StreamedRecordKey::from_manifest(manifest)?;
        Ok(self.read_history(directory, &key, budget)?.state
            == (StreamedAttemptState::LocallyAcknowledged {
                attempt_id: 0,
                attempts: 0,
            }))
    }
    /// Authenticate only an already referenced create snapshot's event state.
    /// The caller supplies its validated manifest and existing directory; no
    /// body handle, storage setup or recovery/native authority is acquired.
    pub(super) fn create_original_state_metadata(
        &self,
        manifest: &SnapshotManifest,
        directory: &dyn Directory,
        budget: &mut Budget,
    ) -> Result<StreamedAttemptState, StoreError> {
        let key = StreamedRecordKey::from_manifest(manifest)?;
        Ok(self.read_history(directory, &key, budget)?.state)
    }
    /// Authenticate one continued file-create edit under the caller's existing
    /// scan budget. This is a metadata/state check, not a native or upload permit.
    #[cfg(windows)]
    pub(super) fn continued_edit_metadata(
        &self,
        record_id: &str,
        budget: &mut Budget,
    ) -> Result<(StreamedRecordKey, SnapshotManifest, StreamedAttemptState), StoreError> {
        let manifest = self.selected_manifest(record_id, budget)?;
        let key = StreamedRecordKey::from_manifest(&manifest)?;
        let directory = self.root.child(&self.key, false)?;
        let state = self.read_history(&*directory, &key, budget)?.state;
        Ok((key, manifest, state))
    }
    /// The sealed original-stream terminal link, if present. A caller must
    /// independently authenticate the joined create and linked edit metadata.
    #[cfg(windows)]
    pub(super) fn create_superseded_metadata(
        &self,
        key: &StreamedRecordKey,
        budget: &mut Budget,
    ) -> Result<Option<crate::namespace_intent::ContinuedEditReference>, StoreError> {
        self.check_key(key)?;
        let directory = self.root.child(&self.key, false)?;
        let history = self.read_history(&*directory, key, budget)?;
        if history.state
            == (StreamedAttemptState::Superseded {
                attempt_id: 0,
                attempts: 0,
            })
        {
            history
                .superseded_edit
                .ok_or(StoreError::CorruptEvidence)
                .map(Some)
        } else if history.superseded_edit.is_none() {
            Ok(None)
        } else {
            Err(StoreError::CorruptEvidence)
        }
    }
    fn read_history(
        &self,
        directory: &dyn Directory,
        key: &StreamedRecordKey,
        budget: &mut Budget,
    ) -> Result<History, StoreError> {
        let names = directory.entries(budget.remaining_entries())?;
        budget.entries(names.len())?;
        self.read_history_names(directory, key, &names, budget)
    }
    fn read_history_names(
        &self,
        directory: &dyn Directory,
        key: &StreamedRecordKey,
        names: &[String],
        budget: &mut Budget,
    ) -> Result<History, StoreError> {
        let mut event_names = Vec::new();
        for name in names {
            let (id, suffix) = split_record_name(name)?;
            if id != key.record_id() {
                continue;
            }
            if suffix == "dispatch.lock" {
                let lock = directory.open(name)?;
                if lock.len()? != 0 {
                    return Err(StoreError::CorruptEvidence);
                }
                lock.verify()?;
            } else if suffix.starts_with("event.") {
                let (sequence, stage) = event_suffix(suffix).ok_or(StoreError::CorruptEvidence)?;
                if stage {
                    return Err(StoreError::IncompleteEvidence);
                }
                event_names.push((sequence, name));
            }
        }
        if event_names.len() > MAX_STREAMED_HISTORY {
            return Err(StoreError::ScanLimit);
        }
        event_names.sort_by_key(|(seq, _)| *seq);
        let mut state = StreamedAttemptState::NotAttempted;
        #[cfg(windows)]
        let mut superseded_edit = None;
        let mut sequence = 0u64;
        let mut active_dispatch: Option<String> = None;
        let mut ordinal = 0u8;
        let mut closed_dispatches = std::collections::HashSet::new();
        for (seq, name) in event_names {
            if seq != sequence + 1 {
                return Err(StoreError::CorruptEvidence);
            }
            let bytes = read_metadata(directory, name, budget)?;
            if bytes.len() > EVENT_LIMIT {
                return Err(StoreError::CorruptEvidence);
            }
            let plain = Zeroizing::new(
                self.protector
                    .open(&event_aad(key, seq), &bytes)
                    .map_err(|_| StoreError::CorruptEvidence)?,
            );
            if plain.len() > EVENT_LIMIT {
                return Err(StoreError::CorruptEvidence);
            }
            let event: Event =
                serde_json::from_slice(&plain).map_err(|_| StoreError::CorruptEvidence)?;
            if event.version != 2
                || event.commitment != key.commitment
                || event.scope != *key.scope()
                || event.record_id != key.record_id()
                || event.generation != key.generation()
                || event.sequence != seq
                || !valid_id(&event.dispatch_id)
                || matches!(
                    state,
                    StreamedAttemptState::LocallyAcknowledged { .. }
                        | StreamedAttemptState::Superseded { .. }
                )
            {
                return Err(StoreError::CorruptEvidence);
            }
            match event.action {
                EventAction::Attempting { ordinal: next } => {
                    if matches!(state, StreamedAttemptState::VerifiedApplied { .. })
                        || event.attempt_id
                            != state
                                .attempt_id()
                                .checked_add(1)
                                .ok_or(StoreError::ScanLimit)?
                    {
                        return Err(StoreError::CorruptEvidence);
                    }
                    if closed_dispatches.contains(&event.dispatch_id) {
                        return Err(StoreError::CorruptEvidence);
                    }
                    let expected = if active_dispatch.as_deref() == Some(&event.dispatch_id) {
                        ordinal + 1
                    } else {
                        1
                    };
                    if next != expected || next > 2 {
                        return Err(StoreError::CorruptEvidence);
                    }
                    if active_dispatch.as_deref() != Some(&event.dispatch_id)
                        && let Some(old) = active_dispatch.take()
                    {
                        closed_dispatches.insert(old);
                    }
                    ordinal = next;
                    active_dispatch = Some(event.dispatch_id);
                    state = StreamedAttemptState::Uncertain {
                        attempt_id: event.attempt_id,
                    };
                }
                EventAction::Outcome { attempts, outcome } => {
                    if closed_dispatches.contains(&event.dispatch_id)
                        || event.attempt_id != state.attempt_id()
                        || attempts > 2
                        || (attempts != 0
                            && (active_dispatch.as_deref() != Some(&event.dispatch_id)
                                || attempts != ordinal))
                        || (attempts == 0 && active_dispatch.as_deref() == Some(&event.dispatch_id))
                        || (matches!(state, StreamedAttemptState::VerifiedApplied { .. })
                            && outcome != StreamedAttemptOutcome::VerifiedApplied)
                    {
                        return Err(StoreError::CorruptEvidence);
                    }
                    state = outcome_state(outcome, event.attempt_id, attempts);
                    if let Some(old) = active_dispatch.take() {
                        closed_dispatches.insert(old);
                    }
                    closed_dispatches.insert(event.dispatch_id);
                    ordinal = 0;
                }
                EventAction::LocalAcknowledged { attempts } => {
                    if state
                        != (StreamedAttemptState::VerifiedApplied {
                            attempt_id: event.attempt_id,
                            attempts,
                        })
                    {
                        return Err(StoreError::CorruptEvidence);
                    }
                    state = StreamedAttemptState::LocallyAcknowledged {
                        attempt_id: event.attempt_id,
                        attempts,
                    };
                }
                EventAction::Superseded { edit } => {
                    #[cfg(not(windows))]
                    {
                        let _ = edit;
                        return Err(StoreError::CorruptEvidence);
                    }
                    #[cfg(windows)]
                    {
                        if state != StreamedAttemptState::NotAttempted
                            || event.attempt_id != 0
                            || active_dispatch.is_some()
                            || !valid_id(&edit.record_id)
                            || edit.record_id == key.record_id()
                            || edit.generation == 0
                            || edit.manifest_commitment == [0; 32]
                        {
                            return Err(StoreError::CorruptEvidence);
                        }
                        superseded_edit = Some(edit);
                        state = StreamedAttemptState::Superseded {
                            attempt_id: 0,
                            attempts: 0,
                        };
                    }
                }
            }
            sequence = seq;
        }
        Ok(History {
            state,
            sequence,
            #[cfg(windows)]
            superseded_edit,
        })
    }
}

/// One record OS lock plus an invocation-local two-PUT bound. The reconciler
/// independently decides fresh versus explicitly reviewed recovery admission.
/// No state-global lock is held across remote/native work.
pub struct StreamedDispatchLease {
    store: Arc<SnapshotStore>,
    directory: Arc<dyn Directory>,
    key: StreamedRecordKey,
    _record_lock: Box<dyn PinnedRead>,
    dispatch_id: String,
    puts: u8,
    finished: bool,
    poisoned: bool,
}
impl StreamedDispatchLease {
    pub fn current_state(&self) -> Result<StreamedAttemptState, StoreError> {
        self.store.check_key(&self.key)?;
        Ok(self
            .store
            .read_history(
                &*self.directory,
                &self.key,
                &mut Budget::new(self.store.policy),
            )?
            .state)
    }
    #[cfg(all(test, unix))]
    pub(super) fn fixture_acknowledge_key(&mut self) -> Result<(), StoreError> {
        self.acknowledge_local(StreamedLocalCompletion {
            key: self.key.clone(),
        })
    }
    #[cfg(windows)]
    pub(crate) fn acknowledge_create(
        &mut self,
        completion: &crate::native::NativeFileCreateCompletion<'_>,
    ) -> Result<CreateSnapshotAcknowledged, StoreError> {
        let (store, key) = completion.snapshot();
        if !completion.binding_valid()
            || !Arc::ptr_eq(store, &self.store)
            || key != &self.key
            || self.current_state()? != StreamedAttemptState::NotAttempted
        {
            return Err(StoreError::Invalid);
        }
        // This ledger made zero PUTs. The file journal owns the actual one PUT.
        self.finish_outcome(0, 0, StreamedAttemptOutcome::VerifiedApplied)?;
        self.acknowledge_local(StreamedLocalCompletion { key: key.clone() })?;
        if self.current_state()?
            != (StreamedAttemptState::LocallyAcknowledged {
                attempt_id: 0,
                attempts: 0,
            })
        {
            return Err(StoreError::IncompleteEvidence);
        }
        Ok(CreateSnapshotAcknowledged {
            store: self.store.clone(),
            key: key.clone(),
        })
    }
    /// Terminalize the original create snapshot without claiming it is the
    /// current file. Only the namespace continuation path may call this after
    /// live native completion and a separately acknowledged edit are proven.
    #[cfg(windows)]
    pub(crate) fn supersede_create(
        &mut self,
        edit: &crate::namespace_intent::ContinuedEditReference,
    ) -> Result<(), StoreError> {
        if self.finished
            || self.poisoned
            || self.current_state()? != StreamedAttemptState::NotAttempted
            || edit.record_id == self.key.record_id()
            || !valid_id(&edit.record_id)
            || edit.generation == 0
            || edit.manifest_commitment == [0; 32]
        {
            return Err(StoreError::Invalid);
        }
        let history = self.history()?;
        self.append(
            history.sequence,
            0,
            EventAction::Superseded { edit: edit.clone() },
        )?;
        self.finished = true;
        Ok(())
    }
    pub fn begin_attempt(&mut self) -> Result<u64, StoreError> {
        if self.finished || self.poisoned || self.puts >= 2 {
            return Err(StoreError::Invalid);
        }
        let history = self.history()?;
        // Keep one terminal receipt slot available before admitting each PUT.
        if history
            .sequence
            .checked_add(2)
            .is_none_or(|n| n > MAX_STREAMED_HISTORY as u64)
        {
            return Err(StoreError::ScanLimit);
        }
        if matches!(
            history.state,
            StreamedAttemptState::VerifiedApplied { .. }
                | StreamedAttemptState::LocallyAcknowledged { .. }
                | StreamedAttemptState::Superseded { .. }
        ) {
            return Err(StoreError::Invalid);
        }
        let attempt = history
            .state
            .attempt_id()
            .checked_add(1)
            .ok_or(StoreError::ScanLimit)?;
        self.append(
            history.sequence,
            attempt,
            EventAction::Attempting {
                ordinal: self.puts + 1,
            },
        )?;
        self.puts += 1;
        Ok(attempt)
    }
    pub fn finish_outcome(
        &mut self,
        attempt_id: u64,
        attempts: u8,
        outcome: StreamedAttemptOutcome,
    ) -> Result<(), StoreError> {
        if self.finished || self.poisoned || attempts != self.puts || attempts > 2 {
            return Err(StoreError::Invalid);
        }
        let history = self.history()?;
        if history.state.attempt_id() != attempt_id
            || matches!(
                history.state,
                StreamedAttemptState::LocallyAcknowledged { .. }
                    | StreamedAttemptState::Superseded { .. }
            )
            || (matches!(history.state, StreamedAttemptState::VerifiedApplied { .. })
                && outcome != StreamedAttemptOutcome::VerifiedApplied)
        {
            return Err(StoreError::Invalid);
        }
        self.append(
            history.sequence,
            attempt_id,
            EventAction::Outcome { attempts, outcome },
        )?;
        self.finished = true;
        Ok(())
    }
    fn history(&self) -> Result<History, StoreError> {
        self.store.check_key(&self.key)?;
        self.store.read_history(
            &*self.directory,
            &self.key,
            &mut Budget::new(self.store.policy),
        )
    }
    fn append(
        &mut self,
        previous: u64,
        attempt_id: u64,
        action: EventAction,
    ) -> Result<(), StoreError> {
        if previous >= MAX_STREAMED_HISTORY as u64 {
            return Err(StoreError::ScanLimit);
        }
        let sequence = previous + 1;
        let event = Event {
            version: 2,
            commitment: self.key.commitment,
            scope: self.key.scope().clone(),
            record_id: self.key.record_id().into(),
            generation: self.key.generation(),
            sequence,
            dispatch_id: self.dispatch_id.clone(),
            attempt_id,
            action,
        };
        let plain = Zeroizing::new(serde_json::to_vec(&event).map_err(|_| StoreError::Invalid)?);
        if plain.len() > EVENT_LIMIT {
            return Err(StoreError::Quota);
        }
        let sealed = self
            .store
            .protector
            .seal(&event_aad(&self.key, sequence), &plain)
            .map_err(|_| StoreError::CorruptEvidence)?;
        if sealed.is_empty() || sealed.len() > EVENT_LIMIT {
            return Err(StoreError::Quota);
        }
        // Record lock is already owned. This short state lock covers inventory
        // and publication only; caller cannot hold it through HTTP.
        let _state_lease = self.store.acquire_lock()?;
        self.store.check_key(&self.key)?;
        let inventory = self.store.inventory()?;
        if inventory
            .bytes
            .checked_add(sealed.len() as u64)
            .is_none_or(|n| n > self.store.policy.max_state_bytes)
        {
            return Err(StoreError::Quota);
        }
        if inventory
            .entries
            .checked_add(2)
            .is_none_or(|n| n > self.store.policy.max_entries)
        {
            return Err(StoreError::ScanLimit);
        }
        let name = format!("{}.event.{sequence:020}", self.key.record_id());
        let result = persist_metadata(&*self.directory, &name, &sealed);
        if result.is_err() {
            self.poisoned = true;
            return Err(StoreError::PublicationUncertain);
        }
        Ok(())
    }
    /// Intentionally unavailable outside trusted crate/native integration.
    pub(crate) fn acknowledge_native(
        &mut self,
        completion: &crate::CompletedLocalEdit,
    ) -> Result<(), StoreError> {
        self.acknowledge_local(StreamedLocalCompletion::from_native_completion(completion)?)
    }

    pub(crate) fn acknowledge_local(
        &mut self,
        completion: StreamedLocalCompletion,
    ) -> Result<(), StoreError> {
        if self.poisoned || completion.key != self.key {
            return Err(StoreError::Invalid);
        }
        let history = self.history()?;
        if let StreamedAttemptState::LocallyAcknowledged { .. } = history.state {
            return Ok(());
        }
        let StreamedAttemptState::VerifiedApplied {
            attempt_id,
            attempts,
        } = history.state
        else {
            return Err(StoreError::Invalid);
        };
        self.append(
            history.sequence,
            attempt_id,
            EventAction::LocalAcknowledged { attempts },
        )
    }
}
#[cfg(windows)]
pub(crate) struct CreateSnapshotAcknowledged {
    store: Arc<SnapshotStore>,
    key: StreamedRecordKey,
}
#[cfg(windows)]
impl CreateSnapshotAcknowledged {
    pub(crate) fn matches(
        &self,
        completion: &crate::native::NativeFileCreateCompletion<'_>,
    ) -> bool {
        let (store, key) = completion.snapshot();
        Arc::ptr_eq(store, &self.store) && key == &self.key
    }
}
pub(crate) struct StreamedLocalCompletion {
    key: StreamedRecordKey,
}
impl StreamedLocalCompletion {
    fn from_native_completion(completion: &crate::CompletedLocalEdit) -> Result<Self, StoreError> {
        let key = completion
            .streamed_key()
            .ok_or(StoreError::Invalid)?
            .clone();
        Ok(Self { key })
    }
}
fn outcome_state(
    outcome: StreamedAttemptOutcome,
    attempt_id: u64,
    attempts: u8,
) -> StreamedAttemptState {
    match outcome {
        StreamedAttemptOutcome::VerifiedApplied => StreamedAttemptState::VerifiedApplied {
            attempt_id,
            attempts,
        },
        StreamedAttemptOutcome::Conflict => StreamedAttemptState::Conflict {
            attempt_id,
            attempts,
        },
        StreamedAttemptOutcome::Ambiguous => StreamedAttemptState::Ambiguous {
            attempt_id,
            attempts,
        },
        StreamedAttemptOutcome::Deferred => StreamedAttemptState::Deferred {
            attempt_id,
            attempts,
        },
    }
}
fn event_aad(key: &StreamedRecordKey, sequence: u64) -> Vec<u8> {
    [EVENT_DOMAIN, &key.commitment, &sequence.to_le_bytes()].concat()
}
/// Accept exactly a fixed 20-digit nonzero sequence, with optional stage suffix.
pub(super) fn event_suffix(suffix: &str) -> Option<(u64, bool)> {
    let suffix = suffix.strip_prefix("event.")?;
    let (digits, stage) = suffix
        .strip_suffix(".stage")
        .map_or((suffix, false), |s| (s, true));
    if digits.len() != 20 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let sequence = digits.parse::<u64>().ok()?;
    (sequence != 0 && sequence <= MAX_STREAMED_HISTORY as u64).then_some((sequence, stage))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::LocalFileIdentity;
    use std::{fs, io::Cursor};
    fn ready() -> (tempfile::TempDir, Arc<SnapshotStore>, StreamedRecordKey) {
        let policy = StorePolicy {
            max_content_bytes: 64 * 1024 * 1024,
            max_state_bytes: 256 * 1024 * 1024,
            max_entries: 2048,
            max_metadata_bytes_per_scan: 4 * 1024 * 1024,
        };
        let (temp, store) = super::super::synthetic_test_store(policy);
        let binding = SnapshotBinding {
            record_id: String::new(),
            scope: store.scope.clone(),
            generation: 3,
            local_file: crate::LocalFileIdentity {
                volume_serial: 1,
                file_index: 4,
            },
            relative_path: "doc.bin".into(),
            remote: None,
            content_len: 10,
        };
        let capture = store.try_begin_capture(binding).unwrap();
        let id = capture.binding().record_id.clone();
        capture
            .capture(&mut Cursor::new(vec![7; 10]), &mut || false)
            .unwrap()
            .verify_and_commit(&mut || false)
            .unwrap();
        let key = store.record_key(&id).unwrap();
        (temp, store, key)
    }
    #[test]
    fn exact_key_record_lock_and_two_put_invocation_bound_survive_restart() {
        let (_temp, store, key) = ready();
        let mut lease = store.acquire_dispatch(&key).unwrap();
        assert_eq!(
            lease.current_state().unwrap(),
            StreamedAttemptState::NotAttempted
        );
        assert_eq!(store.acquire_dispatch(&key).err(), Some(StoreError::Busy));
        assert_eq!(lease.begin_attempt().unwrap(), 1);
        assert_eq!(
            store.discover_records().unwrap()[0].state,
            StreamedAttemptState::Uncertain { attempt_id: 1 }
        );
        assert_eq!(lease.begin_attempt().unwrap(), 2);
        assert_eq!(lease.begin_attempt().err(), Some(StoreError::Invalid));
        assert_eq!(
            lease
                .finish_outcome(2, 1, StreamedAttemptOutcome::Deferred)
                .err(),
            Some(StoreError::Invalid)
        );
        lease
            .finish_outcome(2, 2, StreamedAttemptOutcome::Deferred)
            .unwrap();
        assert!(lease.begin_attempt().is_err());
        drop(lease);
        let restarted = SnapshotStore::from_directory(
            Arc::clone(&store.root),
            store.scope.clone(),
            Arc::clone(&store.protector),
            store.policy,
        )
        .unwrap();
        let mut retry = restarted.acquire_dispatch(&key).unwrap();
        assert_eq!(
            retry.current_state().unwrap(),
            StreamedAttemptState::Deferred {
                attempt_id: 2,
                attempts: 2
            }
        );
        assert_eq!(retry.begin_attempt().unwrap(), 3);
        drop(retry);
        let recovered = restarted.acquire_dispatch(&key).unwrap();
        assert_eq!(
            recovered.current_state().unwrap(),
            StreamedAttemptState::Uncertain { attempt_id: 3 }
        );
    }
    #[test]
    fn verified_remote_evidence_is_not_ack_and_cannot_authorize_another_put() {
        let (_temp, store, key) = ready();
        let mut lease = store.acquire_dispatch(&key).unwrap();
        lease.begin_attempt().unwrap();
        lease
            .finish_outcome(1, 1, StreamedAttemptOutcome::VerifiedApplied)
            .unwrap();
        assert_eq!(
            lease.current_state().unwrap(),
            StreamedAttemptState::VerifiedApplied {
                attempt_id: 1,
                attempts: 1
            }
        );
        drop(lease);
        let mut review = store.acquire_dispatch(&key).unwrap();
        assert!(review.begin_attempt().is_err());
        review
            .finish_outcome(1, 0, StreamedAttemptOutcome::VerifiedApplied)
            .unwrap();
        // Only this in-module synthetic test can mint the currently unconstructible
        // native completion token; no production minting path exists.
        review
            .acknowledge_local(StreamedLocalCompletion { key: key.clone() })
            .unwrap();
        assert_eq!(
            review.current_state().unwrap(),
            StreamedAttemptState::LocallyAcknowledged {
                attempt_id: 1,
                attempts: 0
            }
        );
        review
            .acknowledge_local(StreamedLocalCompletion { key })
            .unwrap();
        assert!(review.begin_attempt().is_err());
    }
    #[test]
    fn changed_generation_scope_manifest_commitment_and_local_identity_keys_are_refused() {
        let (_temp, store, key) = ready();
        for variant in 0..4 {
            let mut bad = key.clone();
            match variant {
                0 => bad.binding.generation += 1,
                1 => bad.binding.scope.account_subject = "foreign".into(),
                2 => bad.commitment[0] ^= 1,
                _ => {
                    bad.binding.local_file = LocalFileIdentity {
                        volume_serial: 1,
                        file_index: 99,
                    }
                }
            }
            assert!(store.acquire_dispatch(&bad).is_err());
            assert!(store.open_verified_key(&bad, &mut || false).is_err());
        }
        assert_eq!(
            store.discover_records().unwrap()[0].state,
            StreamedAttemptState::NotAttempted
        );
    }
    #[test]
    fn torn_foreign_reordered_and_sequence_gap_events_fail_closed_without_body_read() {
        for scenario in 0..4 {
            let (temp, store, key) = ready();
            let mut lease = store.acquire_dispatch(&key).unwrap();
            lease.begin_attempt().unwrap();
            drop(lease);
            let path =
                temp.path()
                    .join(&store.key)
                    .join(format!("{}.event.{:020}", key.record_id(), 1));
            match scenario {
                0 => {
                    fs::write(&path, b"torn").unwrap();
                }
                1 => {
                    fs::rename(
                        &path,
                        path.with_file_name(format!("{}.event.{:020}", key.record_id(), 2)),
                    )
                    .unwrap();
                }
                2 => {
                    fs::write(
                        path.with_file_name(format!("{}.event.{:020}.stage", key.record_id(), 2)),
                        b"partial",
                    )
                    .unwrap();
                }
                _ => {
                    let mut bytes = fs::read(&path).unwrap();
                    bytes[0] ^= 1;
                    fs::write(&path, bytes).unwrap();
                }
            }
            assert!(store.discover_records().is_err());
            assert!(store.discover_metadata().is_err());
            assert!(store.acquire_dispatch(&key).is_err());
        }
    }
    #[test]
    fn small_event_history_limit_and_quota_never_grant_attempt_on_error() {
        let (_temp, store, key) = ready();
        for _ in 0..MAX_STREAMED_HISTORY {
            let mut lease = store.acquire_dispatch(&key).unwrap();
            lease
                .finish_outcome(0, 0, StreamedAttemptOutcome::Deferred)
                .unwrap();
        }
        let mut full = store.acquire_dispatch(&key).unwrap();
        assert_eq!(full.begin_attempt().err(), Some(StoreError::ScanLimit));
        drop(full);
        let (_temp2, store2, key2) = ready();
        let mut policy = store2.policy;
        policy.max_state_bytes = store2.inventory().unwrap().bytes;
        let constrained = SnapshotStore::from_directory(
            Arc::clone(&store2.root),
            store2.scope.clone(),
            Arc::clone(&store2.protector),
            policy,
        )
        .unwrap();
        let mut lease = constrained.acquire_dispatch(&key2).unwrap();
        assert_eq!(lease.begin_attempt().err(), Some(StoreError::Quota));
        assert_eq!(
            lease.current_state().unwrap(),
            StreamedAttemptState::NotAttempted
        );
    }
    #[test]
    fn protected_event_from_another_authenticated_record_is_not_adopted() {
        let (temp, store, first) = ready();
        let mut lease = store.acquire_dispatch(&first).unwrap();
        lease.begin_attempt().unwrap();
        drop(lease);
        let mut second_binding = first.binding.clone();
        second_binding.generation += 1;
        let capture = store.try_begin_capture(second_binding).unwrap();
        let second_id = capture.binding().record_id.clone();
        capture
            .capture(&mut Cursor::new(vec![7; 10]), &mut || false)
            .unwrap()
            .verify_and_commit(&mut || false)
            .unwrap();
        let second = store.record_key(&second_id).unwrap();
        let directory = temp.path().join(&store.key);
        let original = directory.join(format!("{}.event.{:020}", first.record_id(), 1));
        let copied = directory.join(format!("{}.event.{:020}", second.record_id(), 1));
        fs::copy(original, copied).unwrap();
        assert!(store.acquire_dispatch(&second).is_err());
        assert!(store.discover_records().is_err());
    }

    #[test]
    fn zero_put_terminal_and_ack_transitions_are_explicit_and_metadata_only() {
        let (_temp, store, key) = ready();
        let mut initial = store.acquire_dispatch(&key).unwrap();
        assert_eq!(
            initial
                .acknowledge_local(StreamedLocalCompletion { key: key.clone() })
                .err(),
            Some(StoreError::Invalid)
        );
        initial
            .finish_outcome(0, 0, StreamedAttemptOutcome::Deferred)
            .unwrap();
        drop(initial);
        let mut review = store.acquire_dispatch(&key).unwrap();
        review
            .finish_outcome(0, 0, StreamedAttemptOutcome::VerifiedApplied)
            .unwrap();
        assert_eq!(
            review.current_state().unwrap(),
            StreamedAttemptState::VerifiedApplied {
                attempt_id: 0,
                attempts: 0
            }
        );
        assert!(review.begin_attempt().is_err());
    }
}

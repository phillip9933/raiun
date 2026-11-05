//! Preserve-only ordinary v2 snapshots. This store grants local storage
//! verification only, never native capture, upload, clean-state or deletion
//! authority. The Windows adapter adds known legacy recovery metadata usage
//! to the conservative v2 accounting. Every legacy producer must ALSO use the
//! same persistent admission lock before production activation; an inventory
//! hook alone cannot coordinate an unmodified writer.
use crate::streamed_snapshot::{
    AuthenticatedSnapshotReader, EncodedSnapshot, LocalSnapshotCheck, MAX_SNAPSHOT_MANIFEST_BYTES,
    MAX_SNAPSHOT_SEALED_CHUNK_BYTES, SNAPSHOT_CHUNK_BYTES, SnapshotBinding, SnapshotError,
    SnapshotLimits, SnapshotManifest, encode_snapshot, open_manifest, verify_container,
};
use crate::{EditJournalScope, EditRecordProtector};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Seek, Write},
    sync::Arc,
};
use zeroize::Zeroizing;

#[path = "namespace_file_delete_store.rs"]
pub mod namespace_file_delete_store;

#[path = "namespace_file_store.rs"]
pub mod namespace_file_store;

#[path = "namespace_rename_store.rs"]
pub mod namespace_rename_store;

#[path = "namespace_store.rs"]
pub mod namespace_store;

#[path = "streamed_events.rs"]
mod events;
#[path = "streamed_retention.rs"]
mod retention;
#[cfg(windows)]
pub(crate) use events::CreateSnapshotAcknowledged;
#[cfg(windows)]
mod windows;
pub use events::{
    MAX_STREAMED_HISTORY, StreamedAttemptOutcome, StreamedAttemptState, StreamedDispatchLease,
    StreamedRecordKey, StreamedRecoveryMetadata,
};
pub use retention::{RetainedRecordObservation, RetainedRecordsInspection};
#[cfg(windows)]
pub(crate) const V2_STORE_ROOT: &str = "cloud-files-edit-journal-v2";
pub(crate) const V2_QUOTA_LOCK: &str = "quota.lock";
const META_LIMIT: usize = MAX_SNAPSHOT_MANIFEST_BYTES;
const SCOPE_DOMAIN: &[u8] = b"raiun/snapshot-store/scope/v2\0";
const RESERVE_DOMAIN: &[u8] = b"raiun/snapshot-store/reservation/v2\0";

/// Explicit logical ciphertext accounting, not physical disk reservation.
/// Retained reservation maxima AND actual bytes are charged conservatively.
#[derive(Clone, Copy, Debug)]
pub struct StorePolicy {
    pub max_content_bytes: u64,
    pub max_state_bytes: u64,
    pub max_entries: usize,
    pub max_metadata_bytes_per_scan: u64,
}
impl StorePolicy {
    fn codec(self) -> Result<SnapshotLimits, StoreError> {
        SnapshotLimits::new(
            self.max_content_bytes,
            self.max_state_bytes,
            self.max_content_bytes / SNAPSHOT_CHUNK_BYTES as u64
                + u64::from(self.max_content_bytes % SNAPSHOT_CHUNK_BYTES as u64 != 0),
        )
        .map_err(Into::into)
    }
    pub(crate) fn validate(self) -> Result<(), StoreError> {
        if self.max_entries < 4 || self.max_metadata_bytes_per_scan < META_LIMIT as u64 {
            return Err(StoreError::Invalid);
        }
        self.codec()?;
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    Io,
    Busy,
    Invalid,
    Quota,
    ScanLimit,
    IncompleteEvidence,
    CorruptEvidence,
    PublicationUncertain,
    Snapshot(SnapshotError),
}
impl From<SnapshotError> for StoreError {
    fn from(value: SnapshotError) -> Self {
        Self::Snapshot(value)
    }
}
impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "local v2 snapshot store: {self:?}")
    }
}
impl std::error::Error for StoreError {}
fn io_error(_: io::Error) -> StoreError {
    StoreError::Io
}

/// Only for a failed nonblocking OS lock operation. fs2 documents its native
/// contention error separately; on Windows its raw code need not be WouldBlock.
#[cfg(windows)]
pub(crate) fn lock_error(error: io::Error) -> StoreError {
    if error.kind() == io::ErrorKind::WouldBlock
        || error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
    {
        StoreError::Busy
    } else {
        StoreError::Io
    }
}

/// Map only a Windows sharing violation from opening the persistent quota
/// file to contention. This defers admission; it grants no recovery authority.
#[cfg(windows)]
pub(crate) fn quota_lock_open_error(error: io::Error) -> StoreError {
    if error.raw_os_error() == Some(32) {
        StoreError::Busy
    } else {
        io_error(error)
    }
}

#[cfg(all(windows, test))]
#[test]
fn native_lock_contention_is_busy_but_other_lock_errors_are_not() {
    assert_eq!(lock_error(fs2::lock_contended_error()), StoreError::Busy);
    assert_eq!(
        lock_error(io::Error::from(io::ErrorKind::WouldBlock)),
        StoreError::Busy
    );
    assert_eq!(
        lock_error(io::Error::from(io::ErrorKind::PermissionDenied)),
        StoreError::Io
    );
    assert_eq!(
        lock_error(io::Error::from(io::ErrorKind::Other)),
        StoreError::Io
    );
}

// Private, injected storage boundary. Only the Windows implementation is a
// production adapter. Test filesystem handles do not assert immutable parity.
#[derive(Clone, Copy, Eq, PartialEq)]
struct Identity {
    volume: u64,
    file: u64,
}
trait PinnedRead: Read + Seek + Send {
    fn identity(&self) -> Identity;
    fn len(&self) -> Result<u64, StoreError>;
    fn verify(&self) -> Result<(), StoreError>;
    fn lock_exclusive(&mut self) -> Result<(), StoreError>;
}
trait StageWrite: Write {
    fn sync(&self) -> Result<(), StoreError>;
}
trait Directory: Send + Sync {
    fn verify(&self) -> Result<(), StoreError>;
    /// Metadata-only accounting; default is for injected synthetic storage.
    fn external_recovery_usage(&self, _policy: StorePolicy) -> Result<(u64, usize), StoreError> {
        Ok((0, 0))
    }
    fn entries(&self, limit: usize) -> Result<Vec<String>, StoreError>;
    fn child(&self, name: &str, create: bool) -> Result<Arc<dyn Directory>, StoreError>;
    fn create(&self, name: &str) -> Result<(Box<dyn StageWrite>, Identity), StoreError>;
    fn open(&self, name: &str) -> Result<Box<dyn PinnedRead>, StoreError>;
    /// Open only the persistent admission lock. Injected stores retain the
    /// previous generic-open behavior unless they provide a native adapter.
    fn open_quota_lock(&self) -> Result<Box<dyn PinnedRead>, StoreError> {
        self.open(V2_QUOTA_LOCK)
    }
    fn publish(&self, stage: &str, final_name: &str, identity: Identity) -> Result<(), StoreError>;
}

/// Owns the admitted state's entire v2 root. It cannot open arbitrary paths.
pub struct SnapshotStore {
    root: Arc<dyn Directory>,
    scope: EditJournalScope,
    key: String,
    protector: Arc<dyn EditRecordProtector>,
    policy: StorePolicy,
}
impl SnapshotStore {
    #[cfg(windows)]
    pub fn create_or_open(
        admitted_state: Arc<raiun_control_windows::PrivateDirectory>,
        scope: EditJournalScope,
        protector: Arc<dyn EditRecordProtector>,
        policy: StorePolicy,
    ) -> Result<Arc<Self>, StoreError> {
        Self::create_or_open_admitted(
            crate::recovery_state::RecoveryStateRoot::modern(admitted_state),
            scope,
            protector,
            policy,
        )
    }
    #[cfg(windows)]
    pub(crate) fn create_or_open_admitted(
        admitted_state: Arc<crate::recovery_state::RecoveryStateRoot>,
        scope: EditJournalScope,
        protector: Arc<dyn EditRecordProtector>,
        policy: StorePolicy,
    ) -> Result<Arc<Self>, StoreError> {
        Self::from_directory(
            windows::root(admitted_state, V2_STORE_ROOT, true)?,
            scope,
            protector,
            policy,
        )
    }
    #[cfg(windows)]
    pub fn open_existing(
        admitted_state: Arc<raiun_control_windows::PrivateDirectory>,
        scope: EditJournalScope,
        protector: Arc<dyn EditRecordProtector>,
        policy: StorePolicy,
    ) -> Result<Arc<Self>, StoreError> {
        Self::open_existing_admitted(
            crate::recovery_state::RecoveryStateRoot::modern(admitted_state),
            scope,
            protector,
            policy,
        )
    }
    #[cfg(windows)]
    pub(crate) fn open_existing_admitted(
        admitted_state: Arc<crate::recovery_state::RecoveryStateRoot>,
        scope: EditJournalScope,
        protector: Arc<dyn EditRecordProtector>,
        policy: StorePolicy,
    ) -> Result<Arc<Self>, StoreError> {
        Self::from_directory(
            windows::root(admitted_state, V2_STORE_ROOT, false)?,
            scope,
            protector,
            policy,
        )
    }
    /// Read-only authenticated v2 scope catalogs. No selected/dummy scope,
    /// body reads, directory creation or recovery/dispatch authority.
    #[cfg(windows)]
    pub fn discover_state_scopes(
        admitted_state: Arc<raiun_control_windows::PrivateDirectory>,
        protector: Arc<dyn EditRecordProtector>,
        policy: StorePolicy,
    ) -> Result<Vec<EditJournalScope>, StoreError> {
        Self::discover_state_scopes_bounded(
            crate::recovery_state::RecoveryStateRoot::modern(admitted_state),
            protector,
            policy,
            &mut DiscoveryBudget::new(policy),
        )
    }
    /// Share this budget across global catalogs and every selected scope.
    #[cfg(windows)]
    pub(crate) fn discover_state_scopes_bounded(
        admitted_state: Arc<crate::recovery_state::RecoveryStateRoot>,
        protector: Arc<dyn EditRecordProtector>,
        policy: StorePolicy,
        budget: &mut DiscoveryBudget,
    ) -> Result<Vec<EditJournalScope>, StoreError> {
        policy.validate()?;
        let Some(root) = windows::existing_root(admitted_state, V2_STORE_ROOT)? else {
            return Ok(Vec::new());
        };
        discover_scope_catalogs_bounded(&*root, &*protector, policy, budget)
    }
    /// Metadata-only namespace history for an exact admitted provider/root.
    /// Missing state stays absent; this cannot create storage or grant dispatch.
    #[cfg(windows)]
    pub(crate) fn namespace_history_summary_existing(
        admitted_state: Arc<crate::recovery_state::RecoveryStateRoot>,
        protector: Arc<dyn EditRecordProtector>,
        policy: StorePolicy,
        provider: &crate::ProviderScope,
        root: crate::ConfiguredRootIdentity,
    ) -> Result<namespace_rename_store::NamespaceHistorySummary, StoreError> {
        policy.validate()?;
        namespace_rename_store::history_summary_existing(
            windows::existing_root(admitted_state, V2_STORE_ROOT)?,
            protector,
            policy,
            provider,
            root,
        )
    }

    /// Explicit support inspection only; adds bounded static pending phases.
    /// Ordinary guards keep using the lighter summary without these reads.
    #[cfg(windows)]
    pub(crate) fn namespace_history_diagnostic_existing(
        admitted_state: Arc<crate::recovery_state::RecoveryStateRoot>,
        protector: Arc<dyn EditRecordProtector>,
        policy: StorePolicy,
        provider: &crate::ProviderScope,
        root: crate::ConfiguredRootIdentity,
    ) -> Result<namespace_rename_store::NamespaceHistorySummary, StoreError> {
        policy.validate()?;
        namespace_rename_store::history_summary_diagnostic_existing(
            windows::existing_root(admitted_state, V2_STORE_ROOT)?,
            protector,
            policy,
            provider,
            root,
        )
    }

    /// Point-in-time content health for one authenticated provider/root. The
    /// existing v2 quota lease spans global catalog validation, v2 metadata
    /// discovery and the caller's bounded legacy scan. Namespace record bodies
    /// are not opened or counted as content. `scan_legacy` receives the same
    /// remaining work budget and must not mutate state. Its read policy is
    /// selected explicitly by the caller: strict metadata-only classification
    /// or the separately named bounded full-authentication legacy compatibility
    /// query. There is no silent fallback between those policies. This read
    /// does not replace the native callback admission fence required before
    /// callers later perform remote work.
    #[cfg(windows)]
    pub(crate) fn content_history_pending_existing(
        admitted_state: Arc<crate::recovery_state::RecoveryStateRoot>,
        protector: Arc<dyn EditRecordProtector>,
        mut policy: StorePolicy,
        provider: &crate::ProviderScope,
        physical_root: crate::ConfiguredRootIdentity,
        scan_legacy: impl FnOnce(&mut DiscoveryBudget) -> Result<bool, StoreError>,
    ) -> Result<bool, StoreError> {
        policy.validate()?;
        if physical_root.file_index == 0
            || [
                provider.profile_id(),
                provider.account_id(),
                provider.server_origin(),
            ]
            .iter()
            .any(|value| {
                value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control)
            })
            || raiun_opencloud::validate_captured_server_origin(provider.server_origin()).is_err()
        {
            return Err(StoreError::Invalid);
        }
        policy.max_entries = policy.max_entries.min(20_000);
        policy.max_metadata_bytes_per_scan =
            policy.max_metadata_bytes_per_scan.min(64 * 1024 * 1024);
        let mut budget = DiscoveryBudget::new(policy);
        let Some(root) = windows::existing_root(Arc::clone(&admitted_state), V2_STORE_ROOT)? else {
            // There is no v2 tree/quota to lock. The legacy reader remains
            // existing-only and can report evidence or refuse; it cannot
            // create a missing v2 lock just to make the scan appear healthy.
            let legacy_pending = scan_legacy(&mut budget)?;
            admitted_state.verify_path().map_err(io_error)?;
            if windows::existing_root(Arc::clone(&admitted_state), V2_STORE_ROOT)?.is_some() {
                return Err(StoreError::IncompleteEvidence);
            }
            return Ok(legacy_pending);
        };

        root.verify()?;
        let names = root.entries(budget.remaining_entries())?;
        budget.entries(names.len())?;
        if !names.iter().any(|name| name == V2_QUOTA_LOCK) {
            return Err(StoreError::IncompleteEvidence);
        }
        let mut lock = root.open_quota_lock()?;
        if lock.len()? != 0 {
            return Err(StoreError::CorruptEvidence);
        }
        lock.lock_exclusive()?;
        lock.verify()?;
        root.verify()?;
        admitted_state.verify_path().map_err(io_error)?;

        // Re-enumerate after acquiring the existing lock. The same budget
        // covers these names, every authenticated format, record metadata,
        // and the legacy scanner callback.
        let names = root.entries(budget.remaining_entries())?;
        budget.entries(names.len())?;
        let catalogs = validate_root_catalog_scope_union(&*root, &*protector, &names, &mut budget)?;
        let mut pending = false;
        let mut record_count = 0usize;
        let mut seen = std::collections::HashSet::new();
        for scope in catalogs.snapshots.into_iter().filter(|scope| {
            scope.profile_id == provider.profile_id()
                && scope.server_origin == provider.server_origin()
                && scope.account_subject == provider.account_id()
                && scope.root_volume_serial == physical_root.volume_serial
                && scope.root_file_index == physical_root.file_index
        }) {
            // Reuse the already pinned root handle; no second root open and no
            // account/root guessed from a record body.
            let store = SnapshotStore::from_directory(
                Arc::clone(&root),
                scope,
                Arc::clone(&protector),
                policy,
            )?;
            for record in store.discover_records_bounded(&mut budget)? {
                record_count = record_count.checked_add(1).ok_or(StoreError::ScanLimit)?;
                if record_count > 2_000
                    || !seen.insert((record.key.record_id().to_owned(), record.key.generation()))
                {
                    return Err(StoreError::ScanLimit);
                }
                if !matches!(
                    record.state,
                    StreamedAttemptState::LocallyAcknowledged { .. }
                        | StreamedAttemptState::Superseded { .. }
                ) {
                    pending = true;
                }
            }
        }

        let legacy_pending = scan_legacy(&mut budget)?;
        root.verify()?;
        lock.verify()?;
        admitted_state.verify_path().map_err(io_error)?;
        Ok(pending || legacy_pending)
    }

    /// Joint fresh-create custody health, never historical replay or native
    /// completion proof. The existing quota lease and one allowance span both
    /// namespace and content history plus the caller's existing legacy policy.
    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn fresh_create_space_pending_existing(
        admitted_state: Arc<crate::recovery_state::RecoveryStateRoot>,
        protector: Arc<dyn EditRecordProtector>,
        mut policy: StorePolicy,
        provider: &crate::ProviderScope,
        physical_root: crate::ConfiguredRootIdentity,
        candidate_scope: &EditJournalScope,
        namespace_configured: bool,
        trace: Option<&crate::creation_preparation::Trace>,
        scan_legacy: impl FnOnce(&mut DiscoveryBudget) -> Result<bool, StoreError>,
    ) -> Result<bool, StoreError> {
        (|| {
            policy.validate()?;
            validate_scope(candidate_scope)?;
            if physical_root.file_index == 0
                || candidate_scope.profile_id != provider.profile_id()
                || candidate_scope.account_subject != provider.account_id()
                || candidate_scope.server_origin != provider.server_origin()
                || candidate_scope.root_volume_serial != physical_root.volume_serial
                || candidate_scope.root_file_index != physical_root.file_index
                || raiun_opencloud::validate_captured_server_origin(provider.server_origin())
                    .is_err()
            {
                return Err(StoreError::Invalid);
            }
            policy.max_entries = policy.max_entries.min(20_000);
            policy.max_metadata_bytes_per_scan =
                policy.max_metadata_bytes_per_scan.min(64 * 1024 * 1024);
            let mut budget = DiscoveryBudget::new(policy);
            let Some(root) = windows::existing_root(Arc::clone(&admitted_state), V2_STORE_ROOT)?
            else {
                if let Some(trace) = trace {
                    trace.enter(crate::creation_preparation::Stage::LegacyScan);
                }
                let pending = scan_legacy(&mut budget)?;
                if let Some(trace) = trace {
                    trace.enter(crate::creation_preparation::Stage::RecoveryFinal);
                }
                admitted_state.verify_path().map_err(io_error)?;
                if windows::existing_root(Arc::clone(&admitted_state), V2_STORE_ROOT)?.is_some() {
                    return Err(StoreError::IncompleteEvidence);
                }
                if pending && let Some(trace) = trace {
                    trace.enter(crate::creation_preparation::Stage::LegacyPending);
                    trace.category(crate::creation_preparation::Category::Pending);
                }
                return Ok(pending);
            };
            root.verify()?;
            let names = root.entries(budget.remaining_entries())?;
            budget.entries(names.len())?;
            if !names.iter().any(|name| name == V2_QUOTA_LOCK) {
                return Err(StoreError::IncompleteEvidence);
            }
            if let Some(trace) = trace {
                trace.enter(crate::creation_preparation::Stage::RecoveryQuotaOpen);
            }
            let mut lock = root.open_quota_lock()?;
            if lock.len()? != 0 {
                return Err(StoreError::CorruptEvidence);
            }
            if let Some(trace) = trace {
                trace.enter(crate::creation_preparation::Stage::RecoveryQuotaLock);
            }
            lock.lock_exclusive()?;
            lock.verify()?;
            root.verify()?;
            admitted_state.verify_path().map_err(io_error)?;

            if let Some(trace) = trace {
                trace.enter(crate::creation_preparation::Stage::NamespaceScan);
            }
            let (summary, exemptions) =
                namespace_rename_store::history_summary_for_fresh_create_space_existing_locked(
                    Arc::clone(&root),
                    Arc::clone(&protector),
                    policy,
                    provider,
                    physical_root,
                    candidate_scope,
                    &mut budget,
                )?;
            // Keep every unknown/unconfigured-format and summary-bound refusal.
            // The old ACK gap remains the only existing namespace-only exception.
            if let Some(trace) = trace {
                trace.enter(crate::creation_preparation::Stage::NamespaceValidation);
            }
            let _ = namespace_rename_store::history_unresolved_for_fresh_create(
                &summary,
                namespace_configured,
            )
            .map_err(|_| StoreError::IncompleteEvidence)?;
            let excluded_files = summary
                .file_acknowledged_join_gaps
                .checked_add(exemptions.len())
                .ok_or(StoreError::ScanLimit)?;
            let remaining_files = summary
                .file_unresolved
                .checked_sub(excluded_files)
                .ok_or(StoreError::CorruptEvidence)?;
            let namespace_pending = summary.unresolved != 0
                || summary.directory_unresolved != 0
                || summary.delete_unresolved != 0
                || remaining_files != 0;
            let mut matched = vec![false; exemptions.len()];

            // The same retained root/quota lease covers the content view. Preserve
            // its existing body length/pin checks and legacy read policy; no body
            // bytes are decoded by this v2 metadata traversal.
            if let Some(trace) = trace {
                trace.enter(crate::creation_preparation::Stage::SnapshotScan);
            }
            let mut snapshot_pending = false;
            let names = root.entries(budget.remaining_entries())?;
            budget.entries(names.len())?;
            let catalogs =
                validate_root_catalog_scope_union(&*root, &*protector, &names, &mut budget)?;
            let mut record_count = 0usize;
            let mut seen = std::collections::HashSet::new();
            for scope in catalogs.snapshots.into_iter().filter(|scope| {
                scope.profile_id == provider.profile_id()
                    && scope.server_origin == provider.server_origin()
                    && scope.account_subject == provider.account_id()
                    && scope.root_volume_serial == physical_root.volume_serial
                    && scope.root_file_index == physical_root.file_index
            }) {
                let store = SnapshotStore::from_directory(
                    Arc::clone(&root),
                    scope,
                    Arc::clone(&protector),
                    policy,
                )?;
                for record in store.discover_records_bounded(&mut budget)? {
                    record_count = record_count.checked_add(1).ok_or(StoreError::ScanLimit)?;
                    if record_count > 2_000
                        || !seen
                            .insert((record.key.record_id().to_owned(), record.key.generation()))
                    {
                        return Err(StoreError::ScanLimit);
                    }
                    if let Some(index) = exemptions.iter().position(|key| key == &record.key) {
                        if matched[index] || record.state != StreamedAttemptState::NotAttempted {
                            return Err(StoreError::CorruptEvidence);
                        }
                        matched[index] = true;
                    } else if !matches!(
                        record.state,
                        StreamedAttemptState::LocallyAcknowledged { .. }
                            | StreamedAttemptState::Superseded { .. }
                    ) {
                        snapshot_pending = true;
                    }
                }
            }
            if let Some(trace) = trace {
                trace.enter(crate::creation_preparation::Stage::ExemptionMatch);
            }
            if matched.iter().any(|matched| !matched) {
                return Err(StoreError::IncompleteEvidence);
            }
            if let Some(trace) = trace {
                trace.enter(crate::creation_preparation::Stage::LegacyScan);
            }
            let legacy_pending = scan_legacy(&mut budget)?;
            if let Some(trace) = trace {
                trace.enter(crate::creation_preparation::Stage::RecoveryFinal);
            }
            root.verify()?;
            lock.verify()?;
            admitted_state.verify_path().map_err(io_error)?;
            if let Some(trace) = trace {
                let pending_stage = if namespace_pending {
                    Some(crate::creation_preparation::Stage::NamespacePending)
                } else if snapshot_pending {
                    Some(crate::creation_preparation::Stage::SnapshotPending)
                } else if legacy_pending {
                    Some(crate::creation_preparation::Stage::LegacyPending)
                } else {
                    None
                };
                if let Some(stage) = pending_stage {
                    trace.enter(stage);
                    trace.category(crate::creation_preparation::Category::Pending);
                }
            }
            Ok(namespace_pending || snapshot_pending || legacy_pending)
        })()
        .inspect_err(|error| {
            if let Some(trace) = trace {
                trace.store(*error);
            }
        })
    }

    fn from_directory(
        root: Arc<dyn Directory>,
        scope: EditJournalScope,
        protector: Arc<dyn EditRecordProtector>,
        policy: StorePolicy,
    ) -> Result<Arc<Self>, StoreError> {
        policy.validate()?;
        validate_scope(&scope)?;
        root.verify()?;
        let key = scope_key(&scope)?;
        Ok(Arc::new(Self {
            root,
            scope,
            key,
            protector,
            policy,
        }))
    }

    /// Generate a new record ID. Caller-supplied binding.record_id is ignored.
    /// The nonblocking state-global OS lock remains held through commit/drop.
    /// Dropping any state preserves every file and retained quota reservation.
    pub fn try_begin_capture(
        self: &Arc<Self>,
        mut binding: SnapshotBinding,
    ) -> Result<CaptureReservation, StoreError> {
        if binding.scope != self.scope {
            return Err(StoreError::Invalid);
        }
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| StoreError::Io)?;
        binding.record_id = hex(&random);
        validate_binding(&binding)?;
        let reserved_bytes = reservation_bound(binding.content_len)?;
        if binding.content_len > self.policy.max_content_bytes {
            return Err(StoreError::Quota);
        }
        let lease = self.acquire_lock()?;
        let inventory = self.inventory()?;
        let required = reserved_bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add((META_LIMIT * 2) as u64))
            .and_then(|n| n.checked_add(inventory.bytes))
            .ok_or(StoreError::Quota)?;
        if required > self.policy.max_state_bytes {
            return Err(StoreError::Quota);
        }
        // Two catalog entries, reservation, body stage/final, manifest stage/final.
        if inventory
            .entries
            .checked_add(7)
            .is_none_or(|n| n > self.policy.max_entries)
        {
            return Err(StoreError::ScanLimit);
        }
        let directory = self.ensure_scope()?;
        let reservation = Reservation {
            version: 2,
            binding: binding.clone(),
            reserved_bytes,
        };
        let aad = reservation_aad(&self.key, &binding.record_id);
        let sealed = self.seal_metadata(&aad, &reservation)?;
        persist_metadata(
            &*directory,
            &format!("{}.reserve", binding.record_id),
            &sealed,
        )?;
        Ok(CaptureReservation {
            store: Arc::clone(self),
            directory,
            binding,
            _lease: lease,
            reserved_bytes,
        })
    }

    /// Read-only bounded discovery. Never opens or decrypts body files.
    /// Incomplete/corrupt evidence is an error, never a healthy empty result.
    /// Returned metadata is PENDING full body authentication: size and the
    /// current private immutable entry are checked without reading body bytes.
    pub fn discover_metadata(&self) -> Result<Vec<SnapshotManifest>, StoreError> {
        Ok(self
            .discover_records()?
            .into_iter()
            .map(|record| record.manifest)
            .collect())
    }
    fn discover_metadata_budgeted(
        &self,
        budget: &mut Budget,
    ) -> Result<(Vec<SnapshotManifest>, Vec<String>), StoreError> {
        let names = self
            .root
            .entries(self.policy.max_entries.min(budget.remaining_entries()))?;
        budget.entries(names.len())?;
        self.validate_root_catalogs(&names, budget)?;
        let catalog = format!("{}.scope", self.key);
        if !names.contains(&catalog) {
            return Ok((Vec::new(), Vec::new()));
        }
        let directory = self.root.child(&self.key, false)?;
        let names = directory.entries(budget.remaining_entries())?;
        budget.entries(names.len())?;
        let mut manifests = Vec::new();
        for name in &names {
            let (id, suffix) = split_record_name(name)?;
            match suffix {
                "manifest" => {
                    if !names.contains(&format!("{id}.body"))
                        || !names.contains(&format!("{id}.reserve"))
                    {
                        return Err(StoreError::IncompleteEvidence);
                    }
                    let bytes = read_metadata(&*directory, name, budget)?;
                    let manifest = open_manifest(
                        &bytes,
                        &*self.protector,
                        &self.scope,
                        id,
                        self.policy.codec()?,
                    )?;
                    let reservation =
                        self.authenticate_reservation(&*directory, id, &self.scope, budget)?;
                    if reservation.binding != *manifest.binding() {
                        return Err(StoreError::CorruptEvidence);
                    }
                    // Open metadata on an immutable regular/private handle only.
                    // This pin validates current OS entry identity, not original
                    // storage provenance or content; full authentication is later.
                    let body = directory.open(&format!("{id}.body"))?;
                    if body.len()? != manifest.container_len() {
                        return Err(StoreError::IncompleteEvidence);
                    }
                    body.verify()?;
                    manifests.push(manifest);
                }
                "reserve" => {
                    self.authenticate_reservation(&*directory, id, &self.scope, budget)?;
                    if !names.contains(&format!("{id}.manifest")) {
                        return Err(StoreError::IncompleteEvidence);
                    }
                }
                "body" => {
                    if !names.contains(&format!("{id}.manifest")) {
                        return Err(StoreError::IncompleteEvidence);
                    }
                }
                "dispatch.lock" => {
                    let lock = directory.open(name)?;
                    if lock.len()? != 0 || !names.contains(&format!("{id}.manifest")) {
                        return Err(StoreError::CorruptEvidence);
                    }
                    lock.verify()?;
                }
                suffix if suffix.starts_with("event.") => {
                    let (_, stage) =
                        events::event_suffix(suffix).ok_or(StoreError::CorruptEvidence)?;
                    if stage || !names.contains(&format!("{id}.manifest")) {
                        return Err(StoreError::IncompleteEvidence);
                    }
                }
                _ => return Err(StoreError::IncompleteEvidence),
            }
        }
        Ok((manifests, names))
    }

    pub fn open_verified(
        &self,
        record_id: &str,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<VerifiedPinnedSnapshot, StoreError> {
        if !valid_id(record_id) {
            return Err(StoreError::Invalid);
        }
        let mut budget = Budget::new(self.policy);
        self.authenticate_scope(&self.key, &mut budget)?;
        let directory = self.root.child(&self.key, false)?;
        let bytes = read_metadata(&*directory, &format!("{record_id}.manifest"), &mut budget)?;
        let manifest = open_manifest(
            &bytes,
            &*self.protector,
            &self.scope,
            record_id,
            self.policy.codec()?,
        )?;
        let reservation =
            self.authenticate_reservation(&*directory, record_id, &self.scope, &mut budget)?;
        if reservation.binding != *manifest.binding() {
            return Err(StoreError::CorruptEvidence);
        }
        let mut body = directory.open(&format!("{record_id}.body"))?;
        if body.len()? != manifest.container_len() {
            return Err(StoreError::CorruptEvidence);
        }
        let check = verify_container(
            &mut *body,
            &*self.protector,
            &manifest,
            self.policy.codec()?,
            cancelled,
        )?;
        body.verify()?;
        Ok(VerifiedPinnedSnapshot {
            body,
            manifest,
            check,
            protector: Arc::clone(&self.protector),
            limits: self.policy.codec()?,
        })
    }

    fn validate_root_catalogs(
        &self,
        names: &[String],
        budget: &mut Budget,
    ) -> Result<(), StoreError> {
        self.validate_root_catalogs_with_scope_union(names, budget)
            .map(|_| ())
    }

    fn validate_root_catalogs_with_scope_union(
        &self,
        names: &[String],
        budget: &mut Budget,
    ) -> Result<RootCatalogScopes, StoreError> {
        validate_root_catalog_scope_union(&*self.root, &*self.protector, names, budget)
    }

    // Publication callers hold the existing shared quota lease. Authenticate
    // all formats before adding the prospective key, and before any catalog
    // or directory is created. A shared key counts once across store types.
    fn validate_requested_catalog_scope(&self) -> Result<(), StoreError> {
        let mut budget = Budget::new(self.policy);
        let names = self.root.entries(budget.remaining_entries())?;
        budget.entries(names.len())?;
        let mut catalogs = self.validate_root_catalogs_with_scope_union(&names, &mut budget)?;
        catalogs.keys.insert(self.key.clone());
        check_scope_union(&catalogs.keys)
    }

    fn acquire_lock(&self) -> Result<Box<dyn PinnedRead>, StoreError> {
        self.root.verify()?;
        // Create-only: an existing lock is retained forever. No replacement.
        match self.root.create(V2_QUOTA_LOCK) {
            Ok((file, _)) => {
                file.sync()?;
                drop(file);
            }
            Err(_) => { /* existing lock is validated by immutable reopen */ }
        }
        let mut file = self.root.open_quota_lock()?;
        if file.len()? != 0 {
            return Err(StoreError::CorruptEvidence);
        }
        file.lock_exclusive()?;
        file.verify()?;
        Ok(file)
    }
    fn ensure_scope(&self) -> Result<Arc<dyn Directory>, StoreError> {
        self.validate_requested_catalog_scope()?;
        let names = self.root.entries(self.policy.max_entries)?;
        let catalog = format!("{}.scope", self.key);
        if names.contains(&catalog) {
            let mut budget = Budget::new(self.policy);
            self.authenticate_scope(&self.key, &mut budget)?;
            return self.root.child(&self.key, false);
        }
        if names.contains(&self.key) {
            return Err(StoreError::IncompleteEvidence);
        }
        let sealed = self.seal_metadata(&scope_aad(&self.key), &self.scope)?;
        persist_metadata(&*self.root, &catalog, &sealed)?;
        self.root.child(&self.key, true)
    }
    fn seal_metadata<T: Serialize>(&self, aad: &[u8], value: &T) -> Result<Vec<u8>, StoreError> {
        let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| StoreError::Invalid)?);
        if bytes.len() > META_LIMIT / 2 {
            return Err(StoreError::Invalid);
        }
        let sealed = self
            .protector
            .seal(aad, &bytes)
            .map_err(|_| StoreError::CorruptEvidence)?;
        if sealed.is_empty() || sealed.len() > META_LIMIT {
            return Err(StoreError::Quota);
        }
        Ok(sealed)
    }
    fn authenticate_scope(
        &self,
        key: &str,
        budget: &mut Budget,
    ) -> Result<EditJournalScope, StoreError> {
        let scope = authenticate_scope_catalog(&*self.root, &*self.protector, key, budget)?;
        if key == self.key && scope != self.scope {
            return Err(StoreError::CorruptEvidence);
        }
        Ok(scope)
    }
    fn authenticate_reservation(
        &self,
        directory: &dyn Directory,
        id: &str,
        scope: &EditJournalScope,
        budget: &mut Budget,
    ) -> Result<Reservation, StoreError> {
        authenticate_reservation_record(directory, &*self.protector, id, scope, budget)
    }
    /// Scope-independent protected v2 usage. Caller MUST hold the SAME
    /// persistent V2_QUOTA_LOCK. Never creates, relocks, reads a body or adds
    /// legacy usage. No dummy profile/account/Space scope is constructed.
    #[cfg(windows)]
    pub(crate) fn accounted_state_usage_while_locked(
        admitted_state: Arc<crate::recovery_state::RecoveryStateRoot>,
        protector: Arc<dyn EditRecordProtector>,
        policy: StorePolicy,
    ) -> Result<(u64, usize), StoreError> {
        policy.validate()?;
        let Some(root) = windows::existing_root(admitted_state, V2_STORE_ROOT)? else {
            return Ok((0, 0));
        };
        let inventory = v2_inventory_state(&*root, &*protector, policy, None)?;
        Ok((inventory.bytes, inventory.entries))
    }
    /// Caller MUST retain the same persistent V2_QUOTA_LOCK OS lease. Returns
    /// protected v2 accounting ONLY, without recursive lock or legacy usage.
    /// This is accounting, never body/native/remote authority.
    pub(crate) fn accounted_usage_while_locked(&self) -> Result<(u64, usize), StoreError> {
        let inventory = self.v2_inventory()?;
        Ok((inventory.bytes, inventory.entries))
    }
    fn inventory(&self) -> Result<Inventory, StoreError> {
        let (bytes, entries) = self.accounted_usage_while_locked()?;
        let mut inventory = Inventory { bytes, entries };
        let (bytes, entries) = self.root.external_recovery_usage(self.policy)?;
        inventory.add(bytes)?;
        inventory.entries = inventory
            .entries
            .checked_add(entries)
            .ok_or(StoreError::ScanLimit)?;
        if inventory.entries > self.policy.max_entries {
            return Err(StoreError::ScanLimit);
        }
        Ok(inventory)
    }
    fn v2_inventory(&self) -> Result<Inventory, StoreError> {
        v2_inventory_state(
            &*self.root,
            &*self.protector,
            self.policy,
            Some(&self.scope),
        )
    }
}

fn v2_inventory_state(
    root: &dyn Directory,
    protector: &dyn EditRecordProtector,
    policy: StorePolicy,
    expected_scope: Option<&EditJournalScope>,
) -> Result<Inventory, StoreError> {
    policy.validate()?;
    root.verify()?;
    let expected_key = expected_scope.map(scope_key).transpose()?;
    let authenticated_scope =
        |key: &str, budget: &mut Budget| -> Result<EditJournalScope, StoreError> {
            let scope = authenticate_scope_catalog(root, protector, key, budget)?;
            if expected_key.as_deref() == Some(key) && expected_scope != Some(&scope) {
                return Err(StoreError::CorruptEvidence);
            }
            Ok(scope)
        };
    let mut budget = Budget::new(policy);
    let root_names = root.entries(policy.max_entries)?;
    budget.entries(root_names.len())?;
    validate_root_catalog_scope_union(root, protector, &root_names, &mut budget)?;
    let mut result = Inventory {
        bytes: 0,
        entries: root_names.len(),
    };
    let mut unique = std::collections::HashSet::new();
    for name in &root_names {
        if !unique.insert(name) {
            return Err(StoreError::CorruptEvidence);
        }
        if name == V2_QUOTA_LOCK {
            let lock = root.open(name)?;
            if lock.len()? != 0 {
                return Err(StoreError::CorruptEvidence);
            }
            lock.verify()?;
            continue;
        }
        if name == namespace_file_store::ROOT {
            let usage = namespace_file_store::accounted_usage(
                &*root.child(name, false)?,
                protector,
                &mut budget,
            )?;
            result.add(usage.bytes)?;
            result.entries = result
                .entries
                .checked_add(usage.entries)
                .ok_or(StoreError::ScanLimit)?;
            continue;
        }
        if name == namespace_store::ROOT {
            let usage = namespace_store::accounted_usage(&*root.child(name, false)?, &mut budget)?;
            result.add(usage.bytes)?;
            result.entries = result
                .entries
                .checked_add(usage.entries)
                .ok_or(StoreError::ScanLimit)?;
            continue;
        }
        if name == namespace_file_delete_store::ROOT {
            if !root_names.iter().any(|entry| entry == V2_QUOTA_LOCK) {
                return Err(StoreError::IncompleteEvidence);
            }
            let usage = namespace_file_delete_store::accounted_usage(
                &*root.child(name, false)?,
                protector,
                &mut budget,
            )?;
            result.add(usage.bytes)?;
            result.entries = result
                .entries
                .checked_add(usage.entries)
                .ok_or(StoreError::ScanLimit)?;
            continue;
        }
        if name == namespace_rename_store::ROOT {
            if !root_names.iter().any(|entry| entry == V2_QUOTA_LOCK) {
                return Err(StoreError::IncompleteEvidence);
            }
            let usage = namespace_rename_store::accounted_usage(
                &*root.child(name, false)?,
                protector,
                &mut budget,
            )?;
            result.add(usage.bytes)?;
            result.entries = result
                .entries
                .checked_add(usage.entries)
                .ok_or(StoreError::ScanLimit)?;
            continue;
        }
        if let Some(key) = name.strip_suffix(".scope") {
            if !valid_key(key) {
                return Err(StoreError::CorruptEvidence);
            }
            authenticated_scope(key, &mut budget)?;
            result.add(root.open(name)?.len()?)?;
            if !root_names.contains(&key.to_owned()) {
                return Err(StoreError::IncompleteEvidence);
            }
            continue;
        }
        if !valid_key(name) || !root_names.contains(&format!("{name}.scope")) {
            return Err(StoreError::IncompleteEvidence);
        }
        let scope = authenticated_scope(name, &mut budget)?;
        let directory = root.child(name, false)?;
        let names = directory.entries(budget.remaining_entries())?;
        budget.entries(names.len())?;
        result.entries = result
            .entries
            .checked_add(names.len())
            .ok_or(StoreError::ScanLimit)?;
        for child in &names {
            let (id, suffix) = split_record_name(child)?;
            if suffix == "reserve.stage"
                || (suffix != "reserve" && !names.contains(&format!("{id}.reserve")))
            {
                return Err(StoreError::IncompleteEvidence);
            }
            result.add(directory.open(child)?.len()?)?;
            if suffix == "reserve" {
                let reservation = authenticate_reservation_record(
                    &*directory,
                    protector,
                    id,
                    &scope,
                    &mut budget,
                )?;
                result.add(reservation.reserved_bytes)?;
            }
        }
    }
    root.verify()?;
    Ok(result)
}
fn authenticate_reservation_record(
    directory: &dyn Directory,
    protector: &dyn EditRecordProtector,
    id: &str,
    scope: &EditJournalScope,
    budget: &mut Budget,
) -> Result<Reservation, StoreError> {
    let sealed = read_metadata(directory, &format!("{id}.reserve"), budget)?;
    let key = scope_key(scope)?;
    let plain = Zeroizing::new(
        protector
            .open(&reservation_aad(&key, id), &sealed)
            .map_err(|_| StoreError::CorruptEvidence)?,
    );
    if plain.len() > META_LIMIT / 2 {
        return Err(StoreError::CorruptEvidence);
    }
    let record: Reservation =
        serde_json::from_slice(&plain).map_err(|_| StoreError::CorruptEvidence)?;
    validate_binding(&record.binding)?;
    if record.version != 2
        || record.binding.record_id != id
        || &record.binding.scope != scope
        || record.reserved_bytes != reservation_bound(record.binding.content_len)?
    {
        return Err(StoreError::CorruptEvidence);
    }
    Ok(record)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reservation {
    version: u32,
    binding: SnapshotBinding,
    reserved_bytes: u64,
}
pub struct CaptureReservation {
    store: Arc<SnapshotStore>,
    directory: Arc<dyn Directory>,
    binding: SnapshotBinding,
    _lease: Box<dyn PinnedRead>,
    reserved_bytes: u64,
}
impl CaptureReservation {
    pub fn binding(&self) -> &SnapshotBinding {
        &self.binding
    }
    pub fn capture(
        self,
        source: &mut dyn Read,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<StagedSnapshot, StoreError> {
        let stage_name = format!("{}.body.stage", self.binding.record_id);
        let (mut writer, identity) = self.directory.create(&stage_name)?;
        let encoded = encode_snapshot(
            source,
            &mut *writer,
            &*self.store.protector,
            &self.binding,
            self.store.policy.codec()?,
            cancelled,
        )?;
        writer.sync()?;
        drop(writer);
        Ok(StagedSnapshot {
            reservation: self,
            identity,
            encoded,
        })
    }
}
pub struct StagedSnapshot {
    reservation: CaptureReservation,
    identity: Identity,
    encoded: EncodedSnapshot,
}
impl StagedSnapshot {
    /// Call ONLY after the caller revalidates its held native source handle.
    /// Success is durable local storage evidence, not source/remote authority.
    pub fn verify_and_commit(
        self,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<CommittedSnapshot, StoreError> {
        let r = &self.reservation;
        let id = &r.binding.record_id;
        let stage_name = format!("{id}.body.stage");
        let body_name = format!("{id}.body");
        let manifest_name = format!("{id}.manifest");
        let mut stage = r.directory.open(&stage_name)?;
        if stage.identity() != self.identity
            || stage.len()? != self.encoded.manifest().container_len()
            || stage.len()? > r.reserved_bytes
        {
            return Err(StoreError::CorruptEvidence);
        }
        verify_container(
            &mut *stage,
            &*r.store.protector,
            self.encoded.manifest(),
            r.store.policy.codec()?,
            cancelled,
        )?;
        stage.verify()?;
        drop(stage);
        r.directory
            .publish(&stage_name, &body_name, self.identity)
            .map_err(|_| StoreError::PublicationUncertain)?;
        let mut body = r
            .directory
            .open(&body_name)
            .map_err(|_| StoreError::PublicationUncertain)?;
        if body.identity() != self.identity {
            return Err(StoreError::PublicationUncertain);
        }
        verify_container(
            &mut *body,
            &*r.store.protector,
            self.encoded.manifest(),
            r.store.policy.codec()?,
            cancelled,
        )?;
        body.verify()?;
        persist_metadata(
            &*r.directory,
            &manifest_name,
            self.encoded.sealed_manifest(),
        )
        .map_err(|_| StoreError::PublicationUncertain)?;
        let mut budget = Budget::new(r.store.policy);
        let bytes = read_metadata(&*r.directory, &manifest_name, &mut budget)
            .map_err(|_| StoreError::PublicationUncertain)?;
        let manifest = open_manifest(
            &bytes,
            &*r.store.protector,
            &r.store.scope,
            id,
            r.store.policy.codec()?,
        )?;
        if manifest.binding() != &r.binding
            || manifest.content_sha256() != self.encoded.manifest().content_sha256()
            || manifest.container_sha256() != self.encoded.manifest().container_sha256()
            || manifest.container_len() != self.encoded.manifest().container_len()
        {
            return Err(StoreError::PublicationUncertain);
        }
        body.verify()?;
        if cancelled() {
            return Err(StoreError::Snapshot(SnapshotError::Cancelled));
        }
        Ok(CommittedSnapshot {
            manifest,
            store: Arc::clone(&r.store),
        })
    }
}
pub struct CommittedSnapshot {
    manifest: SnapshotManifest,
    // Ephemeral origin only; never serialized or reconstructed from discovery.
    store: Arc<SnapshotStore>,
}
impl CommittedSnapshot {
    pub fn manifest(&self) -> &SnapshotManifest {
        &self.manifest
    }
}
/// Owns the immutable body pin. No path or raw file escapes; conversion
/// retains the same pin in a bounded authenticated plaintext reader.
pub struct VerifiedPinnedSnapshot {
    body: Box<dyn PinnedRead>,
    manifest: SnapshotManifest,
    check: LocalSnapshotCheck,
    protector: Arc<dyn EditRecordProtector>,
    limits: SnapshotLimits,
}
impl VerifiedPinnedSnapshot {
    pub fn manifest(&self) -> &SnapshotManifest {
        &self.manifest
    }
    pub fn local_check(&self) -> &LocalSnapshotCheck {
        &self.check
    }
    pub fn verify_pin(&self) -> Result<(), StoreError> {
        self.body.verify()
    }
    /// Reverify and stream through the SAME owned immutable pin. This grants
    /// local byte authentication only; transport/native authority is separate.
    pub fn into_reader(
        self,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<impl Read + Send, StoreError> {
        self.body.verify()?;
        Ok(AuthenticatedSnapshotReader::new(
            self.body,
            self.manifest,
            self.protector,
            self.limits,
            cancelled,
        )?)
    }
}

struct Inventory {
    bytes: u64,
    entries: usize,
}
impl Inventory {
    fn add(&mut self, n: u64) -> Result<(), StoreError> {
        self.bytes = self.bytes.checked_add(n).ok_or(StoreError::Quota)?;
        Ok(())
    }
}
/// One aggregate metadata-discovery budget. Counters are never reset by a
/// bounded scope call; each call also retains its own StorePolicy ceiling.
pub(crate) struct DiscoveryBudget {
    entries: usize,
    bytes: u64,
}
type Budget = DiscoveryBudget;
impl DiscoveryBudget {
    pub(crate) fn new(policy: StorePolicy) -> Self {
        Self {
            entries: policy.max_entries,
            bytes: policy.max_metadata_bytes_per_scan,
        }
    }
    fn within_policy<T>(
        &mut self,
        policy: StorePolicy,
        work: impl FnOnce(&mut Self) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut local = Self {
            entries: self.entries.min(policy.max_entries),
            bytes: self.bytes.min(policy.max_metadata_bytes_per_scan),
        };
        let before_entries = local.entries;
        let before_bytes = local.bytes;
        let result = work(&mut local);
        self.entries -= before_entries - local.entries;
        self.bytes -= before_bytes - local.bytes;
        result
    }
    pub(crate) fn remaining_entries(&self) -> usize {
        self.entries
    }
    #[cfg(windows)]
    pub(crate) fn remaining_metadata_bytes(&self) -> u64 {
        self.bytes
    }
    #[cfg(windows)]
    pub(crate) fn charge_external_scan(
        &mut self,
        entries: usize,
        metadata_bytes: u64,
    ) -> Result<(), StoreError> {
        self.entries = self
            .entries
            .checked_sub(entries)
            .ok_or(StoreError::ScanLimit)?;
        self.bytes = self
            .bytes
            .checked_sub(metadata_bytes)
            .ok_or(StoreError::ScanLimit)?;
        Ok(())
    }
    fn entries(&mut self, count: usize) -> Result<(), StoreError> {
        self.entries = self
            .entries
            .checked_sub(count)
            .ok_or(StoreError::ScanLimit)?;
        Ok(())
    }
}
// This boundary is portable only for injected tests. The production Windows
// opener supplies already validated private directory/ancestor capabilities.
#[cfg(all(test, unix))]
fn discover_scope_catalogs(
    root: &dyn Directory,
    protector: &dyn EditRecordProtector,
    policy: StorePolicy,
) -> Result<Vec<EditJournalScope>, StoreError> {
    discover_scope_catalogs_bounded(root, protector, policy, &mut Budget::new(policy))
}
#[cfg(any(windows, test))]
fn discover_scope_catalogs_bounded(
    root: &dyn Directory,
    protector: &dyn EditRecordProtector,
    policy: StorePolicy,
    budget: &mut DiscoveryBudget,
) -> Result<Vec<EditJournalScope>, StoreError> {
    budget.within_policy(policy, |budget| {
        discover_scope_catalogs_inner(root, protector, policy, budget)
    })
}
#[cfg(any(windows, test))]
fn discover_scope_catalogs_inner(
    root: &dyn Directory,
    protector: &dyn EditRecordProtector,
    policy: StorePolicy,
    budget: &mut Budget,
) -> Result<Vec<EditJournalScope>, StoreError> {
    policy.validate()?;
    root.verify()?;
    let names = root.entries(policy.max_entries.min(budget.remaining_entries()))?;
    budget.entries(names.len())?;
    Ok(validate_root_catalog_scope_union(root, protector, &names, budget)?.snapshots)
}

struct RootCatalogScopes {
    snapshots: Vec<EditJournalScope>,
    rename: Vec<EditJournalScope>,
    delete: Vec<EditJournalScope>,
    directories: Vec<EditJournalScope>,
    keys: std::collections::HashSet<String>,
}

fn check_scope_union(keys: &std::collections::HashSet<String>) -> Result<(), StoreError> {
    if keys.len() > 256 {
        return Err(StoreError::ScanLimit);
    }
    Ok(())
}

// Every catalog is authenticated under the caller's single remaining budget,
// even when another format already contributed the same scope key. Returning
// snapshot/rename groups separately never reinterprets another format's data.
fn validate_root_catalog_scope_union(
    root: &dyn Directory,
    protector: &dyn EditRecordProtector,
    names: &[String],
    budget: &mut Budget,
) -> Result<RootCatalogScopes, StoreError> {
    root.verify()?;
    let mut unique = std::collections::HashSet::new();
    let mut result = RootCatalogScopes {
        snapshots: Vec::new(),
        rename: Vec::new(),
        delete: Vec::new(),
        directories: Vec::new(),
        keys: std::collections::HashSet::new(),
    };
    for name in names {
        if !unique.insert(name) {
            return Err(StoreError::CorruptEvidence);
        }
        if name == V2_QUOTA_LOCK {
            let lock = root.open_quota_lock()?;
            if lock.len()? != 0 {
                return Err(StoreError::CorruptEvidence);
            }
            lock.verify()?;
        } else if name == namespace_file_store::ROOT {
            result
                .keys
                .extend(namespace_file_store::validated_catalog_scope_keys(
                    &*root.child(name, false)?,
                    protector,
                    budget,
                )?);
        } else if name == namespace_file_delete_store::ROOT {
            if !names.iter().any(|entry| entry == V2_QUOTA_LOCK) {
                return Err(StoreError::IncompleteEvidence);
            }
            result.delete = namespace_file_delete_store::validate_catalogs(
                &*root.child(name, false)?,
                protector,
                budget,
            )?;
            for scope in &result.delete {
                result.keys.insert(scope_key(scope)?);
            }
        } else if name == namespace_rename_store::ROOT {
            if !names.iter().any(|entry| entry == V2_QUOTA_LOCK) {
                return Err(StoreError::IncompleteEvidence);
            }
            result.rename = namespace_rename_store::validate_catalogs(
                &*root.child(name, false)?,
                protector,
                budget,
            )?;
            for scope in &result.rename {
                result.keys.insert(scope_key(scope)?);
            }
        } else if name == namespace_store::ROOT {
            result.directories = namespace_store::validated_catalog_scopes(
                &*root.child(name, false)?,
                protector,
                budget,
            )?;
            for scope in &result.directories {
                result.keys.insert(scope_key(scope)?);
            }
        } else if let Some(key) = name.strip_suffix(".scope") {
            if !valid_key(key) || !names.contains(&key.to_owned()) {
                return Err(StoreError::IncompleteEvidence);
            }
            let scope = authenticate_scope_catalog(root, protector, key, budget)?;
            root.child(key, false)?.verify()?;
            result.keys.insert(key.to_owned());
            result.snapshots.push(scope);
        } else if !valid_key(name) || !names.contains(&format!("{name}.scope")) {
            return Err(StoreError::IncompleteEvidence);
        }
    }
    root.verify()?;
    check_scope_union(&result.keys)?;
    Ok(result)
}
fn authenticate_scope_catalog(
    root: &dyn Directory,
    protector: &dyn EditRecordProtector,
    key: &str,
    budget: &mut Budget,
) -> Result<EditJournalScope, StoreError> {
    if !valid_key(key) {
        return Err(StoreError::Invalid);
    }
    let sealed = read_metadata(root, &format!("{key}.scope"), budget)?;
    let plain = Zeroizing::new(
        protector
            .open(&scope_aad(key), &sealed)
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

fn read_metadata(
    directory: &dyn Directory,
    name: &str,
    budget: &mut Budget,
) -> Result<Vec<u8>, StoreError> {
    let mut file = directory.open(name)?;
    let length = file.len()?;
    if length == 0 || length > META_LIMIT as u64 {
        return Err(StoreError::CorruptEvidence);
    }
    budget.bytes = budget
        .bytes
        .checked_sub(length)
        .ok_or(StoreError::ScanLimit)?;
    let mut bytes = vec![0; length as usize];
    file.read_exact(&mut bytes).map_err(io_error)?;
    let mut end = [0];
    if file.read(&mut end).map_err(io_error)? != 0 {
        return Err(StoreError::CorruptEvidence);
    }
    file.verify()?;
    Ok(bytes)
}
fn persist_metadata(
    directory: &dyn Directory,
    final_name: &str,
    bytes: &[u8],
) -> Result<(), StoreError> {
    let stage = format!("{final_name}.stage");
    let (mut file, identity) = directory.create(&stage)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync()?;
    drop(file);
    directory.publish(&stage, final_name, identity)?;
    let mut reopened = directory.open(final_name)?;
    if reopened.identity() != identity || reopened.len()? != bytes.len() as u64 {
        return Err(StoreError::PublicationUncertain);
    }
    let mut actual = vec![0; bytes.len()];
    reopened.read_exact(&mut actual).map_err(io_error)?;
    if actual != bytes {
        return Err(StoreError::PublicationUncertain);
    }
    reopened.verify()
}
fn reservation_bound(length: u64) -> Result<u64, StoreError> {
    let count =
        length / SNAPSHOT_CHUNK_BYTES as u64 + u64::from(length % SNAPSHOT_CHUNK_BYTES as u64 != 0);
    count
        .checked_mul((24 + MAX_SNAPSHOT_SEALED_CHUNK_BYTES) as u64)
        .and_then(|n| n.checked_add(60 + META_LIMIT as u64 * 3))
        .ok_or(StoreError::Quota)
}
fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_key(key: &str) -> bool {
    key.len() == 64
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn split_record_name(name: &str) -> Result<(&str, &str), StoreError> {
    let (id, suffix) = name.split_once('.').ok_or(StoreError::IncompleteEvidence)?;
    if !valid_id(id)
        || !matches!(
            suffix,
            "reserve"
                | "reserve.stage"
                | "body"
                | "body.stage"
                | "manifest"
                | "manifest.stage"
                | "dispatch.lock"
        ) && events::event_suffix(suffix).is_none()
    {
        return Err(StoreError::IncompleteEvidence);
    }
    Ok((id, suffix))
}
fn validate_scope(scope: &EditJournalScope) -> Result<(), StoreError> {
    if [
        &scope.profile_id,
        &scope.server_origin,
        &scope.account_subject,
        &scope.space_id,
        &scope.root_resource_id,
    ]
    .iter()
    .any(|s| s.is_empty() || s.len() > 4096 || s.chars().any(char::is_control))
        || scope.root_file_index == 0
    {
        return Err(StoreError::Invalid);
    }
    let (scheme, authority) = scope
        .server_origin
        .split_once("://")
        .ok_or(StoreError::Invalid)?;
    if !matches!(scheme, "http" | "https")
        || authority.is_empty()
        || authority
            .bytes()
            .any(|b| matches!(b, b'/' | b'?' | b'#' | b'@') || b.is_ascii_whitespace())
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn validate_binding(b: &SnapshotBinding) -> Result<(), StoreError> {
    validate_scope(&b.scope)?;
    if !valid_id(&b.record_id)
        || b.generation == 0
        || b.local_file.file_index == 0
        || b.local_file.volume_serial != b.scope.root_volume_serial
        || b.relative_path.is_empty()
        || b.relative_path.len() > 32 * 1024
        || b.relative_path.contains('\\')
        || b.relative_path.chars().any(char::is_control)
        || b.relative_path
            .split('/')
            .any(|s| matches!(s, "" | "." | ".."))
    {
        return Err(StoreError::Invalid);
    }
    if let Some(remote) = &b.remote
        && (remote.resource_id.is_empty()
            || remote.resource_id.len() > 4096
            || remote.resource_id.chars().any(char::is_control)
            || remote.etag.len() > 4096
            || remote.etag.chars().any(char::is_control))
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn scope_key(scope: &EditJournalScope) -> Result<String, StoreError> {
    Ok(hex(&Sha256::digest(
        serde_json::to_vec(scope).map_err(|_| StoreError::Invalid)?,
    )))
}
fn scope_aad(key: &str) -> Vec<u8> {
    [SCOPE_DOMAIN, key.as_bytes()].concat()
}
fn reservation_aad(key: &str, id: &str) -> Vec<u8> {
    [RESERVE_DOMAIN, key.as_bytes(), b"/", id.as_bytes()].concat()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(all(test, unix))]
#[path = "streamed_store_tests.rs"]
mod tests;

#[cfg(all(
    test,
    windows,
    debug_assertions,
    feature = "synthetic-agent-integration"
))]
#[path = "scope_union_native_test.rs"]
mod scope_union_native_proof;

/// Synthetic disk fixture only: no Unix/Windows immutable parity claim.
#[cfg(all(test, unix))]
pub(crate) fn synthetic_test_store(policy: StorePolicy) -> (tempfile::TempDir, Arc<SnapshotStore>) {
    let (directory, _observe, store) = tests::fixture_with(policy);
    (directory, store)
}

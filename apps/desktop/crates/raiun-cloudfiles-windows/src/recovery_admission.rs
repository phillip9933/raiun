//! Windows state-wide v1/v2 local recovery quota admission. No replay, cleanup,
//! credential, upload, healthy-record or native completion authority.
#![cfg(windows)]

use crate::streamed_store::{SnapshotStore, StoreError, StorePolicy, V2_QUOTA_LOCK, V2_STORE_ROOT};
use crate::{EditJournalScope, EditRecordProtector};
use raiun_control_windows::{
    LegacyRecoveryMetadataDirectory, OwnedPrivateReader, PinnedDirectory, PrivateDirectory,
};
use std::{ffi::OsStr, io, sync::Arc};

const LEGACY_JOURNAL: &str = "cloud-files-edit-journal-v1";
const LEGACY_SCOPES: &str = "cloud-files-edit-scopes-v1";

/// Only the two recovery trees are included. Provider identity catalogs,
/// offline cache, session storage and other stores have separate bounds and
/// MUST NOT be implicitly initialized or traversed by this accounting pass.
pub struct RecoveryAdmission {
    state: Arc<PrivateDirectory>,
    protector: Arc<dyn EditRecordProtector>,
    policy: StorePolicy,
}

/// Retain through the entire admitted local write/publication. This reservation
/// is not durable disk space or credit: no accounting is reduced when it drops.
/// Cooperating v1 AND v2 writers must hold the same persistent quota.lock; this
/// module alone does not retrofit older constructors or serialize older writers.
pub struct RecoveryAdmissionLease {
    _lock: OwnedPrivateReader,
    _root: Arc<PrivateDirectory>,
    _state: Arc<PrivateDirectory>,
    _store: Option<Arc<SnapshotStore>>,
}

impl RecoveryAdmission {
    /// Physical state-directory identity only; not account or upload authority.
    pub fn state_identity(&self) -> raiun_control_windows::PinnedFileIdentity {
        self.state.identity()
    }

    pub fn new(
        state: Arc<PrivateDirectory>,
        protector: Arc<dyn EditRecordProtector>,
        policy: StorePolicy,
    ) -> Result<Self, StoreError> {
        policy.validate()?;
        state.verify_path().map_err(io_error)?;
        Ok(Self {
            state,
            protector,
            policy,
        })
    }

    pub fn try_reserve(
        &self,
        scope: &EditJournalScope,
        additional_bytes: u64,
        additional_entries: usize,
    ) -> Result<RecoveryAdmissionLease, StoreError> {
        self.reserve_locked(Some(scope), additional_bytes, additional_entries)
    }

    /// Catalog/probe initialization precedes discovery of a Space scope.
    /// Account-independent quota accounting supplies no dispatch authority.
    pub(crate) fn try_reserve_unscoped(
        &self,
        additional_bytes: u64,
        additional_entries: usize,
    ) -> Result<RecoveryAdmissionLease, StoreError> {
        self.reserve_locked(None, additional_bytes, additional_entries)
    }

    fn reserve_locked(
        &self,
        scope: Option<&EditJournalScope>,
        additional_bytes: u64,
        additional_entries: usize,
    ) -> Result<RecoveryAdmissionLease, StoreError> {
        self.state.verify_path().map_err(io_error)?;
        let parent = pinned_parent(&self.state)?;
        let root = Arc::new(
            PrivateDirectory::create_or_open_under(&parent, OsStr::new(V2_STORE_ROOT))
                .map_err(io_error)?,
        );
        // Persistent create-only lock. Never remove, rename, replace or repair.
        if let Ok((file, _)) = root.create_new_file(OsStr::new(V2_QUOTA_LOCK)) {
            file.sync_all().map_err(io_error)?;
            drop(file);
        }
        // A concurrent immutable lock owner may make CREATE_NEW report a
        // sharing error before an existence error. Accept no error as proof:
        // only the following protected immutable open admits an existing
        // entry. Missing/wrong-policy/reparse entries still fail closed.
        let mut lock = root
            .open_owned_immutable_file(OsStr::new(V2_QUOTA_LOCK))
            .map_err(io_error)?;
        if lock.metadata().map_err(io_error)?.len() != 0 {
            return Err(StoreError::CorruptEvidence);
        }
        lock.try_lock_exclusive().map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                StoreError::Busy
            } else {
                StoreError::Io
            }
        })?;
        lock.verify().map_err(io_error)?;
        root.verify_path().map_err(io_error)?;
        self.state.verify_path().map_err(io_error)?;
        let store = scope
            .map(|scope| {
                SnapshotStore::create_or_open(
                    Arc::clone(&self.state),
                    scope.clone(),
                    Arc::clone(&self.protector),
                    self.policy,
                )
            })
            .transpose()?;
        // These helpers deliberately do NOT reacquire quota.lock or include
        // legacy usage. No fabricated Space scope is used for initialization.
        let v2 = if let Some(store) = &store {
            store.accounted_usage_while_locked()?
        } else {
            SnapshotStore::accounted_state_usage_while_locked(
                Arc::clone(&self.state),
                Arc::clone(&self.protector),
                self.policy,
            )?
        };
        let legacy = legacy_recovery_usage(&self.state, self.policy)?;
        check_combined_usage(
            v2,
            legacy,
            (additional_bytes, additional_entries),
            self.policy,
        )?;
        lock.verify().map_err(io_error)?;
        self.state.verify_path().map_err(io_error)?;
        Ok(RecoveryAdmissionLease {
            _lock: lock,
            _root: root,
            _state: Arc::clone(&self.state),
            _store: store,
        })
    }
}

fn check_combined_usage(
    v2: (u64, usize),
    legacy: (u64, usize),
    additional: (u64, usize),
    policy: StorePolicy,
) -> Result<(), StoreError> {
    let bytes =
        v2.0.checked_add(legacy.0)
            .and_then(|n| n.checked_add(additional.0))
            .ok_or(StoreError::Quota)?;
    let entries =
        v2.1.checked_add(legacy.1)
            .and_then(|n| n.checked_add(additional.1))
            .ok_or(StoreError::Quota)?;
    if bytes > policy.max_state_bytes || entries > policy.max_entries {
        return Err(StoreError::Quota);
    }
    Ok(())
}

/// Metadata-only sizes/counts of known legacy recovery roots. Call under the
/// state's v2 quota.lock to serialize cooperating recovery writers. No body is
/// read/decrypted and an unknown file is charged, never adopted as healthy.
pub(crate) fn legacy_recovery_usage(
    state: &Arc<PrivateDirectory>,
    policy: StorePolicy,
) -> Result<(u64, usize), StoreError> {
    policy.validate()?;
    state.verify_path().map_err(io_error)?;
    let parent = pinned_parent(state)?;
    let mut usage = Usage {
        bytes: 0,
        entries: 0,
        policy,
    };
    for (name, scopes_allowed) in [(LEGACY_JOURNAL, true), (LEGACY_SCOPES, false)] {
        let root = match LegacyRecoveryMetadataDirectory::open_under(&parent, OsStr::new(name)) {
            Ok(root) => Arc::new(root),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // Only an actually absent direct entry is empty. An existing
                // dangling reparse point or malformed root remains a refusal.
                match std::fs::symlink_metadata(state.path().join(name)) {
                    Err(absent) if absent.kind() == io::ErrorKind::NotFound => continue,
                    _ => return Err(StoreError::CorruptEvidence),
                }
            }
            Err(_) => return Err(StoreError::CorruptEvidence),
        };
        usage.charge(0)?; // charge the retained known root itself as one entry
        scan_directory(&root, scopes_allowed, &mut usage)?;
    }
    state.verify_path().map_err(io_error)?;
    Ok((usage.bytes, usage.entries))
}

fn scan_directory(
    directory: &Arc<LegacyRecoveryMetadataDirectory>,
    scopes_allowed: bool,
    usage: &mut Usage,
) -> Result<(), StoreError> {
    directory.verify_path().map_err(io_error)?;
    for entry in std::fs::read_dir(directory.path()).map_err(io_error)? {
        // Charge work/count before metadata opens. No unbounded name collection.
        usage.charge(0)?;
        let name = entry.map_err(io_error)?.file_name();
        match directory.open_child_directory(&name) {
            Ok(child) => {
                // Journal permits exactly one scope-directory level. Unknown
                // directories/deeper trees never disappear from accounting.
                let scope_name = name.to_str().ok_or(StoreError::CorruptEvidence)?;
                if !scopes_allowed || !valid_scope_key(scope_name) {
                    return Err(StoreError::CorruptEvidence);
                }
                scan_directory(&Arc::new(child), false, usage)?;
            }
            Err(_) => {
                // Metadata-only no-read-data handle: current-owner, regular,
                // no-reparse, single-link and immutable while measured.
                // Legacy default file DACLs are not modern private-file authority.
                // Locks/stages/retained/unknown plain files all count alike.
                let bytes = directory
                    .file_length(&name)
                    .map_err(|_| StoreError::CorruptEvidence)?;
                usage.add_bytes(bytes)?;
            }
        }
    }
    directory.verify_path().map_err(io_error)
}

fn pinned_parent(directory: &Arc<PrivateDirectory>) -> Result<PinnedDirectory, StoreError> {
    directory.verify_path().map_err(io_error)?;
    let parent = PinnedDirectory::open(directory.path()).map_err(io_error)?;
    if parent.identity() != directory.identity() {
        return Err(StoreError::CorruptEvidence);
    }
    directory.verify_path().map_err(io_error)?;
    Ok(parent)
}
fn valid_scope_key(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn io_error(_: io::Error) -> StoreError {
    StoreError::Io
}
struct Usage {
    bytes: u64,
    entries: usize,
    policy: StorePolicy,
}
impl Usage {
    fn charge(&mut self, bytes: u64) -> Result<(), StoreError> {
        self.entries = self.entries.checked_add(1).ok_or(StoreError::ScanLimit)?;
        if self.entries > self.policy.max_entries {
            return Err(StoreError::ScanLimit);
        }
        self.add_bytes(bytes)
    }
    fn add_bytes(&mut self, bytes: u64) -> Result<(), StoreError> {
        self.bytes = self.bytes.checked_add(bytes).ok_or(StoreError::Quota)?;
        if self.bytes > self.policy.max_state_bytes {
            return Err(StoreError::Quota);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> StorePolicy {
        StorePolicy {
            max_content_bytes: 1024,
            max_state_bytes: 1024 * 1024,
            max_entries: 100,
            max_metadata_bytes_per_scan: 1024 * 1024,
        }
    }
    #[test]
    fn combined_arithmetic_charges_all_sources_without_overflow_or_credit() {
        let p = policy();
        assert!(check_combined_usage((20, 2), (30, 3), (40, 4), p).is_ok());
        assert_eq!(
            check_combined_usage((p.max_state_bytes, 2), (1, 1), (0, 0), p),
            Err(StoreError::Quota)
        );
        assert_eq!(
            check_combined_usage((u64::MAX, 1), (1, 1), (0, 0), p),
            Err(StoreError::Quota)
        );
        assert_eq!(
            check_combined_usage((0, usize::MAX), (0, 1), (0, 0), p),
            Err(StoreError::Quota)
        );
        assert_eq!(
            check_combined_usage((0, 99), (0, 1), (0, 1), p),
            Err(StoreError::Quota)
        );
    }

    fn fixture() -> Arc<PrivateDirectory> {
        // Keep the unique fixture on success and failure; no user state or
        // production DPAPI is used and no cleanup is implied by this test.
        let path = tempfile::tempdir().unwrap().keep();
        let parent = PinnedDirectory::open(&path).unwrap();
        Arc::new(PrivateDirectory::create_or_open_under(&parent, OsStr::new("state")).unwrap())
    }
    fn child(parent: &Arc<PrivateDirectory>, name: &str) -> Arc<PrivateDirectory> {
        Arc::new(
            PrivateDirectory::create_or_open_under(
                &pinned_parent(parent).unwrap(),
                OsStr::new(name),
            )
            .unwrap(),
        )
    }
    fn blob(directory: &Arc<PrivateDirectory>, name: &str, bytes: &[u8]) {
        use std::io::Write;
        let (mut file, _) = directory.create_new_file(OsStr::new(name)).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
    struct NoCrypto;
    impl EditRecordProtector for NoCrypto {
        fn seal(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, crate::JournalError> {
            panic!("empty-v2 metadata quota must not seal bodies")
        }
        fn open(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, crate::JournalError> {
            panic!("legacy size accounting must not decrypt bodies")
        }
    }
    fn scope() -> EditJournalScope {
        EditJournalScope {
            profile_id: "synthetic".into(),
            server_origin: "https://cloud.example.test".into(),
            account_subject: "account-a".into(),
            space_id: "personal-a".into(),
            root_resource_id: "root-a".into(),
            root_volume_serial: 7,
            root_file_index: 11,
        }
    }

    #[test]
    #[ignore = "opt-in native Windows private metadata accounting fixture; no production state, no crypto, retained fixture"]
    fn legacy_accounting_charges_retained_stages_locks_and_unknown_plain_files() {
        let state = fixture();
        assert_eq!(legacy_recovery_usage(&state, policy()).unwrap(), (0, 0));
        let journal = child(&state, LEGACY_JOURNAL);
        let scope = child(&journal, &"a".repeat(64));
        blob(&scope, "record.body", b"1234567");
        blob(&scope, ".stage-retained", b"12345678901");
        blob(&scope, "dispatch.lock", b"");
        blob(&journal, "unknown-retained", b"123");
        let catalogs = child(&state, LEGACY_SCOPES);
        blob(&catalogs, "unknown-file", b"12345");
        assert_eq!(legacy_recovery_usage(&state, policy()).unwrap(), (26, 8));
        let mut few_entries = policy();
        few_entries.max_entries = 4;
        assert_eq!(
            legacy_recovery_usage(&state, few_entries),
            Err(StoreError::ScanLimit)
        );
        blob(&catalogs, "quota-file", &[0; 64]);
        let mut low = policy();
        low.max_state_bytes = 64;
        assert_eq!(legacy_recovery_usage(&state, low), Err(StoreError::Quota));
        let _unexpected = child(&scope, "unexpected-depth");
        assert_eq!(
            legacy_recovery_usage(&state, policy()),
            Err(StoreError::CorruptEvidence)
        );
    }

    #[test]
    #[ignore = "opt-in native Windows persistent quota lock fixture; no production state, retained fixture"]
    fn coordinator_keeps_one_lock_identity_and_nonblocking_cross_owner_exclusion() {
        let state = fixture();
        let protector: Arc<dyn EditRecordProtector> = Arc::new(NoCrypto);
        let coordinator = RecoveryAdmission::new(state, protector, policy()).unwrap();
        let first = coordinator.try_reserve(&scope(), 1, 1).unwrap();
        let identity = first._lock.identity();
        assert!(matches!(
            coordinator.try_reserve(&scope(), 1, 1),
            Err(StoreError::Busy)
        ));
        drop(first);
        let second = coordinator.try_reserve(&scope(), 1, 1).unwrap();
        assert_eq!(identity, second._lock.identity());
        drop(second);
        assert!(
            coordinator
                .try_reserve(&scope(), policy().max_state_bytes, 0)
                .is_ok()
        );
        // No body reservation has been consumed/published by this fixture, so
        // the retained zero-byte lock costs one entry and zero bytes.
        assert!(matches!(
            coordinator.try_reserve(&scope(), 0, policy().max_entries),
            Err(StoreError::Quota)
        ));
        assert!(matches!(
            coordinator.try_reserve(&scope(), u64::MAX, 0),
            Err(StoreError::Quota)
        ));
    }

    #[test]
    #[ignore = "opt-in native Windows private hard-link and catalog-depth refusal; retained fixture"]
    fn legacy_accounting_refuses_hardlink_aliases_and_flat_catalog_subdirectories() {
        let state = fixture();
        let catalogs = child(&state, LEGACY_SCOPES);
        blob(&catalogs, "plain", b"accounted ciphertext bytes");
        std::fs::hard_link(
            catalogs.path().join("plain"),
            state.path().join("external-alias"),
        )
        .unwrap();
        assert_eq!(
            legacy_recovery_usage(&state, policy()),
            Err(StoreError::CorruptEvidence)
        );
        let second = fixture();
        let catalogs = child(&second, LEGACY_SCOPES);
        let _unexpected = child(&catalogs, "a-child-directory");
        assert_eq!(
            legacy_recovery_usage(&second, policy()),
            Err(StoreError::CorruptEvidence)
        );
    }
}

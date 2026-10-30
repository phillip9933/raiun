//! Read-only observations of authenticated snapshot metadata and event history.
//! No eligibility, deletion, native completion or upload authority is provided.
use super::{SnapshotStore, StoreError, StreamedAttemptState};

/// Aggregate metadata for one observed historical-record class. No captured
/// path, account identifier or record-selection capability is returned.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetainedRecordObservation {
    pub record_count: u64,
    /// Sum of manifest plaintext lengths, including repeated content in distinct
    /// historical saves. Not disk usage, reserved capacity or reclaimable bytes.
    pub logical_content_bytes: u64,
}

impl RetainedRecordObservation {
    fn add(&mut self, logical_content_bytes: u64) -> Result<(), StoreError> {
        let record_count = self
            .record_count
            .checked_add(1)
            .ok_or(StoreError::ScanLimit)?;
        let bytes = self
            .logical_content_bytes
            .checked_add(logical_content_bytes)
            .ok_or(StoreError::ScanLimit)?;
        self.record_count = record_count;
        self.logical_content_bytes = bytes;
        Ok(())
    }
}

/// Non-atomic observation of existing bounded discovery, not a coherent global
/// or quota snapshot. Histories may change while different records are read.
/// Current body bytes are NOT authenticated. Historical local acknowledgement
/// grants no cleanup eligibility or current remote/native completion authority.
/// This API changes no retention policy and promises no secure erasure.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetainedRecordsInspection {
    pub never_attempted: RetainedRecordObservation,
    pub unresolved: RetainedRecordObservation,
    pub remote_verified_only: RetainedRecordObservation,
    pub historical_local_acknowledged: RetainedRecordObservation,
}

impl SnapshotStore {
    /// Inspect this store's selected scope through `discover_records`, preserving
    /// its discovery budgets and every scan/authentication failure. Reads only
    /// metadata/history and body entry metadata; does not verify current body
    /// content, take new locks, create files or initiate any remote/native work.
    /// Logical plaintext totals are not filesystem usage or reclaimable capacity.
    pub fn inspect_retained_records(&self) -> Result<RetainedRecordsInspection, StoreError> {
        let mut inspection = RetainedRecordsInspection::default();
        for record in self.discover_records()? {
            let class = match record.state {
                StreamedAttemptState::NotAttempted => &mut inspection.never_attempted,
                StreamedAttemptState::Uncertain { .. }
                | StreamedAttemptState::Conflict { .. }
                | StreamedAttemptState::Ambiguous { .. }
                | StreamedAttemptState::Deferred { .. } => &mut inspection.unresolved,
                StreamedAttemptState::VerifiedApplied { .. } => {
                    &mut inspection.remote_verified_only
                }
                StreamedAttemptState::LocallyAcknowledged { .. } => {
                    &mut inspection.historical_local_acknowledged
                }
            };
            class.add(record.manifest.binding().content_len)?;
        }
        Ok(inspection)
    }
}

#[cfg(test)]
mod arithmetic_tests {
    use super::*;

    #[test]
    fn checked_totals_fail_without_partially_changing_a_class() {
        for original in [
            RetainedRecordObservation {
                record_count: u64::MAX,
                logical_content_bytes: 0,
            },
            RetainedRecordObservation {
                record_count: 1,
                logical_content_bytes: u64::MAX,
            },
        ] {
            let mut observed = original;
            assert_eq!(observed.add(1), Err(StoreError::ScanLimit));
            assert_eq!(observed, original);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::streamed_snapshot::SnapshotBinding;
    use crate::streamed_store::{StorePolicy, StreamedAttemptOutcome, StreamedRecordKey};
    use std::{collections::BTreeMap, fs, io::Cursor, path::Path, sync::Arc};

    fn policy() -> StorePolicy {
        StorePolicy {
            max_content_bytes: 1024 * 1024,
            max_state_bytes: 64 * 1024 * 1024,
            max_entries: 2048,
            max_metadata_bytes_per_scan: 4 * 1024 * 1024,
        }
    }

    fn capture(store: &Arc<SnapshotStore>, bytes: u64) -> StreamedRecordKey {
        let binding = SnapshotBinding {
            record_id: String::new(),
            scope: store.scope.clone(),
            generation: 3,
            local_file: crate::LocalFileIdentity {
                volume_serial: 1,
                file_index: 4,
            },
            relative_path: "synthetic.txt".into(),
            remote: None,
            content_len: bytes,
        };
        let reservation = store.try_begin_capture(binding).unwrap();
        let id = reservation.binding().record_id.clone();
        reservation
            .capture(&mut Cursor::new(vec![7; bytes as usize]), &mut || false)
            .unwrap()
            .verify_and_commit(&mut || false)
            .unwrap();
        store.record_key(&id).unwrap()
    }

    fn snapshot(path: &Path) -> BTreeMap<std::path::PathBuf, Vec<u8>> {
        fn collect(base: &Path, path: &Path, output: &mut BTreeMap<std::path::PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    collect(base, &path, output);
                } else {
                    output.insert(
                        path.strip_prefix(base).unwrap().to_owned(),
                        fs::read(path).unwrap(),
                    );
                }
            }
        }
        let mut result = BTreeMap::new();
        collect(path, path, &mut result);
        result
    }

    #[test]
    fn mixed_real_histories_include_native_test_completion_without_mutating_evidence() {
        // Uses the existing synthetic remote-readback/native-token fixture, not
        // a Windows OS ACK. Production completion constructors remain unchanged.
        let (temp, store, _key, proof) = crate::streamed_reconcile::tests::bridge_fixture();
        let bridged = crate::VerifiedEditReadback::from_streamed(proof).unwrap();
        let completion =
            crate::CompletedLocalEdit::from_verified_native_completion(&bridged).unwrap();
        bridged
            .streamed_backing()
            .unwrap()
            .lock()
            .unwrap()
            .acknowledge_native(&completion)
            .unwrap();
        drop(completion);
        drop(bridged);
        capture(&store, 0);
        capture(&store, 10);
        let uncertain = capture(&store, 11);
        store
            .acquire_dispatch(&uncertain)
            .unwrap()
            .begin_attempt()
            .unwrap();
        for (bytes, outcome) in [
            (12, StreamedAttemptOutcome::Conflict),
            (13, StreamedAttemptOutcome::Ambiguous),
            (14, StreamedAttemptOutcome::Deferred),
            (15, StreamedAttemptOutcome::VerifiedApplied),
        ] {
            let key = capture(&store, bytes);
            let mut lease = store.acquire_dispatch(&key).unwrap();
            lease.begin_attempt().unwrap();
            lease.finish_outcome(1, 1, outcome).unwrap();
        }
        let before = snapshot(temp.path());
        let observed = store.inspect_retained_records().unwrap();
        assert_eq!(
            observed.never_attempted,
            RetainedRecordObservation {
                record_count: 2,
                logical_content_bytes: 10
            }
        );
        assert_eq!(
            observed.unresolved,
            RetainedRecordObservation {
                record_count: 4,
                logical_content_bytes: 50
            }
        );
        assert_eq!(
            observed.remote_verified_only,
            RetainedRecordObservation {
                record_count: 1,
                logical_content_bytes: 15
            }
        );
        assert_eq!(
            observed.historical_local_acknowledged,
            RetainedRecordObservation {
                record_count: 1,
                logical_content_bytes: 3
            }
        );
        assert_eq!(store.inspect_retained_records().unwrap(), observed);
        assert_eq!(snapshot(temp.path()), before);
    }

    #[test]
    fn empty_observation_does_not_initialize_files_or_locks() {
        let (temp, store) = super::super::synthetic_test_store(policy());
        let before = snapshot(temp.path());
        assert_eq!(
            store.inspect_retained_records().unwrap(),
            RetainedRecordsInspection::default()
        );
        assert_eq!(snapshot(temp.path()), before);
    }

    #[test]
    fn discovery_entry_budget_failure_is_not_an_empty_or_partial_summary() {
        let (temp, store) = super::super::synthetic_test_store(policy());
        capture(&store, 10);
        let limited = SnapshotStore::from_directory(
            Arc::clone(&store.root),
            store.scope.clone(),
            Arc::clone(&store.protector),
            StorePolicy {
                max_entries: 4,
                ..policy()
            },
        )
        .unwrap();
        let before = snapshot(temp.path());
        assert_eq!(
            limited.inspect_retained_records(),
            Err(StoreError::ScanLimit)
        );
        assert_eq!(snapshot(temp.path()), before);
    }

    #[test]
    fn malformed_history_and_body_entry_metadata_propagate_without_mutation() {
        for failure in ["history", "body_length", "manifest", "scope"] {
            let (temp, store) = super::super::synthetic_test_store(policy());
            let key = capture(&store, 10);
            let directory = temp.path().join(&store.key);
            match failure {
                "history" => {
                    let mut lease = store.acquire_dispatch(&key).unwrap();
                    lease.begin_attempt().unwrap();
                    fs::write(
                        directory.join(format!("{}.event.{:020}", key.record_id(), 1)),
                        b"torn",
                    )
                    .unwrap();
                }
                "body_length" => fs::write(
                    directory.join(format!("{}.body", key.record_id())),
                    b"short",
                )
                .unwrap(),
                "manifest" => fs::write(
                    directory.join(format!("{}.manifest", key.record_id())),
                    b"torn",
                )
                .unwrap(),
                _ => fs::write(temp.path().join(format!("{}.scope", store.key)), b"torn").unwrap(),
            }
            let before = snapshot(temp.path());
            assert!(store.inspect_retained_records().is_err(), "{failure}");
            assert_eq!(snapshot(temp.path()), before);
        }
    }

    #[test]
    fn same_length_body_corruption_is_not_detected_by_metadata_observation() {
        let (temp, store) = super::super::synthetic_test_store(policy());
        let key = capture(&store, 10);
        let body = temp
            .path()
            .join(&store.key)
            .join(format!("{}.body", key.record_id()));
        let mut bytes = fs::read(&body).unwrap();
        bytes[0] ^= 1;
        fs::write(&body, bytes).unwrap();
        let before = snapshot(temp.path());
        assert_eq!(
            store
                .inspect_retained_records()
                .unwrap()
                .never_attempted
                .logical_content_bytes,
            10
        );
        assert_eq!(snapshot(temp.path()), before);
        assert!(store.open_verified_key(&key, &mut || false).is_err());
    }
}

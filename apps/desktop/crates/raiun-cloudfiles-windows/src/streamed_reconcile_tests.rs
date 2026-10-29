use super::*;
use crate::{
    LocalFileIdentity,
    streamed_snapshot::SnapshotBinding,
    streamed_store::{StorePolicy, synthetic_test_store},
};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

fn scope() -> EditJournalScope {
    EditJournalScope {
        profile_id: "synthetic".into(),
        server_origin: "https://synthetic.invalid".into(),
        account_subject: "subject".into(),
        space_id: "personal".into(),
        root_resource_id: "root".into(),
        root_volume_serial: 1,
        root_file_index: 2,
    }
}
fn policy() -> StorePolicy {
    StorePolicy {
        max_content_bytes: 64 * 1024 * 1024,
        max_state_bytes: 256 * 1024 * 1024,
        max_entries: 2048,
        max_metadata_bytes_per_scan: 4 * 1024 * 1024,
    }
}
struct Generated(u64);
impl Read for Generated {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.0.min(out.len() as u64) as usize;
        out[..n].fill(b'x');
        self.0 -= n as u64;
        Ok(n)
    }
}
fn capture(store: &Arc<SnapshotStore>, length: u64, generation: u64) -> StreamedRecordKey {
    let binding = SnapshotBinding {
        record_id: String::new(),
        scope: scope(),
        generation,
        local_file: LocalFileIdentity {
            volume_serial: 1,
            file_index: 4,
        },
        relative_path: "doc.bin".into(),
        remote: Some(RemoteEditBaseline {
            resource_id: "file".into(),
            etag: "\"v1\"".into(),
            byte_len: 1,
        }),
        content_len: length,
    };
    let committed = store
        .try_begin_capture(binding)
        .unwrap()
        .capture(&mut Generated(length), &mut || false)
        .unwrap()
        .verify_and_commit(&mut || false)
        .unwrap();
    store
        .record_key(&committed.manifest().binding().record_id)
        .unwrap()
}
fn version() -> RecoveryRemoteVersion {
    RecoveryRemoteVersion {
        resource_id: "file".into(),
        etag: "\"v1\"".into(),
        size: 1,
        is_directory: false,
        encrypted: false,
        writable: true,
    }
}
#[derive(Clone, Copy)]
enum Behavior {
    Apply,
    LostApplied,
    Transient,
    Forbidden,
    Changed,
}
struct State {
    version: RecoveryRemoteVersion,
    sha: [u8; 32],
    behaviors: VecDeque<Behavior>,
    puts: u8,
    stats: u8,
    reads: u8,
    max_read: usize,
    fail_read: bool,
    revoke_read: bool,
}
struct Remote {
    store: Arc<SnapshotStore>,
    key: StreamedRecordKey,
    state: Mutex<State>,
    authorized: AtomicBool,
}
impl Remote {
    fn new(store: &Arc<SnapshotStore>, key: &StreamedRecordKey, behaviors: &[Behavior]) -> Self {
        Self {
            store: store.clone(),
            key: key.clone(),
            state: Mutex::new(State {
                version: version(),
                sha: [0; 32],
                behaviors: behaviors.iter().copied().collect(),
                puts: 0,
                stats: 0,
                reads: 0,
                max_read: 0,
                fail_read: false,
                revoke_read: false,
            }),
            authorized: AtomicBool::new(true),
        }
    }
    fn applied(&self) {
        let pin = self
            .store
            .open_verified_key(&self.key, &mut || false)
            .unwrap();
        let mut s = self.state.lock().unwrap();
        s.version.etag = "\"v2\"".into();
        s.version.size = pin.manifest().binding().content_len;
        s.sha = *pin.manifest().content_sha256();
    }
}
impl StreamedRecoveryRemote for Remote {
    fn server_origin(&self) -> &str {
        "https://synthetic.invalid"
    }
    fn ensure_authorized(
        &self,
        expected: &EditJournalScope,
        generation: u64,
    ) -> Result<(), CloudError> {
        if self.authorized.load(Ordering::Acquire) && expected == &scope() && generation == 3 {
            Ok(())
        } else {
            Err(CloudError::new(
                ErrorKind::Unauthorized,
                "synthetic revoked",
            ))
        }
    }
    fn stat(
        &self,
        expected: &EditJournalScope,
        path: &str,
    ) -> Result<RecoveryRemoteVersion, CloudError> {
        self.ensure_authorized(expected, 3)?;
        assert_eq!(path, "doc.bin");
        let mut s = self.state.lock().unwrap();
        s.stats += 1;
        Ok(s.version.clone())
    }
    fn conditional_upload(
        &self,
        expected: &EditJournalScope,
        path: &str,
        mut source: Box<dyn Read + Send>,
        baseline: &RemoteEditBaseline,
        length: u64,
        sha: [u8; 32],
    ) -> Result<StreamedRemoteDigest, CloudError> {
        self.ensure_authorized(expected, 3)?;
        assert_eq!(path, "doc.bin");
        assert_eq!(baseline.etag, "\"v1\"");
        assert_eq!(baseline.resource_id, "file");
        assert_eq!(baseline.byte_len, 1);
        let selected = self
            .store
            .discover_records()
            .unwrap()
            .into_iter()
            .find(|m| m.key == self.key)
            .unwrap();
        assert!(
            matches!(selected.state, StreamedAttemptState::Uncertain { .. }),
            "Attempting must be durable before PUT"
        );
        let behavior = {
            let mut s = self.state.lock().unwrap();
            s.puts += 1;
            s.behaviors.pop_front().unwrap_or(Behavior::Apply)
        };
        if matches!(behavior, Behavior::Transient) {
            return Err(CloudError::new(ErrorKind::Offline, "synthetic transient"));
        }
        if matches!(behavior, Behavior::Forbidden) {
            return Err(CloudError::new(ErrorKind::Forbidden, "synthetic refusal"));
        }
        if matches!(behavior, Behavior::Changed) {
            let mut s = self.state.lock().unwrap();
            s.version.etag = "\"competitor\"".into();
            return Err(CloudError::new(ErrorKind::Offline, "synthetic uncertain"));
        }
        let mut buffer = [0; 8191];
        let mut count = 0;
        let mut hash = Sha256::new();
        loop {
            let n = source.read(&mut buffer).unwrap();
            if n == 0 {
                break;
            }
            count += n as u64;
            hash.update(&buffer[..n]);
            self.state.lock().unwrap().max_read = 8191;
        }
        assert_eq!(count, length);
        assert_eq!(<[u8; 32]>::from(hash.finalize()), sha);
        let mut s = self.state.lock().unwrap();
        s.version.etag = "\"v2\"".into();
        s.version.size = length;
        s.sha = sha;
        if matches!(behavior, Behavior::LostApplied) {
            return Err(CloudError::new(
                ErrorKind::Offline,
                "synthetic response loss",
            ));
        }
        Ok(StreamedRemoteDigest {
            version: s.version.clone(),
            bytes: length,
            sha256: sha,
        })
    }
    fn read_digest(
        &self,
        expected: &EditJournalScope,
        path: &str,
        id: &str,
        etag: &str,
        _length: u64,
        _sha: [u8; 32],
    ) -> Result<StreamedRemoteDigest, CloudError> {
        self.ensure_authorized(expected, 3)?;
        assert_eq!(path, "doc.bin");
        assert_eq!(id, "file");
        let mut s = self.state.lock().unwrap();
        s.reads += 1;
        assert_eq!(etag, s.version.etag);
        if s.revoke_read {
            self.authorized.store(false, Ordering::Release);
        }
        if s.fail_read {
            return Err(CloudError::new(
                ErrorKind::Offline,
                "synthetic read failure",
            ));
        }
        Ok(StreamedRemoteDigest {
            version: s.version.clone(),
            bytes: s.version.size,
            sha256: s.sha,
        })
    }
}
fn recovered(
    store: &Arc<SnapshotStore>,
    key: &StreamedRecordKey,
    remote: &Remote,
) -> Result<StreamedReconciliationResult, StoreError> {
    reconcile_recovered_streamed_edit(
        store,
        key,
        &scope(),
        remote,
        ExplicitRecoveryApproval::user_reviewed(),
        Arc::new(|| false),
    )
}
#[test]
fn generated_large_snapshot_is_verified_and_exact_lock_pin_retained_in_opaque_proof() {
    let (_dir, store) = synthetic_test_store(policy());
    let key = capture(&store, 17 * 1024 * 1024 + 7, 3);
    let remote = Remote::new(&store, &key, &[Behavior::Apply]);
    let result = reconcile_streamed_edit(
        &store,
        &key,
        &scope(),
        &remote,
        StreamedAdmission::Fresh,
        Arc::new(|| false),
    )
    .unwrap();
    assert_eq!(
        result.outcome,
        ReconciliationOutcome::VerifiedApplied { attempts: 1 }
    );
    let proof = result.verified.unwrap();
    assert_eq!(proof.key(), &key);
    assert_eq!(proof.manifest().binding().content_len, 17 * 1024 * 1024 + 7);
    assert_eq!(proof.remote_version().etag, "\"v2\"");
    assert_eq!(format!("{proof:?}"), "VerifiedStreamedReadback([BOUND])");
    assert!(matches!(
        store.acquire_dispatch(&key),
        Err(StoreError::Busy)
    ));
    assert!(remote.state.lock().unwrap().max_read <= 8191);
    drop(proof);
    assert!(matches!(
        store
            .acquire_dispatch(&key)
            .unwrap()
            .current_state()
            .unwrap(),
        StreamedAttemptState::VerifiedApplied { attempts: 1, .. }
    ));
    assert_eq!(store.discover_records().unwrap().len(), 1);
}
#[test]
fn retries_are_bounded_and_always_keep_original_condition() {
    for (behaviors, puts, expected) in [
        (
            &[Behavior::Transient, Behavior::Apply][..],
            2,
            ReconciliationOutcome::VerifiedApplied { attempts: 2 },
        ),
        (
            &[Behavior::Transient, Behavior::Transient][..],
            2,
            ReconciliationOutcome::Deferred,
        ),
        (
            &[Behavior::Forbidden][..],
            1,
            ReconciliationOutcome::Deferred,
        ),
        (
            &[Behavior::Changed][..],
            1,
            ReconciliationOutcome::Conflict(ReconciliationIssue::ContentMismatch),
        ),
    ] {
        let (_dir, store) = synthetic_test_store(policy());
        let key = capture(&store, 3, 3);
        let remote = Remote::new(&store, &key, behaviors);
        let result = recovered(&store, &key, &remote).unwrap();
        assert_eq!(result.outcome, expected);
        assert_eq!(remote.state.lock().unwrap().puts, puts);
        assert_eq!(store.discover_records().unwrap().len(), 1);
    }
}
#[test]
fn lost_response_reconciles_with_digest_and_uncertain_restart_never_becomes_fresh() {
    let (_dir, store) = synthetic_test_store(policy());
    let key = capture(&store, 3, 3);
    let remote = Remote::new(&store, &key, &[Behavior::LostApplied]);
    let result = recovered(&store, &key, &remote).unwrap();
    assert_eq!(
        result.outcome,
        ReconciliationOutcome::VerifiedApplied { attempts: 1 }
    );
    assert_eq!(remote.state.lock().unwrap().reads, 1);
    drop(result);
    let (_dir, store) = synthetic_test_store(policy());
    let key = capture(&store, 3, 3);
    let mut lease = store.acquire_dispatch(&key).unwrap();
    assert_eq!(lease.begin_attempt().unwrap(), 1);
    drop(lease);
    let remote = Remote::new(&store, &key, &[]);
    remote.applied();
    assert!(
        reconcile_streamed_edit(
            &store,
            &key,
            &scope(),
            &remote,
            StreamedAdmission::Fresh,
            Arc::new(|| false)
        )
        .is_err()
    );
    assert_eq!(remote.state.lock().unwrap().stats, 0);
    let result = recovered(&store, &key, &remote).unwrap();
    assert_eq!(
        result.outcome,
        ReconciliationOutcome::VerifiedApplied { attempts: 0 }
    );
    assert!(result.verified.is_some());
    assert_eq!(remote.state.lock().unwrap().puts, 0);
}
#[test]
fn mandatory_authorization_wrong_generation_scope_key_and_corrupt_body_refuse_http() {
    let (_dir, store) = synthetic_test_store(policy());
    let key = capture(&store, 3, 3);
    let remote = Remote::new(&store, &key, &[]);
    remote.authorized.store(false, Ordering::Release);
    assert_eq!(
        recovered(&store, &key, &remote).unwrap().outcome,
        ReconciliationOutcome::Deferred
    );
    assert_eq!(remote.state.lock().unwrap().stats, 0);
    let (_dir, other) = synthetic_test_store(policy());
    let wrong = capture(&other, 3, 3);
    assert!(recovered(&store, &wrong, &remote).is_err());
    let mut wrongscope = scope();
    wrongscope.root_resource_id = "other".into();
    assert!(
        reconcile_streamed_edit(
            &store,
            &key,
            &wrongscope,
            &remote,
            StreamedAdmission::Fresh,
            Arc::new(|| false)
        )
        .is_err()
    );
    let (_dir, store) = synthetic_test_store(policy());
    let key = capture(&store, 3, 4);
    let remote = Remote::new(&store, &key, &[]);
    assert_eq!(
        recovered(&store, &key, &remote).unwrap().outcome,
        ReconciliationOutcome::Deferred
    );
    assert_eq!(remote.state.lock().unwrap().stats, 0);
    let (dir, store) = synthetic_test_store(policy());
    let key = capture(&store, 3, 3);
    let remote = Remote::new(&store, &key, &[]);
    let scope_dir = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.file_type().unwrap().is_dir())
        .unwrap()
        .path();
    let body = scope_dir.join(format!("{}.body", key.record_id()));
    std::fs::OpenOptions::new()
        .write(true)
        .open(body)
        .unwrap()
        .write_all(b"!")
        .unwrap();
    assert!(recovered(&store, &key, &remote).is_err());
    assert_eq!(remote.state.lock().unwrap().stats, 0);
    assert_eq!(remote.state.lock().unwrap().puts, 0);
}
#[test]
fn changed_resource_roles_and_readback_revocation_cannot_mint_proof() {
    for mode in 0..4 {
        let (_dir, store) = synthetic_test_store(policy());
        let key = capture(&store, 3, 3);
        let remote = Remote::new(&store, &key, &[]);
        {
            let mut s = remote.state.lock().unwrap();
            match mode {
                0 => s.version.resource_id = "other".into(),
                1 => s.version.writable = false,
                2 => s.version.encrypted = true,
                _ => {
                    s.version.etag = "\"v2\"".into();
                    s.version.size = 3;
                    s.sha = [7; 32];
                    s.revoke_read = true;
                }
            }
        }
        let result = recovered(&store, &key, &remote).unwrap();
        assert!(result.verified.is_none());
        assert!(!matches!(
            result.outcome,
            ReconciliationOutcome::VerifiedApplied { .. }
        ));
        assert_eq!(remote.state.lock().unwrap().puts, 0);
    }
}
#[test]
fn verified_history_requires_new_readback_and_failed_recheck_keeps_historical_state() {
    let (_dir, store) = synthetic_test_store(policy());
    let key = capture(&store, 3, 3);
    let remote = Remote::new(&store, &key, &[Behavior::Apply]);
    let result = recovered(&store, &key, &remote).unwrap();
    drop(result);
    remote.state.lock().unwrap().fail_read = true;
    let result = recovered(&store, &key, &remote).unwrap();
    assert_eq!(result.outcome, ReconciliationOutcome::Ambiguous);
    assert!(result.verified.is_none());
    assert_eq!(remote.state.lock().unwrap().puts, 1);
    assert!(matches!(
        store.discover_records().unwrap()[0].state,
        StreamedAttemptState::VerifiedApplied { attempts: 1, .. }
    ));
}

#[test]
fn fresh_changed_revision_can_verify_zero_put_without_rebasing_or_false_digest() {
    for correct_digest in [true, false] {
        let (_dir, store) = synthetic_test_store(policy());
        let key = capture(&store, 3, 3);
        let remote = Remote::new(&store, &key, &[]);
        remote.applied();
        if !correct_digest {
            remote.state.lock().unwrap().sha = [9; 32];
        }
        let result = reconcile_streamed_edit(
            &store,
            &key,
            &scope(),
            &remote,
            StreamedAdmission::Fresh,
            Arc::new(|| false),
        )
        .unwrap();
        assert_eq!(remote.state.lock().unwrap().puts, 0);
        assert_eq!(remote.state.lock().unwrap().reads, 1);
        if correct_digest {
            assert_eq!(
                result.outcome,
                ReconciliationOutcome::VerifiedApplied { attempts: 0 }
            );
            assert!(result.verified.is_some());
        } else {
            assert_eq!(
                result.outcome,
                ReconciliationOutcome::Conflict(ReconciliationIssue::ContentMismatch)
            );
            assert!(result.verified.is_none());
        }
    }
}

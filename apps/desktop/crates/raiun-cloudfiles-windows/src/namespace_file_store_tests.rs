//! Injected Unix disk storage, not native Windows admission or server evidence.
use super::*;
use crate::namespace_intent::{
    CapturedAuthorization, LocalNamespaceEntry, NamespaceFileContent, NamespaceObjectKind,
    NamespaceParent, StorageClassification,
};
use crate::{LocalFileIdentity, RemoteEditBaseline};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[test]
fn own_pending_snapshot_keeps_initial_clean_fence_but_late_close_invalidates() {
    use crate::{
        close_capture_admission::CloseCaptureAdmission, save_rename_admission::SaveRenameAdmission,
    };
    let (_temp, base, files, _) = fixture();
    let tracker = Arc::new(CloseCaptureAdmission::default());
    let ticket = tracker.try_begin_rename().unwrap();
    let (_, lifetime) = ticket.dispatch_probe(tracker.clone()).unwrap();
    let guard = SaveRenameAdmission::new(ticket);
    let _lifetime = lifetime;
    let observation = _lifetime.observation_probe();
    assert!(guard.probe_clean(|| base.discover_records().map(|records| !records.is_empty())));
    let _fresh = files
        .publish_fresh(draft(&base, 1), commit(&base, 1), mapping(), &mut || false)
        .unwrap();
    let records = base.discover_records().unwrap();
    assert_eq!(records.len(), 1);
    assert!(!matches!(
        records[0].state,
        StreamedAttemptState::LocallyAcknowledged { .. }
    ));
    assert!(
        !guard.probe_clean(|| base.discover_records().map(|records| !records.is_empty())),
        "generic content scan sees own Pending body"
    );
    assert!(
        guard.check().is_ok() && observation(),
        "retained clean fence permits only own newly published body"
    );
    let mut close = tracker.begin_close();
    close.finish_clean();
    assert!(
        guard.check().is_ok(),
        "old rename clean-close behavior is unchanged"
    );
    assert!(
        !observation(),
        "new create conservatively refuses even an intervening clean close"
    );
}

#[test]
fn connected_create_remote_verified_prefix_reopens_unresolved_without_replay_or_completion() {
    let (_temp, base, files, _) = fixture();
    let publication = files
        .publish_fresh(draft(&base, 1), commit(&base, 1), mapping(), &mut || false)
        .unwrap();
    let key = publication.record().key().clone();
    let intent = publication.record().intent().clone();
    let NamespaceOperation::CreateFile {
        destination,
        content,
    } = intent.operation
    else {
        unreachable!()
    };
    let mut lease = files.acquire_dispatch(&key).unwrap();
    lease.mark_submitted().unwrap();
    let report = crate::namespace_intent::NamespaceDestinationReport {
        destination: destination.clone(),
        remote: RemoteEditBaseline {
            resource_id: "created-file".into(),
            etag: "\"created-v1\"".into(),
            byte_len: 1,
        },
        content: Some(content),
    };
    let mut wrong = report.clone();
    wrong.destination.name = "different.bin".into();
    assert!(
        lease
            .append(NamespaceEventKind::RemoteVerified { report: wrong })
            .is_err()
    );
    lease
        .append(NamespaceEventKind::RemoteVerified { report })
        .unwrap();
    assert_eq!(lease.progress().remote, NamespacePhase::Verified);
    assert!(!lease.progress().recorded_complete);
    assert!(
        lease
            .append(NamespaceEventKind::LocalCompleted { destination })
            .is_err()
    );
    drop(lease);
    let reopened = FileCreateStore::new(base).unwrap();
    let retained = reopened.discover().unwrap().pop().unwrap();
    assert_eq!(retained.progress().remote, NamespacePhase::Verified);
    assert!(!retained.progress().recorded_complete);
    assert!(
        reopened
            .acquire_dispatch(&key)
            .unwrap()
            .mark_submitted()
            .is_err()
    );
}

fn policy() -> StorePolicy {
    StorePolicy {
        max_content_bytes: 32 * 1024 * 1024,
        max_state_bytes: 256 * 1024 * 1024,
        max_entries: 2048,
        max_metadata_bytes_per_scan: 8 * 1024 * 1024,
    }
}
#[derive(Default)]
struct Observation {
    quota: AtomicBool,
    bad_body_reads: AtomicUsize,
    body_reads: AtomicUsize,
    fail_intent: AtomicBool,
    fail_event: AtomicBool,
    external_bytes: AtomicUsize,
}
struct Disk {
    inner: Arc<dyn Directory>,
    observation: Arc<Observation>,
}
impl Directory for Disk {
    fn verify(&self) -> Result<(), StoreError> {
        self.inner.verify()
    }
    fn external_recovery_usage(&self, p: StorePolicy) -> Result<(u64, usize), StoreError> {
        let (bytes, entries) = self.inner.external_recovery_usage(p)?;
        Ok((
            bytes
                .checked_add(self.observation.external_bytes.load(Ordering::SeqCst) as u64)
                .ok_or(StoreError::Quota)?,
            entries,
        ))
    }
    fn entries(&self, limit: usize) -> Result<Vec<String>, StoreError> {
        self.inner.entries(limit)
    }
    fn child(&self, name: &str, create: bool) -> Result<Arc<dyn Directory>, StoreError> {
        Ok(Arc::new(Self {
            inner: self.inner.child(name, create)?,
            observation: self.observation.clone(),
        }))
    }
    fn create(&self, name: &str) -> Result<(Box<dyn StageWrite>, Identity), StoreError> {
        self.inner.create(name)
    }
    fn open(&self, name: &str) -> Result<Box<dyn PinnedRead>, StoreError> {
        Ok(Box::new(Pin {
            inner: self.inner.open(name)?,
            observation: self.observation.clone(),
            quota: name == V2_QUOTA_LOCK,
            body: name.ends_with(".body") || name.ends_with(".body.stage"),
            locked: false,
        }))
    }
    fn publish(&self, stage: &str, final_name: &str, id: Identity) -> Result<(), StoreError> {
        if final_name.ends_with(".intent")
            && self.observation.fail_intent.swap(false, Ordering::SeqCst)
        {
            return Err(StoreError::Io);
        }
        if final_name.contains(".event.")
            && self.observation.fail_event.swap(false, Ordering::SeqCst)
        {
            return Err(StoreError::Io);
        }
        self.inner.publish(stage, final_name, id)
    }
}
struct Pin {
    inner: Box<dyn PinnedRead>,
    observation: Arc<Observation>,
    quota: bool,
    body: bool,
    locked: bool,
}
impl Read for Pin {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.body {
            self.observation.body_reads.fetch_add(1, Ordering::SeqCst);
            if self.observation.quota.load(Ordering::SeqCst) {
                self.observation
                    .bad_body_reads
                    .fetch_add(1, Ordering::SeqCst);
            }
        }
        self.inner.read(out)
    }
}
impl Seek for Pin {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}
impl PinnedRead for Pin {
    fn identity(&self) -> Identity {
        self.inner.identity()
    }
    fn len(&self) -> Result<u64, StoreError> {
        self.inner.len()
    }
    fn verify(&self) -> Result<(), StoreError> {
        self.inner.verify()
    }
    fn lock_exclusive(&mut self) -> Result<(), StoreError> {
        self.inner.lock_exclusive()?;
        self.locked = true;
        if self.quota {
            self.observation.quota.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
}
impl Drop for Pin {
    fn drop(&mut self) {
        if self.quota && self.locked {
            self.observation.quota.store(false, Ordering::SeqCst);
        }
    }
}
fn fixture() -> (
    tempfile::TempDir,
    Arc<SnapshotStore>,
    Arc<FileCreateStore>,
    Arc<Observation>,
) {
    let (temp, base) = synthetic_test_store(policy());
    let observation = Arc::new(Observation::default());
    let base = SnapshotStore::from_directory(
        Arc::new(Disk {
            inner: base.root.clone(),
            observation: observation.clone(),
        }),
        base.scope.clone(),
        base.protector.clone(),
        base.policy,
    )
    .unwrap();
    let files = FileCreateStore::new(base.clone()).unwrap();
    (temp, base, files, observation)
}
fn byte(offset: u64) -> u8 {
    (offset.wrapping_mul(37) % 251) as u8
}
struct Generated {
    position: u64,
    length: u64,
}
impl Read for Generated {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = (self.length - self.position).min(out.len() as u64) as usize;
        for (i, b) in out[..n].iter_mut().enumerate() {
            *b = byte(self.position + i as u64);
        }
        self.position += n as u64;
        Ok(n)
    }
}
fn hash(length: u64) -> String {
    let mut h = Sha256::new();
    let mut source = Generated {
        position: 0,
        length,
    };
    let mut b = [0; 64 * 1024];
    loop {
        let n = source.read(&mut b).unwrap();
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    hex(&h.finalize())
}
fn binding(base: &SnapshotStore, len: u64) -> SnapshotBinding {
    SnapshotBinding {
        record_id: String::new(),
        scope: base.scope.clone(),
        generation: 9,
        local_file: LocalFileIdentity {
            volume_serial: 1,
            file_index: 42,
        },
        relative_path: "folder/new.bin".into(),
        remote: None,
        content_len: len,
    }
}
fn commit(base: &Arc<SnapshotStore>, len: u64) -> CommittedSnapshot {
    base.try_begin_capture(binding(base, len))
        .unwrap()
        .capture(
            &mut Generated {
                position: 0,
                length: len,
            },
            &mut || false,
        )
        .unwrap()
        .verify_and_commit(&mut || false)
        .unwrap()
}
fn draft(base: &SnapshotStore, len: u64) -> NamespaceIntent {
    NamespaceIntent {
        schema_version: 1,
        record_id: "0".repeat(32),
        record_generation: 9,
        operation: NamespaceOperation::CreateFile {
            destination: LocalNamespaceEntry {
                parent: NamespaceParent {
                    scope: base.scope.clone(),
                    authorization: CapturedAuthorization {
                        agent_generation: 9,
                        token_generation: 4,
                    },
                    classification: StorageClassification::Ordinary,
                    local_file: LocalFileIdentity {
                        volume_serial: 1,
                        file_index: 41,
                    },
                    local_components: vec!["Personal".into(), "folder".into()],
                    remote: RemoteEditBaseline {
                        resource_id: "parent".into(),
                        etag: "\"parent-v1\"".into(),
                        byte_len: 0,
                    },
                },
                name: "new.bin".into(),
                local_file: LocalFileIdentity {
                    volume_serial: 1,
                    file_index: 42,
                },
                object_kind: NamespaceObjectKind::File,
            },
            content: NamespaceFileContent {
                byte_len: len,
                sha256: hash(len),
            },
        },
    }
}
fn mapping() -> CapturedCreatePath {
    CapturedCreatePath::new(
        vec!["Personal".into(), "folder".into(), "new.bin".into()],
        "folder/new.bin".into(),
    )
    .unwrap()
}

#[test]
fn zero_and_large_join_authenticate_before_quota_and_discover_without_body_reads() {
    for len in [0, 17 * 1024 * 1024 + 7] {
        let (_temp, base, files, observation) = fixture();
        let receipt = commit(&base, len);
        let snapshot_id = receipt.manifest().binding().record_id.clone();
        observation.bad_body_reads.store(0, Ordering::SeqCst);
        let published = files
            .publish_fresh(draft(&base, len), receipt, mapping(), &mut || false)
            .unwrap();
        assert_ne!(published.record().key().record_id(), snapshot_id);
        assert_eq!(published.record().snapshot_id(), snapshot_id);
        assert_eq!(
            observation.bad_body_reads.load(Ordering::SeqCst),
            0,
            "join must not read payload under quota"
        );
        let key = published.record().key().clone();
        let pin = published.into_verified();
        pin.verify_pin().unwrap();
        drop(pin);
        let before = observation.body_reads.load(Ordering::SeqCst);
        let records = files.discover().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(before, observation.body_reads.load(Ordering::SeqCst));
        assert!(
            base.discover_records().is_ok(),
            "new child must be recognized by existing snapshot discovery"
        );
        let mut verified = files
            .open_joined(&key, &mut || false)
            .unwrap()
            .into_reader(Arc::new(|| false))
            .unwrap();
        let mut h = Sha256::new();
        let mut count = 0u64;
        let mut buffer = [0; 127];
        loop {
            let n = verified.read(&mut buffer).unwrap();
            if n == 0 {
                break;
            }
            count += n as u64;
            h.update(&buffer[..n]);
        }
        assert_eq!(count, len);
        assert_eq!(hex(&h.finalize()), hash(len));
    }
}
#[test]
fn wrong_scope_generation_file_length_hash_and_mapping_never_publish() {
    for variant in 0..7 {
        let (_temp, base, files, _) = fixture();
        let receipt = commit(&base, 3);
        let mut intent = draft(&base, 3);
        let mut path = mapping();
        match variant {
            0 => intent.record_generation += 1,
            1 => {
                if let NamespaceOperation::CreateFile { destination, .. } = &mut intent.operation {
                    destination.parent.scope.account_subject = "foreign".into();
                }
            }
            2 => {
                if let NamespaceOperation::CreateFile { destination, .. } = &mut intent.operation {
                    destination.local_file.file_index += 1;
                }
            }
            3 => {
                if let NamespaceOperation::CreateFile { content, .. } = &mut intent.operation {
                    content.byte_len += 1;
                }
            }
            4 => {
                if let NamespaceOperation::CreateFile { content, .. } = &mut intent.operation {
                    content.sha256 = "a".repeat(64);
                }
            }
            5 => path.space_relative_path = "other/new.bin".into(),
            _ => path.local_components[1] = "other".into(),
        }
        assert!(
            files
                .publish_fresh(intent, receipt, path, &mut || false)
                .is_err()
        );
        assert!(files.discover().unwrap().is_empty());
        assert_eq!(
            base.discover_records().unwrap().len(),
            1,
            "orphan body retained"
        );
    }
}
#[test]
fn fresh_receipt_requires_exact_origin_arc_and_does_not_adopt_copied_store() {
    let (temp, base, _, _) = fixture();
    let receipt = commit(&base, 1);
    // Even same physical root, scope and protector behind a new Arc is NOT the
    // original fresh capture receipt's admitted store instance.
    let other = SnapshotStore::from_directory(
        base.root.clone(),
        base.scope.clone(),
        base.protector.clone(),
        base.policy,
    )
    .unwrap();
    let files = FileCreateStore::new(other).unwrap();
    assert!(
        files
            .publish_fresh(draft(&base, 1), receipt, mapping(), &mut || false)
            .is_err()
    );
    let receipt = commit(&base, 1);
    let (target_temp, target) = synthetic_test_store(policy());
    let target_scope = target_temp.path().join(&base.key);
    std::fs::create_dir(&target_scope).unwrap();
    std::fs::copy(
        temp.path().join(format!("{}.scope", base.key)),
        target_temp.path().join(format!("{}.scope", base.key)),
    )
    .unwrap();
    for entry in std::fs::read_dir(temp.path().join(&base.key)).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), target_scope.join(entry.file_name())).unwrap();
    }
    assert!(
        target.discover_records().is_ok(),
        "copied synthetic metadata is otherwise authentic"
    );
    let files = FileCreateStore::new(target).unwrap();
    assert!(
        files
            .publish_fresh(draft(&base, 1), receipt, mapping(), &mut || false)
            .is_err()
    );
}
#[test]
fn submitted_restart_is_retained_and_cannot_replay_or_publish_duplicate() {
    let (_temp, base, files, _) = fixture();
    let published = files
        .publish_fresh(draft(&base, 1), commit(&base, 1), mapping(), &mut || false)
        .unwrap();
    let key = published.record().key().clone();
    drop(published);
    let mut lease = files.acquire_dispatch(&key).unwrap();
    assert_eq!(files.acquire_dispatch(&key).err(), Some(StoreError::Busy));
    lease.mark_submitted().unwrap();
    assert_eq!(lease.progress().attention, None);
    assert!(lease.mark_submitted().is_err());
    drop(lease);
    let restarted = FileCreateStore::new(base.clone()).unwrap();
    let record = restarted.discover().unwrap().pop().unwrap();
    assert_eq!(record.progress().remote, NamespacePhase::Submitted);
    assert_eq!(
        record.progress().attention,
        Some(NamespaceAttention::Uncertain)
    );
    let mut lease = restarted.acquire_dispatch(&key).unwrap();
    assert_eq!(
        lease.progress().attention,
        Some(NamespaceAttention::Uncertain)
    );
    assert!(lease.mark_submitted().is_err());
    assert!(
        lease
            .record_attention(NamespaceAttention::Deferred)
            .is_err()
    );
    drop(lease);
    let receipt = commit(&base, 1);
    assert!(
        restarted
            .publish_fresh(draft(&base, 1), receipt, mapping(), &mut || false)
            .is_err()
    );
    assert_eq!(restarted.discover().unwrap().len(), 1);
}
#[test]
fn partial_publication_preserves_body_and_stage_and_restarts_fail_closed() {
    let (temp, base, files, observation) = fixture();
    let receipt = commit(&base, 3);
    let id = receipt.manifest().binding().record_id.clone();
    observation.fail_intent.store(true, Ordering::SeqCst);
    assert_eq!(
        files
            .publish_fresh(draft(&base, 3), receipt, mapping(), &mut || false)
            .err(),
        Some(StoreError::PublicationUncertain)
    );
    assert!(
        temp.path()
            .join(&base.key)
            .join(format!("{id}.body"))
            .is_file()
    );
    assert!(
        std::fs::read_dir(temp.path().join(ROOT).join(&base.key))
            .unwrap()
            .any(|e| e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".intent.stage"))
    );
    assert!(
        FileCreateStore::new(base.clone())
            .unwrap()
            .discover()
            .is_err()
    );
    let usage = base.inventory().unwrap();
    assert!(usage.bytes > 3);
    assert!(usage.entries > 4);
}
#[test]
fn quota_and_concurrent_state_writer_never_publish_a_join() {
    let (_temp, base, files, observation) = fixture();
    let receipt = commit(&base, 1);
    let held = base.acquire_lock().unwrap();
    assert_eq!(
        files
            .publish_fresh(draft(&base, 1), receipt, mapping(), &mut || false)
            .err(),
        Some(StoreError::Busy)
    );
    drop(held);
    assert!(files.discover().unwrap().is_empty());
    let receipt = commit(&base, 1);
    observation
        .external_bytes
        .store(base.policy.max_state_bytes as usize, Ordering::SeqCst);
    assert_eq!(
        files
            .publish_fresh(draft(&base, 1), receipt, mapping(), &mut || false)
            .err(),
        Some(StoreError::Quota)
    );
    observation.external_bytes.store(0, Ordering::SeqCst);
    assert!(files.discover().unwrap().is_empty());
}
#[test]
fn sealed_reference_swaps_and_missing_body_are_attention_not_empty() {
    for variant in 0..9 {
        let (temp, base, files, _) = fixture();
        let published = files
            .publish_fresh(draft(&base, 1), commit(&base, 1), mapping(), &mut || false)
            .unwrap();
        let key = published.record().key().clone();
        let mut join = published.record().joined.clone();
        drop(published);
        match variant {
            0 => join.snapshot.manifest_commitment[0] ^= 1,
            1 => join.snapshot.container_sha256[0] ^= 1,
            2 => join.snapshot.space_relative_path = "other/new.bin".into(),
            3 => join.snapshot.id = commit(&base, 1).manifest().binding().record_id.clone(),
            4 => join.snapshot.generation += 1,
            5 => join.snapshot.container_len += 1,
            6 => join.snapshot.content_sha256[0] ^= 1,
            7 => join.snapshot.id = "../outside".into(),
            _ => {
                std::fs::remove_file(
                    temp.path()
                        .join(&base.key)
                        .join(format!("{}.body", join.snapshot.id)),
                )
                .unwrap();
                assert!(files.discover().is_err());
                continue;
            }
        }
        // Synthetic protector reseals a contradictory join; rejecting it must
        // depend on full reference validation, not only MAC integrity.
        let plain = Zeroizing::new(serde_json::to_vec(&join).unwrap());
        let forged = FileCreateKey {
            digest: hex(&join_hash(&plain)),
            ..key.clone()
        };
        let sealed = files.seal(&forged, 0, &[0; 32], &plain).unwrap();
        let envelope = serde_json::to_vec(&Envelope {
            generation: forged.generation,
            digest: forged.digest,
            sealed,
        })
        .unwrap();
        std::fs::write(
            temp.path()
                .join(ROOT)
                .join(&base.key)
                .join(format!("{}.intent", key.id)),
            envelope,
        )
        .unwrap();
        assert!(files.discover().is_err());
        assert!(files.open_joined(&key, &mut || false).is_err());
    }
}
#[test]
fn body_tamper_cancellation_and_existing_remote_baseline_are_never_admitted() {
    let (temp, base, files, _) = fixture();
    let receipt = commit(&base, 2);
    let id = receipt.manifest().binding().record_id.clone();
    let body = temp.path().join(&base.key).join(format!("{id}.body"));
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&body)
        .unwrap();
    file.seek(io::SeekFrom::Start(70)).unwrap();
    let mut byte = [0];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 1;
    file.seek(io::SeekFrom::Start(70)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(
        files
            .publish_fresh(draft(&base, 2), receipt, mapping(), &mut || false)
            .is_err()
    );
    let receipt = commit(&base, 1);
    assert!(
        files
            .publish_fresh(draft(&base, 1), receipt, mapping(), &mut || true)
            .is_err()
    );
    let mut bound = binding(&base, 1);
    bound.remote = Some(RemoteEditBaseline {
        resource_id: "existing".into(),
        etag: "\"v1\"".into(),
        byte_len: 1,
    });
    let receipt = base
        .try_begin_capture(bound)
        .unwrap()
        .capture(
            &mut Generated {
                position: 0,
                length: 1,
            },
            &mut || false,
        )
        .unwrap()
        .verify_and_commit(&mut || false)
        .unwrap();
    assert!(
        files
            .publish_fresh(draft(&base, 1), receipt, mapping(), &mut || false)
            .is_err()
    );
}

#[test]
fn failed_submitted_event_retains_stage_and_poisoned_lease_never_retries() {
    let (temp, base, files, observation) = fixture();
    let published = files
        .publish_fresh(draft(&base, 1), commit(&base, 1), mapping(), &mut || false)
        .unwrap();
    let key = published.record().key().clone();
    let body_id = published.record().snapshot_id().to_owned();
    drop(published);
    let mut lease = files.acquire_dispatch(&key).unwrap();
    observation.fail_event.store(true, Ordering::SeqCst);
    assert_eq!(
        lease.mark_submitted().err(),
        Some(StoreError::PublicationUncertain)
    );
    assert_eq!(
        lease.mark_submitted().err(),
        Some(StoreError::PublicationUncertain)
    );
    drop(lease);
    assert!(
        temp.path()
            .join(ROOT)
            .join(&base.key)
            .join(format!("{}.event.{:020}.stage", key.id, 1))
            .is_file()
    );
    assert!(
        temp.path()
            .join(&base.key)
            .join(format!("{body_id}.body"))
            .is_file()
    );
    assert!(files.discover().is_err());
    assert!(files.acquire_dispatch(&key).is_err());
}
#[test]
fn authenticated_event_from_another_join_is_not_adopted() {
    let (temp, base, files, _) = fixture();
    let first = files
        .publish_fresh(draft(&base, 1), commit(&base, 1), mapping(), &mut || false)
        .unwrap();
    let a = first.record().key().clone();
    drop(first);
    let mut bind = binding(&base, 1);
    bind.relative_path = "folder/other.bin".into();
    bind.local_file.file_index = 43;
    let receipt = base
        .try_begin_capture(bind)
        .unwrap()
        .capture(
            &mut Generated {
                position: 0,
                length: 1,
            },
            &mut || false,
        )
        .unwrap()
        .verify_and_commit(&mut || false)
        .unwrap();
    let mut intent = draft(&base, 1);
    if let NamespaceOperation::CreateFile { destination, .. } = &mut intent.operation {
        destination.name = "other.bin".into();
        destination.local_file.file_index = 43;
    }
    let path = CapturedCreatePath::new(
        vec!["Personal".into(), "folder".into(), "other.bin".into()],
        "folder/other.bin".into(),
    )
    .unwrap();
    let second = files
        .publish_fresh(intent, receipt, path, &mut || false)
        .unwrap();
    let b = second.record().key().clone();
    drop(second);
    let mut lease = files.acquire_dispatch(&a).unwrap();
    lease.mark_submitted().unwrap();
    drop(lease);
    let mut lease = files.acquire_dispatch(&b).unwrap();
    lease.mark_submitted().unwrap();
    drop(lease);
    let directory = temp.path().join(ROOT).join(&base.key);
    std::fs::copy(
        directory.join(format!("{}.event.{:020}", a.id, 1)),
        directory.join(format!("{}.event.{:020}", b.id, 1)),
    )
    .unwrap();
    assert!(files.discover().is_err());
    assert!(files.open_joined(&b, &mut || false).is_err());
}
#[test]
fn unknown_file_root_catalog_is_not_ignored_by_snapshot_scans_or_quota() {
    let (temp, base, _, _) = fixture();
    let receipt = commit(&base, 1);
    drop(receipt);
    std::fs::create_dir(temp.path().join(ROOT)).unwrap();
    std::fs::write(temp.path().join(ROOT).join("unknown.catalog"), b"retained").unwrap();
    assert!(base.discover_records().is_err());
    assert!(base.inventory().is_err());
}

#[test]
fn file_catalogs_share_one_metadata_budget_and_have_a_finite_scope_bound() {
    let (temp, base, files, _) = fixture();
    let published = files
        .publish_fresh(draft(&base, 0), commit(&base, 0), mapping(), &mut || false)
        .unwrap();
    drop(published);
    let root = base.root.child(ROOT, false).unwrap();
    let mut second = base.scope.clone();
    second.space_id = "second".into();
    second.root_resource_id = "second-root".into();
    let second_key = scope_key(&second).unwrap();
    let sealed = base
        .seal_metadata(&catalog_aad(&second_key), &second)
        .unwrap();
    persist_metadata(&*root, &format!("{second_key}.scope"), &sealed).unwrap();
    root.child(&second_key, true).unwrap();
    let first_len = std::fs::metadata(temp.path().join(ROOT).join(format!("{}.scope", base.key)))
        .unwrap()
        .len();
    let mut budget = Budget::new(base.policy);
    budget.bytes = first_len + sealed.len() as u64 - 1;
    assert_eq!(
        catalogs(&*root, &*base.protector, &mut budget).err(),
        Some(StoreError::ScanLimit)
    );
    for n in 2..=MAX_SCOPES {
        let mut scope = base.scope.clone();
        scope.space_id = format!("scope-{n}");
        scope.root_resource_id = format!("root-{n}");
        let key = scope_key(&scope).unwrap();
        let sealed = base.seal_metadata(&catalog_aad(&key), &scope).unwrap();
        persist_metadata(&*root, &format!("{key}.scope"), &sealed).unwrap();
        root.child(&key, true).unwrap();
    }
    assert_eq!(files.discover().err(), Some(StoreError::ScanLimit));
    assert!(base.inventory().is_err());
}

#[test]
fn catalog_key_export_authenticates_every_catalog_under_the_caller_budget() {
    let (_temp, base, files, _) = fixture();
    let published = files
        .publish_fresh(draft(&base, 0), commit(&base, 0), mapping(), &mut || false)
        .unwrap();
    drop(published);
    let root = base.root.child(ROOT, false).unwrap();
    let mut budget = Budget::new(base.policy);
    let keys = validated_catalog_scope_keys(&*root, &*base.protector, &mut budget).unwrap();
    assert_eq!(keys, vec![base.key.clone()]);

    let (_temp, base, _files, _) = fixture();
    let root = base.root.child(ROOT, true).unwrap();
    let key = scope_key(&base.scope).unwrap();
    let sealed = base.seal_metadata(&catalog_aad(&key), &base.scope).unwrap();
    persist_metadata(&*root, &format!("{key}.scope"), &sealed).unwrap();
    root.child(&key, true).unwrap();
    std::fs::write(
        _temp.path().join(ROOT).join(format!("{key}.scope")),
        b"tampered catalog",
    )
    .unwrap();
    let mut budget = Budget::new(base.policy);
    assert_eq!(
        validated_catalog_scope_keys(&*root, &*base.protector, &mut budget).err(),
        Some(StoreError::CorruptEvidence)
    );
}

#[test]
fn mapping_constructor_checks_correspondence_and_bounds_but_grants_no_admission() {
    assert!(
        CapturedCreatePath::new(
            vec![
                "Spaces".into(),
                "Projects".into(),
                "folder".into(),
                "new.bin".into()
            ],
            "folder/new.bin".into()
        )
        .is_ok()
    );
    for remote in [
        "/folder/new.bin",
        "folder//new.bin",
        "../new.bin",
        "other/new.bin",
        "folder/new.bin/",
    ] {
        assert!(
            CapturedCreatePath::new(
                vec!["Personal".into(), "folder".into(), "new.bin".into()],
                remote.into()
            )
            .is_err()
        );
    }
    assert!(
        CapturedCreatePath::new(vec!["Personal".into(), "new.bin".into()], "a".repeat(32769))
            .is_err()
    );
    assert!(
        CapturedCreatePath::new(vec!["Unknown".into(), "new.bin".into()], "new.bin".into())
            .is_err()
    );
}

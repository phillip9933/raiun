//! Synthetic Unix disk adapter: these tests do not establish immutable Unix
//! or Windows native filesystem guarantees.
use super::*;
use crate::{JournalError, LocalFileIdentity};
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{Cursor, SeekFrom},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
pub(super) struct Observe {
    publishes: AtomicUsize,
    fail_publish: AtomicUsize,
    body_reads: AtomicUsize,
    external_bytes: AtomicUsize,
    external_entries: AtomicUsize,
    duplicate_entry: AtomicUsize,
}
struct Disk {
    path: PathBuf,
    observe: Arc<Observe>,
}
impl Directory for Disk {
    fn verify(&self) -> Result<(), StoreError> {
        let m = fs::symlink_metadata(&self.path).map_err(io_error)?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err(StoreError::CorruptEvidence);
        }
        Ok(())
    }
    fn external_recovery_usage(&self, _policy: StorePolicy) -> Result<(u64, usize), StoreError> {
        Ok((
            self.observe.external_bytes.load(Ordering::Relaxed) as u64,
            self.observe.external_entries.load(Ordering::Relaxed),
        ))
    }
    fn entries(&self, limit: usize) -> Result<Vec<String>, StoreError> {
        self.verify()?;
        let mut result = Vec::new();
        for entry in fs::read_dir(&self.path).map_err(io_error)? {
            if result.len() >= limit {
                return Err(StoreError::ScanLimit);
            }
            result.push(
                entry
                    .map_err(io_error)?
                    .file_name()
                    .into_string()
                    .map_err(|_| StoreError::Invalid)?,
            );
        }
        result.sort();
        if self.observe.duplicate_entry.load(Ordering::Relaxed) != 0 && !result.is_empty() {
            result.push(result[0].clone());
        }
        Ok(result)
    }
    fn child(&self, name: &str, create: bool) -> Result<Arc<dyn Directory>, StoreError> {
        let path = self.path.join(name);
        if create {
            fs::create_dir(&path).map_err(io_error)?;
        }
        let next = Arc::new(Self {
            path,
            observe: Arc::clone(&self.observe),
        });
        next.verify()?;
        Ok(next)
    }
    fn create(&self, name: &str) -> Result<(Box<dyn StageWrite>, Identity), StoreError> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(self.path.join(name))
            .map_err(io_error)?;
        let id = file_identity(&f)?;
        Ok((Box::new(f), id))
    }
    fn open(&self, name: &str) -> Result<Box<dyn PinnedRead>, StoreError> {
        let path = self.path.join(name);
        let m = fs::symlink_metadata(&path).map_err(io_error)?;
        if !m.is_file() || m.file_type().is_symlink() {
            return Err(StoreError::CorruptEvidence);
        }
        let f = File::open(path).map_err(io_error)?;
        Ok(Box::new(DiskRead {
            id: file_identity(&f)?,
            file: f,
            is_body: name.ends_with(".body") || name.ends_with(".body.stage"),
            observe: Arc::clone(&self.observe),
        }))
    }
    fn publish(&self, stage: &str, final_name: &str, identity: Identity) -> Result<(), StoreError> {
        let n = self.observe.publishes.fetch_add(1, Ordering::SeqCst) + 1;
        if self.observe.fail_publish.load(Ordering::SeqCst) == n {
            return Err(StoreError::Io);
        }
        let source = self.path.join(stage);
        if file_identity(&File::open(&source).map_err(io_error)?)? != identity {
            return Err(StoreError::CorruptEvidence);
        }
        fs::hard_link(&source, self.path.join(final_name)).map_err(io_error)?;
        fs::remove_file(source).map_err(io_error)?;
        File::open(&self.path)
            .and_then(|f| f.sync_all())
            .map_err(io_error)
    }
}
impl StageWrite for File {
    fn sync(&self) -> Result<(), StoreError> {
        self.sync_all().map_err(io_error)
    }
}
fn file_identity(f: &File) -> Result<Identity, StoreError> {
    let m = f.metadata().map_err(io_error)?;
    Ok(Identity {
        volume: m.dev(),
        file: m.ino(),
    })
}
struct DiskRead {
    file: File,
    id: Identity,
    is_body: bool,
    observe: Arc<Observe>,
}
impl Read for DiskRead {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.is_body {
            self.observe.body_reads.fetch_add(1, Ordering::Relaxed);
        }
        self.file.read(bytes)
    }
}
impl Seek for DiskRead {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.file.seek(from)
    }
}
impl PinnedRead for DiskRead {
    fn identity(&self) -> Identity {
        self.id
    }
    fn len(&self) -> Result<u64, StoreError> {
        Ok(self.file.metadata().map_err(io_error)?.len())
    }
    fn verify(&self) -> Result<(), StoreError> {
        if file_identity(&self.file)? == self.id {
            Ok(())
        } else {
            Err(StoreError::CorruptEvidence)
        }
    }
    fn lock_exclusive(&mut self) -> Result<(), StoreError> {
        self.file.try_lock_exclusive().map_err(|e| {
            if e.kind() == io::ErrorKind::WouldBlock {
                StoreError::Busy
            } else {
                StoreError::Io
            }
        })
    }
}
// Synthetic authenticated encoding only; not cryptography or DPAPI evidence.
struct Protector;
impl EditRecordProtector for Protector {
    fn seal(&self, aad: &[u8], bytes: &[u8]) -> Result<Vec<u8>, JournalError> {
        let mut h = Sha256::new();
        h.update(aad);
        h.update(bytes);
        let mut result = h.finalize().to_vec();
        result.extend(bytes.iter().map(|b| b ^ 0xa5));
        Ok(result)
    }
    fn open(&self, aad: &[u8], bytes: &[u8]) -> Result<Vec<u8>, JournalError> {
        if bytes.len() < 32 {
            return Err(JournalError::ProtectionFailed);
        }
        let plain: Vec<_> = bytes[32..].iter().map(|b| b ^ 0xa5).collect();
        let mut h = Sha256::new();
        h.update(aad);
        h.update(&plain);
        let hash: [u8; 32] = h.finalize().into();
        if hash.as_slice() != &bytes[..32] {
            return Err(JournalError::ProtectionFailed);
        }
        Ok(plain)
    }
}
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
fn binding(len: u64) -> SnapshotBinding {
    SnapshotBinding {
        record_id: String::new(),
        scope: scope(),
        generation: 3,
        local_file: LocalFileIdentity {
            volume_serial: 1,
            file_index: 4,
        },
        relative_path: "doc.bin".into(),
        remote: None,
        content_len: len,
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
pub(super) fn fixture_with(
    policy: StorePolicy,
) -> (tempfile::TempDir, Arc<Observe>, Arc<SnapshotStore>) {
    let t = tempfile::tempdir().unwrap();
    let observe = Arc::new(Observe::default());
    let root = Arc::new(Disk {
        path: t.path().to_owned(),
        observe: Arc::clone(&observe),
    });
    let store = SnapshotStore::from_directory(root, scope(), Arc::new(Protector), policy).unwrap();
    (t, observe, store)
}
struct Generated {
    remaining: u64,
    largest: usize,
}
impl Read for Generated {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.largest = self.largest.max(out.len());
        let n = self.remaining.min(out.len() as u64) as usize;
        out[..n].fill(0x67);
        self.remaining -= n as u64;
        Ok(n)
    }
}
fn record_files(root: &Path, key: &str) -> Vec<String> {
    fs::read_dir(root.join(key))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect()
}
#[test]
fn large_disk_snapshot_commits_reopens_and_discovers_without_body_reads() {
    let (_t, observe, store) = fixture_with(policy());
    let length = 17 * 1024 * 1024 + 71;
    let mut source = Generated {
        remaining: length,
        largest: 0,
    };
    let reservation = store.try_begin_capture(binding(length)).unwrap();
    let id = reservation.binding().record_id.clone();
    let staged = reservation.capture(&mut source, &mut || false).unwrap();
    assert_eq!(source.remaining, 0);
    assert!(source.largest <= SNAPSHOT_CHUNK_BYTES);
    let committed = staged.verify_and_commit(&mut || false).unwrap();
    assert_eq!(committed.manifest().binding().content_len, length);
    let restarted = SnapshotStore::from_directory(
        Arc::clone(&store.root),
        scope(),
        Arc::new(Protector),
        policy(),
    )
    .unwrap();
    let before = observe.body_reads.load(Ordering::Relaxed);
    assert_eq!(restarted.discover_metadata().unwrap().len(), 1);
    assert_eq!(observe.body_reads.load(Ordering::Relaxed), before);
    let verified = restarted.open_verified(&id, &mut || false).unwrap();
    assert_eq!(verified.local_check().content_len(), length);
    verified.verify_pin().unwrap();
    let mut reader = verified.into_reader(Arc::new(|| false)).unwrap();
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 8192];
    let mut count = 0u64;
    loop {
        let n = reader.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        assert!(buffer[..n].iter().all(|b| *b == 0x67));
        digest.update(&buffer[..n]);
        count += n as u64;
    }
    let actual: [u8; 32] = digest.finalize().into();
    assert_eq!(count, length);
    assert_eq!(&actual, committed.manifest().content_sha256());
}
#[test]
fn independent_store_instances_contend_and_dropped_reservation_is_retained_and_charged() {
    let (t, observe, store) = fixture_with(policy());
    let other = SnapshotStore::from_directory(
        Arc::new(Disk {
            path: t.path().to_owned(),
            observe,
        }),
        scope(),
        Arc::new(Protector),
        policy(),
    )
    .unwrap();
    let held = store.try_begin_capture(binding(1)).unwrap();
    assert_eq!(
        other.try_begin_capture(binding(1)).err(),
        Some(StoreError::Busy)
    );
    let id = held.binding().record_id.clone();
    drop(held);
    assert!(record_files(t.path(), &store.key).contains(&format!("{id}.reserve")));
    assert_eq!(
        other.discover_metadata().err(),
        Some(StoreError::IncompleteEvidence)
    );
    let mut small = policy();
    small.max_state_bytes = reservation_bound(1).unwrap();
    let constrained =
        SnapshotStore::from_directory(Arc::clone(&store.root), scope(), Arc::new(Protector), small)
            .unwrap();
    assert_eq!(
        constrained.try_begin_capture(binding(1)).err(),
        Some(StoreError::Quota)
    );
}
#[test]
fn manifest_publication_failure_preserves_body_manifest_stage_and_reservation() {
    let (t, observe, store) = fixture_with(policy());
    let held = store.try_begin_capture(binding(100)).unwrap();
    let id = held.binding().record_id.clone();
    let staged = held
        .capture(&mut Cursor::new(vec![3; 100]), &mut || false)
        .unwrap();
    // Scope descriptor and reservation were first, body third, manifest fourth.
    observe.fail_publish.store(4, Ordering::SeqCst);
    assert_eq!(
        staged.verify_and_commit(&mut || false).err(),
        Some(StoreError::PublicationUncertain)
    );
    let files = record_files(t.path(), &store.key);
    for suffix in ["body", "manifest.stage", "reserve"] {
        assert!(files.contains(&format!("{id}.{suffix}")));
    }
    assert!(!files.contains(&format!("{id}.manifest")));
    assert_eq!(
        store.discover_metadata().err(),
        Some(StoreError::IncompleteEvidence)
    );
}
#[test]
fn failed_source_and_cancel_preserve_stages_never_publish_manifest() {
    for cancel in [false, true] {
        let (t, _, store) = fixture_with(policy());
        let held = store.try_begin_capture(binding(100)).unwrap();
        let id = held.binding().record_id.clone();
        let error = held
            .capture(&mut Cursor::new(vec![3; 50]), &mut || cancel)
            .err()
            .unwrap();
        assert_eq!(
            error,
            StoreError::Snapshot(if cancel {
                SnapshotError::Cancelled
            } else {
                SnapshotError::SourceLengthMismatch
            })
        );
        let files = record_files(t.path(), &store.key);
        assert!(files.contains(&format!("{id}.body.stage")));
        assert!(files.contains(&format!("{id}.reserve")));
        assert!(!files.contains(&format!("{id}.manifest")));
    }
}
#[test]
fn swapped_body_identity_and_modified_final_bytes_do_not_verify() {
    let (t, _, store) = fixture_with(policy());
    let held = store.try_begin_capture(binding(100)).unwrap();
    let id = held.binding().record_id.clone();
    let staged = held
        .capture(&mut Cursor::new(vec![3; 100]), &mut || false)
        .unwrap();
    let path = t.path().join(&store.key).join(format!("{id}.body.stage"));
    fs::rename(&path, path.with_extension("retained-original")).unwrap();
    fs::write(&path, vec![0; 200]).unwrap();
    assert_eq!(
        staged.verify_and_commit(&mut || false).err(),
        Some(StoreError::CorruptEvidence)
    );
    let (_t2, _, store2) = fixture_with(policy());
    let r = store2.try_begin_capture(binding(10)).unwrap();
    let id2 = r.binding().record_id.clone();
    r.capture(&mut Cursor::new(vec![2; 10]), &mut || false)
        .unwrap()
        .verify_and_commit(&mut || false)
        .unwrap();
    // Synthetic storage permits same-user writes; production Windows pins deny them.
    let body_path = _t2.path().join(&store2.key).join(format!("{id2}.body"));
    let mut bytes = fs::read(&body_path).unwrap();
    let end = bytes.len() - 1;
    bytes[end] ^= 1;
    fs::write(&body_path, bytes).unwrap();
    assert!(store2.open_verified(&id2, &mut || false).is_err());
}
#[test]
fn wrong_account_scope_corrupt_catalog_and_scan_exhaustion_fail_closed() {
    let (t, observe, store) = fixture_with(policy());
    let r = store.try_begin_capture(binding(0)).unwrap();
    r.capture(&mut io::empty(), &mut || false)
        .unwrap()
        .verify_and_commit(&mut || false)
        .unwrap();
    let mut wrong = scope();
    wrong.account_subject = "foreign".into();
    let foreign = SnapshotStore::from_directory(
        Arc::clone(&store.root),
        wrong,
        Arc::new(Protector),
        policy(),
    )
    .unwrap();
    assert!(foreign.discover_metadata().unwrap().is_empty());
    let mut bounded = policy();
    bounded.max_entries = 4;
    let small = SnapshotStore::from_directory(
        Arc::clone(&store.root),
        scope(),
        Arc::new(Protector),
        bounded,
    )
    .unwrap();
    assert_eq!(small.discover_metadata().err(), Some(StoreError::ScanLimit));
    let catalog = t.path().join(format!("{}.scope", store.key));
    fs::write(catalog, b"corrupt").unwrap();
    assert!(store.discover_metadata().is_err());
    assert!(observe.body_reads.load(Ordering::Relaxed) > 0);
}

#[test]
fn file_chunk_policy_is_independent_of_directory_entry_policy() {
    let mut p = policy();
    p.max_entries = 8;
    let (_t, _, store) = fixture_with(p);
    let length = SNAPSHOT_CHUNK_BYTES as u64 * 9 + 1;
    let r = store.try_begin_capture(binding(length)).unwrap();
    let mut source = Generated {
        remaining: length,
        largest: 0,
    };
    r.capture(&mut source, &mut || false)
        .unwrap()
        .verify_and_commit(&mut || false)
        .unwrap();
    assert_eq!(store.discover_metadata().unwrap().len(), 1);
}

#[test]
fn missing_wrongsize_body_and_full_reservation_binding_mismatch_are_attention() {
    for scenario in [0, 1, 2] {
        let (t, _, store) = fixture_with(policy());
        let r = store.try_begin_capture(binding(10)).unwrap();
        let id = r.binding().record_id.clone();
        r.capture(&mut Cursor::new(vec![2; 10]), &mut || false)
            .unwrap()
            .verify_and_commit(&mut || false)
            .unwrap();
        let directory = t.path().join(&store.key);
        if scenario == 0 {
            fs::rename(
                directory.join(format!("{id}.body")),
                t.path().join("retained-body"),
            )
            .unwrap();
        } else if scenario == 1 {
            OpenOptions::new()
                .write(true)
                .open(directory.join(format!("{id}.body")))
                .unwrap()
                .set_len(1)
                .unwrap();
        } else {
            let dir = store.root.child(&store.key, false).unwrap();
            let mut reservation = store
                .authenticate_reservation(&*dir, &id, &store.scope, &mut Budget::new(store.policy))
                .unwrap();
            reservation.binding.relative_path = "different.bin".into();
            let sealed = store
                .seal_metadata(&reservation_aad(&store.key, &id), &reservation)
                .unwrap();
            fs::write(directory.join(format!("{id}.reserve")), sealed).unwrap();
        }
        assert!(store.discover_metadata().is_err());
        assert!(store.open_verified(&id, &mut || false).is_err());
    }
}

#[test]
fn absent_selected_scope_does_not_hide_unknown_or_incomplete_root_evidence() {
    for name in [
        "unknown",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.scope.stage",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.scope",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        let (t, _, store) = fixture_with(policy());
        fs::write(t.path().join(name), b"retained").unwrap();
        assert_eq!(
            store.discover_metadata().err(),
            Some(StoreError::IncompleteEvidence)
        );
    }
    let (_t, _, store) = fixture_with(policy());
    assert!(store.discover_metadata().unwrap().is_empty());
}

#[test]
fn failed_event_publication_preserves_stage_and_grants_no_attempt() {
    let (temp, observe, store) = fixture_with(policy());
    let reservation = store.try_begin_capture(binding(10)).unwrap();
    let id = reservation.binding().record_id.clone();
    reservation
        .capture(&mut Cursor::new(vec![2; 10]), &mut || false)
        .unwrap()
        .verify_and_commit(&mut || false)
        .unwrap();
    let key = store.record_key(&id).unwrap();
    let before_reads = observe.body_reads.load(Ordering::Relaxed);
    let mut lease = store.acquire_dispatch(&key).unwrap();
    observe.fail_publish.store(
        observe.publishes.load(Ordering::SeqCst) + 1,
        Ordering::SeqCst,
    );
    assert_eq!(
        lease.begin_attempt().err(),
        Some(StoreError::PublicationUncertain)
    );
    assert_eq!(lease.begin_attempt().err(), Some(StoreError::Invalid));
    let stage = temp
        .path()
        .join(&store.key)
        .join(format!("{id}.event.{:020}.stage", 1));
    assert!(stage.is_file());
    assert!(store.discover_records().is_err());
    assert_eq!(observe.body_reads.load(Ordering::Relaxed), before_reads);
    drop(lease);
    assert!(store.acquire_dispatch(&key).is_err());
    assert!(stage.is_file());
}

#[test]
fn injected_external_usage_blocks_capture_and_events_without_body_reads_or_recursive_lock() {
    let (_temp, observe, store) = fixture_with(policy());
    let reserve = store.try_begin_capture(binding(1)).unwrap();
    let id = reserve.binding().record_id.clone();
    reserve
        .capture(&mut Cursor::new(vec![9]), &mut || false)
        .unwrap()
        .verify_and_commit(&mut || false)
        .unwrap();
    let key = store.record_key(&id).unwrap();
    let state_lock = store.acquire_lock().unwrap();
    let v2 = store.accounted_usage_while_locked().unwrap();
    assert!(v2.0 > 0);
    observe
        .external_bytes
        .store(store.policy.max_state_bytes as usize, Ordering::Relaxed);
    assert_eq!(
        store.accounted_usage_while_locked().unwrap(),
        v2,
        "stats must omit hook to avoid coordinator doublecount"
    );
    drop(state_lock);
    let before = observe.body_reads.load(Ordering::Relaxed);
    assert_eq!(
        store.try_begin_capture(binding(1)).err(),
        Some(StoreError::Quota)
    );
    assert_eq!(store.acquire_dispatch(&key).err(), Some(StoreError::Quota));
    assert_eq!(observe.body_reads.load(Ordering::Relaxed), before);
    observe.external_bytes.store(0, Ordering::Relaxed);
    let mut lease = store.acquire_dispatch(&key).unwrap();
    observe
        .external_bytes
        .store(store.policy.max_state_bytes as usize, Ordering::Relaxed);
    assert_eq!(lease.begin_attempt().err(), Some(StoreError::Quota));
    assert_eq!(
        lease.current_state().unwrap(),
        StreamedAttemptState::NotAttempted
    );
    observe.external_bytes.store(0, Ordering::Relaxed);
    observe
        .external_entries
        .store(store.policy.max_entries, Ordering::Relaxed);
    assert_eq!(
        store.try_begin_capture(binding(1)).err(),
        Some(StoreError::ScanLimit)
    );
}

#[test]
fn failed_outcome_publication_keeps_attempt_intent_and_never_reports_ack() {
    let (temp, observe, store) = fixture_with(policy());
    let reservation = store.try_begin_capture(binding(1)).unwrap();
    let id = reservation.binding().record_id.clone();
    reservation
        .capture(&mut Cursor::new(vec![2]), &mut || false)
        .unwrap()
        .verify_and_commit(&mut || false)
        .unwrap();
    let key = store.record_key(&id).unwrap();
    let mut lease = store.acquire_dispatch(&key).unwrap();
    assert_eq!(lease.begin_attempt().unwrap(), 1);
    observe.fail_publish.store(
        observe.publishes.load(Ordering::SeqCst) + 1,
        Ordering::SeqCst,
    );
    assert_eq!(
        lease
            .finish_outcome(1, 1, StreamedAttemptOutcome::VerifiedApplied)
            .err(),
        Some(StoreError::PublicationUncertain)
    );
    let directory = temp.path().join(&store.key);
    assert!(directory.join(format!("{id}.event.{:020}", 1)).is_file());
    assert!(
        directory
            .join(format!("{id}.event.{:020}.stage", 2))
            .is_file()
    );
    assert!(!directory.join(format!("{id}.event.{:020}", 2)).exists());
    assert!(directory.join(format!("{id}.body")).is_file());
    assert!(store.discover_records().is_err());
    drop(lease);
    assert!(store.acquire_dispatch(&key).is_err());
}

#[test]
fn global_catalog_discovery_authenticates_scopes_without_selected_scope_or_body_reads() {
    let (_temp, observe, store) = fixture_with(policy());
    assert!(
        discover_scope_catalogs(&*store.root, &*store.protector, policy())
            .unwrap()
            .is_empty()
    );
    let r = store.try_begin_capture(binding(1)).unwrap();
    r.capture(&mut Cursor::new(vec![1]), &mut || false)
        .unwrap()
        .verify_and_commit(&mut || false)
        .unwrap();
    let mut foreign = scope();
    foreign.account_subject = "other-subject".into();
    let other = SnapshotStore::from_directory(
        Arc::clone(&store.root),
        foreign.clone(),
        Arc::clone(&store.protector),
        policy(),
    )
    .unwrap();
    let mut b = binding(0);
    b.scope = foreign.clone();
    let r = other.try_begin_capture(b).unwrap();
    r.capture(&mut io::empty(), &mut || false)
        .unwrap()
        .verify_and_commit(&mut || false)
        .unwrap();
    let before = observe.body_reads.load(Ordering::Relaxed);
    let scopes = discover_scope_catalogs(&*store.root, &*store.protector, policy()).unwrap();
    assert_eq!(scopes.len(), 2);
    assert!(scopes.contains(&scope()));
    assert!(scopes.contains(&foreign));
    assert_eq!(observe.body_reads.load(Ordering::Relaxed), before);
}

#[test]
fn global_catalog_unknown_stage_missing_pair_corrupt_scope_and_nonzero_lock_fail_closed() {
    for scenario in 0..5 {
        let (temp, _, store) = fixture_with(policy());
        let r = store.try_begin_capture(binding(0)).unwrap();
        drop(r);
        match scenario {
            0 => fs::write(temp.path().join("unknown"), b"retain").unwrap(),
            1 => fs::write(
                temp.path().join(format!("{}.scope.stage", store.key)),
                b"retain",
            )
            .unwrap(),
            2 => fs::rename(
                temp.path().join(&store.key),
                temp.path().join("retained-scope"),
            )
            .unwrap(),
            3 => fs::write(
                temp.path().join(format!("{}.scope", store.key)),
                b"bad protection",
            )
            .unwrap(),
            _ => fs::write(temp.path().join(V2_QUOTA_LOCK), b"not-zero").unwrap(),
        }
        assert!(discover_scope_catalogs(&*store.root, &*store.protector, policy()).is_err());
    }
}

#[test]
fn global_catalog_budget_and_unsafe_scope_directory_are_not_healthy_empty() {
    let (temp, _, store) = fixture_with(policy());
    drop(store.try_begin_capture(binding(0)).unwrap());
    let mut tiny = policy();
    tiny.max_entries = 4;
    for n in 0..3 {
        fs::write(temp.path().join(format!("extra{n}")), b"retained").unwrap();
    }
    assert_eq!(
        discover_scope_catalogs(&*store.root, &*store.protector, tiny).err(),
        Some(StoreError::ScanLimit)
    );
    for n in 0..3 {
        fs::rename(
            temp.path().join(format!("extra{n}")),
            temp.path()
                .join(&store.key)
                .join(format!("retained-extra{n}")),
        )
        .unwrap();
    }
    let path = temp.path().join(&store.key);
    let retained = temp.path().join("retained-directory");
    fs::rename(&path, &retained).unwrap();
    std::os::unix::fs::symlink(&retained, &path).unwrap();
    assert!(discover_scope_catalogs(&*store.root, &*store.protector, policy()).is_err());
}

#[test]
fn global_catalog_duplicate_names_and_aggregate_metadata_budget_are_rejected() {
    let (temp, observe, store) = fixture_with(policy());
    drop(store.try_begin_capture(binding(0)).unwrap());
    observe.duplicate_entry.store(1, Ordering::Relaxed);
    assert_eq!(
        discover_scope_catalogs(&*store.root, &*store.protector, policy()).err(),
        Some(StoreError::CorruptEvidence)
    );
    observe.duplicate_entry.store(0, Ordering::Relaxed);
    let mut other_scope = scope();
    other_scope.account_subject = "other-synthetic".into();
    let other_key = scope_key(&other_scope).unwrap();
    fs::create_dir(temp.path().join(&other_key)).unwrap();
    // Bounded valid JSON whitespace exercises aggregate READ budget, with no
    // oversized field or body allocation and no artificial protector behavior.
    for (key, value) in [(&store.key, scope()), (&other_key, other_scope)] {
        let mut plain = serde_json::to_vec(&value).unwrap();
        plain.resize(META_LIMIT / 2, b' ');
        let sealed = store.protector.seal(&scope_aad(key), &plain).unwrap();
        fs::write(temp.path().join(format!("{key}.scope")), sealed).unwrap();
    }
    let mut small = policy();
    small.max_metadata_bytes_per_scan = META_LIMIT as u64;
    assert_eq!(
        discover_scope_catalogs(&*store.root, &*store.protector, small).err(),
        Some(StoreError::ScanLimit)
    );
}

#[test]
fn aggregate_discovery_budget_is_not_reset_for_second_selected_scope() {
    let (_temp, observe, first) = fixture_with(policy());
    let r = first.try_begin_capture(binding(0)).unwrap();
    r.capture(&mut io::empty(), &mut || false)
        .unwrap()
        .verify_and_commit(&mut || false)
        .unwrap();
    let mut other = scope();
    other.space_id = "second-space".into();
    let second = SnapshotStore::from_directory(
        Arc::clone(&first.root),
        other.clone(),
        Arc::clone(&first.protector),
        policy(),
    )
    .unwrap();
    let mut b = binding(0);
    b.scope = other;
    second
        .try_begin_capture(b)
        .unwrap()
        .capture(&mut io::empty(), &mut || false)
        .unwrap()
        .verify_and_commit(&mut || false)
        .unwrap();
    assert_eq!(first.discover_records().unwrap().len(), 1);
    assert_eq!(second.discover_records().unwrap().len(), 1);
    let mut outer = policy();
    outer.max_entries = 20;
    let mut budget = DiscoveryBudget::new(outer);
    let before = observe.body_reads.load(Ordering::Relaxed);
    assert_eq!(
        discover_scope_catalogs_bounded(&*first.root, &*first.protector, first.policy, &mut budget)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        first.discover_records_bounded(&mut budget).unwrap().len(),
        1
    );
    assert_eq!(
        second.discover_records_bounded(&mut budget).err(),
        Some(StoreError::ScanLimit)
    );
    assert_eq!(observe.body_reads.load(Ordering::Relaxed), before);
}

#[test]
fn aggregate_discovery_read_bytes_are_debited_across_calls_and_policy_still_clamps() {
    let (_temp, _observe, first) = fixture_with(policy());
    drop(first.try_begin_capture(binding(0)).unwrap());
    // Global catalogs need no body/record read and permit reservation-only scope.
    let mut budget = DiscoveryBudget::new(policy());
    discover_scope_catalogs_bounded(&*first.root, &*first.protector, first.policy, &mut budget)
        .unwrap();
    let consumed = first.policy.max_metadata_bytes_per_scan - budget.bytes;
    assert!(consumed > 0);
    let mut exact = DiscoveryBudget {
        entries: 100,
        bytes: consumed,
    };
    discover_scope_catalogs_bounded(&*first.root, &*first.protector, first.policy, &mut exact)
        .unwrap();
    assert_eq!(exact.bytes, 0);
    assert_eq!(
        discover_scope_catalogs_bounded(&*first.root, &*first.protector, first.policy, &mut exact)
            .err(),
        Some(StoreError::ScanLimit)
    );
    // Larger outer allowance cannot widen the selected store's policy.
    let mut small = policy();
    small.max_entries = 4;
    let mut large = DiscoveryBudget::new(policy());
    let before = large.entries;
    let result = large.within_policy(small, |local| {
        assert_eq!(local.entries, 4);
        local.entries(3)
    });
    assert!(result.is_ok());
    assert_eq!(large.entries, before - 3);
}

#[test]
fn scope_free_accounting_matches_selected_usage_without_body_reads_or_scope_creation() {
    let (_temp, observe, store) = fixture_with(policy());
    let blank = v2_inventory_state(&*store.root, &*store.protector, store.policy, None).unwrap();
    assert_eq!((blank.bytes, blank.entries), (0, 0));
    let r = store.try_begin_capture(binding(100)).unwrap();
    r.capture(&mut Cursor::new(vec![1; 100]), &mut || false)
        .unwrap()
        .verify_and_commit(&mut || false)
        .unwrap();
    let mut foreign = scope();
    foreign.account_subject = "another-account".into();
    let other = SnapshotStore::from_directory(
        Arc::clone(&store.root),
        foreign.clone(),
        Arc::clone(&store.protector),
        policy(),
    )
    .unwrap();
    let mut b = binding(0);
    b.scope = foreign;
    drop(other.try_begin_capture(b).unwrap()); // retained protected reservation
    let lease = store.acquire_lock().unwrap();
    let before = observe.body_reads.load(Ordering::Relaxed);
    let global = v2_inventory_state(&*store.root, &*store.protector, store.policy, None).unwrap();
    assert_eq!(
        store.accounted_usage_while_locked().unwrap(),
        (global.bytes, global.entries)
    );
    assert_eq!(
        other.accounted_usage_while_locked().unwrap(),
        (global.bytes, global.entries)
    );
    assert_eq!(observe.body_reads.load(Ordering::Relaxed), before);
    drop(lease);
}

#[test]
fn scope_free_accounting_rejects_corrupt_reservation_and_unknown_root_evidence() {
    for corrupt_reservation in [true, false] {
        let (temp, _, store) = fixture_with(policy());
        let r = store.try_begin_capture(binding(0)).unwrap();
        let id = r.binding().record_id.clone();
        drop(r);
        if corrupt_reservation {
            fs::write(
                temp.path().join(&store.key).join(format!("{id}.reserve")),
                b"bad protection",
            )
            .unwrap();
        } else {
            fs::write(temp.path().join("unknown.stage"), b"retained").unwrap();
        }
        assert!(v2_inventory_state(&*store.root, &*store.protector, store.policy, None).is_err());
    }
}

use super::*;
use crate::JournalError;
use std::{
    io::Cursor,
    sync::atomic::{AtomicUsize, Ordering},
};

// Deterministic test-only corruption detector/XOR, not a production cipher or
// an assertion about DPAPI. It lets tests observe every AAD/body boundary.
#[derive(Default)]
struct TestProtector {
    seal_calls: AtomicUsize,
    open_calls: AtomicUsize,
    max_plain: AtomicUsize,
}
impl EditRecordProtector for TestProtector {
    fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, JournalError> {
        self.seal_calls.fetch_add(1, Ordering::Relaxed);
        self.max_plain.fetch_max(plain.len(), Ordering::Relaxed);
        let mut digest = Sha256::new();
        digest.update(b"synthetic test protector");
        digest.update((aad.len() as u64).to_le_bytes());
        digest.update(aad);
        digest.update(plain);
        let mut output = digest.finalize().to_vec();
        output.extend(plain.iter().map(|b| b ^ 0xa5));
        Ok(output)
    }
    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, JournalError> {
        self.open_calls.fetch_add(1, Ordering::Relaxed);
        if sealed.len() < 32 {
            return Err(JournalError::ProtectionFailed);
        }
        let plain: Vec<u8> = sealed[32..].iter().map(|b| b ^ 0xa5).collect();
        let mut digest = Sha256::new();
        digest.update(b"synthetic test protector");
        digest.update((aad.len() as u64).to_le_bytes());
        digest.update(aad);
        digest.update(&plain);
        let actual: [u8; 32] = digest.finalize().into();
        if actual.as_slice() != &sealed[..32] {
            return Err(JournalError::ProtectionFailed);
        }
        Ok(plain)
    }
}

fn binding(length: u64) -> SnapshotBinding {
    SnapshotBinding {
        record_id: "0123456789abcdef0123456789abcdef".into(),
        scope: EditJournalScope {
            profile_id: "default".into(),
            server_origin: "https://synthetic.invalid".into(),
            account_subject: "synthetic".into(),
            space_id: "personal".into(),
            root_resource_id: "root".into(),
            root_volume_serial: 1,
            root_file_index: 2,
        },
        generation: 3,
        local_file: LocalFileIdentity {
            volume_serial: 1,
            file_index: 4,
        },
        relative_path: "docs/file.bin".into(),
        remote: Some(RemoteEditBaseline {
            resource_id: "remote-file".into(),
            etag: "\"v1\"".into(),
            byte_len: length,
        }),
        content_len: length,
    }
}
fn limits() -> SnapshotLimits {
    SnapshotLimits::new(64 * 1024 * 1024, 128 * 1024 * 1024, 1024).unwrap()
}

struct Generated {
    remaining: u64,
    offset: u64,
    largest: usize,
}
impl Generated {
    fn new(length: u64) -> Self {
        Self {
            remaining: length,
            offset: 0,
            largest: 0,
        }
    }
}
fn pattern(offset: u64) -> u8 {
    (offset.wrapping_mul(17).wrapping_add(offset / 257) % 251) as u8
}
impl Read for Generated {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.largest = self.largest.max(output.len());
        let count = self.remaining.min(output.len() as u64) as usize;
        for (index, byte) in output[..count].iter_mut().enumerate() {
            *byte = pattern(self.offset + index as u64);
        }
        self.remaining -= count as u64;
        self.offset += count as u64;
        Ok(count)
    }
}
#[derive(Default)]
struct CheckPattern {
    offset: u64,
    largest: usize,
}
impl Write for CheckPattern {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.largest = self.largest.max(bytes.len());
        for (index, byte) in bytes.iter().enumerate() {
            if *byte != pattern(self.offset + index as u64) {
                return Err(io::Error::other("synthetic byte mismatch"));
            }
        }
        self.offset += bytes.len() as u64;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encoded_small(length: u64, protector: &TestProtector) -> (Vec<u8>, EncodedSnapshot) {
    let mut container = Vec::new();
    let encoded = encode_snapshot(
        &mut Generated::new(length),
        &mut container,
        protector,
        &binding(length),
        limits(),
        &mut || false,
    )
    .unwrap();
    (container, encoded)
}

#[test]
fn generated_large_snapshot_uses_bounded_chunks_and_disk_without_body_sized_allocation() {
    let length = 17 * 1024 * 1024 + 123;
    let protector = TestProtector::default();
    let binding = binding(length);
    let mut source = Generated::new(length);
    let mut file = tempfile::tempfile().unwrap();
    let encoded = encode_snapshot(
        &mut source,
        &mut file,
        &protector,
        &binding,
        limits(),
        &mut || false,
    )
    .unwrap();
    assert!(source.largest <= SNAPSHOT_CHUNK_BYTES);
    assert!(protector.max_plain.load(Ordering::Relaxed) <= SNAPSHOT_CHUNK_BYTES);
    let calls = protector.open_calls.load(Ordering::Relaxed);
    let manifest = open_manifest(
        encoded.sealed_manifest(),
        &protector,
        &binding.scope,
        &binding.record_id,
        limits(),
    )
    .unwrap();
    assert_eq!(
        protector.open_calls.load(Ordering::Relaxed),
        calls + 1,
        "metadata decode authenticates only its manifest"
    );
    let checked =
        verify_container(&mut file, &protector, &manifest, limits(), &mut || false).unwrap();
    assert_eq!(checked.content_len(), length);
    assert_eq!(file.stream_position().unwrap(), 0);
    let mut sink = CheckPattern::default();
    decode_container(
        &mut file,
        &mut sink,
        &protector,
        &manifest,
        limits(),
        &mut || false,
    )
    .unwrap();
    assert_eq!(sink.offset, length);
    assert!(sink.largest <= SNAPSHOT_CHUNK_BYTES);
    assert_eq!(checked.content_sha256(), manifest.content_sha256());
    assert_eq!(checked.container_sha256(), manifest.container_sha256());
}

#[test]
fn empty_exact_and_partial_chunks_have_exact_eof() {
    for length in [
        0,
        1,
        SNAPSHOT_CHUNK_BYTES as u64,
        SNAPSHOT_CHUNK_BYTES as u64 + 1,
    ] {
        let protector = TestProtector::default();
        let (container, encoded) = encoded_small(length, &protector);
        let checked = verify_container(
            &mut Cursor::new(container),
            &protector,
            encoded.manifest(),
            limits(),
            &mut || false,
        )
        .unwrap();
        assert_eq!(checked.content_len(), length);
        for source_length in [length + 1, length.saturating_sub(1)] {
            if source_length == length {
                continue;
            }
            let error = encode_snapshot(
                &mut Generated::new(source_length),
                &mut io::sink(),
                &protector,
                &binding(length),
                limits(),
                &mut || false,
            )
            .err()
            .unwrap();
            assert_eq!(error, SnapshotError::SourceLengthMismatch);
        }
    }
}

#[test]
fn corruption_truncation_append_reorder_duplicate_and_cross_binding_are_refused() {
    let protector = TestProtector::default();
    let length = SNAPSHOT_CHUNK_BYTES as u64 * 2;
    let (container, encoded) = encoded_small(length, &protector);
    let manifest = encoded.manifest();
    let mut cases = Vec::new();
    for cut in [
        0,
        HEADER_BYTES - 1,
        HEADER_BYTES + FRAME_BYTES,
        container.len() - 1,
    ] {
        cases.push(container[..cut].to_vec());
    }
    let mut appended = container.clone();
    appended.push(0);
    cases.push(appended);
    let mut bad = container.clone();
    bad[HEADER_BYTES + FRAME_BYTES + 33] ^= 1;
    cases.push(bad);
    let frame_size = FRAME_BYTES + SNAPSHOT_CHUNK_BYTES + 32;
    let mut reordered = container.clone();
    let (left, right) = reordered[HEADER_BYTES..].split_at_mut(frame_size);
    left.swap_with_slice(right);
    cases.push(reordered);
    let mut duplicate = container.clone();
    duplicate.copy_within(
        HEADER_BYTES..HEADER_BYTES + frame_size,
        HEADER_BYTES + frame_size,
    );
    cases.push(duplicate);
    let mut oversized = container.clone();
    oversized[HEADER_BYTES + 20..HEADER_BYTES + 24].copy_from_slice(&u32::MAX.to_le_bytes());
    cases.push(oversized);
    let mut offset = container.clone();
    offset[HEADER_BYTES + 8..HEADER_BYTES + 16].copy_from_slice(&u64::MAX.to_le_bytes());
    cases.push(offset);
    for bytes in cases {
        assert!(
            verify_container(
                &mut Cursor::new(bytes),
                &protector,
                manifest,
                limits(),
                &mut || false
            )
            .is_err()
        );
    }
    let mut other = binding(length);
    other.record_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    let mut other_container = Vec::new();
    encode_snapshot(
        &mut Generated::new(length),
        &mut other_container,
        &protector,
        &other,
        limits(),
        &mut || false,
    )
    .unwrap();
    assert!(
        verify_container(
            &mut Cursor::new(other_container),
            &protector,
            manifest,
            limits(),
            &mut || false
        )
        .is_err()
    );
    let mut altered = manifest.clone();
    altered.content_sha256[0] ^= 1;
    assert!(
        verify_container(
            &mut Cursor::new(container),
            &protector,
            &altered,
            limits(),
            &mut || false
        )
        .is_err()
    );
}

#[test]
fn metadata_authentication_scope_record_limits_and_manifest_framing_are_strict() {
    let protector = TestProtector::default();
    let (_, encoded) = encoded_small(10, &protector);
    let b = binding(10);
    let mut scope = b.scope.clone();
    scope.account_subject = "other".into();
    assert!(
        open_manifest(
            encoded.sealed_manifest(),
            &protector,
            &scope,
            &b.record_id,
            limits()
        )
        .is_err()
    );
    assert!(
        open_manifest(
            encoded.sealed_manifest(),
            &protector,
            &b.scope,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            limits()
        )
        .is_err()
    );
    let mut bad = encoded.sealed_manifest().to_vec();
    bad[MANIFEST_HEADER_BYTES + 33] ^= 1;
    assert!(open_manifest(&bad, &protector, &b.scope, &b.record_id, limits()).is_err());
    for bytes in [
        encoded.sealed_manifest()[..MANIFEST_HEADER_BYTES - 1].to_vec(),
        [encoded.sealed_manifest(), &[0]].concat(),
    ] {
        assert!(open_manifest(&bytes, &protector, &b.scope, &b.record_id, limits()).is_err());
    }
    let short = SnapshotLimits::new(9, 128 * 1024 * 1024, 1024).unwrap();
    assert!(
        open_manifest(
            encoded.sealed_manifest(),
            &protector,
            &b.scope,
            &b.record_id,
            short
        )
        .is_err()
    );
    let mut wrong = encoded.manifest().clone();
    wrong.chunk_count = u64::MAX;
    assert!(validate_manifest(&wrong, limits()).is_err());
    wrong = encoded.manifest().clone();
    wrong.container_len = u64::MAX;
    assert!(validate_manifest(&wrong, limits()).is_err());
    let mut no_read = Generated::new(u64::MAX);
    let mut large = binding(u64::MAX);
    assert_eq!(
        encode_snapshot(
            &mut no_read,
            &mut io::sink(),
            &protector,
            &large,
            limits(),
            &mut || false
        )
        .err(),
        Some(SnapshotError::LimitExceeded)
    );
    assert_eq!(no_read.offset, 0);
    large.generation = 0;
    assert_eq!(
        encode_snapshot(
            &mut no_read,
            &mut io::sink(),
            &protector,
            &large,
            limits(),
            &mut || false
        )
        .err(),
        Some(SnapshotError::InvalidBinding)
    );
}

#[test]
fn cancellation_between_chunks_never_returns_a_commit_or_local_check() {
    let protector = TestProtector::default();
    let b = binding(SNAPSHOT_CHUNK_BYTES as u64 * 3);
    let mut source = Generated::new(b.content_len);
    let mut calls = 0;
    let error = encode_snapshot(
        &mut source,
        &mut io::sink(),
        &protector,
        &b,
        limits(),
        &mut || {
            calls += 1;
            calls >= 3
        },
    )
    .err()
    .unwrap();
    assert_eq!(error, SnapshotError::Cancelled);
    assert_eq!(source.offset, SNAPSHOT_CHUNK_BYTES as u64);
    let (container, encoded) = encoded_small(b.content_len, &protector);
    let mut calls = 0;
    let error = verify_container(
        &mut Cursor::new(container),
        &protector,
        encoded.manifest(),
        limits(),
        &mut || {
            calls += 1;
            calls >= 3
        },
    )
    .err()
    .unwrap();
    assert_eq!(error, SnapshotError::Cancelled);
}

#[test]
fn chunks_cannot_be_transplanted_even_with_matching_frames_and_header() {
    let protector = TestProtector::default();
    let length = SNAPSHOT_CHUNK_BYTES as u64 + 1;
    let (mut container, encoded) = encoded_small(length, &protector);
    let mut changed = binding(length);
    changed.scope.space_id = "other-space".into();
    let mut foreign = Vec::new();
    encode_snapshot(
        &mut Generated::new(length),
        &mut foreign,
        &protector,
        &changed,
        limits(),
        &mut || false,
    )
    .unwrap();
    // Leave the expected header and all frame lengths intact, replacing only
    // the first protected blob. Rejection must come from its binding AAD.
    let start = HEADER_BYTES + FRAME_BYTES;
    let end = start + SNAPSHOT_CHUNK_BYTES + 32;
    container[start..end].copy_from_slice(&foreign[start..end]);
    assert_eq!(
        verify_container(
            &mut Cursor::new(container),
            &protector,
            encoded.manifest(),
            limits(),
            &mut || false,
        )
        .err(),
        Some(SnapshotError::ProtectionFailed)
    );
}

#[test]
fn io_failure_and_container_budget_never_produce_committed_metadata() {
    struct FailWrite;
    impl Write for FailWrite {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic write failure"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let protector = TestProtector::default();
    let mut source = Generated::new(1);
    assert_eq!(
        encode_snapshot(
            &mut source,
            &mut FailWrite,
            &protector,
            &binding(1),
            limits(),
            &mut || false,
        )
        .err(),
        Some(SnapshotError::Io)
    );
    assert_eq!(source.offset, 0);
    let tiny = SnapshotLimits::new(1, (HEADER_BYTES + FRAME_BYTES + 1) as u64, 1).unwrap();
    let mut partial = Vec::new();
    assert_eq!(
        encode_snapshot(
            &mut Generated::new(1),
            &mut partial,
            &protector,
            &binding(1),
            tiny,
            &mut || false,
        )
        .err(),
        Some(SnapshotError::LimitExceeded)
    );
    assert!(partial.len() <= tiny.max_container_bytes as usize);
}

#[test]
fn metadata_open_has_no_dependency_on_body_existence_or_validity() {
    let protector = TestProtector::default();
    let (mut body, encoded) = encoded_small(20, &protector);
    body.clear();
    let b = binding(20);
    let before = protector.open_calls.load(Ordering::Relaxed);
    let manifest = open_manifest(
        encoded.sealed_manifest(),
        &protector,
        &b.scope,
        &b.record_id,
        limits(),
    )
    .unwrap();
    assert_eq!(protector.open_calls.load(Ordering::Relaxed), before + 1);
    assert_eq!(manifest.binding(), &b);
    assert!(
        verify_container(
            &mut Cursor::new(body),
            &protector,
            &manifest,
            limits(),
            &mut || false
        )
        .is_err()
    );
}

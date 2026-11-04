use super::*;
use crate::JournalError;
use std::{
    fs::File,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

// Synthetic authentication detector, not a production cipher/DPAPI claim.
#[derive(Default)]
struct Protector {
    tamper: AtomicBool,
}
impl EditRecordProtector for Protector {
    fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, JournalError> {
        let mut hash = Sha256::new();
        hash.update(aad);
        hash.update(plain);
        let mut result = hash.finalize().to_vec();
        result.extend_from_slice(plain);
        Ok(result)
    }
    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, JournalError> {
        if sealed.len() < 32 {
            return Err(JournalError::ProtectionFailed);
        }
        let mut hash = Sha256::new();
        hash.update(aad);
        hash.update(&sealed[32..]);
        if hash.finalize().as_slice() != &sealed[..32] {
            return Err(JournalError::ProtectionFailed);
        }
        let mut plain = sealed[32..].to_vec();
        if self.tamper.load(Ordering::Relaxed) && !plain.is_empty() {
            plain[0] ^= 1;
        }
        Ok(plain)
    }
}
fn binding(length: u64) -> SnapshotBinding {
    SnapshotBinding {
        record_id: "0123456789abcdef0123456789abcdef".into(),
        scope: EditJournalScope {
            profile_id: "test".into(),
            server_origin: "https://synthetic.invalid".into(),
            account_subject: "subject".into(),
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
        relative_path: "file.bin".into(),
        remote: Some(RemoteEditBaseline {
            resource_id: "file".into(),
            etag: "\"v1\"".into(),
            byte_len: length,
        }),
        content_len: length,
    }
}
fn limits() -> SnapshotLimits {
    SnapshotLimits::new(64 * 1024 * 1024, 128 * 1024 * 1024, 1024).unwrap()
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
fn encoded(length: u64, protector: &Protector) -> (File, SnapshotManifest) {
    let mut file = tempfile::tempfile().unwrap();
    let result = encode_snapshot(
        &mut Generated(length),
        &mut file,
        protector,
        &binding(length),
        limits(),
        &mut || false,
    )
    .unwrap();
    // Exercise authenticated metadata decode, not just encoder-returned fields.
    let manifest = open_manifest(
        result.sealed_manifest(),
        protector,
        &binding(length).scope,
        &binding(length).record_id,
        limits(),
    )
    .unwrap();
    (file, manifest)
}
#[derive(Default)]
struct Control {
    fail: AtomicBool,
    extra: AtomicBool,
    interrupts: AtomicUsize,
    max: AtomicUsize,
}
struct Controlled {
    file: File,
    control: Arc<Control>,
}
impl Read for Controlled {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.control.max.fetch_max(out.len(), Ordering::Relaxed);
        if self.control.fail.load(Ordering::Relaxed) {
            return Err(io::Error::other("synthetic private path must not escape"));
        }
        if self.control.interrupts.load(Ordering::Relaxed) > 0 {
            self.control.interrupts.fetch_sub(1, Ordering::Relaxed);
            return Err(io::ErrorKind::Interrupted.into());
        }
        let n = self.file.read(out)?;
        if n == 0 && !out.is_empty() && self.control.extra.load(Ordering::Relaxed) {
            out[0] = b'!';
            return Ok(1);
        }
        Ok(n)
    }
}
impl Seek for Controlled {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        self.file.seek(p)
    }
}
fn controlled(
    length: u64,
) -> (
    AuthenticatedSnapshotReader<Controlled>,
    Arc<Control>,
    Arc<AtomicBool>,
    Arc<Protector>,
) {
    let protector = Arc::new(Protector::default());
    let (file, manifest) = encoded(length, &protector);
    let control = Arc::new(Control::default());
    control.interrupts.store(2, Ordering::Relaxed);
    let cancel = Arc::new(AtomicBool::new(false));
    let cancellation = cancel.clone();
    let reader = AuthenticatedSnapshotReader::new(
        Controlled {
            file,
            control: control.clone(),
        },
        manifest,
        protector.clone(),
        limits(),
        Arc::new(move || cancellation.load(Ordering::Relaxed)),
    )
    .unwrap();
    (reader, control, cancel, protector)
}
#[test]
fn disk_backed_generated_large_body_has_bounded_requests_and_plaintext() {
    let length = 17 * 1024 * 1024 + 7;
    let (mut reader, control, _, _) = controlled(length);
    let mut output = [0; 8191];
    let mut total = 0u64;
    let mut hash = Sha256::new();
    loop {
        let n = reader.read(&mut output).unwrap();
        if n == 0 {
            break;
        }
        assert!(output[..n].iter().all(|b| *b == b'x'));
        hash.update(&output[..n]);
        total += n as u64;
        assert!(reader.plaintext.len() <= SNAPSHOT_CHUNK_BYTES);
        assert!(reader.ciphertext.len() <= MAX_SNAPSHOT_SEALED_CHUNK_BYTES);
    }
    assert_eq!(total, length);
    assert_eq!(
        <[u8; 32]>::from(hash.finalize()),
        reader.manifest.content_sha256
    );
    assert!(control.max.load(Ordering::Relaxed) <= MAX_SNAPSHOT_SEALED_CHUNK_BYTES);
}
#[test]
fn tiny_reads_empty_exact_and_partial_chunks_with_interrupts() {
    for length in [
        0,
        1,
        SNAPSHOT_CHUNK_BYTES as u64,
        SNAPSHOT_CHUNK_BYTES as u64 + 3,
    ] {
        let (mut reader, control, _, _) = controlled(length);
        control.interrupts.store(3, Ordering::Relaxed);
        assert_eq!(reader.read(&mut []).unwrap(), 0);
        let mut total = 0;
        let mut byte = [0];
        while reader.read(&mut byte).unwrap() != 0 {
            assert_eq!(byte[0], b'x');
            total += 1;
        }
        assert_eq!(total, length);
        assert_eq!(reader.read(&mut byte).unwrap(), 0);
    }
}
#[test]
fn constructor_rejects_corrupt_truncated_appended_and_wrong_manifest() {
    for mode in 0..4 {
        let protector = Arc::new(Protector::default());
        let (mut file, mut manifest) = encoded(SNAPSHOT_CHUNK_BYTES as u64 + 1, &protector);
        match mode {
            0 => {
                file.seek(SeekFrom::Start(
                    HEADER_BYTES as u64 + FRAME_BYTES as u64 + 1,
                ))
                .unwrap();
                file.write_all(b"!").unwrap();
            }
            1 => {
                file.set_len(manifest.container_len - 1).unwrap();
            }
            2 => {
                file.seek(SeekFrom::End(0)).unwrap();
                file.write_all(b"!").unwrap();
            }
            _ => {
                manifest.binding.generation += 1;
            }
        }
        assert!(
            AuthenticatedSnapshotReader::new(
                file,
                manifest,
                protector,
                limits(),
                Arc::new(|| false)
            )
            .is_err()
        );
    }
}
#[test]
fn cancellation_and_source_failures_remain_terminal_even_for_empty_reads() {
    for cancel_error in [true, false] {
        let (mut reader, control, cancel, _) = controlled(SNAPSHOT_CHUNK_BYTES as u64 + 1);
        let mut first = [0];
        assert_eq!(reader.read(&mut first).unwrap(), 1);
        if cancel_error {
            cancel.store(true, Ordering::Relaxed);
        } else {
            // Drain the buffered first frame before failing the underlying source.
            let mut rest = [0; SNAPSHOT_CHUNK_BYTES - 1];
            reader.read_exact(&mut rest).unwrap();
            control.fail.store(true, Ordering::Relaxed);
        }
        let error = reader.read(&mut first).unwrap_err();
        assert!(!error.to_string().contains("private path"));
        cancel.store(false, Ordering::Relaxed);
        control.fail.store(false, Ordering::Relaxed);
        for _ in 0..3 {
            assert_eq!(reader.read(&mut first).unwrap_err().kind(), error.kind());
            assert!(reader.read(&mut []).is_err());
        }
    }
}
#[test]
fn final_chunk_is_withheld_until_second_pass_digest_and_eof_succeed() {
    for extra in [true, false] {
        let (mut reader, control, _, protector) = controlled(SNAPSHOT_CHUNK_BYTES as u64 + 7);
        let mut first = [0; SNAPSHOT_CHUNK_BYTES];
        assert_eq!(reader.read(&mut first).unwrap(), first.len());
        if extra {
            control.extra.store(true, Ordering::Relaxed);
        } else {
            protector.tamper.store(true, Ordering::Relaxed);
        }
        let mut final_bytes = [0xa5; 7];
        assert!(reader.read(&mut final_bytes).is_err());
        assert_eq!(final_bytes, [0xa5; 7]);
        assert!(reader.read(&mut final_bytes).is_err());
    }
}

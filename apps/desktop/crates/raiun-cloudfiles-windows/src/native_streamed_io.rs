//! Bounded digest-only completion reads. No upload or native clean authority.
use crate::Error;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const DIGEST_CHUNK_BYTES: usize = 64 * 1024;

/// Eligibility only, never a capture receipt or native completion authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CaptureKind {
    Vault,
    Legacy,
    Streamed,
}

pub(super) fn select_capture_kind(
    length: u64,
    streamed_admitted: bool,
    vault: bool,
) -> Result<CaptureKind, Error> {
    if length > crate::MAX_FILE_BYTES {
        return Err(Error::EditRecoveryUnavailable);
    }
    if vault {
        if length > crate::MAX_REQUEST_BYTES {
            return Err(Error::EditRecoveryUnavailable);
        }
        return Ok(CaptureKind::Vault);
    }
    if streamed_admitted {
        return Ok(CaptureKind::Streamed);
    }
    if length > crate::MAX_REQUEST_BYTES {
        return Err(Error::EditRecoveryUnavailable);
    }
    Ok(CaptureKind::Legacy)
}

#[cfg(any(windows, test))]
fn offset_words(offset: u64) -> (u32, u32) {
    (offset as u32, (offset >> 32) as u32)
}

/// Read exactly the declared content and then independently probe EOF. The
/// reader must return only initialized bytes, no more than the supplied slice.
/// Any short body read, extra byte, cancellation or native error fails closed.
fn digest_bounded(
    expected_len: u64,
    cancelled: impl Fn() -> bool,
    mut read_at: impl FnMut(u64, &mut [u8], bool) -> Result<usize, Error>,
) -> Result<String, Error> {
    let mut buffer = Zeroizing::new([0u8; DIGEST_CHUNK_BYTES]);
    let mut hash = Sha256::new();
    let mut offset = 0u64;
    while offset < expected_len {
        if cancelled() {
            return Err(Error::EditRecoveryUnavailable);
        }
        let request = (expected_len - offset).min(DIGEST_CHUNK_BYTES as u64) as usize;
        let count = read_at(offset, &mut buffer[..request], false)?;
        if count != request || cancelled() {
            return Err(Error::EditRecoveryUnavailable);
        }
        hash.update(&buffer[..count]);
        offset = offset
            .checked_add(count as u64)
            .ok_or(Error::EditRecoveryUnavailable)?;
    }
    if cancelled() || read_at(expected_len, &mut buffer[..1], true)? != 0 || cancelled() {
        return Err(Error::EditRecoveryUnavailable);
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(windows)]
mod windows {
    use super::super::{
        CompletionIo, CompletionOverlapped, GetLastError, GetOverlappedResult, Handle,
        ProtectedCompletionFile, ReadFile, win32_io_error,
    };
    use super::*;
    use crate::CancellationToken;
    use std::{ptr::null_mut, time::Duration};

    const ERROR_HANDLE_EOF: u32 = 38;
    const ERROR_IO_INCOMPLETE: u32 = 996;
    const ERROR_IO_PENDING: u32 = 997;

    fn cancelled(token: Option<&CancellationToken>) -> bool {
        token.is_some_and(|token| token.is_cancelled() || token.is_expired())
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CancelIoEx(handle: Handle, overlapped: *const CompletionOverlapped) -> i32;
    }

    impl ProtectedCompletionFile {
        /// Hash the exact referenced file with bounded memory and explicit u64
        /// offsets. Cancellation requests cancel+actual drain; a broken driver
        /// can therefore block return. This creates no completion authority and
        /// changes neither sharing/oplock policy nor the production size gate.
        pub(in super::super) fn digest_complete(
            &self,
            expected_len: u64,
            cancellation: Option<&CancellationToken>,
        ) -> Result<String, Error> {
            digest_bounded(
                expected_len,
                || cancelled(cancellation),
                |offset, buffer, eof_probe| {
                    let mut read = PendingRead {
                        file: self,
                        io: CompletionIo::new()?,
                        buffer,
                        pending: false,
                    };
                    read.read_at(offset, eof_probe, cancellation)
                },
            )
        }
    }

    /// Borrows the Cf owner and caller buffer through actual I/O completion.
    /// This guard is never moved after submission; methods only borrow it.
    /// Its Drop also drains on unwind before either borrow can be released.
    struct PendingRead<'a> {
        file: &'a ProtectedCompletionFile,
        io: CompletionIo,
        buffer: &'a mut [u8],
        pending: bool,
    }

    impl PendingRead<'_> {
        fn read_at(
            &mut self,
            offset: u64,
            eof_probe: bool,
            cancellation: Option<&CancellationToken>,
        ) -> Result<usize, Error> {
            if cancelled(cancellation) {
                return Err(Error::EditRecoveryUnavailable);
            }
            let length =
                u32::try_from(self.buffer.len()).map_err(|_| Error::EditRecoveryUnavailable)?;
            if length == 0 || length as usize > DIGEST_CHUNK_BYTES || (eof_probe && length != 1) {
                return Err(Error::EditRecoveryUnavailable);
            }
            (self.io.overlapped.offset, self.io.overlapped.offset_high) = offset_words(offset);
            // SAFETY: the protected Cf owner remains referenced through this
            // guard. Buffer/event/OVERLAPPED live at stable locations until
            // terminal completion, including cancellation and unwinding. No
            // ownership of the borrowed Win32 handle is taken or transferred.
            let submitted = unsafe {
                ReadFile(
                    self.file.raw,
                    self.buffer.as_mut_ptr().cast(),
                    length,
                    null_mut(),
                    &mut self.io.overlapped,
                )
            };
            if submitted == 0 {
                // Capture before any OS call changes last-error state.
                let code = unsafe { GetLastError() };
                if code != ERROR_IO_PENDING {
                    if eof_probe && code == ERROR_HANDLE_EOF {
                        return Ok(0);
                    }
                    return Err(win32_io_error("submit bounded completion digest read"));
                }
            }
            self.pending = true;
            loop {
                if cancelled(cancellation) {
                    self.cancel_and_drain();
                    return Err(Error::EditRecoveryUnavailable);
                }
                let mut count = 0;
                // SAFETY: exact live submitted pair; no buffer access occurs
                // until completion. wait=false permits cancellation polling.
                let complete = unsafe {
                    GetOverlappedResult(self.file.raw, &mut self.io.overlapped, &mut count, 0)
                };
                if complete != 0 {
                    self.pending = false;
                    return usize::try_from(count).map_err(|_| Error::EditRecoveryUnavailable);
                }
                let code = unsafe { GetLastError() };
                if !matches!(code, ERROR_IO_INCOMPLETE | ERROR_IO_PENDING) {
                    // Private valid handle/event/pair: this is the operation's
                    // terminal status. EOF is accepted only for planned probe.
                    self.pending = false;
                    return if eof_probe && code == ERROR_HANDLE_EOF {
                        Ok(0)
                    } else {
                        Err(win32_io_error("finish bounded completion digest read"))
                    };
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        fn cancel_and_drain(&mut self) {
            if !self.pending {
                return;
            }
            // SAFETY: cancel only this read. Success or NOT_FOUND is not drain
            // proof, so all references/event/buffer remain live for the wait.
            unsafe { CancelIoEx(self.file.raw, &self.io.overlapped) };
            loop {
                let mut count = 0;
                // SAFETY: exact pair and storage stay live through definitive
                // terminal completion; an unresponsive driver can block here.
                let complete = unsafe {
                    GetOverlappedResult(self.file.raw, &mut self.io.overlapped, &mut count, 1)
                };
                if complete != 0
                    || !matches!(
                        unsafe { GetLastError() },
                        ERROR_IO_INCOMPLETE | ERROR_IO_PENDING
                    )
                {
                    self.pending = false;
                    return;
                }
            }
        }
    }

    impl Drop for PendingRead<'_> {
        fn drop(&mut self) {
            self.cancel_and_drain();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn generated(offset: u64) -> u8 {
        (offset.wrapping_mul(37) % 251) as u8
    }

    #[test]
    fn offset_words_preserve_u64_boundary_and_high_bits() {
        for offset in [
            0,
            65536,
            u32::MAX as u64,
            1u64 << 32,
            (1u64 << 32) + 7,
            u64::MAX,
        ] {
            let (low, high) = offset_words(offset);
            assert_eq!((u64::from(high) << 32) | u64::from(low), offset);
        }
    }

    #[test]
    fn known_sha256_is_checked_with_exact_eof_probe() {
        let digest = digest_bounded(
            3,
            || false,
            |offset, buffer, eof| {
                if eof {
                    assert_eq!(offset, 3);
                    return Ok(0);
                }
                assert_eq!(offset, 0);
                buffer.copy_from_slice(b"abc");
                Ok(3)
            },
        )
        .unwrap();
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn bounded_digest_covers_empty_exact_partial_chunks_and_large_generated_body() {
        for length in [0, 1, 65536, 65537, 17 * 1024 * 1024 + 7] {
            let mut expected = Sha256::new();
            let mut max_request = 0;
            let mut expected_offset = 0;
            let actual = digest_bounded(
                length,
                || false,
                |offset, buffer, eof| {
                    assert_eq!(offset, expected_offset);
                    max_request = max_request.max(buffer.len());
                    if eof {
                        assert_eq!(offset, length);
                        assert_eq!(buffer.len(), 1);
                        return Ok(0);
                    }
                    for (i, byte) in buffer.iter_mut().enumerate() {
                        *byte = generated(offset + i as u64);
                    }
                    expected.update(&*buffer);
                    expected_offset += buffer.len() as u64;
                    Ok(buffer.len())
                },
            )
            .unwrap();
            assert_eq!(actual, format!("{:x}", expected.finalize()));
            assert!(max_request <= DIGEST_CHUNK_BYTES);
        }
    }

    #[test]
    fn streamed_selection_covers_every_new_ordinary_length_without_vault_fallback() {
        for length in [
            0,
            1,
            2 * 1024 * 1024 + 7,
            crate::MAX_REQUEST_BYTES,
            crate::MAX_REQUEST_BYTES + 1,
            crate::MAX_FILE_BYTES,
        ] {
            assert_eq!(
                select_capture_kind(length, true, false).unwrap(),
                CaptureKind::Streamed
            );
        }
        for length in [0, 1, crate::MAX_REQUEST_BYTES] {
            assert_eq!(
                select_capture_kind(length, false, false).unwrap(),
                CaptureKind::Legacy
            );
            assert_eq!(
                select_capture_kind(length, true, true).unwrap(),
                CaptureKind::Vault
            );
            assert_eq!(
                select_capture_kind(length, false, true).unwrap(),
                CaptureKind::Vault
            );
        }
        assert!(select_capture_kind(crate::MAX_REQUEST_BYTES + 1, false, false).is_err());
        assert!(select_capture_kind(crate::MAX_REQUEST_BYTES + 1, true, true).is_err());
        assert!(select_capture_kind(crate::MAX_FILE_BYTES + 1, true, false).is_err());
        assert!(select_capture_kind(crate::MAX_FILE_BYTES + 1, true, true).is_err());
    }

    #[test]
    fn recovery_job_cancel_after_first_native_hash_chunk_never_finishes_digest() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let stopped = Arc::new(AtomicBool::new(false));
        let observed = stopped.clone();
        let job =
            crate::CancellationToken::for_recovery_job(crate::StreamedRecoveryPolicy::default())
                .with_revocation_check(Arc::new(move || observed.load(Ordering::Acquire)));
        let calls = Cell::new(0);
        let result = digest_bounded(
            65537,
            || job.is_stopped(),
            |_, buffer, _| {
                calls.set(calls.get() + 1);
                stopped.store(true, Ordering::Release);
                Ok(buffer.len())
            },
        );
        assert!(result.is_err());
        assert_eq!(calls.get(), 1);
        assert!(job.is_stopped());
    }

    #[test]
    fn truncated_extra_overcount_and_reader_error_are_not_digests() {
        assert!(digest_bounded(5, || false, |_, _, _| Ok(4)).is_err());
        assert!(digest_bounded(5, || false, |_, b, _| Ok(b.len() + 1)).is_err());
        assert!(digest_bounded(0, || false, |_, _, _| Ok(1)).is_err());
        assert!(
            digest_bounded(1, || false, |_, _, _| Err(Error::EditRecoveryUnavailable)).is_err()
        );
    }

    #[test]
    fn cancellation_before_during_and_after_eof_prevents_digest_success() {
        assert!(
            digest_bounded(1, || true, |_, _, _| panic!("no read after cancellation")).is_err()
        );
        let cancelled = Cell::new(false);
        assert!(
            digest_bounded(
                65537,
                || cancelled.get(),
                |_, buffer, _| {
                    cancelled.set(true);
                    Ok(buffer.len())
                }
            )
            .is_err()
        );
        let cancelled = Cell::new(false);
        assert!(
            digest_bounded(
                0,
                || cancelled.get(),
                |_, _, eof| {
                    assert!(eof);
                    cancelled.set(true);
                    Ok(0)
                }
            )
            .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires isolated native Windows Cloud Files API; ordinary synthetic files only; helper has no clean authority"]
    fn native_digest_exact_offsets_empty_partial_and_seventeen_megabytes() {
        use super::super::{ProtectedCompletionFile, create_private_test_root, wide_path};
        use std::io::Write;
        let root = create_private_test_root().unwrap();
        // Preserve this task-owned root and all files on failure, as existing
        // protected-completion fixtures do. No provider/mount hook is added.
        for length in [0u64, 1, 65536, 65537, 17 * 1024 * 1024 + 7] {
            let path = root.join(format!("digest-{length}.bin"));
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .unwrap();
            let mut expected = Sha256::new();
            let mut buffer = Zeroizing::new([0u8; DIGEST_CHUNK_BYTES]);
            let mut offset = 0;
            while offset < length {
                let count = (length - offset).min(DIGEST_CHUNK_BYTES as u64) as usize;
                for (index, byte) in buffer[..count].iter_mut().enumerate() {
                    *byte = generated(offset + index as u64);
                }
                file.write_all(&buffer[..count]).unwrap();
                expected.update(&buffer[..count]);
                offset += count as u64;
            }
            file.sync_all().unwrap();
            drop(file);
            let guard = ProtectedCompletionFile::open(&wide_path(&path).unwrap()).unwrap();
            assert_eq!(
                guard.digest_complete(length, None).unwrap(),
                format!("{:x}", expected.finalize())
            );
            assert!(guard.digest_complete(length + 1, None).is_err());
            if length != 0 {
                assert!(guard.digest_complete(length - 1, None).is_err());
            }
            let cancelled = crate::CancellationToken::new();
            cancelled.cancel();
            assert!(guard.digest_complete(length, Some(&cancelled)).is_err());
            drop(guard);
        }
    }
}

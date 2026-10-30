//! Independent count/hash/EOF witness; no filesystem or publication authority.
use sha2::{Digest, Sha256};
use std::io::{self, Read};
pub(super) struct CaptureHash {
    expected: u64,
    count: u64,
    hash: Sha256,
    eof: bool,
    failed: bool,
}
impl CaptureHash {
    pub(super) fn new(expected: u64) -> Self {
        Self {
            expected,
            count: 0,
            hash: Sha256::new(),
            eof: false,
            failed: false,
        }
    }
    pub(super) fn observe(&mut self, bytes: &[u8]) -> bool {
        if self.failed {
            return false;
        }
        if self.eof {
            if bytes.is_empty() {
                return true;
            }
            self.failed = true;
            return false;
        }
        if bytes.is_empty() {
            self.eof = true;
            return self.count == self.expected;
        }
        let Some(next) = self.count.checked_add(bytes.len() as u64) else {
            self.failed = true;
            return false;
        };
        if next > self.expected {
            self.failed = true;
            return false;
        }
        self.count = next;
        self.hash.update(bytes);
        true
    }
    pub(super) fn finish(self) -> Option<[u8; 32]> {
        (self.eof && !self.failed && self.count == self.expected)
            .then(|| self.hash.finalize().into())
    }
}
pub(super) struct CaptureReader<'a, R: Read, C: FnMut() -> bool> {
    source: &'a mut R,
    hash: CaptureHash,
    cancelled: C,
}
impl<'a, R: Read, C: FnMut() -> bool> CaptureReader<'a, R, C> {
    pub(super) fn new(source: &'a mut R, length: u64, cancelled: C) -> Self {
        Self {
            source,
            hash: CaptureHash::new(length),
            cancelled,
        }
    }
    pub(super) fn finish(self) -> Option<[u8; 32]> {
        self.hash.finish()
    }
}
impl<R: Read, C: FnMut() -> bool> Read for CaptureReader<'_, R, C> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if (self.cancelled)() {
            return Err(io::Error::other("plain capture stopped"));
        }
        let bound = output.len().min(64 * 1024);
        let count = self.source.read(&mut output[..bound])?;
        if count > bound || (self.cancelled)() || !self.hash.observe(&output[..count]) {
            return Err(io::Error::other("plain capture evidence unavailable"));
        }
        Ok(count)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_empty_and_partitioned_streams_require_eof() {
        for bytes in [b"".as_slice(), b"abc"] {
            let mut witness = CaptureHash::new(bytes.len() as u64);
            for chunk in bytes.chunks(2) {
                assert!(witness.observe(chunk));
            }
            assert!(witness.observe(&[]));
            assert_eq!(witness.finish(), Some(Sha256::digest(bytes).into()));
        }
        let mut missing = CaptureHash::new(3);
        assert!(missing.observe(b"abc"));
        assert!(missing.finish().is_none());
    }
    #[test]
    fn truncation_overflow_and_after_eof_are_refused() {
        let mut short = CaptureHash::new(3);
        assert!(short.observe(b"ab"));
        assert!(!short.observe(&[]));
        assert!(short.finish().is_none());
        let mut long = CaptureHash::new(2);
        assert!(!long.observe(b"abc"));
        assert!(long.finish().is_none());
        let mut extra = CaptureHash::new(0);
        assert!(extra.observe(&[]));
        assert!(!extra.observe(b"a"));
        assert!(extra.finish().is_none());
    }
}

#[cfg(test)]
mod reader_tests {
    use super::*;
    use std::cell::Cell;
    #[test]
    fn actual_reader_bounds_each_read_and_matches_complete_digest() {
        struct Generated {
            remaining: usize,
            max: usize,
        }
        impl Read for Generated {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.max = self.max.max(b.len());
                let n = b.len().min(self.remaining);
                b[..n].fill(42);
                self.remaining -= n;
                Ok(n)
            }
        }
        let mut source = Generated {
            remaining: 17 * 1024 * 1024 + 7,
            max: 0,
        };
        let length = source.remaining;
        let mut reader = CaptureReader::new(&mut source, length as u64, || false);
        let mut buffer = vec![0; 256 * 1024];
        let mut expected = Sha256::new();
        let mut count = 0;
        loop {
            let n = reader.read(&mut buffer).unwrap();
            if n == 0 {
                break;
            }
            count += n;
            expected.update(&buffer[..n]);
        }
        assert_eq!(reader.finish(), Some(expected.finalize().into()));
        assert_eq!(count, length);
        assert_eq!(source.max, 64 * 1024);
    }
    #[test]
    fn cancellation_before_or_during_read_never_yields_successful_hash() {
        let stopped = Cell::new(true);
        let mut source = std::io::Cursor::new(b"abc");
        let mut reader = CaptureReader::new(&mut source, 3, || stopped.get());
        let mut b = [0; 8];
        assert!(reader.read(&mut b).is_err());
        assert!(reader.finish().is_none());
        assert_eq!(source.position(), 0);
        struct StopDuring<'a>(&'a Cell<bool>);
        impl Read for StopDuring<'_> {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                b[0] = 1;
                self.0.set(true);
                Ok(1)
            }
        }
        stopped.set(false);
        let mut source = StopDuring(&stopped);
        let mut reader = CaptureReader::new(&mut source, 1, || stopped.get());
        assert!(reader.read(&mut b).is_err());
        assert!(reader.finish().is_none());
    }
}

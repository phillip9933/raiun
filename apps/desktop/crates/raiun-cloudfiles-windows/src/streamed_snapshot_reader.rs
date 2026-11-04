//! Pull decoding after full local authentication of the same owned container.
//! The caller must supply an immutable pinned reader and retain its identity
//! guarantees. This reader grants no remote-write or native-completion authority.
use super::*;
use std::sync::Arc;

/// A bounded plaintext reader over one preverified protected container.
///
/// Construction authenticates the whole container before exposing any bytes.
/// Later reads authenticate frames again, and withhold the final plaintext chunk
/// until complete digests, length and EOF have been checked again. The caller
/// still owns the obligation to make R immutable; generic Read + Seek cannot
/// establish filesystem identity or prevent another writer.
pub struct AuthenticatedSnapshotReader<R: Read + Seek> {
    input: R,
    manifest: SnapshotManifest,
    protector: Arc<dyn EditRecordProtector>,
    _limits: SnapshotLimits,
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ciphertext: Zeroizing<Vec<u8>>,
    plaintext: Zeroizing<Vec<u8>>,
    position: usize,
    index: u64,
    offset: u64,
    container_bytes: u64,
    container_digest: Sha256,
    content_digest: Sha256,
    finished: bool,
    failure: Option<SnapshotError>,
}

impl<R: Read + Seek> AuthenticatedSnapshotReader<R> {
    pub fn new(
        mut input: R,
        manifest: SnapshotManifest,
        protector: Arc<dyn EditRecordProtector>,
        limits: SnapshotLimits,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Self, SnapshotError> {
        verify_container(
            &mut input,
            protector.as_ref(),
            &manifest,
            limits,
            &mut || cancelled(),
        )?;
        let mut reader = Self {
            input,
            manifest,
            protector,
            _limits: limits,
            cancelled,
            ciphertext: Zeroizing::new(vec![0; MAX_SNAPSHOT_SEALED_CHUNK_BYTES]),
            plaintext: Zeroizing::new(Vec::new()),
            position: 0,
            index: 0,
            offset: 0,
            container_bytes: 0,
            container_digest: Sha256::new(),
            content_digest: Sha256::new(),
            finished: false,
            failure: None,
        };
        let mut actual = [0; HEADER_BYTES];
        reader.exact(&mut actual)?;
        if actual
            != header(
                &reader.manifest.binding,
                reader.manifest.binding_sha256,
                reader.manifest.chunk_count,
            )
        {
            return Err(SnapshotError::BindingMismatch);
        }
        if reader.manifest.chunk_count == 0 {
            reader.finish()?;
        }
        Ok(reader)
    }

    fn check_cancel(&self) -> Result<(), SnapshotError> {
        if (self.cancelled)() {
            Err(SnapshotError::Cancelled)
        } else {
            Ok(())
        }
    }

    // Same bounds/count/hash contract as ContainerReader::exact. Check between
    // individual reads as well so Interrupted cannot mask cancellation forever.
    fn exact(&mut self, bytes: &mut [u8]) -> Result<(), SnapshotError> {
        let next = self
            .container_bytes
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.manifest.container_len)
            .ok_or(SnapshotError::Malformed)?;
        let mut position = 0;
        while position < bytes.len() {
            self.check_cancel()?;
            match self.input.read(&mut bytes[position..]) {
                Ok(0) => return Err(SnapshotError::Malformed),
                Ok(count) => position += count,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(SnapshotError::Io),
            }
        }
        self.check_cancel()?;
        self.container_digest.update(&*bytes);
        self.container_bytes = next;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), SnapshotError> {
        self.check_cancel()?;
        if self.index != self.manifest.chunk_count
            || self.offset != self.manifest.binding.content_len
            || self.container_bytes != self.manifest.container_len
        {
            return Err(SnapshotError::Malformed);
        }
        let mut byte = Zeroizing::new([0; 1]);
        loop {
            self.check_cancel()?;
            match self.input.read(&mut *byte) {
                Ok(0) => break,
                Ok(_) => return Err(SnapshotError::Malformed),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(SnapshotError::Io),
            }
        }
        self.check_cancel()?;
        if <[u8; 32]>::from(self.content_digest.clone().finalize()) != self.manifest.content_sha256
            || <[u8; 32]>::from(self.container_digest.clone().finalize())
                != self.manifest.container_sha256
        {
            return Err(SnapshotError::Malformed);
        }
        self.finished = true;
        Ok(())
    }

    fn next_chunk(&mut self) -> Result<(), SnapshotError> {
        self.check_cancel()?;
        let length = chunk_len(self.manifest.binding.content_len, self.offset)?;
        let mut frame = [0; FRAME_BYTES];
        self.exact(&mut frame)?;
        let index = u64::from_le_bytes(
            frame[..8]
                .try_into()
                .map_err(|_| SnapshotError::Malformed)?,
        );
        let offset = u64::from_le_bytes(
            frame[8..16]
                .try_into()
                .map_err(|_| SnapshotError::Malformed)?,
        );
        let plain = u32::from_le_bytes(
            frame[16..20]
                .try_into()
                .map_err(|_| SnapshotError::Malformed)?,
        ) as usize;
        let sealed = u32::from_le_bytes(
            frame[20..24]
                .try_into()
                .map_err(|_| SnapshotError::Malformed)?,
        ) as usize;
        if index != self.index
            || offset != self.offset
            || plain != length
            || sealed == 0
            || sealed > MAX_SNAPSHOT_SEALED_CHUNK_BYTES
        {
            return Err(SnapshotError::Malformed);
        }
        // Temporarily move the fixed sealed buffer to avoid overlapping borrows.
        // Restore it on all results, and never allocate a file-sized buffer.
        let mut ciphertext = std::mem::replace(&mut self.ciphertext, Zeroizing::new(Vec::new()));
        let result = self.exact(&mut ciphertext[..sealed]);
        self.ciphertext = ciphertext;
        result?;
        let aad = chunk_aad(
            &self.manifest.binding,
            &self.manifest.binding_sha256,
            index,
            offset,
            length,
        )?;
        let decoded = Zeroizing::new(
            self.protector
                .open(&aad, &self.ciphertext[..sealed])
                .map_err(|_| SnapshotError::ProtectionFailed)?,
        );
        self.ciphertext.as_mut_slice().zeroize();
        if decoded.len() != length {
            return Err(SnapshotError::Malformed);
        }
        self.content_digest.update(&decoded);
        self.offset = self
            .offset
            .checked_add(length as u64)
            .ok_or(SnapshotError::LimitExceeded)?;
        self.index = self
            .index
            .checked_add(1)
            .ok_or(SnapshotError::LimitExceeded)?;
        self.check_cancel()?;
        if self.index == self.manifest.chunk_count {
            self.finish()?;
        }
        // The final chunk becomes available only after finish succeeded.
        self.plaintext = decoded;
        self.position = 0;
        Ok(())
    }

    fn read_checked(&mut self, output: &mut [u8]) -> Result<usize, SnapshotError> {
        self.check_cancel()?;
        if output.is_empty() {
            return Ok(0);
        }
        if self.position == self.plaintext.len() {
            self.plaintext.as_mut_slice().zeroize();
            self.plaintext = Zeroizing::new(Vec::new());
            self.position = 0;
            if self.finished {
                return Ok(0);
            }
            self.next_chunk()?;
        }
        self.check_cancel()?;
        let count = output.len().min(self.plaintext.len() - self.position);
        output[..count].copy_from_slice(&self.plaintext[self.position..self.position + count]);
        self.plaintext[self.position..self.position + count].zeroize();
        self.position += count;
        Ok(count)
    }
}

impl<R: Read + Seek> Read for AuthenticatedSnapshotReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let result = match self.failure {
            Some(error) => Err(error),
            None => self.read_checked(output),
        };
        result.map_err(|error| {
            self.failure = Some(error);
            self.plaintext.as_mut_slice().zeroize();
            self.ciphertext.as_mut_slice().zeroize();
            io::Error::new(
                if error == SnapshotError::Cancelled {
                    io::ErrorKind::ConnectionAborted
                } else {
                    io::ErrorKind::InvalidData
                },
                error,
            )
        })
    }
}

#[cfg(test)]
#[path = "streamed_snapshot_reader_tests.rs"]
mod tests;

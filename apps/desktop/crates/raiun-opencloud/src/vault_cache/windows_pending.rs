//! Authenticated bounded plaintext view over one immutable cache ciphertext.
//! Plaintext lives only in zeroizing blocks; the original unlock is never renewed.
use super::*;
use raiun_cache::CacheContentReader;
use raiun_vault::{VerifiedVaultSession, session::VaultSessionEpoch};
use zeroize::{Zeroize, Zeroizing};

const PLAIN: u64 = 65_536;
const CIPHER: u64 = PLAIN + 16;

pub(crate) struct PendingBodyReadSeek<'a> {
    ciphertext: CacheContentReader,
    sessions: &'a VaultSessionCoordinator,
    scope: VaultSessionScope,
    epoch: VaultSessionEpoch,
    header: Zeroizing<[u8; 32]>,
    cipher_len: u64,
    envelope_len: u64,
    body_offset: u64,
    body_len: u64,
    position: u64,
    block_index: Option<u64>,
    block: Zeroizing<Vec<u8>>,
    sha256: String,
    pub(super) cached_source: Option<(RemoteEntry, String)>,
    cancelled: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
}

impl<'a> PendingBodyReadSeek<'a> {
    pub(super) fn new(
        ciphertext: CacheContentReader,
        sessions: &'a VaultSessionCoordinator,
        scope: &VaultSessionScope,
        expected_cipher_len: u64,
        cancelled: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Self, CloudError> {
        let envelope_len = plaintext_len_from_ciphertext(expected_cipher_len)?;
        if envelope_len > MAX_EDIT_BYTES + EDIT_HEADER_BYTES + MAX_EDIT_METADATA_BYTES as u64
            || ciphertext.metadata().map_err(io_error)?.len() != expected_cipher_len
        {
            return Err(invalid("encrypted edit envelope lengths are invalid"));
        }
        let epoch = sessions.capture_session_epoch(scope).map_err(vault_error)?;
        let mut result = Self {
            ciphertext,
            sessions,
            scope: scope.clone(),
            epoch,
            header: Zeroizing::new([0; 32]),
            cipher_len: expected_cipher_len,
            envelope_len,
            body_offset: 0,
            body_len: envelope_len,
            position: 0,
            block_index: None,
            block: Zeroizing::new(Vec::new()),
            sha256: String::new(),
            cached_source: None,
            cancelled,
        };
        result
            .ciphertext
            .read_exact(&mut *result.header)
            .map_err(io_error)?;
        if result.header[..8] != *b"RCLONE\0\0" {
            return Err(invalid("encrypted edit ciphertext header is invalid"));
        }
        // Authenticate EVERY block before names/state become journal authority.
        let mut offset = 0;
        while offset < envelope_len {
            result.load_block(offset / PLAIN, None).map_err(io_error)?;
            offset = offset
                .checked_add(result.block.len() as u64)
                .ok_or_else(|| invalid("encrypted edit size overflowed"))?;
        }
        if offset != envelope_len {
            return Err(invalid("encrypted edit length changed"));
        }
        result.clear();
        Ok(result)
    }

    pub(super) fn set_body(&mut self, offset: u64, length: u64) -> Result<(), CloudError> {
        if offset.checked_add(length) != Some(self.envelope_len) {
            return Err(invalid("encrypted edit body lengths are invalid"));
        }
        self.body_offset = offset;
        self.body_len = length;
        self.position = 0;
        let mut hash = Sha256::new();
        let mut buffer = Zeroizing::new(vec![0; PLAIN as usize]);
        loop {
            let n = self.read(&mut buffer).map_err(io_error)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        self.sha256 = format!("{:x}", hash.finalize());
        self.seek(SeekFrom::Start(0)).map_err(io_error)?;
        Ok(())
    }

    pub(super) fn with_verified_session<T>(
        &self,
        use_session: impl FnOnce(&VerifiedVaultSession) -> Result<T, CloudError>,
    ) -> Result<T, CloudError> {
        self.sessions
            .with_verified_session_at_epoch(&self.scope, &self.epoch, |session| {
                Ok(use_session(session))
            })
            .map_err(vault_error)?
    }

    pub(crate) fn check_current(&mut self) -> Result<(), CloudError> {
        self.current().map_err(io_error)
    }

    pub(crate) fn set_cancelled(
        &mut self,
        cancelled: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
    ) {
        let original = std::sync::Arc::clone(&self.cancelled);
        self.cancelled = std::sync::Arc::new(move || original() || cancelled());
    }

    fn check_cancelled(&mut self) -> io::Result<()> {
        if (self.cancelled)() {
            self.clear();
            return Err(io::Error::other("encrypted edit operation was cancelled"));
        }
        Ok(())
    }

    pub(crate) fn len(&self) -> u64 {
        self.body_len
    }
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    fn clear(&mut self) {
        self.block.zeroize();
        self.block.clear();
        self.block_index = None;
    }

    fn current(&mut self) -> io::Result<()> {
        self.check_cancelled()?;
        match self
            .sessions
            .with_session_epoch(&self.scope, &self.epoch, || ())
        {
            Ok(()) => Ok(()),
            Err(_) => {
                self.clear();
                Err(io::Error::other("vault session is no longer current"))
            }
        }
    }

    fn load_block(&mut self, index: u64, session: Option<&VerifiedVaultSession>) -> io::Result<()> {
        self.check_cancelled()?;
        if session.is_none() {
            self.current()?;
        }
        if self.block_index == Some(index) {
            return Ok(());
        }
        self.clear();
        let start = index
            .checked_mul(CIPHER)
            .and_then(|n| n.checked_add(32))
            .ok_or_else(|| io::Error::other("encrypted block offset overflowed"))?;
        let remaining = self
            .cipher_len
            .checked_sub(start)
            .ok_or_else(|| io::Error::other("encrypted block offset is invalid"))?;
        let count = remaining.min(CIPHER) as usize;
        if count < 16 {
            return Err(io::Error::other("encrypted block is truncated"));
        }
        let mut ciphertext = Zeroizing::new(vec![0; count]);
        self.ciphertext.seek(SeekFrom::Start(start))?;
        self.ciphertext.read_exact(&mut ciphertext)?;
        let decrypted = match session {
            Some(session) => {
                session.decrypt_authenticated_block_at(&self.header, index, &ciphertext)
            }
            None => self.sessions.decrypt_authenticated_block_at_epoch(
                &self.scope,
                &self.epoch,
                &self.header,
                index,
                &ciphertext,
            ),
        }
        .map_err(|_| io::Error::other("encrypted block authentication failed"))?;
        let plain_start = index
            .checked_mul(PLAIN)
            .ok_or_else(|| io::Error::other("plaintext offset overflowed"))?;
        if decrypted.len() as u64 != self.envelope_len.saturating_sub(plain_start).min(PLAIN) {
            return Err(io::Error::other("encrypted block length changed"));
        }
        self.block = decrypted;
        self.block_index = Some(index);
        Ok(())
    }

    fn read_inner(
        &mut self,
        output: &mut [u8],
        session: Option<&VerifiedVaultSession>,
    ) -> io::Result<usize> {
        self.check_cancelled()?;
        if session.is_none() {
            self.current()?;
        }
        if output.is_empty() || self.position == self.body_len {
            return Ok(0);
        }
        let absolute = self
            .body_offset
            .checked_add(self.position)
            .ok_or_else(|| io::Error::other("pending body offset overflowed"))?;
        self.load_block(absolute / PLAIN, session)?;
        let start = (absolute % PLAIN) as usize;
        let count = output
            .len()
            .min(self.block.len().saturating_sub(start))
            .min((self.body_len - self.position).min(usize::MAX as u64) as usize);
        if count == 0 {
            return Err(io::Error::other("pending body is truncated"));
        }
        if session.is_some() {
            // The enclosing exact-epoch crypto lease already fences this copy.
            output[..count].copy_from_slice(&self.block[start..start + count]);
        } else {
            let copied = self
                .sessions
                .with_session_epoch(&self.scope, &self.epoch, || {
                    output[..count].copy_from_slice(&self.block[start..start + count]);
                });
            if copied.is_err() {
                self.clear();
                return Err(io::Error::other("vault session is no longer current"));
            }
        }
        self.position += count as u64;
        Ok(count)
    }

    /// Encrypt locally under the SAME opaque unlock without coordinator reentry.
    /// The caller must release this local lease before sending the ciphertext.
    pub(crate) fn encrypt_to_ciphertext(
        &mut self,
        destination: &Path,
        maximum: u64,
    ) -> Result<u64, CloudError> {
        self.encrypt_envelope_to_ciphertext(&[], destination, maximum)
    }

    pub(super) fn encrypt_envelope_to_ciphertext(
        &mut self,
        prefix: &[u8],
        destination: &Path,
        maximum: u64,
    ) -> Result<u64, CloudError> {
        self.current().map_err(io_error)?;
        self.position = 0;
        let length = (prefix.len() as u64)
            .checked_add(self.body_len)
            .ok_or_else(|| invalid("encrypted edit size overflowed"))?;
        if length > maximum {
            return Err(invalid("encrypted edit exceeds its size limit"));
        }
        let sessions = self.sessions;
        let scope = self.scope.clone();
        let epoch = self.epoch.clone();
        let result = sessions
            .with_verified_session_at_epoch(&scope, &epoch, |session| {
                let mut direct = DirectReader {
                    body: self,
                    session,
                };
                let mut chain = io::Cursor::new(prefix).chain(&mut direct);
                session.encrypt_file_transactional(&mut chain, destination, length, maximum)
            })
            .map_err(vault_error);
        self.clear();
        result
    }
}

struct DirectReader<'b, 'a> {
    body: &'b mut PendingBodyReadSeek<'a>,
    session: &'b VerifiedVaultSession,
}
impl Read for DirectReader<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.body.read_inner(output, Some(self.session))
    }
}
impl Read for PendingBodyReadSeek<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let result = self.read_inner(output, None);
        if result.is_err() {
            self.clear();
        }
        result
    }
}
impl Seek for PendingBodyReadSeek<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.current()?;
        let next = match position {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.body_len) + i128::from(n),
        };
        if next < 0 || next > i128::from(self.body_len) {
            self.clear();
            return Err(io::Error::other("pending body seek is outside its bounds"));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}

/// Final EOF is part of the encoder transaction: reject wrong protected-body
/// bytes before ciphertext can be published into the journal.
pub(super) struct ExactDigestReader<'a, R: Read> {
    source: &'a mut R,
    remaining: u64,
    digest: Sha256,
    expected: [u8; 32],
    checked: bool,
    cancelled: &'a dyn Fn() -> bool,
}
impl<'a, R: Read> ExactDigestReader<'a, R> {
    pub(super) fn new(
        source: &'a mut R,
        length: u64,
        expected: [u8; 32],
        cancelled: &'a dyn Fn() -> bool,
    ) -> Self {
        Self {
            source,
            remaining: length,
            digest: Sha256::new(),
            expected,
            checked: false,
            cancelled,
        }
    }
}
impl<R: Read> Read for ExactDigestReader<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if (self.cancelled)() {
            return Err(io::Error::other("encrypted edit operation was cancelled"));
        }
        if output.is_empty() {
            return Ok(0);
        }
        if self.remaining > 0 {
            let maximum = output
                .len()
                .min(self.remaining.min(usize::MAX as u64) as usize);
            let count = self.source.read(&mut output[..maximum])?;
            if count == 0 {
                return Err(io::Error::other("protected edit source is truncated"));
            }
            self.digest.update(&output[..count]);
            self.remaining -= count as u64;
            return Ok(count);
        }
        if !self.checked {
            let mut extra = Zeroizing::new([0u8; 1]);
            if self.source.read(&mut *extra)? != 0
                || self.digest.clone().finalize().as_slice() != self.expected
            {
                return Err(io::Error::other(
                    "protected edit source digest or length changed",
                ));
            }
            self.checked = true;
        }
        Ok(0)
    }
}

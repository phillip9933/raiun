//! Codec for the OpenCloud Web rclone-crypt vault profile.
//!
//! This crate has no remote I/O. File encryption/decryption is transactional:
//! data is staged in a private sibling file and only published after the
//! complete input and its declared length have been checked.

#![forbid(unsafe_code)]

use aes::{
    Aes256,
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use crypto_secretbox::{XSalsa20Poly1305, aead::Aead};
use scrypt::{Params as ScryptParams, scrypt};
use std::{
    io::{self, Read, Write},
    path::Path,
};
use tempfile::NamedTempFile;
use zeroize::{Zeroize, Zeroizing};

pub mod directory;
pub mod sealed_cache;
pub mod session;

const SALT: [u8; 16] = [
    0xa8, 0x0d, 0xf4, 0x3a, 0x8f, 0xbd, 0x03, 0x08, 0xa7, 0xca, 0xb8, 0x3e, 0x58, 0x1f, 0x86, 0xb1,
];
const MAGIC: [u8; 8] = *b"RCLONE\0\0";
const HEADER_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const BLOCK_PLAIN_LEN: usize = 65_536;
const BLOCK_CIPHER_LEN: usize = BLOCK_PLAIN_LEN + 16;
pub const MAX_AUTHENTICATED_PREFIX_BYTES: usize = BLOCK_PLAIN_LEN * 2;
const MAX_NAME_UTF8: usize = 255;
const MAX_ENCRYPTED_NAME: usize = 3_277;
const MAX_DECODED_NAME: usize = 2_048;
const MAX_PATH: usize = 32_768;
const MAX_PASSWORD_BYTES: usize = 4_096;
const MAX_PORTABLE_PATH_COMPONENTS: usize = 1_024;

/// Errors are deliberately generic and never include passwords or key bytes.
#[derive(Debug)]
pub struct VaultError(String);

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for VaultError {}

impl From<io::Error> for VaultError {
    fn from(error: io::Error) -> Self {
        Self(format!("vault I/O failed: {error}"))
    }
}

fn invalid(message: &'static str) -> VaultError {
    VaultError(message.to_owned())
}

/// Low-level, unverified codec. It can decode individually authenticated
/// blocks without proving that the passphrase belongs to this vault. Call
/// [`VaultCipher::verify_and_unlock`] before exposing decoded data to an app.
pub struct VaultCipher {
    keys: Zeroizing<[u8; 80]>,
}

impl VaultCipher {
    /// Derive keys from a passphrase using the OpenCloud Web/rclone defaults.
    ///
    /// Scrypt is intentionally synchronous and memory-hard. Callers must bound
    /// concurrent unlock attempts at the application layer.
    pub fn from_password(password: &mut [u8]) -> Result<Self, VaultError> {
        let mut derived = Zeroizing::new([0u8; 80]);
        let result = (|| {
            if password.is_empty() {
                return Err(invalid("vault password must not be empty"));
            }
            if password.len() > MAX_PASSWORD_BYTES {
                return Err(invalid("vault password exceeds the 4096-byte limit"));
            }
            std::str::from_utf8(password)
                .map_err(|_| invalid("vault password must be valid UTF-8"))?;
            // RustCrypto Params caps the password-hash profile field at 64,
            // but its low-level RFC 7914 function accepts the standard
            // 80-byte output length used by rclone.
            let params = ScryptParams::new(14, 8, 1, 64)
                .map_err(|_| invalid("invalid vault key derivation parameters"))?;
            scrypt(password, &SALT, &params, &mut *derived)
                .map_err(|_| invalid("vault key derivation failed"))?;
            Self::from_key_material(&derived[..])
        })();
        password.zeroize();
        result
    }

    /// Restore the 80-byte bundle after the caller authenticates/unseals it.
    /// The caller must zeroize its input buffer after this copy.
    pub fn from_key_material(material: &[u8]) -> Result<Self, VaultError> {
        if material.len() != 80 {
            return Err(invalid("invalid rclone key bundle length"));
        }
        let mut keys = Zeroizing::new([0u8; 80]);
        keys.copy_from_slice(material);
        Ok(Self { keys })
    }

    /// Verify the vault's authenticated UUID token and convert this codec into
    /// the app-facing session. On failure `self` is dropped and its keys are
    /// zeroized.
    pub fn verify_and_unlock(
        self,
        integrity_token: &str,
    ) -> Result<VerifiedVaultSession, VaultError> {
        if !self.verify_integrity_token(integrity_token) {
            return Err(invalid("vault integrity token did not verify"));
        }
        Ok(VerifiedVaultSession { cipher: self })
    }

    /// Initialize local crypto material for a brand-new vault, producing its
    /// first authenticated integrity token.
    ///
    /// This does not create or validate a remote collection. Callers must only
    /// use the returned session/token as part of a conditional create flow,
    /// then read back and validate the newly created root before associating
    /// this session with it. Existing vaults must use [`Self::verify_and_unlock`].
    pub fn initialize_new_vault(self) -> Result<NewVaultDraft, VaultError> {
        let integrity_token = make_integrity_token(&self)?;
        Ok(NewVaultDraft {
            cipher: self,
            integrity_token,
        })
    }

    fn encrypt_name_unchecked(&self, name: &str) -> Result<String, VaultError> {
        validate_name(name)?;
        let bytes = Zeroizing::new(name.as_bytes().to_vec());
        let pad = 16 - (bytes.len() % 16);
        let mut padded = Zeroizing::new(vec![pad as u8; bytes.len() + pad]);
        padded[..bytes.len()].copy_from_slice(&bytes);
        let encrypted = Zeroizing::new(eme_transform(
            &self.keys[32..64],
            &self.keys[64..80],
            &padded,
            true,
        )?);
        Ok(encode_base32hex(&encrypted))
    }

    fn encrypt_bytes<R: Read, W: Write>(
        &self,
        input: &mut R,
        output: &mut W,
        expected_len: u64,
        initial_nonce: &[u8; NONCE_LEN],
    ) -> Result<u64, VaultError> {
        output.write_all(&MAGIC)?;
        output.write_all(initial_nonce)?;
        let cipher = XSalsa20Poly1305::new_from_slice(&self.keys[..32])
            .map_err(|_| invalid("invalid content key"))?;
        let mut nonce = Zeroizing::new(*initial_nonce);
        let mut block = Zeroizing::new(vec![0u8; BLOCK_PLAIN_LEN]);
        let mut remaining = expected_len;
        while remaining > 0 {
            let count = usize::try_from(remaining.min(BLOCK_PLAIN_LEN as u64))
                .map_err(|_| invalid("vault plaintext length overflow"))?;
            read_exact_or_error(
                input,
                &mut block[..count],
                "plaintext ended before declared length",
            )?;
            let encrypted = cipher
                .encrypt(
                    crypto_secretbox::Nonce::from_slice(&*nonce),
                    &block[..count],
                )
                .map_err(|_| invalid("vault block encryption failed"))?;
            let mut encrypted = Zeroizing::new(encrypted);
            output.write_all(&encrypted)?;
            block[..count].zeroize();
            encrypted.zeroize();
            remaining -= count as u64;
            increment_nonce(&mut nonce)?;
        }
        let mut trailing = [0u8; 1];
        loop {
            match input.read(&mut trailing) {
                Ok(0) => break,
                Ok(_) => return Err(invalid("plaintext exceeds declared length")),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        trailing.zeroize();
        Ok(expected_len)
    }

    /// Decrypt one base32hex-encoded filename component.
    pub fn decrypt_name(&self, encrypted: &str) -> Result<String, VaultError> {
        if encrypted.is_empty() || encrypted.len() > MAX_ENCRYPTED_NAME {
            return Err(invalid("invalid encrypted name length"));
        }
        let mut raw = decode_base32hex(encrypted)?;
        if raw.is_empty() || raw.len() % 16 != 0 || raw.len() > MAX_DECODED_NAME {
            raw.zeroize();
            return Err(invalid("invalid encrypted name size"));
        }
        let mut padded = eme_transform(&self.keys[32..64], &self.keys[64..80], &raw, false)?;
        raw.zeroize();
        let result = (|| {
            let pad = *padded
                .last()
                .ok_or_else(|| invalid("invalid name padding"))? as usize;
            if !(1..=16).contains(&pad) || padded.len() < pad {
                return Err(invalid("invalid name padding"));
            }
            if !padded[padded.len() - pad..]
                .iter()
                .all(|byte| *byte as usize == pad)
            {
                return Err(invalid("invalid name padding"));
            }
            let name = std::str::from_utf8(&padded[..padded.len() - pad])
                .map_err(|_| invalid("invalid UTF-8 vault name"))?;
            validate_name(name)?;
            Ok(name.to_owned())
        })();
        padded.zeroize();
        result
    }

    /// Decrypt slash-separated encrypted path components. Empty path denotes
    /// the vault root. Absolute, empty-component, and traversal paths fail.
    pub fn decrypt_path(&self, encrypted: &str) -> Result<String, VaultError> {
        if encrypted.is_empty() {
            return Ok(String::new());
        }
        if encrypted.len() > MAX_PATH || encrypted.starts_with('/') || encrypted.ends_with('/') {
            return Err(invalid("invalid encrypted path"));
        }
        encrypted
            .split('/')
            .map(|component| self.decrypt_name(component))
            .collect::<Result<Vec<_>, _>>()
            .map(|parts| parts.join("/"))
    }

    /// Verify the Web vault's base64-encoded authenticated UUID token.
    /// An authenticated canonical UUID is required; arbitrary valid ciphertext
    /// and empty/header-only values do not establish that the passphrase is right.
    pub fn verify_integrity_token(&self, token: &str) -> bool {
        if token.is_empty() || token.len() > 256 {
            return false;
        }
        let Ok(ciphertext) = STANDARD.decode(token) else {
            return false;
        };
        if !(49..=256).contains(&ciphertext.len()) {
            return false;
        }
        let mut plaintext = Zeroizing::new(Vec::with_capacity(64));
        let mut input = ciphertext.as_slice();
        let result = self.decrypt_bytes(&mut input, &mut *plaintext, 64, Some(36));
        result.is_ok() && is_uuid(std::str::from_utf8(&plaintext).unwrap_or(""))
    }

    /// Decrypt to a new destination file, publishing it only after every
    /// present block authenticates and an optional trusted length matches.
    ///
    /// The target must not already exist. A private temporary sibling is
    /// removed on all errors, including late authentication failures. The
    /// encrypted format does not authenticate total file length: a deletion
    /// exactly at a block boundary cannot be detected without `expected_len`
    /// obtained from a trusted source (for example authenticated metadata).
    pub fn decrypt_file_transactional<R: Read>(
        &self,
        input: &mut R,
        destination: &Path,
        maximum_plaintext_bytes: u64,
        expected_len: Option<u64>,
    ) -> Result<u64, VaultError> {
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        let mut staged = NamedTempFile::new_in(parent)?;
        let size = self.decrypt_bytes(
            input,
            staged.as_file_mut(),
            maximum_plaintext_bytes,
            expected_len,
        )?;
        staged.as_file_mut().flush()?;
        staged.as_file().sync_all()?;
        staged.persist_noclobber(destination).map_err(|error| {
            VaultError(format!(
                "could not publish decrypted vault file: {}",
                error.error
            ))
        })?;
        Ok(size)
    }

    /// Decrypt a complete file into a bounded zeroizing memory buffer.
    /// Callers must provide a trusted expected length and a small maximum;
    /// this is intended for explicit cross-vault copies, not general reads.
    pub fn decrypt_file_to_bytes<R: Read>(
        &self,
        input: &mut R,
        maximum_plaintext_bytes: u64,
        expected_len: u64,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if expected_len > maximum_plaintext_bytes {
            return Err(invalid("vault plaintext size limit exceeded"));
        }
        let capacity = usize::try_from(expected_len)
            .map_err(|_| invalid("vault plaintext size limit exceeded"))?;
        let mut plaintext = Zeroizing::new(Vec::new());
        plaintext
            .try_reserve_exact(capacity)
            .map_err(|_| invalid("vault plaintext buffer allocation failed"))?;
        self.decrypt_bytes(
            input,
            &mut *plaintext,
            maximum_plaintext_bytes,
            Some(expected_len),
        )?;
        Ok(plaintext)
    }

    /// Decrypt only the first independently authenticated content blocks.
    ///
    /// This is intended for small encrypted metadata prefixes. It reads at
    /// most `MAX_AUTHENTICATED_PREFIX_BYTES` plaintext and never claims the rest of the file
    /// is intact or complete. The caller must bound and validate the returned
    /// prefix before using it. Plaintext is zeroized when the returned value
    /// is dropped.
    pub fn decrypt_authenticated_prefix<R: Read>(
        &self,
        input: &mut R,
        maximum_prefix_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if maximum_prefix_bytes == 0 || maximum_prefix_bytes > MAX_AUTHENTICATED_PREFIX_BYTES {
            return Err(invalid("vault prefix size limit is invalid"));
        }
        let mut header = [0u8; HEADER_LEN];
        read_exact_or_error(input, &mut header, "truncated vault file header")?;
        if header[..8] != MAGIC {
            header.zeroize();
            return Err(invalid("invalid rclone vault file header"));
        }
        let mut nonce = Zeroizing::new([0u8; NONCE_LEN]);
        nonce.copy_from_slice(&header[8..]);
        header.zeroize();

        let cipher = XSalsa20Poly1305::new_from_slice(&self.keys[..32])
            .map_err(|_| invalid("invalid content key"))?;
        let mut block = Zeroizing::new(vec![0u8; BLOCK_CIPHER_LEN]);
        let mut prefix = Zeroizing::new(Vec::with_capacity(maximum_prefix_bytes));
        while prefix.len() < maximum_prefix_bytes {
            let count = read_up_to(input, &mut block)?;
            if count < 16 {
                return Err(invalid("truncated encrypted vault block"));
            }
            let nonce_value = crypto_secretbox::Nonce::from_slice(&*nonce);
            let plaintext = cipher
                .decrypt(nonce_value, &block[..count])
                .map_err(|_| invalid("vault block authentication failed"))?;
            let mut plaintext = Zeroizing::new(plaintext);
            let copy_len = plaintext.len().min(maximum_prefix_bytes - prefix.len());
            prefix.extend_from_slice(&plaintext[..copy_len]);
            plaintext.zeroize();
            block[..count].zeroize();
            if count < BLOCK_CIPHER_LEN {
                break;
            }
            increment_nonce(&mut nonce)?;
        }
        Ok(prefix)
    }

    fn decrypt_bytes<W: Write>(
        &self,
        input: &mut impl Read,
        output: &mut W,
        maximum_plaintext_bytes: u64,
        expected_len: Option<u64>,
    ) -> Result<u64, VaultError> {
        let mut header = [0u8; HEADER_LEN];
        read_exact_or_error(input, &mut header, "truncated vault file header")?;
        if header[..8] != MAGIC {
            header.zeroize();
            return Err(invalid("invalid rclone vault file header"));
        }
        let mut nonce = Zeroizing::new([0u8; NONCE_LEN]);
        nonce.copy_from_slice(&header[8..]);
        header.zeroize();
        let cipher = XSalsa20Poly1305::new_from_slice(&self.keys[..32])
            .map_err(|_| invalid("invalid content key"))?;
        let mut block = Zeroizing::new(vec![0u8; BLOCK_CIPHER_LEN]);
        let mut total = 0u64;
        loop {
            let count = read_up_to(input, &mut block)?;
            if count == 0 {
                break;
            }
            if count < 16 {
                return Err(invalid("truncated encrypted vault block"));
            }
            let plain_size = count - 16;
            if (plain_size as u64) > maximum_plaintext_bytes.saturating_sub(total) {
                return Err(invalid("vault plaintext size limit exceeded"));
            }
            let nonce_value = crypto_secretbox::Nonce::from_slice(&*nonce);
            let plaintext = cipher
                .decrypt(nonce_value, &block[..count])
                .map_err(|_| invalid("vault block authentication failed"))?;
            let mut plaintext = Zeroizing::new(plaintext);
            output.write_all(&plaintext)?;
            total = total
                .checked_add(plaintext.len() as u64)
                .ok_or_else(|| invalid("vault plaintext length overflow"))?;
            plaintext.zeroize();
            block[..count].zeroize();
            increment_nonce(&mut nonce)?;
            if count < BLOCK_CIPHER_LEN {
                // The read filled fewer than one complete encrypted block;
                // EOF was observed by read_up_to, so no more data follows.
                break;
            }
        }
        if expected_len.is_some_and(|expected| expected != total) {
            return Err(invalid(
                "vault plaintext length does not match trusted metadata",
            ));
        }
        Ok(total)
    }
}

/// Local material prepared for a new remote vault, before its root is created.
///
/// This type deliberately has no name/content encryption methods and cannot be
/// inserted as a verified session. After a server has conditionally created
/// the root and its integrity property has been read back, consume the draft
/// with that exact value to obtain a [`VerifiedVaultSession`].
pub struct NewVaultDraft {
    cipher: VaultCipher,
    integrity_token: String,
}

impl NewVaultDraft {
    /// The encrypted UUID value to attach to the newly-created root. This is
    /// ciphertext metadata, not a password or key.
    pub fn integrity_token(&self) -> &str {
        &self.integrity_token
    }

    /// Finish initialization only when the newly-created root reads back the
    /// exact token generated by this draft and that token verifies locally.
    pub fn verify_created_root(
        self,
        observed_integrity_token: &str,
    ) -> Result<VerifiedVaultSession, VaultError> {
        if observed_integrity_token != self.integrity_token
            || !self.cipher.verify_integrity_token(observed_integrity_token)
        {
            return Err(invalid(
                "created vault root did not return its integrity token",
            ));
        }
        Ok(VerifiedVaultSession {
            cipher: self.cipher,
        })
    }
}

/// A codec session that has verified the vault's authenticated UUID token.
/// This is the intended application-facing type; its path decoder enforces
/// portable filesystem component rules before returning names or paths.
pub struct VerifiedVaultSession {
    cipher: VaultCipher,
}

impl VerifiedVaultSession {
    /// Recheck a root's current integrity token against this session's content
    /// key. The token is still untrusted server metadata; this only establishes
    /// whether its authenticated UUID decrypts under the retained key.
    pub fn verify_integrity_token(&self, token: &str) -> bool {
        self.cipher.verify_integrity_token(token)
    }

    /// Decode one filename and reject names that are unsafe on Windows.
    pub fn decrypt_name(&self, encrypted: &str) -> Result<String, VaultError> {
        let name = self.cipher.decrypt_name(encrypted)?;
        validate_portable_name(&name)?;
        Ok(name)
    }

    /// Encrypt one portable filename component using OpenCloud's EME format.
    pub fn encrypt_name(&self, name: &str) -> Result<String, VaultError> {
        validate_portable_name(name)?;
        self.cipher.encrypt_name_unchecked(name)
    }

    /// Encrypt a relative path component-by-component. An empty path denotes
    /// the vault root; absolute, empty-component, and traversal paths fail.
    pub fn encrypt_path(&self, plain: &str) -> Result<String, VaultError> {
        if plain.is_empty() {
            return Ok(String::new());
        }
        if plain.len() > MAX_PATH || plain.starts_with('/') || plain.ends_with('/') {
            return Err(invalid("invalid vault path"));
        }
        let components = plain.split('/').collect::<Vec<_>>();
        if components.len() > MAX_PORTABLE_PATH_COMPONENTS {
            return Err(invalid("vault path has too many components"));
        }
        components
            .into_iter()
            .map(|component| self.encrypt_name(component))
            .collect::<Result<Vec<_>, _>>()
            .map(|encrypted| encrypted.join("/"))
    }

    /// Encrypt exactly `expected_len` plaintext bytes to a new destination.
    /// The destination is not overwritten and the private sibling temporary
    /// file is removed on every failure. The maximum is checked before I/O.
    pub fn encrypt_file_transactional<R: Read>(
        &self,
        input: &mut R,
        destination: &Path,
        expected_len: u64,
        maximum_plaintext_bytes: u64,
    ) -> Result<u64, VaultError> {
        if expected_len > maximum_plaintext_bytes {
            return Err(invalid("vault plaintext size limit exceeded"));
        }
        let mut nonce = Zeroizing::new([0u8; NONCE_LEN]);
        getrandom::fill(&mut *nonce).map_err(|_| invalid("OS randomness unavailable"))?;
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        let mut staged = NamedTempFile::new_in(parent)?;
        let size = self
            .cipher
            .encrypt_bytes(input, staged.as_file_mut(), expected_len, &nonce)?;
        staged.as_file_mut().flush()?;
        staged.as_file().sync_all()?;
        staged.persist_noclobber(destination).map_err(|error| {
            VaultError(format!(
                "could not publish encrypted vault file: {}",
                error.error
            ))
        })?;
        Ok(size)
    }

    /// Decode a relative vault path to checked components. The root is an
    /// empty component list. Join each component beneath a trusted vault root;
    /// never pass an unchecked path to an absolute join operation.
    pub fn decrypt_path(&self, encrypted: &str) -> Result<PortableVaultPath, VaultError> {
        if encrypted.is_empty() {
            return Ok(PortableVaultPath {
                components: Vec::new(),
            });
        }
        // Reject oversized input before scanning components while the session
        // registry may be holding its lock.
        if encrypted.len() > MAX_PATH {
            return Err(invalid("invalid encrypted path"));
        }
        if encrypted.matches('/').count() + 1 > MAX_PORTABLE_PATH_COMPONENTS {
            return Err(invalid("vault path has too many components"));
        }
        let decoded = self.cipher.decrypt_path(encrypted)?;
        let components = decoded
            .split('/')
            .map(|component| {
                validate_portable_name(component)?;
                Ok(component.to_owned())
            })
            .collect::<Result<Vec<_>, VaultError>>()?;
        Ok(PortableVaultPath { components })
    }

    /// Transactionally decrypt one file with the same bounds and no-clobber
    /// behavior as the low-level codec.
    pub fn decrypt_file_transactional<R: Read>(
        &self,
        input: &mut R,
        destination: &Path,
        maximum_plaintext_bytes: u64,
        expected_len: Option<u64>,
    ) -> Result<u64, VaultError> {
        self.cipher.decrypt_file_transactional(
            input,
            destination,
            maximum_plaintext_bytes,
            expected_len,
        )
    }

    /// Decrypt one complete, metadata-bounded file into zeroizing memory.
    pub fn decrypt_file_to_bytes<R: Read>(
        &self,
        input: &mut R,
        maximum_plaintext_bytes: u64,
        expected_len: u64,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.cipher
            .decrypt_file_to_bytes(input, maximum_plaintext_bytes, expected_len)
    }

    /// Decrypt one independently authenticated prefix block. The remainder
    /// of the ciphertext is deliberately not inspected by this method.
    pub fn decrypt_authenticated_prefix<R: Read>(
        &self,
        input: &mut R,
        maximum_prefix_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.cipher
            .decrypt_authenticated_prefix(input, maximum_prefix_bytes)
    }
}

/// A decoded relative path represented as validated individual components.
/// It cannot contain a root, drive prefix, separator, or traversal component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableVaultPath {
    components: Vec<String>,
}

impl PortableVaultPath {
    /// Validated path components for joining one by one beneath a trusted root.
    pub fn components(&self) -> impl ExactSizeIterator<Item = &str> {
        self.components.iter().map(String::as_str)
    }

    /// Consume the path into its already-validated components.
    pub fn into_components(self) -> Vec<String> {
        self.components
    }

    /// True when this path refers to the vault root.
    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }
}

fn read_exact_or_error<R: Read>(
    input: &mut R,
    buffer: &mut [u8],
    message: &'static str,
) -> Result<(), VaultError> {
    let mut read = 0;
    while read < buffer.len() {
        match input.read(&mut buffer[read..]) {
            Ok(0) => return Err(invalid(message)),
            Ok(count) => read += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn read_up_to<R: Read>(input: &mut R, buffer: &mut [u8]) -> Result<usize, VaultError> {
    let mut read = 0;
    while read < buffer.len() {
        match input.read(&mut buffer[read..]) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(read)
}

fn make_integrity_token(cipher: &VaultCipher) -> Result<String, VaultError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut uuid_bytes = Zeroizing::new([0u8; 16]);
    getrandom::fill(&mut *uuid_bytes).map_err(|_| invalid("OS randomness unavailable"))?;
    // RFC 4122 UUID v4 version and variant bits.
    uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x40;
    uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80;
    let mut uuid = Zeroizing::new(Vec::with_capacity(36));
    for (index, byte) in uuid_bytes.iter().copied().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            uuid.push(b'-');
        }
        uuid.push(HEX[(byte >> 4) as usize]);
        uuid.push(HEX[(byte & 0x0f) as usize]);
    }
    let mut nonce = Zeroizing::new([0u8; NONCE_LEN]);
    getrandom::fill(&mut *nonce).map_err(|_| invalid("OS randomness unavailable"))?;
    let mut reader = uuid.as_slice();
    let mut encrypted = Zeroizing::new(Vec::with_capacity(HEADER_LEN + 36 + 16));
    cipher.encrypt_bytes(&mut reader, &mut *encrypted, 36, &nonce)?;
    let token = STANDARD.encode(&*encrypted);
    if !cipher.verify_integrity_token(&token) {
        return Err(invalid("new vault integrity token failed verification"));
    }
    Ok(token)
}

fn encode_base32hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut output = String::with_capacity(bytes.len().saturating_mul(8).div_ceil(5));
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((accumulator >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        output.push(ALPHABET[((accumulator << (5 - bits)) & 31) as usize] as char);
    }
    output
}

fn increment_nonce(nonce: &mut [u8; NONCE_LEN]) -> Result<(), VaultError> {
    for byte in nonce.iter_mut() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            return Ok(());
        }
    }
    Err(invalid("rclone vault nonce exhausted"))
}

fn is_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
}

fn validate_name(name: &str) -> Result<(), VaultError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.chars().any(char::is_control)
        || name.len() > MAX_NAME_UTF8
    {
        return Err(invalid("unsafe or oversized vault name"));
    }
    Ok(())
}

fn validate_portable_name(name: &str) -> Result<(), VaultError> {
    validate_name(name)?;
    if name.ends_with('.')
        || name.ends_with(' ')
        || name
            .chars()
            .any(|character| matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
    {
        return Err(invalid("vault name is not portable to Windows filesystems"));
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or(name)
        .trim_end_matches([' ', '.']);
    let upper = stem.to_ascii_uppercase();
    let numbered_device = |prefix: &str| {
        upper.strip_prefix(prefix).is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    };
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || numbered_device("COM")
        || numbered_device("LPT")
    {
        return Err(invalid("vault name is a reserved Windows device name"));
    }
    Ok(())
}

fn decode_base32hex(text: &str) -> Result<Vec<u8>, VaultError> {
    let mut output = Vec::with_capacity(text.len() * 5 / 8);
    let mut value = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        let digit = match byte.to_ascii_lowercase() {
            b'0'..=b'9' => byte.to_ascii_lowercase() - b'0',
            b'a'..=b'v' => byte.to_ascii_lowercase() - b'a' + 10,
            _ => return Err(invalid("invalid base32hex vault name")),
        };
        value = (value << 5) | u32::from(digit);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push(((value >> bits) & 0xff) as u8);
        }
    }
    if bits >= 5 || (value & ((1u32 << bits) - 1)) != 0 {
        output.zeroize();
        return Err(invalid("invalid base32hex padding bits"));
    }
    Ok(output)
}

fn eme_transform(
    key: &[u8],
    tweak: &[u8],
    input: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>, VaultError> {
    if key.len() != 32
        || tweak.len() != 16
        || input.is_empty()
        || input.len() % 16 != 0
        || input.len() > MAX_DECODED_NAME
    {
        return Err(invalid("invalid EME name parameters"));
    }
    let aes = Aes256::new_from_slice(key).map_err(|_| invalid("invalid EME key"))?;
    let count = input.len() / 16;
    let mut l = [0u8; 16];
    aes.encrypt_block((&mut l).into());
    let mut l_table = Vec::with_capacity(count);
    for _ in 0..count {
        double_block(&mut l);
        l_table.push(l);
    }
    let mut result = vec![0u8; input.len()];
    let mut block = aes::Block::default();
    for (index, chunk) in input.chunks_exact(16).enumerate() {
        for i in 0..16 {
            block[i] = chunk[i] ^ l_table[index][i];
        }
        if encrypt {
            aes.encrypt_block(&mut block);
        } else {
            aes.decrypt_block(&mut block);
        }
        result[index * 16..index * 16 + 16].copy_from_slice(&block);
    }
    let mut mp = [0u8; 16];
    mp.copy_from_slice(tweak);
    for chunk in result.chunks_exact(16) {
        xor_block(&mut mp, chunk);
    }
    let mut mc = aes::Block::default();
    mc.copy_from_slice(&mp);
    if encrypt {
        aes.encrypt_block(&mut mc);
    } else {
        aes.decrypt_block(&mut mc);
    }
    let mut mix = mp;
    xor_block(&mut mix, &mc);
    for index in 1..count {
        double_block(&mut mix);
        let chunk = &mut result[index * 16..index * 16 + 16];
        for i in 0..16 {
            chunk[i] ^= mix[i];
        }
    }
    let mut first = mc;
    for i in 0..16 {
        first[i] ^= tweak[i];
    }
    for chunk in result.chunks_exact(16).skip(1) {
        xor_block(first.as_mut_slice(), chunk);
    }
    result[..16].copy_from_slice(&first);
    for (index, chunk) in result.chunks_exact_mut(16).enumerate() {
        block.copy_from_slice(chunk);
        if encrypt {
            aes.encrypt_block(&mut block);
        } else {
            aes.decrypt_block(&mut block);
        }
        for i in 0..16 {
            chunk[i] = block[i] ^ l_table[index][i];
        }
    }
    l.zeroize();
    mp.zeroize();
    mc.as_mut_slice().zeroize();
    mix.zeroize();
    first.zeroize();
    block.as_mut_slice().zeroize();
    l_table.zeroize();
    Ok(result)
}

fn double_block(bytes: &mut [u8; 16]) {
    let carry = bytes[15] >> 7;
    for index in (1..16).rev() {
        bytes[index] = (bytes[index] << 1) | (bytes[index - 1] >> 7);
    }
    bytes[0] = (bytes[0] << 1) ^ (0x87 * carry);
}

fn xor_block(left: &mut [u8], right: &[u8]) {
    for (a, b) in left.iter_mut().zip(right) {
        *a ^= *b;
    }
}

#[cfg(test)]
mod tests {
    use super::validate_portable_name;

    #[test]
    fn portable_names_reject_windows_ads_devices_and_trailing_normalization() {
        for name in [
            "file:stream",
            "CON",
            "con.txt",
            "NUL.log",
            "PRN",
            "AUX.anything",
            "COM1",
            "com9.txt",
            "LPT1",
            "lpt9.ext",
            "CONIN$",
            "conout$.txt",
            "COM¹",
            "LPT³.log",
            "trailing.",
            "trailing ",
            "a<b",
            "a>b",
            "a\"b",
            "a|b",
            "a?b",
            "a*b",
        ] {
            assert!(validate_portable_name(name).is_err(), "accepted {name:?}");
        }
        for name in ["report.txt", "COM10.txt", "folder_name", "résumé"] {
            assert!(validate_portable_name(name).is_ok(), "rejected {name:?}");
        }
    }
}

#[cfg(test)]
mod encryption_tests {
    use super::{BLOCK_CIPHER_LEN, BLOCK_PLAIN_LEN, NONCE_LEN, VaultCipher, VerifiedVaultSession};
    use std::io::Cursor;

    fn password_cipher() -> VaultCipher {
        let mut password = b"potato".to_vec();
        VaultCipher::from_password(&mut password).unwrap()
    }

    fn pattern(size: usize) -> Vec<u8> {
        (0..size).map(|index| (index * 31 + 7) as u8).collect()
    }

    #[test]
    fn encrypted_names_match_published_web_and_rclone_vectors() {
        let cipher = password_cipher();
        let token = include_str!("../tests/fixtures/web-integrity-token.b64").trim();
        let session = cipher.verify_and_unlock(token).unwrap();
        for (plain, encrypted) in [
            ("1", "9cmn80lns8obm4t3koceogil20"),
            ("123456789012345", "39pfuflp0u10iqi88m20aq3i28"),
            (
                "1234567890123456",
                "9qg6n1iouahpupqlekm1k6sa5psf32kr83f3vv36c5kqrhij022g",
            ),
            ("写真🗃️", "m9t62nq5a92ncslf90dorqurss"),
            (
                "folder/école.txt",
                "um9jr7t436jbmsgpub5sfni4qk/ap8un5letkkhetgjpn9528qi4c",
            ),
            (
                "interop/写真🗃️-65537.bin",
                "f5qevq76he1rhpr8cjg4vbit6k/1sjbdv65fk0ih90u44je3u9oo548bi5ppg9q023n6aklqemohseg",
            ),
        ] {
            assert_eq!(session.encrypt_path(plain).unwrap(), encrypted);
            assert_eq!(
                session
                    .decrypt_path(encrypted)
                    .unwrap()
                    .into_components()
                    .join("/"),
                plain
            );
        }
    }

    #[test]
    fn deterministic_content_encryption_matches_android_web_oracle_at_block_boundaries() {
        let cipher = password_cipher();
        let nonce = std::array::from_fn::<_, NONCE_LEN, _>(|index| (index + 1) as u8);
        for size in [
            0,
            1,
            BLOCK_PLAIN_LEN - 1,
            BLOCK_PLAIN_LEN,
            BLOCK_PLAIN_LEN + 1,
        ] {
            let mut input = Cursor::new(pattern(size));
            let mut ciphertext = Vec::new();
            assert_eq!(
                cipher
                    .encrypt_bytes(&mut input, &mut ciphertext, size as u64, &nonce)
                    .unwrap(),
                size as u64
            );
            let expected: &[u8] = match size {
                0 => include_bytes!("../tests/fixtures/web-0.bin"),
                1 => include_bytes!("../tests/fixtures/web-1.bin"),
                65_535 => include_bytes!("../tests/fixtures/web-65535.bin"),
                65_536 => include_bytes!("../tests/fixtures/web-65536.bin"),
                _ => include_bytes!("../tests/fixtures/web-65537.bin"),
            };
            assert_eq!(ciphertext, expected, "size {size}");
        }
    }

    #[test]
    fn authenticated_prefix_reads_only_bounded_blocks_and_rejects_tampering() {
        let cipher = password_cipher();
        let nonce = std::array::from_fn::<_, NONCE_LEN, _>(|index| (index + 1) as u8);
        let plain = pattern(BLOCK_PLAIN_LEN * 3);
        let mut source = Cursor::new(plain.clone());
        let mut encrypted = Vec::new();
        cipher
            .encrypt_bytes(&mut source, &mut encrypted, plain.len() as u64, &nonce)
            .unwrap();

        let prefix_limit = BLOCK_PLAIN_LEN + 14;
        let mut input = Cursor::new(encrypted.clone());
        let prefix = cipher
            .decrypt_authenticated_prefix(&mut input, prefix_limit)
            .unwrap();
        assert_eq!(&prefix[..], &plain[..prefix_limit]);
        assert_eq!(
            input.position(),
            (32 + (BLOCK_PLAIN_LEN + 16) * 2) as u64,
            "prefix reads stop after the blocks needed for the bounded prefix"
        );

        let mut later_corruption = encrypted.clone();
        later_corruption[32 + BLOCK_CIPHER_LEN + 9] ^= 0x40;
        let mut prefix_reader = Cursor::new(later_corruption.clone());
        let prefix = cipher
            .decrypt_authenticated_prefix(&mut prefix_reader, 32)
            .unwrap();
        assert_eq!(&prefix[..], &plain[..32]);
        assert_eq!(prefix_reader.position(), (32 + BLOCK_CIPHER_LEN) as u64);

        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("full.bin");
        assert!(
            cipher
                .decrypt_file_transactional(
                    &mut Cursor::new(later_corruption),
                    &destination,
                    plain.len() as u64,
                    Some(plain.len() as u64),
                )
                .is_err()
        );
        assert!(!destination.exists());

        encrypted[32 + 9] ^= 0x80;
        let mut corrupted = Cursor::new(encrypted);
        assert!(
            cipher
                .decrypt_authenticated_prefix(&mut corrupted, prefix_limit)
                .is_err()
        );
    }

    #[test]
    fn only_verified_sessions_expose_the_public_encryption_apis() {
        let raw = password_cipher();
        let token = include_str!("../tests/fixtures/web-integrity-token.b64").trim();
        let session: VerifiedVaultSession = raw.verify_and_unlock(token).unwrap();
        assert!(session.encrypt_path("../secret").is_err());
        assert!(session.encrypt_path("safe//name").is_err());
    }
}

//! Portable v2 local snapshot codec. No path, native handle, publication,
//! quota, network operation or remote/clean-state authority is provided here.
//!
//! The caller owns an immutable container identity and durable publication of
//! ciphertext followed by the sealed commit manifest. A successful codec check
//! authenticates local bytes only. It does not establish source provenance,
//! current authorization, an unchanged file, or a verified remote readback.
use crate::{EditJournalScope, EditRecordProtector, LocalFileIdentity, RemoteEditBaseline};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Seek, SeekFrom, Write};
use zeroize::{Zeroize, Zeroizing};

#[path = "streamed_snapshot_reader.rs"]
mod reader;
pub use reader::AuthenticatedSnapshotReader;

pub const SNAPSHOT_CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_SNAPSHOT_SEALED_CHUNK_BYTES: usize = 128 * 1024;
pub const MAX_SNAPSHOT_MANIFEST_BYTES: usize = 512 * 1024;
const MAX_MANIFEST_PLAINTEXT_BYTES: usize = 256 * 1024;
const MAX_BINDING_BYTES: usize = 128 * 1024;
const CONTAINER_MAGIC: &[u8; 8] = b"RAIUNSC2";
const MANIFEST_MAGIC: &[u8; 8] = b"RAIUNSM2";
const HEADER_BYTES: usize = 8 + 32 + 8 + 8 + 4;
const FRAME_BYTES: usize = 8 + 8 + 4 + 4;
const MANIFEST_HEADER_BYTES: usize = 8 + 4;
const CHUNK_DOMAIN: &[u8] = b"raiun/local-streamed-snapshot/chunk/v2\0";
const MANIFEST_DOMAIN: &[u8] = b"raiun/local-streamed-snapshot/manifest/v2\0";

/// Captured metadata, not a capability. All codec entry points validate it.
/// Weak/absent baselines may be retained as evidence, never upload permission.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotBinding {
    pub record_id: String,
    pub scope: EditJournalScope,
    pub generation: u64,
    pub local_file: LocalFileIdentity,
    pub relative_path: String,
    pub remote: Option<RemoteEditBaseline>,
    pub content_len: u64,
}

impl std::fmt::Debug for SnapshotBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SnapshotBinding([LOCAL METADATA])")
    }
}

/// Explicit per-operation policy. These are not disk reservations or an
/// aggregate store quota. Fixed frame/metadata allocation bounds cannot grow.
#[derive(Clone, Copy, Debug)]
pub struct SnapshotLimits {
    max_content_bytes: u64,
    max_container_bytes: u64,
    max_chunks: u64,
}

impl SnapshotLimits {
    pub fn new(
        max_content_bytes: u64,
        max_container_bytes: u64,
        max_chunks: u64,
    ) -> Result<Self, SnapshotError> {
        if max_container_bytes < HEADER_BYTES as u64 || (max_content_bytes != 0 && max_chunks == 0)
        {
            return Err(SnapshotError::LimitExceeded);
        }
        Ok(Self {
            max_content_bytes,
            max_container_bytes,
            max_chunks,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotError {
    Io,
    InvalidBinding,
    BindingMismatch,
    LimitExceeded,
    SourceLengthMismatch,
    Malformed,
    ProtectionFailed,
    Cancelled,
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Io => "local snapshot I/O failed",
            Self::InvalidBinding => "local snapshot binding is invalid",
            Self::BindingMismatch => "local snapshot belongs to another binding",
            Self::LimitExceeded => "local snapshot exceeds its policy bound",
            Self::SourceLengthMismatch => "local snapshot source length differs from its binding",
            Self::Malformed => "local snapshot is incomplete or malformed",
            Self::ProtectionFailed => "local snapshot authentication failed",
            Self::Cancelled => "local snapshot operation was cancelled",
        })
    }
}
impl std::error::Error for SnapshotError {}

/// Authenticated metadata decoded without opening or reading a container.
/// This contains no remote/native authority and does not prove body validity.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    version: u32,
    binding: SnapshotBinding,
    binding_sha256: [u8; 32],
    chunk_bytes: u32,
    chunk_count: u64,
    content_sha256: [u8; 32],
    container_sha256: [u8; 32],
    container_len: u64,
}

impl SnapshotManifest {
    pub fn binding(&self) -> &SnapshotBinding {
        &self.binding
    }
    pub fn chunk_count(&self) -> u64 {
        self.chunk_count
    }
    pub fn content_sha256(&self) -> &[u8; 32] {
        &self.content_sha256
    }
    pub fn container_sha256(&self) -> &[u8; 32] {
        &self.container_sha256
    }
    pub fn container_len(&self) -> u64 {
        self.container_len
    }
}
impl std::fmt::Debug for SnapshotManifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SnapshotManifest([LOCAL METADATA; BODY NOT VERIFIED])")
    }
}

/// Returned only after complete source EOF and encoding. The container may
/// still be buffered/undurable and must be reopened through the caller's
/// immutable-entry verification before publication or remote consumption.
pub struct EncodedSnapshot {
    manifest: SnapshotManifest,
    sealed_manifest: Vec<u8>,
}
impl EncodedSnapshot {
    pub fn manifest(&self) -> &SnapshotManifest {
        &self.manifest
    }
    pub fn sealed_manifest(&self) -> &[u8] {
        &self.sealed_manifest
    }
    pub fn into_parts(self) -> (SnapshotManifest, Vec<u8>) {
        (self.manifest, self.sealed_manifest)
    }
}

/// Full local byte authentication/counting result. It intentionally owns no
/// file/path and grants no source-identity, remote-write or clean-state proof.
#[derive(Debug)]
pub struct LocalSnapshotCheck {
    content_len: u64,
    content_sha256: [u8; 32],
    container_len: u64,
    container_sha256: [u8; 32],
}
impl LocalSnapshotCheck {
    pub fn content_len(&self) -> u64 {
        self.content_len
    }
    pub fn content_sha256(&self) -> &[u8; 32] {
        &self.content_sha256
    }
    pub fn container_len(&self) -> u64 {
        self.container_len
    }
    pub fn container_sha256(&self) -> &[u8; 32] {
        &self.container_sha256
    }
}

/// Encode one framed container and a separately sealed commit manifest. The
/// output is never flushed, synced, published or deleted by this codec. Errors
/// may leave a partial container; the caller must preserve/classify that state.
/// Cancellation is checked between chunks and before committing metadata.
pub fn encode_snapshot<R: Read + ?Sized, W: Write + ?Sized>(
    source: &mut R,
    container: &mut W,
    protector: &dyn EditRecordProtector,
    binding: &SnapshotBinding,
    limits: SnapshotLimits,
    cancelled: &mut dyn FnMut() -> bool,
) -> Result<EncodedSnapshot, SnapshotError> {
    let digest = binding_digest(binding)?;
    let count = validate_limits(binding, limits)?;
    check_cancel(cancelled)?;
    let mut output = ContainerWriter {
        output: container,
        digest: Sha256::new(),
        bytes: 0,
        maximum: limits.max_container_bytes,
    };
    output.emit(&header(binding, digest, count))?;
    let mut plaintext = Zeroizing::new(vec![0u8; SNAPSHOT_CHUNK_BYTES]);
    let mut content_digest = Sha256::new();
    let mut offset = 0u64;
    for index in 0..count {
        check_cancel(cancelled)?;
        let length = chunk_len(binding.content_len, offset)?;
        read_source_exact(source, &mut plaintext[..length])?;
        content_digest.update(&plaintext[..length]);
        let aad = chunk_aad(binding, &digest, index, offset, length)?;
        let sealed = protector
            .seal(&aad, &plaintext[..length])
            .map_err(|_| SnapshotError::ProtectionFailed)?;
        plaintext.as_mut_slice().zeroize();
        if sealed.is_empty() || sealed.len() > MAX_SNAPSHOT_SEALED_CHUNK_BYTES {
            return Err(SnapshotError::LimitExceeded);
        }
        let mut frame = [0u8; FRAME_BYTES];
        frame[..8].copy_from_slice(&index.to_le_bytes());
        frame[8..16].copy_from_slice(&offset.to_le_bytes());
        frame[16..20].copy_from_slice(&(length as u32).to_le_bytes());
        frame[20..24].copy_from_slice(&(sealed.len() as u32).to_le_bytes());
        output.emit(&frame)?;
        output.emit(&sealed)?;
        offset = offset
            .checked_add(length as u64)
            .ok_or(SnapshotError::LimitExceeded)?;
    }
    check_cancel(cancelled)?;
    if offset != binding.content_len || !at_eof(source)? {
        return Err(SnapshotError::SourceLengthMismatch);
    }
    let manifest = SnapshotManifest {
        version: 2,
        binding: binding.clone(),
        binding_sha256: digest,
        chunk_bytes: SNAPSHOT_CHUNK_BYTES as u32,
        chunk_count: count,
        content_sha256: content_digest.finalize().into(),
        container_sha256: output.digest.finalize().into(),
        container_len: output.bytes,
    };
    let plain =
        Zeroizing::new(serde_json::to_vec(&manifest).map_err(|_| SnapshotError::InvalidBinding)?);
    if plain.len() > MAX_MANIFEST_PLAINTEXT_BYTES {
        return Err(SnapshotError::LimitExceeded);
    }
    check_cancel(cancelled)?;
    let aad = manifest_aad(&binding.scope, &binding.record_id)?;
    let sealed = protector
        .seal(&aad, &plain)
        .map_err(|_| SnapshotError::ProtectionFailed)?;
    let total = sealed
        .len()
        .checked_add(MANIFEST_HEADER_BYTES)
        .ok_or(SnapshotError::LimitExceeded)?;
    if sealed.is_empty() || total > MAX_SNAPSHOT_MANIFEST_BYTES {
        return Err(SnapshotError::LimitExceeded);
    }
    let mut sealed_manifest = Vec::with_capacity(total);
    sealed_manifest.extend_from_slice(MANIFEST_MAGIC);
    sealed_manifest.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
    sealed_manifest.extend_from_slice(&sealed);
    check_cancel(cancelled)?;
    Ok(EncodedSnapshot {
        manifest,
        sealed_manifest,
    })
}

/// Decode only protected commit metadata. Scope and record ID are trusted
/// expectations from the caller's admitted catalog, never a body/path lookup.
pub fn open_manifest(
    sealed: &[u8],
    protector: &dyn EditRecordProtector,
    expected_scope: &EditJournalScope,
    expected_record_id: &str,
    limits: SnapshotLimits,
) -> Result<SnapshotManifest, SnapshotError> {
    let aad = manifest_aad(expected_scope, expected_record_id)?;
    if sealed.len() < MANIFEST_HEADER_BYTES
        || sealed.len() > MAX_SNAPSHOT_MANIFEST_BYTES
        || &sealed[..8] != MANIFEST_MAGIC
    {
        return Err(SnapshotError::Malformed);
    }
    let length = u32::from_le_bytes(
        sealed[8..12]
            .try_into()
            .map_err(|_| SnapshotError::Malformed)?,
    ) as usize;
    if length == 0 || length.checked_add(MANIFEST_HEADER_BYTES) != Some(sealed.len()) {
        return Err(SnapshotError::Malformed);
    }
    let plain = Zeroizing::new(
        protector
            .open(&aad, &sealed[MANIFEST_HEADER_BYTES..])
            .map_err(|_| SnapshotError::ProtectionFailed)?,
    );
    if plain.len() > MAX_MANIFEST_PLAINTEXT_BYTES {
        return Err(SnapshotError::LimitExceeded);
    }
    let manifest: SnapshotManifest =
        serde_json::from_slice(&plain).map_err(|_| SnapshotError::Malformed)?;
    if &manifest.binding.scope != expected_scope || manifest.binding.record_id != expected_record_id
    {
        return Err(SnapshotError::BindingMismatch);
    }
    validate_manifest(&manifest, limits)?;
    Ok(manifest)
}

/// Verify a complete container and rewind it on success. Immutability and
/// entry identity between this check and later use belong to the caller.
pub fn verify_container<R: Read + Seek + ?Sized>(
    container: &mut R,
    protector: &dyn EditRecordProtector,
    manifest: &SnapshotManifest,
    limits: SnapshotLimits,
    cancelled: &mut dyn FnMut() -> bool,
) -> Result<LocalSnapshotCheck, SnapshotError> {
    decode_container(
        container,
        &mut io::sink(),
        protector,
        manifest,
        limits,
        cancelled,
    )
}

/// Stream authenticated chunks to a sink and check the complete digests/EOF.
/// A failed check may leave plaintext in the sink. Do not publish that sink or
/// feed this directly to a remote mutation: first verify the SAME caller-owned
/// immutable container, retaining its pin throughout subsequent consumption.
pub fn decode_container<R: Read + Seek + ?Sized, W: Write + ?Sized>(
    container: &mut R,
    plaintext: &mut W,
    protector: &dyn EditRecordProtector,
    manifest: &SnapshotManifest,
    limits: SnapshotLimits,
    cancelled: &mut dyn FnMut() -> bool,
) -> Result<LocalSnapshotCheck, SnapshotError> {
    validate_manifest(manifest, limits)?;
    check_cancel(cancelled)?;
    container
        .seek(SeekFrom::Start(0))
        .map_err(|_| SnapshotError::Io)?;
    let mut input = ContainerReader {
        input: container,
        digest: Sha256::new(),
        bytes: 0,
        expected: manifest.container_len,
    };
    let mut header_bytes = [0u8; HEADER_BYTES];
    input.exact(&mut header_bytes)?;
    if header_bytes
        != header(
            &manifest.binding,
            manifest.binding_sha256,
            manifest.chunk_count,
        )
    {
        return Err(SnapshotError::BindingMismatch);
    }
    let mut ciphertext = Zeroizing::new(vec![0u8; MAX_SNAPSHOT_SEALED_CHUNK_BYTES]);
    let mut content_digest = Sha256::new();
    let mut offset = 0u64;
    for index in 0..manifest.chunk_count {
        check_cancel(cancelled)?;
        let length = chunk_len(manifest.binding.content_len, offset)?;
        let mut frame = [0u8; FRAME_BYTES];
        input.exact(&mut frame)?;
        let frame_index = u64::from_le_bytes(
            frame[..8]
                .try_into()
                .map_err(|_| SnapshotError::Malformed)?,
        );
        let frame_offset = u64::from_le_bytes(
            frame[8..16]
                .try_into()
                .map_err(|_| SnapshotError::Malformed)?,
        );
        let frame_plain = u32::from_le_bytes(
            frame[16..20]
                .try_into()
                .map_err(|_| SnapshotError::Malformed)?,
        );
        let frame_sealed = u32::from_le_bytes(
            frame[20..24]
                .try_into()
                .map_err(|_| SnapshotError::Malformed)?,
        ) as usize;
        if frame_index != index
            || frame_offset != offset
            || frame_plain as usize != length
            || frame_sealed == 0
            || frame_sealed > MAX_SNAPSHOT_SEALED_CHUNK_BYTES
        {
            return Err(SnapshotError::Malformed);
        }
        input.exact(&mut ciphertext[..frame_sealed])?;
        let aad = chunk_aad(
            &manifest.binding,
            &manifest.binding_sha256,
            index,
            offset,
            length,
        )?;
        let decoded = Zeroizing::new(
            protector
                .open(&aad, &ciphertext[..frame_sealed])
                .map_err(|_| SnapshotError::ProtectionFailed)?,
        );
        if decoded.len() != length {
            return Err(SnapshotError::Malformed);
        }
        content_digest.update(&decoded);
        plaintext
            .write_all(&decoded)
            .map_err(|_| SnapshotError::Io)?;
        offset = offset
            .checked_add(length as u64)
            .ok_or(SnapshotError::LimitExceeded)?;
    }
    check_cancel(cancelled)?;
    if offset != manifest.binding.content_len
        || input.bytes != manifest.container_len
        || !at_eof(input.input)?
    {
        return Err(SnapshotError::Malformed);
    }
    let content_sha256: [u8; 32] = content_digest.finalize().into();
    let container_sha256: [u8; 32] = input.digest.finalize().into();
    if content_sha256 != manifest.content_sha256 || container_sha256 != manifest.container_sha256 {
        return Err(SnapshotError::Malformed);
    }
    input
        .input
        .seek(SeekFrom::Start(0))
        .map_err(|_| SnapshotError::Io)?;
    check_cancel(cancelled)?;
    Ok(LocalSnapshotCheck {
        content_len: offset,
        content_sha256,
        container_len: input.bytes,
        container_sha256,
    })
}

fn validate_manifest(
    manifest: &SnapshotManifest,
    limits: SnapshotLimits,
) -> Result<(), SnapshotError> {
    let digest = binding_digest(&manifest.binding)?;
    let count = validate_limits(&manifest.binding, limits)?;
    if manifest.version != 2
        || manifest.chunk_bytes != SNAPSHOT_CHUNK_BYTES as u32
        || manifest.binding_sha256 != digest
        || manifest.chunk_count != count
    {
        return Err(SnapshotError::Malformed);
    }
    let minimum = (HEADER_BYTES as u64)
        .checked_add(
            count
                .checked_mul((FRAME_BYTES + 1) as u64)
                .ok_or(SnapshotError::LimitExceeded)?,
        )
        .ok_or(SnapshotError::LimitExceeded)?;
    let maximum = (HEADER_BYTES as u64)
        .checked_add(
            count
                .checked_mul((FRAME_BYTES + MAX_SNAPSHOT_SEALED_CHUNK_BYTES) as u64)
                .ok_or(SnapshotError::LimitExceeded)?,
        )
        .ok_or(SnapshotError::LimitExceeded)?;
    if manifest.container_len < minimum
        || manifest.container_len > maximum
        || manifest.container_len > limits.max_container_bytes
    {
        return Err(SnapshotError::LimitExceeded);
    }
    Ok(())
}

fn validate_limits(
    binding: &SnapshotBinding,
    limits: SnapshotLimits,
) -> Result<u64, SnapshotError> {
    let count = binding.content_len / SNAPSHOT_CHUNK_BYTES as u64
        + u64::from(binding.content_len % SNAPSHOT_CHUNK_BYTES as u64 != 0);
    let minimum = (HEADER_BYTES as u64)
        .checked_add(
            count
                .checked_mul((FRAME_BYTES + 1) as u64)
                .ok_or(SnapshotError::LimitExceeded)?,
        )
        .ok_or(SnapshotError::LimitExceeded)?;
    if binding.content_len > limits.max_content_bytes
        || count > limits.max_chunks
        || minimum > limits.max_container_bytes
    {
        return Err(SnapshotError::LimitExceeded);
    }
    Ok(count)
}

fn binding_digest(binding: &SnapshotBinding) -> Result<[u8; 32], SnapshotError> {
    validate_scope(&binding.scope)?;
    if !valid_record_id(&binding.record_id)
        || binding.generation == 0
        || binding.local_file.volume_serial != binding.scope.root_volume_serial
        || binding.local_file.file_index == 0
        || binding.relative_path.is_empty()
        || binding.relative_path.len() > 32 * 1024
        || binding.relative_path.starts_with('/')
        || binding.relative_path.ends_with('/')
        || binding.relative_path.contains('\\')
        || binding.relative_path.chars().any(char::is_control)
        || binding
            .relative_path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(SnapshotError::InvalidBinding);
    }
    if let Some(remote) = &binding.remote
        && (!valid_field(&remote.resource_id)
            || remote.etag.len() > 4096
            || remote.etag.chars().any(char::is_control))
    {
        return Err(SnapshotError::InvalidBinding);
    }
    // Struct field order is fixed, without maps/floats or normalization of
    // account/path identities. This exact v2 serialization defines canonical
    // binding bytes; future schema changes require another format/domain.
    let bytes =
        Zeroizing::new(serde_json::to_vec(binding).map_err(|_| SnapshotError::InvalidBinding)?);
    if bytes.len() > MAX_BINDING_BYTES {
        return Err(SnapshotError::LimitExceeded);
    }
    Ok(Sha256::digest(&bytes).into())
}

fn validate_scope(scope: &EditJournalScope) -> Result<(), SnapshotError> {
    if [
        &scope.profile_id,
        &scope.server_origin,
        &scope.account_subject,
        &scope.space_id,
        &scope.root_resource_id,
    ]
    .iter()
    .any(|value| !valid_field(value))
        || scope.root_file_index == 0
    {
        return Err(SnapshotError::InvalidBinding);
    }
    let (scheme, authority) = scope
        .server_origin
        .split_once("://")
        .ok_or(SnapshotError::InvalidBinding)?;
    if !matches!(scheme, "http" | "https")
        || authority.is_empty()
        || authority
            .bytes()
            .any(|b| matches!(b, b'/' | b'?' | b'#' | b'@') || b.is_ascii_whitespace())
    {
        return Err(SnapshotError::InvalidBinding);
    }
    Ok(())
}
fn valid_field(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control)
}
fn valid_record_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn manifest_aad(scope: &EditJournalScope, record_id: &str) -> Result<Vec<u8>, SnapshotError> {
    validate_scope(scope)?;
    if !valid_record_id(record_id) {
        return Err(SnapshotError::InvalidBinding);
    }
    let scope_bytes =
        Zeroizing::new(serde_json::to_vec(scope).map_err(|_| SnapshotError::InvalidBinding)?);
    let mut aad = MANIFEST_DOMAIN.to_vec();
    aad.extend_from_slice(&Sha256::digest(&scope_bytes));
    aad.extend_from_slice(record_id.as_bytes());
    Ok(aad)
}
fn chunk_aad(
    binding: &SnapshotBinding,
    digest: &[u8; 32],
    index: u64,
    offset: u64,
    plain_len: usize,
) -> Result<Vec<u8>, SnapshotError> {
    let plain_len = u32::try_from(plain_len).map_err(|_| SnapshotError::LimitExceeded)?;
    let mut aad = CHUNK_DOMAIN.to_vec();
    aad.extend_from_slice(digest);
    aad.extend_from_slice(binding.record_id.as_bytes());
    aad.extend_from_slice(&index.to_le_bytes());
    aad.extend_from_slice(&offset.to_le_bytes());
    aad.extend_from_slice(&plain_len.to_le_bytes());
    aad.extend_from_slice(&binding.content_len.to_le_bytes());
    Ok(aad)
}
fn header(binding: &SnapshotBinding, digest: [u8; 32], count: u64) -> [u8; HEADER_BYTES] {
    let mut bytes = [0u8; HEADER_BYTES];
    bytes[..8].copy_from_slice(CONTAINER_MAGIC);
    bytes[8..40].copy_from_slice(&digest);
    bytes[40..48].copy_from_slice(&binding.content_len.to_le_bytes());
    bytes[48..56].copy_from_slice(&count.to_le_bytes());
    bytes[56..60].copy_from_slice(&(SNAPSHOT_CHUNK_BYTES as u32).to_le_bytes());
    bytes
}
fn chunk_len(total: u64, offset: u64) -> Result<usize, SnapshotError> {
    let remaining = total.checked_sub(offset).ok_or(SnapshotError::Malformed)?;
    if remaining == 0 {
        return Err(SnapshotError::Malformed);
    }
    Ok(remaining.min(SNAPSHOT_CHUNK_BYTES as u64) as usize)
}
fn check_cancel(cancelled: &mut dyn FnMut() -> bool) -> Result<(), SnapshotError> {
    if cancelled() {
        Err(SnapshotError::Cancelled)
    } else {
        Ok(())
    }
}
fn read_source_exact<R: Read + ?Sized>(
    source: &mut R,
    output: &mut [u8],
) -> Result<(), SnapshotError> {
    source.read_exact(output).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            SnapshotError::SourceLengthMismatch
        } else {
            SnapshotError::Io
        }
    })
}
fn at_eof<R: Read + ?Sized>(input: &mut R) -> Result<bool, SnapshotError> {
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        match input.read(&mut *byte) {
            Ok(0) => return Ok(true),
            Ok(_) => return Ok(false),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(SnapshotError::Io),
        }
    }
}
struct ContainerWriter<'a, W: ?Sized> {
    output: &'a mut W,
    digest: Sha256,
    bytes: u64,
    maximum: u64,
}
impl<W: Write + ?Sized> ContainerWriter<'_, W> {
    fn emit(&mut self, bytes: &[u8]) -> Result<(), SnapshotError> {
        let next = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.maximum)
            .ok_or(SnapshotError::LimitExceeded)?;
        self.output
            .write_all(bytes)
            .map_err(|_| SnapshotError::Io)?;
        self.digest.update(bytes);
        self.bytes = next;
        Ok(())
    }
}
struct ContainerReader<'a, R: ?Sized> {
    input: &'a mut R,
    digest: Sha256,
    bytes: u64,
    expected: u64,
}
impl<R: Read + ?Sized> ContainerReader<'_, R> {
    fn exact(&mut self, bytes: &mut [u8]) -> Result<(), SnapshotError> {
        let next = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.expected)
            .ok_or(SnapshotError::Malformed)?;
        self.input.read_exact(bytes).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                SnapshotError::Malformed
            } else {
                SnapshotError::Io
            }
        })?;
        self.digest.update(&*bytes);
        self.bytes = next;
        Ok(())
    }
}

#[cfg(test)]
#[path = "streamed_snapshot_tests.rs"]
mod tests;

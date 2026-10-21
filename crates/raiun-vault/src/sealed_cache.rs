//! Bounded encrypted metadata envelopes for a future vault offline cache.
//!
//! This module stores only opaque server metadata (including already-encrypted
//! vault name components). It never accepts or emits decoded filenames, and it
//! does not provide a cache database, listing-completeness proof, or offline
//! refresh policy. All fields are encrypted with the existing verified vault
//! session for the exact `VaultSessionScope`. The temporary plaintext staging
//! file is removed on normal completion, but this is not secure erasure and
//! cannot prevent crash residue, operating-system paging, or backups.

use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

use tempfile::tempdir;

use crate::{
    VaultCipher, VaultError, invalid,
    session::{VaultSessionCoordinator, VaultSessionScope},
};
use zeroize::Zeroize;

const MAGIC: [u8; 8] = *b"RAIUNVC\0";
const VERSION: u16 = 1;
const HEADER_LEN: u64 = 8 + 2 + 8 + 4;
const MAX_ENTRIES: usize = 10_000;
const MAX_PLAINTEXT_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_CIPHERTEXT_BYTES: u64 =
    32 + MAX_PLAINTEXT_BYTES + 16 * MAX_PLAINTEXT_BYTES.div_ceil(65_536);
const MAX_CONTENT_CIPHERTEXT_BYTES: u64 = (1 << 40) + 32 + 16 * ((1 << 40) / 65_536);
const MAX_ID_BYTES: usize = 512;
const MAX_ORIGIN_BYTES: usize = 2_048;
const MAX_NAME_BYTES: usize = 3_277;
const MAX_ETAG_BYTES: usize = 4_096;
const MAX_TOKEN_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 32_768;

/// Opaque metadata for one server entry. `encrypted_name` must be the raw
/// encrypted vault component, never a decrypted/display name. The ETag and
/// lengths remain server-provided revision hints; sealing does not make them
/// authoritative outside this local encrypted envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedVaultEntry {
    pub resource_id: String,
    pub parent_resource_id: String,
    pub encrypted_name: String,
    pub etag: Option<String>,
    pub ciphertext_len: u64,
    pub directory: bool,
    pub modified_unix: i64,
    pub writable: bool,
}

impl std::fmt::Debug for SealedVaultEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SealedVaultEntry")
            .field("resource_id", &"[REDACTED]")
            .field("parent_resource_id", &"[REDACTED]")
            .field("encrypted_name", &"[REDACTED]")
            .field("etag", &"[REDACTED]")
            .field("ciphertext_len", &self.ciphertext_len)
            .field("directory", &self.directory)
            .finish()
    }
}

/// Complete bounded metadata snapshot for one exact vault root.
///
/// `root_etag` is included as a locally protected freshness hint, not as a
/// cryptographic proof of server state. `integrity_token` is checked against
/// the already-unlocked session both while sealing and opening.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedVaultSnapshot {
    pub integrity_token: String,
    pub root_etag: Option<String>,
    /// Physical DAV binding and Space display/capability metadata. Stored only
    /// inside this authenticated ciphertext envelope; server values remain
    /// untrusted hints when used offline.
    pub root_path: String,
    pub space_dav_root: String,
    pub space_name: String,
    pub space_dav_url: String,
    pub space_personal: bool,
    pub space_writable: bool,
    pub space_encrypted: bool,
    pub directory_resource_id: String,
    /// Encrypted relative path from the vault root; empty denotes the root.
    pub encrypted_directory_path: String,
    pub directory_etag: String,
    pub directory_modified_unix: i64,
    pub directory_writable: bool,
    pub entries: Vec<SealedVaultEntry>,
}

impl std::fmt::Debug for SealedVaultSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SealedVaultSnapshot")
            .field("integrity_token", &"[REDACTED]")
            .field("root_etag", &"[REDACTED]")
            .field("root_path", &"[REDACTED]")
            .field("space_dav_root", &"[REDACTED]")
            .field("space_name", &"[REDACTED]")
            .field("space_dav_url", &"[REDACTED]")
            .field("directory_resource_id", &"[REDACTED]")
            .field("directory_path", &"[REDACTED]")
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

/// Size summary returned after a complete encrypted envelope is published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedVaultBlobInfo {
    pub plaintext_bytes: u64,
    pub ciphertext_bytes: u64,
    pub entry_count: usize,
}

/// Encrypt one complete metadata snapshot to a new no-clobber destination.
/// Plaintext staging is private and temporary; the destination contains only
/// the vault's standard authenticated-block ciphertext format.
pub fn seal_snapshot(
    sessions: &VaultSessionCoordinator,
    scope: &VaultSessionScope,
    snapshot: &SealedVaultSnapshot,
    destination: &Path,
) -> Result<SealedVaultBlobInfo, VaultError> {
    if !sessions.verify_integrity_token(scope, &snapshot.integrity_token)? {
        return Err(invalid(
            "vault snapshot token does not match the unlocked scope",
        ));
    }
    validate_encrypted_directory_path(sessions, scope, snapshot)?;
    let plaintext_bytes = encoded_size(scope, snapshot)?;
    if plaintext_bytes > MAX_PLAINTEXT_BYTES {
        return Err(invalid("sealed vault metadata exceeds its size limit"));
    }

    let private = tempdir()?;
    let plaintext_path = private.path().join("metadata.tmp");
    let mut plaintext = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&plaintext_path)?;
    write_snapshot(&mut plaintext, scope, snapshot, plaintext_bytes)?;
    plaintext.flush()?;
    plaintext.sync_all()?;
    drop(plaintext);

    let mut plaintext = File::open(&plaintext_path)?;
    let encrypted_plaintext_bytes = sessions.encrypt_file_transactional(
        scope,
        &mut plaintext,
        destination,
        plaintext_bytes,
        MAX_PLAINTEXT_BYTES,
    )?;
    if encrypted_plaintext_bytes != plaintext_bytes {
        return Err(invalid(
            "sealed vault encrypted length did not match its envelope",
        ));
    }
    let ciphertext_bytes = ciphertext_len(plaintext_bytes)?;
    Ok(SealedVaultBlobInfo {
        plaintext_bytes,
        ciphertext_bytes,
        entry_count: snapshot.entries.len(),
    })
}

/// Decrypt and validate one complete metadata envelope using only the exact
/// unlocked scope. No partial snapshot is returned. `maximum_ciphertext_bytes`
/// should be the caller's trusted cache-record bound and may be lower than the
/// format maximum; ciphertext lengths and all embedded server metadata remain
/// untrusted until this function returns successfully.
pub fn open_snapshot<R: Read>(
    sessions: &VaultSessionCoordinator,
    scope: &VaultSessionScope,
    input: &mut R,
    maximum_ciphertext_bytes: u64,
) -> Result<(SealedVaultSnapshot, SealedVaultBlobInfo), VaultError> {
    if maximum_ciphertext_bytes == 0 || maximum_ciphertext_bytes > MAX_CIPHERTEXT_BYTES {
        return Err(invalid("invalid sealed vault ciphertext limit"));
    }
    let mut bounded = input.take(maximum_ciphertext_bytes.saturating_add(1));
    let private = tempdir()?;
    let plaintext_path = private.path().join("metadata.tmp");
    let plaintext_bytes = sessions.decrypt_file_transactional(
        scope,
        &mut bounded,
        &plaintext_path,
        MAX_PLAINTEXT_BYTES,
        None,
    )?;
    if plaintext_bytes > MAX_PLAINTEXT_BYTES {
        return Err(invalid("sealed vault metadata exceeds its size limit"));
    }
    // Read `take`'s consumed byte count without requiring a seekable source.
    // The wrapper's remaining limit equals max+1 minus bytes consumed.
    let consumed = maximum_ciphertext_bytes
        .saturating_add(1)
        .saturating_sub(bounded.limit());
    if consumed > maximum_ciphertext_bytes {
        return Err(invalid("sealed vault ciphertext exceeds its size limit"));
    }
    if consumed != ciphertext_len(plaintext_bytes)? {
        return Err(invalid(
            "sealed vault ciphertext length does not match its envelope",
        ));
    }

    let mut plaintext = File::open(&plaintext_path)?;
    let (snapshot, declared_len) = read_snapshot(&mut plaintext, scope)?;
    if declared_len != plaintext_bytes || plaintext_bytes != fs::metadata(&plaintext_path)?.len() {
        return Err(invalid(
            "sealed vault metadata length does not match its envelope",
        ));
    }
    if !sessions.verify_integrity_token(scope, &snapshot.integrity_token)? {
        return Err(invalid(
            "sealed vault snapshot token does not match the unlocked scope",
        ));
    }
    validate_encrypted_directory_path(sessions, scope, &snapshot)?;
    let entry_count = snapshot.entries.len();
    Ok((
        snapshot,
        SealedVaultBlobInfo {
            plaintext_bytes,
            ciphertext_bytes: consumed,
            entry_count,
        },
    ))
}

fn encoded_size(
    scope: &VaultSessionScope,
    snapshot: &SealedVaultSnapshot,
) -> Result<u64, VaultError> {
    validate_snapshot(snapshot)?;
    let mut size = HEADER_LEN;
    for field in [
        scope.account_id(),
        scope.server_origin(),
        scope.space_id(),
        scope.resource_id(),
        snapshot.integrity_token.as_str(),
    ] {
        size = add_string_size(size, field, MAX_ID_BYTES.max(MAX_ORIGIN_BYTES))?;
    }
    size = add_optional_string_size(size, snapshot.root_etag.as_deref(), MAX_ETAG_BYTES)?;
    size = add_string_size(size, &snapshot.root_path, MAX_PATH_BYTES)?;
    size = add_string_size(size, &snapshot.space_dav_root, MAX_PATH_BYTES)?;
    size = add_string_size(size, &snapshot.space_name, 4_096)?;
    size = add_string_size(size, &snapshot.space_dav_url, MAX_PATH_BYTES)?;
    size = size
        .checked_add(3)
        .ok_or_else(|| invalid("sealed vault metadata size overflow"))?;
    size = add_string_size(size, &snapshot.directory_resource_id, MAX_ID_BYTES)?;
    if snapshot.encrypted_directory_path.len() > 32_768 {
        return Err(invalid(
            "sealed vault directory path exceeds its size limit",
        ));
    }
    size = add_string_size(size, &snapshot.encrypted_directory_path, 32_768)?;
    size = add_string_size(size, &snapshot.directory_etag, MAX_ETAG_BYTES)?;
    size = size
        .checked_add(8 + 1)
        .ok_or_else(|| invalid("sealed vault metadata size overflow"))?;
    for entry in &snapshot.entries {
        size = add_string_size(size, &entry.resource_id, MAX_ID_BYTES)?;
        size = add_string_size(size, &entry.parent_resource_id, MAX_ID_BYTES)?;
        size = add_string_size(size, &entry.encrypted_name, MAX_NAME_BYTES)?;
        size = add_optional_string_size(size, entry.etag.as_deref(), MAX_ETAG_BYTES)?;
        size = size
            .checked_add(8 + 1 + 8 + 1)
            .ok_or_else(|| invalid("sealed vault metadata size overflow"))?;
    }
    if size > MAX_PLAINTEXT_BYTES {
        return Err(invalid("sealed vault metadata exceeds its size limit"));
    }
    Ok(size)
}

fn ciphertext_len(plaintext_bytes: u64) -> Result<u64, VaultError> {
    32u64
        .checked_add(plaintext_bytes)
        .and_then(|size| size.checked_add(16 * plaintext_bytes.div_ceil(65_536)))
        .ok_or_else(|| invalid("sealed vault ciphertext length overflow"))
}

fn validate_snapshot(snapshot: &SealedVaultSnapshot) -> Result<(), VaultError> {
    if snapshot.entries.len() > MAX_ENTRIES {
        return Err(invalid("sealed vault metadata has too many entries"));
    }
    validate_text(
        &snapshot.integrity_token,
        MAX_TOKEN_BYTES,
        "integrity token",
    )?;
    if let Some(etag) = &snapshot.root_etag {
        validate_text(etag, MAX_ETAG_BYTES, "root ETag")?;
    }
    validate_text(&snapshot.root_path, MAX_PATH_BYTES, "root path")?;
    validate_text(&snapshot.space_dav_root, MAX_PATH_BYTES, "Space DAV root")?;
    validate_text(&snapshot.space_name, 4_096, "Space name")?;
    validate_text(&snapshot.space_dav_url, MAX_PATH_BYTES, "Space DAV URL")?;
    validate_text(
        &snapshot.directory_resource_id,
        MAX_ID_BYTES,
        "directory resource identifier",
    )?;
    if snapshot.encrypted_directory_path.len() > 32_768 {
        return Err(invalid(
            "sealed vault directory path exceeds its size limit",
        ));
    }
    validate_text(&snapshot.directory_etag, MAX_ETAG_BYTES, "directory ETag")?;
    let mut ids = HashSet::with_capacity(snapshot.entries.len());
    for entry in &snapshot.entries {
        validate_text(&entry.resource_id, MAX_ID_BYTES, "resource identifier")?;
        validate_text(
            &entry.parent_resource_id,
            MAX_ID_BYTES,
            "parent resource identifier",
        )?;
        validate_encrypted_name(&entry.encrypted_name)?;
        if let Some(etag) = &entry.etag {
            validate_text(etag, MAX_ETAG_BYTES, "entry ETag")?;
        }
        if entry.ciphertext_len > MAX_CONTENT_CIPHERTEXT_BYTES {
            return Err(invalid("sealed vault entry exceeds its size limit"));
        }
        if !ids.insert(entry.resource_id.as_str()) {
            return Err(invalid(
                "sealed vault metadata has duplicate resource identifiers",
            ));
        }
    }
    Ok(())
}

fn validate_encrypted_name(name: &str) -> Result<(), VaultError> {
    if name.is_empty()
        || name.len() > MAX_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'v').contains(&byte))
    {
        return Err(invalid(
            "sealed vault metadata has an invalid encrypted name",
        ));
    }
    Ok(())
}

fn validate_encrypted_directory_path(
    sessions: &VaultSessionCoordinator,
    scope: &VaultSessionScope,
    snapshot: &SealedVaultSnapshot,
) -> Result<(), VaultError> {
    if snapshot.encrypted_directory_path.is_empty()
        && snapshot.directory_resource_id != scope.resource_id()
    {
        return Err(invalid(
            "sealed vault root listing has a different resource identifier",
        ));
    }
    sessions
        .decrypt_path(scope, &snapshot.encrypted_directory_path)
        .map(|_| ())
}

fn validate_text(value: &str, max: usize, label: &'static str) -> Result<(), VaultError> {
    if value.is_empty() || value.len() > max || value.contains('\0') {
        return Err(invalid(match label {
            "integrity token" => "invalid sealed vault integrity token",
            "root ETag" | "entry ETag" => "invalid sealed vault ETag",
            _ => "invalid sealed vault identifier",
        }));
    }
    Ok(())
}

fn add_string_size(mut size: u64, value: &str, max: usize) -> Result<u64, VaultError> {
    if value.len() > max || value.len() > u16::MAX as usize {
        return Err(invalid(
            "sealed vault metadata field exceeds its size limit",
        ));
    }
    size = size
        .checked_add(2 + value.len() as u64)
        .ok_or_else(|| invalid("sealed vault metadata size overflow"))?;
    Ok(size)
}

fn add_optional_string_size(size: u64, value: Option<&str>, max: usize) -> Result<u64, VaultError> {
    match value {
        Some(value) => add_string_size(
            size.checked_add(1)
                .ok_or_else(|| invalid("sealed vault metadata size overflow"))?,
            value,
            max,
        ),
        None => size
            .checked_add(1)
            .ok_or_else(|| invalid("sealed vault metadata size overflow")),
    }
}

fn write_snapshot<W: Write>(
    output: &mut W,
    scope: &VaultSessionScope,
    snapshot: &SealedVaultSnapshot,
    total_len: u64,
) -> Result<(), VaultError> {
    output.write_all(&MAGIC)?;
    output.write_all(&VERSION.to_be_bytes())?;
    output.write_all(&total_len.to_be_bytes())?;
    output.write_all(&(snapshot.entries.len() as u32).to_be_bytes())?;
    for field in [
        scope.account_id(),
        scope.server_origin(),
        scope.space_id(),
        scope.resource_id(),
        snapshot.integrity_token.as_str(),
    ] {
        write_string(output, field)?;
    }
    write_optional_string(output, snapshot.root_etag.as_deref())?;
    write_string(output, &snapshot.root_path)?;
    write_string(output, &snapshot.space_dav_root)?;
    write_string(output, &snapshot.space_name)?;
    write_string(output, &snapshot.space_dav_url)?;
    output.write_all(&[
        u8::from(snapshot.space_personal),
        u8::from(snapshot.space_writable),
        u8::from(snapshot.space_encrypted),
    ])?;
    write_string(output, &snapshot.directory_resource_id)?;
    write_string_allow_empty(output, &snapshot.encrypted_directory_path)?;
    write_string(output, &snapshot.directory_etag)?;
    output.write_all(&snapshot.directory_modified_unix.to_be_bytes())?;
    output.write_all(&[u8::from(snapshot.directory_writable)])?;
    for entry in &snapshot.entries {
        write_string(output, &entry.resource_id)?;
        write_string(output, &entry.parent_resource_id)?;
        write_string(output, &entry.encrypted_name)?;
        write_optional_string(output, entry.etag.as_deref())?;
        output.write_all(&entry.ciphertext_len.to_be_bytes())?;
        output.write_all(&[u8::from(entry.directory)])?;
        output.write_all(&entry.modified_unix.to_be_bytes())?;
        output.write_all(&[u8::from(entry.writable)])?;
    }
    Ok(())
}

fn read_snapshot<R: Read>(
    input: &mut R,
    expected_scope: &VaultSessionScope,
) -> Result<(SealedVaultSnapshot, u64), VaultError> {
    let mut magic = [0u8; 8];
    read_exact(input, &mut magic)?;
    if magic != MAGIC {
        return Err(invalid("invalid sealed vault metadata header"));
    }
    let version = read_u16(input)?;
    if version != VERSION {
        return Err(invalid("unsupported sealed vault metadata version"));
    }
    let total_len = read_u64(input)?;
    if !(HEADER_LEN..=MAX_PLAINTEXT_BYTES).contains(&total_len) {
        return Err(invalid("invalid sealed vault metadata length"));
    }
    let count = read_u32(input)? as usize;
    if count > MAX_ENTRIES {
        return Err(invalid("sealed vault metadata has too many entries"));
    }
    let account_id = read_string(input, MAX_ID_BYTES)?;
    let origin = read_string(input, MAX_ORIGIN_BYTES)?;
    let space_id = read_string(input, MAX_ID_BYTES)?;
    let root_id = read_string(input, MAX_ID_BYTES)?;
    if account_id != expected_scope.account_id()
        || origin != expected_scope.server_origin()
        || space_id != expected_scope.space_id()
        || root_id != expected_scope.resource_id()
    {
        return Err(invalid("sealed vault metadata belongs to another scope"));
    }
    let integrity_token = read_string(input, MAX_TOKEN_BYTES)?;
    let root_etag = read_optional_string(input, MAX_ETAG_BYTES)?;
    let root_path = read_string(input, MAX_PATH_BYTES)?;
    let space_dav_root = read_string(input, MAX_PATH_BYTES)?;
    let space_name = read_string(input, 4_096)?;
    let space_dav_url = read_string(input, MAX_PATH_BYTES)?;
    let space_personal = read_bool(input)?;
    let space_writable = read_bool(input)?;
    let space_encrypted = read_bool(input)?;
    let directory_resource_id = read_string(input, MAX_ID_BYTES)?;
    let encrypted_directory_path = read_string_allow_empty(input, 32_768)?;
    let directory_etag = read_string(input, MAX_ETAG_BYTES)?;
    let directory_modified_unix = read_i64(input)?;
    let directory_writable = read_bool(input)?;
    let mut entries = Vec::with_capacity(count);
    let mut ids = HashSet::with_capacity(count);
    for _ in 0..count {
        let resource_id = read_string(input, MAX_ID_BYTES)?;
        let parent_resource_id = read_string(input, MAX_ID_BYTES)?;
        let encrypted_name = read_string(input, MAX_NAME_BYTES)?;
        let etag = read_optional_string(input, MAX_ETAG_BYTES)?;
        let ciphertext_len = read_u64(input)?;
        let directory = read_bool(input)?;
        let modified_unix = read_i64(input)?;
        let writable = read_bool(input)?;
        validate_encrypted_name(&encrypted_name)?;
        if !ids.insert(resource_id.clone()) {
            return Err(invalid(
                "sealed vault metadata has duplicate resource identifiers",
            ));
        }
        entries.push(SealedVaultEntry {
            resource_id,
            parent_resource_id,
            encrypted_name,
            etag,
            ciphertext_len,
            directory,
            modified_unix,
            writable,
        });
    }
    let mut trailing = [0u8; 1];
    if input.read(&mut trailing)? != 0 {
        return Err(invalid("sealed vault metadata contains trailing data"));
    }
    let snapshot = SealedVaultSnapshot {
        integrity_token,
        root_etag,
        root_path,
        space_dav_root,
        space_name,
        space_dav_url,
        space_personal,
        space_writable,
        space_encrypted,
        directory_resource_id,
        encrypted_directory_path,
        directory_etag,
        directory_modified_unix,
        directory_writable,
        entries,
    };
    validate_snapshot(&snapshot)?;
    if encoded_size(expected_scope, &snapshot)? != total_len {
        return Err(invalid(
            "sealed vault metadata length does not match its envelope",
        ));
    }
    Ok((snapshot, total_len))
}

fn write_string<W: Write>(output: &mut W, value: &str) -> Result<(), VaultError> {
    let len = u16::try_from(value.len())
        .map_err(|_| invalid("sealed vault metadata field exceeds its size limit"))?;
    output.write_all(&len.to_be_bytes())?;
    output.write_all(value.as_bytes())?;
    Ok(())
}

fn write_string_allow_empty<W: Write>(output: &mut W, value: &str) -> Result<(), VaultError> {
    let len = u16::try_from(value.len())
        .map_err(|_| invalid("sealed vault metadata field exceeds its size limit"))?;
    output.write_all(&len.to_be_bytes())?;
    output.write_all(value.as_bytes())?;
    Ok(())
}

fn write_optional_string<W: Write>(output: &mut W, value: Option<&str>) -> Result<(), VaultError> {
    match value {
        Some(value) => {
            output.write_all(&[1])?;
            write_string(output, value)?;
        }
        None => output.write_all(&[0])?,
    }
    Ok(())
}

fn read_string<R: Read>(input: &mut R, max: usize) -> Result<String, VaultError> {
    let len = read_u16(input)? as usize;
    if len == 0 || len > max {
        return Err(invalid("invalid sealed vault metadata field length"));
    }
    let mut bytes = vec![0; len];
    read_exact(input, &mut bytes)?;
    let value =
        String::from_utf8(bytes).map_err(|_| invalid("invalid sealed vault metadata text"))?;
    if value.contains('\0') {
        return Err(invalid("invalid sealed vault metadata text"));
    }
    Ok(value)
}

fn read_string_allow_empty<R: Read>(input: &mut R, max: usize) -> Result<String, VaultError> {
    let len = read_u16(input)? as usize;
    if len > max {
        return Err(invalid("invalid sealed vault metadata field length"));
    }
    let mut bytes = vec![0; len];
    read_exact(input, &mut bytes)?;
    let value =
        String::from_utf8(bytes).map_err(|_| invalid("invalid sealed vault metadata text"))?;
    if value.contains('\0') {
        return Err(invalid("invalid sealed vault metadata text"));
    }
    Ok(value)
}

fn read_optional_string<R: Read>(input: &mut R, max: usize) -> Result<Option<String>, VaultError> {
    let mut tag = [0u8; 1];
    read_exact(input, &mut tag)?;
    match tag[0] {
        0 => Ok(None),
        1 => read_string(input, max).map(Some),
        _ => Err(invalid("invalid sealed vault optional-field marker")),
    }
}

fn read_u16(input: &mut impl Read) -> Result<u16, VaultError> {
    let mut bytes = [0u8; 2];
    read_exact(input, &mut bytes)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(input: &mut impl Read) -> Result<u32, VaultError> {
    let mut bytes = [0u8; 4];
    read_exact(input, &mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(input: &mut impl Read) -> Result<u64, VaultError> {
    let mut bytes = [0u8; 8];
    read_exact(input, &mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

fn read_i64(input: &mut impl Read) -> Result<i64, VaultError> {
    let mut bytes = [0u8; 8];
    read_exact(input, &mut bytes)?;
    Ok(i64::from_be_bytes(bytes))
}

fn read_bool(input: &mut impl Read) -> Result<bool, VaultError> {
    let mut byte = [0u8; 1];
    read_exact(input, &mut byte)?;
    match byte[0] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid("invalid sealed vault boolean field")),
    }
}

/// Unlock from a previously sealed envelope without storing the public root
/// token outside ciphertext. A candidate cipher decrypts only to private
/// temporary storage; it is inserted into the coordinator only after the
/// embedded exact scope and root token verify. The input must be seekable
/// because the envelope is reopened through the now-verified coordinator
/// before any metadata is returned.
pub fn unlock_from_snapshot<R: Read + Seek>(
    sessions: &VaultSessionCoordinator,
    scope: &VaultSessionScope,
    password: &mut [u8],
    input: &mut R,
    maximum_ciphertext_bytes: u64,
) -> Result<(SealedVaultSnapshot, SealedVaultBlobInfo), VaultError> {
    if maximum_ciphertext_bytes == 0 || maximum_ciphertext_bytes > MAX_CIPHERTEXT_BYTES {
        password.zeroize();
        return Err(invalid("invalid sealed vault ciphertext limit"));
    }
    sessions.unlock_with_deriver(scope, password, |password| {
        let cipher = VaultCipher::from_password(password)?;
        let mut bounded = input.take(maximum_ciphertext_bytes.saturating_add(1));
        let private = tempdir()?;
        let plaintext_path = private.path().join("metadata.tmp");
        let plaintext_bytes = cipher.decrypt_file_transactional(
            &mut bounded,
            &plaintext_path,
            MAX_PLAINTEXT_BYTES,
            None,
        )?;
        let consumed = maximum_ciphertext_bytes
            .saturating_add(1)
            .saturating_sub(bounded.limit());
        if consumed > maximum_ciphertext_bytes
            || consumed != ciphertext_len(plaintext_bytes)?
            || plaintext_bytes > MAX_PLAINTEXT_BYTES
        {
            return Err(invalid("sealed vault ciphertext length is invalid"));
        }
        let mut plaintext = File::open(&plaintext_path)?;
        let (snapshot, declared_len) = read_snapshot(&mut plaintext, scope)?;
        if declared_len != plaintext_bytes
            || plaintext_bytes != fs::metadata(&plaintext_path)?.len()
        {
            return Err(invalid(
                "sealed vault metadata length does not match its envelope",
            ));
        }
        if !cipher.verify_integrity_token(&snapshot.integrity_token) {
            return Err(invalid(
                "vault password did not verify the cached root token",
            ));
        }
        let verified = cipher.verify_and_unlock(&snapshot.integrity_token)?;
        verified.decrypt_path(&snapshot.encrypted_directory_path)?;
        Ok(verified)
    })?;
    input.seek(SeekFrom::Start(0))?;
    open_snapshot(sessions, scope, input, maximum_ciphertext_bytes)
}

fn read_exact(input: &mut impl Read, output: &mut [u8]) -> Result<(), VaultError> {
    input
        .read_exact(output)
        .map_err(|error| match error.kind() {
            io::ErrorKind::UnexpectedEof => invalid("truncated sealed vault metadata"),
            _ => error.into(),
        })
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Cursor, path::Path, sync::Arc};

    use crate::session::{VaultSessionCoordinator, VaultSessionScope};

    use super::{
        SealedVaultEntry, SealedVaultSnapshot, open_snapshot, seal_snapshot, unlock_from_snapshot,
    };

    const TOKEN: &str = include_str!("../tests/fixtures/web-integrity-token.b64");

    fn scope(account: &str, space: &str, root: &str) -> VaultSessionScope {
        VaultSessionScope::new(account, "https://vault.example", space, root).unwrap()
    }

    fn coordinator(unlocked_scope: &VaultSessionScope) -> Arc<VaultSessionCoordinator> {
        let sessions = Arc::new(VaultSessionCoordinator::new());
        let mut password = b"potato".to_vec();
        sessions
            .unlock(unlocked_scope, &mut password, TOKEN.trim())
            .unwrap();
        sessions
    }

    fn snapshot(entries: Vec<SealedVaultEntry>) -> SealedVaultSnapshot {
        SealedVaultSnapshot {
            integrity_token: TOKEN.trim().to_owned(),
            root_etag: Some("\"root-r1\"".to_owned()),
            root_path: "/Travel.vault".to_owned(),
            space_dav_root: "https://vault.example/remote.php/dav/files/user/".to_owned(),
            space_name: "Personal".to_owned(),
            space_dav_url: "https://vault.example/remote.php/dav/files/user/".to_owned(),
            space_personal: true,
            space_writable: true,
            space_encrypted: false,
            directory_resource_id: "root-resource".to_owned(),
            encrypted_directory_path: String::new(),
            directory_etag: "\"root-r1\"".to_owned(),
            directory_modified_unix: 1,
            directory_writable: true,
            entries,
        }
    }

    fn entry(id: &str, encrypted_name: &str) -> SealedVaultEntry {
        SealedVaultEntry {
            resource_id: id.to_owned(),
            parent_resource_id: "root-resource".to_owned(),
            encrypted_name: encrypted_name.to_owned(),
            etag: Some(format!("\"{id}-r1\"")),
            ciphertext_len: 123,
            directory: false,
            modified_unix: 1,
            writable: true,
        }
    }

    fn roundtrip(
        sessions: &VaultSessionCoordinator,
        scope: &VaultSessionScope,
        value: &SealedVaultSnapshot,
        path: &Path,
    ) -> (SealedVaultSnapshot, Vec<u8>) {
        let info = seal_snapshot(sessions, scope, value, path).unwrap();
        let ciphertext = fs::read(path).unwrap();
        assert_eq!(ciphertext.len() as u64, info.ciphertext_bytes);
        let (decoded, decoded_info) = open_snapshot(
            sessions,
            scope,
            &mut Cursor::new(ciphertext.clone()),
            info.ciphertext_bytes,
        )
        .unwrap();
        assert_eq!(decoded, *value);
        assert_eq!(decoded_info, info);
        (decoded, ciphertext)
    }

    #[test]
    fn seals_only_opaque_metadata_and_roundtrips_exact_scope() {
        let scope = scope("profile-1", "space-1", "root-resource");
        let sessions = coordinator(&scope);
        let value = snapshot(vec![entry("file-1", "f4g5h6")]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opaque-cache-key");
        let (_, ciphertext) = roundtrip(&sessions, &scope, &value, &path);
        assert!(
            !ciphertext
                .windows(b"f4g5h6".len())
                .any(|window| window == b"f4g5h6")
        );
        assert!(
            !ciphertext
                .windows(b"root-resource".len())
                .any(|window| window == b"root-resource")
        );
    }

    #[test]
    fn rejects_authenticated_envelope_from_another_scope() {
        let source_scope = scope("profile-1", "space-1", "root-resource");
        let other_scope = scope("profile-2", "space-1", "root-resource");
        let sessions = coordinator(&source_scope);
        let mut other_password = b"potato".to_vec();
        sessions
            .unlock(&other_scope, &mut other_password, TOKEN.trim())
            .unwrap();
        let value = snapshot(vec![entry("file-1", "f4g5h6")]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opaque-cache-key");
        let (_, ciphertext) = roundtrip(&sessions, &source_scope, &value, &path);
        let error = open_snapshot(
            &sessions,
            &other_scope,
            &mut Cursor::new(ciphertext),
            8 * 1024 * 1024,
        )
        .unwrap_err();
        assert!(error.to_string().contains("another scope"));
    }

    #[test]
    fn offline_unlock_verifies_embedded_token_before_publishing_session() {
        let scope = scope("profile-1", "space-1", "root-resource");
        let original = coordinator(&scope);
        let value = snapshot(vec![entry("file-1", "f4g5h6")]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opaque-cache-key");
        let info = seal_snapshot(&original, &scope, &value, &path).unwrap();
        let ciphertext = fs::read(path).unwrap();

        let restarted = VaultSessionCoordinator::new();
        let mut wrong_password = b"not-potato".to_vec();
        assert!(
            unlock_from_snapshot(
                &restarted,
                &scope,
                &mut wrong_password,
                &mut Cursor::new(ciphertext.clone()),
                info.ciphertext_bytes,
            )
            .is_err()
        );
        assert!(wrong_password.iter().all(|byte| *byte == 0));
        assert!(!restarted.is_unlocked(&scope).unwrap());

        let mut password = b"potato".to_vec();
        let (opened, opened_info) = unlock_from_snapshot(
            &restarted,
            &scope,
            &mut password,
            &mut Cursor::new(ciphertext),
            info.ciphertext_bytes,
        )
        .unwrap();
        assert!(password.iter().all(|byte| *byte == 0));
        assert!(restarted.is_unlocked(&scope).unwrap());
        assert_eq!(opened, value);
        assert_eq!(opened_info, info);
    }

    #[test]
    fn rejects_tampered_blocks_and_full_block_boundary_truncation() {
        let scope = scope("profile-1", "space-1", "root-resource");
        let sessions = coordinator(&scope);
        let many = (0..400)
            .map(|index| entry(&format!("file-{index}"), &"f".repeat(320)))
            .collect();
        let value = snapshot(many);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opaque-cache-key");
        let (_, ciphertext) = roundtrip(&sessions, &scope, &value, &path);
        let mut damaged = ciphertext.clone();
        damaged[40] ^= 0x80;
        assert!(
            open_snapshot(
                &sessions,
                &scope,
                &mut Cursor::new(damaged),
                8 * 1024 * 1024,
            )
            .is_err()
        );

        // Web crypto authenticates blocks individually, so this specifically
        // verifies that the envelope's in-ciphertext total length catches a
        // deletion at a complete 64 KiB plaintext block boundary.
        let first_block_boundary = 32 + 65_536 + 16;
        assert!(ciphertext.len() > first_block_boundary);
        let truncated = ciphertext[..first_block_boundary].to_vec();
        assert!(
            open_snapshot(
                &sessions,
                &scope,
                &mut Cursor::new(truncated),
                8 * 1024 * 1024,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_unbounded_duplicate_or_invalid_records_without_publishing() {
        let scope = scope("profile-1", "space-1", "root-resource");
        let sessions = coordinator(&scope);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opaque-cache-key");
        let duplicate = snapshot(vec![entry("file-1", "f4g5h6"), entry("file-1", "g4h5i6")]);
        assert!(seal_snapshot(&sessions, &scope, &duplicate, &path).is_err());
        assert!(!path.exists());
        let invalid_name = snapshot(vec![entry("file-1", "plain-name.txt")]);
        assert!(seal_snapshot(&sessions, &scope, &invalid_name, &path).is_err());
        assert!(!path.exists());
        let oversized_entry = SealedVaultSnapshot {
            entries: vec![SealedVaultEntry {
                ciphertext_len: u64::MAX,
                ..entry("file-1", "f4g5h6")
            }],
            ..snapshot(Vec::new())
        };
        assert!(seal_snapshot(&sessions, &scope, &oversized_entry, &path).is_err());
        assert!(!path.exists());
        let too_many = snapshot(
            (0..10_001)
                .map(|i| entry(&format!("f{i}"), "f4g5h6"))
                .collect(),
        );
        assert!(seal_snapshot(&sessions, &scope, &too_many, &path).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn locked_scope_cannot_open_metadata_and_bad_token_cannot_seal() {
        let scope = scope("profile-1", "space-1", "root-resource");
        let sessions = coordinator(&scope);
        let value = snapshot(vec![entry("file-1", "f4g5h6")]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opaque-cache-key");
        let (_, ciphertext) = roundtrip(&sessions, &scope, &value, &path);
        sessions.lock(&scope).unwrap();
        assert!(
            open_snapshot(
                &sessions,
                &scope,
                &mut Cursor::new(ciphertext),
                8 * 1024 * 1024,
            )
            .is_err()
        );

        let bad = SealedVaultSnapshot {
            integrity_token: "not-a-valid-token".to_owned(),
            ..value
        };
        let bad_path = dir.path().join("bad-token-cache-key");
        assert!(seal_snapshot(&sessions, &scope, &bad, &bad_path).is_err());
        assert!(!bad_path.exists());
    }
}

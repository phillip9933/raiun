//! Handle-bound Windows blob storage and publication receipts.

use super::{CacheError, MAX_CONTENT_BYTES, io_error};
use raiun_control_windows::PinnedFileIdentity;
use raiun_control_windows::{
    OwnedPrivateReader, PinnedPrivateFile, PinnedPrivateFileAccess, PrivateDirectory,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;

const PUBLICATION_LOCK: &str = ".publication.lock";

#[cfg(test)]
#[path = "reservation_inventory_tests.rs"]
mod reservation_inventory_tests;

/// Receipt for a verified publication, retaining its immutable handle.
/// `created` only describes this publication; it is not permission to delete.
/// Cleanup must still check database references and the exact file identity.
pub(super) struct PublishedBlob {
    // Keeping this handle alive prevents replacement through metadata commit.
    _reader: OwnedPrivateReader,
    #[cfg(test)]
    name: String,
    #[cfg(test)]
    identity: PinnedFileIdentity,
    pub(super) byte_len: u64,
    pub(super) digest: String,
    #[cfg(test)]
    created: bool,
}

impl PublishedBlob {
    fn new(
        reader: OwnedPrivateReader,
        _name: &str,
        byte_len: u64,
        digest: String,
        _created: bool,
    ) -> Self {
        Self {
            #[cfg(test)]
            identity: reader.identity(),
            _reader: reader,
            #[cfg(test)]
            name: _name.to_owned(),
            byte_len,
            digest,
            #[cfg(test)]
            created: _created,
        }
    }
}

pub(super) struct WindowsBlobStore {
    pub(super) directory: Arc<PrivateDirectory>,
    pub(super) max_bytes: u64,
    pub(super) max_objects: usize,
}

/// The same pin spans publication and the caller's metadata transaction.
/// A lease from a different directory/store cannot authorize publication.
pub(super) struct PublicationLease<'a> {
    directory: &'a Arc<PrivateDirectory>,
    _lock: PinnedPrivateFile<'a>,
}

pub(super) struct StorageInventory {
    // Includes the full promised length of versioned stage reservations;
    // this is a logical byte charge, not filesystem allocated-block usage.
    pub(super) physical_bytes: u64,
    pub(super) unindexed_bytes: u64,
    objects: usize,
}

/// One reservation owns only its private stage, never an older cache object.
/// Drop releases handles but does not delete uncertain recovery bytes.
pub(super) struct ReservedDownload<'a> {
    store: &'a WindowsBlobStore,
    writer: Option<PinnedPrivateFile<'a>>,
    name: String,
    destination: String,
    identity: PinnedFileIdentity,
    length: u64,
    written: u64,
    digest: Sha256,
}

impl ReservedDownload<'_> {
    /// Explicitly abandon only this never-published, never-indexed GET stage.
    /// Generic Drop still preserves uncertainty; no destination is touched.
    pub(super) fn abort(mut self) -> Result<(), CacheError> {
        let _lease = self.store.publication_lease()?;
        drop(self.writer.take());
        self.store
            .directory
            .open_delete_candidate(OsStr::new(&self.name), self.identity)
            .map_err(io_error)?
            .delete()
            .map_err(io_error)
    }
    pub(super) fn append(&mut self, offset: u64, bytes: &[u8]) -> Result<(), CacheError> {
        if offset != self.written {
            return Err(CacheError::Conflict);
        }
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or(CacheError::LimitExceeded)?;
        if end > self.length || bytes.len() > 1024 * 1024 {
            return Err(CacheError::LimitExceeded);
        }
        self.writer
            .as_mut()
            .ok_or(CacheError::Conflict)?
            .write_all(bytes)
            .map_err(io_error)?;
        self.digest.update(bytes);
        self.written = end;
        Ok(())
    }

    pub(super) fn finish(self) -> Result<PublishedBlob, CacheError> {
        self.finish_cancellable(|| false)
    }

    pub(super) fn finish_cancellable(
        mut self,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<PublishedBlob, CacheError> {
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        if self.written != self.length {
            return Err(CacheError::Corrupt);
        }
        let expected = format!("{:x}", self.digest.finalize());
        self.writer
            .as_mut()
            .ok_or(CacheError::Conflict)?
            .flush()
            .map_err(io_error)?;
        drop(self.writer.take());
        let lease = self.store.publication_lease()?;
        let publication = self.store.directory.publish_staged_file(
            OsStr::new(&self.name),
            OsStr::new(&self.destination),
            self.identity,
        );
        let (created, expected_identity) = match publication {
            Ok(identity) => (true, Some(identity)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (false, None),
            Err(error) => return Err(io_error(error)),
        };
        let mut reader = self
            .store
            .directory
            .open_owned_immutable_file(OsStr::new(&self.destination))
            .map_err(io_error)?;
        if expected_identity.is_some_and(|identity| identity != reader.identity()) {
            return Err(CacheError::Corrupt);
        }
        // Full readback uses only this file's immutable pin. No global cache,
        // backend or token-publication lease may span this verification.
        drop(lease);
        let (length, actual) = hash_bounded_cancellable(&mut reader, self.length, &mut cancelled)?;
        if length != self.length || actual != expected {
            return Err(CacheError::Corrupt);
        }
        reader.rewind().map_err(io_error)?;
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        if !created {
            // This exact, never-indexed stage is now a verified duplicate of
            // the pinned destination. No older blob or journal is removed.
            let _lease = self.store.publication_lease()?;
            self.store
                .directory
                .open_delete_candidate(OsStr::new(&self.name), self.identity)
                .map_err(io_error)?
                .delete()
                .map_err(io_error)?;
        }
        Ok(PublishedBlob::new(
            reader,
            &self.destination,
            length,
            actual,
            created,
        ))
    }
}

impl WindowsBlobStore {
    pub(super) fn finish_existing_download(
        reader: OwnedPrivateReader,
        name: &str,
        length: u64,
        digest: &str,
    ) -> Result<PublishedBlob, CacheError> {
        Self::finish_existing_download_cancellable(reader, name, length, digest, || false)
    }

    pub(super) fn finish_existing_download_cancellable(
        mut reader: OwnedPrivateReader,
        name: &str,
        length: u64,
        digest: &str,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<PublishedBlob, CacheError> {
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        validate_name(name)?;
        if length > MAX_CONTENT_BYTES {
            return Err(CacheError::LimitExceeded);
        }
        let (actual_length, actual_digest) =
            hash_bounded_cancellable(&mut reader, length, &mut cancelled)?;
        if actual_length != length || actual_digest != digest {
            return Err(CacheError::Corrupt);
        }
        reader.rewind().map_err(io_error)?;
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        Ok(PublishedBlob::new(
            reader,
            name,
            length,
            actual_digest,
            false,
        ))
    }
    pub(super) fn reserve_download<'a>(
        &'a self,
        lease: &PublicationLease<'_>,
        destination: &str,
        length: u64,
    ) -> Result<ReservedDownload<'a>, CacheError> {
        if !Arc::ptr_eq(lease.directory, &self.directory) {
            return Err(CacheError::UnsafeDirectory);
        }
        validate_name(destination)?;
        if length > MAX_CONTENT_BYTES {
            return Err(CacheError::LimitExceeded);
        }
        self.check_capacity(length)?;
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|_| CacheError::Io("cannot allocate reservation name".into()))?;
        let name = format!(
            ".stage-v1-{}-{length:016x}",
            nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let writer = self
            .directory
            .create_new_pinned_file(OsStr::new(&name))
            .map_err(io_error)?;
        let identity = writer.identity();
        Ok(ReservedDownload {
            store: self,
            writer: Some(writer),
            name,
            destination: destination.into(),
            identity,
            length,
            written: 0,
            digest: Sha256::new(),
        })
    }
    pub(super) fn publication_lease(&self) -> Result<PublicationLease<'_>, CacheError> {
        Ok(PublicationLease {
            directory: &self.directory,
            _lock: super::windows_lock::try_private_lock(
                &self.directory,
                OsStr::new(PUBLICATION_LOCK),
            )?,
        })
    }

    pub(super) fn open_verified(
        &self,
        name: &str,
        length: u64,
        digest: &str,
    ) -> Result<OwnedPrivateReader, CacheError> {
        self.open_verified_cancellable(name, length, digest, || false)
    }

    pub(super) fn open_verified_cancellable(
        &self,
        name: &str,
        length: u64,
        digest: &str,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<OwnedPrivateReader, CacheError> {
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        validate_name(name)?;
        if length > MAX_CONTENT_BYTES {
            return Err(CacheError::LimitExceeded);
        }
        let mut file = self
            .directory
            .open_owned_immutable_file(OsStr::new(name))
            .map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    CacheError::NotFound
                } else {
                    io_error(error)
                }
            })?;
        let (actual_length, actual_digest) =
            hash_bounded_cancellable(&mut file, length, &mut cancelled)?;
        if actual_length != length || actual_digest != digest {
            return Err(CacheError::Corrupt);
        }
        file.rewind().map_err(io_error)?;
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        Ok(file)
    }

    /// Success retains an immutable pin through the caller's read. The caller
    /// must retain its original source until success; a rejected existing-object
    /// retry does not create another recovery copy. Once staging starts, failures
    /// preserve staging/published bytes: a rename may have happened already.
    #[cfg(test)]
    fn publish(
        &self,
        name: &str,
        source: &mut impl Read,
        length: u64,
    ) -> Result<PublishedBlob, CacheError> {
        let lease = self.publication_lease()?;
        self.publish_under_lease(&lease, name, source, length)
    }

    pub(super) fn publish_under_lease<R: Read + ?Sized>(
        &self,
        lease: &PublicationLease<'_>,
        name: &str,
        source: &mut R,
        length: u64,
    ) -> Result<PublishedBlob, CacheError> {
        if !Arc::ptr_eq(lease.directory, &self.directory) {
            return Err(CacheError::UnsafeDirectory);
        }
        validate_name(name)?;
        if length > MAX_CONTENT_BYTES {
            return Err(CacheError::LimitExceeded);
        }
        // Reuse an existing exact object without reserving a new stage. Keep
        // its immutable handle through both hashes and the returned read: never
        // verify by pathname and then reopen an unchecked replacement.
        match self.directory.open_owned_immutable_file(OsStr::new(name)) {
            Ok(mut file) => {
                let (existing_length, existing_digest) = hash_bounded(&mut file, length)?;
                if existing_length != length {
                    return Err(CacheError::Corrupt);
                }
                let (source_length, source_digest) = hash_bounded(source, length)?;
                if source_length != length || source_digest != existing_digest {
                    return Err(CacheError::Corrupt);
                }
                file.rewind().map_err(io_error)?;
                return Ok(PublishedBlob::new(
                    file,
                    name,
                    length,
                    existing_digest,
                    false,
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
        self.check_capacity(length)?;
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|_| CacheError::Io("cannot allocate private stage name".into()))?;
        let stage_name = format!(
            ".stage-{}",
            nonce.iter().map(|v| format!("{v:02x}")).collect::<String>()
        );
        let mut stage = self
            .directory
            .create_new_pinned_file(OsStr::new(&stage_name))
            .map_err(io_error)?;
        let identity = stage.identity();
        let mut hasher = Sha256::new();
        let mut count = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = source.read(&mut buffer).map_err(io_error)?;
            if read == 0 {
                break;
            }
            count = count
                .checked_add(read as u64)
                .ok_or(CacheError::LimitExceeded)?;
            if count > length {
                return Err(CacheError::Corrupt);
            }
            stage.write_all(&buffer[..read]).map_err(io_error)?;
            hasher.update(&buffer[..read]);
        }
        if count != length {
            return Err(CacheError::Corrupt);
        }
        let digest = format!("{:x}", hasher.finalize());
        stage.flush().map_err(io_error)?;
        drop(stage);
        // Publication reopens this identity with exclusive write access and
        // flushes its exact handle before and after write-through rename.
        match self.directory.publish_staged_file(
            OsStr::new(&stage_name),
            OsStr::new(name),
            identity,
        ) {
            Ok(published) => {
                let file = self.open_verified(name, length, &digest)?;
                if file.identity() != published {
                    return Err(CacheError::Corrupt);
                }
                Ok(PublishedBlob::new(file, name, length, digest, true))
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let file = self.open_verified(name, length, &digest)?;
                self.directory
                    .open_delete_candidate(OsStr::new(&stage_name), identity)
                    .map_err(io_error)?
                    .delete()
                    .map_err(io_error)?;
                Ok(PublishedBlob::new(file, name, length, digest, false))
            }
            Err(error) => Err(io_error(error)),
        }
    }

    fn check_capacity(&self, incoming: u64) -> Result<(), CacheError> {
        if incoming > self.max_bytes {
            return Err(CacheError::InsufficientSpace);
        }
        let inventory = self.scan_inventory(&BTreeSet::new())?;
        if inventory.objects >= self.max_objects
            || inventory.physical_bytes > self.max_bytes - incoming
        {
            return Err(CacheError::InsufficientSpace);
        }
        Ok(())
    }

    pub(super) fn inventory(
        &self,
        lease: &PublicationLease<'_>,
        indexed: &BTreeSet<String>,
    ) -> Result<StorageInventory, CacheError> {
        if !Arc::ptr_eq(lease.directory, &self.directory) {
            return Err(CacheError::UnsafeDirectory);
        }
        self.scan_inventory(indexed)
    }

    fn scan_inventory(&self, indexed: &BTreeSet<String>) -> Result<StorageInventory, CacheError> {
        self.directory.verify_path().map_err(io_error)?;
        let mut inventory = StorageInventory {
            physical_bytes: 0,
            unindexed_bytes: 0,
            objects: 0,
        };
        // Enumeration supplies names only. Every size comes from an immutable
        // handle opened beneath the retained private directory, never metadata
        // read through an unvalidated path. Unknown recovery files are preserved.
        for entry in std::fs::read_dir(self.directory.path()).map_err(io_error)? {
            let name = entry.map_err(io_error)?.file_name();
            if name == OsStr::new(PUBLICATION_LOCK) {
                continue;
            }
            inventory.objects = inventory
                .objects
                .checked_add(1)
                .ok_or(CacheError::LimitExceeded)?;
            if inventory.objects > self.max_objects {
                return Err(CacheError::LimitExceeded);
            }
            let text = name.to_str().ok_or(CacheError::UnsafeDirectory)?;
            let stage = super::stage_name::classify(text)?;
            if stage == super::stage_name::StageName::Ordinary {
                validate_name(text)?;
            }
            // A reserved stage may be written without holding this global
            // publication lease. Inventory only observes its pinned size;
            // ordinary immutable objects retain no-write-sharing opens.
            let access = match stage {
                super::stage_name::StageName::Reserved(_) => PinnedPrivateFileAccess::ReadOnly,
                _ => PinnedPrivateFileAccess::ImmutableRead,
            };
            let mut file = self
                .directory
                .open_pinned_file(&name, access)
                .map_err(io_error)?;
            let length = file.seek(SeekFrom::End(0)).map_err(io_error)?;
            if length > MAX_CONTENT_BYTES {
                return Err(CacheError::LimitExceeded);
            }
            let charged = match stage {
                super::stage_name::StageName::Reserved(promised) => length.max(promised),
                _ => length,
            };
            inventory.physical_bytes = inventory
                .physical_bytes
                .checked_add(charged)
                .ok_or(CacheError::LimitExceeded)?;
            if stage != super::stage_name::StageName::Ordinary || !indexed.contains(text) {
                inventory.unindexed_bytes = inventory
                    .unindexed_bytes
                    .checked_add(charged)
                    .ok_or(CacheError::LimitExceeded)?;
            }
        }
        self.directory.verify_path().map_err(io_error)?;
        Ok(inventory)
    }

    /// Acquire deletion authority before removing metadata. A live immutable
    /// reader refuses DELETE sharing, so callers retain its accounting row.
    pub(super) fn prepare_eviction<'a>(
        &'a self,
        lease: &PublicationLease<'_>,
        name: &str,
    ) -> Result<Option<PinnedPrivateFile<'a>>, CacheError> {
        if !Arc::ptr_eq(lease.directory, &self.directory) {
            return Err(CacheError::UnsafeDirectory);
        }
        validate_name(name)?;
        let observed = match self.directory.open_owned_immutable_file(OsStr::new(name)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(error)),
        };
        let identity = observed.identity();
        drop(observed);
        match self
            .directory
            .open_delete_candidate(OsStr::new(name), identity)
        {
            Ok(file) => Ok(Some(file)),
            Err(error) if matches!(error.raw_os_error(), Some(32 | 33)) => {
                Err(CacheError::Conflict)
            }
            Err(error) => Err(io_error(error)),
        }
    }

    #[cfg(test)]
    fn delete_observed(&self, name: &str, identity: PinnedFileIdentity) -> Result<(), CacheError> {
        validate_name(name)?;
        self.directory
            .open_delete_candidate(OsStr::new(name), identity)
            .map_err(io_error)?
            .delete()
            .map_err(io_error)
    }
}

fn validate_name(name: &str) -> Result<(), CacheError> {
    // Match the cache's opaque SHA-256 .blob basenames, never user paths.
    let key = name.strip_suffix(".blob").ok_or(CacheError::InvalidEntry)?;
    if key.len() != 64
        || !key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CacheError::InvalidEntry);
    }
    Ok(())
}

fn hash_bounded<R: Read + ?Sized>(reader: &mut R, limit: u64) -> Result<(u64, String), CacheError> {
    hash_bounded_cancellable(reader, limit, || false)
}

fn hash_bounded_cancellable<R: Read + ?Sized>(
    reader: &mut R,
    limit: u64,
    mut cancelled: impl FnMut() -> bool,
) -> Result<(u64, String), CacheError> {
    let mut length = 0_u64;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        let count = reader.read(&mut buffer).map_err(io_error)?;
        // Include cancellation arriving during the final read or EOF probe.
        // Never return a verified receipt after an observed cancellation.
        if cancelled() {
            return Err(CacheError::Cancelled);
        }
        if count == 0 {
            break;
        }
        length = length
            .checked_add(count as u64)
            .ok_or(CacheError::LimitExceeded)?;
        if length > limit {
            return Err(CacheError::Corrupt);
        }
        hasher.update(&buffer[..count]);
    }
    Ok((length, format!("{:x}", hasher.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use raiun_control_windows::PinnedDirectory;
    use std::fs::OpenOptions;

    fn store(state: &std::path::Path) -> WindowsBlobStore {
        let parent = PinnedDirectory::open(state).unwrap();
        WindowsBlobStore {
            max_bytes: 8 * 1024 * 1024,
            max_objects: 128,
            directory: Arc::new(
                PrivateDirectory::create_or_open_under(&parent, OsStr::new("blobs")).unwrap(),
            ),
        }
    }
    fn key() -> String {
        format!("{}.blob", "a".repeat(64))
    }

    #[test]
    fn publication_rejects_a_lease_from_another_store_without_creating_bytes() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let owner = store(first.path());
        let other = store(second.path());
        let lease = owner.publication_lease().unwrap();
        assert!(matches!(
            other.publish_under_lease(&lease, &key(), &mut &b"data"[..], 4),
            Err(CacheError::UnsafeDirectory)
        ));
        assert!(!other.directory.path().join(key()).exists());
        assert_eq!(
            std::fs::read_dir(other.directory.path()).unwrap().count(),
            0
        );
    }

    #[test]
    fn publication_reopens_verified_bytes_and_rejects_conflicting_content() {
        let state = tempfile::tempdir().unwrap();
        let store = store(state.path());
        let published = store.publish(&key(), &mut &b"original"[..], 8).unwrap();
        assert!(published.created);
        assert_eq!(published.name, key());
        assert_eq!(published.byte_len, 8);
        assert_eq!(published.identity, published._reader.identity());
        let identity = published.identity;
        let PublishedBlob {
            _reader: mut file,
            digest,
            ..
        } = published;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
        drop(file);
        let reused = store.publish(&key(), &mut &b"original"[..], 8).unwrap();
        assert!(!reused.created);
        assert_eq!(reused.identity, identity);
        assert_eq!(reused.name, key());
        assert_eq!(reused.byte_len, 8);
        let PublishedBlob {
            _reader: duplicate,
            digest: same_digest,
            ..
        } = reused;
        assert_eq!(digest, same_digest);
        drop(duplicate);
        assert!(store.publish(&key(), &mut &b"replaced"[..], 8).is_err());
        drop(store);
        let reopened = self::store(state.path());
        let mut file = reopened.open_verified(&key(), 8, &digest).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
    }

    #[test]
    fn immutable_read_excludes_writers_and_delete_until_pin_closes() {
        let state = tempfile::tempdir().unwrap();
        let store = store(state.path());
        let PublishedBlob { _reader: file, .. } =
            store.publish(&key(), &mut &b"original"[..], 8).unwrap();
        let identity = file.identity();
        assert!(
            OpenOptions::new()
                .write(true)
                .open(store.directory.path().join(key()))
                .is_err()
        );
        assert!(store.delete_observed(&key(), identity).is_err());
        drop(file);
        store.delete_observed(&key(), identity).unwrap();
        assert!(!store.directory.path().join(key()).exists());
    }

    #[test]
    fn wrong_length_and_unsafe_names_never_publish() {
        let state = tempfile::tempdir().unwrap();
        let store = store(state.path());
        assert!(store.publish(&key(), &mut &b"too long"[..], 3).is_err());
        assert!(!store.directory.path().join(key()).exists());
        assert!(store.publish("../escape", &mut &b"x"[..], 1).is_err());
        assert!(!state.path().join("escape").exists());
        assert!(
            std::fs::read_dir(store.directory.path()).unwrap().count() > 0,
            "failed stage remains recoverable"
        );
    }

    #[test]
    fn hardlink_reads_and_replaced_identity_deletes_are_rejected() {
        let state = tempfile::tempdir().unwrap();
        let store = store(state.path());
        let PublishedBlob {
            _reader: file,
            digest,
            ..
        } = store.publish(&key(), &mut &b"original"[..], 8).unwrap();
        let old = file.identity();
        drop(file);
        let alias = store.directory.path().join("alias");
        std::fs::hard_link(store.directory.path().join(key()), &alias).unwrap();
        assert!(store.open_verified(&key(), 8, &digest).is_err());
        std::fs::remove_file(&alias).unwrap();
        // Retain the old object under a different name so its ID cannot be reused.
        std::fs::rename(
            store.directory.path().join(key()),
            store
                .directory
                .path()
                .join(format!("{}.blob", "b".repeat(64))),
        )
        .unwrap();
        let PublishedBlob { _reader: file, .. } =
            store.publish(&key(), &mut &b"new body"[..], 8).unwrap();
        drop(file);
        assert!(store.delete_observed(&key(), old).is_err());
        assert_eq!(
            std::fs::read(store.directory.path().join(key())).unwrap(),
            b"new body"
        );
    }
    struct BrokenSource;
    impl Read for BrokenSource {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic interrupted input"))
        }
    }

    fn object_count(store: &WindowsBlobStore) -> usize {
        std::fs::read_dir(store.directory.path())
            .unwrap()
            .filter(|entry| entry.as_ref().unwrap().file_name() != OsStr::new(PUBLICATION_LOCK))
            .count()
    }

    #[test]
    fn failed_stages_remain_accounted_after_reopen_without_deleting_recovery() {
        let state = tempfile::tempdir().unwrap();
        let mut store = store(state.path());
        store.max_bytes = 8;
        let mut interrupted = (&b"four"[..]).chain(BrokenSource);
        assert!(store.publish(&key(), &mut interrupted, 8).is_err());
        assert_eq!(object_count(&store), 1);
        drop(store);
        let mut reopened = self::store(state.path());
        reopened.max_bytes = 8;
        assert!(matches!(
            reopened.publish(&key(), &mut &b"12345"[..], 5),
            Err(CacheError::InsufficientSpace)
        ));
        assert_eq!(object_count(&reopened), 1);
        let stage = std::fs::read_dir(reopened.directory.path())
            .unwrap()
            .map(|entry| entry.unwrap())
            .find(|entry| entry.file_name().to_string_lossy().starts_with(".stage-"))
            .unwrap();
        assert_eq!(std::fs::read(stage.path()).unwrap(), b"four");
    }

    #[test]
    fn empty_failed_stages_are_bounded_by_object_count() {
        let state = tempfile::tempdir().unwrap();
        let mut store = store(state.path());
        store.max_objects = 2;
        assert!(store.publish(&key(), &mut BrokenSource, 0).is_err());
        assert!(store.publish(&key(), &mut BrokenSource, 0).is_err());
        assert_eq!(object_count(&store), 2);
        assert!(matches!(
            store.publish(&key(), &mut BrokenSource, 0),
            Err(CacheError::InsufficientSpace)
        ));
        assert_eq!(object_count(&store), 2);
    }

    #[test]
    fn publication_budget_lock_blocks_other_store_and_unknown_entries_fail_closed() {
        let state = tempfile::tempdir().unwrap();
        let store = store(state.path());
        let another = self::store(state.path());
        let lock = super::super::windows_lock::try_private_lock(
            &store.directory,
            OsStr::new(PUBLICATION_LOCK),
        )
        .unwrap();
        assert!(matches!(
            another.publish(&key(), &mut &b"x"[..], 1),
            Err(CacheError::Conflict)
        ));
        assert_eq!(object_count(&store), 0);
        drop(lock);
        let unexpected = store
            .directory
            .create_new_pinned_file(OsStr::new("unexpected"))
            .unwrap();
        drop(unexpected);
        assert!(another.publish(&key(), &mut &b"x"[..], 1).is_err());
        assert_eq!(object_count(&store), 1);
        assert!(store.directory.path().join("unexpected").is_file());
    }
    #[test]
    fn identical_retry_at_full_budget_reuses_exact_object_without_staging() {
        let state = tempfile::tempdir().unwrap();
        let mut store = store(state.path());
        store.max_bytes = 8;
        store.max_objects = 1;
        let PublishedBlob {
            _reader: file,
            digest,
            ..
        } = store.publish(&key(), &mut &b"original"[..], 8).unwrap();
        let identity = file.identity();
        drop(file);
        for _ in 0..3 {
            let PublishedBlob {
                _reader: mut file,
                digest: reused_digest,
                ..
            } = store.publish(&key(), &mut &b"original"[..], 8).unwrap();
            assert_eq!(file.identity(), identity);
            assert_eq!(reused_digest, digest);
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"original");
            assert_eq!(object_count(&store), 1);
        }
        let other = format!("{}.blob", "c".repeat(64));
        assert!(matches!(
            store.publish(&other, &mut &b"x"[..], 1),
            Err(CacheError::InsufficientSpace)
        ));
        assert_eq!(object_count(&store), 1);
    }

    #[test]
    fn conflicting_short_long_and_interrupted_retries_preserve_existing_object() {
        let state = tempfile::tempdir().unwrap();
        let mut store = store(state.path());
        store.max_bytes = 8;
        store.max_objects = 1;
        let PublishedBlob {
            _reader: file,
            digest,
            ..
        } = store.publish(&key(), &mut &b"original"[..], 8).unwrap();
        let identity = file.identity();
        drop(file);
        for mut body in [&b"replaced"[..], &b"short"[..], &b"too-long-source"[..]] {
            assert!(matches!(
                store.publish(&key(), &mut body, 8),
                Err(CacheError::Corrupt)
            ));
        }
        assert!(store.publish(&key(), &mut BrokenSource, 8).is_err());
        let mut file = store.open_verified(&key(), 8, &digest).unwrap();
        assert_eq!(file.identity(), identity);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
        assert_eq!(object_count(&store), 1);
    }
    #[test]
    fn returned_reader_keeps_directory_and_file_pinned_after_store_drop() {
        let state = tempfile::tempdir().unwrap();
        let store = store(state.path());
        let directory_path = store.directory.path().to_path_buf();
        let weak = Arc::downgrade(&store.directory);
        let PublishedBlob {
            _reader: reader, ..
        } = store.publish(&key(), &mut &b"original"[..], 8).unwrap();
        let identity = reader.identity();
        drop(store);
        assert!(
            weak.upgrade().is_some(),
            "reader must own its directory lifetime"
        );
        assert!(std::fs::rename(&directory_path, state.path().join("moved")).is_err());
        assert!(
            OpenOptions::new()
                .write(true)
                .open(directory_path.join(key()))
                .is_err()
        );
        let reader = std::thread::spawn(move || {
            let mut reader = reader;
            assert_eq!(reader.metadata().unwrap().len(), 8);
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"original");
            reader.rewind().unwrap();
            reader.verify().unwrap();
            reader
        })
        .join()
        .unwrap();
        assert_eq!(reader.identity(), identity);
        let mut reader = crate::CacheContentReader::from(reader);
        assert_eq!(reader.metadata().unwrap().len(), 8);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
        reader.rewind().unwrap();
        assert!(weak.upgrade().is_some());
        assert!(std::fs::rename(&directory_path, state.path().join("moved")).is_err());
        drop(reader);
        assert!(
            weak.upgrade().is_none(),
            "closed reader must release its directory owner"
        );
        std::fs::rename(&directory_path, state.path().join("moved")).unwrap();
    }
}

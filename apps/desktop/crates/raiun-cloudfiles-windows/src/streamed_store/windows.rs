//! Windows-only safe adapter. Native policy remains in control-windows.
use super::*;
use crate::recovery_state::RecoveryStateRoot;
use raiun_control_windows::{
    OwnedPrivateReader, PinnedDirectory, PinnedFileIdentity, PrivateDirectory,
    PrivateMetadataReadError,
};
use std::{ffi::OsStr, fs::File};

const _: () = assert!(PrivateDirectory::MAX_METADATA_READ_BYTES >= META_LIMIT as u64);

struct WindowsDirectory {
    directory: Arc<PrivateDirectory>,
    _admitted_state: Arc<RecoveryStateRoot>,
}
pub(super) fn root(
    state: Arc<RecoveryStateRoot>,
    name: &str,
    create: bool,
) -> Result<Arc<dyn Directory>, StoreError> {
    if name != V2_STORE_ROOT {
        return Err(StoreError::Invalid);
    }
    state.verify_path().map_err(io_error)?;
    let parent = PinnedDirectory::open(state.path()).map_err(io_error)?;
    let directory = if create {
        PrivateDirectory::create_or_open_under(&parent, OsStr::new(name))
    } else {
        PrivateDirectory::open_under(&parent, OsStr::new(name))
    }
    .map_err(io_error)?;
    state.verify_path().map_err(io_error)?;
    Ok(Arc::new(WindowsDirectory {
        directory: Arc::new(directory),
        _admitted_state: state,
    }))
}
/// Open only an existing root. Preserve absence separately from every unsafe
/// entry/type/ACL failure; never recreate missing recovery evidence.
pub(super) fn existing_root(
    state: Arc<RecoveryStateRoot>,
    name: &str,
) -> Result<Option<Arc<dyn Directory>>, StoreError> {
    if name != V2_STORE_ROOT {
        return Err(StoreError::Invalid);
    }
    state.verify_path().map_err(io_error)?;
    let parent = PinnedDirectory::open(state.path()).map_err(io_error)?;
    let directory = match PrivateDirectory::open_under(&parent, OsStr::new(name)) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // A dangling reparse point is existing unsafe evidence, not absence.
            match std::fs::symlink_metadata(state.path().join(name)) {
                Err(missing) if missing.kind() == io::ErrorKind::NotFound => {
                    state.verify_path().map_err(io_error)?;
                    parent.verify_path().map_err(io_error)?;
                    return Ok(None);
                }
                _ => return Err(StoreError::Io),
            }
        }
        Err(error) => return Err(io_error(error)),
    };
    state.verify_path().map_err(io_error)?;
    Ok(Some(Arc::new(WindowsDirectory {
        directory: Arc::new(directory),
        _admitted_state: state,
    })))
}
impl Directory for WindowsDirectory {
    fn immutable_metadata_reads(&self) -> bool {
        true
    }
    fn verify(&self) -> Result<(), StoreError> {
        self._admitted_state.verify_path().map_err(io_error)?;
        self.directory.verify_path().map_err(io_error)
    }
    fn external_recovery_usage(&self, policy: StorePolicy) -> Result<(u64, usize), StoreError> {
        crate::recovery_admission::legacy_recovery_usage(&self._admitted_state, policy)
    }
    fn entries(&self, limit: usize) -> Result<Vec<String>, StoreError> {
        self.verify()?;
        let mut names = Vec::new();
        for entry in std::fs::read_dir(self.directory.path()).map_err(io_error)? {
            if names.len() >= limit {
                return Err(StoreError::ScanLimit);
            }
            let name = entry
                .map_err(io_error)?
                .file_name()
                .into_string()
                .map_err(|_| StoreError::CorruptEvidence)?;
            if name.len() > 128 || !name.is_ascii() {
                return Err(StoreError::CorruptEvidence);
            }
            names.push(name);
        }
        self.verify()?;
        names.sort();
        Ok(names)
    }
    fn child(&self, name: &str, create: bool) -> Result<Arc<dyn Directory>, StoreError> {
        self.verify()?;
        let parent = PinnedDirectory::open(self.directory.path()).map_err(io_error)?;
        let directory = if create {
            PrivateDirectory::create_or_open_under(&parent, OsStr::new(name))
        } else {
            PrivateDirectory::open_under(&parent, OsStr::new(name))
        }
        .map_err(io_error)?;
        self.verify()?;
        Ok(Arc::new(Self {
            directory: Arc::new(directory),
            _admitted_state: Arc::clone(&self._admitted_state),
        }))
    }
    fn create(&self, name: &str) -> Result<(Box<dyn StageWrite>, Identity), StoreError> {
        self.verify()?;
        let (file, identity) = self
            .directory
            .create_new_file(OsStr::new(name))
            .map_err(io_error)?;
        Ok((Box::new(file), from_native(identity)))
    }
    fn open(&self, name: &str) -> Result<Box<dyn PinnedRead>, StoreError> {
        self.verify()?;
        let file = self
            .directory
            .open_owned_immutable_file(OsStr::new(name))
            .map_err(io_error)?;
        Ok(Box::new(file))
    }
    fn read_metadata_checked(
        &self,
        name: &str,
        metadata_limit: u64,
        remaining: &mut u64,
    ) -> Result<Vec<u8>, StoreError> {
        self._admitted_state.verify_path().map_err(io_error)?;
        let result =
            self.directory
                .read_metadata_checked(OsStr::new(name), metadata_limit, remaining);
        self._admitted_state.verify_path().map_err(io_error)?;
        result.map_err(|error| match error {
            PrivateMetadataReadError::InvalidLength => StoreError::CorruptEvidence,
            PrivateMetadataReadError::Budget => StoreError::ScanLimit,
            PrivateMetadataReadError::Io(error) => io_error(error),
        })
    }
    fn metadata_sizes(&self, names: &[String]) -> Result<Vec<u64>, StoreError> {
        self.verify()?;
        let mut sizes = Vec::with_capacity(names.len());
        for chunk in names.chunks(PrivateDirectory::MAX_METADATA_SIZE_BATCH) {
            let names: Vec<_> = chunk.iter().map(OsStr::new).collect();
            sizes.extend(
                self.directory
                    .metadata_sizes_checked(&names)
                    .map_err(io_error)?,
            );
        }
        self.verify()?;
        Ok(sizes)
    }
    fn open_quota_lock(&self) -> Result<Box<dyn PinnedRead>, StoreError> {
        self.verify()?;
        let file = self
            .directory
            .open_owned_immutable_file(OsStr::new(V2_QUOTA_LOCK))
            .map_err(quota_lock_open_error)?;
        Ok(Box::new(file))
    }
    fn publish(&self, stage: &str, final_name: &str, identity: Identity) -> Result<(), StoreError> {
        self.verify()?;
        self.directory
            .publish_staged_file(
                OsStr::new(stage),
                OsStr::new(final_name),
                PinnedFileIdentity {
                    volume_serial: u32::try_from(identity.volume)
                        .map_err(|_| StoreError::Invalid)?,
                    file_index: identity.file,
                },
            )
            .map_err(|_| StoreError::PublicationUncertain)?;
        self.verify()
    }
}
impl StageWrite for File {
    fn sync(&self) -> Result<(), StoreError> {
        self.sync_all().map_err(io_error)
    }
}
fn from_native(id: PinnedFileIdentity) -> Identity {
    Identity {
        volume: id.volume_serial as u64,
        file: id.file_index,
    }
}
impl PinnedRead for OwnedPrivateReader {
    fn identity(&self) -> Identity {
        from_native(OwnedPrivateReader::identity(self))
    }
    fn len(&self) -> Result<u64, StoreError> {
        self.metadata().map(|m| m.len()).map_err(io_error)
    }
    fn verify(&self) -> Result<(), StoreError> {
        OwnedPrivateReader::verify(self).map_err(io_error)
    }
    fn lock_exclusive(&mut self) -> Result<(), StoreError> {
        self.try_lock_exclusive().map_err(lock_error)
    }
}
// The concrete OwnedPrivateReader already provides checked Read and Seek.
// Do not extract or clone its raw file or alter share modes here.

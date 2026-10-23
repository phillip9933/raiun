//! Windows private media staging. Errors preserve created entries; no Drop deletion.
use super::{
    CloudError, Engine, ErrorKind, MAX_MEDIA_STAGED_FILE_BYTES, MAX_MEDIA_STAGED_TOTAL_BYTES,
    SourceSignature, hash_reader, io_error,
};
use raiun_control_windows::{
    OwnedPrivateReader, PinnedDirectory, PinnedFileIdentity, PrivateDirectory,
};
use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
static NEXT_STAGE: AtomicU64 = AtomicU64::new(0);
const MAX_ENTRIES: usize = 100_000;
fn refused() -> CloudError {
    CloudError::new(
        ErrorKind::Io,
        "Private media staging is unavailable; retained copies were preserved",
    )
}
fn directory(engine: &Engine) -> Result<Arc<PrivateDirectory>, CloudError> {
    let owner = engine.db()?;
    owner.media_directory().ok_or_else(refused)
}
fn bytes_in(directory: &Arc<PrivateDirectory>) -> Result<u64, CloudError> {
    directory.verify_path().map_err(io_error)?;
    let mut total = 0u64;
    for (index, entry) in fs::read_dir(directory.path())
        .map_err(io_error)?
        .enumerate()
    {
        if index >= MAX_ENTRIES {
            return Err(refused());
        }
        let name = entry.map_err(io_error)?.file_name();
        let reader = directory
            .open_owned_immutable_file(&name)
            .map_err(io_error)?;
        let size = reader.metadata().map_err(io_error)?.len();
        if size > MAX_MEDIA_STAGED_FILE_BYTES {
            return Err(refused());
        }
        total = total.checked_add(size).ok_or_else(refused)?;
        if total > MAX_MEDIA_STAGED_TOTAL_BYTES as u64 {
            return Err(refused());
        }
        reader.verify().map_err(io_error)?;
    }
    directory.verify_path().map_err(io_error)?;
    Ok(total)
}
/// Read-only recovery admission: validate both the account state root and its
/// protected staging child, without creating entries or repairing permissions.
pub(super) fn existing_directory(state_dir: &Path) -> io::Result<Option<Arc<PrivateDirectory>>> {
    let open = || -> io::Result<Arc<PrivateDirectory>> {
        let parent_path = state_dir
            .parent()
            .ok_or_else(|| io::Error::other("Missing private media parent"))?;
        let name = state_dir
            .file_name()
            .ok_or_else(|| io::Error::other("Missing private media root"))?;
        let parent = PinnedDirectory::open(parent_path)?;
        let root = PrivateDirectory::open_under(&parent, name)?;
        let root_pin = PinnedDirectory::open(root.path())?;
        let staging =
            PrivateDirectory::open_under(&root_pin, std::ffi::OsStr::new("media-staging"))?;
        root.verify_path()?;
        Ok(Arc::new(staging))
    };
    match open() {
        Ok(directory) => Ok(Some(directory)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) fn directory_bytes(engine: &Engine) -> Result<u64, CloudError> {
    let directory = directory(engine)?; // DB guard ends before enumeration/I/O.
    bytes_in(&directory)
}
pub(super) struct StageWriter {
    file: File,
    directory: Arc<PrivateDirectory>,
    pending: OsString,
    final_name: OsString,
    identity: PinnedFileIdentity,
    existing_bytes: u64,
}
impl StageWriter {
    pub(super) fn create(engine: &Engine) -> Result<Self, CloudError> {
        let directory = directory(engine)?;
        let existing_bytes = bytes_in(&directory)?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| refused())?
            .as_nanos();
        let mut sequence = NEXT_STAGE.load(Ordering::Relaxed);
        loop {
            let next = sequence.checked_add(1).ok_or_else(refused)?;
            match NEXT_STAGE.compare_exchange_weak(
                sequence,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => sequence = current,
            }
        }
        let stem = format!("media-{}-{nanos}-{sequence}", std::process::id());
        let pending = OsString::from(format!("{stem}.pending"));
        let final_name = OsString::from(format!("{stem}.stage"));
        let (file, identity) = directory.create_new_file(&pending).map_err(io_error)?;
        Ok(Self {
            file,
            directory,
            pending,
            final_name,
            identity,
            existing_bytes,
        })
    }
    pub(super) fn as_file(&self) -> &File {
        &self.file
    }
    pub(super) fn finish(self, expected: &SourceSignature) -> Result<StagedMedia, CloudError> {
        if expected.size > MAX_MEDIA_STAGED_FILE_BYTES
            || self.file.metadata().map_err(io_error)?.len() != expected.size
        {
            return Err(refused());
        }
        self.file.sync_all().map_err(io_error)?;
        self.directory.verify_path().map_err(io_error)?;
        let Self {
            file,
            directory,
            pending,
            final_name,
            identity,
            ..
        } = self;
        drop(file);
        // This operation validates expected identity, flushes and performs a
        // no-replace write-through rename. Its failure may be post-rename.
        let published = directory
            .publish_staged_file(&pending, &final_name, identity)
            .map_err(io_error)?;
        if published != identity {
            return Err(refused());
        }
        let reader = directory
            .open_owned_immutable_file(&final_name)
            .map_err(io_error)?;
        if reader.identity() != identity {
            return Err(refused());
        }
        let path = directory.path().join(&final_name);
        let mut staged = StagedMedia {
            reader,
            directory,
            name: final_name,
            identity,
            path,
        };
        if !staged.matches_signature(expected)? {
            return Err(refused());
        }
        Ok(staged)
    }
}
impl Write for StageWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.directory.verify_path()?;
        let current = self.file.metadata()?.len();
        let next = current
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("Media staging quota exceeded"))?;
        if next > MAX_MEDIA_STAGED_FILE_BYTES
            || self
                .existing_bytes
                .checked_add(next)
                .is_none_or(|total| total > MAX_MEDIA_STAGED_TOTAL_BYTES as u64)
        {
            return Err(io::Error::other("Media staging quota exceeded"));
        }
        self.file.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.directory.verify_path()?;
        self.file.flush()
    }
}
pub(super) struct StagedMedia {
    reader: OwnedPrivateReader,
    directory: Arc<PrivateDirectory>,
    name: OsString,
    identity: PinnedFileIdentity,
    path: PathBuf,
}
impl StagedMedia {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn matches_signature(
        &mut self,
        expected: &SourceSignature,
    ) -> Result<bool, CloudError> {
        self.reader.verify().map_err(io_error)?;
        let before = self.reader.metadata().map_err(io_error)?;
        if !before.is_file()
            || before.len() != expected.size
            || expected.size > MAX_MEDIA_STAGED_FILE_BYTES
        {
            return Ok(false);
        }
        self.reader.seek(SeekFrom::Start(0)).map_err(io_error)?;
        let hash = hash_reader(&mut self.reader, &|| false)?;
        let after = self.reader.metadata().map_err(io_error)?;
        self.reader.verify().map_err(io_error)?;
        Ok(after.len() == expected.size && hash == expected.sha256)
    }
    pub(super) fn cleanup(self) -> io::Result<()> {
        let Self {
            reader,
            directory,
            name,
            identity,
            ..
        } = self;
        reader.verify()?;
        drop(reader);
        directory.open_delete_candidate(&name, identity)?.delete()
    }
}

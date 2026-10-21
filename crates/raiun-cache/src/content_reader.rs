use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom};

/// A read-only content stream retaining its platform storage owner.
/// Cache APIs validate scope, version and content before returning this reader.
/// It deliberately exposes no writable file, raw handle or cloning API.
pub struct CacheContentReader {
    inner: Reader,
}

enum Reader {
    Portable(File),
    #[cfg(windows)]
    Windows(raiun_control_windows::OwnedPrivateReader),
}

impl CacheContentReader {
    pub(crate) fn portable(file: File) -> Self {
        Self {
            inner: Reader::Portable(file),
        }
    }

    pub fn metadata(&self) -> io::Result<Metadata> {
        match &self.inner {
            Reader::Portable(file) => file.metadata(),
            #[cfg(windows)]
            Reader::Windows(file) => file.metadata(),
        }
    }
}

#[cfg(windows)]
impl From<raiun_control_windows::OwnedPrivateReader> for CacheContentReader {
    fn from(reader: raiun_control_windows::OwnedPrivateReader) -> Self {
        Self {
            inner: Reader::Windows(reader),
        }
    }
}

impl std::fmt::Debug for CacheContentReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CacheContentReader")
            .finish_non_exhaustive()
    }
}

impl Read for CacheContentReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            Reader::Portable(file) => file.read(buffer),
            #[cfg(windows)]
            Reader::Windows(file) => file.read(buffer),
        }
    }
}

impl Seek for CacheContentReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        match &mut self.inner {
            Reader::Portable(file) => file.seek(position),
            #[cfg(windows)]
            Reader::Windows(file) => file.seek(position),
        }
    }
}

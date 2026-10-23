//! Safe handle-pinned primitives for the encrypted edit journal.
//!
//! Journal callers use a path only to open a directory with
//! `FILE_FLAG_OPEN_REPARSE_POINT`. The handle denies delete sharing and pins
//! that directory entry for its lifetime. Child file opens also open the
//! reparse point itself and reject reparse/directory attributes before any
//! bytes are read. Unsafe Win32 calls stay in this adapter crate.

use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::{
        ffi::OsStrExt,
        io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, RawHandle},
    },
    path::{Path, PathBuf},
    sync::Arc,
};

use windows_sys::Win32::{
    Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree},
    Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
        GetSecurityInfo, SE_FILE_OBJECT,
    },
    Security::{
        ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION, AclSizeInformation, CONTAINER_INHERIT_ACE,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetLengthSid,
        GetSecurityDescriptorControl, GetSecurityDescriptorDacl, INHERITED_ACE, IsValidSid,
        OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, GetFileInformationByHandle, GetVolumeInformationByHandleW, OPEN_EXISTING,
    },
};

const SDDL_REVISION_1: u32 = 1;
const MAX_PRIVATE_ACES: u32 = 1;
const FILE_ALL_ACCESS_MASK: u32 = 0x001F_01FF;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

const DELETE_ACCESS: u32 = 0x0001_0000;
const FILE_DISPOSITION_INFO_CLASS: u32 = 4;
const FILE_RENAME_INFO_CLASS: u32 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinnedFileIdentity {
    pub volume_serial: u32,
    pub file_index: u64,
}

/// A directory opened without following its final reparse point and held
/// without delete sharing, preventing rename/replacement while in use.
pub struct PinnedDirectory {
    path: PathBuf,
    // Holding every path component without delete sharing prevents an
    // ancestor swap from redirecting later pathname-based child operations.
    _handles: Vec<File>,
    identity: PinnedFileIdentity,
}

impl PinnedDirectory {
    pub fn open(path: &Path) -> io::Result<Self> {
        let handles = open_directory_chain(path)?;
        let identity = identity(handles.last().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Journal directory path is empty",
            )
        })?)?;
        Ok(Self {
            path: path.to_owned(),
            _handles: handles,
            identity,
        })
    }

    /// Create the named child if absent, then open and pin the actual entry.
    /// Reparse points and non-directories are rejected even if another
    /// process wins the create/open race.
    pub fn create_child_directory(&self, name: &OsStr) -> io::Result<Self> {
        self.verify_path()?;
        validate_component(name)?;
        let path = self.path.join(name);
        let wide = wide_extended_path(&path)?;
        let created = unsafe { CreateDirectoryW(wide.as_ptr(), std::ptr::null()) };
        if created == 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        let child = Self::open(&path)?;
        self.verify_path()?;
        Ok(child)
    }

    /// Verify the pathname still resolves to this held directory identity.
    pub fn verify_path(&self) -> io::Result<()> {
        let current = open_directory_handle(&self.path)?;
        if identity(&current)? != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Pinned directory identity changed",
            ));
        }
        Ok(())
    }

    pub fn identity(&self) -> PinnedFileIdentity {
        self.identity
    }

    /// Duplicate this already-open directory for capability-based traversal.
    /// Keep this owner alive to retain every ancestor pin while using the file.
    pub fn try_clone_directory_file(&self) -> io::Result<File> {
        self.verify_path()?;
        let file = self
            ._handles
            .last()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "Pinned directory is empty")
            })?
            .try_clone()?;
        if identity(&file)? != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Pinned directory identity changed",
            ));
        }
        self.verify_path()?;
        Ok(file)
    }

    /// Create an immutable child file without following an existing reparse
    /// point. The returned handle remains pinned against rename/delete.
    pub fn create_new_file(&self, name: &OsStr) -> io::Result<(File, PinnedFileIdentity)> {
        self.verify_path()?;
        validate_component(name)?;
        let file = open_file_handle(
            &self.path.join(name),
            GENERIC_READ | GENERIC_WRITE,
            CREATE_NEW,
        )?;
        let id = identity(&file)?;
        self.verify_path()?;
        Ok((file, id))
    }

    /// Open one regular child without following its final reparse point.
    pub fn open_regular_file(&self, name: &OsStr) -> io::Result<(File, PinnedFileIdentity)> {
        trace_publish_stage("verify_parent_before_child_open", self.verify_path())?;
        validate_component(name)?;
        let path = self.path.join(name);
        trace_path_shape("child_open", &path);
        let file = trace_publish_stage(
            "open_child_handle",
            open_file_handle(&path, GENERIC_READ, OPEN_EXISTING),
        )?;
        let id = trace_publish_stage("child_handle_identity", identity(&file))?;
        trace_publish_stage("verify_parent_after_child_open", self.verify_path())?;
        Ok((file, id))
    }

    /// Hold one ordinary source file immutable while a path-based backend reads
    /// it. Existing writers, reparse points, replacement and new writers are
    /// refused; this does not require a private application-state ACL.
    pub fn open_immutable_regular_file(
        &self,
        name: &OsStr,
    ) -> io::Result<(File, PinnedFileIdentity)> {
        self.verify_path()?;
        validate_component(name)?;
        let file = open_file_handle_with_share(
            &self.path.join(name),
            GENERIC_READ,
            OPEN_EXISTING,
            FILE_SHARE_READ,
        )?;
        let id = identity(&file)?;
        self.verify_path()?;
        Ok((file, id))
    }

    /// Atomically rename a pinned staging file to an absent child. The rename
    /// is handle-based and does not replace an existing destination; this does
    /// not depend on filesystem hard-link support. The returned identity is
    /// checked by reopening the published entry.
    pub fn publish_staged_file(
        &self,
        source: &OsStr,
        destination: &OsStr,
        expected: PinnedFileIdentity,
    ) -> io::Result<PinnedFileIdentity> {
        self.publish_staged_file_policy(source, destination, expected, false)
    }

    fn publish_staged_file_policy(
        &self,
        source: &OsStr,
        destination: &OsStr,
        expected: PinnedFileIdentity,
        private: bool,
    ) -> io::Result<PinnedFileIdentity> {
        self.publish_staged_file_with_final_flush(
            source,
            destination,
            expected,
            private,
            File::sync_all,
        )
    }

    fn publish_staged_file_with_final_flush(
        &self,
        source: &OsStr,
        destination: &OsStr,
        expected: PinnedFileIdentity,
        private: bool,
        final_flush: impl FnOnce(&File) -> io::Result<()>,
    ) -> io::Result<PinnedFileIdentity> {
        self.verify_path()?;
        validate_component(source)?;
        validate_component(destination)?;
        let source_path = self.path.join(source);
        trace_path_shape("stage_open", &source_path);
        let staged_file = trace_publish_stage(
            "reopen_stage_with_delete",
            open_file_handle_with_share_and_flags(
                &source_path,
                GENERIC_READ | DELETE_ACCESS | if private { GENERIC_WRITE } else { 0 },
                OPEN_EXISTING,
                if private {
                    FILE_SHARE_READ
                } else {
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
                },
                if private { FILE_FLAG_WRITE_THROUGH } else { 0 },
            ),
        )?;
        if trace_publish_stage("stage_handle_identity", identity(&staged_file))? != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Staged file identity changed",
            ));
        }

        if private {
            validate_private_handle(&staged_file, PrivateEntryKind::File)?;
            require_ntfs(&staged_file)?;
            // Flush bytes on the exact identity-checked handle before making
            // the name visible. WRITE_THROUGH also applies to its rename.
            staged_file.sync_all()?;
        }
        let destination_path = wide_extended_path(&self.path.join(destination))?;
        trace_path_shape("rename_destination", &self.path.join(destination));
        let filename_len = destination_path
            .len()
            .checked_sub(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Path is empty"))?
            .checked_mul(std::mem::size_of::<u16>())
            .and_then(|bytes| u32::try_from(bytes).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Path is too long"))?;
        let header_len = std::mem::offset_of!(FileRenameInfo, file_name);
        let buffer_len = header_len
            .checked_add(filename_len as usize)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Path is too long"))?;
        // `SetFileInformationByHandle` validates a buffer at least as large
        // as sizeof(FILE_RENAME_INFO) plus the variable name bytes. The
        // flexible one-WCHAR tail and structure padding make that larger than
        // offsetof(FileName) + FileNameLength on Windows.
        let buffer_len = buffer_len.max(
            std::mem::size_of::<FileRenameInfo>()
                .checked_add(filename_len as usize)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Path is too long"))?,
        );
        let word_len = buffer_len.div_ceil(std::mem::size_of::<usize>());
        let mut buffer = vec![0usize; word_len];
        let info = buffer.as_mut_ptr().cast::<FileRenameInfo>();
        unsafe {
            (*info).replace_if_exists = 0;
            (*info).root_directory = std::ptr::null_mut();
            (*info).file_name_length = filename_len;
            std::ptr::copy_nonoverlapping(
                destination_path.as_ptr(),
                (*info).file_name.as_mut_ptr(),
                filename_len as usize / std::mem::size_of::<u16>(),
            );
        }
        let renamed = unsafe {
            SetFileInformationByHandle(
                staged_file.as_raw_handle() as HANDLE,
                FILE_RENAME_INFO_CLASS,
                buffer.as_ptr().cast(),
                u32::try_from(buffer_len)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Path is too long"))?,
            )
        };
        trace_publish_stage(
            "rename_by_handle",
            if renamed == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            },
        )?;

        if private {
            // An error here is an uncertain publication: retain both names'
            // possible recovery state; the caller must not delete on error.
            final_flush(&staged_file)?;
        }

        // Keep the rename handle alive through the destination checks. In
        // private mode it denies writes and deletes, including the interval
        // between rename and reopening the destination. The verification
        // handle must share delete access already held by the rename handle.
        let published = trace_publish_stage(
            "reopen_published_entry",
            open_file_handle_with_share(
                &self.path.join(destination),
                GENERIC_READ,
                OPEN_EXISTING,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ),
        )?;
        let actual = identity(&published)?;
        trace_publish_stage("verify_parent_after_rename", self.verify_path())?;
        if private {
            validate_private_handle(&published, PrivateEntryKind::File)?;
        }
        if actual != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Published file identity changed",
            ));
        }
        Ok(actual)
    }

    /// Delete only the exact file identity previously observed. Disposition
    /// is applied to the opened handle, never to a re-resolved pathname.
    pub fn remove_file_if_identity(
        &self,
        name: &OsStr,
        expected: PinnedFileIdentity,
    ) -> io::Result<bool> {
        self.verify_path()?;
        validate_component(name)?;
        let file = open_file_handle(
            &self.path.join(name),
            DELETE_ACCESS | GENERIC_READ,
            OPEN_EXISTING,
        )?;
        if identity(&file)? != expected {
            return Ok(false);
        }
        let disposition = FileDispositionInfo { delete_file: 1 };
        let ok = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle() as HANDLE,
                FILE_DISPOSITION_INFO_CLASS,
                (&disposition as *const FileDispositionInfo).cast(),
                std::mem::size_of::<FileDispositionInfo>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        self.verify_path()?;
        Ok(true)
    }
}

/// A handle-pinned directory whose owner and protected DACL have been
/// validated against the current Windows user. This API is deliberately
/// separate from the journal directory primitives: callers must opt in to
/// the stricter private-state policy explicitly.
pub struct PrivateDirectory {
    directory: PinnedDirectory,
}

/// Access requested for an existing pinned private file. Both modes omit
/// `FILE_SHARE_DELETE`, so the opened entry cannot be renamed or replaced
/// while the returned handle is alive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinnedPrivateFileAccess {
    ReadOnly,
    /// Deny write and delete sharing while verified immutable content is read.
    ImmutableRead,
    ReadWrite,
}

impl PrivateDirectory {
    /// Publish a private staged file without replacing an existing child.
    /// Close the staging writer first. The same rename handle is checked for
    /// private ownership/ACL and expected identity before publication.
    /// Requires NTFS; flushes the exact file before and after a write-through
    /// rename. Device durability still depends on honoring flush requests.
    /// An error may occur after rename: preserve recovery data on failure.
    pub fn publish_staged_file(
        &self,
        source: &OsStr,
        destination: &OsStr,
        expected: PinnedFileIdentity,
    ) -> io::Result<PinnedFileIdentity> {
        self.verify_path()?;
        self.directory
            .publish_staged_file_policy(source, destination, expected, true)
    }

    /// Create a current-user-only child directory, or validate an existing
    /// child without changing its owner or ACL. The child DACL is protected
    /// from inheritance and contains one inheritable full-control ACE for the
    /// current user only.
    pub fn create_or_open_under(parent: &PinnedDirectory, name: &OsStr) -> io::Result<Self> {
        validate_local_drive_path(&parent.path)?;
        parent.verify_path()?;
        validate_component(name)?;
        let path = parent.path.join(name);
        let descriptor = private_security_descriptor(true)?;
        let attributes = security_attributes(&descriptor);
        let wide = wide_extended_path(&path)?;
        let created = unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) };
        if created == 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }

        let directory = PinnedDirectory::open(&path)?;
        validate_private_handle(&directory_handle(&directory)?, PrivateEntryKind::Directory)?;
        parent.verify_path()?;
        Ok(Self { directory })
    }

    /// Open and validate an existing current-user-only child without repairing
    /// its ACL or following any reparse point in the child path.
    pub fn open_under(parent: &PinnedDirectory, name: &OsStr) -> io::Result<Self> {
        validate_local_drive_path(&parent.path)?;
        parent.verify_path()?;
        validate_component(name)?;
        let directory = PinnedDirectory::open(&parent.path.join(name))?;
        validate_private_handle(&directory_handle(&directory)?, PrivateEntryKind::Directory)?;
        parent.verify_path()?;
        Ok(Self { directory })
    }

    pub fn path(&self) -> &Path {
        &self.directory.path
    }

    pub fn identity(&self) -> PinnedFileIdentity {
        self.directory.identity()
    }

    pub fn verify_path(&self) -> io::Result<()> {
        validate_local_drive_path(&self.directory.path)?;
        self.directory.verify_path()?;
        validate_private_handle(
            &directory_handle(&self.directory)?,
            PrivateEntryKind::Directory,
        )
    }

    /// Create a new protected regular child file. Existing files are never
    /// replaced. File and directory handles reject reparse points, and the
    /// opened file must have one link and the exact current-user-only DACL.
    pub fn create_new_file(&self, name: &OsStr) -> io::Result<(File, PinnedFileIdentity)> {
        self.verify_path()?;
        validate_component(name)?;
        let path = self.directory.path.join(name);
        let descriptor = private_security_descriptor(false)?;
        let attributes = security_attributes(&descriptor);
        let wide = wide_extended_path(&path)?;
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &attributes,
                CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        let file = checked_handle(raw, false)?;
        let identity = identity(&file)?;
        if let Err(error) = validate_private_handle(&file, PrivateEntryKind::File) {
            let _ = self.directory.remove_file_if_identity(name, identity);
            return Err(error);
        }
        self.verify_path()?;
        Ok((file, identity))
    }

    /// Open and validate one existing regular child with either the exact
    /// protected file policy or the exact current-user-only inherited policy
    /// produced by ordinary sidecar creation. The no-delete share mode pins
    /// the entry while it is being read.
    pub fn open_regular_file(&self, name: &OsStr) -> io::Result<(File, PinnedFileIdentity)> {
        self.verify_path()?;
        validate_component(name)?;
        let file = open_file_handle(&self.directory.path.join(name), GENERIC_READ, OPEN_EXISTING)?;
        validate_private_handle(&file, PrivateEntryKind::File)?;
        let identity = identity(&file)?;
        self.verify_path()?;
        Ok((file, identity))
    }

    /// Create a new current-user-only child and retain a no-delete-sharing
    /// handle to the exact file. Existing names are never followed or
    /// replaced. The file is opened read/write to support a caller's atomic
    /// create/open handoff.
    pub fn create_new_pinned_file(&self, name: &OsStr) -> io::Result<PinnedPrivateFile<'_>> {
        self.verify_path()?;
        validate_component(name)?;
        let path = self.directory.path.join(name);
        let descriptor = private_security_descriptor(false)?;
        let attributes = security_attributes(&descriptor);
        let wide = wide_extended_path(&path)?;
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &attributes,
                CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        let file = checked_handle(raw, false)?;
        let identity = identity(&file)?;
        if let Err(error) = validate_private_handle(&file, PrivateEntryKind::File) {
            drop(file);
            let _ = self.directory.remove_file_if_identity(name, identity);
            return Err(error);
        }
        self.verify_path()?;
        Ok(PinnedPrivateFile {
            directory: self,
            file,
            identity,
            delete_authorized: false,
        })
    }

    /// Open one validated private child and retain its no-delete-sharing
    /// handle. This pins the file entry against replacement for the handle's
    /// lifetime. It does not make SQLite's own sidecar lifecycle safe; a VFS
    /// must explicitly mediate every open and delete operation.
    pub fn open_pinned_file(
        &self,
        name: &OsStr,
        access: PinnedPrivateFileAccess,
    ) -> io::Result<PinnedPrivateFile<'_>> {
        self.verify_path()?;
        validate_component(name)?;
        let desired_access = match access {
            PinnedPrivateFileAccess::ReadOnly | PinnedPrivateFileAccess::ImmutableRead => {
                GENERIC_READ
            }
            PinnedPrivateFileAccess::ReadWrite => GENERIC_READ | GENERIC_WRITE,
        };
        let share = match access {
            PinnedPrivateFileAccess::ImmutableRead => FILE_SHARE_READ,
            _ => FILE_SHARE_READ | FILE_SHARE_WRITE,
        };
        let file = open_file_handle_with_share(
            &self.directory.path.join(name),
            desired_access,
            OPEN_EXISTING,
            share,
        )?;
        validate_private_handle(&file, PrivateEntryKind::File)?;
        let identity = identity(&file)?;
        self.verify_path()?;
        Ok(PinnedPrivateFile {
            directory: self,
            file,
            identity,
            delete_authorized: false,
        })
    }

    /// Open an immutable reader that owns its validated directory lifetime.
    /// The exact file denies both write and delete sharing. No borrowed
    /// self-reference or raw-handle transfer escapes this adapter.
    pub fn open_owned_immutable_file(
        self: &Arc<Self>,
        name: &OsStr,
    ) -> io::Result<OwnedPrivateReader> {
        let pin = self.open_pinned_file(name, PinnedPrivateFileAccess::ImmutableRead)?;
        Ok(OwnedPrivateReader {
            file: pin.file,
            directory: Arc::clone(self),
            identity: pin.identity,
        })
    }

    /// Open a validated file for deletion by its exact handle. The expected
    /// identity prevents deleting a replacement at the same name. The caller
    /// must first close any read/write pin: Windows sharing rules correctly
    /// reject DELETE access while such a no-delete-sharing handle is open.
    pub fn open_delete_candidate(
        &self,
        name: &OsStr,
        expected: PinnedFileIdentity,
    ) -> io::Result<PinnedPrivateFile<'_>> {
        self.verify_path()?;
        validate_component(name)?;
        let file = open_file_handle(
            &self.directory.path.join(name),
            DELETE_ACCESS | GENERIC_READ,
            OPEN_EXISTING,
        )?;
        validate_private_handle(&file, PrivateEntryKind::File)?;
        let identity = identity(&file)?;
        if identity != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Private file identity changed before delete",
            ));
        }
        self.verify_path()?;
        Ok(PinnedPrivateFile {
            directory: self,
            file,
            identity,
            delete_authorized: true,
        })
    }
}

/// A private file whose exact handle remains open without delete sharing.
/// The borrow keeps its validated parent directory and ancestor handles alive.
pub struct PinnedPrivateFile<'directory> {
    directory: &'directory PrivateDirectory,
    file: File,
    identity: PinnedFileIdentity,
    delete_authorized: bool,
}

impl PinnedPrivateFile<'_> {
    /// Lock the exact validated file; closing this pin releases the OS lock.
    /// Persistent generation-lock files must never be deleted/recreated.
    pub fn try_lock_exclusive(&mut self) -> io::Result<()> {
        self.verify()?;
        fs2::FileExt::try_lock_exclusive(&self.file)
    }

    pub fn unlock(&mut self) -> io::Result<()> {
        fs2::FileExt::unlock(&self.file)
    }

    pub fn identity(&self) -> PinnedFileIdentity {
        self.identity
    }

    /// Borrow the operating-system handle only for the lifetime of this pin.
    /// This does not transfer ownership or grant delete access.
    pub fn borrowed_handle(&self) -> io::Result<BorrowedHandle<'_>> {
        self.verify()?;
        Ok(self.file.as_handle())
    }

    /// Revalidate the held file and its private parent path.
    pub fn verify(&self) -> io::Result<()> {
        self.directory.verify_path()?;
        if identity(&self.file)? != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Pinned private file identity changed",
            ));
        }
        validate_private_handle(&self.file, PrivateEntryKind::File)
    }

    /// Delete the exact currently pinned entry. Only handles opened through
    /// `open_delete_candidate` carry DELETE access; disposition is applied to
    /// that same handle and never re-resolves the path.
    pub fn delete(self) -> io::Result<()> {
        if !self.delete_authorized {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Pinned private file was not opened for deletion",
            ));
        }
        self.verify()?;
        let disposition = FileDispositionInfo { delete_file: 1 };
        let ok = unsafe {
            SetFileInformationByHandle(
                self.file.as_raw_handle() as HANDLE,
                FILE_DISPOSITION_INFO_CLASS,
                (&disposition as *const FileDispositionInfo).cast(),
                std::mem::size_of::<FileDispositionInfo>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        self.directory.verify_path()
    }
}

impl Read for PinnedPrivateFile<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.verify()?;
        self.file.read(buffer)
    }
}

impl Write for PinnedPrivateFile<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.verify()?;
        self.file.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.verify()?;
        self.file.flush()
    }
}

impl Seek for PinnedPrivateFile<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.verify()?;
        self.file.seek(position)
    }
}

/// An immutable private reader owning both its file and directory pins.
/// The file field drops first, before the directory's ancestor handle chain.
/// There is deliberately no raw File extraction, cloning, Write or delete API.
pub struct OwnedPrivateReader {
    file: File,
    directory: Arc<PrivateDirectory>,
    identity: PinnedFileIdentity,
}

impl OwnedPrivateReader {
    pub fn identity(&self) -> PinnedFileIdentity {
        self.identity
    }

    pub fn verify(&self) -> io::Result<()> {
        self.directory.verify_path()?;
        if identity(&self.file)? != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Owned private reader identity changed",
            ));
        }
        validate_private_handle(&self.file, PrivateEntryKind::File)
    }

    pub fn metadata(&self) -> io::Result<std::fs::Metadata> {
        self.verify()?;
        self.file.metadata()
    }
}

impl Read for OwnedPrivateReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.verify()?;
        self.file.read(buffer)
    }
}

impl Seek for OwnedPrivateReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.verify()?;
        self.file.seek(position)
    }
}

#[derive(Clone, Copy)]
enum PrivateEntryKind {
    Directory,
    File,
}

#[derive(Clone, Copy)]
struct PrivateAclFacts {
    owner_matches: bool,
    dacl_present: bool,
    dacl_non_null: bool,
    dacl_defaulted: bool,
    dacl_protected: bool,
    ace_count: u32,
    ace_type: u8,
    ace_flags: u8,
    access_mask: u32,
    ace_sid_matches: bool,
}

fn private_acl_policy_valid(kind: PrivateEntryKind, facts: PrivateAclFacts) -> bool {
    if !facts.owner_matches
        || !facts.dacl_present
        || !facts.dacl_non_null
        || facts.dacl_defaulted
        || facts.ace_count != MAX_PRIVATE_ACES
        || facts.ace_type != ACCESS_ALLOWED_ACE_TYPE
        || facts.access_mask != FILE_ALL_ACCESS_MASK
        || !facts.ace_sid_matches
    {
        return false;
    }
    match kind {
        PrivateEntryKind::Directory => {
            facts.dacl_protected
                && facts.ace_flags == (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
        }
        PrivateEntryKind::File => {
            (facts.dacl_protected && facts.ace_flags == 0)
                || (!facts.dacl_protected
                    && (facts.ace_flags == INHERITED_ACE as u8
                        || facts.ace_flags == (OBJECT_INHERIT_ACE | INHERITED_ACE) as u8
                        || facts.ace_flags
                            == (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERITED_ACE) as u8))
        }
    }
}

fn directory_handle(directory: &PinnedDirectory) -> io::Result<File> {
    open_directory_handle(&directory.path)
}

fn security_attributes(descriptor: &SecurityDescriptor) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    }
}

struct SecurityDescriptor(*mut std::ffi::c_void);

impl SecurityDescriptor {
    fn new(sddl: &str) -> io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = std::ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || descriptor.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

fn private_security_descriptor(directory: bool) -> io::Result<SecurityDescriptor> {
    let sid = super::win32::current_user_sid_for_storage()?;
    let inheritance = if directory { "OICI" } else { "" };
    // Set OWNER explicitly to the token user. Relying on Windows' default
    // owner group can produce an Administrators owner for service/elevated
    // tokens even though the private DACL is scoped to the token SID.
    SecurityDescriptor::new(&format!("O:{sid}D:P(A;{inheritance};FA;;;{sid})"))
}

fn validate_private_handle(file: &File, kind: PrivateEntryKind) -> io::Result<()> {
    let info = file_info(file)?;
    let is_directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    let is_reparse = info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    if is_reparse
        || is_directory != matches!(kind, PrivateEntryKind::Directory)
        || (matches!(kind, PrivateEntryKind::File) && info.nNumberOfLinks != 1)
    {
        return Err(private_policy_error());
    }

    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let descriptor = SecurityDescriptor(descriptor);
    if owner.is_null() || dacl.is_null() {
        return Err(private_policy_error());
    }

    let current_sid = current_user_sid_ptr()?;
    let owner_matches = unsafe { EqualSid(owner, current_sid.0) } != 0;

    let mut dacl_present = 0;
    let mut actual_dacl = std::ptr::null_mut();
    let mut dacl_defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor.0,
            &mut dacl_present,
            &mut actual_dacl,
            &mut dacl_defaulted,
        )
    } == 0
        || dacl_present == 0
        || actual_dacl.is_null()
        || dacl_defaulted != 0
    {
        return Err(private_policy_error());
    }

    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
        return Err(private_policy_error());
    }
    let dacl_protected = control & SE_DACL_PROTECTED != 0;

    let mut acl_size = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            actual_dacl,
            (&mut acl_size as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
        || acl_size.AceCount != MAX_PRIVATE_ACES
    {
        return Err(private_policy_error());
    }

    let mut ace = std::ptr::null_mut();
    if unsafe { GetAce(actual_dacl, 0, &mut ace) } == 0 || ace.is_null() {
        return Err(private_policy_error());
    }
    let header = unsafe { &*ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
    let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    if usize::from(header.AceSize) < sid_offset + 8 {
        return Err(private_policy_error());
    }
    let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    let sid_in_ace = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
    let sid_length = unsafe { GetLengthSid(sid_in_ace) } as usize;
    if sid_length > usize::from(header.AceSize).saturating_sub(sid_offset)
        || unsafe { IsValidSid(sid_in_ace) } == 0
    {
        return Err(private_policy_error());
    }
    let facts = PrivateAclFacts {
        owner_matches,
        dacl_present: dacl_present != 0,
        dacl_non_null: !actual_dacl.is_null(),
        dacl_defaulted: dacl_defaulted != 0,
        dacl_protected,
        ace_count: acl_size.AceCount,
        ace_type: header.AceType,
        ace_flags: header.AceFlags,
        access_mask: allowed.Mask,
        ace_sid_matches: unsafe { EqualSid(sid_in_ace, current_sid.0) } != 0,
    };
    if !private_acl_policy_valid(kind, facts) {
        return Err(private_policy_error());
    }
    Ok(())
}

struct Sid(*mut std::ffi::c_void);

impl Drop for Sid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

fn current_user_sid_ptr() -> io::Result<Sid> {
    let sid = super::win32::current_user_sid_for_storage()?;
    let wide: Vec<u16> = sid.encode_utf16().chain(Some(0)).collect();
    let mut pointer = std::ptr::null_mut();
    let ok = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut pointer) };
    if ok == 0 || pointer.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(Sid(pointer))
}

fn private_policy_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Private directory or file security policy is not satisfied",
    )
}

fn validate_local_drive_path(path: &Path) -> io::Result<()> {
    use std::path::Component;

    let mut units = path.as_os_str().encode_wide();
    let drive = units.next();
    let colon = units.next();
    let separator = units.next();
    let has_extra_colon = units.any(|unit| unit == b':' as u16);
    if !drive.is_some_and(|unit| {
        (u16::from(b'A')..=u16::from(b'Z')).contains(&unit)
            || (u16::from(b'a')..=u16::from(b'z')).contains(&unit)
    }) || colon != Some(b':' as u16)
        || !matches!(separator, Some(0x5c | 0x2f))
        || has_extra_colon
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Private state must use a local drive-absolute path",
        ));
    }
    Ok(())
}

#[repr(C)]
struct FileDispositionInfo {
    delete_file: u8,
}

#[repr(C)]
struct FileRenameInfo {
    replace_if_exists: u8,
    root_directory: HANDLE,
    file_name_length: u32,
    file_name: [u16; 1],
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetFileInformationByHandle(
        file: HANDLE,
        class: u32,
        info: *const std::ffi::c_void,
        size: u32,
    ) -> i32;
}

fn open_directory_handle(path: &Path) -> io::Result<File> {
    let wide = wide_extended_path(path)?;
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    checked_handle(raw, true)
}

fn open_directory_chain(path: &Path) -> io::Result<Vec<File>> {
    use std::path::Component;

    let mut current = PathBuf::new();
    let mut handles = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => {
                current.push(component.as_os_str());
                handles.push(open_directory_handle(&current)?);
            }
            Component::Normal(name) => {
                current.push(name);
                handles.push(open_directory_handle(&current)?);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Journal directory path must not contain parent components",
                ));
            }
        }
    }
    if handles.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Journal directory path is not rooted",
        ));
    }
    Ok(handles)
}

fn open_file_handle(path: &Path, access: u32, disposition: u32) -> io::Result<File> {
    open_file_handle_with_share(
        path,
        access,
        disposition,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
}

fn open_file_handle_with_share(
    path: &Path,
    access: u32,
    disposition: u32,
    share_mode: u32,
) -> io::Result<File> {
    open_file_handle_with_share_and_flags(path, access, disposition, share_mode, 0)
}

fn open_file_handle_with_share_and_flags(
    path: &Path,
    access: u32,
    disposition: u32,
    share_mode: u32,
    flags: u32,
) -> io::Result<File> {
    let wide = wide_extended_path(path)?;
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            share_mode,
            std::ptr::null(),
            disposition,
            FILE_FLAG_OPEN_REPARSE_POINT | flags,
            std::ptr::null_mut(),
        )
    };
    checked_handle(raw, false)
}

// Query the pinned file's volume, never a path that could resolve elsewhere.
fn require_ntfs(file: &File) -> io::Result<()> {
    let mut filesystem = [0u16; 32];
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle() as HANDLE,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let end = filesystem
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(filesystem.len());
    if !String::from_utf16_lossy(&filesystem[..end]).eq_ignore_ascii_case("NTFS") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Private durable publication requires NTFS",
        ));
    }
    Ok(())
}

fn checked_handle(raw: HANDLE, directory: bool) -> io::Result<File> {
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(raw as RawHandle) };
    let info = file_info(&file)?;
    let is_directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    let is_reparse = info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    if is_reparse || is_directory != directory {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Journal entry is not a plain expected file type",
        ));
    }
    Ok(file)
}

fn identity(file: &File) -> io::Result<PinnedFileIdentity> {
    let info = file_info(file)?;
    Ok(PinnedFileIdentity {
        volume_serial: info.dwVolumeSerialNumber,
        file_index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    })
}

fn file_info(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

fn validate_component(name: &OsStr) -> io::Result<()> {
    let value = name.to_string_lossy();
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains(['\\', '/', ':'])
        || value.contains('\0')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Journal child name is invalid",
        ));
    }
    Ok(())
}

pub(crate) fn wide_extended_path(path: &Path) -> io::Result<Vec<u16>> {
    let encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    if encoded.starts_with(&"\\\\?\\".encode_utf16().collect::<Vec<_>>()) {
        return Ok(encoded.into_iter().chain(Some(0)).collect());
    }
    let mut result: Vec<u16> = if encoded.starts_with(&[b'\\' as u16, b'\\' as u16]) {
        let mut prefixed: Vec<u16> = "\\\\?\\UNC\\".encode_utf16().collect();
        prefixed.extend_from_slice(&encoded[2..]);
        prefixed
    } else if encoded.len() >= 3
        && encoded[1] == b':' as u16
        && (encoded[2] == b'\\' as u16 || encoded[2] == b'/' as u16)
    {
        let mut prefixed: Vec<u16> = "\\\\?\\".encode_utf16().collect();
        prefixed.extend_from_slice(&encoded);
        prefixed
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Rename destination must be absolute",
        ));
    };
    result.push(0);
    Ok(result)
}

fn trace_publish_stage<T>(stage: &'static str, result: io::Result<T>) -> io::Result<T> {
    #[cfg(any(test, feature = "synthetic-agent-integration"))]
    if let Err(error) = &result {
        eprintln!(
            "pinned_publish_error_stage={stage} kind={:?} code={:?}",
            error.kind(),
            error.raw_os_error()
        );
    }
    #[cfg(not(any(test, feature = "synthetic-agent-integration")))]
    let _ = stage;
    result
}

fn trace_path_shape(stage: &'static str, path: &Path) {
    #[cfg(any(test, feature = "synthetic-agent-integration"))]
    {
        let encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
        let prefix = if encoded.starts_with(&"\\\\?\\".encode_utf16().collect::<Vec<_>>()) {
            "extended"
        } else if encoded.starts_with(&[b'\\' as u16, b'\\' as u16]) {
            "unc"
        } else if encoded.len() >= 3
            && encoded[1] == b':' as u16
            && (encoded[2] == b'\\' as u16 || encoded[2] == b'/' as u16)
        {
            "drive"
        } else {
            "other"
        };
        eprintln!(
            "pinned_path_shape={stage} utf16_len={} prefix={prefix}",
            encoded.len()
        );
    }
    #[cfg(not(any(test, feature = "synthetic-agent-integration")))]
    let _ = (stage, path);
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        os::windows::ffi::OsStrExt,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };
    use windows_sys::Win32::{
        Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo},
        Security::{
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
            GetSecurityDescriptorLength, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
            UNPROTECTED_DACL_SECURITY_INFORMATION,
        },
        Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, WRITE_DAC, WRITE_OWNER,
        },
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn valid_private_acl_facts(kind: PrivateEntryKind) -> PrivateAclFacts {
        let (dacl_protected, ace_flags) = match kind {
            PrivateEntryKind::Directory => {
                (true, (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8)
            }
            PrivateEntryKind::File => (true, 0),
        };
        PrivateAclFacts {
            owner_matches: true,
            dacl_present: true,
            dacl_non_null: true,
            dacl_defaulted: false,
            dacl_protected,
            ace_count: MAX_PRIVATE_ACES,
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            ace_flags,
            access_mask: FILE_ALL_ACCESS_MASK,
            ace_sid_matches: true,
        }
    }

    fn private_test_directory() -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "raiun-pinned-publication-{}-{now}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("create isolated test directory");
        path
    }

    fn private_directory_under(parent_path: &Path) -> (PinnedDirectory, PrivateDirectory) {
        let parent = PinnedDirectory::open(parent_path).expect("pin private test parent");
        let name = format!(
            "private-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        );
        let private = PrivateDirectory::create_or_open_under(&parent, OsStr::new(&name))
            .expect("create current-user-only child");
        (parent, private)
    }

    fn replace_dacl(path: &Path, sddl: Option<&str>) {
        let wide_path = wide_extended_path(path).expect("encode test path");
        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | WRITE_DAC,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE, "open ACL test handle");
        let file = unsafe { File::from_raw_handle(handle as RawHandle) };
        let descriptor = sddl.map(|value| SecurityDescriptor::new(value).expect("build test ACL"));
        let (dacl, protection_information) = if let Some(descriptor) = &descriptor {
            let mut present = 0;
            let mut dacl = std::ptr::null_mut();
            let mut defaulted = 0;
            assert_ne!(
                unsafe {
                    GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted)
                },
                0
            );
            assert_ne!(present, 0);
            assert!(!dacl.is_null());
            let mut control = 0;
            let mut revision = 0;
            assert_ne!(
                unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) },
                0
            );
            let protection = if control & SE_DACL_PROTECTED != 0 {
                PROTECTED_DACL_SECURITY_INFORMATION
            } else {
                UNPROTECTED_DACL_SECURITY_INFORMATION
            };
            (dacl, protection)
        } else {
            (std::ptr::null_mut(), PROTECTED_DACL_SECURITY_INFORMATION)
        };
        let status = unsafe {
            SetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | protection_information,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(status, 0, "set test ACL");
    }

    fn security_descriptor_bytes(path: &Path) -> Vec<u8> {
        let wide_path = wide_extended_path(path).expect("encode security descriptor path");
        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(
            handle, INVALID_HANDLE_VALUE,
            "open security descriptor handle"
        );
        let file = unsafe { File::from_raw_handle(handle as RawHandle) };
        let mut owner = std::ptr::null_mut();
        let mut dacl = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, 0, "read security descriptor");
        let descriptor = SecurityDescriptor(descriptor);
        let length = unsafe { GetSecurityDescriptorLength(descriptor.0) } as usize;
        assert!(length > 0);
        unsafe { std::slice::from_raw_parts(descriptor.0.cast::<u8>(), length).to_vec() }
    }

    fn set_test_file_owner_to_token_user(path: &Path) {
        let wide_path = wide_extended_path(path).expect("encode test file path");
        let raw = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | WRITE_OWNER,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        let file = checked_handle(raw, false).expect("open test file for owner setup");
        let owner = current_user_sid_ptr().expect("get current test token SID");
        let status = unsafe {
            SetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                owner.0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(status, 0, "set test file owner to current token SID");
    }

    #[test]
    fn extended_rename_paths_preserve_drive_and_unc_roots() {
        let drive = wide_extended_path(Path::new(r"C:\Users\test\journal\record.bin"))
            .expect("extended drive path");
        assert_eq!(
            drive,
            r"\\?\C:\Users\test\journal\record.bin"
                .encode_utf16()
                .chain(Some(0))
                .collect::<Vec<_>>()
        );
        let unc = wide_extended_path(Path::new(r"\\server\share\journal\record.bin"))
            .expect("extended UNC path");
        assert_eq!(
            unc,
            r"\\?\UNC\server\share\journal\record.bin"
                .encode_utf16()
                .chain(Some(0))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn staged_publish_renames_atomically_without_replacing_existing_child() {
        let path = private_test_directory();
        {
            let directory = PinnedDirectory::open(&path).expect("pin test directory");
            let (mut first, first_identity) = directory
                .create_new_file(OsStr::new(".stage-first"))
                .expect("create first stage file");
            first
                .write_all(b"first snapshot")
                .expect("write first stage");
            first.sync_all().expect("sync first stage");
            drop(first);
            let published = directory
                .publish_staged_file(
                    OsStr::new(".stage-first"),
                    OsStr::new("record.bin"),
                    first_identity,
                )
                .expect("publish first record");
            assert_eq!(published, first_identity);
            assert_eq!(
                std::fs::read(path.join("record.bin")).expect("read published record"),
                b"first snapshot"
            );

            let (mut second, second_identity) = directory
                .create_new_file(OsStr::new(".stage-second"))
                .expect("create second stage file");
            second
                .write_all(b"replacement")
                .expect("write second stage");
            second.sync_all().expect("sync second stage");
            drop(second);
            assert!(
                directory
                    .publish_staged_file(
                        OsStr::new(".stage-second"),
                        OsStr::new("record.bin"),
                        second_identity,
                    )
                    .is_err()
            );
            assert_eq!(
                std::fs::read(path.join("record.bin")).expect("read original record"),
                b"first snapshot"
            );
            assert!(path.join(".stage-second").exists());
        }
        std::fs::remove_dir_all(path).expect("remove test directory");
    }

    #[test]
    fn staged_publish_supports_long_pinned_directory_paths() {
        let root = private_test_directory();
        let mut directory = PinnedDirectory::open(&root).expect("pin test directory");
        let mut suffix = 0_u32;
        while directory.path.as_os_str().encode_wide().count() < 300 {
            let name = format!("long-journal-component-{suffix:02}-xxxxxxxxxxxxxxxx");
            directory = directory
                .create_child_directory(OsStr::new(&name))
                .expect("create long-path child");
            suffix += 1;
        }

        let (mut stage, stage_id) = directory
            .create_new_file(OsStr::new(".stage-record"))
            .expect("create long-path stage");
        stage.write_all(b"long path snapshot").expect("write stage");
        stage.sync_all().expect("sync stage");
        drop(stage);

        let published = directory
            .publish_staged_file(
                OsStr::new(".stage-record"),
                OsStr::new("record.bin"),
                stage_id,
            )
            .expect("publish long-path record");
        assert_eq!(published, stage_id);
        assert_eq!(
            std::fs::read(directory.path.join("record.bin")).expect("read published record"),
            b"long path snapshot"
        );

        drop(directory);
        std::fs::remove_dir_all(root).expect("remove long-path test tree");
    }

    #[test]
    fn held_ancestor_handle_prevents_parent_swap_during_publication() {
        let root = private_test_directory();
        let parent_path = root.join("parent");
        let child_path = parent_path.join("child");
        std::fs::create_dir(&parent_path).expect("create parent");
        std::fs::create_dir(&child_path).expect("create child");
        let directory = PinnedDirectory::open(&child_path).expect("pin child and ancestors");

        let replacement_path = root.join("replacement");
        let swap = std::fs::rename(&parent_path, &replacement_path);
        assert!(swap.is_err(), "held ancestor must deny rename/replacement");
        assert!(!replacement_path.exists());
        directory
            .verify_path()
            .expect("original pinned path still resolves to its identity");

        let (mut stage, stage_id) = directory
            .create_new_file(OsStr::new(".stage-record"))
            .expect("create stage under pinned parent");
        stage.write_all(b"parent identity").expect("write stage");
        stage.sync_all().expect("sync stage");
        drop(stage);
        assert_eq!(
            directory
                .publish_staged_file(
                    OsStr::new(".stage-record"),
                    OsStr::new("record.bin"),
                    stage_id,
                )
                .expect("publish in the pinned parent"),
            stage_id
        );
        directory
            .verify_path()
            .expect("verify pinned parent after publish");

        drop(directory);
        std::fs::remove_dir_all(root).expect("remove isolated test directory");
    }

    #[test]
    fn private_generation_lock_serializes_independent_handles() {
        let root = private_test_directory();
        let (parent, private) = private_directory_under(&root);
        let mut first = private
            .create_new_pinned_file(OsStr::new("generation.lock"))
            .unwrap();
        let expected = first.identity();
        let mut second = private
            .open_pinned_file(
                OsStr::new("generation.lock"),
                super::PinnedPrivateFileAccess::ReadWrite,
            )
            .unwrap();
        first.try_lock_exclusive().unwrap();
        assert!(second.try_lock_exclusive().is_err());
        first.unlock().unwrap();
        second.try_lock_exclusive().unwrap();
        drop(second);
        first.try_lock_exclusive().unwrap();
        assert_eq!(first.identity(), expected);
        drop(first);
        assert!(private.path().join("generation.lock").is_file());
        drop(private);
        drop(parent);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn immutable_private_read_denies_writers_until_pin_closes() {
        let root = private_test_directory();
        let (parent, private) = private_directory_under(&root);
        let (mut writer, _) = private.create_new_file(OsStr::new("blob")).unwrap();
        writer.write_all(b"verified content").unwrap();
        writer.sync_all().unwrap();
        assert!(
            private
                .open_pinned_file(
                    OsStr::new("blob"),
                    super::PinnedPrivateFileAccess::ImmutableRead
                )
                .is_err()
        );
        drop(writer);
        let reader = private
            .open_pinned_file(
                OsStr::new("blob"),
                super::PinnedPrivateFileAccess::ImmutableRead,
            )
            .unwrap();
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(private.path().join("blob"))
                .is_err()
        );
        let second = private
            .open_pinned_file(
                OsStr::new("blob"),
                super::PinnedPrivateFileAccess::ImmutableRead,
            )
            .unwrap();
        assert_eq!(reader.identity(), second.identity());
        drop(second);
        drop(reader);
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(private.path().join("blob"))
            .unwrap();
        drop(writer);
        drop(private);
        drop(parent);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_publication_failed_final_flush_preserves_published_recovery() {
        let root = private_test_directory();
        let (parent, private) = private_directory_under(&root);
        let (mut stage, expected) = private.create_new_file(OsStr::new("stage")).unwrap();
        stage
            .write_all(b"recover after uncertain publication")
            .unwrap();
        stage.sync_all().unwrap();
        drop(stage);
        let failure = private
            .directory
            .publish_staged_file_with_final_flush(
                OsStr::new("stage"),
                OsStr::new("blob"),
                expected,
                true,
                |rename_handle| {
                    assert_eq!(identity(rename_handle).unwrap(), expected);
                    // The post-rename interval must still exclude writers and
                    // deleters even though the destination name is now visible.
                    for access in [GENERIC_WRITE, DELETE_ACCESS] {
                        let error = open_file_handle_with_share(
                            &private.path().join("blob"),
                            access,
                            OPEN_EXISTING,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        )
                        .unwrap_err();
                        assert_eq!(error.raw_os_error(), Some(32)); // sharing violation
                    }
                    Err(io::Error::other("injected post-rename flush failure"))
                },
            )
            .unwrap_err();
        assert_eq!(failure.to_string(), "injected post-rename flush failure");
        assert!(!private.path().join("stage").exists());
        let (mut published, actual) = private.open_regular_file(OsStr::new("blob")).unwrap();
        assert_eq!(actual, expected);
        let mut bytes = Vec::new();
        published.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"recover after uncertain publication");
        drop(published);
        drop(private);
        drop(parent);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_publication_preserves_identity_and_existing_destination() {
        let root = private_test_directory();
        let (parent, private) = private_directory_under(&root);
        let (mut stage, expected) = private.create_new_file(OsStr::new("stage")).unwrap();
        stage.write_all(b"original").unwrap();
        stage.sync_all().unwrap();
        drop(stage);
        assert_eq!(
            private
                .publish_staged_file(OsStr::new("stage"), OsStr::new("blob"), expected)
                .unwrap(),
            expected
        );
        let (mut other, other_id) = private.create_new_file(OsStr::new("other")).unwrap();
        other.write_all(b"replacement").unwrap();
        other.sync_all().unwrap();
        drop(other);
        assert!(
            private
                .publish_staged_file(OsStr::new("other"), OsStr::new("blob"), other_id)
                .is_err()
        );
        assert_eq!(
            std::fs::read(private.path().join("blob")).unwrap(),
            b"original"
        );
        assert_eq!(
            std::fs::read(private.path().join("other")).unwrap(),
            b"replacement"
        );
        let (opened, actual) = private.open_regular_file(OsStr::new("blob")).unwrap();
        assert_eq!(actual, expected);
        drop(opened);
        drop(private);
        drop(parent);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_directory_creates_and_reopens_exact_current_user_policy() {
        let root = private_test_directory();
        let (parent, private) = private_directory_under(&root);
        let (mut file, expected) = private
            .create_new_file(OsStr::new("record.bin"))
            .expect("create protected file");
        file.write_all(b"private cache record")
            .expect("write protected file");
        file.sync_all().expect("flush protected file");
        drop(file);

        let (opened, actual) = private
            .open_regular_file(OsStr::new("record.bin"))
            .expect("open protected file");
        assert_eq!(expected, actual);
        assert_eq!(
            std::fs::read(private.path().join("record.bin")).unwrap(),
            b"private cache record"
        );
        drop(opened);

        let child_name = private.path().file_name().unwrap();
        let reopened = PrivateDirectory::open_under(&parent, child_name)
            .expect("reopen and validate, without ACL repair");
        assert_eq!(reopened.identity(), private.identity());

        drop(reopened);
        drop(private);
        drop(parent);
        std::fs::remove_dir_all(root).expect("remove private test tree");
    }

    #[test]
    fn pinned_private_file_keeps_identity_and_blocks_path_replacement() {
        let root = private_test_directory();
        let (parent, private) = private_directory_under(&root);
        let file_path = private.path().join("record.bin");
        let replacement_path = private.path().join("replacement.bin");
        let mut created = private
            .create_new_pinned_file(OsStr::new("record.bin"))
            .expect("create and pin a private child");
        let expected = created.identity();
        created
            .write_all(b"pinned bytes")
            .expect("write through pin");
        created.flush().expect("flush through pin");
        assert!(
            private
                .open_delete_candidate(OsStr::new("record.bin"), expected)
                .is_err(),
            "DELETE open must fail while a no-delete-sharing pin is alive"
        );
        assert!(std::fs::rename(&file_path, &replacement_path).is_err());
        let _borrowed = created.borrowed_handle().expect("borrow checked handle");
        created.verify().expect("verify same held identity");
        drop(created);

        let mut opened = private
            .open_pinned_file(OsStr::new("record.bin"), PinnedPrivateFileAccess::ReadOnly)
            .expect("open a read-only pin");
        assert_eq!(opened.identity(), expected);
        let mut bytes = Vec::new();
        opened.read_to_end(&mut bytes).expect("read through pin");
        assert_eq!(bytes, b"pinned bytes");
        assert!(opened.write(b"x").is_err(), "read-only pin cannot write");
        drop(opened);

        let delete = private
            .open_delete_candidate(OsStr::new("record.bin"), expected)
            .expect("open exact delete candidate after pins close");
        assert_eq!(delete.identity(), expected);
        delete.delete().expect("delete by the exact pinned handle");
        assert!(!file_path.exists());

        drop(private);
        drop(parent);
        std::fs::remove_dir_all(root).expect("remove private test tree");
    }

    #[test]
    fn private_delete_candidate_rejects_replaced_identity_without_deleting_it() {
        let root = private_test_directory();
        let (parent, private) = private_directory_under(&root);
        let file_path = private.path().join("record.bin");
        let first = private
            .create_new_pinned_file(OsStr::new("record.bin"))
            .expect("create original file");
        let original_identity = first.identity();
        drop(first);
        std::fs::remove_file(&file_path).expect("remove original after pin closes");
        let replacement = private
            .create_new_pinned_file(OsStr::new("record.bin"))
            .expect("create replacement at same name");
        let replacement_identity = replacement.identity();
        assert_ne!(replacement_identity, original_identity);
        drop(replacement);

        assert!(
            private
                .open_delete_candidate(OsStr::new("record.bin"), original_identity)
                .is_err()
        );
        assert_eq!(
            private
                .open_pinned_file(OsStr::new("record.bin"), PinnedPrivateFileAccess::ReadOnly,)
                .expect("replacement remains present")
                .identity(),
            replacement_identity
        );

        drop(private);
        drop(parent);
        std::fs::remove_dir_all(root).expect("remove private test tree");
    }

    #[test]
    fn pinned_private_file_rejects_reparse_entries_without_following_them() {
        let root = private_test_directory();
        let (parent, private) = private_directory_under(&root);
        let target = root.join("target");
        std::fs::create_dir(&target).expect("create isolated reparse target");
        let name = format!("junction-{}", NEXT_TEMP.fetch_add(1, Ordering::Relaxed));
        let link = private.path().join(&name);
        let result = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .expect("run standard-user junction creator");
        assert!(
            result.status.success(),
            "create synthetic reparse entry: {}",
            String::from_utf8_lossy(&result.stderr)
        );

        assert!(
            private
                .open_pinned_file(OsStr::new(&name), PinnedPrivateFileAccess::ReadOnly)
                .is_err()
        );
        assert!(
            private
                .open_delete_candidate(
                    OsStr::new(&name),
                    PinnedFileIdentity {
                        volume_serial: 0,
                        file_index: 0,
                    },
                )
                .is_err()
        );

        drop(private);
        drop(parent);
        let _ = std::fs::remove_dir(&link);
        std::fs::remove_dir_all(root).expect("remove private test tree");
    }

    #[test]
    fn private_directory_accepts_ordinary_sqlite_sidecar_inheritance() {
        let root = private_test_directory();
        let (parent, private) = private_directory_under(&root);
        for name in ["cache.sqlite", "cache.sqlite-wal", "cache.sqlite-shm"] {
            let path = private.path().join(name);
            let mut ordinary = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .expect("create ordinary SQLite sidecar with inherited DACL");
            ordinary.write_all(b"test").unwrap();
            ordinary.sync_all().unwrap();
            drop(ordinary);
            // SYSTEM and elevated CI tokens may default to an Administrators
            // owner. Set only this synthetic file's owner to the token user;
            // the owner-only API leaves the inherited DACL under test intact.
            // Production validation never repairs ownership or access rules.
            set_test_file_owner_to_token_user(&path);
            let (mut opened, _) = private
                .open_regular_file(OsStr::new(name))
                .expect("accept exact current-user-only inherited ACL");
            let mut bytes = Vec::new();
            opened.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"test");
        }
        drop(private);
        drop(parent);
        std::fs::remove_dir_all(root).expect("remove private test tree");
    }

    #[test]
    fn private_acl_policy_rejects_wrong_owner_mask_flags_and_type_facts() {
        let valid_directory = valid_private_acl_facts(PrivateEntryKind::Directory);
        assert!(private_acl_policy_valid(
            PrivateEntryKind::Directory,
            valid_directory
        ));

        let mut wrong_owner = valid_directory;
        wrong_owner.owner_matches = false;
        assert!(!private_acl_policy_valid(
            PrivateEntryKind::Directory,
            wrong_owner
        ));

        let mut wrong_sid = valid_directory;
        wrong_sid.ace_sid_matches = false;
        assert!(!private_acl_policy_valid(
            PrivateEntryKind::Directory,
            wrong_sid
        ));

        let mut wrong_mask = valid_directory;
        wrong_mask.access_mask = 0x0012_0089;
        assert!(!private_acl_policy_valid(
            PrivateEntryKind::Directory,
            wrong_mask
        ));

        let mut wrong_type = valid_directory;
        wrong_type.ace_type = 1;
        assert!(!private_acl_policy_valid(
            PrivateEntryKind::Directory,
            wrong_type
        ));

        let mut wrong_flags = valid_directory;
        wrong_flags.ace_flags = 0;
        assert!(!private_acl_policy_valid(
            PrivateEntryKind::Directory,
            wrong_flags
        ));

        let mut inherited_sidecar = valid_private_acl_facts(PrivateEntryKind::File);
        inherited_sidecar.dacl_protected = false;
        inherited_sidecar.ace_flags =
            (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERITED_ACE) as u8;
        assert!(private_acl_policy_valid(
            PrivateEntryKind::File,
            inherited_sidecar
        ));

        inherited_sidecar.ace_flags = OBJECT_INHERIT_ACE as u8;
        assert!(!private_acl_policy_valid(
            PrivateEntryKind::File,
            inherited_sidecar
        ));
    }

    #[test]
    fn private_directory_rejects_broad_null_and_unknown_dacls_without_repair() {
        let root = private_test_directory();
        let (parent, private) = private_directory_under(&root);
        let owner_sid = super::super::win32::current_user_sid_for_storage().unwrap();

        let protected_name = private.path().file_name().unwrap();
        for sddl in [
            Some("D:P(A;OICI;FA;;;WD)".to_owned()),
            None,
            Some(format!("D:P(A;OICI;FA;;;{owner_sid})(A;OICI;FA;;;BU)")),
            Some(format!("D:(A;OICI;FA;;;{owner_sid})")),
            Some(format!("D:P(A;OICI;FR;;;{owner_sid})")),
            Some(format!("D:P(A;;FA;;;{owner_sid})")),
        ] {
            replace_dacl(private.path(), sddl.as_deref());
            let before = security_descriptor_bytes(private.path());
            assert!(PrivateDirectory::open_under(&parent, protected_name).is_err());
            assert_eq!(
                before,
                security_descriptor_bytes(private.path()),
                "validation must not repair the existing descriptor"
            );
        }

        // Restore only for test cleanup after proving every failed open left
        // the malformed descriptor untouched.
        replace_dacl(
            private.path(),
            Some(&format!("D:P(A;OICI;FA;;;{owner_sid})")),
        );

        drop(private);
        drop(parent);
        std::fs::remove_dir_all(root).expect("remove private test tree");
    }

    #[test]
    fn private_file_rejects_hard_links() {
        let root = private_test_directory();
        let (parent, private) = private_directory_under(&root);
        let (file, _) = private
            .create_new_file(OsStr::new("record.bin"))
            .expect("create protected file");
        drop(file);
        std::fs::hard_link(private.path().join("record.bin"), root.join("alias.bin"))
            .expect("create same-volume hard link");
        assert!(private.open_regular_file(OsStr::new("record.bin")).is_err());

        drop(private);
        drop(parent);
        std::fs::remove_dir_all(root).expect("remove private test tree");
    }

    #[test]
    fn private_api_rejects_nonlocal_and_device_path_prefixes() {
        for invalid in [
            r"\\server\share\state",
            r"\\?\C:\state",
            r"\\.\pipe\state",
            r"\??\C:\state",
            r"C:relative\state",
            r"C:\state:stream",
            r"relative\state",
            r"C:\state\..\other",
        ] {
            assert!(
                validate_local_drive_path(Path::new(invalid)).is_err(),
                "{invalid}"
            );
        }
        assert!(validate_local_drive_path(Path::new(r"C:\Users\test\state")).is_ok());
    }

    #[test]
    fn private_api_rejects_wrong_entry_types() {
        let root = private_test_directory();
        let (parent, private) = private_directory_under(&root);
        let ordinary_file = private.path().join("not-a-directory");
        std::fs::write(&ordinary_file, b"x").expect("create file in private directory");
        assert!(
            PrivateDirectory::open_under(&parent, OsStr::new("private-does-not-exist")).is_err()
        );
        assert!(PrivateDirectory::open_under(&parent, ordinary_file.file_name().unwrap()).is_err());
        std::fs::create_dir(private.path().join("not-a-file")).expect("create child directory");
        assert!(private.open_regular_file(OsStr::new("not-a-file")).is_err());
        drop(private);
        drop(parent);
        std::fs::remove_dir_all(root).expect("remove private test tree");
    }

    #[test]
    fn private_directory_rejects_reparse_child_and_holds_ancestor_chain() {
        let root = private_test_directory();
        let outer = root.join("outer");
        std::fs::create_dir(&outer).expect("create outer parent");
        let (parent, private) = private_directory_under(&outer);
        let target = root.join("target");
        std::fs::create_dir(&target).expect("create reparse target");
        let link_name = format!("link-{}", NEXT_TEMP.fetch_add(1, Ordering::Relaxed));
        let link_path = outer.join(&link_name);
        let junction = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link_path)
            .arg(&target)
            .output()
            .expect("run standard-user junction creator");
        assert!(
            junction.status.success(),
            "create synthetic reparse directory: {}",
            String::from_utf8_lossy(&junction.stderr)
        );
        assert!(PrivateDirectory::open_under(&parent, OsStr::new(&link_name)).is_err());

        assert!(
            std::fs::rename(&outer, root.join("outer-renamed")).is_err(),
            "pinned ancestor chain must prevent replacement"
        );
        private.verify_path().expect("private path remains pinned");

        drop(private);
        drop(parent);
        let _ = std::fs::remove_dir(&link_path);
        std::fs::remove_dir_all(root).expect("remove private test tree");
    }
    #[test]
    fn immutable_regular_file_pin_denies_writes_and_replacement_until_drop() {
        let root = private_test_directory();
        let path = root.join("source.bin");
        let renamed = root.join("renamed.bin");
        let expected = b"ordinary synthetic source";
        std::fs::write(&path, expected).expect("create ordinary source");
        let parent = PinnedDirectory::open(&root).expect("hold ordinary parent");
        let (mut pinned, captured) = parent
            .open_immutable_regular_file(OsStr::new("source.bin"))
            .expect("pin immutable ordinary file");
        assert_eq!(identity(&pinned).unwrap(), captured);
        let mut actual = Vec::new();
        pinned.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected);
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
        assert!(std::fs::rename(&path, &renamed).is_err());
        assert!(std::fs::remove_file(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), expected);
        assert!(!renamed.exists());
        drop(pinned);
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("ordinary write allowed after immutable pin drops");
        assert_eq!(std::fs::read(&path).unwrap(), expected);
        writer.write_all(b"controlled").unwrap();
        writer.flush().unwrap();
        drop(writer);
        let after = std::fs::read(&path).unwrap();
        assert_eq!(&after[..10], b"controlled");
        assert_eq!(&after[10..], &expected[10..]);
        drop(parent);
        std::fs::remove_dir_all(root).unwrap();
    }
}

//! Single-owner native adapter; see the external safety review note before use.
use super::{
    ConstructionStage, DirectoryForm, NOTIFICATION_BUFFER_BYTES, NotificationBatch,
    OBSERVER_ACCESS_MASK, RescanReason, directory_form, parse_notification_buffer,
};
use crate::{PinnedDirectory, PinnedFileIdentity};
use std::{
    cell::UnsafeCell,
    io,
    marker::PhantomData,
    os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    ptr,
    rc::Rc,
    sync::Arc,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED,
        GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED, FILE_LIST_DIRECTORY,
        FILE_NAME_NORMALIZED, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
        FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FileAttributeTagInfo, GetFileInformationByHandle,
        GetFileInformationByHandleEx, GetFinalPathNameByHandleW, OPEN_EXISTING,
        ReadDirectoryChangesW, VOLUME_NAME_GUID,
    },
    System::{
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        Threading::{CreateEventW, ResetEvent, WaitForSingleObject},
    },
};

// Explicit UTF-16 lengths and the OS uppercase table avoid locale-dependent
// folding. This is only alias detection over untrusted notification names; it
// never establishes filesystem identity or grants a namespace operation.
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CompareStringOrdinal(
        left: *const u16,
        left_len: i32,
        right: *const u16,
        right_len: i32,
        ignore_case: i32,
    ) -> i32;
}
pub(super) fn ordinal_names_equal(left: &str, right: &str) -> Option<bool> {
    let left: Vec<u16> = left.encode_utf16().collect();
    let right: Vec<u16> = right.encode_utf16().collect();
    if left.is_empty() || right.is_empty() || left.len() > 255 || right.len() > 255 {
        return None;
    }
    // SAFETY: both buffers remain live, lengths are positive and bounded, and
    // TRUE is exactly one as required by CompareStringOrdinal.
    match unsafe {
        CompareStringOrdinal(
            left.as_ptr(),
            left.len() as i32,
            right.as_ptr(),
            right.len() as i32,
            1,
        )
    } {
        1 | 3 => Some(false),
        2 => Some(true),
        _ => None,
    }
}

#[repr(C, align(4))]
struct AlignedBuffer([u8; NOTIFICATION_BUFFER_BYTES]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObserverPoll {
    /// No read has been armed. The caller must explicitly arm after each batch.
    Idle,
    /// The same owner must remain alive with all its I/O storage intact.
    Pending,
    Batch(NotificationBatch),
    /// Permanently stopped. Cancellation always invalidates continuity; a new
    /// observer must be paired with reconciliation, even if no hints were seen.
    Stopped,
}

/// Physically pinned, hint-only observer with one outstanding overlapped read.
/// An owned observation handle authenticates no provider, account or namespace.
///
/// The observer is neither Send nor Sync. There are no background workers or
/// borrowed native buffers. Poll/cancel waits are capped at 60 seconds; other
/// filesystem metadata calls are normal synchronous OS calls. Cancel does NOT
/// free an outstanding read on timeout. Drop cancels and BLOCKS until actual
/// completion, possibly indefinitely if the driver never completes cancellation.
/// Call cancel_and_drain repeatedly and retain the owner while it reports Pending
/// to keep shutdown responsive. Never drop it on a callback/GUI owner thread.
pub struct DirectoryObserver {
    // Only the ordinary constructor retains a full ordinary ancestor chain.
    // Handle-only mode has no pathname/ancestor or provider authority.
    root: Option<Arc<PinnedDirectory>>,
    expected: PinnedFileIdentity,
    directory: OwnedHandle,
    event: OwnedHandle,
    // UnsafeCell permits external kernel writes while pending. Both allocations
    // keep fixed addresses even when the outer Rust owner is moved.
    overlapped: Box<UnsafeCell<OVERLAPPED>>,
    buffer: Box<UnsafeCell<AlignedBuffer>>,
    pending: bool,
    stopping: bool,
    _single_thread: PhantomData<Rc<()>>,
}

const OBSERVER_ACCESS: u32 = OBSERVER_ACCESS_MASK;
const _: () = assert!(OBSERVER_ACCESS == FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES);

/// Coarse constructor evidence only. No handle, path or security data is held
/// beyond the original io::Error, which the ordinary API returns unchanged.
pub struct ObserverConstructionFailure {
    stage: ConstructionStage,
    error: io::Error,
}
impl ObserverConstructionFailure {
    fn at(stage: ConstructionStage, error: io::Error) -> Self {
        Self { stage, error }
    }
    #[cfg(all(feature = "synthetic-agent-integration", debug_assertions))]
    pub fn stage(&self) -> &'static str {
        self.stage.code()
    }
    #[cfg(all(feature = "synthetic-agent-integration", debug_assertions))]
    pub fn native_code(&self) -> Option<i32> {
        self.error.raw_os_error()
    }
    #[cfg(all(feature = "synthetic-agent-integration", debug_assertions))]
    pub fn kind(&self) -> io::ErrorKind {
        self.error.kind()
    }
    pub fn into_io_error(self) -> io::Error {
        // The ordinary API deliberately discards only the coarse stage.
        let _ = self.stage.code();
        self.error
    }
}

const MAX_KERNEL_PATH_UNITS: usize = 32_768;

fn valid_kernel_volume_path(path: &[u16]) -> bool {
    if !(50..=MAX_KERNEL_PATH_UNITS).contains(&path.len())
        || path.last() != Some(&0)
        || path[..path.len() - 1].contains(&0)
    {
        return false;
    }
    let Ok(text) = String::from_utf16(&path[..path.len() - 1]) else {
        return false;
    };
    let bytes = text.as_bytes();
    if bytes.len() < 49
        || !bytes.starts_with(b"\\\\?\\Volume{")
        || bytes[47] != b'}'
        || bytes[48] != b'\\'
    {
        return false;
    }
    for (i, byte) in bytes[11..47].iter().enumerate() {
        if [8, 13, 18, 23].contains(&i) {
            if *byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    let suffix = &text[49..];
    suffix.is_empty()
        || suffix.split('\\').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.ends_with(['.', ' '])
                && part.encode_utf16().count() <= 255
                && !part.chars().any(|c| {
                    c.is_control() || matches!(c, '/' | ':' | '<' | '>' | '"' | '|' | '?' | '*')
                })
        })
}

fn kernel_volume_path(original: HANDLE) -> io::Result<Vec<u16>> {
    let mut path = vec![0u16; MAX_KERNEL_PATH_UNITS];
    // SAFETY: live borrowed handle; fixed bounded writable UTF16 storage. The
    // documented normalized Volume GUID result excludes NUL on success. There
    // is one query, no unbounded resize or DOS/UNC/device-path fallback.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            original,
            path.as_mut_ptr(),
            MAX_KERNEL_PATH_UNITS as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_GUID,
        )
    };
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    let length = length as usize;
    if length >= MAX_KERNEL_PATH_UNITS || path[length] != 0 {
        return Err(root_changed());
    }
    path.truncate(length + 1);
    if !valid_kernel_volume_path(&path) {
        return Err(root_changed());
    }
    Ok(path)
}

impl DirectoryObserver {
    /// Accept only an independently admitted, fully no-follow-pinned directory
    /// and the expected exact root ID. No path or event-string constructor exists.
    /// PinnedDirectory's existing ordinary/no-reparse root policy is unchanged;
    /// this constructor does not admit a connected Cloud Files reparse root.
    pub fn new(root: Arc<PinnedDirectory>, expected: PinnedFileIdentity) -> io::Result<Self> {
        if expected.file_index == 0 || root.identity() != expected {
            return Err(root_changed());
        }
        root.verify_path()?;
        let original = root.try_clone_directory_file()?;
        let mut observer = Self::from_borrowed_directory(original.as_handle(), expected)?;
        root.verify_path()?;
        // The general handle-only factory permits cloud tags; this existing
        // constructor must retain its strictly ordinary/no-reparse contract.
        if verify_directory(observer.directory.as_raw_handle() as HANDLE, expected)?.form
            != DirectoryForm::Ordinary
        {
            return Err(root_changed());
        }
        observer.root = Some(root);
        Ok(observer)
    }

    /// Own an overlapped observation handle for this exact physical directory.
    /// The borrow is used only during construction and is never closed here.
    /// Ordinary and known Cloud Files tags are recognized, but this authenticates
    /// NO provider/account/registration/ancestor or ordinary-storage capability.
    /// A provider must retain and revalidate its own root and publication lease.
    /// A bounded kernel-derived Volume GUID path locates a separate handle;
    /// exact original/new FileID and type/tag checks must join it before I/O.
    /// The locator grants no ancestor/provider authority and has no fallback.
    pub fn from_borrowed_directory(
        original: BorrowedHandle<'_>,
        expected: PinnedFileIdentity,
    ) -> io::Result<Self> {
        Self::construct(original, expected).map_err(ObserverConstructionFailure::into_io_error)
    }

    /// Synthetic/debug diagnostics only, with exactly the ordinary factory's
    /// behavior. A stage or error code never grants physical/provider authority.
    #[cfg(all(feature = "synthetic-agent-integration", debug_assertions))]
    pub fn from_borrowed_directory_diagnostic(
        original: BorrowedHandle<'_>,
        expected: PinnedFileIdentity,
    ) -> Result<Self, ObserverConstructionFailure> {
        Self::construct(original, expected)
    }

    fn construct(
        original: BorrowedHandle<'_>,
        expected: PinnedFileIdentity,
    ) -> Result<Self, ObserverConstructionFailure> {
        let before =
            verify_directory(original.as_raw_handle() as HANDLE, expected).map_err(|error| {
                ObserverConstructionFailure::at(ConstructionStage::OriginalMetadata, error)
            })?;
        let locator = kernel_volume_path(original.as_raw_handle() as HANDLE).map_err(|error| {
            ObserverConstructionFailure::at(ConstructionStage::KernelPath, error)
        })?;
        // SAFETY: locator is a bounded, NUL-terminated kernel-derived normalized
        // local Volume GUID path. OPEN_REPARSE_POINT opens the leaf itself. The
        // caller retains the borrowed original and its own admitted root lease;
        // SAME FileID/type/tag must join both handles below BEFORE event or I/O.
        // No fallback, DELETE sharing, privilege or ACL change is attempted.
        let raw = unsafe {
            CreateFileW(
                locator.as_ptr(),
                OBSERVER_ACCESS,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OVERLAPPED,
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            return Err(ObserverConstructionFailure::at(
                ConstructionStage::SameObjectOpen,
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: CreateFileW returned one new exclusively owned valid handle.
        let directory = unsafe { OwnedHandle::from_raw_handle(raw) };
        let reopened = verify_directory(raw, expected).map_err(|error| {
            ObserverConstructionFailure::at(ConstructionStage::ReopenedMetadata, error)
        })?;
        let original_after = verify_directory(original.as_raw_handle() as HANDLE, expected)
            .map_err(|error| {
                ObserverConstructionFailure::at(ConstructionStage::OriginalPostMetadata, error)
            })?;
        let reopened_after = verify_directory(raw, expected).map_err(|error| {
            ObserverConstructionFailure::at(ConstructionStage::ReopenedPostMetadata, error)
        })?;
        if before != reopened || before != original_after || before != reopened_after {
            return Err(ObserverConstructionFailure::at(
                ConstructionStage::MetadataChanged,
                root_changed(),
            ));
        }
        // SAFETY: unnamed, manual-reset, initially nonsignaled event; no borrowed
        // pointers or shared named synchronization objects are supplied.
        let raw_event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if raw_event.is_null() {
            return Err(ObserverConstructionFailure::at(
                ConstructionStage::Event,
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: successful CreateEventW transfers one new owned handle.
        let event = unsafe { OwnedHandle::from_raw_handle(raw_event) };
        let overlapped = OVERLAPPED {
            hEvent: raw_event,
            ..OVERLAPPED::default()
        };
        Ok(Self {
            root: None,
            expected,
            directory,
            event,
            overlapped: Box::new(UnsafeCell::new(overlapped)),
            buffer: Box::new(UnsafeCell::new(AlignedBuffer(
                [0; NOTIFICATION_BUFFER_BYTES],
            ))),
            pending: false,
            stopping: false,
            _single_thread: PhantomData,
        })
    }

    pub fn root_identity(&self) -> PinnedFileIdentity {
        self.expected
    }

    pub fn has_pending_io(&self) -> bool {
        self.pending
    }

    fn verify_current_root(&self) -> io::Result<()> {
        if let Some(root) = &self.root {
            root.verify_path()?;
        }
        let observed = verify_directory(self.directory.as_raw_handle() as HANDLE, self.expected)?;
        if self.root.is_some() && observed.form != DirectoryForm::Ordinary {
            return Err(root_changed());
        }
        Ok(())
    }

    /// Arm at most one recursive read. An existing read is never replaced.
    /// After an error or completed batch, reconciliation decides when to rearm.
    pub fn arm(&mut self) -> ObserverPoll {
        if self.pending {
            return ObserverPoll::Pending;
        }
        if self.stopping {
            return ObserverPoll::Stopped;
        }
        if self.verify_current_root().is_err() {
            self.stopping = true;
            return rescan(RescanReason::RootChanged);
        }
        // SAFETY: no operation is pending. Reset the event and OVERLAPPED only
        // after completion of the prior read. Event is unique and owned.
        if unsafe { ResetEvent(self.event.as_raw_handle() as HANDLE) } == 0 {
            return rescan(RescanReason::NativeError(last_error()));
        }
        // SAFETY: no outstanding kernel access; allocation is uniquely owned.
        unsafe {
            self.overlapped.get().write(OVERLAPPED {
                hEvent: self.event.as_raw_handle() as HANDLE,
                ..OVERLAPPED::default()
            });
        }
        self.pending = true;
        // SAFETY: directory was reopened OVERLAPPED with LIST_DIRECTORY. Buffer
        // is DWORD-aligned, initialized and fixed-size; OVERLAPPED has a unique
        // live event. Both stable allocations and all handles live until drain.
        // Async completion does not use lpBytesReturned or a completion routine.
        let queued = unsafe {
            ReadDirectoryChangesW(
                self.directory.as_raw_handle() as HANDLE,
                self.buffer.get().cast(),
                NOTIFICATION_BUFFER_BYTES as u32,
                1,
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_DIR_NAME
                    | FILE_NOTIFY_CHANGE_SIZE
                    | FILE_NOTIFY_CHANGE_LAST_WRITE,
                ptr::null_mut(),
                self.overlapped.get(),
                None,
            )
        };
        if queued == 0 {
            let code = last_error();
            if code != ERROR_IO_PENDING {
                // A failed submission has no outstanding read. Never inspect
                // stale buffer bytes or interpret an error as an empty inventory.
                self.pending = false;
                return rescan(RescanReason::NativeError(code));
            }
        }
        ObserverPoll::Pending
    }

    /// Wait for this read only, at most min(wait, 60 seconds). A timeout and a
    /// wait API error both retain the outstanding I/O and its storage unchanged.
    pub fn poll(&mut self, wait: Duration) -> ObserverPoll {
        if !self.pending {
            return if self.stopping {
                ObserverPoll::Stopped
            } else {
                ObserverPoll::Idle
            };
        }
        let millis = wait.as_millis().min(60_000) as u32;
        // SAFETY: event is valid and remains alive until after the read drains.
        match unsafe { WaitForSingleObject(self.event.as_raw_handle() as HANDLE, millis) } {
            WAIT_TIMEOUT => return ObserverPoll::Pending,
            WAIT_OBJECT_0 => (),
            _ => return rescan(RescanReason::NativeError(last_error())),
        }
        let mut transferred = 0;
        // SAFETY: exact handle/OVERLAPPED pair from the only submitted operation.
        // False avoids an additional unbounded wait after the bounded event wait.
        let complete = unsafe {
            GetOverlappedResult(
                self.directory.as_raw_handle() as HANDLE,
                self.overlapped.get(),
                &mut transferred,
                0,
            )
        };
        if complete == 0 {
            let code = last_error();
            if matches!(code, ERROR_IO_INCOMPLETE | ERROR_IO_PENDING) {
                return ObserverPoll::Pending;
            }
            // With this valid, private handle/event/OVERLAPPED pair these are
            // operation completion errors, not permission to reuse pending I/O.
            self.pending = false;
            return rescan(if code == ERROR_OPERATION_ABORTED {
                RescanReason::Cancelled
            } else {
                RescanReason::NativeError(code)
            });
        }
        self.pending = false;
        if self.stopping {
            // Cancellation may race a normal completion. Continuity still ends;
            // never dispatch the late hints as a new observation generation.
            return rescan(RescanReason::Cancelled);
        }
        if self.verify_current_root().is_err() {
            self.stopping = true;
            return rescan(RescanReason::RootChanged);
        }
        let length = transferred as usize;
        if length > NOTIFICATION_BUFFER_BYTES {
            return rescan(RescanReason::Limit);
        }
        // SAFETY: completion has been observed and no operation is pending;
        // kernel writes are finished. Only initialized bytes within the count
        // are exposed to the portable parser, and no slice escapes this call.
        let bytes = unsafe { &(&(*self.buffer.get()).0)[..length] };
        ObserverPoll::Batch(parse_notification_buffer(bytes))
    }

    /// Permanently stop admission, request cancellation of only this read and
    /// wait boundedly. Pending means the SAME owner still owns live kernel I/O;
    /// retain it and poll/cancel again. Even ERROR_NOT_FOUND is not a drain.
    pub fn cancel_and_drain(&mut self, wait: Duration) -> ObserverPoll {
        self.stopping = true;
        if !self.pending {
            return ObserverPoll::Stopped;
        }
        // SAFETY: private valid handle and exact stable OVERLAPPED. CancelIoEx
        // requests cancellation only; allocations/handles remain owned.
        if unsafe {
            CancelIoEx(
                self.directory.as_raw_handle() as HANDLE,
                self.overlapped.get(),
            )
        } == 0
        {
            let code = last_error();
            if code != ERROR_NOT_FOUND {
                return rescan(RescanReason::NativeError(code));
            }
        }
        self.poll(wait)
    }
}

impl Drop for DirectoryObserver {
    fn drop(&mut self) {
        if !self.pending {
            return;
        }
        // SAFETY: all raw resources are still owned and valid. Cancellation is
        // not completion, including NOT_FOUND. Keep every allocation, event,
        // directory handle and ancestor pin alive through the blocking drain.
        unsafe {
            CancelIoEx(
                self.directory.as_raw_handle() as HANDLE,
                self.overlapped.get(),
            );
        }
        loop {
            let mut transferred = 0;
            // SAFETY: private matching pair; wait=true is deliberate in Drop.
            // No deadline can justify freeing kernel-accessible memory early.
            let complete = unsafe {
                GetOverlappedResult(
                    self.directory.as_raw_handle() as HANDLE,
                    self.overlapped.get(),
                    &mut transferred,
                    1,
                )
            };
            if complete != 0 || !matches!(last_error(), ERROR_IO_INCOMPLETE | ERROR_IO_PENDING) {
                self.pending = false;
                break;
            }
        }
    }
}

fn rescan(reason: RescanReason) -> ObserverPoll {
    ObserverPoll::Batch(NotificationBatch::RescanRequired(reason))
}

fn last_error() -> u32 {
    // SAFETY: GetLastError has no pointer or ownership requirements.
    unsafe { GetLastError() }
}

fn root_changed() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "notification root changed")
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct DirectoryMetadata {
    form: DirectoryForm,
    tag: u32,
}

fn verify_directory(handle: HANDLE, expected: PinnedFileIdentity) -> io::Result<DirectoryMetadata> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: owned directory handle remains live and info is writable storage.
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let actual = PinnedFileIdentity {
        volume_serial: info.dwVolumeSerialNumber,
        file_index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    };
    if expected.file_index == 0 || actual != expected {
        return Err(root_changed());
    }
    let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: same live handle; exact SDK class/layout/size and writable output.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // A disagreement in directory/reparse type between independent queries is
    // uncertain, not permission to follow or reinterpret the object.
    let type_bits = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT;
    if info.dwFileAttributes & type_bits != tag.FileAttributes & type_bits {
        return Err(root_changed());
    }
    let form = directory_form(tag.FileAttributes, tag.ReparseTag).ok_or_else(root_changed)?;
    Ok(DirectoryMetadata {
        form,
        tag: tag.ReparseTag,
    })
}

#[cfg(test)]
#[path = "directory_notifications_native_tests.rs"]
mod tests;

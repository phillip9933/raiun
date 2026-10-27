//! A constrained VFS adapter used only by Windows synthetic tests.
//!
//! The adapter mediates every database and rollback-journal pathname through
//! `PrivateDirectory`, then holds a no-delete-sharing pin for the lifetime of
//! the lower Win32 VFS handle. SQLite's own Win32 I/O methods implement the
//! rollback lock protocol and durable file operations. WAL/shared-memory and
//! fetch/mmap are unavailable because the exposed I/O method version is 1.

use std::{
    ffi::{CStr, CString, OsStr, c_char, c_int, c_void},
    io,
    mem::{self, MaybeUninit},
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use raiun_control_windows::{
    PinnedFileIdentity, PinnedPrivateFile, PinnedPrivateFileAccess, PrivateDirectory,
};
use rusqlite::{
    Connection, OpenFlags, ffi,
    hooks::{AuthAction, AuthContext, Authorization},
};

const DATABASE_NAME: &str = "cache.sqlite3";
#[cfg(test)]
const JOURNAL_SUFFIX: &str = "-journal";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DatabasePurpose {
    Cache,
    #[cfg(feature = "trusted-engine-integration")]
    Engine,
}

impl DatabasePurpose {
    fn database_name(self) -> &'static str {
        match self {
            Self::Cache => DATABASE_NAME,
            #[cfg(feature = "trusted-engine-integration")]
            Self::Engine => "engine.sqlite3",
        }
    }

    fn wal_name(self) -> &'static str {
        match self {
            Self::Cache => "cache.sqlite3-wal",
            #[cfg(feature = "trusted-engine-integration")]
            Self::Engine => "engine.sqlite3-wal",
        }
    }

    fn journal_name(self) -> &'static str {
        match self {
            Self::Cache => "cache.sqlite3-journal",
            #[cfg(feature = "trusted-engine-integration")]
            Self::Engine => "engine.sqlite3-journal",
        }
    }
}

static NEXT_VFS_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixedFile {
    Database,
    Journal,
}

impl FixedFile {
    fn name(self, purpose: DatabasePurpose) -> &'static OsStr {
        match self {
            Self::Database => OsStr::new(purpose.database_name()),
            Self::Journal => OsStr::new(purpose.journal_name()),
        }
    }

    fn lower_path(self, context: &VfsContext) -> *const c_char {
        context.lower_filenames.path(self)
    }

    fn identity_slot(self, identities: &mut FileIdentities) -> &mut Option<PinnedFileIdentity> {
        match self {
            Self::Database => &mut identities.database,
            Self::Journal => &mut identities.journal,
        }
    }
}

#[derive(Default)]
struct FileIdentities {
    database: Option<PinnedFileIdentity>,
    journal: Option<PinnedFileIdentity>,
}

// Win32 SQLite consults URI metadata even for non-URI paths. Its filename
// helpers inspect bytes before/after the visible name, so a CString is not a
// valid lower xOpen filename. Own SQLite's complete filename allocation until
// the last context/file lease closes (or is deliberately retained on failure).
struct LowerFilenames {
    database: ffi::sqlite3_filename,
}

impl LowerFilenames {
    fn new(database: &CStr, journal: &CStr, wal: &CStr) -> rusqlite::Result<Self> {
        // SAFETY: the API copies the three NUL-terminated names; zero parameters
        // means azParam is never read. Only this owner frees the returned block.
        let filename = unsafe {
            ffi::sqlite3_create_filename(
                database.as_ptr(),
                journal.as_ptr(),
                wal.as_ptr(),
                0,
                ptr::null_mut(),
            )
        };
        if filename.is_null() {
            return Err(rusqlite::Error::SqliteFailure(
                ffi::Error::new(ffi::SQLITE_NOMEM),
                None,
            ));
        }
        Ok(Self { database: filename })
    }

    fn path(&self, kind: FixedFile) -> *const c_char {
        match kind {
            FixedFile::Database => self.database,
            // SAFETY: self.database is a live sqlite3_create_filename result;
            // the returned journal alias is borrowed from the same allocation.
            FixedFile::Journal => unsafe { ffi::sqlite3_filename_journal(self.database) },
        }
    }
}

impl Drop for LowerFilenames {
    fn drop(&mut self) {
        // SAFETY: the pointer comes from sqlite3_create_filename and is freed
        // exactly once, after all lower file/context borrowers have gone away.
        unsafe { ffi::sqlite3_free_filename(self.database) };
    }
}

struct VfsContext {
    purpose: DatabasePurpose,
    directory: PrivateDirectory,
    database_path: CString,
    journal_path: CString,
    lower_filenames: LowerFilenames,
    vfs_name: CString,
    lower_vfs: *mut ffi::sqlite3_vfs,
    identities: Mutex<FileIdentities>,
    database_open: AtomicBool,
    closing: AtomicBool,
    close_complete: AtomicBool,
    file_close_failed: AtomicBool,
}

#[repr(C)]
struct AdapterFile {
    base: ffi::sqlite3_file,
    lower_storage: Vec<u64>,
    pin: Option<PinnedPrivateFile<'static>>,
    kind: FixedFile,
    identity: PinnedFileIdentity,
    database_slot_claimed: bool,
    context: Arc<VfsContext>,
}

/// A registered one-database VFS plus its connection.
///
/// The connection is always closed before the VFS registration and its pinned
/// directory are released. This is a test harness, not a general-purpose
/// SQLite connection type.
pub struct RegisteredRollbackDb {
    connection: Option<Connection>,
    registration: Option<VfsRegistration>,
}

// SAFETY: moving the owner never relocates its Arc context, boxed VFS or
// published process-lifetime slot/name. Connection is Send but not Sync; its
// owner is not Sync, so cross-thread connection access requires an external
// mutex. Borrowed connections retain the owner's lifetime. Independent VFS
// callbacks hold synchronized context leases, open files retain their context,
// and Closing drains admission before
// teardown. Win32 file handles have no thread affinity. Checked close/BUSY and
// uncertain lower-close paths preserve every live allocation instead of
// freeing it. This is ownership transfer only: no Sync implementation is made.
unsafe impl Send for RegisteredRollbackDb {}

// SQLite callers may retain a VFS pointer obtained before unregister. The
// tiny VFS/name/slot tombstone therefore has process lifetime. Live directory
// handles and data are leased independently and are reclaimed after callbacks
// and opened files release their Arcs.
struct ContextSlot(Mutex<Option<Arc<VfsContext>>>);

// A callback holds the slot lock throughout its operation. Closing therefore
// waits for already-admitted callbacks before blocking future opens, and final
// retirement drains callbacks before dropping the live registration reference.
struct ContextLease(std::sync::MutexGuard<'static, Option<Arc<VfsContext>>>);

impl ContextLease {
    fn arc(&self) -> &Arc<VfsContext> {
        self.0.as_ref().expect("active callback context")
    }
}

impl std::ops::Deref for ContextLease {
    type Target = VfsContext;
    fn deref(&self) -> &Self::Target {
        self.arc()
    }
}

// SAFETY: the VFS raw pointer selects SQLite's process-lifetime built-in
// Win32 VFS. The owned SQLite filename allocation is immutable and survives
// every callback/file through its context lease. Win32 VFS callbacks support
// concurrent callers. Other shared mutable fields use Mutex/atomics, and the pinned
// directory/files contain owned, thread-neutral Win32 handles.
unsafe impl Send for VfsContext {}
unsafe impl Sync for VfsContext {}

struct VfsRegistration {
    context: Arc<VfsContext>,
    slot: &'static ContextSlot,
    vfs: Box<ffi::sqlite3_vfs>,
    registered: bool,
}

impl RegisteredRollbackDb {
    /// Open the fixed test database beneath a validated private directory.
    pub fn open(directory: PrivateDirectory) -> rusqlite::Result<Self> {
        Self::open_for(directory, DatabasePurpose::Cache)
    }

    /// Open only engine.sqlite3 and its rollback journal beneath the held
    /// private directory. This does not admit WAL, other databases, or paths.
    #[cfg(feature = "trusted-engine-integration")]
    pub fn open_engine(directory: PrivateDirectory) -> rusqlite::Result<Self> {
        Self::open_for(directory, DatabasePurpose::Engine)
    }

    /// Open an existing engine database without creating it or initializing
    /// engine schema. This is protected rollback-mode access, not physically
    /// read-only: SQLite may recover an existing hot journal. Callers performing
    /// inventory must issue only bounded reads and never treat saved scope as auth.
    #[cfg(feature = "trusted-engine-integration")]
    pub fn open_engine_existing(directory: PrivateDirectory) -> rusqlite::Result<Self> {
        Self::open_for_with_creation(directory, DatabasePurpose::Engine, false)
    }

    fn open_for(directory: PrivateDirectory, purpose: DatabasePurpose) -> rusqlite::Result<Self> {
        Self::open_for_with_creation(directory, purpose, true)
    }

    fn open_for_with_creation(
        directory: PrivateDirectory,
        purpose: DatabasePurpose,
        create: bool,
    ) -> rusqlite::Result<Self> {
        let registration = VfsRegistration::new_for(directory, purpose)?;
        let context = &*registration.context;
        let db_path = context.database_path.to_str().map_err(|_| {
            rusqlite::Error::InvalidPath(PathBuf::from(context.purpose.database_name()))
        })?;
        let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        if create {
            flags |= OpenFlags::SQLITE_OPEN_CREATE;
        }
        let connection = Connection::open_with_flags_and_vfs(
            db_path,
            flags,
            context.vfs_name.to_str().unwrap_or_default(),
        )?;
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("delete") {
            return Err(rusqlite::Error::InvalidQuery);
        }
        connection.execute_batch("PRAGMA temp_store=MEMORY; PRAGMA synchronous=FULL;")?;
        #[allow(clippy::if_same_then_else)] // Keep each denied policy explicit.
        connection.authorizer(Some(|context: AuthContext<'_>| match context.action {
            AuthAction::Attach { .. }
            | AuthAction::Detach { .. }
            | AuthAction::CreateTempIndex { .. }
            | AuthAction::CreateTempTable { .. }
            | AuthAction::CreateTempTrigger { .. }
            | AuthAction::CreateTempView { .. }
            | AuthAction::DropTempIndex { .. }
            | AuthAction::DropTempTable { .. }
            | AuthAction::DropTempTrigger { .. }
            | AuthAction::DropTempView { .. } => Authorization::Deny,
            AuthAction::Pragma {
                pragma_name,
                pragma_value,
            } => {
                if pragma_name.eq_ignore_ascii_case("journal_mode")
                    && pragma_value.is_some_and(|value| !value.eq_ignore_ascii_case("delete"))
                {
                    Authorization::Deny
                } else if pragma_name.eq_ignore_ascii_case("synchronous")
                    && pragma_value
                        .is_some_and(|value| !value.eq_ignore_ascii_case("full") && value != "2")
                {
                    Authorization::Deny
                } else if pragma_name.eq_ignore_ascii_case("temp_store")
                    && pragma_value
                        .is_some_and(|value| !value.eq_ignore_ascii_case("memory") && value != "2")
                {
                    Authorization::Deny
                } else if pragma_name.eq_ignore_ascii_case("temp_store_directory") {
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }
            _ => Authorization::Allow,
        }));
        Ok(Self {
            connection: Some(connection),
            registration: Some(registration),
        })
    }

    /// Borrow for trusted cache implementation code while keeping the connection
    /// and VFS owner together. This feature is not a sandbox for arbitrary SQL
    /// consumers: callers must not replace the authorizer or alter durability
    /// settings. Never expose this bridge through the public Cache API.
    ///
    /// Only a shared connection reference is lent: a mutable reference would
    /// let safe callers replace/take the connection and outlive its VFS owner.
    /// Borrowed statements and transactions cannot outlive this owner.
    /// Ownership may move between threads, but the owner is not Sync; callers
    /// that share it must serialize every operation with an external mutex.
    #[cfg(feature = "trusted-cache-integration")]
    pub fn borrow_cache_connection(&self) -> &Connection {
        self.connection
            .as_ref()
            .expect("registered connection is live")
    }

    /// Lend the fixed engine connection while this owner retains its VFS and
    /// directory pins. Mutable extraction and ownership escape are unavailable.
    #[cfg(feature = "trusted-engine-integration")]
    pub fn borrow_engine_connection(&self) -> &Connection {
        assert!(self.registration.as_ref().is_some_and(|registration|
            registration.context.purpose == DatabasePurpose::Engine));
        self.connection
            .as_ref()
            .expect("registered connection is live")
    }

    /// Execute an owned-result operation through the trusted cache bridge.
    /// The higher-ranked callback prevents borrowed statements from escaping.
    #[cfg(feature = "trusted-cache-integration")]
    pub fn with_cache_connection<T>(
        &mut self,
        operation: impl for<'a> FnOnce(&'a Connection) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        operation(
            self.connection
                .as_ref()
                .expect("registered connection is live"),
        )
    }

    #[cfg(test)]
    fn connection(&self) -> &Connection {
        self.connection
            .as_ref()
            .expect("registered connection is live")
    }

    /// Close SQLite before unregistering its VFS. If close fails, this returns
    /// the still-live wrapper so the caller may close outstanding statements.
    #[allow(clippy::result_large_err)] // Preserve ownership on SQLite BUSY.
    pub fn close(mut self) -> Result<(), (Self, rusqlite::Error)> {
        if let Some(registration) = &self.registration {
            registration.deactivate();
        }
        let Some(connection) = self.connection.take() else {
            return Ok(());
        };
        match connection.close() {
            Ok(()) => {
                if let Some(registration) = &self.registration {
                    registration.finish_close();
                }
                self.registration.take();
                Ok(())
            }
            Err((connection, error)) => {
                self.connection = Some(connection);
                Err((self, error))
            }
        }
    }
}

impl Drop for RegisteredRollbackDb {
    fn drop(&mut self) {
        if let Some(registration) = &self.registration {
            registration.deactivate();
        }
        if let Some(connection) = self.connection.take() {
            if let Err((connection, _error)) = connection.close() {
                // sqlite3_close can return BUSY while a forgotten statement or
                // blob is alive. Keep the registered VFS/context alive too;
                // leaking is safer than leaving SQLite with dangling pointers.
                mem::forget(connection);
                if let Some(registration) = self.registration.take() {
                    mem::forget(registration);
                }
                return;
            }
        }
        if let Some(registration) = &self.registration {
            registration.finish_close();
        }
        self.registration.take();
    }
}

impl VfsRegistration {
    #[cfg(test)]
    fn new(directory: PrivateDirectory) -> rusqlite::Result<Self> {
        Self::new_for(directory, DatabasePurpose::Cache)
    }

    fn new_for(directory: PrivateDirectory, purpose: DatabasePurpose) -> rusqlite::Result<Self> {
        directory
            .verify_path()
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        let database_path_buf = directory.path().join(purpose.database_name());
        let database_path = path_to_c_string(&database_path_buf)?;
        let journal_path = path_to_c_string(&directory.path().join(purpose.journal_name()))?;
        // Keep public path matching in the original DOS spelling. Only the
        // trusted lower Win32 open receives a canonical extended-length alias.
        // Held directory pins and both verifications reject path replacement.
        let lower_root = std::fs::canonicalize(directory.path())
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        if !matches!(lower_root.components().next(),
            Some(std::path::Component::Prefix(prefix))
                if matches!(prefix.kind(), std::path::Prefix::VerbatimDisk(_)))
        {
            return Err(rusqlite::Error::InvalidPath(lower_root));
        }
        directory
            .verify_path()
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        let database_lower_path = path_to_c_string(&lower_root.join(purpose.database_name()))?;
        let journal_lower_path = path_to_c_string(&lower_root.join(purpose.journal_name()))?;
        // SQLite's metadata allocation contains all three fixed names even
        // though this adapter never admits WAL opens.
        let wal_lower_path = path_to_c_string(&lower_root.join(purpose.wal_name()))?;
        let lower_filenames =
            LowerFilenames::new(&database_lower_path, &journal_lower_path, &wal_lower_path)?;
        // The process default can be replaced by another registered shim or
        // a no-lock VFS. This adapter requires SQLite's standard Win32 locking
        // implementation explicitly; never inherit a mutable default. The
        // longpath variant has the same locking callbacks and a larger path
        // buffer; it still requires the extended alias supplied above.
        let lower_vfs = unsafe { ffi::sqlite3_vfs_find(c"win32-longpath".as_ptr()) };
        if lower_vfs.is_null() {
            return Err(rusqlite::Error::SqliteFailure(
                ffi::Error::new(ffi::SQLITE_NOTFOUND),
                Some("system SQLite VFS unavailable".into()),
            ));
        }

        let id = NEXT_VFS_ID.fetch_add(1, Ordering::Relaxed);
        let vfs_name = CString::new(format!("raiun_rollback_test_{id}"))
            .expect("generated VFS name has no NUL");
        let context = Arc::new(VfsContext {
            purpose,
            directory,
            database_path,
            journal_path,
            lower_filenames,
            vfs_name,
            lower_vfs,
            identities: Mutex::new(FileIdentities::default()),
            database_open: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            close_complete: AtomicBool::new(false),
            file_close_failed: AtomicBool::new(false),
        });

        let lower = unsafe { &*context.lower_vfs };
        if lower.xOpen.is_none()
            || lower.xRandomness.is_none()
            || lower.xSleep.is_none()
            || lower.xCurrentTime.is_none()
        {
            return Err(rusqlite::Error::SqliteFailure(
                ffi::Error::new(ffi::SQLITE_NOTFOUND),
                Some("system SQLite VFS lacks required callbacks".into()),
            ));
        }
        let mut vfs = Box::new(unsafe { MaybeUninit::<ffi::sqlite3_vfs>::zeroed().assume_init() });
        vfs.iVersion = 1;
        vfs.szOsFile = i32::try_from(mem::size_of::<AdapterFile>()).map_err(|_| {
            rusqlite::Error::SqliteFailure(
                ffi::Error::new(ffi::SQLITE_MISUSE),
                Some("SQLite file structure is too large".into()),
            )
        })?;
        vfs.mxPathname = lower.mxPathname;
        vfs.zName = context.vfs_name.clone().into_raw();
        let slot = Box::leak(Box::new(ContextSlot(Mutex::new(Some(Arc::clone(
            &context,
        ))))));
        vfs.pAppData = (slot as *const ContextSlot).cast_mut().cast();
        vfs.xOpen = Some(vfs_open);
        vfs.xDelete = Some(vfs_delete);
        vfs.xAccess = Some(vfs_access);
        vfs.xFullPathname = Some(vfs_full_pathname);
        vfs.xRandomness = Some(vfs_randomness);
        vfs.xSleep = Some(vfs_sleep);
        vfs.xCurrentTime = Some(vfs_current_time);
        vfs.xGetLastError = Some(vfs_get_last_error);

        let register_result = unsafe { ffi::sqlite3_vfs_register(&mut *vfs, 0) };
        if register_result != ffi::SQLITE_OK {
            slot.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            return Err(rusqlite::Error::SqliteFailure(
                ffi::Error::new(register_result),
                Some("could not register rollback test VFS".into()),
            ));
        }
        Ok(Self {
            context,
            slot,
            vfs,
            registered: true,
        })
    }
}

impl VfsRegistration {
    fn deactivate(&self) {
        let slot = self
            .slot
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(context) = slot.as_ref() {
            context.closing.store(true, Ordering::Release);
        }
    }
    fn finish_close(&self) {
        let slot = self
            .slot
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(context) = slot.as_ref() {
            context.close_complete.store(true, Ordering::Release);
        }
    }
}

impl Drop for VfsRegistration {
    fn drop(&mut self) {
        self.deactivate();
        self.slot
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if self.registered {
            let result = unsafe { ffi::sqlite3_vfs_unregister(&mut *self.vfs) };
            if result != ffi::SQLITE_OK {
                std::process::abort();
            }
            self.registered = false;
            // Never free a published VFS: a safe SQLite caller may already
            // hold its pointer. Its permanently inactive slot rejects entry.
            let tombstone = mem::replace(
                &mut self.vfs,
                Box::new(unsafe { MaybeUninit::zeroed().assume_init() }),
            );
            mem::forget(tombstone);
        }
    }
}

fn path_to_c_string(path: &Path) -> rusqlite::Result<CString> {
    if !path.is_absolute() {
        return Err(rusqlite::Error::InvalidPath(path.to_owned()));
    }
    let text = path
        .to_str()
        .ok_or_else(|| rusqlite::Error::InvalidPath(path.to_owned()))?;
    CString::new(text).map_err(|_| rusqlite::Error::InvalidPath(path.to_owned()))
}

fn file_kind_for_flags(flags: c_int) -> Result<FixedFile, c_int> {
    let kind = flags & (ffi::SQLITE_OPEN_MAIN_DB | ffi::SQLITE_OPEN_MAIN_JOURNAL);
    if kind == ffi::SQLITE_OPEN_MAIN_DB {
        Ok(FixedFile::Database)
    } else if kind == ffi::SQLITE_OPEN_MAIN_JOURNAL {
        Ok(FixedFile::Journal)
    } else {
        Err(ffi::SQLITE_CANTOPEN)
    }
}

fn file_kind_for_name(context: &VfsContext, name: &CStr) -> Option<FixedFile> {
    if name == context.database_path.as_c_str() {
        Some(FixedFile::Database)
    } else if name == context.journal_path.as_c_str() {
        Some(FixedFile::Journal)
    } else {
        None
    }
}

fn context_from_vfs(vfs: *mut ffi::sqlite3_vfs) -> Option<ContextLease> {
    if vfs.is_null() {
        return None;
    }
    // Published VFS/slot allocations have process lifetime, including after
    // unregister; late callbacks can safely observe the retired empty slot.
    let slot: &'static ContextSlot = unsafe { (*vfs).pAppData.cast::<ContextSlot>().as_ref() }?;
    let lease = ContextLease(
        slot.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    if lease
        .0
        .as_ref()
        .is_some_and(|context| !context.close_complete.load(Ordering::Acquire))
    {
        Some(lease)
    } else {
        None
    }
}

fn lower_file(file: *mut ffi::sqlite3_file) -> Option<*mut ffi::sqlite3_file> {
    if file.is_null() {
        return None;
    }
    let outer = unsafe { &mut *file.cast::<AdapterFile>() };
    if outer.lower_storage.is_empty() {
        return None;
    }
    Some(outer.lower_storage.as_mut_ptr().cast::<ffi::sqlite3_file>())
}

fn lower_methods(file: *mut ffi::sqlite3_file) -> Option<&'static ffi::sqlite3_io_methods> {
    let lower = lower_file(file)?;
    let methods = unsafe { (*lower).pMethods.as_ref() }?;
    (methods.iVersion >= 1).then_some(methods)
}

fn map_io_error(error: &io::Error) -> c_int {
    match error.kind() {
        io::ErrorKind::NotFound => ffi::SQLITE_CANTOPEN,
        io::ErrorKind::PermissionDenied => ffi::SQLITE_PERM,
        io::ErrorKind::AlreadyExists => ffi::SQLITE_CANTOPEN,
        _ => ffi::SQLITE_IOERR,
    }
}

fn pinned_file(
    context: &VfsContext,
    kind: FixedFile,
    flags: c_int,
) -> Result<(PinnedPrivateFile<'static>, bool), c_int> {
    let wants_create = flags & ffi::SQLITE_OPEN_CREATE != 0;
    let exclusive = flags & ffi::SQLITE_OPEN_EXCLUSIVE != 0;
    if exclusive && !wants_create {
        return Err(ffi::SQLITE_CANTOPEN);
    }

    let directory = &context.directory as *const PrivateDirectory;
    // The registration owns the directory, and every SQLite file is closed
    // before the registration. This is the lifetime invariant for the erased
    // borrow stored in the C-allocated sqlite3_file.
    let directory = unsafe { &*directory };
    let existing = directory.open_pinned_file(
        kind.name(context.purpose),
        PinnedPrivateFileAccess::ReadWrite,
    );
    let (pin, created) = match existing {
        Ok(_pin) if exclusive => return Err(ffi::SQLITE_CANTOPEN),
        Ok(pin) => (pin, false),
        Err(error) if error.kind() == io::ErrorKind::NotFound && wants_create => {
            match directory.create_new_pinned_file(kind.name(context.purpose)) {
                Ok(pin) => (pin, true),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists && !exclusive => {
                    let pin = directory
                        .open_pinned_file(
                            kind.name(context.purpose),
                            PinnedPrivateFileAccess::ReadWrite,
                        )
                        .map_err(|error| map_io_error(&error))?;
                    (pin, false)
                }
                Err(error) => return Err(map_io_error(&error)),
            }
        }
        Err(error) => return Err(map_io_error(&error)),
    };

    let identity = pin.identity();
    {
        let mut identities = context
            .identities
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let slot = kind.identity_slot(&mut identities);
        if slot.is_some_and(|expected| expected != identity) {
            drop(pin);
            return Err(ffi::SQLITE_CANTOPEN);
        }
        *slot = Some(identity);
    }

    // PrivateDirectory lives in a stable Arc allocation. AdapterFile retains
    // that Arc until after dropping this pin, even if registration is retired.
    let pin = unsafe { mem::transmute::<PinnedPrivateFile<'_>, PinnedPrivateFile<'static>>(pin) };
    Ok((pin, created))
}

fn allocate_lower_file(lower_vfs: *mut ffi::sqlite3_vfs) -> Result<Vec<u64>, c_int> {
    if lower_vfs.is_null() {
        return Err(ffi::SQLITE_CANTOPEN);
    }
    let size = unsafe { (*lower_vfs).szOsFile };
    if size <= 0 || size as usize > 1024 * 1024 {
        return Err(ffi::SQLITE_CANTOPEN);
    }
    let words = (size as usize).div_ceil(mem::size_of::<u64>());
    Ok(vec![0; words])
}

fn open_with_pin(
    context: &Arc<VfsContext>,
    file: *mut ffi::sqlite3_file,
    kind: FixedFile,
    flags: c_int,
    out_flags: *mut c_int,
) -> Result<(), c_int> {
    if context.closing.load(Ordering::Acquire) {
        return Err(ffi::SQLITE_CANTOPEN);
    }
    if file.is_null() || out_flags.is_null() {
        return Err(ffi::SQLITE_MISUSE);
    }
    unsafe {
        (*file).pMethods = ptr::null();
        *out_flags = 0;
    }

    let allowed_flags = ffi::SQLITE_OPEN_READWRITE
        | ffi::SQLITE_OPEN_READONLY
        | ffi::SQLITE_OPEN_CREATE
        | ffi::SQLITE_OPEN_EXCLUSIVE
        | ffi::SQLITE_OPEN_NOMUTEX
        | ffi::SQLITE_OPEN_FULLMUTEX
        | ffi::SQLITE_OPEN_SHAREDCACHE
        | ffi::SQLITE_OPEN_PRIVATECACHE
        | ffi::SQLITE_OPEN_NOFOLLOW
        | ffi::SQLITE_OPEN_MAIN_DB
        | ffi::SQLITE_OPEN_MAIN_JOURNAL;
    if flags & !allowed_flags != 0
        || flags & ffi::SQLITE_OPEN_READWRITE == 0
        || flags & ffi::SQLITE_OPEN_READONLY != 0
    {
        return Err(ffi::SQLITE_CANTOPEN);
    }
    if flags & ffi::SQLITE_OPEN_DELETEONCLOSE != 0 {
        return Err(ffi::SQLITE_CANTOPEN);
    }
    if kind == FixedFile::Database
        && context
            .database_open
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return Err(ffi::SQLITE_BUSY);
    }

    let (pin, created) = match pinned_file(context, kind, flags) {
        Ok(result) => result,
        Err(error) => {
            if kind == FixedFile::Database {
                context.database_open.store(false, Ordering::Release);
            }
            return Err(error);
        }
    };
    let identity = pin.identity();
    let lower_storage = match allocate_lower_file(context.lower_vfs) {
        Ok(storage) => storage,
        Err(error) => {
            drop(pin);
            cleanup_created(context, kind, identity, created);
            if kind == FixedFile::Database {
                context.database_open.store(false, Ordering::Release);
            }
            return Err(error);
        }
    };

    let mut outer = AdapterFile {
        base: ffi::sqlite3_file {
            pMethods: ptr::null(),
        },
        lower_storage,
        pin: Some(pin),
        kind,
        identity,
        database_slot_claimed: kind == FixedFile::Database,
        context: Arc::clone(context),
    };
    let lower_ptr = outer.lower_storage.as_mut_ptr().cast::<ffi::sqlite3_file>();
    let lower_open = unsafe { (*context.lower_vfs).xOpen };
    let Some(lower_open) = lower_open else {
        drop(outer);
        cleanup_created(context, kind, identity, created);
        if kind == FixedFile::Database {
            context.database_open.store(false, Ordering::Release);
        }
        return Err(ffi::SQLITE_CANTOPEN);
    };

    // The private pin already created an absent entry, so lower CREATE and
    // EXCLUSIVE must be removed. For an existing entry, CREATE is harmless but
    // removing it makes the lower VFS open-existing only in both cases.
    let lower_flags = flags
        & !(ffi::SQLITE_OPEN_CREATE
            | ffi::SQLITE_OPEN_EXCLUSIVE
            | ffi::SQLITE_OPEN_DELETEONCLOSE
            | ffi::SQLITE_OPEN_NOMUTEX
            | ffi::SQLITE_OPEN_FULLMUTEX
            | ffi::SQLITE_OPEN_SHAREDCACHE
            | ffi::SQLITE_OPEN_PRIVATECACHE
            | ffi::SQLITE_OPEN_NOFOLLOW);
    let path = kind.lower_path(context);
    let mut actual_flags = 0;
    let result = unsafe {
        lower_open(
            context.lower_vfs,
            path,
            lower_ptr,
            lower_flags,
            &mut actual_flags,
        )
    };
    if result != ffi::SQLITE_OK {
        if close_rejected_lower(outer, false) {
            cleanup_created(context, kind, identity, created);
            if kind == FixedFile::Database {
                context.database_open.store(false, Ordering::Release);
            }
        }
        return Err(result);
    }

    let methods = unsafe { (*lower_ptr).pMethods.as_ref() };
    let Some(methods) = methods else {
        close_rejected_lower(outer, true);
        return Err(ffi::SQLITE_IOERR);
    };
    if methods.iVersion < 1
        || methods.xClose.is_none()
        || methods.xRead.is_none()
        || methods.xWrite.is_none()
        || methods.xTruncate.is_none()
        || methods.xSync.is_none()
        || methods.xFileSize.is_none()
        || methods.xLock.is_none()
        || methods.xUnlock.is_none()
        || methods.xCheckReservedLock.is_none()
        || methods.xFileControl.is_none()
        || methods.xSectorSize.is_none()
        || methods.xDeviceCharacteristics.is_none()
    {
        if close_rejected_lower(outer, true) {
            cleanup_created(context, kind, identity, created);
            if kind == FixedFile::Database {
                context.database_open.store(false, Ordering::Release);
            }
        }
        return Err(ffi::SQLITE_IOERR);
    }

    outer.base.pMethods = &IO_METHODS;
    unsafe {
        ptr::write(file.cast::<AdapterFile>(), outer);
        *out_flags = actual_flags;
    }
    Ok(())
}

// A rejected lower xOpen can still leave a live file (pMethods != NULL).
// Only clean up its path or release its claim after a confirmed successful
// xClose. On uncertain close, retain the entire capsule, including lower file
// storage, private pin and context lease, until process exit. This deliberately
// sacrifices bounded memory on an exceptional I/O failure to preserve recovery.
fn close_rejected_lower(mut outer: AdapterFile, open_succeeded: bool) -> bool {
    let lower = outer.lower_storage.as_mut_ptr().cast::<ffi::sqlite3_file>();
    let methods = unsafe { (*lower).pMethods.as_ref() };
    let closed = match methods {
        Some(methods) => methods
            .xClose
            .is_some_and(|close| unsafe { close(lower) } == ffi::SQLITE_OK),
        None => !open_succeeded,
    };
    if closed {
        drop(outer);
        true
    } else {
        outer
            .context
            .file_close_failed
            .store(true, Ordering::Release);
        mem::forget(outer);
        false
    }
}

fn cleanup_created(
    context: &VfsContext,
    kind: FixedFile,
    identity: PinnedFileIdentity,
    created: bool,
) {
    if created {
        let _ = delete_expected(context, kind, identity);
    }
}

fn delete_expected(
    context: &VfsContext,
    kind: FixedFile,
    expected: PinnedFileIdentity,
) -> io::Result<()> {
    if kind == FixedFile::Database {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "test VFS never deletes the main database",
        ));
    }
    if context.file_close_failed.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "rollback journal close failed; preserve it for recovery",
        ));
    }
    let candidate = context
        .directory
        .open_delete_candidate(kind.name(context.purpose), expected)?;
    candidate.delete()?;
    let mut identities = context
        .identities
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *kind.identity_slot(&mut identities) = None;
    Ok(())
}

fn adapter_file(file: *mut ffi::sqlite3_file) -> Option<&'static mut AdapterFile> {
    if file.is_null() || unsafe { (*file).pMethods.is_null() } {
        None
    } else {
        Some(unsafe { &mut *file.cast::<AdapterFile>() })
    }
}

fn callback_rc(default: c_int, operation: impl FnOnce() -> c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(default)
}

unsafe extern "C" fn vfs_open(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    callback_rc(ffi::SQLITE_CANTOPEN, || {
        if file.is_null() || name.is_null() {
            return ffi::SQLITE_MISUSE;
        }
        // SQLite passes NULL pOutFlags for journal opens; it is optional.
        let mut ignored_flags = 0;
        let out_flags = if out_flags.is_null() {
            &mut ignored_flags
        } else {
            out_flags
        };
        unsafe {
            (*file).pMethods = ptr::null();
            *out_flags = 0;
        }
        let Some(context) = context_from_vfs(vfs) else {
            return ffi::SQLITE_MISUSE;
        };
        let requested = unsafe { CStr::from_ptr(name) };
        let Some(kind_from_name) = file_kind_for_name(&context, requested) else {
            return ffi::SQLITE_CANTOPEN;
        };
        let Ok(kind_from_flags) = file_kind_for_flags(flags) else {
            return ffi::SQLITE_CANTOPEN;
        };
        if kind_from_name != kind_from_flags {
            return ffi::SQLITE_CANTOPEN;
        }
        match open_with_pin(context.arc(), file, kind_from_name, flags, out_flags) {
            Ok(()) => ffi::SQLITE_OK,
            Err(error) => error,
        }
    })
}

unsafe extern "C" fn vfs_delete(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    _sync_dir: c_int,
) -> c_int {
    callback_rc(ffi::SQLITE_IOERR_DELETE, || {
        if name.is_null() {
            return ffi::SQLITE_MISUSE;
        }
        let Some(context) = context_from_vfs(vfs) else {
            return ffi::SQLITE_MISUSE;
        };
        let requested = unsafe { CStr::from_ptr(name) };
        let Some(kind) = file_kind_for_name(&context, requested) else {
            return ffi::SQLITE_IOERR_DELETE;
        };
        if kind != FixedFile::Journal {
            return ffi::SQLITE_IOERR_DELETE;
        }
        let expected = {
            let identities = context
                .identities
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match kind {
                FixedFile::Database => identities.database,
                FixedFile::Journal => identities.journal,
            }
        };
        let Some(expected) = expected else {
            return ffi::SQLITE_IOERR_DELETE_NOENT;
        };
        match delete_expected(&context, kind, expected) {
            Ok(()) => ffi::SQLITE_OK,
            Err(error) if error.kind() == io::ErrorKind::NotFound => ffi::SQLITE_IOERR_DELETE_NOENT,
            Err(error) => map_io_error(&error),
        }
    })
}

unsafe extern "C" fn vfs_access(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    flags: c_int,
    out: *mut c_int,
) -> c_int {
    callback_rc(ffi::SQLITE_IOERR_ACCESS, || {
        if name.is_null() || out.is_null() {
            return ffi::SQLITE_MISUSE;
        }
        unsafe { *out = 0 };
        let Some(context) = context_from_vfs(vfs) else {
            return ffi::SQLITE_MISUSE;
        };
        let requested = unsafe { CStr::from_ptr(name) };
        // SQLite probes for a pre-existing WAL even when opening a rollback
        // database. Only report absence after checking the exact anchored name;
        // an existing WAL must fail closed rather than be hidden from recovery.
        let mut wal_name = context.database_path.as_bytes().to_vec();
        wal_name.extend_from_slice(b"-wal");
        if flags == ffi::SQLITE_ACCESS_EXISTS && requested.to_bytes() == wal_name {
            return match context.directory.open_pinned_file(
                OsStr::new(context.purpose.wal_name()),
                PinnedPrivateFileAccess::ReadOnly,
            ) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => ffi::SQLITE_OK,
                _ => ffi::SQLITE_CANTOPEN,
            };
        }
        let Some(kind) = file_kind_for_name(&context, requested) else {
            return ffi::SQLITE_CANTOPEN;
        };
        let access = if flags == ffi::SQLITE_ACCESS_READWRITE {
            PinnedPrivateFileAccess::ReadWrite
        } else if flags == ffi::SQLITE_ACCESS_EXISTS || flags == ffi::SQLITE_ACCESS_READ {
            PinnedPrivateFileAccess::ReadOnly
        } else {
            return ffi::SQLITE_IOERR_ACCESS;
        };
        match context
            .directory
            .open_pinned_file(kind.name(context.purpose), access)
        {
            Ok(pin) => {
                let mut identities = context
                    .identities
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let slot = kind.identity_slot(&mut identities);
                if slot.is_some_and(|expected| expected != pin.identity()) {
                    return ffi::SQLITE_IOERR_ACCESS;
                }
                *slot = Some(pin.identity());
                unsafe { *out = 1 };
                ffi::SQLITE_OK
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => ffi::SQLITE_OK,
            Err(error) => map_io_error(&error),
        }
    })
}

unsafe extern "C" fn vfs_full_pathname(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    output_size: c_int,
    output: *mut c_char,
) -> c_int {
    callback_rc(ffi::SQLITE_CANTOPEN, || {
        if name.is_null() || output.is_null() || output_size <= 0 {
            return ffi::SQLITE_MISUSE;
        }
        unsafe { *output = 0 };
        let Some(context) = context_from_vfs(vfs) else {
            return ffi::SQLITE_MISUSE;
        };
        let requested = unsafe { CStr::from_ptr(name) };
        let alias_matches = requested.to_bytes() == context.purpose.database_name().as_bytes()
            || requested == context.database_path.as_c_str();
        if !alias_matches {
            return ffi::SQLITE_CANTOPEN;
        }
        let path = context.database_path.as_bytes_with_nul();
        if path.len() > output_size as usize {
            return ffi::SQLITE_CANTOPEN;
        }
        unsafe { ptr::copy_nonoverlapping(path.as_ptr().cast::<c_char>(), output, path.len()) };
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn file_close(file: *mut ffi::sqlite3_file) -> c_int {
    callback_rc(ffi::SQLITE_IOERR_CLOSE, || {
        let Some(outer) = adapter_file(file) else {
            return ffi::SQLITE_MISUSE;
        };
        let context = Arc::clone(&outer.context);
        let claimed_database = outer.database_slot_claimed;
        let lower = outer.lower_storage.as_mut_ptr().cast::<ffi::sqlite3_file>();
        let close = unsafe { (*lower).pMethods.as_ref() }.and_then(|methods| methods.xClose);
        let result = close.map_or(ffi::SQLITE_IOERR_CLOSE, |close| unsafe { close(lower) });
        // SQLite frees the outer sqlite3_file after xClose even on error.
        // Move its owned fields out before that happens. On uncertain lower
        // close, keep ALL lower storage/pins/context alive until process exit.
        let capsule = unsafe { ptr::read(file.cast::<AdapterFile>()) };
        unsafe {
            (*file).pMethods = ptr::null();
        }
        if result == ffi::SQLITE_OK {
            drop(capsule);
            if claimed_database {
                context.database_open.store(false, Ordering::Release);
            }
        } else {
            context.file_close_failed.store(true, Ordering::Release);
            mem::forget(capsule);
        }
        result
    })
}

macro_rules! delegate_file_call {
    ($name:ident, $field:ident, ($($arg:ident : $arg_ty:ty),*), $default:expr) => {
        unsafe extern "C" fn $name(file: *mut ffi::sqlite3_file, $($arg: $arg_ty),*) -> c_int {
            callback_rc($default, || {
                let Some(methods) = lower_methods(file) else { return ffi::SQLITE_IOERR; };
                let Some(function) = methods.$field else { return ffi::SQLITE_NOTFOUND; };
                let Some(lower) = lower_file(file) else { return ffi::SQLITE_IOERR; };
                unsafe { function(lower, $($arg),*) }
            })
        }
    };
}

delegate_file_call!(file_read, xRead, (buffer: *mut c_void, amount: c_int, offset: ffi::sqlite3_int64), ffi::SQLITE_IOERR_READ);
delegate_file_call!(file_write, xWrite, (buffer: *const c_void, amount: c_int, offset: ffi::sqlite3_int64), ffi::SQLITE_IOERR_WRITE);
delegate_file_call!(file_truncate, xTruncate, (size: ffi::sqlite3_int64), ffi::SQLITE_IOERR_TRUNCATE);
delegate_file_call!(file_sync, xSync, (flags: c_int), ffi::SQLITE_IOERR_FSYNC);
delegate_file_call!(file_lock, xLock, (lock: c_int), ffi::SQLITE_IOERR_LOCK);
delegate_file_call!(file_unlock, xUnlock, (lock: c_int), ffi::SQLITE_IOERR_UNLOCK);
delegate_file_call!(file_check_reserved, xCheckReservedLock, (reserved: *mut c_int), ffi::SQLITE_IOERR_CHECKRESERVEDLOCK);

unsafe extern "C" fn file_size(
    file: *mut ffi::sqlite3_file,
    size: *mut ffi::sqlite3_int64,
) -> c_int {
    callback_rc(ffi::SQLITE_IOERR_FSTAT, || {
        if size.is_null() {
            return ffi::SQLITE_MISUSE;
        }
        unsafe { *size = 0 };
        let Some(methods) = lower_methods(file) else {
            return ffi::SQLITE_IOERR_FSTAT;
        };
        let Some(function) = methods.xFileSize else {
            return ffi::SQLITE_NOTFOUND;
        };
        let Some(lower) = lower_file(file) else {
            return ffi::SQLITE_IOERR_FSTAT;
        };
        unsafe { function(lower, size) }
    })
}

unsafe extern "C" fn file_control(
    file: *mut ffi::sqlite3_file,
    operation: c_int,
    argument: *mut c_void,
) -> c_int {
    callback_rc(ffi::SQLITE_NOTFOUND, || {
        let Some(outer) = adapter_file(file) else {
            return ffi::SQLITE_MISUSE;
        };
        if operation == ffi::SQLITE_FCNTL_PERSIST_WAL {
            return ffi::SQLITE_NOTFOUND;
        }
        if operation == ffi::SQLITE_FCNTL_HAS_MOVED {
            if argument.is_null() {
                return ffi::SQLITE_MISUSE;
            }
            let moved = outer.pin.as_ref().is_none_or(|pin| pin.verify().is_err());
            unsafe { *argument.cast::<c_int>() = i32::from(moved) };
            return ffi::SQLITE_OK;
        }
        let allowed = matches!(
            operation,
            ffi::SQLITE_FCNTL_LOCKSTATE
                | ffi::SQLITE_FCNTL_LAST_ERRNO
                | ffi::SQLITE_FCNTL_SIZE_HINT
        );
        if !allowed {
            return ffi::SQLITE_NOTFOUND;
        }
        let Some(methods) = lower_methods(file) else {
            return ffi::SQLITE_IOERR;
        };
        let Some(function) = methods.xFileControl else {
            return ffi::SQLITE_NOTFOUND;
        };
        let Some(lower) = lower_file(file) else {
            return ffi::SQLITE_IOERR;
        };
        unsafe { function(lower, operation, argument) }
    })
}

unsafe extern "C" fn file_sector_size(file: *mut ffi::sqlite3_file) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(methods) = lower_methods(file) else {
            return 4096;
        };
        let Some(function) = methods.xSectorSize else {
            return 4096;
        };
        let Some(lower) = lower_file(file) else {
            return 4096;
        };
        unsafe { function(lower) }
    }))
    .unwrap_or(4096)
}

unsafe extern "C" fn file_device_characteristics(file: *mut ffi::sqlite3_file) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(methods) = lower_methods(file) else {
            return 0;
        };
        let Some(function) = methods.xDeviceCharacteristics else {
            return 0;
        };
        let Some(lower) = lower_file(file) else {
            return 0;
        };
        let lower_flags = unsafe { function(lower) };
        lower_flags & ffi::SQLITE_IOCAP_UNDELETABLE_WHEN_OPEN
    }))
    .unwrap_or(0)
}

static IO_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 1,
    xClose: Some(file_close),
    xRead: Some(file_read),
    xWrite: Some(file_write),
    xTruncate: Some(file_truncate),
    xSync: Some(file_sync),
    xFileSize: Some(file_size),
    xLock: Some(file_lock),
    xUnlock: Some(file_unlock),
    xCheckReservedLock: Some(file_check_reserved),
    xFileControl: Some(file_control),
    xSectorSize: Some(file_sector_size),
    xDeviceCharacteristics: Some(file_device_characteristics),
    xShmMap: None,
    xShmLock: None,
    xShmBarrier: None,
    xShmUnmap: None,
    xFetch: None,
    xUnfetch: None,
};

unsafe extern "C" fn vfs_randomness(
    vfs: *mut ffi::sqlite3_vfs,
    amount: c_int,
    output: *mut c_char,
) -> c_int {
    callback_rc(0, || {
        if amount < 0 || (amount > 0 && output.is_null()) {
            return 0;
        }
        let Some(context) = context_from_vfs(vfs) else {
            return 0;
        };
        let Some(function) = (unsafe { (*context.lower_vfs).xRandomness }) else {
            return 0;
        };
        unsafe { function(context.lower_vfs, amount, output) }
    })
}

unsafe extern "C" fn vfs_sleep(vfs: *mut ffi::sqlite3_vfs, microseconds: c_int) -> c_int {
    callback_rc(0, || {
        if microseconds < 0 {
            return 0;
        }
        let Some(context) = context_from_vfs(vfs) else {
            return 0;
        };
        let Some(function) = (unsafe { (*context.lower_vfs).xSleep }) else {
            return 0;
        };
        unsafe { function(context.lower_vfs, microseconds) }
    })
}

unsafe extern "C" fn vfs_current_time(vfs: *mut ffi::sqlite3_vfs, output: *mut f64) -> c_int {
    callback_rc(ffi::SQLITE_ERROR, || {
        if output.is_null() {
            return ffi::SQLITE_MISUSE;
        }
        let Some(context) = context_from_vfs(vfs) else {
            return ffi::SQLITE_MISUSE;
        };
        let Some(function) = (unsafe { (*context.lower_vfs).xCurrentTime }) else {
            return ffi::SQLITE_ERROR;
        };
        unsafe { function(context.lower_vfs, output) }
    })
}

unsafe extern "C" fn vfs_get_last_error(
    vfs: *mut ffi::sqlite3_vfs,
    amount: c_int,
    output: *mut c_char,
) -> c_int {
    callback_rc(0, || {
        if amount < 0 || (amount > 0 && output.is_null()) {
            return 0;
        }
        let Some(context) = context_from_vfs(vfs) else {
            return 0;
        };
        let Some(function) = (unsafe { (*context.lower_vfs).xGetLastError }) else {
            return 0;
        };
        unsafe { function(context.lower_vfs, amount, output) }
    })
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::{OsStr, c_int},
        fs,
        path::Path,
        process::{Command, Stdio},
        sync::Mutex,
    };

    use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
    use rusqlite::ffi;

    use super::{DATABASE_NAME, JOURNAL_SUFFIX, RegisteredRollbackDb};

    const CHILD_DIR_ENV: &str = "RAIUN_ROLLBACK_VFS_CHILD_DIR";

    static LOWER_CLOSE: Mutex<Option<unsafe extern "C" fn(*mut ffi::sqlite3_file) -> c_int>> =
        Mutex::new(None);

    unsafe extern "C" fn close_then_report_failure(file: *mut ffi::sqlite3_file) -> c_int {
        let close = LOWER_CLOSE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .expect("test installs lower close callback");
        let _ = unsafe { close(file) };
        ffi::SQLITE_IOERR_CLOSE
    }

    fn private_directory(root: &Path) -> (PinnedDirectory, PrivateDirectory) {
        let parent = PinnedDirectory::open(root).expect("pin temporary test root");
        let private = PrivateDirectory::create_or_open_under(&parent, OsStr::new("private"))
            .expect("create private test directory");
        (parent, private)
    }

    fn reopen_private_directory(root: &Path) -> (PinnedDirectory, PrivateDirectory) {
        let parent = PinnedDirectory::open(root).expect("pin temporary test root");
        let private = PrivateDirectory::open_under(&parent, OsStr::new("private"))
            .expect("open private test directory");
        (parent, private)
    }

    fn journal_path(root: &Path) -> std::path::PathBuf {
        root.join("private")
            .join(format!("{DATABASE_NAME}{JOURNAL_SUFFIX}"))
    }

    unsafe extern "C" fn retain_handle_and_report_close_failure(
        _file: *mut ffi::sqlite3_file,
    ) -> c_int {
        ffi::SQLITE_IOERR_CLOSE
    }

    #[test]
    fn normal_close_preserves_entire_capsule_when_lower_handle_remains_live() {
        let root = tempfile::tempdir().unwrap();
        let (_parent, private) = private_directory(root.path());
        let registration = super::VfsRegistration::new(private).unwrap();
        let weak = std::sync::Arc::downgrade(&registration.context);
        let mut storage = vec![0_u64; registration.vfs.szOsFile as usize / 8 + 1];
        let file = storage.as_mut_ptr().cast::<ffi::sqlite3_file>();
        let mut out_flags = 0;
        super::open_with_pin(
            &registration.context,
            file,
            super::FixedFile::Journal,
            ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE | ffi::SQLITE_OPEN_MAIN_JOURNAL,
            &mut out_flags,
        )
        .unwrap();
        let lower = super::lower_file(file).unwrap();
        let mut methods = Box::new(unsafe { *(*lower).pMethods });
        methods.xClose = Some(retain_handle_and_report_close_failure);
        let methods = Box::into_raw(methods);
        unsafe {
            (*lower).pMethods = methods;
        }
        assert_eq!(unsafe { super::file_close(file) }, ffi::SQLITE_IOERR_CLOSE);
        assert_eq!(unsafe { super::file_close(file) }, ffi::SQLITE_MISUSE);
        drop(registration);
        assert!(
            weak.upgrade().is_some(),
            "uncertain normal close must retain the context/pin capsule"
        );
        assert_eq!(
            unsafe { (*lower).pMethods },
            methods,
            "lower file storage remains owned"
        );
        assert!(journal_path(root.path()).exists());
        assert!(
            std::fs::remove_file(journal_path(root.path())).is_err(),
            "private pin must continue to reject journal deletion"
        );
    }

    #[test]
    fn rejected_open_cleanup_preserves_capsule_on_uncertain_lower_close() {
        for open_succeeded in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let (_parent, private) = private_directory(root.path());
            let mut registration = super::VfsRegistration::new(private).unwrap();
            let weak = std::sync::Arc::downgrade(&registration.context);
            let mut storage = vec![0_u64; registration.vfs.szOsFile as usize / 8 + 1];
            let file = storage.as_mut_ptr().cast::<ffi::sqlite3_file>();
            let mut out_flags = 0;
            super::open_with_pin(
                &registration.context,
                file,
                super::FixedFile::Journal,
                ffi::SQLITE_OPEN_READWRITE
                    | ffi::SQLITE_OPEN_CREATE
                    | ffi::SQLITE_OPEN_MAIN_JOURNAL,
                &mut out_flags,
            )
            .unwrap();
            let lower = super::lower_file(file).unwrap();
            let mut methods = Box::new(unsafe { *(*lower).pMethods });
            methods.xClose = Some(retain_handle_and_report_close_failure);
            unsafe {
                (*lower).pMethods = Box::into_raw(methods);
            }
            let outer = unsafe { std::ptr::read(file.cast::<super::AdapterFile>()) };
            unsafe {
                (*file).pMethods = std::ptr::null();
            }
            assert!(!super::close_rejected_lower(outer, open_succeeded));
            assert!(
                registration
                    .context
                    .file_close_failed
                    .load(std::sync::atomic::Ordering::Acquire)
            );
            assert!(journal_path(root.path()).exists());
            assert_ne!(
                unsafe {
                    super::vfs_delete(
                        &mut *registration.vfs,
                        registration.context.journal_path.as_ptr(),
                        0,
                    )
                },
                ffi::SQLITE_OK
            );
            drop(registration);
            assert!(
                weak.upgrade().is_some(),
                "uncertain lower handle retains recovery capsule until exit"
            );
        }
    }

    #[test]
    fn closing_allows_journal_cleanup_but_completed_close_rejects_callbacks() {
        let root = tempfile::tempdir().unwrap();
        let (_parent, private) = private_directory(root.path());
        let mut registration = super::VfsRegistration::new(private).unwrap();
        let mut storage = vec![0_u64; registration.vfs.szOsFile as usize / 8 + 1];
        let file = storage.as_mut_ptr().cast::<ffi::sqlite3_file>();
        let mut out_flags = 0;
        super::open_with_pin(
            &registration.context,
            file,
            super::FixedFile::Journal,
            ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE | ffi::SQLITE_OPEN_MAIN_JOURNAL,
            &mut out_flags,
        )
        .unwrap();
        assert_eq!(unsafe { super::file_close(file) }, ffi::SQLITE_OK);
        registration.deactivate();
        assert_eq!(
            unsafe {
                super::vfs_delete(
                    &mut *registration.vfs,
                    registration.context.journal_path.as_ptr(),
                    0,
                )
            },
            ffi::SQLITE_OK
        );
        registration.finish_close();
        let mut exists = -1;
        assert_eq!(
            unsafe {
                super::vfs_access(
                    &mut *registration.vfs,
                    registration.context.journal_path.as_ptr(),
                    ffi::SQLITE_ACCESS_EXISTS,
                    &mut exists,
                )
            },
            ffi::SQLITE_MISUSE
        );
        assert_eq!(exists, 0);
        assert_eq!(
            unsafe {
                super::vfs_delete(
                    &mut *registration.vfs,
                    registration.context.journal_path.as_ptr(),
                    0,
                )
            },
            ffi::SQLITE_MISUSE
        );
    }

    #[test]
    fn closing_drains_callback_lease_and_refuses_later_file_admission() {
        let root = tempfile::tempdir().unwrap();
        let (_parent, private) = private_directory(root.path());
        let mut registration = super::VfsRegistration::new(private).unwrap();
        let pointer = &mut *registration.vfs as *mut ffi::sqlite3_vfs;
        let lease = super::context_from_vfs(pointer).unwrap();
        let slot = registration.slot;
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let closing = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let guard = slot.0.lock().unwrap();
            guard
                .as_ref()
                .unwrap()
                .closing
                .store(true, std::sync::atomic::Ordering::Release);
        });
        started_rx.recv().unwrap();
        // The closing thread cannot mark Closing while an admitted callback
        // still owns the lease, regardless of scheduling.
        assert!(!lease.closing.load(std::sync::atomic::Ordering::Acquire));
        drop(lease);
        closing.join().unwrap();
        let lease = super::context_from_vfs(pointer).unwrap();
        let mut storage = vec![0_u64; registration.vfs.szOsFile as usize / 8 + 1];
        let file = storage.as_mut_ptr().cast::<ffi::sqlite3_file>();
        let mut out_flags = 0;
        assert_eq!(
            super::open_with_pin(
                lease.arc(),
                file,
                super::FixedFile::Database,
                ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE | ffi::SQLITE_OPEN_MAIN_DB,
                &mut out_flags
            ),
            Err(ffi::SQLITE_CANTOPEN)
        );
        assert!(!root.path().join("private").join(DATABASE_NAME).exists());
        drop(lease);
    }

    #[test]
    fn retired_vfs_pointer_rejects_a_callback_entering_after_owner_drop() {
        let root = tempfile::tempdir().unwrap();
        let (_parent, private) = private_directory(root.path());
        let mut registration = super::VfsRegistration::new(private).unwrap();
        let pointer = (&mut *registration.vfs as *mut ffi::sqlite3_vfs) as usize;
        let database_path = registration.context.database_path.clone();
        let weak = std::sync::Arc::downgrade(&registration.context);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let late = std::sync::Arc::clone(&barrier);
        let thread = std::thread::spawn(move || {
            // Simulate SQLite retaining a VFS pointer before unregister but
            // entering the callback only after its owner has been destroyed.
            late.wait();
            let mut exists = -1;
            let result = unsafe {
                super::vfs_access(
                    pointer as *mut ffi::sqlite3_vfs,
                    database_path.as_ptr(),
                    ffi::SQLITE_ACCESS_EXISTS,
                    &mut exists,
                )
            };
            assert_ne!(result, ffi::SQLITE_OK);
            assert_eq!(exists, 0);
        });
        drop(registration);
        assert!(
            weak.upgrade().is_none(),
            "retired slot must release live handles"
        );
        barrier.wait();
        thread.join().unwrap();
    }

    #[test]
    fn opened_file_retains_context_after_registration_is_retired() {
        let root = tempfile::tempdir().unwrap();
        let (_parent, private) = private_directory(root.path());
        let registration = super::VfsRegistration::new(private).unwrap();
        let weak = std::sync::Arc::downgrade(&registration.context);
        let mut storage = vec![0_u64; registration.vfs.szOsFile as usize / 8 + 1];
        let file = storage.as_mut_ptr().cast::<ffi::sqlite3_file>();
        let mut out_flags = 0;
        super::open_with_pin(
            &registration.context,
            file,
            super::FixedFile::Database,
            ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE | ffi::SQLITE_OPEN_MAIN_DB,
            &mut out_flags,
        )
        .unwrap();
        drop(registration);
        assert!(
            weak.upgrade().is_some(),
            "open file must own its context lease"
        );
        let mut size = -1;
        assert_eq!(unsafe { super::file_size(file, &mut size) }, ffi::SQLITE_OK);
        assert_eq!(size, 0);
        assert_eq!(unsafe { super::file_close(file) }, ffi::SQLITE_OK);
        assert!(
            weak.upgrade().is_none(),
            "last file close must release directory pins"
        );
    }

    #[test]
    fn lower_filename_aliases_retain_sqlite_uri_metadata() {
        let names = super::LowerFilenames::new(
            c"\\\\?\\C:\\private\\cache.sqlite3",
            c"\\\\?\\C:\\private\\cache.sqlite3-journal",
            c"\\\\?\\C:\\private\\cache.sqlite3-wal",
        )
        .unwrap();
        for kind in [super::FixedFile::Database, super::FixedFile::Journal] {
            let alias = names.path(kind);
            // SAFETY: both aliases belong to the live SQLite filename owner.
            unsafe {
                assert_eq!(ffi::sqlite3_filename_database(alias), names.database);
                assert_eq!(ffi::sqlite3_uri_boolean(alias, c"exclusive".as_ptr(), 0), 0);
                assert_eq!(ffi::sqlite3_uri_boolean(alias, c"psow".as_ptr(), 1), 1);
            }
        }
    }

    #[test]
    fn rollback_vfs_long_path_commits_rolls_back_and_reopens() {
        use std::os::windows::ffi::OsStrExt;
        let root = tempfile::tempdir().unwrap();
        let (_root_pin, mut private) = private_directory(root.path());
        let mut parents = Vec::new();
        for index in 0..3 {
            let parent = PinnedDirectory::open(private.path()).unwrap();
            let name = format!("long-{index}-{}", "a".repeat(110));
            let next = PrivateDirectory::create_or_open_under(&parent, OsStr::new(&name)).unwrap();
            parents.push((parent, private));
            private = next;
        }
        assert!(private.path().as_os_str().encode_wide().count() > 360);
        let parent = PinnedDirectory::open(private.path().parent().unwrap()).unwrap();
        let name = private.path().file_name().unwrap().to_owned();
        let db = RegisteredRollbackDb::open(private).unwrap();
        db.connection().execute_batch(
            "CREATE TABLE sample(value INTEGER); BEGIN IMMEDIATE; INSERT INTO sample VALUES(41); COMMIT; BEGIN IMMEDIATE; INSERT INTO sample VALUES(99); ROLLBACK;"
        ).unwrap();
        assert!(db.close().is_ok());
        let reopened =
            RegisteredRollbackDb::open(PrivateDirectory::open_under(&parent, &name).unwrap())
                .unwrap();
        let values: (i64, i64) = reopened
            .connection()
            .query_row("SELECT COUNT(*), SUM(value) FROM sample", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(values, (1, 41));
        assert!(reopened.close().is_ok());
    }

    #[test]
    fn rollback_vfs_commits_reopens_rolls_back_and_rejects_wal_attach_and_temp() {
        let root = tempfile::tempdir().expect("temporary test root");
        let (_parent, private) = private_directory(root.path());
        {
            let db = RegisteredRollbackDb::open(private).expect("open fixed database");
            let registration = db.registration.as_ref().expect("registered VFS owner");
            let lower_name =
                unsafe { std::ffi::CStr::from_ptr((*registration.context.lower_vfs).zName) };
            assert_eq!(
                lower_name, c"win32-longpath",
                "must use the locking long-path Win32 VFS"
            );
            let mode: String = db
                .connection()
                .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
                .expect("select rollback journal mode");
            assert_eq!(mode.to_ascii_lowercase(), "delete");
            db.connection()
                .execute_batch(
                    "PRAGMA synchronous=FULL;
                     CREATE TABLE sample(value INTEGER NOT NULL);
                     BEGIN IMMEDIATE;
                     INSERT INTO sample VALUES (41);
                     COMMIT;",
                )
                .expect("commit transaction");

            db.connection()
                .execute_batch("BEGIN IMMEDIATE; INSERT INTO sample VALUES (99); ROLLBACK;")
                .expect("roll back transaction");

            let wal = db
                .connection()
                .query_row("PRAGMA journal_mode=WAL", [], |row| row.get::<_, String>(0));
            assert!(wal.is_err(), "authorizer must reject a WAL mode change");

            assert!(
                db.connection()
                    .execute_batch("PRAGMA temp_store=FILE;")
                    .is_err()
            );
            assert!(
                db.connection()
                    .execute_batch("PRAGMA temp_store_directory='.';")
                    .is_err()
            );
            assert!(
                db.connection()
                    .execute_batch("PRAGMA synchronous=NORMAL;")
                    .is_err()
            );
            assert!(
                db.connection()
                    .execute_batch("PRAGMA synchronous=OFF;")
                    .is_err()
            );
            assert!(
                db.connection()
                    .execute_batch("CREATE TEMP TABLE forbidden(value INTEGER);")
                    .is_err()
            );
            assert!(
                db.connection()
                    .execute_batch("ATTACH DATABASE 'other.sqlite3' AS other;")
                    .is_err()
            );
            assert!(
                db.connection()
                    .execute_batch("ATTACH DATABASE ':memory:' AS in_memory;")
                    .is_err()
            );

            let mut persist_wal = 1;
            let file_control = unsafe {
                ffi::sqlite3_file_control(
                    db.connection().handle(),
                    c"main".as_ptr(),
                    ffi::SQLITE_FCNTL_PERSIST_WAL,
                    (&mut persist_wal as *mut c_int).cast(),
                )
            };
            assert_eq!(file_control, ffi::SQLITE_NOTFOUND);
            assert_eq!(persist_wal, 1, "unsupported control must not mutate output");
        }

        let (_parent, private) = reopen_private_directory(root.path());
        let db = RegisteredRollbackDb::open(private).expect("reopen fixed database");
        let values: Vec<i64> = {
            let mut statement = db
                .connection()
                .prepare("SELECT value FROM sample ORDER BY value")
                .expect("prepare query");
            statement
                .query_map([], |row| row.get(0))
                .expect("query rows")
                .collect::<rusqlite::Result<_>>()
                .expect("collect rows")
        };
        assert_eq!(values, [41]);
    }

    #[test]
    fn rollback_vfs_pinned_database_rejects_path_replacement_while_open() {
        let root = tempfile::tempdir().expect("temporary test root");
        let (_parent, private) = private_directory(root.path());
        let db = RegisteredRollbackDb::open(private).expect("open fixed database");
        db.connection()
            .execute_batch("CREATE TABLE pinned(value INTEGER);")
            .expect("create table");

        let database = root.path().join("private").join(DATABASE_NAME);
        let replacement = root.path().join("replacement.sqlite3");
        fs::write(&replacement, b"replacement").expect("write replacement fixture");
        assert!(fs::rename(&replacement, &database).is_err());
        assert_eq!(
            fs::read(&replacement).expect("replacement remains"),
            b"replacement"
        );
        assert_eq!(
            db.connection()
                .query_row("SELECT count(*) FROM pinned", [], |row| row
                    .get::<_, i64>(0))
                .expect("database remains usable"),
            0
        );
    }

    #[test]
    fn rollback_vfs_delete_rejects_a_replacement_after_the_original_pin_closed() {
        let root = tempfile::tempdir().expect("temporary test root");
        let (_parent, private) = private_directory(root.path());
        let mut registration = super::VfsRegistration::new(private).expect("register VFS");
        let journal_name = OsStr::new("cache.sqlite3-journal");
        let journal_path = journal_path(root.path());
        let moved_path = root.path().join("original-journal");
        let original = registration
            .context
            .directory
            .create_new_pinned_file(journal_name)
            .expect("create original journal");
        let original_identity = original.identity();
        drop(original);
        registration
            .context
            .identities
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .journal = Some(original_identity);

        fs::rename(&journal_path, &moved_path).expect("simulate replacement window");
        let replacement = registration
            .context
            .directory
            .create_new_pinned_file(journal_name)
            .expect("create replacement journal");
        assert_ne!(replacement.identity(), original_identity);
        drop(replacement);

        let result = unsafe {
            super::vfs_delete(
                &mut *registration.vfs,
                registration.context.journal_path.as_ptr(),
                0,
            )
        };
        assert_ne!(result, rusqlite::ffi::SQLITE_OK);
        assert!(journal_path.is_file(), "replacement must not be deleted");
        assert!(
            moved_path.is_file(),
            "original identity remains recoverable"
        );
    }

    #[test]
    fn rollback_vfs_exclusive_create_only_succeeds_for_an_absent_database() {
        let root = tempfile::tempdir().expect("temporary test root");
        let (_parent, private) = private_directory(root.path());
        let registration = super::VfsRegistration::new(private).expect("register VFS");
        let mut storage = vec![0_u64; registration.vfs.szOsFile as usize / 8 + 1];
        let file = storage.as_mut_ptr().cast::<ffi::sqlite3_file>();
        let mut out_flags = -1;
        let flags = ffi::SQLITE_OPEN_READWRITE
            | ffi::SQLITE_OPEN_CREATE
            | ffi::SQLITE_OPEN_EXCLUSIVE
            | ffi::SQLITE_OPEN_MAIN_DB;
        assert_eq!(
            super::open_with_pin(
                &registration.context,
                file,
                super::FixedFile::Database,
                flags,
                &mut out_flags,
            ),
            Ok(())
        );
        assert_eq!(out_flags & ffi::SQLITE_OPEN_DELETEONCLOSE, 0);
        assert_eq!(
            out_flags & !(ffi::SQLITE_OPEN_READONLY | ffi::SQLITE_OPEN_READWRITE),
            0
        );
        assert_eq!(unsafe { super::file_close(file) }, ffi::SQLITE_OK);

        let mut storage = vec![0_u64; registration.vfs.szOsFile as usize / 8 + 1];
        let file = storage.as_mut_ptr().cast::<ffi::sqlite3_file>();
        assert_eq!(
            super::open_with_pin(
                &registration.context,
                file,
                super::FixedFile::Database,
                flags,
                &mut out_flags,
            ),
            Err(ffi::SQLITE_CANTOPEN)
        );
    }

    #[cfg(feature = "trusted-cache-integration")]
    #[test]
    fn registered_owner_moves_between_threads_without_relocating_vfs_state() {
        fn require_send<T: Send>() {}
        require_send::<RegisteredRollbackDb>();
        let root = tempfile::tempdir().unwrap();
        let (_parent, private) = private_directory(root.path());
        let mut db = RegisteredRollbackDb::open(private).unwrap();
        db.with_cache_connection(|connection| connection.execute_batch(
            "CREATE TABLE thread_probe(value INTEGER NOT NULL); INSERT INTO thread_probe VALUES (1);"
        )).unwrap();
        let mut db = std::thread::spawn(move || {
            db.with_cache_connection(|connection| {
                let transaction = connection.unchecked_transaction()?;
                transaction.execute("UPDATE thread_probe SET value=value+1", [])?;
                transaction.commit()
            })
            .unwrap();
            db
        })
        .join()
        .unwrap();
        std::thread::spawn(move || {
            db.with_cache_connection(|connection| {
                let value: i64 =
                    connection.query_row("SELECT value FROM thread_probe", [], |row| row.get(0))?;
                assert_eq!(value, 2);
                Ok(())
            })
            .unwrap();
            assert!(db.close().is_ok());
        })
        .join()
        .unwrap();
        let (_parent, private) = reopen_private_directory(root.path());
        let db = RegisteredRollbackDb::open(private).unwrap();
        let value: i64 = db
            .connection()
            .query_row("SELECT value FROM thread_probe", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, 2);
        assert!(db.close().is_ok());
    }

    #[cfg(feature = "trusted-cache-integration")]
    #[test]
    fn trusted_cache_bridge_commits_and_rolls_back_without_exposing_owner() {
        let root = tempfile::tempdir().unwrap();
        let (_parent, private) = private_directory(root.path());
        let mut db = RegisteredRollbackDb::open(private).unwrap();
        db.with_cache_connection(|connection| {
            connection.execute_batch("CREATE TABLE bridge(value INTEGER NOT NULL)")?;
            let transaction = connection.unchecked_transaction()?;
            transaction.execute("INSERT INTO bridge VALUES (7)", [])?;
            transaction.commit()
        })
        .unwrap();
        db.with_cache_connection(|connection| {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute("INSERT INTO bridge VALUES (9)", [])?;
            transaction.rollback()?;
            let value: i64 =
                connection.query_row("SELECT sum(value) FROM bridge", [], |row| row.get(0))?;
            assert_eq!(value, 7);
            assert!(connection.execute_batch("PRAGMA synchronous=OFF").is_err());
            Ok(())
        })
        .unwrap();
        assert!(db.close().is_ok());
    }

    #[test]
    fn wal_probe_reports_only_verified_absence() {
        let root = tempfile::tempdir().unwrap();
        let (_parent, private) = private_directory(root.path());
        let mut registration = super::VfsRegistration::new(private).unwrap();
        let wal_path = registration
            .context
            .directory
            .path()
            .join("cache.sqlite3-wal");
        let name = super::path_to_c_string(&wal_path).unwrap();
        let mut exists = -1;
        assert_eq!(
            unsafe {
                super::vfs_access(
                    &mut *registration.vfs,
                    name.as_ptr(),
                    ffi::SQLITE_ACCESS_EXISTS,
                    &mut exists,
                )
            },
            ffi::SQLITE_OK
        );
        assert_eq!(exists, 0);
        std::fs::write(&wal_path, b"preserve WAL recovery").unwrap();
        assert_ne!(
            unsafe {
                super::vfs_access(
                    &mut *registration.vfs,
                    name.as_ptr(),
                    ffi::SQLITE_ACCESS_EXISTS,
                    &mut exists,
                )
            },
            ffi::SQLITE_OK
        );
        assert_eq!(std::fs::read(&wal_path).unwrap(), b"preserve WAL recovery");
    }

    #[test]
    fn close_failure_preserves_pinned_rollback_journal_and_blocks_delete() {
        for kind in [super::FixedFile::Journal, super::FixedFile::Database] {
            let root = tempfile::tempdir().expect("temporary test root");
            let (_parent, private) = private_directory(root.path());
            let mut registration = super::VfsRegistration::new(private).expect("register VFS");
            if kind == super::FixedFile::Database {
                std::fs::write(journal_path(root.path()), b"recovery sentinel").unwrap();
            }
            let mut storage = vec![0_u64; registration.vfs.szOsFile as usize / 8 + 1];
            let file = storage.as_mut_ptr().cast::<ffi::sqlite3_file>();
            let mut out_flags = -1;
            let flags = ffi::SQLITE_OPEN_READWRITE
                | ffi::SQLITE_OPEN_CREATE
                | match kind {
                    super::FixedFile::Journal => ffi::SQLITE_OPEN_MAIN_JOURNAL,
                    super::FixedFile::Database => ffi::SQLITE_OPEN_MAIN_DB,
                };
            assert_eq!(
                super::open_with_pin(&registration.context, file, kind, flags, &mut out_flags,),
                Ok(())
            );

            let lower = super::lower_file(file).expect("lower file allocated");
            let methods = unsafe { (*lower).pMethods.as_ref().expect("lower methods") };
            *LOWER_CLOSE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = methods.xClose;
            let mut injected_methods = Box::new(*methods);
            injected_methods.xClose = Some(close_then_report_failure);
            let injected_methods = Box::into_raw(injected_methods);
            unsafe { (*lower).pMethods = injected_methods };

            assert_eq!(unsafe { super::file_close(file) }, ffi::SQLITE_IOERR_CLOSE);
            // The failed close retains the entire lower capsule. Its method
            // table must remain valid with that capsule until process exit.
            *LOWER_CLOSE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;

            if kind == super::FixedFile::Database {
                assert!(
                    registration
                        .context
                        .database_open
                        .load(std::sync::atomic::Ordering::Acquire)
                );
            }
            let journal = journal_path(root.path());
            assert!(journal.is_file(), "failed close must retain the journal");
            let delete = unsafe {
                super::vfs_delete(
                    &mut *registration.vfs,
                    registration.context.journal_path.as_ptr(),
                    0,
                )
            };
            assert_ne!(delete, ffi::SQLITE_OK);
            assert!(
                journal.is_file(),
                "delete must remain blocked after close failure"
            );
        }
    }

    #[test]
    fn rollback_vfs_recovers_a_hot_journal_after_process_exit() {
        let root = tempfile::tempdir().expect("temporary test root");
        let (_parent, private) = private_directory(root.path());
        {
            let db = RegisteredRollbackDb::open(private).expect("create database");
            db.connection()
                .execute_batch(
                    "PRAGMA journal_mode=DELETE;
                     PRAGMA synchronous=FULL;
                     CREATE TABLE sample(value INTEGER NOT NULL);
                     INSERT INTO sample VALUES (7);",
                )
                .expect("initialize database");
        }

        let executable = std::env::current_exe().expect("test executable");
        let output = Command::new(executable)
            .arg("--exact")
            .arg("rollback_vfs::tests::crash_child_leaves_uncommitted_rollback_journal")
            .arg("--nocapture")
            .env(CHILD_DIR_ENV, root.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run crash child");
        assert!(
            output.status.success(),
            "crash child failed: stdout={:?}, stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let journal = journal_path(root.path());
        assert!(journal.is_file(), "child must leave a hot rollback journal");

        let (_parent, private) = reopen_private_directory(root.path());
        let db = RegisteredRollbackDb::open(private).expect("open and recover hot journal");
        let value = db
            .connection()
            .query_row("SELECT value FROM sample", [], |row| row.get::<_, i64>(0))
            .expect("read recovered row");
        assert_eq!(value, 7, "uncommitted update must be rolled back");
        assert!(!journal.exists(), "recovery should retire the hot journal");
    }

    #[test]
    fn crash_child_leaves_uncommitted_rollback_journal() {
        let Ok(root) = std::env::var(CHILD_DIR_ENV) else {
            return;
        };
        let root = Path::new(&root);
        let (_parent, private) = reopen_private_directory(root);
        let db = RegisteredRollbackDb::open(private).expect("open child database");
        db.connection()
            .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")
            .expect("configure child connection");
        db.connection()
            .execute_batch("BEGIN EXCLUSIVE; UPDATE sample SET value=99;")
            .expect("write uncommitted child transaction");
        std::process::exit(0);
    }
    #[cfg(feature = "trusted-engine-integration")]
    #[test]
    fn trusted_engine_bridge_commits_rolls_back_and_reopens_fixed_database() {
        let root = tempfile::tempdir().unwrap();
        let (_parent, private) = private_directory(root.path());
        assert!(RegisteredRollbackDb::open_engine_existing(private).is_err());
        assert!(!root.path().join("private/engine.sqlite3").exists());
        assert!(!root.path().join("private/engine.sqlite3-journal").exists());
        let (_parent, private) = reopen_private_directory(root.path());
        let db = RegisteredRollbackDb::open_engine(private).unwrap();
        let connection = db.borrow_engine_connection();
        connection.execute_batch("CREATE TABLE engine_probe(value INTEGER NOT NULL); INSERT INTO engine_probe VALUES (7);").unwrap();
        let transaction = connection.unchecked_transaction().unwrap();
        transaction
            .execute("INSERT INTO engine_probe VALUES (99)", [])
            .unwrap();
        assert!(root.path().join("private/engine.sqlite3-journal").is_file());
        assert!(!root.path().join("private/cache.sqlite3").exists());
        transaction.rollback().unwrap();
        assert!(db.close().is_ok());
        let (_parent, private) = reopen_private_directory(root.path());
        let db = RegisteredRollbackDb::open_engine_existing(private).unwrap();
        let values: (i64, i64) = db
            .borrow_engine_connection()
            .query_row("SELECT count(*), sum(value) FROM engine_probe", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(values, (1, 7));
        assert!(db.close().is_ok());
        assert!(!root.path().join("private/engine.sqlite3-journal").exists());
    }

    #[cfg(feature = "trusted-engine-integration")]
    #[test]
    fn trusted_engine_preserves_rollback_only_authorizer_policy() {
        let root = tempfile::tempdir().unwrap();
        let (_parent, private) = private_directory(root.path());
        let db = RegisteredRollbackDb::open_engine(private).unwrap();
        let connection = db.borrow_engine_connection();
        let mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode.to_ascii_lowercase(), "delete");
        for sql in [
            "PRAGMA journal_mode=WAL",
            "PRAGMA synchronous=OFF",
            "PRAGMA temp_store=FILE",
            "CREATE TEMP TABLE forbidden(value INTEGER)",
            "ATTACH DATABASE 'cache.sqlite3' AS cache",
            "ATTACH DATABASE ':memory:' AS memory",
        ] {
            assert!(connection.execute_batch(sql).is_err(), "must refuse {sql}");
        }
        connection
            .execute_batch(
                "CREATE TABLE still_usable(value INTEGER); INSERT INTO still_usable VALUES (1);",
            )
            .unwrap();
        assert!(db.close().is_ok());
        assert!(!root.path().join("private/engine.sqlite3-wal").exists());
        assert!(!root.path().join("private/cache.sqlite3").exists());
    }

    #[cfg(feature = "trusted-engine-integration")]
    #[test]
    fn trusted_engine_and_default_cache_keep_distinct_fixed_basenames() {
        let root = tempfile::tempdir().unwrap();
        let (_parent, private) = private_directory(root.path());
        let engine = RegisteredRollbackDb::open_engine(private).unwrap();
        engine
            .borrow_engine_connection()
            .execute_batch(
                "CREATE TABLE purpose(value TEXT); INSERT INTO purpose VALUES ('engine');",
            )
            .unwrap();
        let (_parent, private) = reopen_private_directory(root.path());
        let cache = RegisteredRollbackDb::open(private).unwrap();
        cache
            .connection()
            .execute_batch(
                "CREATE TABLE purpose(value TEXT); INSERT INTO purpose VALUES ('cache');",
            )
            .unwrap();
        for (db, expected) in [(&engine, "engine"), (&cache, "cache")] {
            let value: String = db
                .connection()
                .query_row("SELECT value FROM purpose", [], |row| row.get(0))
                .unwrap();
            assert_eq!(value, expected);
            let registration = db.registration.as_ref().unwrap();
            assert_eq!(
                super::file_kind_for_name(
                    &registration.context,
                    registration.context.database_path.as_c_str()
                ),
                Some(super::FixedFile::Database)
            );
            assert_eq!(
                super::file_kind_for_name(
                    &registration.context,
                    registration.context.journal_path.as_c_str()
                ),
                Some(super::FixedFile::Journal)
            );
            let other = if expected == "engine" {
                "cache.sqlite3"
            } else {
                "engine.sqlite3"
            };
            let other = super::path_to_c_string(&root.path().join("private").join(other)).unwrap();
            assert_eq!(
                super::file_kind_for_name(&registration.context, &other),
                None
            );
        }
        assert!(engine.close().is_ok());
        assert!(cache.close().is_ok());
        for engine_purpose in [false, true] {
            let (_parent, private) = reopen_private_directory(root.path());
            let db = if engine_purpose {
                RegisteredRollbackDb::open_engine(private)
            } else {
                RegisteredRollbackDb::open(private)
            }
            .unwrap();
            let value: String = db
                .connection()
                .query_row("SELECT value FROM purpose", [], |row| row.get(0))
                .unwrap();
            assert_eq!(value, if engine_purpose { "engine" } else { "cache" });
            assert!(db.close().is_ok());
        }
    }
    #[cfg(feature = "trusted-engine-integration")]
    #[test]
    fn engine_wal_probe_reports_only_verified_absence() {
        let root = tempfile::tempdir().unwrap();
        let (_parent, private) = private_directory(root.path());
        let mut registration =
            super::VfsRegistration::new_for(private, super::DatabasePurpose::Engine).unwrap();
        let wal_path = registration
            .context
            .directory
            .path()
            .join("engine.sqlite3-wal");
        let name = super::path_to_c_string(&wal_path).unwrap();
        let mut exists = -1;
        assert_eq!(
            unsafe {
                super::vfs_access(
                    &mut *registration.vfs,
                    name.as_ptr(),
                    ffi::SQLITE_ACCESS_EXISTS,
                    &mut exists,
                )
            },
            ffi::SQLITE_OK
        );
        assert_eq!(exists, 0);
        let retained = b"preserve engine WAL recovery";
        std::fs::write(&wal_path, retained).unwrap();
        exists = -1;
        assert_eq!(
            unsafe {
                super::vfs_access(
                    &mut *registration.vfs,
                    name.as_ptr(),
                    ffi::SQLITE_ACCESS_EXISTS,
                    &mut exists,
                )
            },
            ffi::SQLITE_CANTOPEN
        );
        assert_eq!(std::fs::read(&wal_path).unwrap(), retained);
    }
}

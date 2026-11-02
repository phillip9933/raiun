//! Native original-owner capture/publication for one encrypted child FILE.
//! No raw pointer or reader crosses the joined-worker boundary.
use super::*;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::io::{self, Read};
// Same READONLY/HIDDEN/SYSTEM/ARCHIVE mask as existing vault completion.
const SETTABLE_VAULT_CHILD_ATTRIBUTES: u32 = 0x1 | 0x2 | 0x4 | 0x20;

#[link(name = "CldApi")]
unsafe extern "system" {
    fn CfConvertToPlaceholder(
        file: Handle,
        identity: *const c_void,
        length: u32,
        flags: u32,
        usn: *mut i64,
        overlapped: *mut c_void,
    ) -> HResult;
}
pub(super) struct VaultFilePins {
    root_path: PathBuf,
    root: RootIdentity,
    components: Vec<String>,
    route: Vec<crate::PlaceholderChild>,
    parent_identity: crate::OpaqueIdentity,
    parent: RawOwnedHandle,
    parent_snapshot: RootSnapshot,
    parent_usn: i64,
    ancestors: Vec<(RawOwnedHandle, RootSnapshot)>,
    source: RawOwnedHandle,
    original: RootSnapshot,
    original_basic: FileBasicInfo,
    usn: i64,
    digest: Cell<Option<[u8; 32]>>,
    captured: Cell<bool>,
    converted: Option<[u8; 16]>,
    attempted: bool,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
#[derive(Clone)]
pub(super) struct VaultFileSendProof {
    root_path: PathBuf,
    root: RootIdentity,
    components: Vec<String>,
    route: Vec<crate::PlaceholderChild>,
    parent_identity: crate::OpaqueIdentity,
    parent: RootSnapshot,
    parent_usn: i64,
    original: RootSnapshot,
    original_basic: FileBasicInfo,
    usn: i64,
}
fn links_one(handle: Handle, expected: RootIdentity) -> Result<bool, Error> {
    let mut info: ByHandleFileInformation = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(win32_io_error("inspect vault child file links"));
    }
    Ok(info.number_of_links == 1
        && info.volume_serial_number == expected.volume_serial
        && ((u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low))
            == expected.file_index)
}
fn plain(snapshot: RootSnapshot) -> bool {
    snapshot.identity.file_index != 0
        && snapshot.file_size <= 1 << 30
        && snapshot.file_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) == 0
        && snapshot.reparse_tag == 0
        && snapshot.placeholder_state == 0
}
impl VaultFilePins {
    pub(super) fn pin(
        connection: &ConfiguredRootConnection,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        parent_components: &[String],
        route: &[crate::PlaceholderChild],
        parent_identity: crate::OpaqueIdentity,
        name: &str,
    ) -> Result<Option<Self>, Error> {
        let erased: Arc<dyn PlaceholderBackend> = backend.clone();
        if !connection.connected
            || !Arc::ptr_eq(&erased, &connection.state.backend)
            || connection.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
            || parent_components.is_empty()
            || parent_components.len() > 255
            || parent_components.iter().any(|s| !valid_component(s))
            || !valid_component(name)
        {
            return Err(Error::ProviderUnavailable);
        }
        let root = connection
            .root
            .as_ref()
            .ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let refs: Vec<_> = parent_components.iter().map(String::as_str).collect();
        let (parent, parent_snapshot, ancestors) =
            native_namespace_directory::pin_namespace_parent(
                root,
                route,
                parent_identity,
                &refs,
                FILE_READ_ATTRIBUTES,
            )?;
        let parent_usn = completion_usn(parent.0, parent_snapshot.identity.file_index)?;
        if parent_usn <= 0 {
            return Err(Error::ConfiguredRootChanged);
        }
        let components: Vec<_> = parent_components
            .iter()
            .cloned()
            .chain(std::iter::once(name.to_owned()))
            .collect();
        let mut path = root.path.clone();
        for part in &components {
            path.push(part);
        }
        let wide = wide_path(&path)?;
        // Original OVERLAPPED owner, no WRITE or DELETE sharing. Existing
        // writers/deleters must close before admission; no reopen for body I/O.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | 2 | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | 0x4000_0000,
                null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            // Only the first plain child open can be a pre-capture writer wait.
            // Read the exact Win32 code before any other native call.
            let code = unsafe { GetLastError() };
            if code == 32 || code == 33 {
                return Ok(None);
            }
            return Err(native_error(
                "pin encrypted child file",
                (0x8007_0000u32 | code) as i32,
            ));
        }
        let source = RawOwnedHandle(raw);
        let original = root_snapshot(source.0)?;
        let usn = completion_usn(source.0, original.identity.file_index)?;
        let original_basic = completion_basic_info(source.0)?;
        if !plain(original)
            || usn <= 0
            || original.identity.volume_serial != root.identity.volume_serial
            || original.identity == root.identity
            || original.identity == parent_snapshot.identity
            || !links_one(source.0, original.identity)?
            || !windows_paths_equal(
                &final_path_for_handle(source.0).map_err(|_| Error::ConfiguredRootChanged)?,
                &path,
            )
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let pinned = Self {
            root_path: root.path.clone(),
            root: root.identity,
            components,
            route: route.to_vec(),
            parent_identity,
            parent,
            parent_snapshot,
            parent_usn,
            ancestors,
            source,
            original,
            original_basic,
            usn,
            digest: Cell::new(None),
            captured: Cell::new(false),
            converted: None,
            attempted: false,
            _thread: std::marker::PhantomData,
        };
        pinned.verify(connection, false)?;
        Ok(Some(pinned))
    }
    pub(super) fn file(&self) -> crate::LocalFileIdentity {
        crate::LocalFileIdentity {
            volume_serial: self.original.identity.volume_serial,
            file_index: self.original.identity.file_index,
        }
    }
    pub(super) fn parent_file(&self) -> crate::LocalFileIdentity {
        crate::LocalFileIdentity {
            volume_serial: self.parent_snapshot.identity.volume_serial,
            file_index: self.parent_snapshot.identity.file_index,
        }
    }
    pub(super) fn parent_usn(&self) -> i64 {
        self.parent_usn
    }
    pub(super) fn usn(&self) -> i64 {
        self.usn
    }
    pub(super) fn components(&self) -> &[String] {
        &self.components
    }
    pub(super) fn len(&self) -> u64 {
        self.original.file_size
    }
    fn path(&self) -> PathBuf {
        let mut p = self.root_path.clone();
        for c in &self.components {
            p.push(c);
        }
        p
    }
    fn verify_parents(&self) -> Result<(), Error> {
        if !same_edit_snapshot(root_snapshot(self.parent.0)?, self.parent_snapshot)
            || completion_usn(self.parent.0, self.parent_snapshot.identity.file_index)?
                != self.parent_usn
            || native_namespace_directory::opaque_directory_identity(self.parent.0)?
                != *self.parent_identity.as_bytes()
            || self.route.len() != self.ancestors.len() + 1
        {
            return Err(Error::ConfiguredRootChanged);
        }
        for ((handle, snapshot), expected) in self.ancestors.iter().zip(&self.route) {
            let now = root_snapshot(handle.0)?;
            if now.identity != snapshot.identity
                || !cleanup_cloud_reparse_tag(now.reparse_tag)
                || native_namespace_directory::opaque_directory_identity(handle.0)?.as_slice()
                    != expected.identity
            {
                return Err(Error::ConfiguredRootChanged);
            }
        }
        Ok(())
    }
    fn verify_source(
        &self,
        identity: Option<&[u8; 16]>,
        insync: bool,
        usn: i64,
    ) -> Result<(), Error> {
        self.verify_parents()?;
        let now = root_snapshot(self.source.0)?;
        if now.identity != self.original.identity
            || now.file_size != self.original.file_size
            || now.last_write_time != self.original.last_write_time
            || !links_one(self.source.0, self.original.identity)?
            || usn <= 0
            || completion_usn(self.source.0, self.original.identity.file_index)? != usn
            || !windows_paths_equal(
                &final_path_for_handle(self.source.0).map_err(|_| Error::ConfiguredRootChanged)?,
                &self.path(),
            )
        {
            return Err(Error::ConfiguredRootChanged);
        }
        if let Some(identity) = identity {
            if now.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
                || !cleanup_cloud_reparse_tag(now.reparse_tag)
                || now.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
                || now.placeholder_state
                    & (CF_PLACEHOLDER_STATE_PARTIAL | CF_PLACEHOLDER_STATE_PARTIALLY_ON_DISK)
                    != 0
                || now.placeholder_state
                    & !(CF_PLACEHOLDER_STATE_PLACEHOLDER | 0x4 | CF_PLACEHOLDER_STATE_IN_SYNC)
                    != 0
                || (insync && now.placeholder_state & CF_PLACEHOLDER_STATE_IN_SYNC == 0)
                || native_namespace_directory::opaque_directory_identity(self.source.0)?
                    != *identity
            {
                return Err(Error::ConfiguredRootChanged);
            }
        } else if !plain(now)
            || !same_edit_snapshot(now, self.original)
            || completion_basic_info(self.source.0)? != self.original_basic
        {
            return Err(Error::ConfiguredRootChanged);
        }
        Ok(())
    }
    pub(super) fn verify(
        &self,
        connection: &ConfiguredRootConnection,
        converted: bool,
    ) -> Result<(), Error> {
        if !connection.connected
            || connection.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
        {
            return Err(Error::ProviderUnavailable);
        }
        let root = connection
            .root
            .as_ref()
            .ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        if root.identity != self.root || !windows_paths_equal(&root.path, &self.root_path) {
            return Err(Error::ConfiguredRootChanged);
        }
        if converted {
            let identity = self
                .converted
                .as_ref()
                .ok_or(Error::ConfiguredRootChanged)?;
            self.verify_source(Some(identity), true, self.usn)
        } else {
            if self.attempted {
                return Err(Error::EditRecoveryUnavailable);
            }
            self.verify_source(None, false, self.usn)
        }
    }
    fn read_body<T>(
        &self,
        job: &crate::StreamedRecoveryJob,
        stopped: &dyn Fn() -> bool,
        read: impl FnOnce(&mut dyn Read) -> Result<T, Error>,
    ) -> Result<(T, [u8; 32]), Error> {
        if self.attempted || stopped() || job.is_stopped() {
            return Err(Error::EditRecoveryUnavailable);
        }
        self.verify_source(None, false, self.usn)?;
        let mut reader = VaultFileReader {
            source: &self.source,
            offset: 0,
            length: self.len(),
            eof: false,
            hash: Sha256::new(),
            job,
            stopped,
        };
        let value = read(&mut reader)?;
        if !reader.eof || reader.offset != self.len() || stopped() || job.is_stopped() {
            return Err(Error::EditRecoveryUnavailable);
        }
        let digest = reader.hash.finalize().into();
        self.verify_source(None, false, self.usn)?;
        Ok((value, digest))
    }
    pub(super) fn digest(
        &self,
        job: &crate::StreamedRecoveryJob,
        stopped: &dyn Fn() -> bool,
    ) -> Result<[u8; 32], Error> {
        let (_, digest) = self.read_body(job, stopped, |reader| {
            let mut bytes = Zeroizing::new([0u8; 65536]);
            loop {
                if reader
                    .read(&mut *bytes)
                    .map_err(|_| Error::EditRecoveryUnavailable)?
                    == 0
                {
                    break;
                }
            }
            Ok(())
        })?;
        if self.digest.get().is_some_and(|old| old != digest) {
            return Err(Error::ConfiguredRootChanged);
        }
        self.digest.set(Some(digest));
        Ok(digest)
    }
    pub(super) fn with_reader<T>(
        &self,
        job: &crate::StreamedRecoveryJob,
        stopped: &dyn Fn() -> bool,
        read: impl FnOnce(&mut dyn Read) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let expected = self.digest.get().ok_or(Error::EditRecoveryUnavailable)?;
        let (value, digest) = self.read_body(job, stopped, read)?;
        if digest != expected {
            return Err(Error::ConfiguredRootChanged);
        }
        self.captured.set(true);
        Ok(value)
    }
    pub(super) fn send_proof(&self) -> Result<VaultFileSendProof, Error> {
        if self.attempted || !self.captured.get() || self.digest.get().is_none() {
            return Err(Error::EditRecoveryUnavailable);
        }
        self.verify_source(None, false, self.usn)?;
        Ok(VaultFileSendProof {
            root_path: self.root_path.clone(),
            root: self.root,
            components: self.components.clone(),
            route: self.route.clone(),
            parent_identity: self.parent_identity,
            parent: self.parent_snapshot,
            parent_usn: self.parent_usn,
            original: self.original,
            original_basic: self.original_basic,
            usn: self.usn,
        })
    }
    /// Called only after authenticated original-body remote readback and
    /// protected catalogue publication inside the ORIGINAL live epoch fence.
    /// No body I/O or registry reentry occurs under that fence.
    pub(super) fn convert(
        &mut self,
        connection: &ConfiguredRootConnection,
        identity: [u8; 16],
        claim: impl FnOnce() -> bool,
        readonly: bool,
    ) -> Result<(), Error> {
        if identity == [0; 16] || !self.captured.get() || self.digest.get().is_none() {
            return Err(Error::EditRecoveryUnavailable);
        }
        self.verify(connection, false)?;
        self.attempted = true;
        let mut usn = self.usn;
        let hr = unsafe {
            CfConvertToPlaceholder(
                self.source.0,
                identity.as_ptr().cast(),
                16,
                0,
                &mut usn,
                null_mut(),
            )
        };
        if hr < 0 {
            return Err(native_error("convert encrypted child file", hr));
        }
        self.verify_source(Some(&identity), false, usn)?;
        if !claim() {
            return Err(Error::EditRecoveryUnavailable);
        }
        let hr = unsafe { CfSetInSyncState(self.source.0, 1, 0, &mut usn) };
        if hr < 0 {
            return Err(native_error("complete encrypted child file", hr));
        }
        self.verify_source(Some(&identity), true, usn)?;
        let basic = completion_basic_info(self.source.0)?;
        if (basic.file_attributes & FILE_ATTRIBUTE_READONLY != 0) != readonly {
            let attributes = if readonly {
                basic.file_attributes | FILE_ATTRIBUTE_READONLY
            } else {
                basic.file_attributes & !FILE_ATTRIBUTE_READONLY
            };
            let metadata = CfFsMetadata {
                basic_info: FileBasicInfo {
                    file_attributes: attributes & SETTABLE_VAULT_CHILD_ATTRIBUTES,
                    ..basic
                },
                file_size: i64::try_from(self.len()).map_err(|_| Error::EditRecoveryUnavailable)?,
            };
            let hr = unsafe {
                CfUpdatePlaceholder(
                    self.source.0,
                    &metadata,
                    null(),
                    0,
                    null(),
                    0,
                    1 | 2,
                    &mut usn,
                    null_mut(),
                )
            };
            if hr < 0 {
                return Err(native_error("publish encrypted child file attributes", hr));
            }
            self.verify_source(Some(&identity), true, usn)?;
        }
        if (completion_basic_info(self.source.0)?.file_attributes & FILE_ATTRIBUTE_READONLY != 0)
            != readonly
        {
            return Err(Error::ConfiguredRootChanged);
        }
        self.usn = usn;
        self.converted = Some(identity);
        self.verify(connection, true)
    }
}
struct VaultFileReader<'a> {
    source: &'a RawOwnedHandle,
    offset: u64,
    length: u64,
    eof: bool,
    hash: Sha256,
    job: &'a crate::StreamedRecoveryJob,
    stopped: &'a dyn Fn() -> bool,
}
impl Read for VaultFileReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if (self.stopped)() || self.job.is_stopped() {
            return Err(io::Error::other("vault child source stopped"));
        }
        let eof = self.offset == self.length;
        let n = if eof {
            1
        } else {
            bytes
                .len()
                .min(65536)
                .min((self.length - self.offset) as usize)
        };
        let count = native_streamed_io::read_vault_capture_at_with_stop(
            self.source,
            self.offset,
            &mut bytes[..n],
            eof,
            Some(self.job.cancellation()),
            self.stopped,
        )
        .map_err(|_| io::Error::other("vault child source unavailable"))?;
        if (eof && count != 0) || (!eof && count == 0) || (self.stopped)() || self.job.is_stopped()
        {
            return Err(io::Error::other("vault child source changed"));
        }
        self.offset += count as u64;
        self.eof |= eof;
        self.hash.update(&bytes[..count]);
        Ok(count)
    }
}
impl VaultFileSendProof {
    pub(super) fn check(&self) -> Result<(), Error> {
        let rootid = crate::ConfiguredRootIdentity {
            volume_serial: self.root.volume_serial,
            file_index: self.root.file_index,
        };
        let lease = pin_registered_configured_root(&self.root_path, rootid)?;
        let (name, parts) = self
            .components
            .split_last()
            .ok_or(Error::ConfiguredRootChanged)?;
        let refs: Vec<_> = parts.iter().map(String::as_str).collect();
        let (parent, snapshot, _ancestors) =
            native_namespace_directory::pin_reinspected_namespace_parent(
                &lease,
                &self.root_path,
                &self.route,
                self.parent_identity,
                &refs,
            )?;
        if !same_edit_snapshot(snapshot, self.parent)
            || completion_usn(parent.0, snapshot.identity.file_index)? != self.parent_usn
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let mut path = self.root_path.clone();
        for part in parts {
            path.push(part);
        }
        path.push(name);
        // Metadata only, share WRITE to coexist with the original WRITE_DATA
        // owner. Never a second body/writer handle or substitute capture.
        let file = open_root(
            &path,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )?;
        let actual = root_snapshot(file.0)?;
        if !plain(actual)
            || !same_edit_snapshot(actual, self.original)
            || completion_basic_info(file.0)? != self.original_basic
            || !links_one(file.0, self.original.identity)?
            || completion_usn(file.0, self.original.identity.file_index)? != self.usn
            || !windows_paths_equal(
                &final_path_for_handle(file.0).map_err(|_| Error::ConfiguredRootChanged)?,
                &path,
            )
        {
            return Err(Error::ConfiguredRootChanged);
        }
        native_namespace_directory::verify_reinspected_namespace_root(&lease, &self.root_path)
    }
}

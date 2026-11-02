//! Local-metadata-only cleanup completeness fence. No unknown entry is
//! decrypted, hydrated, adopted, uploaded, dehydrated or deleted here.
use super::*;
use std::collections::{BTreeSet, HashMap, HashSet};
const MAX_ENTRIES: usize = 10_000;
const MAX_DEPTH: usize = 64;
const MAX_COMPONENT_BYTES: usize = 16 * 1024 * 1024;
#[repr(C)]
#[allow(dead_code)] // Complete WIN32_FIND_DATAW ABI, including unused metadata.
struct FindData {
    attributes: u32,
    times: [u32; 6],
    size_high: u32,
    size_low: u32,
    reserved: [u32; 2],
    name: [u16; 260],
    alternate: [u16; 14],
}
const _: () = {
    assert!(size_of::<FindData>() == 592);
    assert!(std::mem::offset_of!(FindData, name) == 44);
};
#[link(name = "kernel32")]
unsafe extern "system" {
    fn FindFirstFileExW(
        pattern: *const u16,
        level: i32,
        data: *mut FindData,
        search: i32,
        filter: *const c_void,
        flags: u32,
    ) -> Handle;
    fn FindNextFileW(find: Handle, data: *mut FindData) -> i32;
    fn FindClose(find: Handle) -> i32;
}
struct FindOwner(Handle);
impl Drop for FindOwner {
    fn drop(&mut self) {
        unsafe { FindClose(self.0) };
    }
}
fn local_names(path: &Path) -> Result<Vec<String>, Error> {
    let pattern = wide_path(&path.join("*"))?;
    let mut data: FindData = unsafe { zeroed() };
    // FIND_FIRST_EX_ON_DISK_ENTRIES_ONLY(4) excludes provider-virtual entries.
    // No fallback to ordinary enumeration/population or body recall is allowed.
    let raw = unsafe { FindFirstFileExW(pattern.as_ptr(), 1, &mut data, 0, null(), 4) };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        return match unsafe { GetLastError() } {
            2 | 18 => Ok(Vec::new()),
            _ => Err(win32_io_error("enumerate local vault entries")),
        };
    }
    let find = FindOwner(raw);
    let mut names = Vec::new();
    let mut seen = HashSet::new();
    loop {
        let end = data
            .name
            .iter()
            .position(|u| *u == 0)
            .ok_or(Error::ConfiguredRootChanged)?;
        let name =
            String::from_utf16(&data.name[..end]).map_err(|_| Error::ConfiguredRootChanged)?;
        if name != "." && name != ".." {
            if !valid_component(&name) || names.len() >= MAX_ENTRIES || !seen.insert(name.clone()) {
                return Err(Error::EditRecoveryUnavailable);
            }
            names.push(name);
        }
        if unsafe { FindNextFileW(find.0, &mut data) } == 0 {
            if unsafe { GetLastError() } == 18 {
                break;
            }
            return Err(win32_io_error("continue local vault enumeration"));
        }
    }
    Ok(names)
}
struct Node {
    handle: RawOwnedHandle,
    snapshot: RootSnapshot,
    usn: i64,
    opaque: [u8; 16],
    components: Vec<String>,
    directory: bool,
}
pub(super) struct InventoryFence {
    locator: crate::VaultCleanupRootLocator,
    owned: BTreeSet<[u8; 16]>,
    nodes: Vec<Node>,
    component_bytes: usize,
    _ancestors: Vec<(RawOwnedHandle, RootSnapshot)>,
}
fn path(root: &OwnedConfiguredRoot, components: &[String]) -> PathBuf {
    let mut path = root.path.clone();
    for c in components {
        path.push(c);
    }
    path
}
fn basic_node(
    handle: RawOwnedHandle,
    root: &OwnedConfiguredRoot,
    components: Vec<String>,
    owned: &BTreeSet<[u8; 16]>,
) -> Result<Node, Error> {
    let snapshot = root_snapshot(handle.0)?;
    let directory = snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    let opaque = native_namespace_directory::opaque_directory_identity(handle.0)?;
    let usn = completion_usn(handle.0, snapshot.identity.file_index)?;
    if snapshot.identity.volume_serial != root.identity.volume_serial
        || snapshot.identity.file_index == 0
        || snapshot.identity == root.identity
        || usn <= 0
        || snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        || !cleanup_cloud_reparse_tag(snapshot.reparse_tag)
        || snapshot.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
        || snapshot.placeholder_state & CF_PLACEHOLDER_STATE_SYNC_ROOT != 0
        || snapshot.placeholder_state & !0x3f != 0
        || !owned.contains(&opaque)
        || !windows_paths_equal(
            &final_path_for_handle(handle.0).map_err(|_| Error::ConfiguredRootChanged)?,
            &path(root, &components),
        )
    {
        return Err(Error::EditRecoveryUnavailable);
    }
    if !directory {
        if snapshot.placeholder_state & CF_PLACEHOLDER_STATE_IN_SYNC == 0 {
            return Err(Error::EditRecoveryUnavailable);
        }
        let mut info: ByHandleFileInformation = unsafe { zeroed() };
        if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0 {
            return Err(win32_io_error("inspect local vault file links"));
        }
        if info.number_of_links != 1 {
            return Err(Error::EditRecoveryUnavailable);
        }
    }
    Ok(Node {
        handle,
        snapshot,
        usn,
        opaque,
        components,
        directory,
    })
}
fn file_bound(
    node: &Node,
    rows: &HashMap<[u8; 16], &hydration_inventory::HydratedFileRow>,
    require_empty: bool,
) -> Result<(), Error> {
    if node.directory {
        return Ok(());
    }
    if modified_ranges_for_handle(node.handle.0).map_err(|_| Error::EditRecoveryUnavailable)? {
        return Err(Error::EditRecoveryUnavailable);
    }
    let empty = placeholder_on_disk_empty(node.handle.0)?;
    let bound = rows.get(&node.opaque).is_some_and(|r| {
        r.file_index() == node.snapshot.identity.file_index
            && r.length() == node.snapshot.file_size
            && r.components() == node.components.as_slice()
    });
    if (require_empty && !empty) || (!empty && !bound) {
        return Err(Error::EditRecoveryUnavailable);
    }
    Ok(())
}
impl InventoryFence {
    pub(super) fn begin(
        root: &OwnedConfiguredRoot,
        locator: crate::VaultCleanupRootLocator,
        owned: &BTreeSet<[u8; 16]>,
        rows: &[hydration_inventory::HydratedFileRow],
    ) -> Result<Self, Error> {
        Self::scan(root, locator, owned, rows, false)
    }
    fn scan(
        root: &OwnedConfiguredRoot,
        locator: crate::VaultCleanupRootLocator,
        owned: &BTreeSet<[u8; 16]>,
        rows: &[hydration_inventory::HydratedFileRow],
        require_empty: bool,
    ) -> Result<Self, Error> {
        root.verify_identity(true)?;
        root.verify_registered()?;
        if locator.components.is_empty() || locator.components.len() != locator.route.len() {
            return Err(Error::EditRecoveryUnavailable);
        }
        let last = locator.route.last().ok_or(Error::EditRecoveryUnavailable)?;
        let identity: [u8; 16] = last
            .identity
            .as_slice()
            .try_into()
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        let opaque = locator.identity;
        if opaque.as_bytes() != &identity {
            return Err(Error::EditRecoveryUnavailable);
        }
        let refs: Vec<_> = locator.components.iter().map(String::as_str).collect();
        let (handle, _snapshot, ancestors) = native_namespace_directory::pin_namespace_parent(
            root,
            &locator.route,
            opaque,
            &refs,
            FILE_READ_ATTRIBUTES,
        )?;
        let node = basic_node(handle, root, locator.components.clone(), owned)?;
        if !node.directory || node.opaque != identity {
            return Err(Error::EditRecoveryUnavailable);
        }
        let component_bytes = locator
            .components
            .iter()
            .try_fold(0usize, |sum, s| sum.checked_add(s.len()))
            .ok_or(Error::EditRecoveryUnavailable)?;
        if component_bytes > MAX_COMPONENT_BYTES {
            return Err(Error::EditRecoveryUnavailable);
        }
        let mut scan = Self {
            locator,
            owned: owned.clone(),
            nodes: vec![node],
            component_bytes,
            _ancestors: ancestors,
        };
        let row_index: HashMap<_, _> = rows.iter().map(|r| (*r.identity(), r)).collect();
        if row_index.len() != rows.len() {
            return Err(Error::EditRecoveryUnavailable);
        }
        let mut seen = HashSet::new();
        seen.insert(scan.nodes[0].snapshot.identity.file_index);
        let mut seen_opaque = HashSet::new();
        seen_opaque.insert(scan.nodes[0].opaque);
        scan.walk(
            root,
            0,
            0,
            &row_index,
            require_empty,
            &mut seen,
            &mut seen_opaque,
        )?;
        let nodes: HashMap<_, _> = scan.nodes.iter().map(|n| (n.opaque, n)).collect();
        for row in rows {
            let node = nodes
                .get(row.identity())
                .ok_or(Error::EditRecoveryUnavailable)?;
            if node.directory
                || node.snapshot.identity.file_index != row.file_index()
                || node.snapshot.file_size != row.length()
                || node.components.as_slice() != row.components()
            {
                return Err(Error::EditRecoveryUnavailable);
            }
        }
        drop(nodes);
        scan.verify_pins(root, &row_index, require_empty)?;
        Ok(scan)
    }
    fn walk(
        &mut self,
        root: &OwnedConfiguredRoot,
        index: usize,
        depth: usize,
        rows: &HashMap<[u8; 16], &hydration_inventory::HydratedFileRow>,
        require_empty: bool,
        seen: &mut HashSet<u64>,
        seen_opaque: &mut HashSet<[u8; 16]>,
    ) -> Result<(), Error> {
        if depth > MAX_DEPTH {
            return Err(Error::EditRecoveryUnavailable);
        }
        let directory = &self.nodes[index];
        let components = directory.components.clone();
        let names = local_names(&path(root, &components))?;
        self.check_node(root, index, require_empty)?;
        for name in names {
            if self.nodes.len() >= MAX_ENTRIES || components.len() >= 256 {
                return Err(Error::EditRecoveryUnavailable);
            }
            let mut child = components.clone();
            child.push(name);
            let bytes = child
                .iter()
                .try_fold(0usize, |sum, s| sum.checked_add(s.len()))
                .ok_or(Error::EditRecoveryUnavailable)?;
            self.component_bytes = self
                .component_bytes
                .checked_add(bytes)
                .ok_or(Error::EditRecoveryUnavailable)?;
            if self.component_bytes > MAX_COMPONENT_BYTES {
                return Err(Error::EditRecoveryUnavailable);
            }
            let wide = wide_path(&path(root, &child))?;
            // OPEN_REPARSE_POINT and OPEN_NO_RECALL: metadata only, never
            // traverse a foreign reparse target. Hold every name against delete.
            let raw = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | 0x0010_0000,
                    null_mut(),
                )
            };
            if raw.is_null() || raw == INVALID_HANDLE_VALUE {
                return Err(win32_io_error("pin local vault entry"));
            }
            let node = basic_node(RawOwnedHandle(raw), root, child, &self.owned)?;
            if !seen.insert(node.snapshot.identity.file_index) || !seen_opaque.insert(node.opaque) {
                return Err(Error::EditRecoveryUnavailable);
            }
            file_bound(&node, rows, require_empty)?;
            let is_directory = node.directory;
            let next = self.nodes.len();
            self.nodes.push(node);
            if is_directory {
                self.walk(
                    root,
                    next,
                    depth + 1,
                    rows,
                    require_empty,
                    seen,
                    seen_opaque,
                )?;
            }
        }
        self.check_node(root, index, require_empty)
    }
    fn check_node(
        &self,
        root: &OwnedConfiguredRoot,
        index: usize,
        require_empty: bool,
    ) -> Result<(), Error> {
        let node = &self.nodes[index];
        let current = root_snapshot(node.handle.0)?;
        if current.identity != node.snapshot.identity
            || current.file_size != node.snapshot.file_size
            || (current.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != node.directory
            || current.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            || current.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
            || current.placeholder_state & CF_PLACEHOLDER_STATE_SYNC_ROOT != 0
            || current.placeholder_state & !0x3f != 0
            || (!node.directory && current.placeholder_state & CF_PLACEHOLDER_STATE_IN_SYNC == 0)
            || !cleanup_cloud_reparse_tag(current.reparse_tag)
            || native_namespace_directory::opaque_directory_identity(node.handle.0)? != node.opaque
            || !windows_paths_equal(
                &final_path_for_handle(node.handle.0).map_err(|_| Error::ConfiguredRootChanged)?,
                &path(root, &node.components),
            )
        {
            return Err(Error::EditRecoveryUnavailable);
        }
        let usn = completion_usn(node.handle.0, current.identity.file_index)?;
        if usn <= 0 || ((node.directory || !require_empty) && usn != node.usn) {
            return Err(Error::EditRecoveryUnavailable);
        }
        if !node.directory {
            let mut info: ByHandleFileInformation = unsafe { zeroed() };
            if unsafe { GetFileInformationByHandle(node.handle.0, &mut info) } == 0 {
                return Err(win32_io_error("recheck local vault file links"));
            }
            if info.number_of_links != 1 {
                return Err(Error::EditRecoveryUnavailable);
            }
        }
        if !node.directory && require_empty {
            if modified_ranges_for_handle(node.handle.0)
                .map_err(|_| Error::EditRecoveryUnavailable)?
                || !placeholder_on_disk_empty(node.handle.0)?
            {
                return Err(Error::EditRecoveryUnavailable);
            }
        }
        Ok(())
    }
    fn verify_pins(
        &self,
        root: &OwnedConfiguredRoot,
        rows: &HashMap<[u8; 16], &hydration_inventory::HydratedFileRow>,
        require_empty: bool,
    ) -> Result<(), Error> {
        root.verify_identity(true)?;
        root.verify_registered()?;
        if self._ancestors.len() + 1 != self.locator.route.len() {
            return Err(Error::ConfiguredRootChanged);
        }
        for ((handle, snapshot), expected) in self._ancestors.iter().zip(&self.locator.route) {
            let current = root_snapshot(handle.0)?;
            if current.identity != snapshot.identity
                || !cleanup_cloud_reparse_tag(current.reparse_tag)
                || native_namespace_directory::opaque_directory_identity(handle.0)?.as_slice()
                    != expected.identity
            {
                return Err(Error::ConfiguredRootChanged);
            }
        }
        for index in 0..self.nodes.len() {
            self.check_node(root, index, require_empty)?;
            file_bound(&self.nodes[index], rows, require_empty)?;
        }
        Ok(())
    }
    pub(super) fn verify(
        &self,
        root: &OwnedConfiguredRoot,
        rows: &[hydration_inventory::HydratedFileRow],
    ) -> Result<(), Error> {
        let row_index: HashMap<_, _> = rows.iter().map(|r| (*r.identity(), r)).collect();
        if row_index.len() != rows.len() {
            return Err(Error::EditRecoveryUnavailable);
        }
        self.verify_pins(root, &row_index, true)?;
        let locator = crate::VaultCleanupRootLocator {
            identity: self.locator.identity,
            components: self.locator.components.clone(),
            route: self.locator.route.clone(),
        };
        let current = Self::scan(root, locator, &self.owned, rows, true)?;
        if current.nodes.len() != self.nodes.len() {
            return Err(Error::EditRecoveryUnavailable);
        }
        let nodes: HashMap<_, _> = current.nodes.iter().map(|n| (&n.components, n)).collect();
        for old in &self.nodes {
            let node = nodes
                .get(&old.components)
                .ok_or(Error::EditRecoveryUnavailable)?;
            if node.snapshot.identity != old.snapshot.identity
                || node.snapshot.file_size != old.snapshot.file_size
                || node.opaque != old.opaque
                || node.directory != old.directory
            {
                return Err(Error::EditRecoveryUnavailable);
            }
        }
        self.verify_pins(root, &row_index, true)
    }
}

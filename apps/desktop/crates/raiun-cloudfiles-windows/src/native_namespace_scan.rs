//! Bounded handle-based inventory hints. No cursor or page is publication authority.
use super::*;
use crate::namespace_intent::CapturedAuthorization;
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Weak;
#[path = "native_namespace_scan_parser.rs"]
mod parser;
const MAX_ENTRIES: usize = 20_000;
const MAX_PATH_BYTES: usize = 32 * 1024;
const MAX_QUEUE_BYTES: usize = 1024 * 1024;
const LIST_DIRECTORY: u32 = 1;

#[derive(Clone)]
struct Queued {
    components: Vec<String>,
    identity: [u8; 16],
    physical: RootIdentity,
    navigation: bool,
}
struct Parent {
    queued: Queued,
    handle: RawOwnedHandle,
    snapshot: RootSnapshot,
    _ancestors: Vec<(RawOwnedHandle, RootSnapshot)>,
    expected_children: Vec<crate::PlaceholderChild>,
    route: Vec<crate::PlaceholderChild>,
    started: bool,
}
pub(crate) struct Scan {
    backend: Weak<crate::OpenCloudPlaceholderBackend>,
    composite: crate::OpaqueIdentity,
    root: RootIdentity,
    authorization: CapturedAuthorization,
    generation: u64,
    max_entries: usize,
    examined: usize,
    queued_bytes: usize,
    queue: VecDeque<Queued>,
    parent: Option<Parent>,
    finished: bool,
    failed: bool,
    limit_reached: bool,
    // Explicit owner-thread affinity, independent of raw-handle auto traits.
    _owner: PhantomData<Rc<()>>,
}
fn path_size(parts: &[String]) -> Option<usize> {
    parts
        .iter()
        .try_fold(0usize, |n, p| n.checked_add(p.len())?.checked_add(1))
}
fn opaque(handle: Handle) -> Result<[u8; 16], Error> {
    let mut storage = [0u64; 6];
    let mut returned = 0;
    // SAFETY: aligned initialized48-byte buffer; result bounds and fixed16-byte
    // identity header are checked before slicing. No ownership transfer.
    let hr = unsafe {
        CfGetPlaceholderInfo(
            handle,
            CF_PLACEHOLDER_INFO_BASIC,
            storage.as_mut_ptr().cast(),
            48,
            &mut returned,
        )
    };
    if hr < 0 || !(44..=48).contains(&returned) {
        return Err(Error::ConfiguredRootChanged);
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), returned as usize) };
    if u32::from_ne_bytes(
        bytes[24..28]
            .try_into()
            .map_err(|_| Error::ConfiguredRootChanged)?,
    ) != 16
    {
        return Err(Error::ConfiguredRootChanged);
    }
    bytes[28..44]
        .try_into()
        .map_err(|_| Error::ConfiguredRootChanged)
}
fn open(path: &Path, access: u32) -> Result<RawOwnedHandle, Error> {
    let wide = wide_path(path)?;
    // SAFETY: bounded rooted path while all ancestors are pinned; open the leaf
    // itself, never a name surrogate; omit DELETE sharing throughout enumeration.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(win32_io_error("pin scan directory"));
    }
    Ok(RawOwnedHandle(handle))
}
impl ConfiguredRootConnection {
    fn verify_scan(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        scan: &Scan,
    ) -> Result<(), Error> {
        let actual = scan.backend.upgrade().ok_or(Error::ProviderUnavailable)?;
        let erased: Arc<dyn PlaceholderBackend> = backend.clone();
        if !Arc::ptr_eq(&actual, backend)
            || !Arc::ptr_eq(&erased, &self.state.backend)
            || !self.connected
            || self.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
            || scan.generation == 0
            || scan.authorization.agent_generation != scan.generation
            || scan.authorization.token_generation != backend.scope().token_generation()
            || !backend.owns_composite_root_identity(scan.composite)
        {
            return Err(Error::ProviderUnavailable);
        }
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        if root.identity != scan.root {
            return Err(Error::ConfiguredRootChanged);
        }
        let recovery = self
            .state
            .recovery
            .as_ref()
            .ok_or(Error::EditRecoveryUnavailable)?;
        if recovery.provider_scope() != backend.scope()
            || recovery.root_identity()
                != (crate::ConfiguredRootIdentity {
                    volume_serial: scan.root.volume_serial,
                    file_index: scan.root.file_index,
                })
        {
            return Err(Error::ProviderUnavailable);
        }
        Ok(())
    }
    pub(crate) fn begin_namespace_scan(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        composite: crate::OpaqueIdentity,
        authorization: CapturedAuthorization,
        generation: u64,
        max_entries: usize,
    ) -> Result<Scan, Error> {
        if !(1..=MAX_ENTRIES).contains(&max_entries) {
            return Err(Error::InvalidConfiguredRoot);
        }
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        let mut scan = Scan {
            backend: Arc::downgrade(backend),
            composite,
            root: root.identity,
            authorization,
            generation,
            max_entries,
            examined: 0,
            queued_bytes: 0,
            queue: VecDeque::new(),
            parent: None,
            finished: false,
            failed: false,
            limit_reached: false,
            _owner: PhantomData,
        };
        self.verify_scan(backend, &scan)?;
        scan.queue.push_back(Queued {
            components: Vec::new(),
            identity: *composite.as_bytes(),
            physical: root.identity,
            navigation: true,
        });
        Ok(scan)
    }
    fn scan_parent(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        scan: &Scan,
        queued: Queued,
    ) -> Result<Option<Parent>, Error> {
        self.verify_scan(backend, scan)?;
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        let (handle, snapshot, ancestors, route) = if queued.components.is_empty() {
            let handle = open(&root.path, LIST_DIRECTORY | FILE_READ_ATTRIBUTES)?;
            let snapshot = root_snapshot(handle.0)?;
            if snapshot.identity != root.identity {
                return Err(Error::ConfiguredRootChanged);
            }
            (handle, snapshot, Vec::new(), Vec::new())
        } else {
            let parts = queued
                .components
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            let route = if queued.navigation {
                // ONLY the Spaces child of the authenticated composite root.
                if parts.as_slice() != ["Spaces"] {
                    return Err(Error::ConfiguredRootChanged);
                }
                backend
                    .enumerate(
                        scan.composite.as_bytes(),
                        &CancellationToken::with_timeout(std::time::Duration::from_secs(30)),
                    )
                    .map_err(|_| Error::ProviderUnavailable)?
                    .into_iter()
                    .filter(|c| c.name == "Spaces" && c.metadata.is_directory)
                    .collect::<Vec<_>>()
            } else {
                // Unknown/encrypted/vault or currently unavailable ancestry is
                // not traversed. All inventory remains explicitly unknown.
                let Ok(captured) = backend.capture_namespace_parent(
                    &parts,
                    crate::ConfiguredRootIdentity {
                        volume_serial: scan.root.volume_serial,
                        file_index: scan.root.file_index,
                    },
                    scan.authorization,
                ) else {
                    return Ok(None);
                };
                captured.route
            };
            let expected = route.last().ok_or(Error::ConfiguredRootChanged)?;
            if expected.identity.as_slice() != queued.identity {
                return Err(Error::ConfiguredRootChanged);
            }
            let (handle, snapshot, ancestors) = pin_configured_directory_path(
                root,
                expected,
                &parts,
                LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            )?;
            if ancestors.len() + 1 != route.len() {
                return Err(Error::ConfiguredRootChanged);
            }
            for ((ancestor, state), expected) in ancestors.iter().zip(&route) {
                if !cleanup_cloud_reparse_tag(state.reparse_tag)
                    || opaque(ancestor.0)?.as_slice() != expected.identity
                {
                    return Err(Error::ConfiguredRootChanged);
                }
            }
            if !cleanup_cloud_reparse_tag(snapshot.reparse_tag)
                || opaque(handle.0)? != queued.identity
            {
                return Err(Error::ConfiguredRootChanged);
            }
            (handle, snapshot, ancestors, route)
        };
        if snapshot.identity != queued.physical {
            return Err(Error::ConfiguredRootChanged);
        }
        let expected_children = backend
            .enumerate(
                &queued.identity,
                &CancellationToken::with_timeout(std::time::Duration::from_secs(30)),
            )
            .map_err(|_| Error::ProviderUnavailable)?;
        if expected_children.len() > MAX_ENTRIES {
            return Err(Error::ProviderUnavailable);
        }
        self.verify_scan(backend, scan)?;
        Ok(Some(Parent {
            queued,
            handle,
            snapshot,
            _ancestors: ancestors,
            expected_children,
            route,
            started: false,
        }))
    }
    fn verify_scan_parent(&self, parent: &Parent) -> Result<(), Error> {
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        let before = root_snapshot(parent.handle.0)?;
        if before.identity != parent.snapshot.identity {
            return Err(Error::ConfiguredRootChanged);
        }
        if parent.queued.components.is_empty() {
            let fresh = open(&root.path, FILE_READ_ATTRIBUTES)?;
            if root_snapshot(fresh.0)?.identity != parent.snapshot.identity {
                return Err(Error::ConfiguredRootChanged);
            }
        } else {
            let parts = parent
                .queued
                .components
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            let last = parent.route.last().ok_or(Error::ConfiguredRootChanged)?;
            let (fresh, snapshot, ancestors) =
                pin_configured_directory_path(root, last, &parts, FILE_READ_ATTRIBUTES)?;
            if snapshot.identity != parent.snapshot.identity
                || ancestors.len() + 1 != parent.route.len()
                || !cleanup_cloud_reparse_tag(snapshot.reparse_tag)
                || opaque(fresh.0)? != parent.queued.identity
                || opaque(parent.handle.0)? != parent.queued.identity
            {
                return Err(Error::ConfiguredRootChanged);
            }
            for ((handle, state), expected) in ancestors.iter().zip(&parent.route) {
                if !cleanup_cloud_reparse_tag(state.reparse_tag)
                    || opaque(handle.0)?.as_slice() != expected.identity
                {
                    return Err(Error::ConfiguredRootChanged);
                }
            }
        }
        Ok(())
    }
    pub(crate) fn advance_namespace_scan(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        scan: &mut Scan,
    ) -> Result<crate::NamespaceScanPage, Error> {
        if scan.failed {
            return Err(Error::ConnectionStateInvalid);
        }
        let result = self.advance_namespace_scan_inner(backend, scan);
        if result.is_err() {
            // Never resume a cursor after a partial/failed page and silently
            // skip the failed parent. All handles are synchronous and safely
            // close here; a new scan requires fresh contextual admission.
            scan.failed = true;
            scan.parent = None;
            scan.queue.clear();
            scan.queued_bytes = 0;
        }
        result
    }
    fn advance_namespace_scan_inner(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        scan: &mut Scan,
    ) -> Result<crate::NamespaceScanPage, Error> {
        self.verify_scan(backend, scan)?;
        let mut candidates = Vec::new();
        if scan.finished {
            return Ok(crate::NamespaceScanPage {
                candidates,
                finished: true,
                limit_reached: scan.limit_reached,
            });
        }
        if scan.parent.is_none() {
            let Some(queued) = scan.queue.pop_front() else {
                scan.finished = true;
                return Ok(crate::NamespaceScanPage {
                    candidates,
                    finished: true,
                    limit_reached: false,
                });
            };
            scan.queued_bytes = scan
                .queued_bytes
                .checked_sub(path_size(&queued.components).ok_or(Error::ConfiguredRootChanged)?)
                .ok_or(Error::ConfiguredRootChanged)?;
            scan.parent = self.scan_parent(backend, scan, queued)?;
            if scan.parent.is_none() {
                return Ok(crate::NamespaceScanPage {
                    candidates,
                    finished: false,
                    limit_reached: false,
                });
            }
        }
        let mut parent = scan.parent.take().ok_or(Error::ConnectionStateInvalid)?;
        // Reopen and join the exact pinned parent each page; enumeration itself
        // remains on the retained original HANDLE, excluding pathname ABA.
        self.verify_scan_parent(&parent)?;
        let mut storage = [0u64; parser::BUFFER_BYTES / 8];
        // SAFETY: aligned fixed buffer, live synchronous owned directory handle;
        // GetFileInformationByHandleEx retains neither pointer nor pending I/O.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                parent.handle.0,
                if parent.started { 19 } else { 20 },
                storage.as_mut_ptr().cast(),
                parser::BUFFER_BYTES as u32,
            )
        };
        parent.started = true;
        let mut exhausted = false;
        if ok == 0 {
            if unsafe { GetLastError() } == 18 {
                exhausted = true;
            } else {
                return Err(win32_io_error("enumerate pinned scan directory"));
            }
        } else {
            let bytes = unsafe {
                std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), parser::BUFFER_BYTES)
            };
            let names = parser::parse(bytes).map_err(|_| Error::ConfiguredRootChanged)?;
            for name in names {
                if name == "." || name == ".." {
                    continue;
                }
                if !valid_component(&name) {
                    return Err(Error::ConfiguredRootChanged);
                }
                if scan.examined >= scan.max_entries {
                    scan.limit_reached = true;
                    scan.finished = true;
                    break;
                }
                scan.examined += 1;
                let mut components = parent.queued.components.clone();
                components.push(name.clone());
                let bytes = path_size(&components).ok_or(Error::ConfiguredRootChanged)?;
                if components.len() > 256
                    || bytes > MAX_PATH_BYTES
                    || self
                        .root
                        .as_ref()
                        .and_then(|r| r.path.to_str())
                        .and_then(|p| p.len().checked_add(bytes))
                        .is_none_or(|n| n > MAX_PATH_BYTES)
                {
                    scan.limit_reached = true;
                    scan.finished = true;
                    break;
                }
                let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
                let mut path = root.path.clone();
                for p in &components {
                    path.push(p);
                }
                let leaf = open(&path, FILE_READ_ATTRIBUTES)?;
                let snapshot = root_snapshot(leaf.0)?;
                if snapshot.identity.volume_serial != scan.root.volume_serial
                    || snapshot.identity.file_index == 0
                {
                    return Err(Error::ConfiguredRootChanged);
                }
                if snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
                    continue;
                }
                if snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                    && snapshot.placeholder_state == 0
                {
                    if !parent.queued.navigation {
                        candidates.push(crate::NamespaceDirectoryCandidate {
                            parent_components: parent.queued.components.clone(),
                            name,
                            local_file: LocalFileIdentity {
                                volume_serial: snapshot.identity.volume_serial,
                                file_index: snapshot.identity.file_index,
                            },
                        });
                    }
                    // Plain parents are NEVER traversed before publication.
                    continue;
                }
                if !cleanup_cloud_reparse_tag(snapshot.reparse_tag)
                    || snapshot.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
                {
                    continue;
                }
                let identity = opaque(leaf.0)?;
                if !parent.expected_children.iter().any(|c| {
                    c.metadata.is_directory && c.name == name && c.identity.as_slice() == identity
                }) {
                    continue;
                }
                let navigation = parent.queued.components.is_empty() && name == "Spaces";
                if parent.queued.components.is_empty() && name != "Personal" && name != "Spaces" {
                    continue;
                }
                if scan.queue.len() >= scan.max_entries
                    || scan
                        .queued_bytes
                        .checked_add(bytes)
                        .is_none_or(|n| n > MAX_QUEUE_BYTES)
                {
                    scan.limit_reached = true;
                    scan.finished = true;
                    break;
                }
                scan.queued_bytes += bytes;
                scan.queue.push_back(Queued {
                    components,
                    identity,
                    physical: snapshot.identity,
                    navigation,
                });
            }
        }
        self.verify_scan_parent(&parent)?;
        self.verify_scan(backend, scan)?;
        if !exhausted && !scan.finished {
            scan.parent = Some(parent);
        }
        if scan.finished {
            scan.queue.clear();
            scan.parent = None;
            scan.queued_bytes = 0;
        }
        Ok(crate::NamespaceScanPage {
            candidates,
            finished: scan.finished,
            limit_reached: scan.limit_reached,
        })
    }
}

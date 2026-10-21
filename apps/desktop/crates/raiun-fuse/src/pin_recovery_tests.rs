use super::*;
use raiun_cache::{Cache, PinInfo, PinState};
use raiun_core::backend::CloudBackend;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize};

const ACCOUNT: &str = "recovery-account";
const ORIGIN: &str = "https://example.invalid";
const SPACE: &str = "personal";
const ROOT_ID: &str = "personal-root";

struct TestBackend {
    offline: AtomicBool,
    delete_calls: AtomicUsize,
    files: Mutex<HashMap<String, (RemoteEntry, Vec<u8>)>>,
}

impl TestBackend {
    fn new() -> Self {
        let path = "/saved.txt";
        let body = b"historical bytes".to_vec();
        let entry = RemoteEntry {
            id: "saved-file-id".into(),
            path: path.into(),
            directory: false,
            size: body.len() as u64,
            etag: "saved-etag-v1".into(),
            modified_unix: 1,
            writable: true,
            encrypted: false,
        };
        Self {
            offline: AtomicBool::new(false),
            delete_calls: AtomicUsize::new(0),
            files: Mutex::new(HashMap::from([(path.into(), (entry, body))])),
        }
    }

    fn online(&self) -> Result<(), CloudError> {
        if self.offline.load(Ordering::Acquire) {
            Err(CloudError::new(ErrorKind::Offline, "synthetic offline"))
        } else {
            Ok(())
        }
    }

    fn root() -> RemoteEntry {
        RemoteEntry {
            id: ROOT_ID.into(),
            path: "/".into(),
            directory: true,
            size: 0,
            etag: "root-etag".into(),
            modified_unix: 1,
            writable: true,
            encrypted: false,
        }
    }
}

impl CloudBackend for TestBackend {
    fn server_origin(&self) -> Option<String> {
        Some(ORIGIN.into())
    }

    fn spaces(&self) -> Result<Vec<CloudSpace>, CloudError> {
        Ok(vec![CloudSpace {
            id: SPACE.into(),
            name: "Personal".into(),
            dav_url: format!("{ORIGIN}/dav"),
            personal: true,
            writable: true,
            encrypted: false,
        }])
    }

    fn list(
        &self,
        space: &str,
        path: &str,
        visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
    ) -> Result<(), CloudError> {
        self.online()?;
        if space != SPACE {
            return Err(CloudError::new(
                ErrorKind::NotFound,
                "unknown fixture Space",
            ));
        }
        for (candidate, (entry, _)) in self.files.lock().unwrap().iter() {
            let parent = candidate
                .rsplit_once('/')
                .map(|(parent, _)| if parent.is_empty() { "/" } else { parent });
            if parent == Some(path) {
                visit(entry.clone())?;
            }
        }
        Ok(())
    }

    fn stat(&self, space: &str, path: &str) -> Result<RemoteEntry, CloudError> {
        self.online()?;
        if space != SPACE {
            return Err(CloudError::new(
                ErrorKind::NotFound,
                "unknown fixture Space",
            ));
        }
        if path == "/" {
            return Ok(Self::root());
        }
        self.files
            .lock()
            .unwrap()
            .get(path)
            .map(|(entry, _)| entry.clone())
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "missing fixture file"))
    }

    fn download(
        &self,
        space: &str,
        path: &str,
        expected_etag: Option<&str>,
        destination: &Path,
    ) -> Result<RemoteEntry, CloudError> {
        self.online()?;
        if space != SPACE {
            return Err(CloudError::new(
                ErrorKind::NotFound,
                "unknown fixture Space",
            ));
        }
        let files = self.files.lock().unwrap();
        let (entry, body) = files
            .get(path)
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "missing fixture file"))?;
        if expected_etag.is_some_and(|etag| etag != entry.etag) {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "fixture revision changed",
            ));
        }
        fs::write(destination, body).map_err(io_cloud)?;
        Ok(entry.clone())
    }

    fn upload(
        &self,
        _space: &str,
        _path: &str,
        _source: &Path,
        _condition: WriteCondition,
    ) -> Result<RemoteEntry, CloudError> {
        Err(CloudError::new(
            ErrorKind::Unsupported,
            "fixture is read-only",
        ))
    }

    fn download_in_root(
        &self,
        space: &str,
        path: &str,
        expected_etag: Option<&str>,
        destination: &Path,
        expected_root: &str,
    ) -> Result<RemoteEntry, CloudError> {
        if expected_root != ROOT_ID {
            return Err(CloudError::new(ErrorKind::Conflict, "fixture root changed"));
        }
        self.download(space, path, expected_etag, destination)
    }

    fn mkdir(&self, _space: &str, _path: &str) -> Result<RemoteEntry, CloudError> {
        Err(CloudError::new(
            ErrorKind::Unsupported,
            "fixture is read-only",
        ))
    }

    fn delete(&self, space: &str, path: &str, etag: &str) -> Result<(), CloudError> {
        self.online()?;
        self.delete_calls.fetch_add(1, Ordering::AcqRel);
        if space != SPACE {
            return Err(CloudError::new(
                ErrorKind::NotFound,
                "unknown fixture Space",
            ));
        }
        let mut files = self.files.lock().unwrap();
        match files.get(path) {
            Some((entry, _)) if entry.etag == etag => {
                files.remove(path);
                Ok(())
            }
            Some(_) => Err(CloudError::new(
                ErrorKind::Conflict,
                "fixture revision changed",
            )),
            None => Err(CloudError::new(ErrorKind::NotFound, "missing fixture file")),
        }
    }

    fn rename(
        &self,
        _space: &str,
        _from: &str,
        _to: &str,
        _etag: &str,
    ) -> Result<RemoteEntry, CloudError> {
        Err(CloudError::new(
            ErrorKind::Unsupported,
            "fixture is read-only",
        ))
    }
}

struct Fixture {
    _state: tempfile::TempDir,
    filesystem: RaiunFilesystem,
    backend: Arc<TestBackend>,
    pin: PinInfo,
}

fn stale_fixture() -> Fixture {
    let state = tempfile::tempdir().unwrap();
    let engine_dir = state.path().join("engine");
    let cache_dir = state.path().join("offline-cache");
    fs::create_dir(&cache_dir).unwrap();
    #[cfg(unix)]
    fs::set_permissions(
        &cache_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();

    let backend = Arc::new(TestBackend::new());
    let cache = Cache::open(&cache_dir, 16 * 1024 * 1024).unwrap();
    let engine = Engine::open(&engine_dir, backend.clone())
        .unwrap()
        .with_offline_cache(cache.clone(), ACCOUNT.into(), ORIGIN.into())
        .unwrap();
    let pin = engine.pin_offline_tree(SPACE, "/", |_| {}).unwrap();
    assert_eq!(pin.state, PinState::Ready);
    let scope = cache
        .find_plaintext_scope(ORIGIN, ACCOUNT, SPACE)
        .unwrap()
        .unwrap();

    drop(engine);
    drop(cache);
    let reopened = Cache::open(&cache_dir, 16 * 1024 * 1024).unwrap();
    reopened.invalidate_paths(&scope, &["/"]).unwrap();
    backend.offline.store(true, Ordering::Release);

    let engine = Engine::open(&engine_dir, backend.clone())
        .unwrap()
        .with_offline_cache(reopened, ACCOUNT.into(), ORIGIN.into())
        .unwrap();
    let spool = state.path().join("spool");
    fs::create_dir(&spool).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&spool, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let owner = fs::metadata(state.path()).unwrap();
    let filesystem = RaiunFilesystem::new(
        engine,
        spool,
        owner.uid(),
        owner.gid(),
        "recovery-test-profile".into(),
        VaultMountRegistry::new(),
        Arc::new(Mutex::new(None)),
    )
    .unwrap();
    Fixture {
        _state: state,
        filesystem,
        backend,
        pin,
    }
}

fn recovery_tree(filesystem: &RaiunFilesystem) -> (Node, Node, Node) {
    let root = filesystem.children(PERSONAL).unwrap();
    let catalog = root
        .iter()
        .find(|node| matches!(node.kind, NodeKind::Recovery(RecoveryNode::Catalog { .. })))
        .expect("stale pin exposes a separate historical root")
        .clone();
    let pins = filesystem.children(catalog.ino).unwrap();
    let pin = pins
        .into_iter()
        .find(|node| matches!(node.kind, NodeKind::Recovery(RecoveryNode::Pin { .. })))
        .expect("historical root exposes its retained pin")
        .clone();
    let entries = filesystem.children(pin.ino).unwrap();
    let file = entries
        .into_iter()
        .find(|node| matches!(node.kind, NodeKind::Recovery(RecoveryNode::Entry { .. })))
        .expect("retained pin exposes its historical file")
        .clone();
    (catalog, pin, file)
}

#[test]
fn stale_pin_is_visible_only_in_historical_root_and_reads_exact_cached_bytes() {
    let fixture = stale_fixture();
    assert!(fixture.filesystem.engine.list(SPACE, "/").is_err());
    let (catalog, _pin, file) = recovery_tree(&fixture.filesystem);
    assert_eq!(catalog.name, "Saved offline copies");
    assert_eq!(file.name, "saved.txt");
    assert_eq!(fixture.filesystem.file_type(&file), FileType::RegularFile);
    assert_eq!(fixture.filesystem.attr(&file).perm & 0o222, 0);
    assert!(fixture.backend.offline.load(Ordering::Acquire));

    let fh = fixture
        .filesystem
        .open_node(file.ino, libc::O_RDONLY)
        .unwrap();
    let handle = fixture.filesystem.file_handle(fh).unwrap();
    let mut open = handle.lock().unwrap();
    let OpenFile::Read(ReadHandle::Recovery(reader)) = &mut *open else {
        panic!("historical file must use the exact cached recovery reader");
    };
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"historical bytes");
}

#[test]
fn historical_nodes_reject_write_truncate_create_delete_rename_and_stale_reopen() {
    let fixture = stale_fixture();
    let (catalog, pin, file) = recovery_tree(&fixture.filesystem);
    for flags in [
        libc::O_WRONLY,
        libc::O_RDWR,
        libc::O_RDONLY | libc::O_TRUNC,
        libc::O_RDONLY | libc::O_APPEND,
        libc::O_RDONLY | libc::O_CREAT,
        libc::O_RDONLY | libc::O_EXCL,
    ] {
        assert!(fixture.filesystem.open_node(file.ino, flags).is_err());
    }
    assert!(
        fixture.filesystem.child_path(&pin, "new.txt").is_err(),
        "create under recovery directory is refused"
    );
    assert!(
        fixture.filesystem.child_path(&pin, "saved.txt").is_err(),
        "a recovery file cannot be a rename source"
    );
    assert!(
        fixture
            .filesystem
            .delete_child(pin.ino, OsStr::new("saved.txt"), false)
            .is_err()
    );
    assert!(
        fixture
            .filesystem
            .delete_child(pin.ino, OsStr::new("saved.txt"), true)
            .is_err()
    );

    // A cached synthetic child name may never become a cloud create/rename target.
    let personal = fixture.filesystem.node(PERSONAL).unwrap();
    assert!(
        fixture
            .filesystem
            .child_path(&personal, &catalog.name)
            .is_err()
    );

    fixture
        .filesystem
        .engine
        .cancel_offline_pin(SPACE, &fixture.pin.id)
        .unwrap();
    assert!(
        fixture
            .filesystem
            .open_node(file.ino, libc::O_RDONLY)
            .is_err()
    );
    assert!(fixture.filesystem.children(pin.ino).is_err());
}

#[test]
fn recovery_catalog_uses_a_nonshadowing_name_when_cloud_listing_has_same_label() {
    let fixture = stale_fixture();
    let existing = RemoteEntry {
        id: "cloud-name-id".into(),
        path: "/Saved offline copies".into(),
        directory: true,
        size: 0,
        etag: "cloud-name-etag".into(),
        modified_unix: 1,
        writable: true,
        encrypted: false,
    };
    let mut result = Vec::new();
    fixture
        .filesystem
        .append_recovery_catalog(PERSONAL, SPACE, &[existing], &mut result)
        .unwrap();
    let catalog = result.pop().unwrap();
    assert_eq!(catalog.name, "Saved offline copies (Raiun 1)");
    let personal = fixture.filesystem.node(PERSONAL).unwrap();
    assert!(
        fixture
            .filesystem
            .child_path(&personal, &catalog.name)
            .is_err(),
        "a synthetic recovery label cannot shadow a cloud mutation target"
    );
}

#[test]
fn recovery_alias_tombstone_survives_remote_create_node_replacement() {
    let fixture = stale_fixture();
    let (catalog, _pin, old_file) = recovery_tree(&fixture.filesystem);
    let personal = fixture.filesystem.node(PERSONAL).unwrap();
    let original_body = b"cloud file created after recovery appeared".to_vec();
    let remote_entry = RemoteEntry {
        id: "created-cloud-item-id".into(),
        path: format!("/{}", catalog.name),
        directory: false,
        size: original_body.len() as u64,
        etag: "created-cloud-etag".into(),
        modified_unix: 2,
        writable: true,
        encrypted: false,
    };
    fixture.backend.files.lock().unwrap().insert(
        remote_entry.path.clone(),
        (remote_entry.clone(), original_body.clone()),
    );
    fixture.backend.offline.store(false, Ordering::Release);

    // Simulate a create completion that maps the cloud result at the same
    // parent/name after the synthetic Recovery node was already displayed.
    let remote_ino = fixture
        .filesystem
        .add_node(
            PERSONAL,
            catalog.name.clone(),
            NodeKind::Remote {
                space: SPACE.into(),
                entry: remote_entry,
            },
        )
        .unwrap();
    assert!(matches!(
        fixture.filesystem.node(remote_ino).unwrap().kind,
        NodeKind::Remote { .. }
    ));
    assert!(matches!(
        fixture.filesystem.node(catalog.ino).unwrap().kind,
        NodeKind::Recovery(_)
    ));

    assert!(
        fixture
            .filesystem
            .child_path(&personal, &catalog.name)
            .is_err()
    );
    assert!(
        fixture
            .filesystem
            .open_node(remote_ino, libc::O_RDWR)
            .is_err()
    );
    assert!(
        fixture
            .filesystem
            .delete_child(PERSONAL, OsStr::new(&catalog.name), false)
            .is_err()
    );
    assert!(
        fixture
            .filesystem
            .open_node(catalog.ino, libc::O_RDWR)
            .is_err()
    );
    assert!(
        fixture
            .filesystem
            .open_node(old_file.ino, libc::O_RDWR)
            .is_err()
    );

    let backend_files = fixture.backend.files.lock().unwrap();
    assert_eq!(fixture.backend.delete_calls.load(Ordering::Acquire), 0);
    assert_eq!(
        backend_files.get(&format!("/{}", catalog.name)).unwrap().1,
        original_body,
        "the alias tombstone prevents deleting the colliding cloud file"
    );
    assert!(backend_files.contains_key("/saved.txt"));
}

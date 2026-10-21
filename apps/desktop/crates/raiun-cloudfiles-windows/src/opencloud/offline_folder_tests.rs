use super::*;
use crate::opencloud::listed_folders::{SavedFolderIntent, SavedFolderIntentState};
use raiun_cache::{
    AvailabilityPolicy, Cache, CacheScope, ContentProtection, ContentVersion, PinInfo, PinState,
    ScopeProtection,
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

const FILE_BODY: &[u8] = b"nested body";

struct FolderFixture {
    worker: Option<thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
    get_count: Arc<AtomicUsize>,
    backend: OpenCloudPlaceholderBackend,
    selected: DirectoryBinding,
    // Keep the backing directory alive until the backend/cache handles drop.
    _cache_temp: tempfile::TempDir,
}

impl FolderFixture {
    fn new(encrypted_child: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let worker_requests = requests.clone();
        let get_count = Arc::new(AtomicUsize::new(0));
        let worker_get_count = get_count.clone();
        let worker = thread::spawn(move || {
            let mut idle = 0;
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        idle = 0;
                        respond_folder_request(
                            &mut stream,
                            address,
                            encrypted_child,
                            &worker_requests,
                            &worker_get_count,
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        idle += 1;
                        if idle > 400 {
                            break;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("folder fixture accept failed: {error}"),
                }
            }
        });
        let server = format!("http://{address}");
        let client = Arc::new(OpenCloudClient::new(&server, "test-token".into()).unwrap());
        let account_id = derive_account_id(&server, "personal-drive");
        let scope = ProviderScope::new(
            client.as_ref(),
            "profile-offline-folder-test".into(),
            account_id,
            client.server_origin().unwrap(),
        )
        .unwrap();
        let catalog = Arc::new(MemoryIdentityCatalog::default());
        let cache_temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(cache_temp.path(), 1024 * 1024).unwrap();
        let backend = OpenCloudPlaceholderBackend::new_with_identity_catalog_and_cache(
            client,
            scope,
            crate::ConfiguredRootIdentity {
                volume_serial: 0x4117,
                file_index: 0x829113,
            },
            catalog,
            cache,
        )
        .unwrap();

        let root = backend
            .register_composite_root_for("personal-drive", "personal-root")
            .unwrap();
        let root_children = backend
            .enumerate(root.as_bytes(), &CancellationToken::new())
            .unwrap();
        let spaces = root_children
            .iter()
            .find(|child| child.name == "Spaces")
            .expect("composite root exposes Spaces");
        let spaces_children = backend
            .enumerate(&spaces.identity, &CancellationToken::new())
            .unwrap();
        let projects = spaces_children
            .iter()
            .find(|child| child.name == "Projects")
            .expect("fixture exposes ordinary Projects space");
        let project_children = backend
            .enumerate(&projects.identity, &CancellationToken::new())
            .unwrap();
        let docs = project_children
            .iter()
            .find(|child| child.name == "docs")
            .expect("fixture exposes nested docs directory");
        let identity = OpaqueIdentity(docs.identity.as_slice().try_into().unwrap());
        let selected = backend
            .state
            .lock()
            .unwrap()
            .directories
            .get(&identity)
            .expect("docs directory binding was admitted")
            .clone();
        if !encrypted_child {
            // Keep a complete cached selected-folder listing so the offline
            // test proves that cached metadata cannot seed a new pin.
            backend
                .enumerate(&docs.identity, &CancellationToken::new())
                .unwrap();
        }

        Self {
            worker: Some(worker),
            stop,
            requests,
            get_count,
            backend,
            selected,
            _cache_temp: cache_temp,
        }
    }

    fn expected(&self) -> FolderCacheBindingExpectation<'_> {
        FolderCacheBindingExpectation {
            space_id: &self.selected.space_id,
            root_resource_id: &self.selected.root_resource_id,
            path: &self.selected.path,
            resource_id: &self.selected.remote_id,
        }
    }

    fn cache(&self) -> &Cache {
        self.backend.cache.as_ref().unwrap()
    }

    fn cache_scope(&self) -> CacheScope {
        CacheScope::new(
            self.backend.scope().server_origin(),
            self.backend.scope().account_id(),
            &self.selected.space_id,
            &self.selected.root_resource_id,
            ScopeProtection::PlaintextAllowed,
        )
        .unwrap()
    }

    fn stop_server(&mut self) {
        if let Some(worker) = self.worker.take() {
            self.stop.store(true, Ordering::Release);
            worker.join().unwrap();
        }
    }

    fn depth_one_requests_for(&self, prefix: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| {
                request.starts_with(prefix)
                    && request
                        .lines()
                        .any(|line| line.eq_ignore_ascii_case("depth: 1"))
            })
            .count()
    }
}

impl Drop for FolderFixture {
    fn drop(&mut self) {
        self.stop_server();
    }
}

fn respond_folder_request(
    stream: &mut TcpStream,
    address: std::net::SocketAddr,
    encrypted_child: bool,
    requests: &Mutex<Vec<String>>,
    get_count: &AtomicUsize,
) {
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut request = Vec::new();
    let mut chunk = [0_u8; 2048];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let count = stream.read(&mut chunk).unwrap();
        assert_ne!(count, 0);
        request.extend_from_slice(&chunk[..count]);
        assert!(request.len() <= 32 * 1024);
    }
    let request = String::from_utf8(request).unwrap();
    let first_line = request.lines().next().unwrap_or_default().to_owned();
    requests.lock().unwrap().push(request.clone());
    let target = first_line.split_whitespace().nth(1).unwrap_or_default();

    if first_line.starts_with("GET /graph/") {
        let graph = format!(
            r#"{{"value":[{{"id":"personal-drive","name":"Personal","driveType":"personal","root":{{"id":"personal-root","webDavUrl":"http://{address}/dav/personal/"}}}},{{"id":"projects-drive","name":"Projects","driveType":"project","root":{{"id":"projects-root","webDavUrl":"http://{address}/dav/projects/"}}}}]}}"#
        );
        write_response(stream, "200 OK", "application/json", graph.as_bytes());
        return;
    }

    if first_line.starts_with("GET /dav/projects/docs/notes.txt") {
        get_count.fetch_add(1, Ordering::AcqRel);
        assert!(
            request
                .lines()
                .any(|line| line.eq_ignore_ascii_case("if-match: \"notes-etag\""))
        );
        let range = request
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("range: bytes=")
                    .map(str::to_owned)
            })
            .expect("offline file transfer is a bounded range request");
        let (start, end) = range.split_once('-').unwrap();
        let start: usize = start.parse().unwrap();
        let end: usize = end.parse().unwrap();
        assert!(start <= end && end < FILE_BODY.len());
        let body = &FILE_BODY[start..=end];
        let headers = format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{end}/{}\r\nETag: \"notes-etag\"\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
            body.len(),
            FILE_BODY.len()
        );
        stream.write_all(headers.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        return;
    }

    if first_line.starts_with("PROPFIND ") {
        let depth_one = request
            .lines()
            .any(|line| line.eq_ignore_ascii_case("depth: 1"));
        let normalized = target.trim_end_matches('/');
        let xml = if normalized == "/dav/personal" {
            collection_response("/dav/personal/", "personal-root", "personal-etag", "")
        } else if normalized == "/dav/projects" {
            let child = if depth_one {
                directory_child("/dav/projects/docs/", "docs-folder", "docs-etag")
            } else {
                String::new()
            };
            collection_response("/dav/projects/", "projects-root", "projects-etag", &child)
        } else if normalized == "/dav/projects/docs" {
            let children = if depth_one {
                let file = file_child(
                    "/dav/projects/docs/notes.txt",
                    "notes-file",
                    "notes-etag",
                    FILE_BODY.len(),
                );
                let encrypted = if encrypted_child {
                    encrypted_directory_child("/dav/projects/docs/Secret.vault/", "secret-folder")
                } else {
                    String::new()
                };
                format!("{file}{encrypted}")
            } else {
                String::new()
            };
            collection_response("/dav/projects/docs/", "docs-folder", "docs-etag", &children)
        } else if normalized == "/dav/projects/docs/notes.txt" {
            file_response(
                "/dav/projects/docs/notes.txt",
                "notes-file",
                "notes-etag",
                FILE_BODY.len(),
            )
        } else {
            panic!("unexpected folder fixture PROPFIND path: {target}");
        };
        write_response(
            stream,
            "207 Multi-Status",
            "application/xml",
            xml.as_bytes(),
        );
        return;
    }

    panic!("unexpected folder fixture request: {first_line}");
}

fn response_element(
    href: &str,
    id: &str,
    etag: &str,
    size: usize,
    directory: bool,
    extra: &str,
) -> String {
    let resource_type = if directory {
        "<d:resourcetype><d:collection/></d:resourcetype>"
    } else {
        "<d:resourcetype/>"
    };
    format!(
        "<d:response><d:href>{href}</d:href><d:propstat><d:prop>{resource_type}<d:getcontentlength>{size}</d:getcontentlength><d:getetag>\"{etag}\"</d:getetag><oc:fileid>{id}</oc:fileid>{extra}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
    )
}

fn collection_response(href: &str, id: &str, etag: &str, children: &str) -> String {
    format!(
        "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">{}{children}</d:multistatus>",
        response_element(href, id, etag, 0, true, "")
    )
}

fn directory_child(href: &str, id: &str, etag: &str) -> String {
    response_element(href, id, etag, 0, true, "")
}

fn file_child(href: &str, id: &str, etag: &str, size: usize) -> String {
    response_element(href, id, etag, size, false, "")
}

fn encrypted_directory_child(href: &str, id: &str) -> String {
    response_element(
        href,
        id,
        "secret-etag",
        0,
        true,
        "<d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype>",
    )
}

fn file_response(href: &str, id: &str, etag: &str, size: usize) -> String {
    format!(
        "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">{}</d:multistatus>",
        response_element(href, id, etag, size, false, "")
    )
}

fn write_response(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
}

fn content_version(id: &str, etag: &str) -> ContentVersion {
    ContentVersion {
        resource_id: id.into(),
        etag: etag.into(),
        protection: ContentProtection::Plaintext,
    }
}

#[test]
fn fresh_nested_folder_pin_validates_parent_membership_and_downloads_exact_file() {
    let mut fixture = FolderFixture::new(false);
    assert_eq!(fixture.selected.path.trim_end_matches('/'), "/docs");
    assert_eq!(fixture.selected.remote_id, "docs-folder");

    let parent_listings_before = fixture.depth_one_requests_for("PROPFIND /dav/projects/ ");
    let mut progress = Vec::<PinInfo>::new();
    let pin = fixture
        .backend
        .pin_folder_offline_for_binding(
            &fixture.expected(),
            &CancellationToken::for_offline_job(),
            |info| progress.push(info),
        )
        .unwrap();
    assert_eq!(pin.state, PinState::Ready);
    assert_eq!(pin.root_resource_id, "docs-folder");
    assert_eq!(pin.root_path.trim_end_matches('/'), "/docs");
    assert_eq!(pin.item_count, 1);
    assert_eq!(pin.ready_content_count, 1);
    assert_eq!(pin.required_content_count, 1);
    assert_eq!(progress.first().unwrap().state, PinState::Building);
    assert_eq!(progress.last().unwrap().state, PinState::Ready);
    assert_eq!(
        fixture.depth_one_requests_for("PROPFIND /dav/projects/ "),
        parent_listings_before + 1,
        "pin admission must freshly list the selected folder's parent"
    );
    assert_eq!(fixture.get_count.load(Ordering::Acquire), 1);

    let cache_scope = fixture.cache_scope();
    assert_eq!(
        fixture.cache().policy(&cache_scope, "notes-file").unwrap(),
        AvailabilityPolicy::Recent,
        "folder pinning must not create a per-file AlwaysOffline policy"
    );
    assert_eq!(
        fixture
            .cache()
            .content_record(
                &cache_scope,
                &content_version("notes-file", "\"notes-etag\"")
            )
            .unwrap()
            .byte_len,
        FILE_BODY.len() as u64
    );

    fixture.stop_server();
    let mut cached = fixture
        .cache()
        .open_content(
            &cache_scope,
            &content_version("notes-file", "\"notes-etag\""),
        )
        .unwrap();
    let mut body = Vec::new();
    cached.read_to_end(&mut body).unwrap();
    assert_eq!(body, FILE_BODY);
}

#[test]
fn listed_folder_page_projects_admitted_directory_tuple_without_network_access() {
    let fixture = FolderFixture::new(false);
    let requests_before = fixture.requests.lock().unwrap().len();
    let gets_before = fixture.get_count.load(Ordering::Acquire);

    let page = fixture
        .backend
        .listed_folder_page(None, &CancellationToken::new())
        .unwrap();
    assert!(page.read_only);
    assert!(page.last_observed);
    assert!(!page.atomic_snapshot);
    assert_eq!(page.unavailable_rows, 0);
    assert!(page.rows.contains(&ListedFolderRow {
        space_id: fixture.selected.space_id.clone(),
        root_resource_id: fixture.selected.root_resource_id.clone(),
        path: fixture.selected.path.clone(),
        resource_id: fixture.selected.remote_id.clone(),
        space_label: "Spaces / Projects".into(),
        saved_intent: SavedFolderIntent { state: SavedFolderIntentState::None, active_pin_id: None, staging_pin_id: None, staging_is_initial: false },
    }));
    for row in &page.rows {
        let value = serde_json::to_value(row).unwrap();
        let fields = value.as_object().unwrap();
        assert_eq!(fields.len(), 6);
        assert!(fields.contains_key("saved_intent"));
        assert!(fields.contains_key("space_id"));
        assert!(fields.contains_key("root_resource_id"));
        assert!(fields.contains_key("path"));
        assert!(fields.contains_key("resource_id"));
        assert!(fields.contains_key("space_label"));
    }
    assert_eq!(fixture.requests.lock().unwrap().len(), requests_before);
    assert_eq!(fixture.get_count.load(Ordering::Acquire), gets_before);

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(matches!(
        fixture.backend.listed_folder_page(None, &cancelled),
        Err(BackendError::Cancelled)
    ));
    assert_eq!(fixture.requests.lock().unwrap().len(), requests_before);
    assert_eq!(fixture.get_count.load(Ordering::Acquire), gets_before);

    fixture.backend.revoke();
    assert!(
        fixture
            .backend
            .listed_folder_page(None, &CancellationToken::new())
            .is_err()
    );
    assert_eq!(fixture.requests.lock().unwrap().len(), requests_before);
    assert_eq!(fixture.get_count.load(Ordering::Acquire), gets_before);
}

#[test]
fn folder_page_omits_identity_only_roots_until_friendly_names_are_discovered() {
    let fixture = FolderFixture::new(false);
    let requests_before = fixture.requests.lock().unwrap().len();
    let labelled = fixture
        .backend
        .listed_folder_page(None, &CancellationToken::new())
        .unwrap();
    assert!(labelled.rows.iter().any(|row| row.space_label == "Personal"));
    assert!(labelled.rows.iter().any(|row| row.space_label == "Spaces / Projects"));
    fixture.backend.state.lock().unwrap().location_labels.clear();
    let unlabelled = fixture
        .backend
        .listed_folder_page(None, &CancellationToken::new())
        .unwrap();
    assert!(unlabelled.rows.is_empty());
    assert_eq!(unlabelled.unavailable_rows, labelled.rows.len());
    assert_eq!(fixture.requests.lock().unwrap().len(), requests_before);
    assert_eq!(fixture.get_count.load(Ordering::Acquire), 0);
}

#[test]
fn cached_folder_listing_cannot_admit_a_new_pin_when_server_is_offline() {
    let mut fixture = FolderFixture::new(false);
    let cache_scope = fixture.cache_scope();
    let cached = fixture
        .cache()
        .listing(&cache_scope, "docs-folder")
        .unwrap();
    assert!(cached.complete);
    assert_eq!(cached.entries.len(), 1);
    assert_eq!(cached.entries[0].entry.id, "notes-file");
    fixture.stop_server();
    // Ordinary enumeration still supports its existing cached fallback. That
    // same metadata must not authorize a newly requested folder snapshot.
    let identity = fixture
        .backend
        .state
        .lock()
        .unwrap()
        .directories
        .iter()
        .find(|(_, binding)| **binding == fixture.selected)
        .map(|(id, _)| *id)
        .unwrap();
    let children = fixture
        .backend
        .enumerate(identity.as_bytes(), &CancellationToken::new())
        .unwrap();
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].name, "notes.txt");

    let result = fixture.backend.pin_folder_offline_for_binding(
        &fixture.expected(),
        &CancellationToken::for_offline_job(),
        |_| {},
    );
    assert!(
        result.is_err(),
        "fresh remote tree validation must fail offline"
    );
    assert!(fixture.cache().pins(&cache_scope).unwrap().is_empty());
    assert_eq!(fixture.get_count.load(Ordering::Acquire), 0);
}

#[test]
fn cancellation_on_initial_building_progress_preserves_durable_pin_without_get() {
    let fixture = FolderFixture::new(false);
    let cache_scope = fixture.cache_scope();
    let cancellation = CancellationToken::for_offline_job();
    let mut progress = Vec::<PinInfo>::new();
    let result = fixture.backend.pin_folder_offline_for_binding(
        &fixture.expected(),
        &cancellation,
        |info| {
            progress.push(info);
            if progress
                .last()
                .is_some_and(|info| info.state == PinState::Building)
            {
                cancellation.cancel();
            }
        },
    );

    assert!(matches!(
        result,
        Err(OfflineDownloadError::Backend(BackendError::Cancelled))
    ));
    assert_eq!(progress.len(), 1);
    assert_eq!(progress[0].state, PinState::Building);
    assert_eq!(fixture.get_count.load(Ordering::Acquire), 0);
    let pins = fixture.cache().pins(&cache_scope).unwrap();
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0].id, progress[0].id);
    assert_eq!(pins[0].state, PinState::Building);
    assert_eq!(pins[0].required_content_count, 1);
    assert_eq!(pins[0].ready_content_count, 0);
    assert!(matches!(
        fixture.cache().content_record(
            &cache_scope,
            &content_version("notes-file", "\"notes-etag\"")
        ),
        Err(raiun_cache::CacheError::NotFound)
    ));
}

#[test]
fn repeated_initial_folder_save_refuses_existing_building_pin_without_get() {
    let fixture = FolderFixture::new(false);
    let cache_scope = fixture.cache_scope();
    let cancellation = CancellationToken::for_offline_job();
    let mut initial_id = None;
    let first = fixture.backend.pin_folder_offline_for_binding(
        &fixture.expected(),
        &cancellation,
        |info| {
            initial_id = Some(info.id);
            cancellation.cancel();
        },
    );
    assert!(matches!(
        first,
        Err(OfflineDownloadError::Backend(BackendError::Cancelled))
    ));
    let initial_id = initial_id.expect("initial admission must expose its durable pin");
    let mut repeated_progress = Vec::new();
    let repeated = fixture.backend.pin_folder_offline_for_binding(
        &fixture.expected(),
        &CancellationToken::for_offline_job(),
        |info| repeated_progress.push(info),
    );
    assert!(repeated.is_err(), "a fresh save must not duplicate saved intent");
    assert!(repeated_progress.is_empty());
    assert_eq!(fixture.get_count.load(Ordering::Acquire), 0);
    let pins = fixture.cache().pins(&cache_scope).unwrap();
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0].id, initial_id);
    assert_eq!(pins[0].state, PinState::Building);
    assert_eq!(pins[0].ready_content_count, 0);
}

#[test]
fn retry_resumes_the_exact_building_pin_and_finishes_without_duplicate_pins() {
    let fixture = FolderFixture::new(false);
    let cache_scope = fixture.cache_scope();
    let first_cancellation = CancellationToken::for_offline_job();
    let mut first_progress = Vec::<PinInfo>::new();
    let first = fixture.backend.pin_folder_offline_for_binding(
        &fixture.expected(),
        &first_cancellation,
        |info| {
            first_progress.push(info);
            if first_progress
                .last()
                .is_some_and(|info| info.state == PinState::Building)
            {
                first_cancellation.cancel();
            }
        },
    );

    assert!(matches!(
        first,
        Err(OfflineDownloadError::Backend(BackendError::Cancelled))
    ));
    assert_eq!(first_progress.len(), 1);
    let durable_id = first_progress[0].id.clone();
    assert_eq!(fixture.get_count.load(Ordering::Acquire), 0);
    let interrupted = fixture.cache().pins(&cache_scope).unwrap();
    assert_eq!(interrupted.len(), 1);
    assert_eq!(interrupted[0].id, durable_id);
    assert_eq!(interrupted[0].state, PinState::Building);

    let parent_proofs_before = fixture.depth_one_requests_for("PROPFIND /dav/projects/ ");
    let retry_cancellation = CancellationToken::for_offline_job();
    let mut retry_progress = Vec::<PinInfo>::new();
    let completed = fixture
        .backend
        .resume_folder_offline_for_binding(
            &fixture.expected(),
            &durable_id,
            &retry_cancellation,
            |info| retry_progress.push(info),
        )
        .unwrap();

    assert_eq!(completed.id, durable_id);
    assert_eq!(completed.state, PinState::Ready);
    assert_eq!(completed.item_count, 1);
    assert_eq!(completed.ready_content_count, 1);
    assert_eq!(completed.required_content_count, 1);
    assert_eq!(retry_progress.first().unwrap().state, PinState::Building);
    assert_eq!(retry_progress.last().unwrap().state, PinState::Ready);
    assert_eq!(
        fixture.depth_one_requests_for("PROPFIND /dav/projects/ "),
        parent_proofs_before + 1
    );
    assert_eq!(fixture.get_count.load(Ordering::Acquire), 1);

    let pins = fixture.cache().pins(&cache_scope).unwrap();
    assert_eq!(
        pins.len(),
        1,
        "retry must not allocate a second durable pin"
    );
    assert_eq!(pins[0].id, durable_id);
    assert_eq!(pins[0].state, PinState::Ready);
    assert_eq!(
        fixture.cache().policy(&cache_scope, "notes-file").unwrap(),
        AvailabilityPolicy::Recent,
        "resuming a folder pin must not create per-file AlwaysOffline policy"
    );
    let mut content = fixture
        .cache()
        .open_content(
            &cache_scope,
            &content_version("notes-file", "\"notes-etag\""),
        )
        .unwrap();
    let mut bytes = Vec::new();
    content.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, FILE_BODY);
}

#[test]
fn wrong_directory_identity_and_encrypted_child_fail_before_pin_creation() {
    let fixture = FolderFixture::new(false);
    let cache_scope = fixture.cache_scope();
    let mut wrong = fixture.expected();
    wrong.resource_id = "different-folder";
    assert!(
        fixture
            .backend
            .pin_folder_offline_for_binding(&wrong, &CancellationToken::for_offline_job(), |_| {})
            .is_err()
    );
    assert!(fixture.cache().pins(&cache_scope).unwrap().is_empty());

    let encrypted_fixture = FolderFixture::new(true);
    let encrypted_scope = encrypted_fixture.cache_scope();
    let result = encrypted_fixture.backend.pin_folder_offline_for_binding(
        &encrypted_fixture.expected(),
        &CancellationToken::for_offline_job(),
        |_| {},
    );
    assert!(
        result.is_err(),
        "encrypted descendants fail the whole folder pin"
    );
    assert!(
        encrypted_fixture
            .cache()
            .pins(&encrypted_scope)
            .unwrap()
            .is_empty()
    );
    assert_eq!(encrypted_fixture.get_count.load(Ordering::Acquire), 0);
}

#[test]
fn refreshing_ready_folder_snapshot_keeps_active_id_and_cached_bytes() {
    let fixture = FolderFixture::new(false);
    let scope = fixture.cache_scope();
    let active = fixture
        .backend
        .pin_folder_offline_for_binding(
            &fixture.expected(),
            &CancellationToken::for_offline_job(),
            |_| {},
        )
        .unwrap();
    assert_eq!(active.state, PinState::Ready);
    assert_eq!(fixture.cache().pins(&scope).unwrap().len(), 1);

    let version = content_version("notes-file", "\"notes-etag\"");
    let mut old_content = fixture.cache().open_content(&scope, &version).unwrap();
    let mut old_bytes = Vec::new();
    old_content.read_to_end(&mut old_bytes).unwrap();
    assert_eq!(old_bytes, FILE_BODY);
    let gets_before_refresh = fixture.get_count.load(Ordering::Acquire);

    let mut progress = Vec::new();
    let refreshed = fixture
        .backend
        .refresh_folder_offline_for_binding(
            &fixture.expected(),
            &active.id,
            None,
            &CancellationToken::for_offline_job(),
            |info| progress.push(info),
        )
        .unwrap();

    assert_eq!(refreshed.id, active.id);
    assert_eq!(refreshed.state, PinState::Ready);
    assert_eq!(progress.first().unwrap().state, PinState::Building);
    assert_ne!(progress.first().unwrap().id, active.id);
    assert_eq!(progress.last().unwrap().id, active.id);
    assert_eq!(progress.last().unwrap().state, PinState::Ready);
    let pins = fixture.cache().pins(&scope).unwrap();
    assert_eq!(pins.len(), 1, "the staging pin must retire after promotion");
    assert_eq!(pins[0].id, active.id);
    assert_eq!(pins[0].state, PinState::Ready);
    assert_eq!(
        fixture.cache().policy(&scope, "notes-file").unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(
        fixture.get_count.load(Ordering::Acquire),
        gets_before_refresh
    );
    let mut refreshed_content = fixture.cache().open_content(&scope, &version).unwrap();
    let mut refreshed_bytes = Vec::new();
    refreshed_content.read_to_end(&mut refreshed_bytes).unwrap();
    assert_eq!(refreshed_bytes, old_bytes);
}

#[test]
fn cancelled_folder_refresh_preserves_both_pins_and_retries_exact_stage() {
    let fixture = FolderFixture::new(false);
    let scope = fixture.cache_scope();
    let active = fixture
        .backend
        .pin_folder_offline_for_binding(
            &fixture.expected(),
            &CancellationToken::for_offline_job(),
            |_| {},
        )
        .unwrap();
    assert_eq!(active.state, PinState::Ready);

    let version = content_version("notes-file", "\"notes-etag\"");
    let mut old_content = fixture.cache().open_content(&scope, &version).unwrap();
    let mut old_bytes = Vec::new();
    old_content.read_to_end(&mut old_bytes).unwrap();
    assert_eq!(old_bytes, FILE_BODY);
    let gets_before_refresh = fixture.get_count.load(Ordering::Acquire);

    let cancellation = CancellationToken::for_offline_job();
    let mut progress = Vec::new();
    let mut staging_id = None;
    let cancelled = fixture.backend.refresh_folder_offline_for_binding(
        &fixture.expected(),
        &active.id,
        None,
        &cancellation,
        |info| {
            if info.state == PinState::Building && staging_id.is_none() {
                staging_id = Some(info.id.clone());
                cancellation.cancel();
            }
            progress.push(info);
        },
    );
    assert!(matches!(
        cancelled,
        Err(OfflineDownloadError::Backend(BackendError::Cancelled))
    ));
    assert_eq!(progress.len(), 1);
    assert_eq!(progress[0].state, PinState::Building);
    let staging_id = staging_id.expect("the staging ID is reported before cancellation");
    assert_ne!(staging_id, active.id);

    let interrupted = fixture.cache().pins(&scope).unwrap();
    assert_eq!(interrupted.len(), 2);
    assert_eq!(
        interrupted
            .iter()
            .find(|pin| pin.id == active.id)
            .unwrap()
            .state,
        PinState::Ready
    );
    assert_eq!(
        interrupted
            .iter()
            .find(|pin| pin.id == staging_id)
            .unwrap()
            .state,
        // pins() verifies cached bytes and can legitimately promote a stage.
        PinState::Ready
    );
    assert_eq!(
        fixture.cache().policy(&scope, "notes-file").unwrap(),
        AvailabilityPolicy::Recent
    );
    let mut retained_content = fixture.cache().open_content(&scope, &version).unwrap();
    let mut retained_bytes = Vec::new();
    retained_content.read_to_end(&mut retained_bytes).unwrap();
    assert_eq!(retained_bytes, old_bytes);
    assert_eq!(
        fixture.get_count.load(Ordering::Acquire),
        gets_before_refresh
    );

    let mut retry_progress = Vec::new();
    let refreshed = fixture
        .backend
        .refresh_folder_offline_for_binding(
            &fixture.expected(),
            &active.id,
            Some(&staging_id),
            &CancellationToken::for_offline_job(),
            |info| retry_progress.push(info),
        )
        .unwrap();

    assert_eq!(refreshed.id, active.id);
    assert_eq!(refreshed.state, PinState::Ready);
    assert_eq!(retry_progress.first().unwrap().id, staging_id);
    assert_eq!(retry_progress.first().unwrap().state, PinState::Building);
    assert_eq!(retry_progress.last().unwrap().id, active.id);
    assert_eq!(retry_progress.last().unwrap().state, PinState::Ready);
    let completed = fixture.cache().pins(&scope).unwrap();
    assert_eq!(
        completed.len(),
        1,
        "retry must not leave a duplicate stage pin"
    );
    assert_eq!(completed[0].id, active.id);
    assert_eq!(completed[0].state, PinState::Ready);
    assert_eq!(
        fixture.cache().policy(&scope, "notes-file").unwrap(),
        AvailabilityPolicy::Recent
    );
    assert_eq!(
        fixture.get_count.load(Ordering::Acquire),
        gets_before_refresh
    );
    let mut final_content = fixture.cache().open_content(&scope, &version).unwrap();
    let mut final_bytes = Vec::new();
    final_content.read_to_end(&mut final_bytes).unwrap();
    assert_eq!(final_bytes, old_bytes);
}


#[test]
fn folder_page_recovers_durable_roles_and_blocks_unknown_or_orphaned_intent_without_network() {
    let fixture = FolderFixture::new(false);
    let scope = fixture.cache_scope();
    let cancellation = CancellationToken::for_offline_job();
    let mut stage_id = None;
    let result = fixture.backend.pin_folder_offline_for_binding(
        &fixture.expected(), &cancellation, |pin| {
            stage_id = Some(pin.id);
            cancellation.cancel();
        },
    );
    assert!(result.is_err());
    let stage_id = stage_id.unwrap();
    let observe = || {
        let before = fixture.requests.lock().unwrap().len();
        let page = fixture.backend.listed_folder_page(None, &CancellationToken::new()).unwrap();
        assert_eq!(fixture.requests.lock().unwrap().len(), before);
        page.rows.into_iter().find(|row| row.resource_id == fixture.selected.remote_id).unwrap().saved_intent
    };
    let initial = observe();
    assert_eq!(initial.state, SavedFolderIntentState::Known);
    assert_eq!(initial.active_pin_id, None);
    assert_eq!(initial.staging_pin_id.as_deref(), Some(stage_id.as_str()));
    assert!(initial.staging_is_initial);
    assert_eq!(fixture.get_count.load(Ordering::Acquire), 0);
    let active = fixture.backend.resume_folder_offline_for_binding(
        &fixture.expected(), &stage_id, &CancellationToken::for_offline_job(), |_| {},
    ).unwrap();
    let saved = observe();
    assert_eq!(saved.active_pin_id.as_deref(), Some(active.id.as_str()));
    assert_eq!(saved.staging_pin_id, None);
    let manifest = fixture.cache().listing(&scope, &fixture.selected.remote_id).unwrap().entries
        .into_iter().map(|entry| raiun_cache::PinManifestEntry {
            parent_resource_id: entry.parent_resource_id, entry: entry.entry,
        }).collect::<Vec<_>>();
    let stage = fixture.cache().begin_folder_refresh_manifest_at_cancellable(
        &scope, &active.id, &fixture.selected.remote_id, &fixture.selected.path, &manifest, || false,
    ).unwrap();
    fixture.cache().cancel_pin_for_scope(&scope, &active.id).unwrap();
    let orphan = observe();
    assert_eq!(orphan.state, SavedFolderIntentState::RecoveryRequired);
    assert_eq!(orphan.active_pin_id, None);
    assert_eq!(orphan.staging_pin_id.as_deref(), Some(stage.id.as_str()));
    assert!(!orphan.staging_is_initial);
    fixture.cache().begin_pin_manifest_at_cancellable(
        &scope, &fixture.selected.remote_id, &fixture.selected.path, &manifest, || false,
    ).unwrap();
    let unknown = observe();
    assert_eq!(unknown.state, SavedFolderIntentState::Unknown);
    assert_eq!(unknown.active_pin_id, None);
    assert_eq!(unknown.staging_pin_id, None);
    assert!(!unknown.staging_is_initial);
    assert_eq!(fixture.get_count.load(Ordering::Acquire), 1);
}

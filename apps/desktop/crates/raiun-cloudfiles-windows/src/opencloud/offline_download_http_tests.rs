use super::*;
use raiun_cache::{
    AvailabilityPolicy, Cache, CacheScope, ContentProtection, ContentVersion, Retention,
    ScopeProtection,
};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    thread,
    time::Duration,
};

type RequestedRanges = Arc<Mutex<Vec<(usize, usize)>>>;
type FixtureParts = (
    String,
    thread::JoinHandle<()>,
    Arc<AtomicBool>,
    RequestedRanges,
);

const LARGE_FILE_SIZE: usize = 17 * 1024 * 1024 + 7;
const LARGE_ETAG: &str = "\"large-file-etag\"";

struct LargeFixtureServer {
    origin: String,
    worker: Option<thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    ranges: RequestedRanges,
}

impl LargeFixtureServer {
    fn start(include_dirty: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let ranges = Arc::new(Mutex::new(Vec::new()));
        let worker_ranges = ranges.clone();
        let worker = thread::spawn(move || {
            let mut idle = 0;
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        idle = 0;
                        respond_large_namespace(
                            &mut stream,
                            address,
                            include_dirty,
                            &worker_ranges,
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        idle += 1;
                        if idle > 400 {
                            break;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("large download fixture accept failed: {error}"),
                }
            }
        });
        Self {
            origin: format!("http://{address}"),
            worker: Some(worker),
            stop,
            ranges,
        }
    }

    fn into_parts(mut self) -> FixtureParts {
        (
            self.origin,
            self.worker.take().unwrap(),
            self.stop,
            self.ranges,
        )
    }
}

fn respond_large_namespace(
    stream: &mut TcpStream,
    address: std::net::SocketAddr,
    include_dirty: bool,
    ranges: &Mutex<Vec<(usize, usize)>>,
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
    let target = request.split_whitespace().nth(1).unwrap_or_default();
    if request.starts_with("GET /graph/") {
        let graph = format!(
            r#"{{"value":[{{"id":"personal-drive","name":"Personal","driveType":"personal","root":{{"id":"personal-root","webDavUrl":"http://{address}/dav/personal/"}}}},{{"id":"projects-drive","name":"Projects","driveType":"project","root":{{"id":"projects-root","webDavUrl":"http://{address}/dav/projects/"}}}},{{"id":"secret-drive","name":"Secret","driveType":"project","root":{{"id":"secret-root","webDavUrl":"http://{address}/dav/secret/","@libre.graph.contentType":"application/vnd.opencloud.vault"}}}}]}}"#
        );
        write_http_response(stream, "200 OK", "application/json", graph.as_bytes());
        return;
    }
    if request.starts_with("GET /dav/projects/readme.txt") {
        assert!(
            request
                .lines()
                .any(|line| { line.eq_ignore_ascii_case(&format!("if-match: {LARGE_ETAG}")) })
        );
        let range = request
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("range: bytes=")
                    .map(str::to_owned)
            })
            .expect("conditional range request");
        let (start, end) = range.split_once('-').unwrap();
        let start: usize = start.parse().unwrap();
        let end: usize = end.parse().unwrap();
        assert!(start <= end && end < LARGE_FILE_SIZE);
        ranges.lock().unwrap().push((start, end));
        let body = (start..=end).map(large_file_byte).collect::<Vec<_>>();
        let response = format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{end}/{LARGE_FILE_SIZE}\r\nETag: {LARGE_ETAG}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(&body).unwrap();
        return;
    }
    if request.starts_with("PROPFIND ") {
        let path = target.split('?').next().unwrap_or(target);
        if path == "/dav/projects/readme.txt" {
            let xml = format!(
                "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\"><d:response><d:href>{path}</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>{LARGE_FILE_SIZE}</d:getcontentlength><d:getetag>{LARGE_ETAG}</d:getetag><oc:fileid>project-file</oc:fileid></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"
            );
            write_http_response(
                stream,
                "207 Multi-Status",
                "application/xml",
                xml.as_bytes(),
            );
            return;
        }
        let (file_id, has_children) = if path.starts_with("/dav/personal/") {
            ("personal-root", false)
        } else if path.starts_with("/dav/projects/") {
            ("projects-root", true)
        } else if path.starts_with("/dav/secret/") {
            ("secret-root", false)
        } else {
            panic!("unexpected large namespace DAV path: {path}");
        };
        let collection = format!(
            "<d:response><d:href>{path}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>\"{file_id}\"</d:getetag><oc:fileid>{file_id}</oc:fileid></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        );
        let listing = if has_children && request.to_ascii_lowercase().contains("depth: 1") {
            let base = path.trim_end_matches('/');
            let mut children = format!(
                "<d:response><d:href>{base}/readme.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>{LARGE_FILE_SIZE}</d:getcontentlength><d:getetag>{LARGE_ETAG}</d:getetag><oc:fileid>project-file</oc:fileid></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
            );
            if include_dirty {
                children.push_str(&format!(
                    "<d:response><d:href>{base}/dirty.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>5</d:getcontentlength><d:getetag>\"dirty-etag\"</d:getetag><oc:fileid>dirty-file</oc:fileid></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
                ));
            }
            children
        } else {
            String::new()
        };
        let xml = format!(
            "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">{collection}{listing}</d:multistatus>"
        );
        write_http_response(
            stream,
            "207 Multi-Status",
            "application/xml",
            xml.as_bytes(),
        );
        return;
    }
    panic!("unexpected large namespace request");
}

fn large_file_byte(offset: usize) -> u8 {
    ((offset.wrapping_mul(31).wrapping_add(7)) % 251) as u8
}

fn write_http_response(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
}

struct OfflineDownloadFixture {
    _temp: tempfile::TempDir,
    worker: Option<thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    backend: OpenCloudPlaceholderBackend,
    file_identity: OpaqueIdentity,
    binding: FileBinding,
}

impl OfflineDownloadFixture {
    fn new() -> Self {
        let (server, worker, stop) = start_namespace_fixture();
        Self::from_server(server, worker, stop)
    }

    fn from_server(server: String, worker: thread::JoinHandle<()>, stop: Arc<AtomicBool>) -> Self {
        let client = Arc::new(OpenCloudClient::new(&server, "test-token".into()).unwrap());
        let account_id = derive_account_id(&server, "personal-drive");
        let scope = ProviderScope::new(
            client.as_ref(),
            "profile-offline-download-test".into(),
            account_id,
            client.server_origin().unwrap(),
        )
        .unwrap();
        let local_root_identity = crate::ConfiguredRootIdentity {
            volume_serial: 0x5511,
            file_index: 0x778899,
        };
        let catalog = Arc::new(MemoryIdentityCatalog::default());
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(temp.path(), 32 * 1024 * 1024).unwrap();
        let backend = OpenCloudPlaceholderBackend::new_with_identity_catalog_and_cache(
            client,
            scope,
            local_root_identity,
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
            .unwrap();
        let spaces_children = backend
            .enumerate(&spaces.identity, &CancellationToken::new())
            .unwrap();
        let projects = spaces_children
            .iter()
            .find(|child| child.name == "Projects")
            .unwrap();
        let project_children = backend
            .enumerate(&projects.identity, &CancellationToken::new())
            .unwrap();
        let file = project_children
            .iter()
            .find(|child| child.name == "readme.txt")
            .unwrap();
        let identity: [u8; 16] = file.identity.as_slice().try_into().unwrap();
        let file_identity = OpaqueIdentity(identity);
        let binding = backend
            .state
            .lock()
            .unwrap()
            .files
            .get(&file_identity)
            .unwrap()
            .clone();

        Self {
            _temp: temp,
            worker: Some(worker),
            stop,
            backend,
            file_identity,
            binding,
        }
    }

    fn expected(&self) -> FileCacheBindingExpectation<'_> {
        FileCacheBindingExpectation {
            space_id: &self.binding.space_id,
            root_resource_id: &self.binding.root_resource_id,
            path: &self.binding.path,
            resource_id: &self.binding.remote_id,
            etag: &self.binding.etag,
            size: self.binding.size,
        }
    }

    fn stop_server(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap();
    }

    fn large(include_dirty: bool) -> (Self, RequestedRanges) {
        let (server, worker, stop, ranges) = LargeFixtureServer::start(include_dirty).into_parts();
        (Self::from_server(server, worker, stop), ranges)
    }

    fn cache_scope(&self) -> CacheScope {
        CacheScope::new(
            self.backend.scope().server_origin(),
            self.backend.scope().account_id(),
            &self.binding.space_id,
            &self.binding.root_resource_id,
            ScopeProtection::PlaintextAllowed,
        )
        .unwrap()
    }
}

#[test]
fn guarded_http_download_publishes_exact_offline_bytes_and_reads_them_after_server_stops() {
    let mut fixture = OfflineDownloadFixture::new();
    assert_eq!(fixture.binding.size, 7);
    assert_eq!(fixture.binding.remote_id, "project-file");
    assert_eq!(fixture.binding.path, "/readme.txt");

    let record = fixture
        .backend
        .download_file_offline_for_binding(&fixture.expected(), &CancellationToken::new())
        .unwrap();
    assert_eq!(record.version.resource_id, fixture.binding.remote_id);
    assert_eq!(record.version.etag, fixture.binding.etag);
    assert_eq!(record.version.protection, ContentProtection::Plaintext);
    assert_eq!(record.byte_len, 7);

    let status = fixture
        .backend
        .file_cache_status_for_binding(&fixture.expected(), &CancellationToken::new())
        .unwrap();
    assert_eq!(status.policy, AvailabilityPolicy::AlwaysOffline);
    assert!(status.recorded_complete_version);
    assert_eq!(status.recorded_bytes, 7);

    // Stop the only server before reading. This proves the complete exact
    // version was committed to the private cache rather than merely returned
    // from the successful conditional GET.
    fixture.stop_server();
    let binding = fixture
        .backend
        .state
        .lock()
        .unwrap()
        .files
        .get(&fixture.file_identity)
        .unwrap()
        .clone();
    assert_eq!(
        fixture
            .backend
            .read_cached_range(&binding, 0, 7, &CancellationToken::new())
            .unwrap(),
        b"content"
    );
}

#[test]
fn cancellation_before_download_admission_preserves_cache_policy_and_content_state() {
    let mut fixture = OfflineDownloadFixture::new();
    let cache_scope = fixture.cache_scope();
    let before_policy = fixture
        .backend
        .cache
        .as_ref()
        .unwrap()
        .policy(&cache_scope, &fixture.binding.remote_id)
        .unwrap();
    let before_usage = fixture.backend.cache.as_ref().unwrap().usage().unwrap();
    assert_eq!(before_policy, AvailabilityPolicy::Recent);
    assert!(matches!(
        fixture.backend.cache.as_ref().unwrap().content_record(
            &cache_scope,
            &ContentVersion {
                resource_id: fixture.binding.remote_id.clone(),
                etag: fixture.binding.etag.clone(),
                protection: ContentProtection::Plaintext,
            }
        ),
        Err(raiun_cache::CacheError::NotFound)
    ));

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(matches!(
        fixture
            .backend
            .download_file_offline_for_binding(&fixture.expected(), &cancelled),
        Err(OfflineDownloadError::Backend(BackendError::Cancelled))
    ));

    let cache = fixture.backend.cache.as_ref().unwrap();
    assert_eq!(
        cache
            .policy(&cache_scope, &fixture.binding.remote_id)
            .unwrap(),
        before_policy
    );
    assert_eq!(
        cache
            .policy_target_state(&cache_scope, &fixture.binding.remote_id)
            .unwrap(),
        None
    );
    assert_eq!(cache.usage().unwrap(), before_usage);
    assert!(matches!(
        cache.content_record(
            &cache_scope,
            &ContentVersion {
                resource_id: fixture.binding.remote_id.clone(),
                etag: fixture.binding.etag.clone(),
                protection: ContentProtection::Plaintext,
            }
        ),
        Err(raiun_cache::CacheError::NotFound)
    ));
    fixture.stop_server();
}

#[test]
fn guarded_http_download_fetches_and_verifies_a_multi_chunk_file() {
    let (mut fixture, ranges) = OfflineDownloadFixture::large(false);
    assert_eq!(fixture.binding.size, LARGE_FILE_SIZE as u64);
    assert_eq!(fixture.binding.etag, LARGE_ETAG);

    let record = fixture
        .backend
        .download_file_offline_for_binding(
            &fixture.expected(),
            &CancellationToken::for_offline_job(),
        )
        .unwrap();
    assert_eq!(record.byte_len, LARGE_FILE_SIZE as u64);
    assert_eq!(record.version.resource_id, "project-file");
    assert_eq!(record.version.etag, LARGE_ETAG);
    let actual_ranges = ranges.lock().unwrap().clone();
    assert_eq!(actual_ranges.len(), 18);
    for (chunk, actual) in actual_ranges.iter().enumerate() {
        let start = chunk * 1024 * 1024;
        let end = (start + 1024 * 1024).min(LARGE_FILE_SIZE) - 1;
        assert_eq!(*actual, (start, end));
    }
    let mut expected_hash = Sha256::new();
    for start in (0..LARGE_FILE_SIZE).step_by(64 * 1024) {
        let end = (start + 64 * 1024).min(LARGE_FILE_SIZE);
        let bytes = (start..end).map(large_file_byte).collect::<Vec<_>>();
        expected_hash.update(&bytes);
    }
    assert_eq!(record.sha256, format!("{:x}", expected_hash.finalize()));

    let status = fixture
        .backend
        .file_cache_status_for_binding(&fixture.expected(), &CancellationToken::new())
        .unwrap();
    assert_eq!(status.policy, AvailabilityPolicy::AlwaysOffline);
    assert!(status.recorded_complete_version);
    assert_eq!(status.recorded_bytes, LARGE_FILE_SIZE as u64);

    fixture.stop_server();
    let binding = fixture
        .backend
        .state
        .lock()
        .unwrap()
        .files
        .get(&fixture.file_identity)
        .unwrap()
        .clone();
    let over_limit =
        fixture
            .backend
            .read_cached_range(&binding, 0, LARGE_FILE_SIZE, &CancellationToken::new());
    assert_eq!(over_limit, Err(BackendError::InvalidRange));
    for (offset, length) in [
        (0_u64, 64_usize),
        ((16 * 1024 * 1024 - 32) as u64, 64),
        ((LARGE_FILE_SIZE - 64) as u64, 64),
    ] {
        let cached = fixture
            .backend
            .read_cached_range(&binding, offset, length, &CancellationToken::new())
            .unwrap();
        let start = usize::try_from(offset).unwrap();
        let expected = (start..start + length)
            .map(large_file_byte)
            .collect::<Vec<_>>();
        assert_eq!(cached, expected);
    }
}

#[test]
fn cancellation_after_first_staged_chunk_releases_only_its_reservation() {
    let (mut fixture, ranges) = OfflineDownloadFixture::large(true);
    let cache_scope = fixture.cache_scope();
    let dirty_entry = raiun_core::backend::RemoteEntry {
        id: "dirty-file".into(),
        path: "/dirty.txt".into(),
        directory: false,
        size: 5,
        etag: "\"dirty-etag\"".into(),
        modified_unix: 0,
        writable: true,
        encrypted: false,
    };
    let dirty_version = ContentVersion {
        resource_id: dirty_entry.id.clone(),
        etag: dirty_entry.etag.clone(),
        protection: ContentProtection::Plaintext,
    };
    fixture
        .backend
        .cache
        .as_ref()
        .unwrap()
        .publish_content(
            &cache_scope,
            &dirty_version,
            &mut &b"dirty"[..],
            5,
            Retention::Dirty,
        )
        .unwrap();
    let cache = fixture.backend.cache.as_ref().unwrap();
    let usage_before = cache.usage().unwrap();
    assert_eq!(usage_before.used_bytes, 5);

    let cancellation = CancellationToken::new();
    let cancelled = cancellation.clone();
    assert!(matches!(
        fixture.backend.download_file_offline_with_chunk_hook(
            &fixture.expected(),
            &cancellation,
            move |offset| {
                if offset == 1024 * 1024 {
                    cancelled.cancel();
                }
            }
        ),
        Err(OfflineDownloadError::Backend(BackendError::Cancelled))
    ));
    assert_eq!(ranges.lock().unwrap().as_slice(), &[(0, 1024 * 1024 - 1)]);

    let cache = fixture.backend.cache.as_ref().unwrap();
    let status = fixture
        .backend
        .file_cache_status_for_binding(&fixture.expected(), &CancellationToken::new())
        .unwrap();
    assert_eq!(status.policy, AvailabilityPolicy::AlwaysOffline);
    assert!(!status.recorded_complete_version);
    assert_eq!(status.recorded_bytes, 0);
    assert_eq!(
        cache
            .policy_target_state(&cache_scope, &fixture.binding.remote_id)
            .unwrap(),
        Some(raiun_cache::TargetState::Stale)
    );
    assert_eq!(cache.usage().unwrap(), usage_before);
    let mut dirty_reader = cache.open_content(&cache_scope, &dirty_version).unwrap();
    let mut dirty_bytes = Vec::new();
    dirty_reader.read_to_end(&mut dirty_bytes).unwrap();
    assert_eq!(dirty_bytes, b"dirty");
    assert_eq!(
        cache
            .content_record(&cache_scope, &dirty_version)
            .unwrap()
            .retention,
        Retention::Dirty
    );
    fixture.stop_server();
}

#[test]
fn pinned_member_http_download_keeps_recent_policy_and_verified_bytes_after_server_stops() {
    let mut fixture = OfflineDownloadFixture::new();
    let scope = fixture.cache_scope();
    let cache = fixture.backend.cache.as_ref().unwrap();
    cache.set_policy_at(&scope, &fixture.binding.remote_id, &fixture.binding.path,
        &fixture.binding.etag, AvailabilityPolicy::Recent).unwrap();
    let listing = cache.listing(&scope, &fixture.binding.root_resource_id).unwrap();
    assert!(listing.complete);
    assert_eq!(listing.entries.len(), 1);
    let manifest = listing.entries.into_iter().map(|row| raiun_cache::PinManifestEntry {
        parent_resource_id: row.parent_resource_id, entry: row.entry,
    }).collect::<Vec<_>>();
    let pin = cache.begin_pin_manifest_at_cancellable(&scope, &fixture.binding.root_resource_id,
        "/", &manifest, || false).unwrap();
    let record = fixture.backend.download_pinned_file_offline_for_binding(
        &fixture.expected(), &pin.id, &CancellationToken::new()).unwrap();
    assert_eq!(record.byte_len, 7);
    assert_eq!(cache.policy(&scope, &fixture.binding.remote_id).unwrap(), AvailabilityPolicy::Recent);
    assert_eq!(cache.policy_target_state(&scope, &fixture.binding.remote_id).unwrap(), None);
    assert_eq!(cache.refresh_pin(&pin.id).unwrap().state, raiun_cache::PinState::Ready);
    assert_eq!(cache.evict_recent(0).unwrap().removed_bytes, 0);
    fixture.stop_server();
    assert_eq!(fixture.backend.read_cached_range(&fixture.binding, 0, 7,
        &CancellationToken::new()).unwrap(), b"content");
    let cache = fixture.backend.cache.as_ref().unwrap();
    cache.cancel_pin_for_scope(&scope, &pin.id).unwrap();
    assert_eq!(cache.evict_recent(0).unwrap().removed_bytes, 7);
}

use super::*;
use crate::{
    ConfiguredRootIdentity, DurableEditRecoveryProvider, EditJournalScope, EditRecordProtector,
    EditRecoveryProvider, LocalFileIdentity, PlaceholderEditBinding,
    ReconciliationOutcome,
};
use sha2::{Digest, Sha256};

struct InitialSaveFixture {
    server: String,
    client: Arc<OpenCloudClient>,
    backend: OpenCloudPlaceholderBackend,
    local_root: crate::ConfiguredRootIdentity,
    worker: Option<thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl InitialSaveFixture {
    fn new(encrypted_child: bool) -> Self {
        let (server, worker, stop) = start_namespace_fixture_with(encrypted_child);
        let client = Arc::new(OpenCloudClient::new(&server, "test-token".into()).unwrap());
        let scope = ProviderScope::new(
            client.as_ref(),
            "profile-initial-save-test".into(),
            derive_account_id(&server, "personal-drive"),
            client.server_origin().unwrap(),
        )
        .unwrap();
        let local_root = crate::ConfiguredRootIdentity {
            volume_serial: 17,
            file_index: 29,
        };
        let backend = OpenCloudPlaceholderBackend::new_with_identity_catalog(
            client.clone(),
            scope,
            local_root,
            Arc::new(MemoryIdentityCatalog::default()),
        )
        .unwrap();
        backend
            .register_composite_root_for("personal-drive", "personal-root")
            .unwrap();
        Self {
            server,
            client,
            backend,
            local_root,
            worker: Some(worker),
            stop,
        }
    }

    fn scope(&self, space_id: &str, root_resource_id: &str) -> EditJournalScope {
        EditJournalScope {
            profile_id: "profile-initial-save-test".into(),
            server_origin: self.client.server_origin().unwrap().to_owned(),
            account_subject: derive_account_id(&self.server, "personal-drive"),
            space_id: space_id.into(),
            root_resource_id: root_resource_id.into(),
            root_volume_serial: self.local_root.volume_serial,
            root_file_index: self.local_root.file_index,
        }
    }
}

impl Drop for InitialSaveFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

#[test]
fn initial_edit_remote_uses_verified_ordinary_space_root_under_lease() {
    let fixture = InitialSaveFixture::new(false);
    let scope = fixture.scope("projects-drive", "projects-root");
    let result = fixture
        .backend
        .with_initial_edit_remote(&scope, |remote| {
            assert_eq!(remote.server_origin(), Some(scope.server_origin.as_str()));
            remote.ensure_authorized(&scope)
        })
        .unwrap();
    assert!(result.is_ok());
}

#[test]
fn initial_edit_remote_rejects_mismatched_account_profile_origin_and_local_root() {
    let fixture = InitialSaveFixture::new(false);
    let scope = fixture.scope("projects-drive", "projects-root");
    let mut invalid_scopes = Vec::new();
    let mut invalid = scope.clone();
    invalid.profile_id.push_str("-other");
    invalid_scopes.push(invalid);
    let mut invalid = scope.clone();
    invalid.account_subject.push_str("-other");
    invalid_scopes.push(invalid);
    let mut invalid = scope.clone();
    invalid.server_origin = "https://other.example.test".into();
    invalid_scopes.push(invalid);
    let mut invalid = scope.clone();
    invalid.root_volume_serial += 1;
    invalid_scopes.push(invalid);
    let mut invalid = scope.clone();
    invalid.root_file_index += 1;
    invalid_scopes.push(invalid);

    for invalid_scope in invalid_scopes {
        let mut called = false;
        assert!(
            fixture
                .backend
                .with_initial_edit_remote(&invalid_scope, |_| {
                    called = true;
                })
                .is_err()
        );
        assert!(!called, "scope mismatch must be rejected before closure");
    }
}

#[test]
fn initial_edit_remote_rejects_changed_root_and_encrypted_space() {
    let fixture = InitialSaveFixture::new(false);
    let changed_root = fixture.scope("projects-drive", "replaced-projects-root");
    let mut called = false;
    assert!(
        fixture
            .backend
            .with_initial_edit_remote(&changed_root, |_| called = true)
            .is_err()
    );
    assert!(!called, "changed root must fail before closure");

    let encrypted_space = fixture.scope("secret-drive", "secret-root");
    assert!(
        fixture
            .backend
            .with_initial_edit_remote(&encrypted_space, |_| called = true)
            .is_err()
    );
    assert!(!called, "encrypted Space must fail before closure");
}

#[test]
fn initial_edit_remote_refuses_backend_and_token_revocation_before_closure() {
    let fixture = InitialSaveFixture::new(false);
    let scope = fixture.scope("projects-drive", "projects-root");
    fixture.backend.revoke();
    let mut called = false;
    assert!(
        fixture
            .backend
            .with_initial_edit_remote(&scope, |_| called = true)
            .is_err()
    );
    assert!(!called, "revoked backend must fail before closure");

    let token_fixture = InitialSaveFixture::new(false);
    let token_scope = token_fixture.scope("projects-drive", "projects-root");
    token_fixture
        .client
        .set_bearer_token("rotated-token".into())
        .unwrap();
    let mut token_closure_called = false;
    assert!(
        token_fixture
            .backend
            .with_initial_edit_remote(&token_scope, |_| token_closure_called = true)
            .is_err()
    );
    assert!(
        !token_closure_called,
        "stale token generation must fail before closure"
    );
}

#[derive(Clone)]
struct InitialSaveTestProtector;

impl EditRecordProtector for InitialSaveTestProtector {
    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, crate::JournalError> {
        let mut sealed = Vec::with_capacity(4 + aad.len() + plaintext.len());
        sealed.extend_from_slice(&(aad.len() as u32).to_le_bytes());
        sealed.extend_from_slice(aad);
        sealed.extend_from_slice(plaintext);
        Ok(sealed)
    }

    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, crate::JournalError> {
        if sealed.len() < 4 {
            return Err(crate::JournalError::ProtectionFailed);
        }
        let aad_len = u32::from_le_bytes(sealed[..4].try_into().unwrap()) as usize;
        if sealed.get(4..4 + aad_len) != Some(aad) {
            return Err(crate::JournalError::ProtectionFailed);
        }
        Ok(sealed[4 + aad_len..].to_vec())
    }
}

#[derive(Clone, Debug)]
struct InitialSaveRequest {
    method: String,
    target: String,
    headers: String,
    body: Vec<u8>,
}

struct InitialSaveHttpFixture {
    server: String,
    requests: Arc<Mutex<Vec<InitialSaveRequest>>>,
    uploaded: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl InitialSaveHttpFixture {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let worker_requests = requests.clone();
        let uploaded = Arc::new(AtomicBool::new(false));
        let worker_uploaded = uploaded.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = thread::spawn(move || {
            let mut idle = 0;
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        idle = 0;
                        handle_initial_save_request(
                            stream,
                            address,
                            &worker_requests,
                            &worker_uploaded,
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        idle += 1;
                        if idle > 400 {
                            break;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("initial-save fixture accept failed: {error}"),
                }
            }
        });
        Self {
            server: format!("http://{address}"),
            requests,
            uploaded,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for InitialSaveHttpFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn handle_initial_save_request(
    mut stream: TcpStream,
    address: std::net::SocketAddr,
    requests: &Mutex<Vec<InitialSaveRequest>>,
    uploaded: &AtomicBool,
) {
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
        let count = stream.read(&mut chunk).unwrap();
        assert_ne!(count, 0, "request ended before headers");
        bytes.extend_from_slice(&chunk[..count]);
        assert!(
            bytes.len() <= 32 * 1024,
            "request headers exceeded fixture bound"
        );
    };
    let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
    let mut request_line = headers.lines().next().unwrap().split_whitespace();
    let method = request_line.next().unwrap().to_owned();
    let target = request_line.next().unwrap().to_owned();
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(str::trim)
                .and_then(|value| value.parse::<usize>().ok())
        })
        .unwrap_or(0);
    assert!(content_length <= 1024 * 1024, "fixture body exceeded bound");
    let mut body = bytes[header_end..].to_vec();
    while body.len() < content_length {
        let count = stream.read(&mut chunk).unwrap();
        assert_ne!(count, 0, "request body ended early");
        body.extend_from_slice(&chunk[..count]);
    }
    assert_eq!(body.len(), content_length);
    requests.lock().unwrap().push(InitialSaveRequest {
        method: method.clone(),
        target: target.clone(),
        headers: headers.clone(),
        body: body.clone(),
    });

    let path = target.split('?').next().unwrap_or(&target);
    let (status, content_type, response_body, extra_headers) = match (method.as_str(), path) {
        ("GET", "/graph/v1.0/me/drives") => (
            "200 OK",
            "application/json",
            format!(
                r#"{{"value":[{{"id":"personal-drive","name":"Personal","driveType":"personal","root":{{"id":"personal-root","webDavUrl":"http://{address}/dav/personal/"}}}},{{"id":"projects-drive","name":"Projects","driveType":"project","root":{{"id":"projects-root","webDavUrl":"http://{address}/dav/projects/"}}}},{{"id":"secret-drive","name":"Secret","driveType":"project","root":{{"id":"secret-root","webDavUrl":"http://{address}/dav/secret/","@libre.graph.contentType":"application/vnd.opencloud.vault"}}}}]}}"#
            ),
            "",
        ),
        ("PROPFIND", "/dav/personal/") => (
            "207 Multi-Status",
            "application/xml",
            root_xml("/dav/personal/", "personal-root"),
            "",
        ),
        ("PROPFIND", "/dav/projects/") => (
            "207 Multi-Status",
            "application/xml",
            root_xml("/dav/projects/", "projects-root"),
            "",
        ),
        ("PROPFIND", "/dav/projects/notes.txt") => {
            let (etag, len) = if uploaded.load(Ordering::Acquire) {
                ("\"new-e2\"", b"new local bytes".len())
            } else {
                ("\"base-e1\"", b"old".len())
            };
            (
                "207 Multi-Status",
                "application/xml",
                file_xml(etag, len),
                "",
            )
        }
        ("PUT", "/dav/projects/notes.txt") => {
            uploaded.store(true, Ordering::Release);
            (
                "204 No Content",
                "application/octet-stream",
                String::new(),
                "",
            )
        }
        ("GET", "/dav/projects/notes.txt") => (
            "200 OK",
            "application/octet-stream",
            "new local bytes".to_owned(),
            "ETag: \"new-e2\"\r\n",
        ),
        _ => panic!("unexpected initial-save request: {method} {target}"),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\n{extra_headers}Connection: close\r\n\r\n{response_body}",
        response_body.len()
    );
    stream.write_all(response.as_bytes()).unwrap();
}

fn root_xml(path: &str, id: &str) -> String {
    format!(
        "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\"><d:response><d:href>{path}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>\"{id}-etag\"</d:getetag><oc:fileid>{id}</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"
    )
}

fn file_xml(etag: &str, len: usize) -> String {
    format!(
        "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\"><d:response><d:href>/dav/projects/notes.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>{len}</d:getcontentlength><d:getetag>{etag}</d:getetag><oc:fileid>project-file</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"
    )
}

fn private_initial_save_tempdir() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    temp
}

#[test]
fn fresh_initial_receipt_uses_verified_route_for_conditional_upload_and_readback() {
    let http = InitialSaveHttpFixture::new();
    let client = Arc::new(OpenCloudClient::new(&http.server, "test-token".into()).unwrap());
    let provider_scope = ProviderScope::new(
        client.as_ref(),
        "profile-initial-save-test".into(),
        derive_account_id(&http.server, "personal-drive"),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let local_root = ConfiguredRootIdentity {
        volume_serial: 17,
        file_index: 29,
    };
    let backend = OpenCloudPlaceholderBackend::new_with_identity_catalog(
        client,
        provider_scope.clone(),
        local_root,
        Arc::new(MemoryIdentityCatalog::default()),
    )
    .unwrap();
    backend
        .register_composite_root_for("personal-drive", "personal-root")
        .unwrap();
    let temp = private_initial_save_tempdir();
    let provider = DurableEditRecoveryProvider::new(
        temp.path().to_path_buf(),
        provider_scope.clone(),
        local_root,
        InitialSaveTestProtector,
    );
    let prepared = provider.prepare(&provider_scope, local_root).unwrap();
    let content = b"new local bytes";
    let binding = PlaceholderEditBinding {
        profile_id: provider_scope.profile_id().into(),
        server_origin: provider_scope.server_origin().into(),
        account_subject: provider_scope.account_id().into(),
        account_generation: provider_scope.token_generation(),
        space_id: "projects-drive".into(),
        root_resource_id: "projects-root".into(),
        remote_resource_id: "project-file".into(),
        virtual_path: "/notes.txt".into(),
        base_etag: "\"base-e1\"".into(),
        base_size: 3,
    };
    let receipt = prepared
        .append_edit_for_initial_dispatch(
            &binding,
            local_root,
            LocalFileIdentity {
                volume_serial: local_root.volume_serial,
                file_index: 55,
            },
            "notes.txt",
            content,
        )
        .unwrap()
        .unwrap();
    let scope = receipt.scope().clone();
    let outcome = backend
        .with_initial_edit_remote(&scope, |remote| {
            prepared.dispatch_initial_receipt(receipt, remote)
        })
        .unwrap()
        .unwrap();
    assert_eq!(
        outcome,
        ReconciliationOutcome::VerifiedApplied { attempts: 1 }
    );

    let requests = http.requests.lock().unwrap();
    let puts: Vec<_> = requests
        .iter()
        .filter(|request| request.method == "PUT")
        .collect();
    let gets: Vec<_> = requests
        .iter()
        .filter(|request| request.method == "GET" && request.target == "/dav/projects/notes.txt")
        .collect();
    assert_eq!(puts.len(), 1);
    assert!(
        puts[0]
            .headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("if-match: \"base-e1\""))
    );
    assert_eq!(puts[0].body, content);
    assert_eq!(gets.len(), 1);
    assert!(
        gets[0]
            .headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("if-match: \"new-e2\""))
    );
    assert!(http.uploaded.load(Ordering::Acquire));
    drop(requests);

    let retained = provider.unresolved_edits().unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].relative_path, "notes.txt");
    assert_eq!(retained[0].content_len, content.len() as u64);
    let digest: String = Sha256::digest(content)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(retained[0].content_sha256, digest);
}

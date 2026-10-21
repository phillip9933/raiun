use raiun_core::backend::ErrorKind;
use raiun_opencloud::{
    OpenCloudClient, RangeReadContext,
    transfer_budget::{TransferBudget, TransferLimits},
};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    num::NonZeroU64,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const SPACE: &str = "recovery-personal";
const ROOT_PATH: &str = "/RecoveryRoot";
const ROOT_ID: &str = "recovery-root-id";
const FILE_PATH: &str = "document.bin";
const FILE_ID: &str = "recovery-file-id";
const INITIAL_ETAG: &str = "\"recovery-v1\"";

#[derive(Clone, Debug)]
struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Default)]
struct State {
    requests: Vec<Request>,
    put_headers_seen: bool,
    root_id: String,
    file_id: String,
    etag: String,
    body: Vec<u8>,
    reject_condition: bool,
    lose_put_response: bool,
    redirect_put: Option<String>,
}

struct Fixture {
    authority: String,
    state: Arc<Mutex<State>>,
    stopping: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Fixture {
    fn start() -> Self {
        Self::start_with(State {
            root_id: ROOT_ID.to_owned(),
            file_id: FILE_ID.to_owned(),
            etag: INITIAL_ETAG.to_owned(),
            body: b"baseline body".to_vec(),
            ..State::default()
        })
    }

    fn start_with(state: State) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let state = Arc::new(Mutex::new(state));
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_state = Arc::clone(&state);
        let thread_stopping = Arc::clone(&stopping);
        let thread_authority = authority.clone();
        let worker = thread::spawn(move || {
            while !thread_stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => serve(stream, &thread_authority, &thread_state),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("synthetic recovery listener failed: {error}"),
                }
            }
        });
        Self {
            authority,
            state,
            stopping,
            worker: Some(worker),
        }
    }

    fn origin(&self) -> String {
        format!("http://{}", self.authority)
    }

    fn requests(&self) -> Vec<Request> {
        self.state.lock().unwrap().requests.clone()
    }

    fn put_headers_seen(&self) -> bool {
        self.state.lock().unwrap().put_headers_seen
    }

    fn set_root_id(&self, id: &str) {
        self.state.lock().unwrap().root_id = id.to_owned();
    }

    fn set_file_id(&self, id: &str) {
        self.state.lock().unwrap().file_id = id.to_owned();
    }

    fn set_etag(&self, etag: &str) {
        self.state.lock().unwrap().etag = etag.to_owned();
    }

    fn reject_condition(&self) {
        self.state.lock().unwrap().reject_condition = true;
    }

    fn lose_put_response(&self) {
        self.state.lock().unwrap().lose_put_response = true;
    }

    fn redirect_put_to(&self, origin: &str) {
        self.state.lock().unwrap().redirect_put = Some(format!("{origin}/capture-redirected-put"));
    }

    fn body(&self) -> Vec<u8> {
        self.state.lock().unwrap().body.clone()
    }

    fn stop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop();
    }
}

fn serve(mut stream: TcpStream, authority: &str, state: &Arc<Mutex<State>>) {
    // Windows accepted sockets inherit the listener's nonblocking mode.
    // Parse each fixture request with the bounded blocking reads below.
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut header_bytes = Vec::new();
    let mut byte = [0u8; 1];
    while !header_bytes.ends_with(b"\r\n\r\n") {
        if stream.read_exact(&mut byte).is_err() {
            return;
        }
        header_bytes.push(byte[0]);
        if header_bytes.len() > 64 * 1024 {
            return;
        }
    }
    let headers_text = String::from_utf8_lossy(&header_bytes);
    let mut lines = headers_text.lines();
    let mut request_line = lines.next().unwrap_or_default().split_ascii_whitespace();
    let method = request_line.next().unwrap_or_default().to_owned();
    let target = request_line.next().unwrap_or_default().to_owned();
    let headers: Vec<_> = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect();
    let content_len = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    if method == "PUT" && target == "/dav/personal/RecoveryRoot/document.bin" {
        state.lock().unwrap().put_headers_seen = true;
    }
    if content_len > 32 * 1024 * 1024 {
        return;
    }
    let mut body = vec![0; content_len];
    if stream.read_exact(&mut body).is_err() {
        return;
    }
    state.lock().unwrap().requests.push(Request {
        method: method.clone(),
        target: target.clone(),
        headers: headers.clone(),
        body: body.clone(),
    });
    if header(&headers, "authorization") != Some("Bearer recovery-test-token") {
        respond(&mut stream, 401, "text/plain", &[], b"unauthorized");
        return;
    }
    if method == "GET" && target == "/graph/v1.0/me/drives" {
        let payload = format!(
            r#"{{"value":[{{"id":"{SPACE}","name":"Personal","driveType":"personal","root":{{"id":"space-root-id","webDavUrl":"http://{authority}/dav/personal/","permissions":"RDNVW"}}}}]}}"#
        );
        respond(
            &mut stream,
            200,
            "application/json",
            &[],
            payload.as_bytes(),
        );
        return;
    }
    if method == "PROPFIND" && target.starts_with("/dav/personal/") {
        let relative = target
            .trim_start_matches("/dav/personal/")
            .trim_end_matches('/');
        let (id, etag, size, is_directory) = if relative.is_empty() {
            (
                "space-root-id".to_owned(),
                "\"space-v1\"".to_owned(),
                0,
                true,
            )
        } else if relative == "RecoveryRoot" {
            let snapshot = state.lock().unwrap();
            (snapshot.root_id.clone(), "\"root-v1\"".to_owned(), 0, true)
        } else if relative == "RecoveryRoot/document.bin" {
            let snapshot = state.lock().unwrap();
            (
                snapshot.file_id.clone(),
                snapshot.etag.clone(),
                snapshot.body.len(),
                false,
            )
        } else {
            respond(&mut stream, 404, "text/plain", &[], b"missing");
            return;
        };
        let kind = if is_directory {
            "<d:resourcetype><d:collection/></d:resourcetype>"
        } else {
            "<d:resourcetype/>"
        };
        let slash = if is_directory { "/" } else { "" };
        let xml = format!(
            r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>http://{authority}{target}{slash}</d:href><d:propstat><d:prop>{kind}<d:getcontentlength>{size}</d:getcontentlength><d:getetag>{etag}</d:getetag><oc:fileid>{id}</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#
        );
        respond(&mut stream, 207, "application/xml", &[], xml.as_bytes());
        return;
    }
    if method == "PUT" && target == "/dav/personal/RecoveryRoot/document.bin" {
        let mut snapshot = state.lock().unwrap();
        if let Some(location) = snapshot.redirect_put.clone() {
            drop(snapshot);
            respond(
                &mut stream,
                307,
                "text/plain",
                &[("Location", location)],
                b"redirect",
            );
            return;
        }
        if snapshot.reject_condition || header(&headers, "if-match") != Some(snapshot.etag.as_str())
        {
            drop(snapshot);
            respond(&mut stream, 412, "text/plain", &[], b"condition failed");
            return;
        }
        snapshot.body = body;
        snapshot.etag = "\"recovery-v2\"".to_owned();
        let lose_response = snapshot.lose_put_response;
        drop(snapshot);
        if !lose_response {
            respond(&mut stream, 204, "text/plain", &[], b"");
        }
        return;
    }
    if method == "GET" && target == "/dav/personal/RecoveryRoot/document.bin" {
        let snapshot = state.lock().unwrap();
        if header(&headers, "if-match") != Some(snapshot.etag.as_str()) {
            respond(&mut stream, 412, "text/plain", &[], b"etag changed");
        } else {
            respond(
                &mut stream,
                200,
                "application/octet-stream",
                &[("ETag", snapshot.etag.clone())],
                &snapshot.body,
            );
        }
        return;
    }
    respond(&mut stream, 404, "text/plain", &[], b"not found");
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_str())
}

fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    headers: &[(&str, String)],
    body: &[u8],
) {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        207 => "Multi-Status",
        307 => "Temporary Redirect",
        401 => "Unauthorized",
        404 => "Not Found",
        412 => "Precondition Failed",
        _ => "Response",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n",
        body.len()
    )
    .unwrap();
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n").unwrap();
    }
    stream.write_all(b"\r\n").unwrap();
    stream.write_all(body).unwrap();
}

fn context(client: &OpenCloudClient) -> RangeReadContext {
    RangeReadContext {
        deadline: Instant::now() + Duration::from_secs(20),
        token_generation: client.token_generation(),
    }
}

fn client(fixture: &Fixture) -> OpenCloudClient {
    OpenCloudClient::new(&fixture.origin(), "recovery-test-token".to_owned()).unwrap()
}

fn client_with_budget(fixture: &Fixture, budget: TransferBudget) -> OpenCloudClient {
    OpenCloudClient::new_with_proxy_and_transfer_budget(
        &fixture.origin(),
        "recovery-test-token".to_owned(),
        &raiun_opencloud::ProxyConfig::System,
        budget,
    )
    .unwrap()
}

#[test]
fn recovery_upload_cancels_promptly_when_auth_generation_changes_during_body() {
    let fixture = Fixture::start();
    let budget = TransferBudget::new();
    budget.set_limits(TransferLimits {
        upload_bytes_per_second: Some(NonZeroU64::new(1).unwrap()),
        download_bytes_per_second: None,
    });
    let client = client_with_budget(&fixture, budget);
    let context = context(&client);
    let upload_client = client.clone();
    let upload = thread::spawn(move || {
        upload_client.recovery_upload_bytes_with_context(
            SPACE,
            ROOT_PATH,
            ROOT_ID,
            FILE_PATH,
            FILE_ID,
            INITIAL_ETAG,
            b"baseline body".len() as u64,
            b"replacement body",
            context,
        )
    });

    let started = Instant::now();
    while !fixture.put_headers_seen() && started.elapsed() < Duration::from_secs(3) {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(fixture.put_headers_seen(), "recovery PUT did not start");
    client
        .set_bearer_token("rotated-recovery-test-token".to_owned())
        .unwrap();
    let error = upload.join().unwrap().unwrap_err();
    assert_eq!(error.kind, ErrorKind::Unauthorized);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(
        fixture
            .requests()
            .iter()
            .all(|request| request.method != "PUT"),
        "the in-flight body should be cancelled before a complete PUT is accepted"
    );
}

#[test]
fn bounded_recovery_upload_and_readback_use_shared_directional_budgets() {
    let fixture = Fixture::start();
    let budget = TransferBudget::new();
    let rate = NonZeroU64::new(2048).unwrap();
    budget.set_limits(TransferLimits {
        upload_bytes_per_second: Some(rate),
        download_bytes_per_second: Some(rate),
    });
    let client = client_with_budget(&fixture, budget.clone());
    let context = context(&client);
    let content = vec![0x5a; 4096];

    let started = Instant::now();
    let uploaded = client
        .recovery_upload_bytes_with_context(
            SPACE,
            ROOT_PATH,
            ROOT_ID,
            FILE_PATH,
            FILE_ID,
            INITIAL_ETAG,
            b"baseline body".len() as u64,
            &content,
            context,
        )
        .unwrap();
    assert_eq!(uploaded.size, content.len() as u64);
    assert!(started.elapsed() >= Duration::from_millis(850));

    let started = Instant::now();
    let (read_entry, read_body) = client
        .recovery_read_bytes_with_context(
            SPACE,
            ROOT_PATH,
            ROOT_ID,
            FILE_PATH,
            FILE_ID,
            &uploaded.etag,
            content.len(),
            context,
        )
        .unwrap();
    assert_eq!(read_entry.size, content.len() as u64);
    assert_eq!(read_body.as_slice(), content);
    assert!(started.elapsed() >= Duration::from_millis(850));
    assert_eq!(budget.limits().upload_bytes_per_second, Some(rate));
    assert_eq!(budget.limits().download_bytes_per_second, Some(rate));
}

fn put_count(fixture: &Fixture) -> usize {
    fixture
        .requests()
        .iter()
        .filter(|request| request.method == "PUT")
        .count()
}

#[test]
fn recovery_stat_upload_and_readback_use_exact_scope_and_conditional_headers() {
    let fixture = Fixture::start();
    let client = client(&fixture);
    let context = context(&client);
    let baseline = client
        .recovery_stat_with_context(SPACE, ROOT_PATH, ROOT_ID, FILE_PATH, context)
        .unwrap();
    assert_eq!(baseline.id, FILE_ID);
    assert_eq!(baseline.etag, INITIAL_ETAG);
    assert_eq!(baseline.size, b"baseline body".len() as u64);

    let replacement = b"recovered bytes that must remain in memory";
    let uploaded = client
        .recovery_upload_bytes_with_context(
            SPACE,
            ROOT_PATH,
            ROOT_ID,
            FILE_PATH,
            FILE_ID,
            INITIAL_ETAG,
            baseline.size,
            replacement,
            context,
        )
        .unwrap();
    assert_eq!(uploaded.id, FILE_ID);
    assert_eq!(uploaded.etag, "\"recovery-v2\"");
    assert_eq!(uploaded.size, replacement.len() as u64);
    let put = fixture
        .requests()
        .into_iter()
        .find(|request| request.method == "PUT")
        .unwrap();
    assert_eq!(put.target, "/dav/personal/RecoveryRoot/document.bin");
    assert_eq!(header(&put.headers, "if-match"), Some(INITIAL_ETAG));
    assert_eq!(header(&put.headers, "if-none-match"), None);
    assert_eq!(put.body, replacement);

    let (read_entry, read_body) = client
        .recovery_read_bytes_with_context(
            SPACE,
            ROOT_PATH,
            ROOT_ID,
            FILE_PATH,
            FILE_ID,
            "\"recovery-v2\"",
            1024,
            context,
        )
        .unwrap();
    assert_eq!(read_entry.etag, "\"recovery-v2\"");
    assert_eq!(read_body.as_slice(), replacement);
    assert_eq!(
        Sha256::digest(read_body.as_slice()),
        Sha256::digest(replacement)
    );
    let get = fixture
        .requests()
        .into_iter()
        .find(|request| request.method == "GET" && request.target.ends_with("document.bin"))
        .unwrap();
    assert_eq!(header(&get.headers, "if-match"), Some("\"recovery-v2\""));
}

#[test]
fn recovery_identity_or_version_mismatch_never_sends_put() {
    for mismatch in ["root", "resource", "etag", "size"] {
        let fixture = Fixture::start();
        match mismatch {
            "root" => fixture.set_root_id("replaced-root-id"),
            "resource" => fixture.set_file_id("replaced-file-id"),
            "etag" => fixture.set_etag("\"recovery-replaced\""),
            "size" => fixture.state.lock().unwrap().body = b"different-size".to_vec(),
            _ => unreachable!(),
        }
        let client = client(&fixture);
        let error = client
            .recovery_upload_bytes_with_context(
                SPACE,
                ROOT_PATH,
                ROOT_ID,
                FILE_PATH,
                FILE_ID,
                INITIAL_ETAG,
                b"baseline body".len() as u64,
                b"replacement",
                context(&client),
            )
            .unwrap_err();
        assert!(matches!(
            error.kind,
            ErrorKind::Conflict | ErrorKind::Unsupported
        ));
        assert_eq!(put_count(&fixture), 0, "mismatch case {mismatch}");
    }
}

#[test]
fn recovery_upload_rejects_unconditional_or_oversized_requests_before_put() {
    let fixture = Fixture::start();
    let client = client(&fixture);
    let mut oversized = vec![0u8; raiun_opencloud::MAX_RECOVERY_UPLOAD_BYTES + 1];
    assert!(
        client
            .recovery_upload_bytes_with_context(
                SPACE,
                ROOT_PATH,
                ROOT_ID,
                FILE_PATH,
                FILE_ID,
                INITIAL_ETAG,
                b"baseline body".len() as u64,
                &oversized,
                context(&client),
            )
            .is_err()
    );
    oversized.fill(0);
    assert!(
        client
            .recovery_read_bytes_with_context(
                SPACE,
                ROOT_PATH,
                ROOT_ID,
                FILE_PATH,
                FILE_ID,
                INITIAL_ETAG,
                raiun_opencloud::MAX_RECOVERY_UPLOAD_BYTES + 1,
                context(&client),
            )
            .is_err()
    );
    assert_eq!(fixture.requests().len(), 0);
}

#[test]
fn lost_put_response_can_be_resolved_by_exact_conditional_readback() {
    let fixture = Fixture::start();
    fixture.lose_put_response();
    let client = client(&fixture);
    let context = context(&client);
    let replacement = b"response was lost after commit";
    let upload = client.recovery_upload_bytes_with_context(
        SPACE,
        ROOT_PATH,
        ROOT_ID,
        FILE_PATH,
        FILE_ID,
        INITIAL_ETAG,
        b"baseline body".len() as u64,
        replacement,
        context,
    );
    assert!(upload.is_err());
    assert_eq!(fixture.body(), replacement);
    assert_eq!(put_count(&fixture), 1);

    let after = client
        .recovery_stat_with_context(SPACE, ROOT_PATH, ROOT_ID, FILE_PATH, context)
        .unwrap();
    assert_eq!(after.id, FILE_ID);
    assert_eq!(after.etag, "\"recovery-v2\"");
    let (verified, body) = client
        .recovery_read_bytes_with_context(
            SPACE,
            ROOT_PATH,
            ROOT_ID,
            FILE_PATH,
            FILE_ID,
            &after.etag,
            1024,
            context,
        )
        .unwrap();
    assert_eq!(verified.size, replacement.len() as u64);
    assert_eq!(body.as_slice(), replacement);
    assert_eq!(put_count(&fixture), 1, "readback must not replay the PUT");
}

#[test]
fn conditional_rejection_and_cross_origin_redirect_never_leak_auth_or_replay() {
    let redirect_target = Fixture::start();
    let redirect_origin = redirect_target.origin();
    let fixture = Fixture::start();
    fixture.redirect_put_to(&redirect_origin);
    let client = client(&fixture);
    let error = client
        .recovery_upload_bytes_with_context(
            SPACE,
            ROOT_PATH,
            ROOT_ID,
            FILE_PATH,
            FILE_ID,
            INITIAL_ETAG,
            b"baseline body".len() as u64,
            b"must not follow redirect",
            context(&client),
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(put_count(&fixture), 1);
    assert!(redirect_target.requests().is_empty());

    fixture.state.lock().unwrap().redirect_put = None;
    fixture.reject_condition();
    let error = client
        .recovery_upload_bytes_with_context(
            SPACE,
            ROOT_PATH,
            ROOT_ID,
            FILE_PATH,
            FILE_ID,
            INITIAL_ETAG,
            b"baseline body".len() as u64,
            b"precondition must hold",
            context(&client),
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Conflict);
    let puts: Vec<_> = fixture
        .requests()
        .into_iter()
        .filter(|request| request.method == "PUT")
        .collect();
    assert_eq!(puts.len(), 2);
    assert!(puts.iter().all(|request| {
        header(&request.headers, "if-match") == Some(INITIAL_ETAG)
            && header(&request.headers, "if-none-match").is_none()
    }));
    assert_eq!(fixture.body(), b"baseline body");
}

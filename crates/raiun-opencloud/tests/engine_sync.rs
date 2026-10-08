use raiun_core::{FolderPair, SyncMode, backend::ErrorKind};
use raiun_engine::Engine;
use raiun_opencloud::OpenCloudClient;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use url::Url;

struct RemoteFile {
    bytes: Vec<u8>,
    revision: u64,
}

impl RemoteFile {
    fn etag(&self) -> String {
        format!("\"rev-{}\"", self.revision)
    }
}

#[derive(Default)]
struct FixtureState {
    files: BTreeMap<String, RemoteFile>,
    next_revision: u64,
    change_after_listing: Option<(String, Vec<u8>)>,
    requests: Vec<RequestRecord>,
}

#[derive(Clone, Debug)]
struct RequestRecord {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct HttpFixture {
    authority: String,
    state: Arc<Mutex<FixtureState>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl HttpFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind synthetic OpenCloud server");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let authority = listener.local_addr().unwrap().to_string();
        let state = Arc::new(Mutex::new(FixtureState::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_state = state.clone();
        let worker_stop = stop.clone();
        let worker_authority = authority.clone();
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => serve_request(stream, &worker_authority, &worker_state),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                }
            }
        });
        Self {
            authority,
            state,
            stop,
            worker: Some(worker),
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.authority)
    }

    fn put_remote(&self, path: &str, bytes: &[u8]) {
        let mut state = self.state.lock().unwrap();
        state.next_revision += 1;
        let revision = state.next_revision;
        state.files.insert(
            path.to_owned(),
            RemoteFile {
                bytes: bytes.to_vec(),
                revision,
            },
        );
    }

    fn conflict_on_next_root_listing(&self, path: &str, bytes: &[u8]) {
        self.state.lock().unwrap().change_after_listing = Some((path.to_owned(), bytes.to_vec()));
    }

    fn remote_bytes(&self, path: &str) -> Vec<u8> {
        self.state.lock().unwrap().files[path].bytes.clone()
    }

    fn requests(&self) -> Vec<RequestRecord> {
        self.state.lock().unwrap().requests.clone()
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("fixture server thread");
        }
    }
}

fn serve_request(mut stream: TcpStream, authority: &str, state: &Arc<Mutex<FixtureState>>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set request timeout");
    let mut raw_headers = Vec::new();
    let mut byte = [0u8; 1];
    while !raw_headers.ends_with(b"\r\n\r\n") {
        if stream.read_exact(&mut byte).is_err() {
            return;
        }
        raw_headers.push(byte[0]);
        assert!(raw_headers.len() <= 64 * 1024, "oversized HTTP headers");
    }
    let header_text = String::from_utf8(raw_headers).expect("ASCII HTTP headers");
    let mut lines = header_text.lines();
    let mut request_line = lines.next().unwrap().split_ascii_whitespace();
    let method = request_line.next().unwrap().to_owned();
    let target = request_line.next().unwrap().to_owned();
    let headers: BTreeMap<String, String> = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect();
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    assert!(content_length <= 4 * 1024 * 1024, "oversized request body");
    let mut body = vec![0; content_length];
    if content_length > 0 && stream.read_exact(&mut body).is_err() {
        return;
    }
    let request = RequestRecord {
        method: method.clone(),
        target: target.clone(),
        headers: headers.clone(),
        body: body.clone(),
    };
    state.lock().unwrap().requests.push(request);

    if headers.get("authorization").map(String::as_str) != Some("Bearer synthetic-token") {
        respond(&mut stream, 401, "text/plain", "unauthorized");
        return;
    }

    if method == "GET" && target.starts_with("/graph/v1.0/me/drives") {
        let body = format!(
            r#"{{"value":[{{"id":"personal-drive","name":"Personal","driveType":"personal","root":{{"id":"root","webDavUrl":"http://{authority}/dav/personal/","permissions":"RDNVW"}}}}]}}"#
        );
        respond(&mut stream, 200, "application/json", &body);
        return;
    }

    let url = Url::parse(&format!("http://fixture{target}")).expect("request target URL");
    let logical = match logical_path(&url) {
        Some(path) => path,
        None => {
            respond(&mut stream, 404, "text/plain", "not found");
            return;
        }
    };
    match method.as_str() {
        "PROPFIND" => {
            let depth = headers.get("depth").map(String::as_str).unwrap_or("0");
            let (response, mutation) = {
                let mut state = state.lock().unwrap();
                if logical != "/" && !state.files.contains_key(&logical) {
                    (None, None)
                } else {
                    let mut entries = Vec::new();
                    entries.push(("/".to_owned(), None));
                    if logical != "/" {
                        entries.retain(|(path, _)| path == &logical);
                    }
                    if logical == "/" && depth == "1" {
                        entries.extend(state.files.iter().map(|(path, file)| {
                            (path.clone(), Some((file.bytes.len() as u64, file.etag())))
                        }));
                    } else if logical != "/" {
                        if let Some(file) = state.files.get(&logical) {
                            entries = vec![(
                                logical.clone(),
                                Some((file.bytes.len() as u64, file.etag())),
                            )];
                        }
                    }
                    let xml = multistatus(authority, &entries);
                    let mutation = if logical == "/" && depth == "1" {
                        state.change_after_listing.take()
                    } else {
                        None
                    };
                    (Some(xml), mutation)
                }
            };
            if let Some(xml) = response {
                respond(&mut stream, 207, "application/xml; charset=utf-8", &xml);
                if let Some((path, bytes)) = mutation {
                    let mut state = state.lock().unwrap();
                    state.next_revision += 1;
                    let revision = state.next_revision;
                    state.files.insert(path, RemoteFile { bytes, revision });
                }
            } else {
                respond(&mut stream, 404, "text/plain", "not found");
            }
        }
        "GET" => {
            let file = state
                .lock()
                .unwrap()
                .files
                .get(&logical)
                .map(|file| file.bytes.clone());
            if let Some(bytes) = file {
                respond_bytes(&mut stream, 200, "application/octet-stream", &bytes);
            } else {
                respond(&mut stream, 404, "text/plain", "not found");
            }
        }
        "PUT" => {
            let mut state = state.lock().unwrap();
            let existing = state.files.get(&logical);
            let allowed = if let Some(expected) = headers.get("if-match") {
                existing.is_some_and(|file| &file.etag() == expected)
            } else if headers
                .get("if-none-match")
                .is_some_and(|value| value == "*")
            {
                existing.is_none()
            } else {
                false
            };
            if !allowed {
                respond(&mut stream, 412, "text/plain", "precondition failed");
            } else {
                state.next_revision += 1;
                let revision = state.next_revision;
                state.files.insert(
                    logical,
                    RemoteFile {
                        bytes: body,
                        revision,
                    },
                );
                respond(&mut stream, 201, "text/plain", "");
            }
        }
        _ => respond(&mut stream, 405, "text/plain", "method not allowed"),
    }
}

fn logical_path(url: &Url) -> Option<String> {
    let suffix = url.path().strip_prefix("/dav/personal/")?;
    if suffix.is_empty() {
        return Some("/".into());
    }
    let decoded = percent_encoding::percent_decode_str(suffix)
        .decode_utf8()
        .ok()?;
    if decoded.contains('/') || decoded == "." || decoded == ".." || decoded.contains('\\') {
        return None;
    }
    Some(format!("/{decoded}"))
}

fn multistatus(authority: &str, entries: &[(String, Option<(u64, String)>)]) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">"#,
    );
    for (path, details) in entries {
        let mut href = Url::parse(&format!("http://{authority}/dav/personal/")).unwrap();
        if path != "/" {
            href.path_segments_mut()
                .unwrap()
                .push(path.trim_start_matches('/'));
        }
        let (size, etag) = details.clone().unwrap_or((0, "\"root-v1\"".into()));
        let collection = if path == "/" { "<d:collection/>" } else { "" };
        xml.push_str(&format!(
            "<d:response><d:href>{}</d:href><d:propstat><d:prop><d:resourcetype>{collection}</d:resourcetype><d:getcontentlength>{size}</d:getcontentlength><d:getetag>{etag}</d:getetag><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
            href.as_str()
        ));
    }
    xml.push_str("</d:multistatus>");
    xml
}

fn respond(stream: &mut TcpStream, status: u16, content_type: &str, body: &str) {
    respond_bytes(stream, status, content_type, body.as_bytes());
}

fn respond_bytes(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
    let phrase = match status {
        200 => "OK",
        201 => "Created",
        207 => "Multi-Status",
        404 => "Not Found",
        401 => "Unauthorized",
        405 => "Method Not Allowed",
        412 => "Precondition Failed",
        _ => "Error",
    };
    write!(stream, "HTTP/1.1 {status} {phrase}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();
}

fn pair(local_path: PathBuf) -> FolderPair {
    FolderPair {
        id: "integration-pair".into(),
        local_path,
        space_id: "personal-drive".into(),
        remote_path: "/".into(),
        mode: SyncMode::TwoWay,
    }
}

#[test]
fn engine_fetch_snapshot_reads_atomically_published_unicode_file() {
    let fixture = HttpFixture::start();
    let work = tempfile::tempdir().unwrap();
    let path = "/日本語.txt";
    let expected = "こんにちは cloud".as_bytes();
    fixture.put_remote(path, expected);

    let client = OpenCloudClient::new(&fixture.url(), "synthetic-token".into()).unwrap();
    let engine = Engine::open(&work.path().join("state"), Arc::new(client)).unwrap();
    let mut snapshot = engine.fetch_snapshot("personal-drive", path).unwrap();
    let mut actual = Vec::new();
    snapshot.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, expected);
    drop(snapshot);
    assert_eq!(
        std::fs::read_dir(work.path().join("state/cache"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn engine_reconciles_through_graph_and_webdav_and_preserves_etag_conflicts() {
    let fixture = HttpFixture::start();
    let work = tempfile::tempdir().unwrap();
    let local_root = work.path().join("pair");
    std::fs::create_dir(&local_root).unwrap();
    let local_name = "café notes.txt";
    let remote_name = "云 文件.txt";
    std::fs::write(local_root.join(local_name), b"local-v1").unwrap();
    fixture.put_remote(&format!("/{remote_name}"), b"remote-v1");

    let client = OpenCloudClient::new(&fixture.url(), "synthetic-token".into()).unwrap();
    let spaces = raiun_core::backend::CloudBackend::spaces(&client).unwrap();
    assert_eq!(spaces.len(), 1);
    assert_eq!(spaces[0].id, "personal-drive");
    assert!(spaces[0].personal && spaces[0].writable);
    let engine = Engine::open(&work.path().join("state"), Arc::new(client)).unwrap();
    let pair = pair(local_root.clone());

    let initial = engine.sync_pair(&pair).unwrap();
    assert_eq!(initial.uploaded, 1);
    assert_eq!(initial.downloaded, 1);
    assert_eq!(
        std::fs::read(local_root.join(remote_name)).unwrap(),
        b"remote-v1"
    );
    assert_eq!(fixture.remote_bytes(&format!("/{local_name}")), b"local-v1");

    fixture.put_remote(&format!("/{remote_name}"), b"remote-v2");
    let remote_update = engine.sync_pair(&pair).unwrap();
    assert_eq!(remote_update.downloaded, 1);
    assert_eq!(
        std::fs::read(local_root.join(remote_name)).unwrap(),
        b"remote-v2"
    );

    std::fs::write(local_root.join(local_name), b"local-v2").unwrap();
    let local_update = engine.sync_pair(&pair).unwrap();
    assert_eq!(local_update.uploaded, 1);
    assert_eq!(fixture.remote_bytes(&format!("/{local_name}")), b"local-v2");

    // Change the remote file after the completed depth-one scan but before
    // the conditional PUT. The precondition from the scan must reject it.
    std::fs::write(local_root.join(local_name), b"local-racing-edit").unwrap();
    fixture.conflict_on_next_root_listing(&format!("/{local_name}"), b"remote-racing-edit");
    let error = engine.sync_pair(&pair).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert_eq!(
        std::fs::read(local_root.join(local_name)).unwrap(),
        b"local-racing-edit"
    );
    assert_eq!(
        fixture.remote_bytes(&format!("/{local_name}")),
        b"remote-racing-edit"
    );

    // A subsequent complete scan sees both edits against the prior baseline
    // and reports a conflict without replacing either side.
    let conflict = engine.sync_pair(&pair).unwrap();
    assert_eq!(conflict.conflicts, 1);
    assert_eq!(
        std::fs::read(local_root.join(local_name)).unwrap(),
        b"local-racing-edit"
    );
    assert_eq!(
        fixture.remote_bytes(&format!("/{local_name}")),
        b"remote-racing-edit"
    );

    let requests = fixture.requests();
    let propfind = requests
        .iter()
        .find(|request| request.method == "PROPFIND")
        .expect("DAV PROPFIND request");
    assert!(String::from_utf8_lossy(&propfind.body).contains("<d:propfind"));
    assert!(requests.iter().all(|request| {
        request.headers.get("authorization").map(String::as_str) == Some("Bearer synthetic-token")
    }));
    let unicode_put = requests
        .iter()
        .find(|request| request.method == "PUT" && request.target.contains("caf%C3%A9%20notes.txt"))
        .expect("DAV PUT for Unicode filename");
    assert_eq!(unicode_put.body, b"local-v1");
    assert_eq!(
        unicode_put.headers.get("if-none-match").map(String::as_str),
        Some("*")
    );
    let conditional_put = requests
        .iter()
        .find(|request| request.method == "PUT" && request.body == b"local-racing-edit")
        .expect("conditional DAV PUT for racing edit");
    assert_eq!(
        conditional_put.headers.get("if-match").map(String::as_str),
        Some("\"rev-4\"")
    );
    assert!(requests.iter().any(|request| {
        request.method == "GET"
            && request
                .target
                .contains("%E4%BA%91%20%E6%96%87%E4%BB%B6.txt")
    }));
    let transfers = engine.transfers(100).unwrap();
    assert!(
        transfers.iter().any(|transfer| {
            transfer.path.ends_with(local_name)
                && transfer.state == "failed"
                && transfer.error.is_some()
        }),
        "expected failed ETag-precondition transfer, got {transfers:?}"
    );
}

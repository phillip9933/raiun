use raiun_opencloud::{OpenCloudClient, vault::VaultMetadataClient};
use raiun_vault::session::{VaultSessionCoordinator, VaultSessionScope};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const SPACE_ID: &str = "personal-drive";
const VAULT_PATH: &str = "/Travel.vault";
const ENCRYPTED_CHILD: &str = "ap8un5letkkhetgjpn9528qi4c";
const EXPECTED_CHILD: &str = "école.txt";
const TOKEN_CIPHERTEXT_MUTATION_INDEX: usize = 48;

#[derive(Clone, Debug)]
struct RequestRecord {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[derive(Default)]
struct FixtureState {
    requests: Vec<RequestRecord>,
}

struct HttpFixture {
    authority: String,
    state: Arc<Mutex<FixtureState>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl HttpFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local synthetic server");
        listener
            .set_nonblocking(true)
            .expect("set synthetic listener nonblocking");
        let authority = listener.local_addr().unwrap().to_string();
        let state = Arc::new(Mutex::new(FixtureState::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_state = Arc::clone(&state);
        let worker_stop = Arc::clone(&stop);
        let worker_authority = authority.clone();
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        serve_request(stream, &worker_authority, &worker_state);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("synthetic server accept failed: {error}"),
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

    fn origin(&self) -> String {
        format!("http://{}", self.authority)
    }

    fn requests(&self) -> Vec<RequestRecord> {
        self.state.lock().unwrap().requests.clone()
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("synthetic server worker");
        }
    }
}

fn serve_request(mut stream: TcpStream, authority: &str, state: &Arc<Mutex<FixtureState>>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set synthetic request timeout");
    let mut raw_headers = Vec::new();
    let mut byte = [0u8; 1];
    while !raw_headers.ends_with(b"\r\n\r\n") {
        if stream.read_exact(&mut byte).is_err() {
            return;
        }
        raw_headers.push(byte[0]);
        assert!(
            raw_headers.len() <= 64 * 1024,
            "oversized test request headers"
        );
    }
    let header_text = String::from_utf8(raw_headers).expect("HTTP headers are ASCII");
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
    assert!(content_length <= 64 * 1024, "unexpected request body size");
    let mut body = vec![0; content_length];
    if content_length > 0 {
        stream.read_exact(&mut body).expect("read request body");
    }
    state.lock().unwrap().requests.push(RequestRecord {
        method: method.clone(),
        target: target.clone(),
        headers: headers.clone(),
        body,
    });

    if headers.get("authorization").map(String::as_str) != Some("Bearer synthetic-token") {
        respond(&mut stream, 401, "text/plain", "unauthorized");
        return;
    }
    match (method.as_str(), target.as_str()) {
        ("GET", "/graph/v1.0/me/drives") => {
            let body = format!(
                r#"{{"value":[{{"id":"{SPACE_ID}","name":"Personal","driveType":"personal","root":{{"id":"personal-root-id","webDavUrl":"http://{authority}/dav/personal/","permissions":"RDNVW"}}}}]}}"#
            );
            respond(&mut stream, 200, "application/json", &body);
        }
        ("PROPFIND", "/dav/personal/") => {
            let body = parent_listing(authority);
            respond(&mut stream, 207, "application/xml; charset=utf-8", &body);
        }
        ("PROPFIND", "/dav/personal/Travel.vault/") => {
            let body = vault_listing(authority);
            respond(&mut stream, 207, "application/xml; charset=utf-8", &body);
        }
        _ => respond(&mut stream, 404, "text/plain", "not found"),
    }
}

fn parent_listing(authority: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone">
          <d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><oc:fileid>personal-root-id</oc:fileid><oc:name>personal</oc:name><oc:size>0</oc:size></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
          <d:response><d:href>http://{authority}/dav/personal/Travel.vault/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>"vault-rev-1"</d:getetag><oc:fileid>vault-root-id</oc:fileid><oc:name>Travel.vault</oc:name><oc:size>0</oc:size><d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
        </d:multistatus>"#
    )
}

fn vault_listing(authority: &str) -> String {
    let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim();
    format!(
        r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone">
          <d:response><d:href>http://{authority}/dav/personal/Travel.vault/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>"vault-rev-2"</d:getetag><d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype><oc:fileid>vault-root-id</oc:fileid><oc:name>Travel.vault</oc:name><oc:size>0</oc:size><ocrclone:integrity-id>{token}</ocrclone:integrity-id></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
          <d:response><d:href>http://{authority}/dav/personal/Travel.vault/{ENCRYPTED_CHILD}</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>13</d:getcontentlength><d:getetag>"child-rev-1"</d:getetag><oc:fileid>encrypted-child-id</oc:fileid><oc:name>{ENCRYPTED_CHILD}</oc:name><oc:size>13</oc:size></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
        </d:multistatus>"#
    )
}

fn respond(stream: &mut TcpStream, status: u16, content_type: &str, body: &str) {
    write!(
        stream,
        "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(body.as_bytes()).unwrap();
}

#[test]
fn discovered_folder_metadata_unlocks_only_the_scoped_synthetic_vault() {
    let fixture = HttpFixture::start();
    let client = OpenCloudClient::new(&fixture.origin(), "synthetic-token".into()).unwrap();
    let metadata = VaultMetadataClient::new(&client);

    let candidates = metadata.discover_folder_vaults(SPACE_ID, "/").unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].raw_name, "Travel.vault");
    assert_eq!(candidates[0].path, VAULT_PATH);
    assert!(
        candidates[0]
            .vault_evidence
            .contains(&raiun_opencloud::vault::VaultEvidence::ContentType)
    );

    let listing = metadata
        .inspect_folder_vault(SPACE_ID, &candidates[0].path)
        .unwrap();
    assert_eq!(listing.space_id, SPACE_ID);
    assert_eq!(listing.root.id, "vault-root-id");
    assert_eq!(listing.children.len(), 1);
    assert_eq!(listing.children[0].raw_name, ENCRYPTED_CHILD);
    assert!(listing.integrity_token.is_some());

    let scope = VaultSessionScope::new(
        "local-account-1",
        &fixture.origin(),
        &listing.space_id,
        &listing.root.id,
    )
    .unwrap();
    let coordinator = VaultSessionCoordinator::new();
    assert!(
        coordinator
            .decrypt_name(&scope, &listing.children[0].raw_name)
            .is_err()
    );

    let mut wrong_password = b"wrong password".to_vec();
    assert!(
        coordinator
            .unlock(
                &scope,
                &mut wrong_password,
                listing.integrity_token.as_deref().unwrap()
            )
            .is_err()
    );
    assert!(wrong_password.iter().all(|byte| *byte == 0));

    let mut wrong_token_password = b"potato".to_vec();
    let mut wrong_token = listing
        .integrity_token
        .as_deref()
        .unwrap()
        .as_bytes()
        .to_vec();
    assert!(wrong_token.len() > TOKEN_CIPHERTEXT_MUTATION_INDEX);
    wrong_token[TOKEN_CIPHERTEXT_MUTATION_INDEX] =
        if wrong_token[TOKEN_CIPHERTEXT_MUTATION_INDEX] == b'A' {
            b'B'
        } else {
            b'A'
        };
    let wrong_token = String::from_utf8(wrong_token).unwrap();
    assert!(
        coordinator
            .unlock(&scope, &mut wrong_token_password, &wrong_token)
            .is_err()
    );
    assert!(wrong_token_password.iter().all(|byte| *byte == 0));

    let mut password = b"potato".to_vec();
    coordinator
        .unlock(
            &scope,
            &mut password,
            listing.integrity_token.as_deref().unwrap(),
        )
        .unwrap();
    assert!(password.iter().all(|byte| *byte == 0));
    assert_eq!(
        coordinator
            .decrypt_name(&scope, &listing.children[0].raw_name)
            .unwrap(),
        EXPECTED_CHILD
    );
    let encrypted_names: Vec<_> = listing
        .children
        .iter()
        .map(|entry| entry.raw_name.as_str())
        .collect();
    assert_eq!(
        coordinator
            .decode_directory_names(&scope, &encrypted_names)
            .unwrap(),
        vec![EXPECTED_CHILD.to_owned()]
    );
    assert!(
        coordinator
            .decode_directory_names(&scope, &[encrypted_names[0], encrypted_names[0]])
            .is_err()
    );
    for mismatched_scope in [
        VaultSessionScope::new(
            "another-account",
            &fixture.origin(),
            SPACE_ID,
            &listing.root.id,
        )
        .unwrap(),
        VaultSessionScope::new(
            "local-account-1",
            "https://elsewhere.example",
            SPACE_ID,
            &listing.root.id,
        )
        .unwrap(),
        VaultSessionScope::new(
            "local-account-1",
            &fixture.origin(),
            "other-space",
            &listing.root.id,
        )
        .unwrap(),
        VaultSessionScope::new(
            "local-account-1",
            &fixture.origin(),
            SPACE_ID,
            "another-root-id",
        )
        .unwrap(),
    ] {
        assert!(
            coordinator
                .decrypt_name(&mismatched_scope, &listing.children[0].raw_name)
                .is_err()
        );
    }
    coordinator.lock(&scope).unwrap();
    assert!(
        coordinator
            .decrypt_name(&scope, &listing.children[0].raw_name)
            .is_err()
    );

    let requests = fixture.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "GET")
            .count(),
        2
    );
    assert!(
        requests
            .iter()
            .filter(|request| request.method == "GET")
            .all(|request| request.target == "/graph/v1.0/me/drives")
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "PROPFIND")
            .count(),
        2
    );
    assert!(
        requests
            .iter()
            .filter(|request| request.method == "PROPFIND")
            .all(|request| {
                request.headers.get("depth").map(String::as_str) == Some("1")
                    && request
                        .body
                        .windows(b"ocrclone:integrity-id".len())
                        .any(|window| window == b"ocrclone:integrity-id")
            })
    );
    let propfind_targets: Vec<_> = requests
        .iter()
        .filter(|request| request.method == "PROPFIND")
        .map(|request| request.target.as_str())
        .collect();
    assert!(propfind_targets.contains(&"/dav/personal/"));
    assert!(propfind_targets.contains(&"/dav/personal/Travel.vault/"));
    assert!(requests.iter().all(|request| {
        matches!(request.method.as_str(), "GET" | "PROPFIND")
            && request.headers.get("authorization").map(String::as_str)
                == Some("Bearer synthetic-token")
    }));
    assert!(
        requests
            .iter()
            .all(|request| request.body.is_empty() || request.method == "PROPFIND")
    );
}

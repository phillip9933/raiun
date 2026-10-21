use raiun_opencloud::{OpenCloudClient, vault_create::create_folder_vault};
use raiun_vault::session::{VaultSessionCoordinator, VaultSessionScope};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

#[derive(Default)]
struct State {
    created: bool,
    token: Option<String>,
    fail_property: bool,
    writes: Vec<String>,
}
struct Fixture {
    origin: String,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let (s, q, o) = (state.clone(), stop.clone(), origin.clone());
        let worker = thread::spawn(move || {
            while !q.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => serve(stream, &o, &s),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                }
            }
        });
        Self {
            origin,
            state,
            stop,
            worker: Some(worker),
        }
    }
    fn client(&self) -> OpenCloudClient {
        OpenCloudClient::new(&self.origin, "synthetic-token".into()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap();
    }
}
fn serve(mut stream: TcpStream, origin: &str, state: &Mutex<State>) {
    // Windows inherits the listener's nonblocking mode on accepted sockets.
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut header = Vec::new();
    let mut byte = [0];
    while !header.ends_with(b"\r\n\r\n") {
        if stream.read_exact(&mut byte).is_err() {
            return;
        }
        header.push(byte[0]);
        assert!(header.len() < 16384);
    }
    let header = String::from_utf8(header).unwrap();
    let mut words = header.lines().next().unwrap().split_whitespace();
    let method = words.next().unwrap();
    let target = words.next().unwrap();
    let len = header
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    assert!(len < 16384);
    let mut body = vec![0; len];
    stream.read_exact(&mut body).unwrap();
    let body = String::from_utf8(body).unwrap();
    let mut state = state.lock().unwrap();
    let (status,response)=match method {
        "GET" => (200,serde_json::json!({"value":[{"id":"space","name":"Personal","driveType":"personal","root":{"webDavUrl":format!("{origin}/dav/space/")}}]}).to_string()),
        "PROPFIND" => {
            let is_vault=target.trim_end_matches('/').ends_with("New.vault");
            if is_vault && !state.created {(404,String::new())} else {
                let (id,name)=if is_vault {("vault-resource","New.vault")}else{("space-root","Personal")};
                let token=if is_vault {state.token.as_ref().map(|t|format!("<v:integrity-id>{t}</v:integrity-id>")).unwrap_or_default()}else{String::new()};
                (207,format!("<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\" xmlns:v=\"ocrclone\"><d:response><d:href>{origin}{target}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>&quot;r1&quot;</d:getetag><oc:fileid>{id}</oc:fileid><oc:name>{name}</oc:name><oc:permissions>RDNVCK</oc:permissions>{token}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"))
            }
        }
        "MKCOL" => {
            assert!(header.to_ascii_lowercase().contains("if-none-match: *"));
            state.writes.push(method.into());
            if state.created {(412,String::new())}else{state.created=true;(201,String::new())}
        }
        "PROPPATCH" => {
            assert!(header.to_ascii_lowercase().contains("if-match: \"r1\""));
            state.writes.push(method.into());
            if !state.fail_property {
                state.token=Some(body.split("<ocrclone:integrity-id>").nth(1).unwrap().split("</ocrclone:integrity-id>").next().unwrap().into());
            }
            (207,"<d:multistatus xmlns:d=\"DAV:\"/>".into())
        }
        _=>panic!("unexpected method {method}"),
    };
    drop(state);
    write!(stream,"HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n{response}",response.len()).unwrap();
}

#[test]
fn new_vault_requires_conditional_creation_and_exact_proof_readback() {
    let fixture = Fixture::start();
    let client = fixture.client();
    let remote = create_folder_vault(&client, "space", "/", "New.vault").unwrap();
    let scope = VaultSessionScope::new(
        "test-account",
        &fixture.origin,
        "space",
        &remote.root().root.id,
    )
    .unwrap();
    let coordinator = VaultSessionCoordinator::new();
    let mut password = b"synthetic creation password".to_vec();
    let pending = coordinator.begin_create(&scope, &mut password).unwrap();
    assert!(password.iter().all(|b| *b == 0));
    assert!(!coordinator.is_unlocked(&scope).unwrap());
    let root = remote.initialize(pending.integrity_token()).unwrap();
    coordinator
        .finish_create(pending, root.integrity_token.as_deref().unwrap())
        .unwrap();
    assert!(coordinator.is_unlocked(&scope).unwrap());
    assert_eq!(fixture.state.lock().unwrap().writes, ["MKCOL", "PROPPATCH"]);
    assert!(create_folder_vault(&client, "space", "/", "New.vault").is_err());
    assert_eq!(
        fixture.state.lock().unwrap().writes,
        ["MKCOL", "PROPPATCH", "MKCOL"]
    );
}

#[test]
fn partial_property_failure_keeps_root_locked_and_does_not_delete_it() {
    let fixture = Fixture::start();
    fixture.state.lock().unwrap().fail_property = true;
    let remote = create_folder_vault(&fixture.client(), "space", "/", "New.vault").unwrap();
    // This is a protocol-only check: even HTTP 207 cannot establish success
    // without the exact property readback. No codec session is involved.
    assert!(remote.initialize("U3ludGhldGljUHJvb2Y=").is_err());
    let state = fixture.state.lock().unwrap();
    assert!(state.created);
    assert!(state.token.is_none());
    assert_eq!(state.writes, ["MKCOL", "PROPPATCH"]);
}

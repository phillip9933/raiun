use super::*;
use std::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, atomic::AtomicBool},
    thread::{self, JoinHandle},
};

#[derive(Clone, Copy, PartialEq)]
enum CancelAt {
    Never,
    BeforeNetwork,
    RootMetadata,
    TargetMetadata,
    Sent,
}

struct Fixture {
    client: OpenCloudClient,
    cancelled: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Fixture {
    fn new(at: CancelAt) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let graph = super::tests::GRAPH
            .replace("127.0.0.1:PORT", &authority)
            .replace("/dav/personal/", "/dav/spaces/drive-1/");
        let client = OpenCloudClient::new_with_proxy(
            &format!("http://{authority}/"),
            "synthetic-token".into(),
            &ProxyConfig::Direct,
        )
        .unwrap();
        let cancelled = Arc::new(AtomicBool::new(at == CancelAt::BeforeNetwork));
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread_cancelled = cancelled.clone();
        let thread_stop = stop.clone();
        let thread_requests = requests.clone();
        let join = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !thread_stop.load(Ordering::Acquire) && Instant::now() < deadline {
                let (mut socket, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let first = read_request(&mut socket);
                thread_requests.lock().unwrap().push(first.clone());
                let mkcol = first.starts_with("MKCOL ");
                let target = first.starts_with("PROPFIND ") && first.contains("/new-folder ");
                let root = first.starts_with("PROPFIND ") && !target;
                // Invalidate the original local probe while a real metadata or
                // mutation response is still in flight, not by call counting.
                if (at == CancelAt::RootMetadata && root)
                    || (at == CancelAt::TargetMetadata && target)
                    || (at == CancelAt::Sent && mkcol)
                {
                    thread_cancelled.store(true, Ordering::Release);
                }
                let (status, body) = if mkcol {
                    ("201 Created", String::new())
                } else if target {
                    ("404 Not Found", String::new())
                } else if root {
                    ("207 Multi-Status", root_entry())
                } else {
                    assert!(first.starts_with("GET "), "unexpected fixture method");
                    ("200 OK", graph.clone())
                };
                write!(
                    socket,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        Self {
            client,
            cancelled,
            requests,
            stop,
            join: Some(join),
        }
    }

    fn run(&self, legacy: bool) -> Result<DirectoryCreateResponse, CloudError> {
        let context = RangeReadContext {
            deadline: Instant::now() + Duration::from_secs(5),
            token_generation: self.client.token_generation(),
        };
        if legacy {
            self.client.mkdir_with_context(
                "drive-1",
                "/",
                "drive-1!expected-root",
                "new-folder",
                context,
            )
        } else {
            self.client.mkdir_with_context_and_cancellation(
                "drive-1",
                "/",
                "drive-1!expected-root",
                "new-folder",
                context,
                || self.cancelled.load(Ordering::Acquire),
            )
        }
    }

    fn mkcols(&self) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|line| line.starts_with("MKCOL "))
            .count()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            join.join().unwrap();
        }
    }
}

fn read_request(socket: &mut TcpStream) -> String {
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        headers.push(byte[0]);
        assert!(headers.len() <= 32 * 1024);
    }
    let headers = String::from_utf8(headers).unwrap();
    let length = headers
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    assert!(length <= 4096);
    let mut body = vec![0; length];
    socket.read_exact(&mut body).unwrap();
    headers.lines().next().unwrap().to_owned()
}

fn root_entry() -> String {
    r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/spaces/drive-1/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>"root-v1"</d:getetag><oc:fileid>drive-1!expected-root</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned()
}

#[test]
fn mkdir_cancelled_before_network_sends_nothing() {
    let fixture = Fixture::new(CancelAt::BeforeNetwork);
    assert_eq!(fixture.run(false).unwrap_err().kind, ErrorKind::Offline);
    assert!(fixture.requests.lock().unwrap().is_empty());
}

#[test]
fn mkdir_cancelled_during_root_metadata_never_sends_mutation() {
    let fixture = Fixture::new(CancelAt::RootMetadata);
    assert_eq!(fixture.run(false).unwrap_err().kind, ErrorKind::Offline);
    assert_eq!(fixture.mkcols(), 0);
    assert!(
        fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.starts_with("PROPFIND "))
    );
}

#[test]
fn mkdir_cancelled_during_target_metadata_never_sends_mutation() {
    let fixture = Fixture::new(CancelAt::TargetMetadata);
    assert_eq!(fixture.run(false).unwrap_err().kind, ErrorKind::Offline);
    assert_eq!(fixture.mkcols(), 0);
    assert!(
        fixture
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.contains("/new-folder "))
    );
}

#[test]
fn mkdir_cancellation_after_single_send_retains_uncertain_outcome() {
    let fixture = Fixture::new(CancelAt::Sent);
    assert!(matches!(
        fixture.run(false).unwrap(),
        DirectoryCreateResponse::Uncertain(_)
    ));
    assert_eq!(fixture.mkcols(), 1);
}

#[test]
fn mkdir_legacy_wrapper_and_uncancelled_sibling_each_send_once() {
    for legacy in [true, false] {
        let fixture = Fixture::new(CancelAt::Never);
        assert!(matches!(
            fixture.run(legacy).unwrap(),
            DirectoryCreateResponse::Created
        ));
        assert_eq!(fixture.mkcols(), 1);
    }
}

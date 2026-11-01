use super::*;
use std::{
    net::{TcpListener, TcpStream},
    sync::{atomic::AtomicBool, mpsc},
    thread,
};

struct Server {
    url: String,
    seen: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
    stopping: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<Vec<String>>>,
}

impl Server {
    fn start(download: bool, cancel_graph: Option<OperationCancellation>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/");
        let graph = super::tests::GRAPH
            .replace("127.0.0.1:PORT", &address.to_string())
            .replace("/dav/personal/", "/dav/spaces/drive-1/");
        let (seen_tx, seen) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let stopping = Arc::new(AtomicBool::new(false));
        let stop = stopping.clone();
        let join = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut requests = Vec::new();
            while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let request = read_request(&mut stream);
                let first = request.lines().next().unwrap();
                let content = first.starts_with("PUT ")
                    || (first.starts_with("GET ") && first.contains("/slow.bin "));
                requests.push(request.clone());
                if content {
                    seen_tx.send(()).unwrap();
                    let _ = release_rx.recv_timeout(Duration::from_secs(5));
                    // No response is sent: the caller must cancel its owned
                    // future while this socket remains held open.
                    break;
                }
                let (status, body) = if first.starts_with("GET ") {
                    if let Some(cancellation) = &cancel_graph {
                        cancellation.cancel();
                    }
                    ("200 OK", graph.clone())
                } else if first.contains("/slow.bin ") {
                    if download {
                        ("207 Multi-Status", dav_entry(false))
                    } else {
                        ("404 Not Found", String::new())
                    }
                } else {
                    ("207 Multi-Status", dav_entry(true))
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
                if cancel_graph.is_some() {
                    break;
                }
            }
            requests
        });
        Self {
            url,
            seen,
            release,
            stopping,
            join: Some(join),
        }
    }

    fn finish(mut self) -> Vec<String> {
        self.stopping.store(true, Ordering::Release);
        let _ = self.release.send(());
        self.join.take().unwrap().join().unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = self.release.send(());
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() <= 32 * 1024);
    }
    let headers = String::from_utf8(bytes).unwrap();
    let length = headers
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    assert!(length <= 1024);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    headers
}

fn dav_entry(root: bool) -> String {
    let (path, kind, id, size) = if root {
        ("", "<d:collection/>", "drive-1!expected-root", 0)
    } else {
        ("slow.bin", "", "drive-1!file", 2)
    };
    format!(
        r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/spaces/drive-1/{path}</d:href><d:propstat><d:prop><d:resourcetype>{kind}</d:resourcetype><d:getetag>"v1"</d:getetag><d:getcontentlength>{size}</d:getcontentlength><oc:fileid>{id}</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#
    )
}

fn transfer(
    client: &OpenCloudClient,
    download: bool,
    path: &Path,
    token: &OperationCancellation,
) -> Result<RemoteEntry, CloudError> {
    if download {
        client.download_in_root_with_cancellation(
            "drive-1",
            "/slow.bin",
            Some("\"v1\""),
            path,
            "drive-1!expected-root",
            token,
        )
    } else {
        client.upload_in_root_with_cancellation(
            "drive-1",
            "/slow.bin",
            path,
            WriteCondition::Absent,
            "drive-1!expected-root",
            token,
        )
    }
}

#[test]
fn cancelled_owner_refuses_before_any_network_and_preserves_local_file() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = OpenCloudClient::new_with_proxy(
        &format!("http://{}/", listener.local_addr().unwrap()),
        "synthetic-token".into(),
        &ProxyConfig::Direct,
    )
    .unwrap();
    let token = OperationCancellation::new();
    token.cancel();
    for download in [false, true] {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"retained").unwrap();
        assert_eq!(
            transfer(&client, download, file.path(), &token)
                .unwrap_err()
                .kind,
            ErrorKind::Offline
        );
        assert_eq!(std::fs::read(file.path()).unwrap(), b"retained");
    }
    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn cancellation_during_metadata_is_not_lost_when_body_token_would_start_later() {
    for download in [false, true] {
        let token = OperationCancellation::new();
        let server = Server::start(download, Some(token.clone()));
        let client = OpenCloudClient::new_with_proxy(
            &server.url,
            "synthetic-token".into(),
            &ProxyConfig::Direct,
        )
        .unwrap();
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"retained").unwrap();
        let result = transfer(&client, download, file.path(), &token);
        let requests = server.finish();
        assert_eq!(result.unwrap_err().kind, ErrorKind::Offline);
        assert_eq!(requests.len(), 1);
        assert_eq!(std::fs::read(file.path()).unwrap(), b"retained");
    }
}

#[test]
fn owned_cancellation_aborts_root_bound_upload_and_download_without_account_cancel() {
    for download in [false, true] {
        let token = OperationCancellation::new();
        let server = Server::start(download, None);
        let budget = TransferBudget::new();
        let unrelated = budget.cancellation();
        let client = OpenCloudClient::new_with_proxy_and_transfer_budget(
            &server.url,
            "synthetic-token".into(),
            &ProxyConfig::Direct,
            budget.clone(),
        )
        .unwrap()
        .with_body_idle_timeout_for_test(Duration::from_secs(5));
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"xy").unwrap();
        let source = file.path().to_owned();
        let owned = token.clone();
        let (result_tx, result_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = result_tx.send(transfer(&client, download, &source, &owned));
        });
        let started = server.seen.recv_timeout(Duration::from_secs(5));
        token.cancel();
        let result = result_rx.recv_timeout(Duration::from_secs(2));
        // Release fixture sockets before assertions, even if a regression
        // failed to cancel promptly; join every owned thread.
        let requests = server.finish();
        worker.join().unwrap();
        started.expect("root-bound transfer reached held content request");
        assert_eq!(
            result
                .expect("cancel before idle timeout")
                .unwrap_err()
                .kind,
            ErrorKind::Offline
        );
        assert!(!unrelated.is_cancelled());
        assert_eq!(std::fs::read(file.path()).unwrap(), b"xy");
        let content = requests.last().unwrap();
        assert!(content.starts_with(if download { "GET " } else { "PUT " }));
        if !download {
            assert!(content.to_ascii_lowercase().contains("if-none-match: *"));
            assert!(content.to_ascii_lowercase().contains("if:"));
        }
    }
}

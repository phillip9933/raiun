//! Focused operation-local Space/root metadata regressions. Synthetic HTTP only.
use super::*;
use crate::tests::{GRAPH, fixture};

const ROOT: &str = r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><oc:fileid>root-id</oc:fileid><d:getcontentlength>0</d:getcontentlength><d:getetag>"root-etag"</d:getetag><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#;

fn graph_count(requests: &[String]) -> usize {
    requests
        .iter()
        .filter(|request| request.starts_with("GET /graph/v1.0/me/drives "))
        .count()
}

#[cfg(unix)]
fn engine(client: Arc<OpenCloudClient>, state: &Path) -> raiun_engine::Engine {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(state, std::fs::Permissions::from_mode(0o700)).unwrap();
    raiun_engine::Engine::open(&state.join("engine"), client.clone())
        .unwrap()
        .with_offline_cache(
            raiun_cache::Cache::open(state, 1024 * 1024).unwrap(),
            "synthetic-account".into(),
            client.server_origin().unwrap(),
        )
        .unwrap()
}

#[cfg(unix)]
#[test]
fn engine_root_metadata_reuses_one_graph_resolution_per_operation() {
    // This is exactly the prior Engine sequence: spaces(), then stat(root).
    let (old_url, old_peer) = fixture(vec![
        ("200 OK", GRAPH.into()),
        ("200 OK", GRAPH.into()),
        ("207 Multi-Status", ROOT.into()),
        ("207 Multi-Status", ROOT.into()),
    ]);
    let old = OpenCloudClient::new_with_proxy(&old_url, "synthetic".into(), &ProxyConfig::Direct)
        .unwrap();
    let old_space = old.spaces().unwrap().remove(0);
    let old_root = old.stat(&old_space.id, "/").unwrap();
    let old_requests = old_peer.join().unwrap();

    let changed = ROOT.replace("root-id", "next-root-id");
    let (url, peer) = fixture(vec![
        ("200 OK", GRAPH.into()),
        ("207 Multi-Status", ROOT.into()),
        ("207 Multi-Status", ROOT.into()),
        ("200 OK", GRAPH.into()),
        ("207 Multi-Status", changed.clone()),
        ("207 Multi-Status", changed),
    ]);
    let client = Arc::new(
        OpenCloudClient::new_with_proxy(&url, "synthetic".into(), &ProxyConfig::Direct).unwrap(),
    );
    let state = tempfile::tempdir().unwrap();
    let engine = engine(client, state.path());
    let first = engine.stat("drive-1", "/");
    let second = engine.stat("drive-1", "/");
    let requests = peer.join().unwrap();
    assert_eq!(first.unwrap(), old_root);
    assert_eq!(second.unwrap().id, "next-root-id", "no cross-call reuse");
    assert_eq!(old_requests.len(), 4);
    assert_eq!(graph_count(&old_requests), 2);
    assert_eq!(requests.len(), 6);
    assert_eq!(graph_count(&requests), 2, "one fresh Graph query per call");
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.starts_with("PROPFIND "))
            .count(),
        4,
        "both original root DAV checks remain in each operation"
    );
}

#[test]
fn root_metadata_denies_unknown_encrypted_and_foreign_spaces_before_dav() {
    for (graph, id, expected) in [
        (GRAPH.to_owned(), "missing", ErrorKind::NotFound),
        (
            GRAPH.replace(
                "\"name\":\"Personal\"",
                "\"name\":\"Personal\",\"encrypted\":true",
            ),
            "drive-1",
            ErrorKind::Unsupported,
        ),
        (
            GRAPH.replace("http://127.0.0.1:PORT", "https://foreign.invalid"),
            "drive-1",
            ErrorKind::InvalidResponse,
        ),
    ] {
        let (url, peer) = fixture(vec![("200 OK", graph)]);
        let client =
            OpenCloudClient::new_with_proxy(&url, "synthetic".into(), &ProxyConfig::Direct)
                .unwrap();
        let result = client.space_root_metadata(id);
        let requests = peer.join().unwrap();
        assert_eq!(result.unwrap_err().kind, expected);
        assert_eq!(requests.len(), 1);
        assert_eq!(graph_count(&requests), 1);
    }
}

#[cfg(unix)]
#[test]
fn root_metadata_keeps_read_only_space_and_root_readable() {
    let graph = GRAPH.replace("\"id\":\"root\",", "\"id\":\"root\",\"permissions\":\"R\",");
    let root = ROOT.replace("RDNVW", "R");
    let (url, peer) = fixture(vec![
        ("200 OK", graph),
        ("207 Multi-Status", root.clone()),
        ("207 Multi-Status", root),
    ]);
    let client = Arc::new(
        OpenCloudClient::new_with_proxy(&url, "synthetic".into(), &ProxyConfig::Direct).unwrap(),
    );
    let state = tempfile::tempdir().unwrap();
    let engine = engine(client, state.path());
    let result = engine.stat("drive-1", "/");
    let requests = peer.join().unwrap();
    let root = result.unwrap();
    assert_eq!(root.id, "root-id");
    assert!(!root.writable);
    assert_eq!(requests.len(), 3);
    assert_eq!(graph_count(&requests), 1);
}

#[test]
fn root_metadata_keeps_ordinary_root_shape_and_vault_checks() {
    for root in [
        ROOT.replace("/dav/personal/</d:href>", "/dav/personal/other</d:href>"),
        ROOT.replace("<d:collection/>", ""),
        ROOT.replace(
            "<d:getcontentlength>",
            "<d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype><d:getcontentlength>",
        ),
    ] {
        let (url, peer) = fixture(vec![("200 OK", GRAPH.into()), ("207 Multi-Status", root)]);
        let client =
            OpenCloudClient::new_with_proxy(&url, "synthetic".into(), &ProxyConfig::Direct).unwrap();
        let result = client.space_root_metadata("drive-1");
        let requests = peer.join().unwrap();
        assert!(result.is_err());
        assert_eq!(requests.len(), 2, "refuse in the original ancestry check");
        assert_eq!(graph_count(&requests), 1);
    }
}

#[test]
fn root_metadata_preserves_outer_generation_and_deadline_before_io() {
    for stale_generation in [false, true] {
        let (url, peer) = fixture(Vec::new());
        let client =
            OpenCloudClient::new_with_proxy(&url, "synthetic".into(), &ProxyConfig::Direct)
                .unwrap();
        let context = RangeReadContext {
            deadline: if stale_generation {
                Instant::now() + Duration::from_secs(5)
            } else {
                Instant::now() - Duration::from_secs(1)
            },
            token_generation: client.token_generation(),
        };
        if stale_generation {
            client.set_bearer_token("synthetic-rotated".into()).unwrap();
        }
        let _guard = RangeContextGuard::enter(context);
        let result = client.space_root_metadata("drive-1");
        let requests = peer.join().unwrap();
        assert_eq!(result.unwrap_err().kind, ErrorKind::Unauthorized);
        assert!(requests.is_empty());
    }
}

#[test]
fn root_metadata_refuses_rotation_during_final_dav_response() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    struct Peer(Option<thread::JoinHandle<Vec<String>>>);
    impl Peer {
        fn finish(mut self) -> Vec<String> {
            self.0.take().unwrap().join().unwrap()
        }
    }
    impl Drop for Peer {
        fn drop(&mut self) {
            if let Some(peer) = self.0.take() {
                let _ = peer.join();
            }
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let client = Arc::new(
        OpenCloudClient::new_with_proxy(
            &format!("http://{address}"),
            "synthetic".into(),
            &ProxyConfig::Direct,
        )
        .unwrap(),
    );
    let rotate = client.clone();
    let peer = Peer(Some(thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut seen = Vec::new();
        for (index, body) in [GRAPH, ROOT, ROOT].into_iter().enumerate() {
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return seen;
                        }
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => return seen,
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                if stream.read_exact(&mut byte).is_err() {
                    return seen;
                }
                header.push(byte[0]);
            }
            let header = String::from_utf8(header).unwrap();
            let length = header
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if stream.read_exact(&mut vec![0; length]).is_err() {
                return seen;
            }
            seen.push(header);
            if index == 2 {
                // The final metadata request used the original bearer. Rotate
                // before delivering its response; no old observation may escape.
                rotate.set_bearer_token("synthetic-rotated".into()).unwrap();
            }
            let body = body.replace("127.0.0.1:PORT", &address.to_string());
            let status = if index == 0 {
                "200 OK"
            } else {
                "207 Multi-Status"
            };
            if write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .is_err()
            {
                return seen;
            }
        }
        seen
    })));
    let result = client.space_root_metadata("drive-1");
    let requests = peer.finish();
    assert_eq!(result.unwrap_err().kind, ErrorKind::Unauthorized);
    assert_eq!(requests.len(), 3);
    assert_eq!(graph_count(&requests), 1);
}

use crate::{tests::GRAPH, *};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::mpsc::{self, Sender},
    thread,
    time::Instant,
};

#[derive(Clone, Copy)]
enum LeafReply {
    Present,
    Missing,
    EmptyMultiStatus,
    Forbidden,
    WrongPath,
}

#[derive(Clone, Copy, Default)]
struct FixtureOptions {
    root_missing_call: Option<usize>,
    root_change_call: Option<usize>,
    parent_missing_call: Option<usize>,
    parent_change_call: Option<usize>,
    wrong_root_id: bool,
    encrypted_root: bool,
    rotate_at_leaf: bool,
    hostile_graph_dav_url: Option<&'static str>,
}

fn request(client: &OpenCloudClient) -> OrdinaryPresenceRequest<'static> {
    OrdinaryPresenceRequest {
        space: "drive-1",
        remote_root_path: "/folder",
        expected_root_id: "configured-root",
        relative_path: "child/item.txt",
        context: RangeReadContext {
            deadline: Instant::now() + Duration::from_secs(5),
            token_generation: client.token_generation(),
        },
    }
}

fn dynamic_fixture(
    options: FixtureOptions,
    leaf_reply: LeafReply,
) -> (OpenCloudClient, Sender<()>, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    let server = format!("http://{authority}");
    let client =
        OpenCloudClient::new_with_proxy(&server, "synthetic-token".into(), &ProxyConfig::Direct)
            .unwrap();
    let worker_client = client.clone();
    let (stop_tx, stop_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let started = Instant::now();
        let mut requests = Vec::new();
        let mut root_calls = 0usize;
        let mut parent_calls = 0usize;
        loop {
            if stop_rx.try_recv().is_ok() || started.elapsed() >= Duration::from_secs(10) {
                break;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .expect("accepted fixture stream must be blocking");
                    let deadline = started + Duration::from_secs(10);
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    let timeout = remaining.min(Duration::from_secs(2));
                    stream
                        .set_read_timeout(Some(timeout))
                        .expect("set bounded fixture read timeout");
                    stream
                        .set_write_timeout(Some(timeout))
                        .expect("set bounded fixture write timeout");
                    let headers = read_headers(&mut stream, deadline);
                    if !consume_body(&mut stream, &headers, deadline) {
                        requests.push(headers);
                        break;
                    }
                    let request_line = headers.lines().next().unwrap_or_default().to_owned();
                    requests.push(headers);
                    if requests.len() >= 64 {
                        break;
                    }
                    let mut pieces = request_line.split_whitespace();
                    let method = pieces.next().unwrap_or_default();
                    let path = pieces.next().unwrap_or_default();
                    let normalized_path = path.trim_end_matches('/');
                    if method == "GET" && path == "/graph/v1.0/me/drives" {
                        let mut graph = GRAPH.replace("127.0.0.1:PORT", &authority);
                        if let Some(hostile) = options.hostile_graph_dav_url {
                            graph = GRAPH.replace("http://127.0.0.1:PORT/dav/personal/", hostile);
                            graph = graph.replace("127.0.0.1:PORT", &authority);
                        }
                        respond(&mut stream, "200 OK", &graph);
                    } else if method == "PROPFIND" && normalized_path == "/dav/personal" {
                        respond(&mut stream, "207 Multi-Status", &personal_root_xml());
                    } else if method == "PROPFIND" && normalized_path == "/dav/personal/folder" {
                        root_calls += 1;
                        if options.root_missing_call == Some(root_calls) {
                            respond(&mut stream, "404 Not Found", "");
                            continue;
                        }
                        let root_id = if options.wrong_root_id {
                            "wrong-root"
                        } else if options.root_change_call == Some(root_calls) {
                            "changed-root"
                        } else {
                            "configured-root"
                        };
                        respond(
                            &mut stream,
                            "207 Multi-Status",
                            &configured_root_xml(root_id, options.encrypted_root),
                        );
                    } else if method == "PROPFIND"
                        && normalized_path == "/dav/personal/folder/child"
                    {
                        parent_calls += 1;
                        if options.parent_missing_call == Some(parent_calls) {
                            respond(&mut stream, "404 Not Found", "");
                        } else {
                            let parent_id = if options.parent_change_call == Some(parent_calls) {
                                "changed-parent"
                            } else {
                                "parent-id"
                            };
                            respond(&mut stream, "207 Multi-Status", &parent_xml(parent_id));
                        }
                    } else if method == "PROPFIND"
                        && normalized_path == "/dav/personal/folder/child/item.txt"
                    {
                        if options.rotate_at_leaf {
                            worker_client
                                .set_bearer_token("rotated-synthetic-token".into())
                                .unwrap();
                        }
                        match leaf_reply {
                            LeafReply::Present => {
                                respond(&mut stream, "207 Multi-Status", &leaf_xml());
                            }
                            LeafReply::Missing => respond(&mut stream, "404 Not Found", ""),
                            LeafReply::EmptyMultiStatus => {
                                respond(
                                    &mut stream,
                                    "207 Multi-Status",
                                    r#"<d:multistatus xmlns:d="DAV:"></d:multistatus>"#,
                                );
                            }
                            LeafReply::Forbidden => respond(&mut stream, "403 Forbidden", ""),
                            LeafReply::WrongPath => {
                                respond(&mut stream, "207 Multi-Status", &wrong_leaf_xml());
                            }
                        }
                    } else {
                        respond(&mut stream, "500 Internal Server Error", "");
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
        requests
    });
    (client, stop_tx, worker)
}

fn read_headers(stream: &mut std::net::TcpStream, deadline: Instant) -> String {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") && bytes.len() < 32 * 1024 && Instant::now() < deadline {
        match stream.read_exact(&mut byte) {
            Ok(()) => bytes.push(byte[0]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn consume_body(stream: &mut std::net::TcpStream, headers: &str, deadline: Instant) -> bool {
    let length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    if length > 64 * 1024 || Instant::now() >= deadline {
        return false;
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).is_ok()
}

fn respond(stream: &mut std::net::TcpStream, status: &str, body: &str) {
    write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n", body.len())
        .expect("write bounded fixture response headers");
    stream
        .write_all(body.as_bytes())
        .expect("write bounded fixture response body");
}

fn finish(stop: Sender<()>, worker: thread::JoinHandle<Vec<String>>) -> Vec<String> {
    let _ = stop.send(());
    worker.join().expect("bounded loopback fixture must join")
}

fn personal_root_xml() -> String {
    dav_directory("/dav/personal/", "personal-root")
}

fn configured_root_xml(id: &str, encrypted: bool) -> String {
    let content_type = if encrypted {
        "<d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype>"
    } else {
        ""
    };
    format!(
        r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/folder/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>"root-etag"</d:getetag><oc:fileid>{id}</oc:fileid>{content_type}<oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#
    )
}

fn parent_xml(id: &str) -> String {
    dav_directory("/dav/personal/folder/child/", id)
}

fn dav_directory(href: &str, id: &str) -> String {
    format!(
        r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>{href}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>"dir-etag"</d:getetag><oc:fileid>{id}</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#
    )
}

fn leaf_xml() -> String {
    r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/folder/child/item.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>7</d:getcontentlength><d:getetag>"leaf-etag"</d:getetag><oc:fileid>leaf-id</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned()
}

fn wrong_leaf_xml() -> String {
    leaf_xml().replace(
        "/dav/personal/folder/child/item.txt",
        "/dav/personal/folder/child/item.txt/descendant",
    )
}

fn assert_metadata_only(requests: &[String]) {
    assert!(requests.iter().all(|headers| {
        let line = headers.lines().next().unwrap_or_default();
        line.starts_with("GET ") || line.starts_with("PROPFIND ")
    }));
}

#[test]
fn direct_leaf_404_is_absent_but_present_metadata_is_preserved() {
    for leaf_reply in [LeafReply::Missing, LeafReply::Present] {
        let (client, stop, worker) = dynamic_fixture(FixtureOptions::default(), leaf_reply);
        let result = client.ordinary_target_presence_with_context(request(&client));
        let seen = finish(stop, worker);
        assert_metadata_only(&seen);
        match (leaf_reply, result.unwrap()) {
            (LeafReply::Missing, OrdinaryTargetPresence::Absent) => {}
            (LeafReply::Present, OrdinaryTargetPresence::Present(entry)) => {
                assert_eq!(entry.id, "leaf-id");
                assert_eq!(entry.path, "/folder/child/item.txt");
                assert_eq!(entry.size, 7);
                assert_eq!(entry.etag, "\"leaf-etag\"");
                assert!(!entry.directory);
            }
            _ => panic!("leaf response must preserve exact presence type"),
        }
    }
}

#[test]
fn empty_multistatus_is_not_misreported_as_leaf_404() {
    let (client, stop, worker) =
        dynamic_fixture(FixtureOptions::default(), LeafReply::EmptyMultiStatus);
    let result = client.ordinary_target_presence_with_context(request(&client));
    let seen = finish(stop, worker);
    assert_metadata_only(&seen);
    assert!(matches!(result, Err(error) if error.kind == ErrorKind::InvalidResponse));
}

#[test]
fn leaf_response_for_a_descendant_path_is_not_returned_as_present() {
    let (client, stop, worker) = dynamic_fixture(FixtureOptions::default(), LeafReply::WrongPath);
    let result = client.ordinary_target_presence_with_context(request(&client));
    let seen = finish(stop, worker);
    assert_metadata_only(&seen);
    assert!(matches!(result, Err(error) if error.kind == ErrorKind::InvalidResponse));
}

#[test]
fn root_and_parent_not_found_remain_errors_not_absence() {
    for options in [
        FixtureOptions {
            root_missing_call: Some(1),
            ..FixtureOptions::default()
        },
        FixtureOptions {
            parent_missing_call: Some(1),
            ..FixtureOptions::default()
        },
    ] {
        let (client, stop, worker) = dynamic_fixture(options, LeafReply::Missing);
        let result = client.ordinary_target_presence_with_context(request(&client));
        let seen = finish(stop, worker);
        assert_metadata_only(&seen);
        assert!(matches!(result, Err(error) if error.kind == ErrorKind::NotFound));
    }
}

#[test]
fn leaf_forbidden_and_encrypted_or_wrong_root_fail_closed() {
    let (client, stop, worker) = dynamic_fixture(FixtureOptions::default(), LeafReply::Forbidden);
    let result = client.ordinary_target_presence_with_context(request(&client));
    let seen = finish(stop, worker);
    assert_metadata_only(&seen);
    assert!(matches!(result, Err(error) if error.kind == ErrorKind::Forbidden));

    for options in [
        FixtureOptions {
            wrong_root_id: true,
            ..FixtureOptions::default()
        },
        FixtureOptions {
            encrypted_root: true,
            ..FixtureOptions::default()
        },
    ] {
        let (client, stop, worker) = dynamic_fixture(options, LeafReply::Missing);
        let result = client.ordinary_target_presence_with_context(request(&client));
        let seen = finish(stop, worker);
        assert_metadata_only(&seen);
        assert!(result.is_err());
    }
}

#[test]
fn post_leaf_root_or_ancestor_change_cannot_be_reported_absent() {
    for options in [
        FixtureOptions {
            root_missing_call: Some(3),
            ..FixtureOptions::default()
        },
        FixtureOptions {
            root_change_call: Some(3),
            ..FixtureOptions::default()
        },
        FixtureOptions {
            parent_missing_call: Some(2),
            ..FixtureOptions::default()
        },
        FixtureOptions {
            parent_change_call: Some(2),
            ..FixtureOptions::default()
        },
        FixtureOptions {
            rotate_at_leaf: true,
            ..FixtureOptions::default()
        },
    ] {
        let (client, stop, worker) = dynamic_fixture(options, LeafReply::Missing);
        let result = client.ordinary_target_presence_with_context(request(&client));
        let seen = finish(stop, worker);
        assert_metadata_only(&seen);
        assert!(result.is_err());
    }
}

#[test]
fn invalid_input_and_expired_context_send_no_http_requests() {
    let (client, stop, worker) = dynamic_fixture(FixtureOptions::default(), LeafReply::Missing);
    let mut invalid = request(&client);
    invalid.relative_path = "../item.txt";
    let invalid_result = client.ordinary_target_presence_with_context(invalid);
    let deep_path = format!(
        "{}/item.txt",
        vec!["child"; MAX_VAULT_GUARD_DEPTH].join("/")
    );
    let mut deep = request(&client);
    deep.relative_path = &deep_path;
    let deep_result = client.ordinary_target_presence_with_context(deep);
    let mut expired = request(&client);
    expired.context.deadline = Instant::now() - Duration::from_millis(1);
    let expired_result = client.ordinary_target_presence_with_context(expired);
    let seen = finish(stop, worker);
    assert!(invalid_result.is_err());
    assert!(deep_result.is_err());
    assert!(expired_result.is_err());
    assert!(seen.is_empty());
}

#[test]
fn graph_dav_query_or_userinfo_is_rejected_before_leaf_lookup() {
    for hostile in [
        "http://127.0.0.1:PORT/dav/personal/?selector=1",
        "http://user@127.0.0.1:PORT/dav/personal/",
    ] {
        let options = FixtureOptions {
            hostile_graph_dav_url: Some(hostile),
            ..FixtureOptions::default()
        };
        let (client, stop, worker) = dynamic_fixture(options, LeafReply::Missing);
        let result = client.ordinary_target_presence_with_context(request(&client));
        let requests = finish(stop, worker);
        assert_eq!(requests.len(), 1);
        assert_metadata_only(&requests);
        assert!(matches!(result, Err(error) if error.kind == ErrorKind::InvalidResponse));
    }
}

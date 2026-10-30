use crate::{
    tests::{GRAPH, fixture},
    *,
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::mpsc::{self, Sender},
    thread,
    time::Instant,
};

const DESTINATION_EMPTY: u8 = 1;
const DESTINATION_FORBIDDEN: u8 = 2;
const DESTINATION_UNEXPECTED: u8 = 3;

#[derive(Clone, Copy)]
enum FinalAction {
    Status(&'static str),
    CommittedStatus(&'static str),
    Drop,
    RotateThenStatus(&'static str),
}

#[derive(Clone, Copy, Default)]
struct FixtureOptions {
    wrong_root_id: bool,
    wrong_source_id: bool,
    destination_exists: bool,
    destination_fault: u8,
    destination_fault_call: u8,
}

fn request(client: &OpenCloudClient) -> ConditionalRenameRequest<'static> {
    ConditionalRenameRequest {
        space: "drive-1",
        remote_root_path: "/",
        expected_root_id: "root",
        source_relative_path: "source.txt",
        destination_relative_path: "renamed.txt",
        expected_source_id: "file-id",
        expected_source_size: 4,
        expected_source_etag: "\"source-etag\"",
        context: RangeReadContext {
            deadline: Instant::now() + Duration::from_secs(5),
            token_generation: client.token_generation(),
        },
    }
}

fn dynamic_fixture(
    options: FixtureOptions,
    final_action: FinalAction,
) -> (
    OpenCloudClient,
    String,
    Sender<()>,
    thread::JoinHandle<Vec<String>>,
) {
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
        let mut destination_calls = 0u8;
        loop {
            if stop_rx.try_recv().is_ok() || started.elapsed() >= Duration::from_secs(10) {
                break;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .expect("accepted fixture stream must use bounded blocking I/O");
                    let deadline = started + Duration::from_secs(10);
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    let socket_timeout = remaining.min(Duration::from_secs(2));
                    stream
                        .set_read_timeout(Some(socket_timeout))
                        .expect("set bounded fixture read timeout");
                    stream
                        .set_write_timeout(Some(socket_timeout))
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
                    if method == "MOVE" {
                        match final_action {
                            FinalAction::Status(status) => {
                                write_response(&mut stream, status, "");
                            }
                            FinalAction::CommittedStatus(status) => {
                                if let Some(move_request) = requests.last_mut() {
                                    move_request
                                        .push_str("\nFIXTURE:MOVE_COMMITTED_BEFORE_RESPONSE");
                                }
                                write_response(&mut stream, status, "");
                            }
                            FinalAction::Drop => drop(stream),
                            FinalAction::RotateThenStatus(status) => {
                                worker_client
                                    .set_bearer_token("rotated-synthetic-token".into())
                                    .unwrap();
                                write_response(&mut stream, status, "");
                            }
                        }
                        continue;
                    }
                    if method == "GET" && path == "/graph/v1.0/me/drives" {
                        write_response(
                            &mut stream,
                            "200 OK",
                            &GRAPH.replace("127.0.0.1:PORT", &authority),
                        );
                    } else if method == "PROPFIND" && path == "/dav/personal/" {
                        let root_id = if options.wrong_root_id {
                            "replacement-root"
                        } else {
                            "root"
                        };
                        write_response(&mut stream, "207 Multi-Status", &root_xml(root_id));
                    } else if method == "PROPFIND" && path == "/dav/personal/source.txt" {
                        let source_id = if options.wrong_source_id {
                            "replacement-file"
                        } else {
                            "file-id"
                        };
                        write_response(&mut stream, "207 Multi-Status", &source_xml(source_id));
                    } else if method == "PROPFIND" && path == "/dav/personal/renamed.txt" {
                        destination_calls = destination_calls.saturating_add(1);
                        if options.destination_exists {
                            write_response(&mut stream, "207 Multi-Status", &destination_xml());
                        } else if options.destination_fault != 0
                            && options.destination_fault_call == destination_calls
                        {
                            match options.destination_fault {
                                DESTINATION_EMPTY => write_response(
                                    &mut stream,
                                    "207 Multi-Status",
                                    r#"<d:multistatus xmlns:d="DAV:"></d:multistatus>"#,
                                ),
                                DESTINATION_FORBIDDEN => {
                                    write_response(&mut stream, "403 Forbidden", "")
                                }
                                _ => write_response(&mut stream, "500 Internal Server Error", ""),
                            }
                        } else {
                            write_response(&mut stream, "404 Not Found", "");
                        }
                    } else {
                        write_response(&mut stream, "500 Internal Server Error", "");
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
    (client, server, stop_tx, worker)
}

fn read_headers(stream: &mut std::net::TcpStream, deadline: Instant) -> String {
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    while !request.ends_with(b"\r\n\r\n") && request.len() < 32 * 1024 && Instant::now() < deadline
    {
        match stream.read_exact(&mut byte) {
            Ok(()) => request.push(byte[0]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&request).into_owned()
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

fn write_response(stream: &mut std::net::TcpStream, status: &str, body: &str) {
    write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n", body.len())
        .expect("write bounded fixture response headers");
    stream
        .write_all(body.as_bytes())
        .expect("write bounded fixture response body");
}

fn root_xml(id: &str) -> String {
    format!(
        r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>"root-etag"</d:getetag><oc:fileid>{id}</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#
    )
}

fn source_xml(id: &str) -> String {
    format!(
        r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/source.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>4</d:getcontentlength><d:getetag>"source-etag"</d:getetag><oc:fileid>{id}</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#
    )
}

fn destination_xml() -> String {
    r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/renamed.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>4</d:getcontentlength><d:getetag>"destination-etag"</d:getetag><oc:fileid>destination-id</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned()
}

fn finish(stop: Sender<()>, worker: thread::JoinHandle<Vec<String>>) -> Vec<String> {
    let _ = stop.send(());
    worker.join().expect("bounded loopback fixture must join")
}

#[test]
fn invalid_shapes_validators_and_expired_context_send_no_requests() {
    let (client, _server, stop, worker) =
        dynamic_fixture(FixtureOptions::default(), FinalAction::Drop);
    let mut all_rejected = true;
    for (source, destination, etag) in [
        ("", "renamed.txt", "\"source-etag\""),
        ("/", "renamed.txt", "\"source-etag\""),
        ("source.txt", "source.txt", "\"source-etag\""),
        ("source.txt", "SOURCE.TXT", "\"source-etag\""),
        ("folder/source.txt", "other/renamed.txt", "\"source-etag\""),
        ("source.txt", "renamed.txt", "W/\"weak\""),
        ("source.txt", "renamed.txt", "bad\netag"),
    ] {
        let mut args = request(&client);
        args.source_relative_path = source;
        args.destination_relative_path = destination;
        args.expected_source_etag = etag;
        all_rejected &= client.conditional_rename_with_context(args).is_err();
    }
    let mut expired = request(&client);
    expired.context.deadline = Instant::now() - Duration::from_millis(1);
    all_rejected &= client.conditional_rename_with_context(expired).is_err();
    let seen = finish(stop, worker);
    assert!(all_rejected);
    assert!(seen.is_empty());
}

#[test]
fn one_move_uses_if_match_overwrite_false_and_treats_post_send_statuses_as_uncertain() {
    for (action, expected_kind, committed_before_response) in [
        (FinalAction::Status("201 Created"), None, false),
        (FinalAction::Status("204 No Content"), None, false),
        (
            FinalAction::Status("409 Conflict"),
            Some(ErrorKind::Conflict),
            false,
        ),
        (
            FinalAction::Status("403 Forbidden"),
            Some(ErrorKind::Forbidden),
            false,
        ),
        (
            FinalAction::CommittedStatus("403 Forbidden"),
            Some(ErrorKind::Forbidden),
            true,
        ),
        (
            FinalAction::CommittedStatus("404 Not Found"),
            Some(ErrorKind::NotFound),
            true,
        ),
    ] {
        let (client, server, stop, worker) = dynamic_fixture(FixtureOptions::default(), action);
        let result = client.conditional_rename_with_context(request(&client));
        let seen = finish(stop, worker);
        let moves: Vec<_> = seen
            .iter()
            .filter(|line| line.starts_with("MOVE "))
            .collect();
        let outcome = match &result {
            Ok(ConditionalRenameResponse::Renamed) => "Renamed".to_owned(),
            Ok(ConditionalRenameResponse::Rejected(error)) => format!("Rejected({:?})", error.kind),
            Ok(ConditionalRenameResponse::Uncertain(error)) => {
                format!("Uncertain({:?})", error.kind)
            }
            Err(error) => format!("BeforeMove({:?})", error.kind),
        };
        let request_lines: Vec<_> = seen
            .iter()
            .filter_map(|headers| headers.lines().next())
            .collect();
        assert_eq!(
            moves.len(),
            1,
            "outcome={outcome}; request_lines={request_lines:?}"
        );
        assert!(moves[0].starts_with("MOVE /dav/personal/source.txt "));
        let headers = moves[0].to_ascii_lowercase();
        assert!(headers.contains("if-match: \"source-etag\""));
        assert!(headers.contains("overwrite: f"));
        assert!(headers.contains(&format!("destination: {server}/dav/personal/renamed.txt")));
        assert_eq!(
            seen.last().map(|line| line.starts_with("MOVE ")),
            Some(true)
        );
        assert_eq!(
            seen.last()
                .is_some_and(|line| line.contains("FIXTURE:MOVE_COMMITTED_BEFORE_RESPONSE")),
            committed_before_response
        );
        match (expected_kind, result.unwrap()) {
            (None, ConditionalRenameResponse::Renamed) => {}
            (Some(expected), ConditionalRenameResponse::Uncertain(error)) => {
                assert_eq!(error.kind, expected);
            }
            _ => panic!("unexpected conditional MOVE outcome"),
        }
    }
}

#[test]
fn unknown_status_disconnect_and_auth_rotation_are_uncertain_without_replay() {
    for action in [
        FinalAction::Status("500 Internal Server Error"),
        FinalAction::Drop,
        FinalAction::RotateThenStatus("201 Created"),
    ] {
        let (client, _server, stop, worker) = dynamic_fixture(FixtureOptions::default(), action);
        let result = client.conditional_rename_with_context(request(&client));
        let seen = finish(stop, worker);
        assert_eq!(
            seen.iter().filter(|line| line.starts_with("MOVE ")).count(),
            1
        );
        assert_eq!(
            seen.last().map(|line| line.starts_with("MOVE ")),
            Some(true)
        );
        assert!(matches!(
            result.unwrap(),
            ConditionalRenameResponse::Uncertain(_)
        ));
    }
}

#[test]
fn root_source_and_existing_destination_mismatches_fail_without_move() {
    for options in [
        FixtureOptions {
            wrong_root_id: true,
            ..FixtureOptions::default()
        },
        FixtureOptions {
            wrong_source_id: true,
            ..FixtureOptions::default()
        },
        FixtureOptions {
            destination_exists: true,
            ..FixtureOptions::default()
        },
    ] {
        let (client, _server, stop, worker) = dynamic_fixture(options, FinalAction::Drop);
        let result = client.conditional_rename_with_context(request(&client));
        let seen = finish(stop, worker);
        assert!(result.is_err());
        assert!(seen.iter().all(|line| !line.starts_with("MOVE ")));
    }
}

#[test]
fn final_destination_checks_require_wire_404_not_empty_or_other_success_responses() {
    for (fault, call, expected_kind) in [
        (DESTINATION_EMPTY, 1, ErrorKind::InvalidResponse),
        // The intermediate generic write-policy check is destination call2;
        // the second direct-leaf check immediately before MOVE is call3.
        (DESTINATION_EMPTY, 3, ErrorKind::InvalidResponse),
        (DESTINATION_FORBIDDEN, 1, ErrorKind::Forbidden),
        (DESTINATION_UNEXPECTED, 1, ErrorKind::InvalidResponse),
    ] {
        let options = FixtureOptions {
            destination_fault: fault,
            destination_fault_call: call,
            ..FixtureOptions::default()
        };
        let (client, _server, stop, worker) = dynamic_fixture(options, FinalAction::Drop);
        let result = client.conditional_rename_with_context(request(&client));
        let seen = finish(stop, worker);
        eprintln!(
            "R33b final destination fault={fault} call={call} expected={expected_kind:?} actual_error={:?} move_count={}",
            result.as_ref().err().map(|error| error.kind),
            seen.iter().filter(|line| line.starts_with("MOVE ")).count()
        );
        assert!(matches!(result, Err(error) if error.kind == expected_kind));
        assert!(seen.iter().all(|line| !line.starts_with("MOVE ")));
        if call == 3 {
            assert_eq!(
                seen.iter()
                    .filter(|line| line.starts_with("PROPFIND /dav/personal/renamed.txt "))
                    .count(),
                3
            );
        }
    }

    let (client, _server, stop, worker) = dynamic_fixture(
        FixtureOptions::default(),
        FinalAction::Status("204 No Content"),
    );
    let result = client.conditional_rename_with_context(request(&client));
    let seen = finish(stop, worker);
    assert!(matches!(result, Ok(ConditionalRenameResponse::Renamed)));
    assert_eq!(
        seen.iter()
            .filter(|line| line.starts_with("PROPFIND /dav/personal/renamed.txt "))
            .count(),
        3
    );
    assert_eq!(
        seen.iter().filter(|line| line.starts_with("MOVE ")).count(),
        1
    );
}

#[test]
fn graph_dav_url_query_or_userinfo_fails_before_move() {
    for hostile_url in [
        "http://127.0.0.1:PORT/dav/personal/?selector=1",
        "http://user@127.0.0.1:PORT/dav/personal/",
    ] {
        let (server, worker) = fixture(vec![(
            "200 OK",
            GRAPH.replace("http://127.0.0.1:PORT/dav/personal/", hostile_url),
        )]);
        let client = OpenCloudClient::new_with_proxy(
            &server,
            "synthetic-token".into(),
            &ProxyConfig::Direct,
        )
        .unwrap();
        let result = client.conditional_rename_with_context(request(&client));
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests.iter().all(|line| !line.starts_with("MOVE ")));
        assert!(matches!(result, Err(error) if error.kind == ErrorKind::InvalidResponse));
    }
}

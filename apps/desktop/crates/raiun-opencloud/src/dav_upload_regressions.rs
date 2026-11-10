//! Ordinary DAV metadata round-trips for the owner's escaped-ampersand folder.
//! Synthetic loopback only; no mounted-drive or live server acceptance.
use super::*;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    thread,
};

const FOLDER: &str = "/Courses & CEUs";
const FOLDER_WIRE: &str = "/dav/personal/Courses%20&%20CEUs";
const FILE: &str = "/Courses & CEUs/notes.txt";
const FILE_WIRE: &str = "/dav/personal/Courses%20&%20CEUs/notes.txt";
const CONTENT: &[u8] = b"synthetic notes";

fn dav(href: &str, directory: bool, etag: Option<&str>, size: usize) -> String {
    let kind = if directory { "<d:collection/>" } else { "" };
    let etag = etag
        .map(|value| format!("<d:getetag>{value}</d:getetag>"))
        .unwrap_or_default();
    format!(
        "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\"><d:response><d:href>{href}</d:href><d:propstat><d:prop><d:resourcetype>{kind}</d:resourcetype><d:getcontentlength>{size}</d:getcontentlength>{etag}<oc:fileid>stable-id</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"
    )
}
fn root() -> String {
    dav("/dav/personal/", true, Some("&quot;root-v1&quot;"), 0)
}
fn folder() -> String {
    dav(
        "/dav/personal/Courses%20&amp;%20CEUs/",
        true,
        Some("&quot;folder-v1&quot;"),
        0,
    )
}
fn file(etag: Option<&str>) -> String {
    dav(
        "/dav/personal/Courses%20&amp;%20CEUs/notes.txt",
        false,
        etag,
        CONTENT.len(),
    )
}
fn parse(xml: &str, request: &str, logical: &str) -> Result<Vec<RemoteEntry>, CloudError> {
    let mut result = Vec::new();
    parse_multistatus(
        xml.as_bytes(),
        &Url::parse(request).unwrap(),
        logical,
        &mut |entry| {
            result.push(entry);
            Ok(())
        },
    )?;
    Ok(result)
}

#[derive(Debug)]
struct Seen {
    line: String,
    depth: Option<String>,
    if_match: Option<String>,
    if_none_match: Option<String>,
    body: Vec<u8>,
}
struct Fixture {
    server: String,
    stop: Option<mpsc::Sender<()>>,
    worker: Option<thread::JoinHandle<Vec<Seen>>>,
}
impl Fixture {
    fn new(responses: Vec<(&'static str, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = mpsc::channel();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut seen = Vec::new();
            for (status, body) in responses {
                let mut socket = loop {
                    if stopped.try_recv().is_ok() {
                        return seen;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "bounded DAV fixture accept deadline"
                    );
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2))
                        }
                        Err(error) => panic!("DAV fixture accept: {error}"),
                    }
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let request = read_request(&mut socket);
                let body = body.replace("127.0.0.1:PORT", &address.to_string());
                write!(
                    socket,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
                seen.push(request);
            }
            seen
        });
        Self {
            server: format!("http://{address}"),
            stop: Some(stop),
            worker: Some(worker),
        }
    }
    fn client(&self) -> OpenCloudClient {
        OpenCloudClient::new_with_proxy(
            &self.server,
            "synthetic-token".into(),
            &ProxyConfig::Direct,
        )
        .unwrap()
    }
    fn finish(mut self) -> Vec<Seen> {
        let _ = self.stop.take().unwrap().send(());
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn read_request(socket: &mut TcpStream) -> Seen {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        assert!(header.len() < 65536);
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        header.push(byte[0]);
    }
    let text = String::from_utf8(header).unwrap();
    let value = |wanted: &str| {
        text.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(wanted)
                .then(|| value.trim().to_owned())
        })
    };
    let len = value("Content-Length")
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(0);
    assert!(len < 1024 * 1024);
    let mut body = vec![0; len];
    socket.read_exact(&mut body).unwrap();
    Seen {
        line: text.lines().next().unwrap().to_owned(),
        depth: value("Depth"),
        if_match: value("If-Match"),
        if_none_match: value("If-None-Match"),
        body,
    }
}
fn graph() -> (&'static str, String) {
    ("200 OK", super::tests::GRAPH.into())
}
fn prop(xml: String) -> (&'static str, String) {
    ("207 Multi-Status", xml)
}

#[test]
fn escaped_ampersand_href_roundtrips_actual_folder_and_literal_question_mark() {
    for (logical, wire, href) in [
        (FOLDER, FOLDER_WIRE, "/dav/personal/Courses%20&amp;%20CEUs/"),
        ("/&?", "/dav/personal/&%3F", "/dav/personal/&amp;%3F/"),
        ("/&?", "/dav/personal/%26%3F", "/dav/personal/%26%3F/"),
    ] {
        let url = format!("https://cloud.invalid{wire}");
        let entry = parse(
            &dav(href, true, Some("&quot;tag&amp;opaque&quot;"), 0),
            &url,
            logical,
        )
        .unwrap()
        .remove(0);
        assert_eq!(entry.path, logical);
        assert!(entry.directory);
        assert_eq!(entry.etag, "\"tag&opaque\"");
        assert!(is_strong_etag(&entry.etag));
        let assembled = append_logical_path(
            &Url::parse("https://cloud.invalid/dav/personal/").unwrap(),
            logical,
        )
        .unwrap();
        assert!(assembled.query().is_none());
        assert!(assembled.fragment().is_none());
        assert_eq!(
            assembled.path(),
            if logical == FOLDER {
                FOLDER_WIRE
            } else {
                "/dav/personal/&%3F"
            }
        );
    }
}

#[test]
fn encoded_etag_is_distinct_from_true_missing_validator() {
    for etag in [
        "<![CDATA[\"revision\"]]>",
        "&#34;&#114;&#101;&#118;&#105;&#115;&#105;&#111;&#110;&#34;",
    ] {
        assert_eq!(
            parse(
                &dav("/dav/personal/file", false, Some(etag), 3),
                "https://cloud.invalid/dav/personal/file",
                "/file"
            )
            .unwrap()[0]
                .etag,
            "\"revision\""
        );
    }
    let error = parse(
        &dav("/dav/personal/file", false, None, 3),
        "https://cloud.invalid/dav/personal/file",
        "/file",
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.message, "DAV response omitted an entity tag");
}

#[test]
fn stat_keeps_courses_ampersand_folder_scope() {
    let fixture = Fixture::new(vec![graph(), prop(root()), prop(folder())]);
    let result = fixture.client().stat("drive-1", FOLDER);
    let seen = fixture.finish();
    let entry = result.unwrap();
    assert_eq!(entry.path, FOLDER);
    assert!(entry.directory);
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[2].line, format!("PROPFIND {FOLDER_WIRE} HTTP/1.1"));
}

#[test]
fn mkdir_followup_preserves_escaped_ampersand_href() {
    for unknown_child in [
        None,
        Some(""), // Preserve the incomplete-multistatus fallback regression.
        Some("<d:response/>"),
        Some(
            "<d:response><d:propstat><d:prop><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
        ),
    ] {
        let fallback = unknown_child.is_some();
        let target = "/Courses & CEUs/new-folder";
        let wire = "/dav/personal/Courses%20&%20CEUs/new-folder";
        let created = dav(
            "/dav/personal/Courses%20&amp;%20CEUs/new-folder",
            true,
            Some("&quot;created-directory&quot;"),
            0,
        );
        let mut responses = vec![
            graph(),
            prop(root()),
            prop(folder()),
            ("404 Not Found", String::new()),
            ("201 Created", String::new()),
            prop(root()),
            prop(folder()),
            prop(created.clone()),
            prop(if let Some(child) = unknown_child {
                if child.is_empty() {
                    created.trim_end_matches("</d:multistatus>").to_owned()
                } else {
                    created.replace("</d:multistatus>", &format!("{child}</d:multistatus>"))
                }
            } else {
                created.clone()
            }),
        ];
        if fallback {
            responses.push(prop(created));
        }
        responses.extend([prop(root()), prop(folder())]);
        let fixture = Fixture::new(responses);
        let preflights = Cell::new(0);
        let result = fixture.client().mkdir_and_confirm_with_preflight_and_view(
            "drive-1",
            target,
            &|space, root| {
                assert_eq!(space.id, "drive-1");
                assert_eq!(root.id, "stable-id");
                preflights.set(preflights.get() + 1);
                Ok(())
            },
        );
        let seen = fixture.finish();
        let (entry, observed_empty) = result.unwrap();
        assert_eq!(entry.path, target);
        assert!(entry.directory);
        assert_eq!(observed_empty, !fallback);
        assert_eq!(preflights.get(), 1);
        assert_eq!(seen.len(), 11 + usize::from(fallback));
        assert_eq!(seen[4].line, format!("MKCOL {wire} HTTP/1.1"));
        assert!(seen[4].body.is_empty());
        // Both post-MKCOL root/ancestry fences remain. Only the second
        // exact target confirmation becomes a complete depth-one view.
        assert_eq!(
            seen.iter()
                .filter(|request| request.line == format!("PROPFIND {FOLDER_WIRE} HTTP/1.1"))
                .count(),
            3
        );
        for index in [3, 7, 8] {
            assert_eq!(seen[index].line, format!("PROPFIND {wire} HTTP/1.1"));
        }
        assert_eq!(seen[3].depth.as_deref(), Some("0"));
        assert_eq!(seen[7].depth.as_deref(), Some("0"));
        assert_eq!(seen[8].depth.as_deref(), Some("1"));
        if fallback {
            assert_eq!(seen[9].line, format!("PROPFIND {wire} HTTP/1.1"));
            assert_eq!(seen[9].depth.as_deref(), Some("0"));
        }
        assert_eq!(
            seen.iter()
                .filter(|request| request.line.starts_with("MKCOL "))
                .count(),
            1
        );
    }
}

#[test]
fn parent_proof_reuse_refuses_unsafe_parent_before_mutation() {
    for (parent, expected) in [
        (folder().replace("RDNVW", "R"), ErrorKind::Forbidden),
        (
            folder().replace("<d:collection/>", ""),
            ErrorKind::Unsupported,
        ),
        (
            folder().replace(
                "</d:prop>",
                "<d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype></d:prop>",
            ),
            ErrorKind::Unsupported,
        ),
        (
            folder().replace("stable-id", "parent\tidentity"),
            ErrorKind::InvalidResponse,
        ),
    ] {
        let fixture = Fixture::new(vec![
            graph(),
            prop(root()),
            prop(parent),
            ("404 Not Found", String::new()),
        ]);
        let result = fixture
            .client()
            .mkdir_and_confirm("drive-1", "/Courses & CEUs/new-folder");
        let seen = fixture.finish();
        assert_eq!(result.unwrap_err().kind, expected);
        assert!(seen.iter().all(
            |request| request.line.starts_with("GET ") || request.line.starts_with("PROPFIND ")
        ));
    }
}

fn upload_responses(final_etag: Option<&str>) -> Vec<(&'static str, String)> {
    vec![
        graph(),
        prop(root()),
        prop(folder()),
        prop(file(Some("&quot;old&amp;revision&quot;"))),
        ("204 No Content", String::new()),
        graph(),
        prop(root()),
        prop(folder()),
        prop(file(final_etag)),
    ]
}
#[test]
fn upload_metadata_keeps_folder_scope_and_exact_conditional_validator() {
    let fixture = Fixture::new(upload_responses(Some("&quot;new&amp;revision&quot;")));
    let source = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(source.path(), CONTENT).unwrap();
    let result = fixture.client().upload(
        "drive-1",
        FILE,
        source.path(),
        WriteCondition::Match("\"old&revision\"".into()),
    );
    let seen = fixture.finish();
    let entry = result.unwrap();
    assert_eq!(entry.path, FILE);
    assert_eq!(entry.size, CONTENT.len() as u64);
    assert_eq!(entry.etag, "\"new&revision\"");
    assert_eq!(seen.len(), 9);
    assert_eq!(seen[4].line, format!("PUT {FILE_WIRE} HTTP/1.1"));
    assert_eq!(seen[4].if_match.as_deref(), Some("\"old&revision\""));
    assert!(seen[4].if_none_match.is_none());
    assert_eq!(seen[4].body, CONTENT);
    assert_eq!(seen[8].line, format!("PROPFIND {FILE_WIRE} HTTP/1.1"));
}

#[test]
fn upload_with_truly_missing_followup_etag_fails_after_one_put_without_retry() {
    let fixture = Fixture::new(upload_responses(None));
    let source = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(source.path(), CONTENT).unwrap();
    let result = fixture.client().upload(
        "drive-1",
        FILE,
        source.path(),
        WriteCondition::Match("\"old&revision\"".into()),
    );
    let seen = fixture.finish();
    let error = result.unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.message, "DAV response omitted an entity tag");
    assert_eq!(
        seen.iter()
            .filter(|request| request.line.starts_with("PUT "))
            .count(),
        1
    );
    assert_eq!(seen[4].body, CONTENT);
    assert_eq!(std::fs::read(source.path()).unwrap(), CONTENT);
}

fn directory_without_validator(href: &str) -> String {
    dav(href, true, None, 0).replace(
        "</d:response>",
        "<d:propstat><d:prop><d:getetag/></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat></d:response>",
    )
}
fn unqualified_root() -> String {
    directory_without_validator("/dav/personal/")
}
fn unqualified_folder() -> String {
    directory_without_validator("/dav/personal/Courses%20&amp;%20CEUs/")
}

#[test]
fn directory_without_etag_can_list_and_create_but_does_not_invent_a_revision() {
    let file_xml = file(Some("&quot;file-v1&quot;"));
    let child = &file_xml
        [file_xml.find("<d:response>").unwrap()..file_xml.find("</d:multistatus>").unwrap()];
    let listing =
        unqualified_folder().replace("</d:multistatus>", &format!("{child}</d:multistatus>"));
    let fixture = Fixture::new(vec![
        graph(),
        prop(unqualified_root()),
        prop(unqualified_folder()),
        prop(listing),
    ]);
    let mut entries = Vec::new();
    fixture
        .client()
        .list("drive-1", FOLDER, &mut |entry| {
            entries.push(entry);
            Ok(())
        })
        .unwrap();
    let seen = fixture.finish();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, FILE);
    assert_eq!(entries[0].etag, "\"file-v1\"");
    assert_eq!(seen.len(), 4);
    let directory = parse(
        &unqualified_folder(),
        "https://cloud.invalid/dav/personal/Courses%20&%20CEUs/",
        FOLDER,
    )
    .unwrap();
    assert!(directory[0].directory);
    assert!(directory[0].etag.is_empty());

    let fixture = Fixture::new(vec![
        graph(),
        prop(unqualified_root()),
        prop(unqualified_folder()),
        ("404 Not Found", String::new()),
        ("201 Created", String::new()),
        graph(),
        prop(unqualified_root()),
        prop(unqualified_folder()),
        prop(file(Some("&quot;created-v1&quot;"))),
    ]);
    let source = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(source.path(), CONTENT).unwrap();
    let entry = fixture
        .client()
        .upload("drive-1", FILE, source.path(), WriteCondition::Absent)
        .unwrap();
    let seen = fixture.finish();
    assert_eq!(entry.etag, "\"created-v1\"");
    assert_eq!(seen.len(), 9);
    assert_eq!(seen[4].line, format!("PUT {FILE_WIRE} HTTP/1.1"));
    assert_eq!(seen[4].if_none_match.as_deref(), Some("*"));
    assert!(seen[4].if_match.is_none());
    assert_eq!(seen[4].body, CONTENT);
}

#[test]
fn directory_without_validator_refuses_delete_and_move_before_mutation_send() {
    let fixture = Fixture::new(vec![
        graph(),
        prop(unqualified_root()),
        prop(unqualified_folder()),
    ]);
    let error = fixture
        .client()
        .delete("drive-1", FOLDER, "\"previous-directory-v1\"")
        .unwrap_err();
    let seen = fixture.finish();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert!(
        seen.iter()
            .all(|request| !request.line.starts_with("DELETE "))
    );

    let fixture = Fixture::new(vec![
        graph(),
        graph(),
        prop(unqualified_root()),
        prop(unqualified_folder()),
    ]);
    let error = fixture
        .client()
        .rename("drive-1", FOLDER, "/renamed", "\"previous-directory-v1\"")
        .unwrap_err();
    let seen = fixture.finish();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert!(
        seen.iter()
            .all(|request| !request.line.starts_with("MOVE "))
    );

    let fixture = Fixture::new(vec![
        graph(),
        prop(unqualified_root()),
        prop(unqualified_folder()),
        prop(file(None)),
    ]);
    let source = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(source.path(), CONTENT).unwrap();
    let error = fixture
        .client()
        .upload(
            "drive-1",
            FILE,
            source.path(),
            WriteCondition::Match("\"old\"".into()),
        )
        .unwrap_err();
    let seen = fixture.finish();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert!(seen.iter().all(|request| !request.line.starts_with("PUT ")));

    let fixture = Fixture::new(vec![
        graph(),
        prop(unqualified_root()),
        prop(folder()),
        ("204 No Content", String::new()),
    ]);
    fixture
        .client()
        .delete("drive-1", FOLDER, "\"original-directory\"")
        .unwrap();
    let seen = fixture.finish();
    assert_eq!(seen[3].line, format!("DELETE {FOLDER_WIRE} HTTP/1.1"));
    assert_eq!(seen[3].if_match.as_deref(), Some("\"original-directory\""));

    // No metadata request, let alone a mutation, may use an absent/weak token.
    let fixture = Fixture::new(vec![]);
    let client = fixture.client();
    for expected in ["", "W/\"directory-v1\"", "*", "unquoted"] {
        assert_eq!(
            client.delete("drive-1", FOLDER, expected).unwrap_err().kind,
            ErrorKind::InvalidResponse
        );
        assert_eq!(
            client
                .rename("drive-1", FOLDER, "/renamed", expected)
                .unwrap_err()
                .kind,
            ErrorKind::InvalidResponse
        );
    }
    assert!(fixture.finish().is_empty());
}

fn metadata_lookup_followup_listing(etag: Option<&str>) -> String {
    let child = file(etag);
    let child =
        &child[child.find("<d:response>").unwrap()..child.find("</d:multistatus>").unwrap()];
    folder().replace("</d:multistatus>", &format!("{child}</d:multistatus>"))
}

fn metadata_lookup_followup_missing(href: &str) -> String {
    format!(
        "<d:multistatus xmlns:d=\"DAV:\"><d:response><d:href>{href}</d:href><d:status>HTTP/1.1 404 Not Found</d:status></d:response></d:multistatus>"
    )
}

#[test]
fn metadata_lookup_followup_reobserves_whole_point_and_directory_proofs() {
    for reason in [
        "DAV response omitted an entity tag",
        "DAV response omitted successful properties",
    ] {
        let error = invalid(reason);
        assert!(incomplete_metadata(&error));
        assert_eq!(
            transfer_metadata_boundary(error, "Ordinary point metadata").message,
            format!("Ordinary point metadata: {reason}")
        );
    }
    assert!(!incomplete_metadata(&CloudError::new(
        ErrorKind::Forbidden,
        "DAV response omitted successful properties"
    )));
    assert!(!incomplete_metadata(&invalid(
        "DAV response omitted an href"
    )));
    let fixture = Fixture::new(vec![
        graph(),
        prop(root()),
        prop(folder()),
        prop(file(None).replace("200 OK", "404 Not Found")),
        graph(),
        prop(root()),
        prop(folder()),
        prop(file(Some("&quot;ready&quot;"))),
    ]);
    let snapshot = fixture
        .client()
        .ordinary_stat_snapshot("drive-1", FILE)
        .unwrap();
    let seen = fixture.finish();
    assert_eq!(snapshot.target.unwrap().etag, "\"ready\"");
    assert_eq!(seen.len(), 8);
    assert_eq!(seen[0].line, seen[4].line);
    assert_eq!(seen[1].line, seen[5].line);
    assert_eq!(seen[2].line, seen[6].line);
    assert_eq!(seen[3].line, seen[7].line);
    assert!(
        seen.iter().all(
            |request| request.line.starts_with("GET ") || request.line.starts_with("PROPFIND ")
        )
    );

    let fixture = Fixture::new(vec![
        graph(),
        prop(root()),
        prop(folder()),
        prop(metadata_lookup_followup_listing(None)),
        graph(),
        prop(root()),
        prop(folder()),
        prop(metadata_lookup_followup_listing(Some("&quot;ready&quot;"))),
    ]);
    let snapshot = fixture
        .client()
        .directory_snapshot("drive-1", FOLDER, Some("stable-id"))
        .unwrap();
    let seen = fixture.finish();
    assert_eq!(snapshot.entries.len(), 1);
    assert_eq!(snapshot.entries[0].etag, "\"ready\"");
    assert_eq!(seen.len(), 8);
    for index in 0..4 {
        assert_eq!(seen[index].line, seen[index + 4].line);
    }
    assert!(
        seen.iter().all(
            |request| request.line.starts_with("GET ") || request.line.starts_with("PROPFIND ")
        )
    );
}

#[test]
fn metadata_lookup_followup_persistent_incomplete_keeps_inner_error_and_bound() {
    let mut responses = Vec::new();
    for _ in 0..50 {
        responses.extend([graph(), prop(root()), prop(folder()), prop(file(None))]);
    }
    let fixture = Fixture::new(responses);
    let started = Instant::now();
    let snapshot = fixture
        .client()
        .ordinary_stat_snapshot("drive-1", FILE)
        .unwrap();
    let elapsed = started.elapsed();
    let seen = fixture.finish();
    let error = snapshot.target.unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(
        error.message,
        "Ordinary point metadata: DAV response omitted an entity tag"
    );
    assert_eq!(snapshot.root.path, "/");
    assert!(elapsed >= Duration::from_secs(2));
    assert!(elapsed < Duration::from_secs(5));
    assert!(seen.len() >= 8 && seen.len() < 200);
    assert_eq!(seen.len() % 4, 0);
    assert!(
        seen.iter().all(
            |request| request.line.starts_with("GET ") || request.line.starts_with("PROPFIND ")
        )
    );
}

#[test]
fn metadata_lookup_followup_exact_inner_404_is_scoped_not_found() {
    let fixture = Fixture::new(vec![
        graph(),
        prop(root()),
        prop(folder()),
        prop(metadata_lookup_followup_missing(
            "/dav/personal/Courses%20&amp;%20CEUs/notes.txt",
        )),
    ]);
    let snapshot = fixture
        .client()
        .ordinary_stat_snapshot("drive-1", FILE)
        .unwrap();
    assert_eq!(snapshot.target.unwrap_err().kind, ErrorKind::NotFound);
    assert_eq!(snapshot.root.path, "/");
    assert_eq!(fixture.finish().len(), 4);
}

#[test]
fn metadata_lookup_followup_404_requires_complete_single_exact_response() {
    let good = metadata_lookup_followup_missing("/dav/personal/file");
    let cases = [
        good.replace("/dav/personal/file", "https://other.invalid/dav/personal/file"),
        good.replace("/dav/personal/file", "/dav/personal/file/child"),
        good.replace("/dav/personal/file", "/dav/personal/other"),
        good.replace("</d:response>", "<d:status>HTTP/1.1 200 OK</d:status></d:response>"),
        good.replace("</d:response>", "<d:href>/dav/personal/file</d:href></d:response>"),
        good.replace("</d:response>", "<d:propstat><d:prop><d:getetag>\"present\"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"),
        good.replace("</d:multistatus>", "<d:response><d:href>/dav/personal/file</d:href><d:status>HTTP/1.1 404 Not Found</d:status></d:response></d:multistatus>"),
        good.replace("</d:multistatus>", "<d:response/></d:multistatus>"),
        good.replace("HTTP/1.1 404 Not Found", "garbage 404 Not Found"),
        format!("{good}<malformed"),
    ];
    for xml in cases {
        let error = parse_multistatus_with_depth(
            xml.as_bytes(),
            &Url::parse("https://cloud.invalid/dav/personal/file").unwrap(),
            "/file",
            true,
            &mut |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidResponse);
    }
    // Failed properties alone and a missing validator are never absence.
    for (xml, retryable) in [
        (dav("/dav/personal/file", false, None, 3), true),
        (
            dav("/dav/personal/file", false, None, 3).replace("200 OK", "404 Not Found"),
            true,
        ),
        (
            dav("/dav/personal/file", false, None, 3).replace("200 OK", "403 Forbidden"),
            true,
        ),
    ] {
        let error = parse_multistatus_with_depth(
            xml.as_bytes(),
            &Url::parse("https://cloud.invalid/dav/personal/file").unwrap(),
            "/file",
            true,
            &mut |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidResponse);
        assert_eq!(incomplete_metadata(&error), retryable);
    }
}

#[test]
fn metadata_lookup_followup_depth_one_failure_never_returns_partial_snapshot() {
    let failure =
        metadata_lookup_followup_missing("/dav/personal/Courses%20&amp;%20CEUs/notes.txt");
    let response =
        &failure[failure.find("<d:response>").unwrap()..failure.find("</d:multistatus>").unwrap()];
    let listing = folder().replace("</d:multistatus>", &format!("{response}</d:multistatus>"));
    let fixture = Fixture::new(vec![graph(), prop(root()), prop(folder()), prop(listing)]);
    let result = fixture
        .client()
        .directory_snapshot("drive-1", FOLDER, Some("stable-id"));
    assert_eq!(result.err().unwrap().kind, ErrorKind::InvalidResponse);
    assert_eq!(fixture.finish().len(), 4);
    assert_eq!(
        parse(
            &metadata_lookup_followup_missing("/dav/personal/file"),
            "https://cloud.invalid/dav/personal/file",
            "/file"
        )
        .unwrap_err()
        .kind,
        ErrorKind::InvalidResponse
    );
}

#[test]
fn metadata_lookup_followup_cancellation_and_generation_prevent_reobservation() {
    let cancellation = OperationCancellation::new();
    let mut reads = 0;
    let result: Result<(), CloudError> = read_metadata_observation(
        Some(&cancellation),
        || {
            reads += 1;
            cancellation.cancel();
            Err(invalid("DAV response omitted an entity tag"))
        },
        |result| {
            Ok(result
                .as_ref()
                .is_err_and(|error| incomplete_metadata(error)))
        },
    );
    assert_eq!(result.unwrap_err().kind, ErrorKind::Offline);
    assert_eq!(reads, 1);

    let fixture = Fixture::new(vec![]);
    let client = fixture.client();
    let context = RangeReadContext {
        deadline: Instant::now() + Duration::from_secs(1),
        token_generation: client.token_generation(),
    };
    client.token_generation.fetch_add(1, Ordering::AcqRel);
    let _context = RangeContextGuard::enter(context);
    let error = client
        .ordinary_stat_snapshot("drive-1", FILE)
        .err()
        .unwrap();
    assert_eq!(error.kind, ErrorKind::Unauthorized);
    assert!(fixture.finish().is_empty());
}

#[test]
fn empty_directory_delete_keeps_fresh_view_and_conditional_confirmation() {
    for mode in ["empty", "nonempty", "malformed"] {
        let directory = folder()
            .replace("stable-id", "directory-id")
            .replace("folder-v1", "after-child-delete");
        let view = match mode {
            "nonempty" => metadata_lookup_followup_listing(Some("&quot;child-v1&quot;"))
                .replace("stable-id", "directory-id")
                .replace("folder-v1", "after-child-delete"),
            "malformed" => directory.replace("</d:multistatus>", "<d:response/></d:multistatus>"),
            _ => directory.clone(),
        };
        let mut responses = vec![graph(), prop(root()), prop(directory), prop(view)];
        if mode == "empty" {
            responses.extend([
                ("204 No Content", String::new()),
                prop(root()),
                ("404 Not Found", String::new()),
            ]);
        }
        let fixture = Fixture::new(responses);
        let preflights = Cell::new(0);
        let result = fixture
            .client()
            .delete_empty_directory_and_confirm_with_preflight(
                "drive-1",
                FOLDER,
                "directory-id",
                &|space, root| {
                    assert_eq!(space.id, "drive-1");
                    assert_eq!(root.id, "stable-id");
                    preflights.set(preflights.get() + 1);
                    Ok(())
                },
            );
        let seen = fixture.finish();
        assert_eq!(seen[2].line, format!("PROPFIND {FOLDER_WIRE} HTTP/1.1"));
        assert_eq!(seen[2].depth.as_deref(), Some("0"));
        assert_eq!(seen[3].line, format!("PROPFIND {FOLDER_WIRE} HTTP/1.1"));
        assert_eq!(seen[3].depth.as_deref(), Some("1"));
        if mode == "empty" {
            result.unwrap();
            assert_eq!(seen.len(), 7);
            assert_eq!(preflights.get(), 1);
            assert_eq!(seen[4].line, format!("DELETE {FOLDER_WIRE} HTTP/1.1"));
            assert_eq!(seen[4].if_match.as_deref(), Some("\"after-child-delete\""));
            assert!(seen[4].if_none_match.is_none());
            assert_eq!(seen[5].line, "PROPFIND /dav/personal/ HTTP/1.1");
            assert_eq!(seen[6].line, format!("PROPFIND {FOLDER_WIRE} HTTP/1.1"));
            assert_eq!(
                seen.iter()
                    .filter(|request| request.line.starts_with("DELETE "))
                    .count(),
                1
            );
        } else {
            let error = result.unwrap_err();
            assert_eq!(
                error.kind,
                if mode == "nonempty" {
                    ErrorKind::Conflict
                } else {
                    ErrorKind::InvalidResponse
                }
            );
            assert_eq!(seen.len(), 4);
            assert_eq!(preflights.get(), 0);
            assert!(
                seen.iter().all(|request| request.line.starts_with("GET ")
                    || request.line.starts_with("PROPFIND "))
            );
        }
    }
}

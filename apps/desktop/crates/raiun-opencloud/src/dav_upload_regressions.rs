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
    let fixture = Fixture::new(vec![
        graph(),
        prop(root()),
        ("404 Not Found", String::new()),
        prop(root()),
        ("201 Created", String::new()),
        graph(),
        prop(root()),
        prop(folder()),
    ]);
    let result = fixture.client().mkdir("drive-1", FOLDER);
    let seen = fixture.finish();
    assert_eq!(result.unwrap().path, FOLDER);
    assert_eq!(seen.len(), 8);
    assert_eq!(seen[4].line, format!("MKCOL {FOLDER_WIRE} HTTP/1.1"));
    assert_eq!(seen[7].line, format!("PROPFIND {FOLDER_WIRE} HTTP/1.1"));
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

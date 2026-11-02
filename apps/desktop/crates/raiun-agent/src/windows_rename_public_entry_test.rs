//! R58 ignored actual public-entry fixtures. No production caller/activation.
use super::*;
use cf::namespace_intent::*;
use cf::{EditRecoveryProvider, PreparedEditRecovery};
use raiun_cloudfiles_windows as cf;
use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
use raiun_core::backend::CloudBackend;
use std::{
    ffi::OsStr,
    fs,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
const SPACE: &str = "personal-drive";
const ROOT_ID: &str = "personal-root";
const SOURCE_ID: &str = "source-file";
const SOURCE_ETAG: &str = "\"source-v1\"";
const DESTINATION_ETAG: &str = "\"source-v2\"";
const CONTENT: [u8; 4096] = [0x5a; 4096];
const OWNER: &[u8] = b"raiun-r58-public-native-entry-owned-v1\n";
const OPT_IN: &str = "RAIUN_R58_NATIVE";
const FIXTURE: &str = "RAIUN_R58_FIXTURE_DIR";
const ROLE: &str = "RAIUN_R58_CHILD_ROLE";
const SOURCE_NAME: &str = "source.bin";
const DESTINATION_NAME: &str = "renamed.bin";
// Observe only the bounded response status line written by this fixture.
// Authorization and other request/response headers are never retained.
struct ObservedResponse {
    stream: TcpStream,
    records: Arc<Mutex<Vec<serde_json::Value>>>,
    diagnostics: Arc<TransportDiagnostics>,
    method: String,
    route: String,
    depth: String,
    first_line: Vec<u8>,
    status_line_complete: bool,
    write_error: Option<(String, String, Option<i32>)>,
}
impl ObservedResponse {
    fn record(&mut self) {
        let status = self
            .status_line_complete
            .then(|| {
                String::from_utf8_lossy(&self.first_line)
                    .split_whitespace()
                    .nth(1)
                    .and_then(|value| value.parse::<u16>().ok())
            })
            .flatten();
        if let Ok(mut records) = self.records.lock()
            && records.len() < 512
        {
            records.push(serde_json::json!({
                "method": self.method, "route": self.route,
                "depth": self.depth,
                "response_status_written": status,
                "response_write_succeeded": self.write_error.is_none(),
                "response_write_error": self.write_error,
            }));
        }
    }
}
impl Write for ObservedResponse {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let count = match self.stream.write(buffer) {
            Ok(count) => count,
            Err(error) => {
                self.write_error = Some((
                    "response_write".to_owned(),
                    format!("{:?}", error.kind()),
                    error.raw_os_error(),
                ));
                self.diagnostics.record("response_write", &error, true);
                return Err(error);
            }
        };
        if count == 0 && !buffer.is_empty() {
            let error = io::Error::new(
                io::ErrorKind::WriteZero,
                "fixture response write returned zero",
            );
            self.write_error = Some((
                "response_write".to_owned(),
                format!("{:?}", error.kind()),
                error.raw_os_error(),
            ));
            self.diagnostics.record("response_write", &error, true);
        }
        if !self.status_line_complete && self.first_line.len() < 128 {
            for &byte in &buffer[..count] {
                self.first_line.push(byte);
                if self.first_line.ends_with(b"\r\n") {
                    self.status_line_complete = true;
                    break;
                }
                if self.first_line.len() >= 128 {
                    break;
                }
            }
        }
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if let Err(error) = self.stream.flush() {
            self.write_error = Some((
                "response_flush".to_owned(),
                format!("{:?}", error.kind()),
                error.raw_os_error(),
            ));
            self.diagnostics.record("response_flush", &error, true);
            return Err(error);
        }
        Ok(())
    }
}
impl Drop for ObservedResponse {
    fn drop(&mut self) {
        self.record();
    }
}

struct TransportDiagnostics {
    accepted_sockets: AtomicUsize,
    accepted_blocking_normalized: AtomicUsize,
    transport_error_count: AtomicUsize,
    response_write_errors: AtomicUsize,
    transport_errors: Mutex<Vec<serde_json::Value>>,
}

impl TransportDiagnostics {
    fn new() -> Self {
        Self {
            accepted_sockets: AtomicUsize::new(0),
            accepted_blocking_normalized: AtomicUsize::new(0),
            transport_error_count: AtomicUsize::new(0),
            response_write_errors: AtomicUsize::new(0),
            transport_errors: Mutex::new(Vec::new()),
        }
    }

    fn record(&self, stage: &str, error: &io::Error, response_write: bool) {
        self.transport_error_count.fetch_add(1, Ordering::AcqRel);
        if response_write {
            self.response_write_errors.fetch_add(1, Ordering::AcqRel);
        }
        if let Ok(mut errors) = self.transport_errors.lock()
            && errors.len() < 512
        {
            errors.push(serde_json::json!({
                "stage": stage,
                "kind": format!("{:?}", error.kind()),
                "raw_os_error": error.raw_os_error(),
            }));
        }
    }

    fn record_stage_error(&self, stage: &str, error: io::Error) {
        self.record(stage, &error, false);
    }
}

struct Loopback {
    origin: String,
    stopped: Arc<AtomicBool>,
    moved: Arc<AtomicBool>,
    move_count: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
    conditional_gets: Arc<Mutex<Vec<(String, String, bool)>>>,
    range_gets: Arc<AtomicUsize>,
    rejected_requests: Arc<AtomicUsize>,

    wire_records: Arc<Mutex<Vec<serde_json::Value>>>,
    transport_diagnostics: Arc<TransportDiagnostics>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Loopback {
    fn start(witness: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback DAV fixture");
        listener
            .set_nonblocking(true)
            .expect("nonblocking fixture listener");
        let address = listener.local_addr().expect("fixture listener address");
        let stopped = Arc::new(AtomicBool::new(false));
        let moved = Arc::new(AtomicBool::new(false));
        let move_count = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let conditional_gets = Arc::new(Mutex::new(Vec::new()));
        let range_gets = Arc::new(AtomicUsize::new(0));
        let rejected_requests = Arc::new(AtomicUsize::new(0));
        let wire_records = Arc::new(Mutex::new(Vec::new()));
        let wire = Arc::clone(&wire_records);
        let transport_diagnostics = Arc::new(TransportDiagnostics::new());
        let transport = Arc::clone(&transport_diagnostics);
        let (stop, renamed, moves, log, gets, ranges, rejected) = (
            Arc::clone(&stopped),
            Arc::clone(&moved),
            Arc::clone(&move_count),
            Arc::clone(&requests),
            Arc::clone(&conditional_gets),
            Arc::clone(&range_gets),
            Arc::clone(&rejected_requests),
        );
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(90);
            while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => {
                        transport.record_stage_error("listener_accept", error);
                        break;
                    }
                };
                transport.accepted_sockets.fetch_add(1, Ordering::AcqRel);
                if let Err(error) = stream.set_nonblocking(false) {
                    transport.record_stage_error("accepted_socket_set_blocking", error);
                    rejected.fetch_add(1, Ordering::AcqRel);
                    continue;
                }
                transport
                    .accepted_blocking_normalized
                    .fetch_add(1, Ordering::AcqRel);
                let timeout = Duration::from_secs(8);
                if let Err(error) = stream.set_read_timeout(Some(timeout)) {
                    transport.record_stage_error("accepted_socket_set_read_timeout", error);
                    rejected.fetch_add(1, Ordering::AcqRel);
                    continue;
                }
                if let Err(error) = stream.set_write_timeout(Some(timeout)) {
                    transport.record_stage_error("accepted_socket_set_write_timeout", error);
                    rejected.fetch_add(1, Ordering::AcqRel);
                    continue;
                }
                let request = match read_request(&mut stream) {
                    Ok(request) => request,
                    Err(failure) => {
                        transport.record_stage_error(failure.stage, failure.error);
                        rejected.fetch_add(1, Ordering::AcqRel);
                        continue;
                    }
                };
                let line = request.lines().next().unwrap_or_default().to_owned();
                if let Ok(mut log) = log.lock() {
                    if log.len() < 512 {
                        log.push(line.clone());
                    }
                }
                let method = line.split_whitespace().next().unwrap_or_default();
                let route = line.split_whitespace().nth(1).unwrap_or_default();
                let headers = header_map(&request);
                let depth = match headers.get("depth").map(String::as_str) {
                    Some("0") => "0",
                    Some("1") => "1",
                    None => "absent",
                    _ => "other",
                };
                let mut stream = ObservedResponse {
                    stream,
                    records: Arc::clone(&wire),
                    diagnostics: Arc::clone(&transport),
                    method: method.to_owned(),
                    route: route.chars().take(256).collect(),
                    depth: depth.to_owned(),
                    first_line: Vec::with_capacity(128),
                    status_line_complete: false,
                    write_error: None,
                };
                match method {
                    "GET" if route.starts_with("/graph/") => {
                        let body = format!(
                            r#"{{"value":[{{"id":"{SPACE}","name":"Personal","driveType":"personal","root":{{"id":"{ROOT_ID}","webDavUrl":"http://{address}/dav/personal/"}}}}]}}"#
                        );
                        respond(&mut stream, "200 OK", "application/json", &body, &[]);
                    }
                    "PROPFIND" if witness && route == "/dav/personal/capture.bin" => {
                        let body =
                            file_xml(route, "\"capture-v1\"").replace(SOURCE_ID, "capture-file");
                        respond(
                            &mut stream,
                            "207 Multi-Status",
                            "application/xml",
                            &body,
                            &[],
                        );
                    }
                    "GET" if witness && route == "/dav/personal/capture.bin" => {
                        if headers.get("if-match").map(String::as_str) != Some("\"capture-v1\"") {
                            rejected.fetch_add(1, Ordering::AcqRel);
                            respond(
                                &mut stream,
                                "412 Precondition Failed",
                                "text/plain",
                                "",
                                &[],
                            );
                            continue;
                        }
                        let (start, body) = ranged_body(&headers).unwrap();
                        if headers.contains_key("range") {
                            respond_bytes(
                                &mut stream,
                                "206 Partial Content",
                                "application/octet-stream",
                                "\"capture-v1\"",
                                &[(
                                    "Content-Range".into(),
                                    format!(
                                        "bytes {}-{}/4096",
                                        start,
                                        start + body.len() as u64 - 1
                                    ),
                                )],
                                &body,
                            );
                        } else {
                            respond_bytes(
                                &mut stream,
                                "200 OK",
                                "application/octet-stream",
                                "\"capture-v1\"",
                                &[],
                                &body,
                            );
                        }
                    }
                    "PROPFIND" if route.trim_end_matches('/') == "/dav/personal" => {
                        let include_child = headers.get("depth").map(String::as_str) != Some("0");
                        let mut body = root_xml(
                            route.trim_end_matches('/'),
                            renamed.load(Ordering::Acquire),
                            include_child,
                        );
                        if witness && include_child {
                            let extra = file_xml("/dav/personal/capture.bin", "\"capture-v1\"")
                                .replace(SOURCE_ID, "capture-file");
                            let start = extra.find("<d:response>").unwrap();
                            let end = extra.find("</d:multistatus>").unwrap();
                            body = body.replace(
                                "</d:multistatus>",
                                &format!("{}</d:multistatus>", &extra[start..end]),
                            );
                        }
                        respond(
                            &mut stream,
                            "207 Multi-Status",
                            "application/xml",
                            &body,
                            &[],
                        );
                    }
                    "PROPFIND" if route.trim_end_matches('/') == "/dav/personal/source.bin" => {
                        if renamed.load(Ordering::Acquire) {
                            respond(&mut stream, "404 Not Found", "application/xml", "", &[]);
                        } else {
                            let body = file_xml("/dav/personal/source.bin", SOURCE_ETAG);
                            respond(
                                &mut stream,
                                "207 Multi-Status",
                                "application/xml",
                                &body,
                                &[],
                            );
                        }
                    }
                    "PROPFIND" if route.trim_end_matches('/') == "/dav/personal/renamed.bin" => {
                        if renamed.load(Ordering::Acquire) {
                            let body = file_xml("/dav/personal/renamed.bin", DESTINATION_ETAG);
                            respond(
                                &mut stream,
                                "207 Multi-Status",
                                "application/xml",
                                &body,
                                &[],
                            );
                        } else {
                            respond(&mut stream, "404 Not Found", "application/xml", "", &[]);
                        }
                    }
                    "GET"
                        if route.trim_end_matches('/') == "/dav/personal/source.bin"
                            || route.trim_end_matches('/') == "/dav/personal/renamed.bin" =>
                    {
                        let is_source = route.trim_end_matches('/') == "/dav/personal/source.bin";
                        let visible = renamed.load(Ordering::Acquire);
                        let etag = if is_source {
                            SOURCE_ETAG
                        } else {
                            DESTINATION_ETAG
                        };
                        let if_match = headers.get("if-match").cloned().unwrap_or_default();
                        if (is_source && visible) || (!is_source && !visible) || if_match != etag {
                            respond(
                                &mut stream,
                                "412 Precondition Failed",
                                "text/plain",
                                "",
                                &[],
                            );
                            rejected.fetch_add(1, Ordering::AcqRel);
                            continue;
                        }
                        if headers.contains_key("range") {
                            ranges.fetch_add(1, Ordering::AcqRel);
                        } else if let Ok(mut gets) = gets.lock() {
                            if gets.len() < 512 {
                                gets.push((
                                    route.trim_end_matches('/').to_owned(),
                                    if_match,
                                    visible,
                                ));
                            }
                        }
                        let Some((start, body_bytes)) = ranged_body(&headers) else {
                            respond(
                                &mut stream,
                                "416 Range Not Satisfiable",
                                "text/plain",
                                "",
                                &[],
                            );
                            continue;
                        };
                        let (status, extra) = if headers.contains_key("range") {
                            (
                                "206 Partial Content",
                                vec![
                                    (
                                        "Content-Range".to_owned(),
                                        format!(
                                            "bytes {}-{}/{}",
                                            start,
                                            start + body_bytes.len() as u64 - 1,
                                            CONTENT.len()
                                        ),
                                    ),
                                    ("Accept-Ranges".to_owned(), "bytes".to_owned()),
                                ],
                            )
                        } else {
                            (
                                "200 OK",
                                vec![("Accept-Ranges".to_owned(), "bytes".to_owned())],
                            )
                        };
                        respond_bytes(
                            &mut stream,
                            status,
                            "application/octet-stream",
                            etag,
                            &extra,
                            &body_bytes,
                        );
                    }
                    "MOVE" if route.trim_end_matches('/') == "/dav/personal/source.bin" => {
                        moves.fetch_add(1, Ordering::AcqRel);
                        let destination = headers.get("destination").cloned().unwrap_or_default();
                        let overwrite = headers
                            .get("overwrite")
                            .map(String::as_str)
                            .unwrap_or_default();
                        let if_match = headers
                            .get("if-match")
                            .map(String::as_str)
                            .unwrap_or_default();
                        if renamed.load(Ordering::Acquire)
                            || destination != format!("http://{address}/dav/personal/renamed.bin")
                            || overwrite != "F"
                            || if_match != SOURCE_ETAG
                        {
                            rejected.fetch_add(1, Ordering::AcqRel);
                            respond(
                                &mut stream,
                                "412 Precondition Failed",
                                "text/plain",
                                "",
                                &[],
                            );
                        } else {
                            renamed.store(true, Ordering::Release);
                            respond(&mut stream, "201 Created", "text/plain", "", &[]);
                        }
                    }
                    _ => {
                        rejected.fetch_add(1, Ordering::AcqRel);
                        respond(
                            &mut stream,
                            "500 Internal Server Error",
                            "text/plain",
                            "",
                            &[],
                        );
                    }
                }
            }
        });
        Self {
            origin: format!("http://{address}"),
            stopped,
            moved,
            move_count,
            requests,
            conditional_gets,
            range_gets,
            rejected_requests,

            wire_records,
            transport_diagnostics,
            worker: Some(worker),
        }
    }

    fn diagnostic_snapshot(&self) -> serde_json::Value {
        let records = self.wire_records.lock().map(|records| records.clone()).ok();
        let transport_errors = self
            .transport_diagnostics
            .transport_errors
            .lock()
            .map(|errors| errors.clone())
            .ok();
        serde_json::json!({
            "record_limit": 512,
            "at_record_limit": records.as_ref().is_some_and(|records| records.len() == 512),
            "wire_responses": records,
            "accepted_socket_count": self.transport_diagnostics.accepted_sockets.load(Ordering::Acquire),
            "accepted_blocking_normalization_count": self.transport_diagnostics.accepted_blocking_normalized.load(Ordering::Acquire),
            "transport_error_limit": 512,
            "transport_error_count": self.transport_diagnostics.transport_error_count.load(Ordering::Acquire),
            "transport_errors": transport_errors,
            "response_write_error_count": self.transport_diagnostics.response_write_errors.load(Ordering::Acquire),
            "move_count": self.move_count.load(Ordering::Acquire),
            "range_gets": self.range_gets.load(Ordering::Acquire),
            "full_get_count": self.conditional_gets.lock().map(|gets| gets.len()).ok(),
            "rejected_requests": self.rejected_requests.load(Ordering::Acquire),
            "snapshot_is_transactional": false
        })
    }
    fn finish(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("loopback fixture worker");
        }
    }
}
impl Drop for Loopback {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct RequestReadFailure {
    stage: &'static str,
    error: io::Error,
}

fn request_failure(stage: &'static str, error: io::Error) -> RequestReadFailure {
    RequestReadFailure { stage, error }
}

fn deadline_remaining(
    deadline: Instant,
    stage: &'static str,
) -> Result<Duration, RequestReadFailure> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| {
            request_failure(
                stage,
                io::Error::new(io::ErrorKind::TimedOut, "loopback request deadline expired"),
            )
        })
}

fn read_request(stream: &mut TcpStream) -> Result<String, RequestReadFailure> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while bytes.len() < 32 * 1024 && !bytes.ends_with(b"\r\n\r\n") {
        let remaining = deadline_remaining(deadline, "request_header_deadline")?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|error| request_failure("request_header_set_timeout", error))?;
        stream
            .read_exact(&mut byte)
            .map_err(|error| request_failure("request_header_read", error))?;
        bytes.push(byte[0]);
    }
    if !bytes.ends_with(b"\r\n\r\n") {
        return Err(request_failure(
            "request_header_size_limit",
            io::Error::new(io::ErrorKind::InvalidData, "request header exceeds 32 KiB"),
        ));
    }
    let headers = String::from_utf8_lossy(&bytes).into_owned();
    let body_len = headers
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    if body_len > 64 * 1024 {
        return Err(request_failure(
            "request_body_size_limit",
            io::Error::new(io::ErrorKind::InvalidData, "request body exceeds 64 KiB"),
        ));
    }
    let mut body = vec![0_u8; body_len];
    let mut received = 0;
    while received < body.len() {
        let remaining = deadline_remaining(deadline, "request_body_deadline")?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|error| request_failure("request_body_set_timeout", error))?;
        let count = stream
            .read(&mut body[received..])
            .map_err(|error| request_failure("request_body_read", error))?;
        if count == 0 {
            return Err(request_failure(
                "request_body_eof",
                io::Error::new(io::ErrorKind::UnexpectedEof, "request body ended early"),
            ));
        }
        received += count;
    }
    Ok(headers)
}
fn header_map(request: &str) -> std::collections::HashMap<String, String> {
    request
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect()
}
fn respond(
    stream: &mut impl Write,
    status: &str,
    content_type: &str,
    body: &str,
    extra: &[(String, String)],
) {
    let mut headers = format!("Content-Type: {content_type}\r\n");
    for (name, value) in extra {
        headers.push_str(name);
        headers.push_str(": ");
        headers.push_str(value);
        headers.push_str("\r\n");
    }
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
        body.len()
    );
    let _ = stream.write_all(body.as_bytes());
}
fn respond_bytes(
    stream: &mut impl Write,
    status: &str,
    content_type: &str,
    etag: &str,
    extra: &[(String, String)],
    body: &[u8],
) {
    let mut headers = format!("Content-Type: {content_type}\r\nETag: {etag}\r\n");
    for (name, value) in extra {
        headers.push_str(name);
        headers.push_str(": ");
        headers.push_str(value);
        headers.push_str("\r\n");
    }
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
        body.len()
    );
    let _ = stream.write_all(body);
}
fn ranged_body(headers: &std::collections::HashMap<String, String>) -> Option<(u64, Vec<u8>)> {
    if let Some(range) = headers.get("range") {
        let value = range.strip_prefix("bytes=")?;
        let (start, end) = value.split_once('-')?;
        let start = start.parse::<usize>().ok()?;
        let end = if end.is_empty() {
            CONTENT.len() - 1
        } else {
            end.parse::<usize>().ok()?
        };
        if start >= CONTENT.len() || end < start {
            return None;
        }
        let end = end.min(CONTENT.len() - 1);
        Some((start as u64, CONTENT[start..=end].to_vec()))
    } else {
        Some((0, CONTENT.to_vec()))
    }
}
fn file_xml(path: &str, etag: &str) -> String {
    format!(
        r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>{path}</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>{}</d:getcontentlength><d:getetag>{etag}</d:getetag><d:getlastmodified>Wed, 21 Oct 2015 07:28:00 GMT</d:getlastmodified><oc:fileid>{SOURCE_ID}</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#,
        CONTENT.len()
    )
}
fn root_xml(path: &str, renamed: bool, include_child: bool) -> String {
    let file_path = if renamed {
        "/dav/personal/renamed.bin"
    } else {
        "/dav/personal/source.bin"
    };
    let etag = if renamed {
        DESTINATION_ETAG
    } else {
        SOURCE_ETAG
    };
    let child = if include_child {
        format!(
            r#"<d:response><d:href>{file_path}</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>{}</d:getcontentlength><d:getetag>{etag}</d:getetag><d:getlastmodified>Wed, 21 Oct 2015 07:28:00 GMT</d:getlastmodified><oc:fileid>{SOURCE_ID}</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"#,
            CONTENT.len()
        )
    } else {
        String::new()
    };
    format!(
        r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>{path}/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>"root-v1"</d:getetag><d:getlastmodified>Wed, 21 Oct 2015 07:28:00 GMT</d:getlastmodified><oc:fileid>{ROOT_ID}</oc:fileid><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>{child}</d:multistatus>"#
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Direct,
    Candidate,
    Pending,
    Inflight,
    Late,
}
impl Case {
    fn selector(self) -> &'static str {
        match self {
            Self::Direct => {
                "agent_windows::windows_rename_public_entry_test::r58_direct_public_entry_completes_one_fresh_personal_rename"
            }
            Self::Candidate => {
                "agent_windows::windows_rename_public_entry_test::r58_candidate_public_entry_completes_one_fresh_personal_rename"
            }
            Self::Pending => {
                "agent_windows::windows_rename_public_entry_test::r58_pending_content_defers_without_namespace_publication"
            }
            Self::Inflight => {
                "agent_windows::windows_rename_public_entry_test::r58_inflight_native_close_defers_and_retains_capture"
            }
            Self::Late => {
                "agent_windows::windows_rename_public_entry_test::r58_late_native_dirty_close_refuses_completion_and_retains_factual_prefix"
            }
        }
    }
}
fn guarded_fixture(case: Case) -> PathBuf {
    assert_eq!(std::env::var(OPT_IN).as_deref(), Ok("fresh-owned-state"));
    let args = std::env::args().collect::<Vec<_>>();
    assert!(
        args.iter().any(|a| a == "--ignored")
            && args.iter().any(|a| a == "--exact")
            && args.iter().any(|a| a == case.selector())
            && args.iter().any(|a| a == "--test-threads=1")
    );
    let path = PathBuf::from(std::env::var_os(FIXTURE).expect("explicit fresh wrapper path"));
    assert!(path.is_absolute());
    let metadata = fs::symlink_metadata(&path).unwrap();
    assert!(metadata.is_dir() && metadata.file_attributes() & 0x400 == 0);
    let marker = path.join("OWNER.txt");
    let metadata = fs::symlink_metadata(&marker).unwrap();
    assert!(
        metadata.is_file()
            && metadata.file_attributes() & 0x400 == 0
            && metadata.len() == OWNER.len() as u64
    );
    assert_eq!(fs::read(marker).unwrap(), OWNER);
    assert!(std::env::var_os("RAIUN_HEADLESS_CONFIG").is_none());
    assert!(std::env::var_os("RAIUN_STATE_DIR").is_none());
    path
}
fn wait_fact(mut fact: impl FnMut() -> bool, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(12);
    while !fact() {
        assert!(
            Instant::now() < deadline,
            "bounded factual barrier: {label}"
        );
        thread::sleep(Duration::from_millis(5));
    }
}
struct FixtureChild(std::process::Child);
impl Drop for FixtureChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn edit_child(
    case: Case,
    fixture: &Path,
    name: &str,
    root: cf::ConfiguredRootIdentity,
) -> FixtureChild {
    assert!(matches!(name, SOURCE_NAME | "capture.bin"));
    FixtureChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                case.selector(),
                "--nocapture",
                "--test-threads=1",
            ])
            .env(ROLE, name)
            .env("RAIUN_R58_ROOT_VOLUME", root.volume_serial.to_string())
            .env("RAIUN_R58_ROOT_FILE", root.file_index.to_string())
            .env(FIXTURE, fixture)
            .stdin(Stdio::null())
            .stdout(Stdio::from(child_log(fixture, name, "stdout")))
            .stderr(Stdio::from(child_log(fixture, name, "stderr")))
            .spawn()
            .unwrap(),
    )
}
fn join_child(child: &mut FixtureChild) {
    let mut result = None;
    wait_fact(
        || {
            result = child.0.try_wait().unwrap();
            result.is_some()
        },
        "owned child terminal exit",
    );
    assert!(result.unwrap().success());
}
fn child_role(fixture: &Path) -> bool {
    let Some(role) = std::env::var_os(ROLE) else {
        return false;
    };
    let name = role.to_str().unwrap();
    assert!(matches!(name, SOURCE_NAME | "capture.bin"));
    let root = fixture.join("cloud-root");
    let original = cf::ConfiguredRootIdentity {
        volume_serial: std::env::var("RAIUN_R58_ROOT_VOLUME")
            .unwrap()
            .parse()
            .unwrap(),
        file_index: std::env::var("RAIUN_R58_ROOT_FILE")
            .unwrap()
            .parse()
            .unwrap(),
    };
    assert_ne!(original.file_index, 0);
    let _original_root = cf::pin_registered_configured_root(&root, original).unwrap();
    let path = root.join("Personal").join(name);
    let mut file = fs::OpenOptions::new().write(true).open(path).unwrap();
    let edited = CONTENT.map(|b| b ^ 0x11);
    file.write_all(&edited).unwrap();
    file.sync_all().unwrap();
    drop(file);
    true
}
fn external_populate(personal: &Path, fixture: &Path) {
    let powershell = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let script = "$ErrorActionPreference='Stop'; $e=[System.IO.Directory]::EnumerateFileSystemEntries($env:RAIUN_R58_PERSONAL).GetEnumerator(); try {$n=0;$s=$false;while($e.MoveNext()){$n++;if($n -gt 2){exit 25};if([IO.Path]::GetFileName($e.Current) -ceq 'source.bin'){$s=$true}};if(-not $s){exit 24};exit 0}finally{$e.Dispose()}";
    let mut child = FixtureChild(
        Command::new(powershell)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ])
            .env("RAIUN_R58_PERSONAL", personal)
            .stdin(Stdio::null())
            .stdout(Stdio::from(child_log(fixture, "materialize", "stdout")))
            .stderr(Stdio::from(child_log(fixture, "materialize", "stderr")))
            .spawn()
            .unwrap(),
    );
    join_child(&mut child);
}
struct RetainedFactory {
    scope: cf::ProviderScope,
    root: cf::ConfiguredRootIdentity,
    prepared: Arc<dyn PreparedEditRecovery>,
}
impl EditRecoveryProvider for RetainedFactory {
    fn prepare(
        &self,
        scope: &cf::ProviderScope,
        root: cf::ConfiguredRootIdentity,
    ) -> Result<Arc<dyn PreparedEditRecovery>, cf::BackendError> {
        if *scope != self.scope || root != self.root {
            return Err(cf::BackendError::Unavailable);
        }
        Ok(Arc::clone(&self.prepared))
    }
}
fn policy() -> cf::streamed_store::StorePolicy {
    cf::streamed_store::StorePolicy {
        max_content_bytes: 16 * 1024 * 1024,
        max_state_bytes: 128 * 1024 * 1024,
        max_entries: 4096,
        max_metadata_bytes_per_scan: 8 * 1024 * 1024,
    }
}
fn wait_callbacks_idle(connection: &cf::ConfiguredRootConnection) {
    wait_fact(
        || connection.rename_public_entry_fixture_callback_counts() == Some((0, 0, 0)),
        "actual callback activity settled (not rename authority)",
    );
}
fn assert_capture_transition(
    connection: &cf::ConfiguredRootConnection,
    before: (usize, usize, usize, usize, usize, i32, usize, usize),
) {
    wait_fact(
        || {
            let after = connection.close_observation_for_integration();
            after.0 == before.0 + 1 && after.7 == before.7 + 1
        },
        "actual dirty capture and journal counters advanced",
    );
    wait_callbacks_idle(connection);
    assert_eq!(
        connection.close_observation_for_integration().1,
        before.1,
        "no unknown close is used to simulate dirty-epoch refusal"
    );
}
fn child_log(fixture: &Path, name: &str, kind: &str) -> fs::File {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(fixture.join(format!("{name}.{kind}.log")))
        .unwrap()
}
fn assert_retained_capture(
    state: Arc<PrivateDirectory>,
    scope: &cf::EditJournalScope,
    protector: &cf::DpapiEditRecordProtector,
    name: &str,
) {
    // Independent read-only authentication only; never used as rename store or dispatch authority.
    let snapshots = cf::streamed_store::SnapshotStore::open_existing(
        state,
        scope.clone(),
        Arc::new(protector.clone()),
        policy(),
    )
    .unwrap();
    let manifests = snapshots.discover_metadata().unwrap();
    assert_eq!(manifests.len(), 1);
    let manifest = &manifests[0];
    assert_eq!(manifest.binding().relative_path, name);
    assert_eq!(manifest.binding().content_len, 4096);
    let pinned = snapshots
        .open_verified(&manifest.binding().record_id, &mut || false)
        .unwrap();
    let mut reader = pinned.into_reader(Arc::new(|| false)).unwrap();
    let mut body = Vec::new();
    reader.read_to_end(&mut body).unwrap();
    assert_eq!(body, CONTENT.map(|b| b ^ 0x11));
}
fn run(case: Case) {
    let fixture = guarded_fixture(case);
    if child_role(&fixture) {
        return;
    }
    assert!(fs::read_dir(&fixture).unwrap().all(|e| matches!(
        e.unwrap().file_name().to_str(),
        Some("OWNER.txt" | "runner.json" | "stdout.log" | "stderr.log")
    )));
    let cloud_root = fixture.join("cloud-root");
    fs::create_dir(&cloud_root).unwrap();
    let barrier_dir = fixture.join("capture-barrier");
    fs::create_dir(&barrier_dir).unwrap();
    assert_eq!(
        std::env::var_os("RAIUN_SYNTHETIC_CFAPI_PATH_GUARD_DIR").as_deref(),
        Some(barrier_dir.as_os_str())
    );
    let mut server = Loopback::start(case == Case::Late);
    let client = Arc::new(
        OpenCloudClient::new_with_proxy(
            &server.origin,
            "synthetic-access-token".into(),
            &raiun_opencloud::ProxyConfig::Direct,
        )
        .unwrap(),
    );
    let origin = client.server_origin().unwrap();
    let account = personal_account_identity(&origin, SPACE);
    let provider_scope =
        cf::ProviderScope::new(&client, "default".into(), account.clone(), origin.clone()).unwrap();
    let lease = cf::pin_configured_root(&cloud_root).unwrap();
    let root = lease.identity();
    let wrapper = PinnedDirectory::open(&fixture).unwrap();
    let state = Arc::new(
        PrivateDirectory::create_or_open_under(&wrapper, OsStr::new("private-state")).unwrap(),
    );
    let protector =
        cf::DpapiEditRecordProtector::from_existing_private_directory(Arc::clone(&state)).unwrap();
    let recovery = Arc::new(
        cf::DurableEditRecoveryProvider::new(
            state.path().to_path_buf(),
            provider_scope.clone(),
            root,
            protector.clone(),
        )
        .with_streamed_recovery(policy())
        .unwrap()
        .with_modern_namespace_file_rename(policy())
        .unwrap(),
    );
    let backend = Arc::new(
        cf::OpenCloudPlaceholderBackend::new_with_identity_catalog(
            Arc::clone(&client),
            provider_scope.clone(),
            root,
            recovery.identity_catalog(),
        )
        .unwrap(),
    );
    let composite = backend.register_composite_root_for(SPACE, ROOT_ID).unwrap();
    let prepared = recovery.prepare(&provider_scope, root).unwrap();
    let factory = Arc::new(RetainedFactory {
        scope: provider_scope.clone(),
        root,
        prepared: Arc::clone(&prepared),
    });
    // The real custody guard requires canonical account metadata and a
    // profile-bound protected store. Keep both inside this fresh wrapper;
    // never consult the current user's saved sessions or repair old history.
    let sessions = Arc::new(
        PrivateDirectory::create_or_open_under(&wrapper, OsStr::new("private-sessions")).unwrap(),
    );
    let session_store = DpapiStore {
        store: raiun_control_windows::DpapiSessionStore::from_existing_private_directory(sessions)
            .unwrap(),
        profile_scope: "default".into(),
    };
    let agent = Arc::new(
        WindowsAgent::new_for_profile_with_services(
            "default",
            session_store,
            None,
            Arc::new(raiun_vault::session::VaultSessionCoordinator::new()),
        )
        .unwrap(),
    );
    agent.attach_existing_file_save_owner().unwrap();
    let generation = 1;
    agent.generation.store(generation, Ordering::Release);
    agent
        .provider
        .authorized_generation
        .store(generation, Ordering::Release);
    let session = auth::Session {
        app_token_username: None,
        server: origin.clone(),
        client_id: "r58-synthetic-client".into(),
        access_token: "synthetic-access-token".into(),
        refresh_token: None,
        expires_at: unix_time_now() + 3600,
        token_endpoint: format!("{origin}/token"),
        expected_issuer: None,
        last_refresh_at: None,
        proxy: raiun_opencloud::ProxyConfig::Direct,
    };
    let binding = ActiveProviderBinding {
        generation,
        path: cloud_root.clone(),
        identity: root,
        personal_space_id: SPACE.into(),
        personal_root_resource_id: ROOT_ID.into(),
    };
    let configuration = RootConfiguration {
        profile_scope: agent.profile_scope.clone(),
        server: session.server.clone(),
        client_id: session.client_id.clone(),
        issuer: None,
        path: cloud_root.to_string_lossy().into_owned(),
        volume_serial: root.volume_serial,
        file_index: root.file_index,
        registration_ownership: Some(RegistrationOwnership {
            state: "registered".into(),
            account_id: account.clone(),
            personal_drive_id: SPACE.into(),
            personal_root_resource_id: Some(ROOT_ID.into()),
            volume_serial: root.volume_serial,
            file_index: root.file_index,
        }),
        valid: true,
    };
    {
        let mut s = agent.state.lock().unwrap();
        s.session = Some(session);
        s.root_configuration = Some(configuration);
        s.online_authenticated = true;
        s.active_generation = generation;
    }
    let mut save_owner = agent
        .provider
        .prepare_existing_file_save_worker(&binding, &agent.state, &agent.session_store, false)
        .unwrap()
        .expect("actual existing save owner");
    let publisher = agent
        .provider
        .fresh_close_source
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .publisher(generation)
        .unwrap();
    let custody_account = raiun_engine::folder_pairs::AccountScope::new(
        "default".into(),
        url::Url::parse(&origin).unwrap().to_string(),
        "r58-synthetic-client".into(),
        None,
        account.clone(),
    )
    .unwrap();
    let custody_account = serde_json::to_vec(&custody_account).unwrap();
    let custody = windows_vault_custody::WindowsVaultCustody::prepare_with_fresh_close_publisher(
        Arc::clone(&agent.session_store),
        &custody_account,
        &cf::prepare_vault_custody_root(&lease, backend.as_ref(), composite).unwrap(),
        Some(publisher),
    )
    .unwrap();
    let runtime = cf::prepare_configured_root_runtime(
        lease,
        Arc::clone(&backend),
        composite,
        factory.clone(),
    )
    .unwrap();
    let runtime = cf::attach_vault_published_history(runtime, custody).unwrap();
    let mut connection = cf::connect_configured_root(runtime).unwrap();
    let activity = connection.rename_public_entry_fixture_activity_source();
    agent.check_existing_file_save_account(&binding).unwrap();
    let original = save_owner.original_active.as_ref().unwrap();
    let actual = agent
        .provider
        .fresh_close_source
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .marker(&binding)
        .unwrap();
    assert!(Arc::ptr_eq(original, &actual) && actual.load(Ordering::Acquire));
    save_owner.committed = true;
    let personal = cloud_root.join("Personal");
    external_populate(&personal, &fixture);
    assert_eq!(fs::read(personal.join(SOURCE_NAME)).unwrap(), CONTENT);
    if case == Case::Late {
        assert_eq!(fs::read(personal.join("capture.bin")).unwrap(), CONTENT);
    }
    let before = connection
        .rename_public_entry_fixture_observation(cf::RenamePublicEntryFixturePath::Source)
        .unwrap();
    assert_eq!(
        before.placeholder_state, 9,
        "ordinary hydrated source starts in-sync before local rename"
    );
    assert_ne!(before.local_file.file_index, 0);
    let parent = connection
        .namespace_directory_fixture_observation(&["Personal"])
        .unwrap();
    let authorization = CapturedAuthorization {
        agent_generation: generation,
        token_generation: provider_scope.token_generation(),
    };
    let scope = cf::EditJournalScope {
        profile_id: provider_scope.profile_id().into(),
        server_origin: provider_scope.server_origin().into(),
        account_subject: provider_scope.account_id().into(),
        space_id: SPACE.into(),
        root_resource_id: ROOT_ID.into(),
        root_volume_serial: root.volume_serial,
        root_file_index: root.file_index,
    };
    let parent_remote = client.stat(SPACE, "/").unwrap();
    let local = LocalNamespaceEntry {
        parent: NamespaceParent {
            scope: scope.clone(),
            authorization,
            classification: StorageClassification::Ordinary,
            local_file: parent.local_file,
            local_components: vec!["Personal".into()],
            remote: cf::RemoteEditBaseline {
                resource_id: parent_remote.id,
                etag: parent_remote.etag,
                byte_len: parent_remote.size,
            },
        },
        name: SOURCE_NAME.into(),
        local_file: before.local_file,
        object_kind: NamespaceObjectKind::File,
    };
    let intent = NamespaceIntent {
        schema_version: NAMESPACE_INTENT_VERSION,
        record_id: "a".repeat(32),
        record_generation: 1,
        operation: NamespaceOperation::MoveWithinScope {
            source: ExistingNamespaceEntry {
                local: local.clone(),
                remote: cf::RemoteEditBaseline {
                    resource_id: SOURCE_ID.into(),
                    etag: SOURCE_ETAG.into(),
                    byte_len: 4096,
                },
            },
            destination: LocalNamespaceEntry {
                name: DESTINATION_NAME.into(),
                ..local
            },
        },
    };
    intent.validate().unwrap();
    let store = connection
        .file_rename_store(&backend, &scope, authorization)
        .unwrap()
        .unwrap();
    let same = prepared
        .file_rename_store(&scope, authorization)
        .unwrap()
        .unwrap();
    assert!(Arc::ptr_eq(&factory.prepared, &prepared));
    // Both store requests come from this retained prepared factory. The real
    // direct public entry independently enforces same_admitted_binding.
    assert!(same.discover_account_root().unwrap().is_empty());
    let catalog_scope =
        cf::ProviderIdentityCatalogScope::new(&provider_scope, root, SPACE, ROOT_ID).unwrap();
    let bindings = recovery.identity_catalog().load(&catalog_scope).unwrap();
    let parent_identity = bindings
        .iter()
        .find_map(|b| match b {
            cf::ProviderIdentityBinding::Directory { path, .. } if path == "/" => {
                Some(b.identity())
            }
            _ => None,
        })
        .expect("real parent catalog binding");
    let source_identity = bindings
        .iter()
        .find_map(|b| match b {
            cf::ProviderIdentityBinding::File { path, .. } if path == "/source.bin" => {
                Some(b.identity())
            }
            _ => None,
        })
        .expect("real source catalog binding");
    assert_eq!(parent_identity.as_bytes(), &parent.opaque_identity.unwrap());
    assert_eq!(source_identity.as_bytes(), &before.opaque_identity.unwrap());
    wait_callbacks_idle(&connection);
    assert!(matches!(
        dispatch_one_initial_edit(
            Some(&connection),
            Some(&backend),
            Some(&binding),
            &agent.provider.authorized_generation
        ),
        Ok(None)
    ));
    let capture_before = connection.close_observation_for_integration();
    assert_eq!(
        capture_before.1, 0,
        "fresh fixture has no unknown callback history"
    );
    let current = |a: CapturedAuthorization| {
        a == authorization
            && agent.generation.load(Ordering::Acquire) == generation
            && client.token_generation() == a.token_generation
    };
    if matches!(case, Case::Pending | Case::Inflight) {
        if case == Case::Inflight {
            fs::write(barrier_dir.join("armed"), b"r58").unwrap();
        }
        let mut child = edit_child(case, &fixture, SOURCE_NAME, root);
        if case == Case::Inflight {
            wait_fact(
                || barrier_dir.join("guard-pinned").exists(),
                "actual modified close entered pinned callback",
            );
        } else {
            join_child(&mut child);
            // Process exit is not callback completion; the nonblocking history
            // scan requires the actual capture to have completed first.
            assert_capture_transition(&connection, capture_before);
            wait_fact(
                || {
                    prepared
                        .has_unresolved_content_authenticated_legacy()
                        .unwrap()
                },
                "actual capture durable pending",
            );
        }
        assert!(matches!(
            connection.reconcile_fresh_file_rename(
                &backend,
                &store,
                intent,
                parent_identity,
                &current
            ),
            Err(cf::NativeFileRenameError::DeferredBeforePublication)
        ));
        assert!(store.discover_account_root().unwrap().is_empty());
        assert_eq!(server.move_count.load(Ordering::Acquire), 0);
        if case == Case::Inflight {
            fs::write(barrier_dir.join("release"), b"r58").unwrap();
            join_child(&mut child);
        }
        assert_capture_transition(&connection, capture_before);
        wait_fact(
            || {
                prepared
                    .has_unresolved_content_authenticated_legacy()
                    .unwrap()
            },
            "capture still durable after refusal",
        );
        assert_retained_capture(Arc::clone(&state), &scope, &protector, SOURCE_NAME);
        let pending = connection
            .take_initial_edit()
            .unwrap()
            .expect("actual callback receipt survives");
        assert!(pending.matches_provider(&provider_scope, root));
        drop(pending);
    } else {
        let _initial = connection.attach_namespace_observer().unwrap();
        fs::rename(personal.join(SOURCE_NAME), personal.join(DESTINATION_NAME)).unwrap();
        let pending = connection
            .rename_public_entry_fixture_observation(cf::RenamePublicEntryFixturePath::Destination)
            .unwrap();
        assert_eq!(pending.local_file, before.local_file);
        assert_eq!(pending.placeholder_state, 1);
        wait_callbacks_idle(&connection);
        // Retain the actual child OUTSIDE the catalog-locked callback, even on
        // unwind. FixtureChild's Drop kills a live process; ManuallyDrop prevents
        // that cleanup from running under the publication lock or on uncertainty.
        let late_child = std::rc::Rc::new(std::cell::RefCell::new(
            None::<std::mem::ManuallyDrop<FixtureChild>>,
        ));
        let expected_late_entry = if case == Case::Late {
            let baseline = activity().expect("actual fixture activity available");
            assert_eq!(baseline.active_callbacks, 0);
            assert_eq!(baseline.active_fetches, 0);
            assert_eq!(baseline.staged_fetches, 0);
            assert!(!baseline.close_admission_unknown);
            baseline
                .dirty_close_entries
                .checked_add(1)
                .filter(|value| *value != u64::MAX)
                .expect("bounded actual dirty-entry observation")
        } else {
            0
        };
        let _completion_barrier =
            if case == Case::Late {
                fs::write(barrier_dir.join("armed"), b"r58").unwrap();
                let fixture = fixture.clone();
                let barrier = barrier_dir.clone();
                let retained_store = Arc::clone(&store);
                let activity = Arc::clone(&activity);
                let child_slot = std::rc::Rc::clone(&late_child);
                Some(
                    cf::synthetic_agent_integration::arm_file_rename_completion_fixture(
                        intent.clone(),
                        move |published| {
                            let histories = retained_store.discover_account_root().unwrap();
                            assert_eq!(histories.len(), 1);
                            assert_eq!(histories[0].intent, *published);
                            assert_eq!(histories[0].progress.sequence, 2);
                            assert_eq!(
                                histories[0].progress.remote,
                                cf::namespace_intent::NamespacePhase::Verified
                            );
                            assert!(!histories[0].progress.local_completed);
                            // Native identity update and RemoteVerified already occurred.
                            // A different ordinary file on the SAME real callback tracker
                            // now closes dirty; no tracker permit or synthetic epoch exists.
                            assert!(child_slot.borrow().is_none());
                            *child_slot.borrow_mut() = Some(std::mem::ManuallyDrop::new(
                                edit_child(Case::Late, &fixture, "capture.bin", root),
                            ));
                            // The callback has passed REAL dirty bookkeeping, but
                            // binding/body capture needs the catalog lock held here.
                            // Observe only the lock-free entry fact, never wait for
                            // its downstream pin/journal while retaining that lock.
                            wait_fact(
                                || {
                                    activity().is_some_and(|state| {
                                        state.dirty_close_entries == expected_late_entry
                                            && state.active_callbacks > 0
                                            && state.active_fetches == 0
                                            && state.staged_fetches == 0
                                            && !state.close_admission_unknown
                                            && state.unverifiable_closes == capture_before.1
                                    })
                                },
                                "actual late dirty callback entered before completion claim",
                            );
                            fs::write(barrier.join("release"), b"r58").unwrap();
                        },
                    )
                    .unwrap(),
                )
            } else {
                None
            };
        let outcome=if case==Case::Candidate {
            let observation=connection.poll_namespace_observer(Duration::from_millis(250)).unwrap();
            let pairs=match observation.poll(){raiun_control_windows::directory_notifications::ObserverPoll::Batch(batch)=>raiun_control_windows::directory_notifications::directory_rename_hints::pair_rename_hints(batch),_=>panic!("complete native rename batch required")};
            let hints=match pairs {raiun_control_windows::directory_notifications::directory_rename_hints::RenameHintBatch::Pairs(mut pairs)=>{assert_eq!(pairs.len(),1);pairs.remove(0)},_=>panic!("one complete same-batch pair required")};
            let candidate=backend.file_rename_binding_candidate(source_identity,parent_identity,hints,authorization,before.local_file,&current).unwrap();
            connection.reconcile_fresh_file_rename_candidate(&backend,&candidate,1,&current)
        } else {
            connection.reconcile_fresh_file_rename(&backend,&store,intent,parent_identity,&current)
        }.unwrap();
        if case == Case::Late {
            assert_eq!(
                outcome,
                cf::namespace_file_rename::FileRenameOutcome::RemoteVerifiedLocalPending
            );
            let mut child = late_child
                .borrow_mut()
                .take()
                .expect("same actual late child retained");
            join_child(&mut child);
            // Drop the kill-on-drop wrapper only after positively observed exit.
            drop(std::mem::ManuallyDrop::into_inner(child));
            assert_capture_transition(&connection, capture_before);
            assert!(
                barrier_dir.join("guard-pinned").exists(),
                "actual path pins observed after catalog unlock"
            );
            let after_capture = activity().expect("actual capture activity available");
            assert_eq!(after_capture.active_callbacks, 0);
            assert_eq!(after_capture.active_fetches, 0);
            assert_eq!(after_capture.staged_fetches, 0);
            assert_eq!(after_capture.modified_closes, capture_before.0 + 1);
            assert_eq!(after_capture.journaled_closes, capture_before.7 + 1);
            assert_eq!(after_capture.dirty_close_entries, expected_late_entry);
            assert!(!after_capture.close_admission_unknown);
            assert_eq!(after_capture.unverifiable_closes, capture_before.1);
        }
        let expected = if case == Case::Late {
            cf::namespace_file_rename::FileRenameOutcome::RemoteVerifiedLocalPending
        } else {
            cf::namespace_file_rename::FileRenameOutcome::Completed
        };
        assert_eq!(outcome, expected);
        let after = connection
            .rename_public_entry_fixture_observation(cf::RenamePublicEntryFixturePath::Destination)
            .unwrap();
        assert_eq!(before.local_file, after.local_file);
        assert_eq!(after.placeholder_state, 1);
        assert_ne!(before.opaque_identity, after.opaque_identity);
        assert_eq!(fs::read(personal.join(DESTINATION_NAME)).unwrap(), CONTENT);
        assert!(!personal.join(SOURCE_NAME).exists());
        let history = store.discover_account_root().unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].progress.recorded_complete, case != Case::Late);
        assert_eq!(
            history[0].progress.sequence,
            if case == Case::Late { 2 } else { 4 }
        );
        if case == Case::Late {
            assert!(!history[0].progress.local_completed);
            assert_retained_capture(Arc::clone(&state), &scope, &protector, "capture.bin");
            let pending = connection
                .take_initial_edit()
                .unwrap()
                .expect("late actual callback receipt remains");
            assert!(pending.matches_provider(&provider_scope, root));
            drop(pending);
            assert!(
                prepared
                    .has_unresolved_content_authenticated_legacy()
                    .unwrap()
            );
        }
        assert_eq!(server.move_count.load(Ordering::Acquire), 1);
        let gets = server.conditional_gets.lock().unwrap();
        assert!(
            gets.iter()
                .any(|g| g.0.ends_with(SOURCE_NAME) && g.1 == SOURCE_ETAG)
        );
        assert!(
            gets.iter()
                .any(|g| g.0.ends_with(DESTINATION_NAME) && g.1 == DESTINATION_ETAG)
        );
        drop(gets);
        connection
            .stop_namespace_observer(Duration::from_millis(250))
            .unwrap();
    }
    fs::write(fixture.join("R58-RESULTS.json"),serde_json::to_vec_pretty(&serde_json::json!({"selector":case.selector(),"native_entry_executed":true,"moves":server.move_count.load(Ordering::Acquire),"source_file_id":before.local_file.file_index,"root_file_id":root.file_index,"state_retained":state.path().exists(),"rename_completion_requests_no_mark_in_sync":true,"protocol":server.diagnostic_snapshot(),"remote_renamed":server.moved.load(Ordering::Acquire),"request_count":server.requests.lock().unwrap().len()})).unwrap()).unwrap();
    connection.disconnect_in_place().unwrap();
    agent.stop_fresh_close_worker().unwrap();
    agent.stop_and_join().unwrap();
    server.finish();
}
#[test]
#[ignore = "R58 actual native registration; fresh isolated owned NTFS/ordinary-user VM contract required"]
fn r58_direct_public_entry_completes_one_fresh_personal_rename() {
    run(Case::Direct)
}
#[test]
#[ignore = "R58 actual native registration; fresh isolated owned NTFS/ordinary-user VM contract required"]
fn r58_candidate_public_entry_completes_one_fresh_personal_rename() {
    run(Case::Candidate)
}
#[test]
#[ignore = "R58 actual modified-close callback; isolated native guard required"]
fn r58_pending_content_defers_without_namespace_publication() {
    run(Case::Pending)
}
#[test]
#[ignore = "R58 actual held modified-close callback; isolated native guard required"]
fn r58_inflight_native_close_defers_and_retains_capture() {
    run(Case::Inflight)
}
#[test]
#[ignore = "R58 actual late modified-close callback; isolated native guard required"]
fn r58_late_native_dirty_close_refuses_completion_and_retains_factual_prefix() {
    run(Case::Late)
}

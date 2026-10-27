use raiun_cache::{
    Cache, CacheError, CacheScope, CiphertextPinState, CiphertextWriteState, ScopeProtection,
};
use raiun_core::backend::{CloudBackend, WriteCondition};
use raiun_core::{FolderPair, SyncMode, VaultBinding};
use raiun_engine::{ConflictChoice, Engine};
use raiun_opencloud::{
    OpenCloudClient, ProxyConfig,
    transfer_budget::{TransferBudget, TransferLimits},
    vault_backend::{
        VaultBackend, VaultCancelledCreateReceiptState, VaultCopyOutcome,
        VaultCopyReconciliationReason, VaultCopyRequest, VaultCopyResolutionOutcome,
        VaultCopyResolutionReason, VaultDeleteOutcome, VaultDirectoryCreateOutcome,
        VaultPendingDirectorySubtreeRetargetExpectedRevision,
        VaultPendingDirectorySubtreeRetargetResolutionState, VaultUploadOutcome,
    },
    vault_cache::{VaultOfflineCache, VaultPendingOperationKind, VaultPendingParentRef},
};
use raiun_vault::session::{VaultSessionCoordinator, VaultSessionScope};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Cursor, Read, Write},
    net::{TcpListener, TcpStream},
    num::NonZeroU64,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use tempfile::NamedTempFile;

const SPACE: &str = "personal-drive";
const ROOT_PATH: &str = "/Travel.vault";
const ROOT_ID: &str = "vault-root-id";

#[derive(Clone, Debug)]
struct RequestRecord {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[derive(Default)]
struct State {
    requests: Vec<RequestRecord>,
    child: Option<(String, Vec<u8>)>,
    child_directory: bool,
    child_resource_id: String,
    nested_directory: Option<(String, String)>,
    nested_child: Option<(String, Vec<u8>)>,
    root_id: String,
    root_etag: String,
    token: String,
    whole_space: bool,
    etag_version: u64,
    corrupt_download: bool,
    reject_put: bool,
    lose_put_response: bool,
    replacement_put_body: Option<Vec<u8>>,
    preserve_put_etag: bool,
    lose_move_response: bool,
    lose_delete_response: bool,
    lose_mkcol_response: bool,
    disconnect: bool,
    unauthorized: bool,
    get_delay_ms: u64,
    copy_put_gate: Option<Arc<CopyPutGate>>,
}

#[derive(Default)]
struct CopyPutGate {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl CopyPutGate {
    fn wait_for_body_prefix<T>(&self, worker: &JoinHandle<T>) -> bool {
        // Downloading, staging and encrypting the source precede the gated PUT.
        // Allow slower debug Windows builds to prepare it; revocation itself
        // still happens only after the fixture observes the real upload body.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let mut state = self.state.lock().unwrap();
        while !state.0 {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() || worker.is_finished() {
                // Never leave the fixture blocked if preparation fails or
                // reaches this gate just after the readiness deadline.
                state.1 = true;
                self.changed.notify_all();
                return false;
            }
            let (next, _) = self
                .changed
                .wait_timeout(state, remaining.min(Duration::from_millis(100)))
                .unwrap();
            state = next;
        }
        true
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap();
        state.1 = true;
        self.changed.notify_all();
    }

    fn reached_prefix(&self) {
        let mut state = self.state.lock().unwrap();
        state.0 = true;
        self.changed.notify_all();
        while !state.1 {
            state = self.changed.wait(state).unwrap();
        }
    }
}

struct Fixture {
    authority: String,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Fixture {
    fn start() -> Self {
        Self::start_mode(false)
    }

    fn start_whole_space() -> Self {
        Self::start_mode(true)
    }

    fn start_mode(whole_space: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let state = Arc::new(Mutex::new(State {
            root_id: if whole_space {
                "space-root-id".to_owned()
            } else {
                ROOT_ID.to_owned()
            },
            token: include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64")
                .trim()
                .to_owned(),
            child_resource_id: "child-resource-id".to_owned(),
            whole_space,
            ..State::default()
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_state = Arc::clone(&state);
        let thread_stop = Arc::clone(&stop);
        let thread_authority = authority.clone();
        let worker = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => serve(stream, &thread_authority, &thread_state),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("synthetic listener failed: {error}"),
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

    fn replace_root_id(&self, id: &str) {
        self.state.lock().unwrap().root_id = id.to_owned();
    }

    fn replace_root_etag(&self, etag: &str) {
        self.state.lock().unwrap().root_etag = etag.to_owned();
    }

    fn replace_token(&self, token: &str) {
        self.state.lock().unwrap().token = token.to_owned();
    }

    fn corrupt_download(&self) {
        self.state.lock().unwrap().corrupt_download = true;
    }

    fn reject_put(&self) {
        self.state.lock().unwrap().reject_put = true;
    }

    fn disconnect(&self, disconnected: bool) {
        self.state.lock().unwrap().disconnect = disconnected;
    }

    fn allow_put(&self) {
        self.state.lock().unwrap().reject_put = false;
    }

    fn lose_put_response(&self) {
        self.state.lock().unwrap().lose_put_response = true;
    }

    fn restore_put_responses(&self) {
        self.state.lock().unwrap().lose_put_response = false;
    }

    fn replace_next_put_body(&self, ciphertext: Vec<u8>) {
        self.state.lock().unwrap().replacement_put_body = Some(ciphertext);
    }

    fn pause_next_copy_put_body(&self) -> Arc<CopyPutGate> {
        let gate = Arc::new(CopyPutGate::default());
        self.state.lock().unwrap().copy_put_gate = Some(Arc::clone(&gate));
        gate
    }

    fn lose_move_response(&self) {
        self.state.lock().unwrap().lose_move_response = true;
    }

    fn lose_delete_response(&self) {
        self.state.lock().unwrap().lose_delete_response = true;
    }

    fn lose_mkcol_response(&self) {
        self.state.lock().unwrap().lose_mkcol_response = true;
    }

    fn replace_child_resource_id(&self, id: &str) {
        self.state.lock().unwrap().child_resource_id = id.to_owned();
    }

    fn clear_child(&self) {
        self.state.lock().unwrap().child = None;
    }

    fn replace_child_cipher_without_etag(&self, cipher: Vec<u8>) {
        self.state.lock().unwrap().child.as_mut().unwrap().1 = cipher;
    }

    fn mark_child_directory(&self, directory: bool) {
        self.state.lock().unwrap().child_directory = directory;
    }

    fn delay_get(&self, delay_ms: u64) {
        self.state.lock().unwrap().get_delay_ms = delay_ms;
    }

    fn set_unauthorized(&self, unauthorized: bool) {
        self.state.lock().unwrap().unauthorized = unauthorized;
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop_server();
    }
}

impl Fixture {
    fn stop_server(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

fn serve(mut stream: TcpStream, authority: &str, state: &Arc<Mutex<State>>) {
    // Windows accepted sockets inherit the listener's nonblocking mode. Keep
    // request parsing blocking like the other synthetic HTTP fixtures.
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut headers_buf = Vec::new();
    let mut byte = [0; 1];
    while !headers_buf.ends_with(b"\r\n\r\n") {
        if stream.read_exact(&mut byte).is_err() {
            return;
        }
        headers_buf.push(byte[0]);
        assert!(headers_buf.len() <= 64 * 1024);
    }
    let text = String::from_utf8(headers_buf).unwrap();
    let mut lines = text.lines();
    let mut first = lines.next().unwrap().split_ascii_whitespace();
    let method = first.next().unwrap().to_owned();
    let target = first.next().unwrap().to_owned();
    let headers: BTreeMap<_, _> = lines
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            Some((key.to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect();
    let content_len = headers
        .get("content-length")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    assert!(content_len <= 20 * 1024 * 1024);
    let copy_put_gate = if method == "PUT" {
        state.lock().unwrap().copy_put_gate.take()
    } else {
        None
    };
    let mut body = vec![0; content_len];
    if let Some(gate) = copy_put_gate.as_ref().filter(|_| content_len > 128) {
        if stream.read_exact(&mut body[..128]).is_err() {
            return;
        }
        gate.reached_prefix();
        if stream.read_exact(&mut body[128..]).is_err() {
            return;
        }
    } else if content_len > 0 && stream.read_exact(&mut body).is_err() {
        return;
    }
    state.lock().unwrap().requests.push(RequestRecord {
        method: method.clone(),
        target: target.clone(),
        headers: headers.clone(),
        body: body.clone(),
    });

    if state.lock().unwrap().disconnect {
        return;
    }

    let get_delay_ms = if method == "GET" && target.starts_with("/dav/") {
        state.lock().unwrap().get_delay_ms
    } else {
        0
    };
    if get_delay_ms > 0 {
        thread::sleep(Duration::from_millis(get_delay_ms));
    }

    if state.lock().unwrap().unauthorized
        || headers.get("authorization").map(String::as_str) != Some("Bearer synthetic-token")
    {
        respond(&mut stream, 401, "text/plain", b"unauthorized");
        return;
    }
    match (method.as_str(), target.as_str()) {
        ("GET", "/graph/v1.0/me/drives") => {
            let encrypted = if state.lock().unwrap().whole_space {
                r#","contentType":"application/vnd.opencloud.vault""#
            } else {
                ""
            };
            let body = format!(
                r#"{{"value":[{{"id":"{SPACE}","name":"Personal","driveType":"personal","root":{{"id":"space-root-id","webDavUrl":"http://{authority}/dav/personal/","permissions":"RDNVW"{encrypted}}}}}]}}"#
            );
            respond(&mut stream, 200, "application/json", body.as_bytes());
        }
        ("PROPFIND", "/dav/personal/Travel.vault/") | ("PROPFIND", "/dav/personal/") => {
            let snapshot = state.lock().unwrap();
            let include_children = headers.get("depth").map(String::as_str) != Some("0");
            respond(
                &mut stream,
                207,
                "application/xml",
                root_listing(authority, &snapshot, include_children).as_bytes(),
            );
        }
        ("PROPFIND", path)
            if path.starts_with("/dav/personal/Travel.vault/")
                || (path.starts_with("/dav/personal/") && path != "/dav/personal/") =>
        {
            let snapshot = state.lock().unwrap();
            if let Some((root_name, _)) =
                snapshot.child.as_ref().filter(|_| snapshot.child_directory)
            {
                let prefix = format!("/dav/personal/Travel.vault/{root_name}");
                if let Some(relative) = path.strip_prefix(&prefix) {
                    let relative = relative.trim_matches('/');
                    if relative.is_empty() {
                        let body = file_listing(
                            authority,
                            root_name,
                            0,
                            true,
                            snapshot.whole_space,
                            snapshot.etag_version.max(1),
                            &snapshot.child_resource_id,
                        );
                        respond(&mut stream, 207, "application/xml", body.as_bytes());
                        return;
                    }
                    if let Some((nested_name, nested_id)) =
                        snapshot.nested_directory.as_ref().filter(|(name, _)| {
                            relative == *name || relative.starts_with(&format!("{name}/"))
                        })
                    {
                        let nested_path = format!("{root_name}/{nested_name}");
                        if relative == nested_name {
                            let body = file_listing(
                                authority,
                                nested_name,
                                0,
                                true,
                                snapshot.whole_space,
                                snapshot.etag_version.max(1),
                                nested_id,
                            );
                            let body = with_nested_href(authority, &nested_path, nested_name, body);
                            respond(&mut stream, 207, "application/xml", body.as_bytes());
                            return;
                        }
                        if let Some((child_name, cipher)) = snapshot
                            .nested_child
                            .as_ref()
                            .filter(|(name, _)| relative.ends_with(name))
                        {
                            let child_path = format!("{nested_path}/{child_name}");
                            let body = file_listing(
                                authority,
                                child_name,
                                cipher.len(),
                                false,
                                snapshot.whole_space,
                                snapshot.etag_version.max(1),
                                "nested-child-resource-id",
                            );
                            let body = with_nested_href(authority, &child_path, child_name, body);
                            respond(&mut stream, 207, "application/xml", body.as_bytes());
                            return;
                        }
                        respond(&mut stream, 404, "text/plain", b"missing");
                        return;
                    }
                }
            }
            let response = snapshot
                .child
                .as_ref()
                .filter(|(name, _)| path.trim_end_matches('/').ends_with(name));
            if let Some((name, cipher)) = response {
                if !snapshot.child_directory && path.ends_with('/') {
                    respond(
                        &mut stream,
                        404,
                        "text/plain",
                        b"file path has a collection slash",
                    );
                    return;
                }
                let body = file_listing(
                    authority,
                    name,
                    cipher.len(),
                    snapshot.child_directory,
                    snapshot.whole_space,
                    snapshot.etag_version.max(1),
                    &snapshot.child_resource_id,
                );
                respond(&mut stream, 207, "application/xml", body.as_bytes());
            } else {
                respond(&mut stream, 404, "text/plain", b"missing");
            }
        }
        ("MKCOL", path)
            if path.starts_with("/dav/personal/Travel.vault/")
                || (path.starts_with("/dav/personal/") && path != "/dav/personal/") =>
        {
            let name = path.rsplit('/').next().unwrap().to_owned();
            let mut snapshot = state.lock().unwrap();
            let nested_parent_matches = snapshot
                .child
                .as_ref()
                .filter(|_| snapshot.child_directory)
                .is_some_and(|(root_name, _)| {
                    let prefix = format!("/dav/personal/Travel.vault/{root_name}/");
                    path.strip_prefix(&prefix)
                        .is_some_and(|relative| !relative.is_empty() && !relative.contains('/'))
                });
            if nested_parent_matches && snapshot.nested_directory.is_none() {
                snapshot.nested_directory = Some((name, "nested-directory-resource-id".into()));
                snapshot.etag_version = snapshot.etag_version.saturating_add(1);
                drop(snapshot);
                respond(&mut stream, 201, "text/plain", b"");
            } else if snapshot.child.is_some() {
                drop(snapshot);
                respond(&mut stream, 405, "text/plain", b"already exists");
            } else {
                snapshot.child = Some((name, Vec::new()));
                snapshot.child_directory = true;
                snapshot.etag_version = snapshot.etag_version.saturating_add(1);
                let lose_response = snapshot.lose_mkcol_response;
                drop(snapshot);
                if !lose_response {
                    respond(&mut stream, 201, "text/plain", b"");
                }
            }
        }
        ("MOVE", path)
            if path.starts_with("/dav/personal/Travel.vault/")
                || (path.starts_with("/dav/personal/") && path != "/dav/personal/") =>
        {
            let source_name = path.rsplit('/').next().unwrap();
            let target_name = headers
                .get("destination")
                .and_then(|destination| destination.rsplit('/').next())
                .unwrap_or("")
                .to_owned();
            let mut snapshot = state.lock().unwrap();
            if headers.get("if-match").map(String::as_str)
                != Some(format!("\"child-rev-{}\"", snapshot.etag_version.max(1)).as_str())
                || headers.get("overwrite").map(String::as_str) != Some("F")
                || snapshot
                    .child
                    .as_ref()
                    .is_none_or(|(name, _)| name != source_name)
            {
                drop(snapshot);
                respond(&mut stream, 412, "text/plain", b"move precondition failed");
            } else {
                snapshot.child.as_mut().unwrap().0 = target_name;
                snapshot.etag_version = snapshot.etag_version.saturating_add(1);
                let lose_response = snapshot.lose_move_response;
                drop(snapshot);
                if !lose_response {
                    respond(&mut stream, 201, "text/plain", b"");
                }
            }
        }
        ("DELETE", path)
            if path.starts_with("/dav/personal/Travel.vault/")
                || (path.starts_with("/dav/personal/") && path != "/dav/personal/") =>
        {
            let name = path.rsplit('/').next().unwrap();
            let mut snapshot = state.lock().unwrap();
            if headers.get("if-match").map(String::as_str)
                != Some(format!("\"child-rev-{}\"", snapshot.etag_version.max(1)).as_str())
                || snapshot
                    .child
                    .as_ref()
                    .is_none_or(|(current, _)| current != name)
            {
                drop(snapshot);
                respond(
                    &mut stream,
                    412,
                    "text/plain",
                    b"delete precondition failed",
                );
            } else {
                snapshot.child = None;
                snapshot.child_directory = false;
                snapshot.etag_version = snapshot.etag_version.saturating_add(1);
                let lose_response = snapshot.lose_delete_response;
                drop(snapshot);
                if !lose_response {
                    respond(&mut stream, 204, "text/plain", b"");
                }
            }
        }
        ("GET", path)
            if path.starts_with("/dav/personal/Travel.vault/")
                || (path.starts_with("/dav/personal/") && path != "/dav/personal/") =>
        {
            let snapshot = state.lock().unwrap();
            let nested_parts = path
                .strip_prefix("/dav/personal/Travel.vault/")
                .map(|relative| relative.split('/').collect::<Vec<_>>())
                .unwrap_or_default();
            if nested_parts.len() == 3
                && snapshot
                    .nested_directory
                    .as_ref()
                    .is_some_and(|(nested_name, _)| nested_name == nested_parts[1])
            {
                if let Some((_, cipher)) = snapshot
                    .nested_child
                    .as_ref()
                    .filter(|(name, _)| name == nested_parts[2])
                {
                    if headers.get("if-match").map(String::as_str)
                        != Some(format!("\"child-rev-{}\"", snapshot.etag_version.max(1)).as_str())
                    {
                        respond(&mut stream, 412, "text/plain", b"etag mismatch");
                    } else {
                        respond(&mut stream, 200, "application/octet-stream", cipher);
                    }
                } else {
                    respond(&mut stream, 404, "text/plain", b"missing");
                }
                return;
            }
            if let Some((_, cipher)) = snapshot
                .child
                .as_ref()
                .filter(|(name, _)| path.ends_with(name))
            {
                if headers.get("if-match").map(String::as_str)
                    != Some(format!("\"child-rev-{}\"", snapshot.etag_version.max(1)).as_str())
                {
                    respond(&mut stream, 412, "text/plain", b"etag mismatch");
                } else {
                    let mut bytes = cipher.clone();
                    if snapshot.corrupt_download && bytes.len() > 32 {
                        let last = bytes.len() - 1;
                        bytes[last] ^= 0x40;
                    }
                    respond(&mut stream, 200, "application/octet-stream", &bytes);
                }
            } else {
                respond(&mut stream, 404, "text/plain", b"missing");
            }
        }
        ("PUT", path)
            if path.starts_with("/dav/personal/Travel.vault/")
                || (path.starts_with("/dav/personal/") && path != "/dav/personal/") =>
        {
            let mut snapshot = state.lock().unwrap();
            let nested_parts = path
                .strip_prefix("/dav/personal/Travel.vault/")
                .map(|relative| relative.split('/').collect::<Vec<_>>())
                .unwrap_or_default();
            if nested_parts.len() == 3
                && snapshot
                    .nested_directory
                    .as_ref()
                    .is_some_and(|(nested_name, _)| nested_name == nested_parts[1])
            {
                let same_target = snapshot
                    .nested_child
                    .as_ref()
                    .is_some_and(|(name, _)| name == nested_parts[2]);
                let current_etag = format!("\"child-rev-{}\"", snapshot.etag_version.max(1));
                let precondition_ok =
                    if headers.get("if-none-match").map(String::as_str) == Some("*") {
                        !same_target
                    } else if let Some(etag) = headers.get("if-match") {
                        same_target && etag == &current_etag
                    } else {
                        false
                    };
                if snapshot.reject_put || !precondition_ok {
                    drop(snapshot);
                    respond(&mut stream, 412, "text/plain", b"precondition failed");
                    return;
                }
                snapshot.nested_child = Some((nested_parts[2].to_owned(), body));
                snapshot.etag_version = snapshot.etag_version.saturating_add(1);
                let lose_response = snapshot.lose_put_response;
                drop(snapshot);
                if lose_response {
                    return;
                }
                respond(&mut stream, 201, "text/plain", b"");
                return;
            }
            let target_name = path.rsplit('/').next().unwrap_or_default();
            let same_target = snapshot
                .child
                .as_ref()
                .is_some_and(|(name, _)| name == target_name);
            let current_etag = format!("\"child-rev-{}\"", snapshot.etag_version.max(1));
            let precondition_ok = if headers.get("if-none-match").map(String::as_str) == Some("*") {
                !same_target
            } else if let Some(etag) = headers.get("if-match") {
                same_target && etag == &current_etag
            } else {
                false
            };
            if snapshot.reject_put || !precondition_ok {
                drop(snapshot);
                respond(&mut stream, 412, "text/plain", b"precondition failed");
                return;
            }
            let encrypted_name = path.rsplit('/').next().unwrap().to_owned();
            let stored_body = snapshot.replacement_put_body.take().unwrap_or(body);
            snapshot.child = Some((encrypted_name, stored_body));
            snapshot.child_directory = false;
            if !snapshot.preserve_put_etag {
                snapshot.etag_version = snapshot.etag_version.saturating_add(1);
            }
            let lose_response = snapshot.lose_put_response;
            drop(snapshot);
            if lose_response {
                return;
            }
            respond(&mut stream, 201, "text/plain", b"");
        }
        _ => respond(&mut stream, 404, "text/plain", b"not found"),
    }
}

fn root_listing(authority: &str, state: &State, include_children: bool) -> String {
    let token = &state.token;
    let root_etag = if state.root_etag.is_empty() {
        "\"root-rev-2\""
    } else {
        &state.root_etag
    };
    let (root_href, root_name, child_prefix) = if state.whole_space {
        (
            format!("http://{authority}/dav/personal/"),
            "personal",
            format!("http://{authority}/dav/personal/"),
        )
    } else {
        (
            format!("http://{authority}/dav/personal/Travel.vault/"),
            "Travel.vault",
            format!("http://{authority}/dav/personal/Travel.vault/"),
        )
    };
    let mut child_xml = String::new();
    if include_children && let Some((name, cipher)) = state.child.as_ref() {
        let resource_type = if state.child_directory {
            "<d:resourcetype><d:collection/></d:resourcetype>"
        } else {
            "<d:resourcetype/>"
        };
        child_xml = format!(
            r#"<d:response><d:href>{child_prefix}{name}</d:href><d:propstat><d:prop>{resource_type}<d:getcontentlength>{}</d:getcontentlength><d:getetag>"child-rev-{}"</d:getetag><oc:fileid>{}</oc:fileid><oc:name>{name}</oc:name><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"#,
            if state.child_directory {
                0
            } else {
                cipher.len()
            },
            state.etag_version.max(1),
            state.child_resource_id
        );
    }
    format!(
        r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone"><d:response><d:href>{root_href}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>{root_etag}</d:getetag><d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype><oc:fileid>{}</oc:fileid><oc:name>{root_name}</oc:name><oc:size>0</oc:size><oc:permissions>RDNVW</oc:permissions><ocrclone:integrity-id>{token}</ocrclone:integrity-id></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>{child_xml}</d:multistatus>"#,
        state.root_id
    )
}

fn file_listing(
    authority: &str,
    name: &str,
    size: usize,
    directory: bool,
    whole_space: bool,
    etag_version: u64,
    resource_id: &str,
) -> String {
    let prefix = if whole_space {
        format!("http://{authority}/dav/personal/")
    } else {
        format!("http://{authority}/dav/personal/Travel.vault/")
    };
    let resource_type = if directory {
        "<d:resourcetype><d:collection/></d:resourcetype>"
    } else {
        "<d:resourcetype/>"
    };
    let href_suffix = if directory { "/" } else { "" };
    format!(
        r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>{prefix}{name}{href_suffix}</d:href><d:propstat><d:prop>{resource_type}<d:getcontentlength>{size}</d:getcontentlength><d:getetag>"child-rev-{etag_version}"</d:getetag><oc:fileid>{resource_id}</oc:fileid><oc:name>{name}</oc:name><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#
    )
}

fn with_nested_href(authority: &str, relative_path: &str, _name: &str, xml: String) -> String {
    let prefix = if relative_path.starts_with("/") {
        format!("http://{authority}/dav/personal/")
    } else {
        format!("http://{authority}/dav/personal/Travel.vault/")
    };
    let leaf = relative_path.rsplit('/').next().unwrap_or_default();
    let slash = if xml.contains("<d:collection/>") {
        "/"
    } else {
        ""
    };
    xml.replace(
        &format!("<d:href>{prefix}{leaf}{slash}</d:href>"),
        &format!("<d:href>{prefix}{relative_path}{slash}</d:href>"),
    )
}

fn respond(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
    // A correctly cancelled async client may close its socket while this
    // synthetic server is intentionally delaying a body response.
    let _ = write!(
        stream,
        "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(body);
}

#[test]
fn online_private_writer_verifies_complete_content_and_refuses_unpublished_failures() {
    let fixture = Fixture::start();
    let (backend, sessions, scope) = setup(&fixture);
    let plaintext: Vec<u8> = (0..65537).map(|index| (index * 31 + 7) as u8).collect();
    let mut source = NamedTempFile::new().unwrap();
    source.write_all(&plaintext).unwrap();
    source.flush().unwrap();
    let entry = backend
        .upload(SPACE, "/held.bin", source.path(), WriteCondition::Absent)
        .unwrap();
    let staging = tempfile::tempdir().unwrap();
    let nominal = staging.path().join("unpublished-plaintext");
    let mut output = Vec::new();
    let received = backend
        .download_online_to_private_writer(
            SPACE,
            "/held.bin",
            &entry.etag,
            staging.path(),
            &mut output,
        )
        .unwrap();
    assert_eq!(received.id, entry.id);
    assert_eq!(received.etag, entry.etag);
    assert_eq!(received.size, plaintext.len() as u64);
    assert_eq!(output, plaintext);
    assert!(!nominal.exists());
    assert_eq!(std::fs::read_dir(staging.path()).unwrap().count(), 0);

    let mut mismatch = Vec::new();
    assert!(
        backend
            .download_online_to_private_writer(
                SPACE,
                "/held.bin",
                "\"stale-revision\"",
                staging.path(),
                &mut mismatch
            )
            .is_err()
    );
    assert!(mismatch.is_empty());
    fixture.corrupt_download();
    let mut partial = Vec::new();
    assert!(
        backend
            .download_online_to_private_writer(
                SPACE,
                "/held.bin",
                &entry.etag,
                staging.path(),
                &mut partial
            )
            .is_err()
    );
    assert_eq!(partial, plaintext[..65536]);
    assert!(!nominal.exists());
    assert_eq!(std::fs::read_dir(staging.path()).unwrap().count(), 0);

    let cache_state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(cache_state.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
    }
    let cache = Cache::open(cache_state.path(), 16 * 1024 * 1024).unwrap();
    let adapter = VaultOfflineCache::new(cache, scope.clone(), ROOT_PATH).unwrap();
    let cached = VaultBackend::new_with_offline_cache(
        OpenCloudClient::new(&fixture.origin(), "synthetic-token".into()).unwrap(),
        sessions,
        scope,
        ROOT_PATH.into(),
        adapter,
    )
    .unwrap();
    let requests_before = fixture.requests().len();
    let mut forbidden = Vec::new();
    assert!(
        cached
            .download_online_to_private_writer(
                SPACE,
                "/held.bin",
                &entry.etag,
                staging.path(),
                &mut forbidden
            )
            .is_err()
    );
    assert!(forbidden.is_empty());
    assert_eq!(fixture.requests().len(), requests_before);
    assert!(!nominal.exists());
}

#[test]
fn virtual_upload_encrypts_and_uses_absent_precondition() {
    let fixture = Fixture::start();
    let client = OpenCloudClient::new(&fixture.origin(), "synthetic-token".to_owned()).unwrap();
    let sessions = Arc::new(VaultSessionCoordinator::new());
    let scope = VaultSessionScope::new("account-a", &fixture.origin(), SPACE, ROOT_ID).unwrap();
    let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim();
    let mut password = b"potato".to_vec();
    sessions.unlock(&scope, &mut password, token).unwrap();
    let backend =
        VaultBackend::new(client, Arc::clone(&sessions), scope, ROOT_PATH.to_owned()).unwrap();

    let mut source = NamedTempFile::new().unwrap();
    source
        .write_all(b"plaintext that must never go over DAV")
        .unwrap();
    source.flush().unwrap();
    let before = fixture.requests().len();
    assert!(backend.stat(SPACE, "").is_err());
    assert_eq!(
        fixture.requests().len(),
        before,
        "invalid paths must fail before network I/O"
    );

    let result = backend
        .upload(SPACE, "/notes.txt", source.path(), WriteCondition::Absent)
        .unwrap();
    assert_eq!(result.path, "/notes.txt");
    assert!(!result.encrypted);
    let requests = fixture.requests();
    let put = requests
        .iter()
        .find(|request| request.method == "PUT")
        .unwrap();
    assert_eq!(
        put.headers.get("if-none-match").map(String::as_str),
        Some("*")
    );
    assert!(!put.target.contains("notes.txt"));
    assert!(!String::from_utf8_lossy(&put.body).contains("plaintext that must never go over DAV"));
    assert!(put.body.len() > b"plaintext that must never go over DAV".len());

    let matched = backend
        .upload(
            SPACE,
            "/notes.txt",
            source.path(),
            WriteCondition::Match("\"child-rev-1\"".to_owned()),
        )
        .unwrap();
    assert_eq!(matched.path, "/notes.txt");
    let requests = fixture.requests();
    let matched_put = requests
        .iter()
        .rev()
        .find(|request| request.method == "PUT")
        .unwrap();
    assert_eq!(
        matched_put.headers.get("if-match").map(String::as_str),
        Some("\"child-rev-1\"")
    );
    let original_cipher = matched_put.body.clone();

    let before = fixture.requests().len();
    let mut second = NamedTempFile::new().unwrap();
    second.write_all(b"second upload must conflict").unwrap();
    second.flush().unwrap();
    fixture.reject_put();
    assert!(
        backend
            .upload(
                SPACE,
                "/notes.txt",
                second.path(),
                WriteCondition::Match(matched.etag.clone()),
            )
            .is_err()
    );
    let requests = fixture.requests();
    let rejected = requests[before..]
        .iter()
        .find(|request| request.method == "PUT")
        .expect("a conditional PUT reached the synthetic server");
    assert_eq!(rejected.headers.get("if-match"), Some(&matched.etag));
    assert_eq!(
        fixture.state.lock().unwrap().child.as_ref().unwrap().1,
        original_cipher
    );
    fixture.allow_put();

    let mut destination = NamedTempFile::new().unwrap();
    destination.write_all(b"old local contents").unwrap();
    destination.flush().unwrap();
    let (destination_file, destination_path) = destination.keep().unwrap();
    drop(destination_file);
    backend
        .download(SPACE, "/notes.txt", Some(&matched.etag), &destination_path)
        .unwrap();
    assert_eq!(
        std::fs::read(&destination_path).unwrap(),
        b"plaintext that must never go over DAV"
    );

    let mut preserved = NamedTempFile::new().unwrap();
    preserved
        .write_all(b"preserve on corrupt download")
        .unwrap();
    preserved.flush().unwrap();
    let (preserved_file, preserved_path) = preserved.keep().unwrap();
    drop(preserved_file);
    fixture.corrupt_download();
    assert!(
        backend
            .download(SPACE, "/notes.txt", Some(&matched.etag), &preserved_path)
            .is_err()
    );
    assert_eq!(
        std::fs::read(&preserved_path).unwrap(),
        b"preserve on corrupt download"
    );
}

#[test]
fn encrypted_ciphertext_streams_use_the_shared_upload_and_download_budgets() {
    let fixture = Fixture::start();
    let budget = TransferBudget::new();
    let rate = NonZeroU64::new(16 * 1024).unwrap();
    budget.set_limits(TransferLimits {
        upload_bytes_per_second: Some(rate),
        download_bytes_per_second: Some(rate),
    });
    let client = OpenCloudClient::new_with_proxy_and_transfer_budget(
        &fixture.origin(),
        "synthetic-token".to_owned(),
        &ProxyConfig::System,
        budget,
    )
    .unwrap();
    let sessions = Arc::new(VaultSessionCoordinator::new());
    let scope = VaultSessionScope::new("account-a", &fixture.origin(), SPACE, ROOT_ID).unwrap();
    let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim();
    let mut password = b"potato".to_vec();
    sessions.unlock(&scope, &mut password, token).unwrap();
    let backend =
        VaultBackend::new(client, Arc::clone(&sessions), scope, ROOT_PATH.to_owned()).unwrap();

    let plaintext = vec![0x5c; 32 * 1024];
    let source = NamedTempFile::new().unwrap();
    std::fs::write(source.path(), &plaintext).unwrap();
    let started = std::time::Instant::now();
    let entry = backend
        .upload(SPACE, "/limited.bin", source.path(), WriteCondition::Absent)
        .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(700));
    assert_eq!(entry.size, plaintext.len() as u64);
    let stored = fixture
        .requests()
        .into_iter()
        .find(|request| request.method == "PUT")
        .expect("encrypted PUT reached the fixture");
    assert_ne!(stored.body, plaintext);
    assert_eq!(
        fixture.state.lock().unwrap().child.as_ref().unwrap().1,
        stored.body
    );

    let output_dir = tempfile::tempdir().unwrap();
    let output = output_dir.path().join("downloaded.bin");
    let started = std::time::Instant::now();
    backend
        .download(SPACE, "/limited.bin", Some(&entry.etag), &output)
        .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(700));
    assert_eq!(std::fs::read(output).unwrap(), plaintext);
}

#[test]
fn prepared_reader_upload_rejects_bad_length_or_read_before_any_put() {
    struct MidstreamError {
        sent: bool,
    }
    impl Read for MidstreamError {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if !self.sent {
                self.sent = true;
                output[..2].copy_from_slice(b"ok");
                Ok(2)
            } else {
                Err(std::io::Error::other("synthetic reader failure"))
            }
        }
    }
    impl std::io::Seek for MidstreamError {
        fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
            match position {
                std::io::SeekFrom::Start(0) => {
                    self.sent = false;
                    Ok(0)
                }
                _ => Err(std::io::Error::other("unsupported synthetic seek")),
            }
        }
    }

    let fixture = Fixture::start();
    let (backend, _, _) = setup(&fixture);
    let target = backend
        .prepare_write_target("/notes.txt", &WriteCondition::Absent)
        .unwrap();

    let mut short = std::io::Cursor::new(b"tiny".to_vec());
    let before = fixture.requests().len();
    assert!(
        backend
            .upload_prepared_reader(&target, &mut short, 5, WriteCondition::Absent)
            .is_err()
    );
    assert!(
        !fixture.requests()[before..]
            .iter()
            .any(|request| request.method == "PUT")
    );

    let mut long = std::io::Cursor::new(b"longer".to_vec());
    let before = fixture.requests().len();
    assert!(
        backend
            .upload_prepared_reader(&target, &mut long, 5, WriteCondition::Absent)
            .is_err()
    );
    assert!(
        !fixture.requests()[before..]
            .iter()
            .any(|request| request.method == "PUT")
    );

    let mut interrupted = MidstreamError { sent: false };
    let before = fixture.requests().len();
    assert!(
        backend
            .upload_prepared_reader(&target, &mut interrupted, 4, WriteCondition::Absent)
            .is_err()
    );
    assert!(
        !fixture.requests()[before..]
            .iter()
            .any(|request| request.method == "PUT")
    );

    let mut empty = std::io::Cursor::new(Vec::new());
    let before = fixture.requests().len();
    assert!(
        backend
            .upload_prepared_reader(
                &target,
                &mut empty,
                1024 * 1024 * 1024 * 1024 + 1,
                WriteCondition::Absent,
            )
            .is_err()
    );
    assert!(
        !fixture.requests()[before..]
            .iter()
            .any(|request| request.method == "PUT")
    );
}

#[test]
fn prepared_reader_upload_resets_to_zero_and_verifies_remote_entry() {
    let fixture = Fixture::start();
    let (backend, _, _) = setup(&fixture);
    let target = backend
        .prepare_write_target("/notes.txt", &WriteCondition::Absent)
        .unwrap();
    let mut source = std::io::Cursor::new(b"prefix plus payload".to_vec());
    source.set_position(7);
    let entry = backend
        .upload_prepared_reader(&target, &mut source, 19, WriteCondition::Absent)
        .unwrap();
    assert_eq!(entry.path, "/notes.txt");
    assert_eq!(entry.size, 19);
    assert!(!entry.id.is_empty());
    assert!(!entry.etag.is_empty());
    let put = fixture
        .requests()
        .into_iter()
        .find(|request| request.method == "PUT")
        .unwrap();
    assert!(!put.target.contains("notes.txt"));
}

#[test]
fn late_ciphertext_corruption_never_publishes_partial_plaintext() {
    let fixture = Fixture::start();
    let (backend, _, _) = setup(&fixture);
    let plaintext = vec![0x5a; 70_000];
    let mut source = NamedTempFile::new().unwrap();
    source.write_all(&plaintext).unwrap();
    source.flush().unwrap();
    backend
        .upload(SPACE, "/large.bin", source.path(), WriteCondition::Absent)
        .unwrap();

    let mut destination = NamedTempFile::new().unwrap();
    destination.write_all(b"keep this destination").unwrap();
    destination.flush().unwrap();
    let (destination_file, destination_path) = destination.keep().unwrap();
    drop(destination_file);
    fixture.corrupt_download();
    assert!(
        backend
            .download(SPACE, "/large.bin", None, &destination_path)
            .is_err()
    );
    assert_eq!(
        std::fs::read(&destination_path).unwrap(),
        b"keep this destination"
    );
}

#[test]
fn folder_mutations_use_encrypted_paths_and_conditional_dav_headers() {
    let fixture = Fixture::start();
    let (backend, _, _) = setup(&fixture);

    let created = backend.mkdir(SPACE, "/folder").unwrap();
    assert_eq!(created.path, "/folder");
    assert!(created.directory);
    let requests = fixture.requests();
    let mkcol = requests
        .iter()
        .find(|request| request.method == "MKCOL")
        .unwrap();
    assert!(!mkcol.target.contains("folder"));

    let moved = backend
        .rename(SPACE, "/folder", "/renamed", &created.etag)
        .unwrap();
    assert_eq!(moved.path, "/renamed");
    let requests = fixture.requests();
    let move_request = requests
        .iter()
        .find(|request| request.method == "MOVE")
        .unwrap();
    assert_eq!(
        move_request.headers.get("if-match").map(String::as_str),
        Some(created.etag.as_str())
    );
    assert_eq!(
        move_request.headers.get("overwrite").map(String::as_str),
        Some("F")
    );
    assert!(!move_request.target.contains("folder"));
    assert!(
        !move_request
            .headers
            .get("destination")
            .unwrap()
            .contains("renamed")
    );

    backend.delete(SPACE, "/renamed", &moved.etag).unwrap();
    let requests = fixture.requests();
    let delete = requests
        .iter()
        .find(|request| request.method == "DELETE")
        .unwrap();
    assert_eq!(
        delete.headers.get("if-match").map(String::as_str),
        Some(moved.etag.as_str())
    );
    assert!(!delete.target.contains("renamed"));
}

#[test]
fn locked_or_replaced_root_never_sends_a_put() {
    let fixture = Fixture::start();
    let (backend, sessions, scope) = setup(&fixture);
    let mut source = NamedTempFile::new().unwrap();
    source.write_all(b"must stay local").unwrap();
    source.flush().unwrap();

    sessions.lock(&scope).unwrap();
    let before = fixture.requests().len();
    assert!(
        backend
            .upload(SPACE, "/notes.txt", source.path(), WriteCondition::Absent)
            .is_err()
    );
    assert!(
        !fixture.requests()[before..]
            .iter()
            .any(|request| request.method == "PUT")
    );

    let fixture = Fixture::start();
    let (backend, _, _) = setup(&fixture);
    fixture.replace_root_id("replacement-root");
    let before = fixture.requests().len();
    assert!(
        backend
            .upload(SPACE, "/notes.txt", source.path(), WriteCondition::Absent)
            .is_err()
    );
    assert!(
        !fixture.requests()[before..]
            .iter()
            .any(|request| request.method == "PUT")
    );

    let fixture = Fixture::start();
    let (backend, _, _) = setup(&fixture);
    fixture.replace_token("not-the-unlocked-token");
    let before = fixture.requests().len();
    assert!(
        backend
            .upload(SPACE, "/notes.txt", source.path(), WriteCondition::Absent)
            .is_err()
    );
    assert!(
        !fixture.requests()[before..]
            .iter()
            .any(|request| request.method == "PUT")
    );
}

#[test]
fn wrong_password_does_not_create_a_write_capable_backend() {
    let fixture = Fixture::start();
    let client = OpenCloudClient::new(&fixture.origin(), "synthetic-token".to_owned()).unwrap();
    let sessions = VaultSessionCoordinator::new();
    let scope = VaultSessionScope::new("account-a", &fixture.origin(), SPACE, ROOT_ID).unwrap();
    let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim();
    let mut password = b"wrong password".to_vec();
    assert!(sessions.unlock(&scope, &mut password, token).is_err());
    assert!(password.iter().all(|byte| *byte == 0));
    assert!(VaultBackend::new(client, Arc::new(sessions), scope, ROOT_PATH.to_owned()).is_err());
    assert!(
        !fixture
            .requests()
            .iter()
            .any(|request| request.method == "PUT"
                || request.method == "DELETE"
                || request.method == "MOVE")
    );
}

fn setup(
    fixture: &Fixture,
) -> (
    VaultBackend,
    Arc<VaultSessionCoordinator>,
    VaultSessionScope,
) {
    let client = OpenCloudClient::new(&fixture.origin(), "synthetic-token".to_owned()).unwrap();
    let sessions = Arc::new(VaultSessionCoordinator::new());
    let scope = VaultSessionScope::new("account-a", &fixture.origin(), SPACE, ROOT_ID).unwrap();
    let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim();
    let mut password = b"potato".to_vec();
    sessions.unlock(&scope, &mut password, token).unwrap();
    let backend = VaultBackend::new(
        client,
        Arc::clone(&sessions),
        scope.clone(),
        ROOT_PATH.to_owned(),
    )
    .unwrap();
    (backend, sessions, scope)
}

fn setup_cached(
    fixture: &Fixture,
) -> (
    VaultBackend,
    Arc<VaultSessionCoordinator>,
    VaultSessionScope,
    tempfile::TempDir,
    Cache,
) {
    let (backend, sessions, scope, state, cache, _) = setup_cached_with_client(fixture);
    (backend, sessions, scope, state, cache)
}

fn setup_cached_with_client(
    fixture: &Fixture,
) -> (
    VaultBackend,
    Arc<VaultSessionCoordinator>,
    VaultSessionScope,
    tempfile::TempDir,
    Cache,
    OpenCloudClient,
) {
    setup_cached_with_client_and_budget(fixture, TransferBudget::new())
}

fn setup_cached_with_client_and_budget(
    fixture: &Fixture,
    transfer_budget: TransferBudget,
) -> (
    VaultBackend,
    Arc<VaultSessionCoordinator>,
    VaultSessionScope,
    tempfile::TempDir,
    Cache,
    OpenCloudClient,
) {
    let (_, sessions, scope) = setup(fixture);
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let cache = Cache::open(state.path(), 16 * 1024 * 1024).unwrap();
    let cache_adapter = VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH).unwrap();
    let client = OpenCloudClient::new(&fixture.origin(), "synthetic-token".to_owned())
        .unwrap()
        .with_transfer_budget(transfer_budget);
    let backend = VaultBackend::new_with_offline_cache(
        client.clone(),
        Arc::clone(&sessions),
        scope.clone(),
        ROOT_PATH.to_owned(),
        cache_adapter,
    )
    .unwrap();
    (backend, sessions, scope, state, cache, client)
}

fn assert_tree_does_not_contain(path: &std::path::Path, needles: &[&[u8]]) {
    let mut pending = vec![path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for item in std::fs::read_dir(directory).unwrap() {
            let path = item.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let bytes = std::fs::read(path).unwrap();
                for needle in needles {
                    assert!(
                        !bytes.windows(needle.len()).any(|window| window == *needle),
                        "sealed journal leaked source binding value {:?}",
                        String::from_utf8_lossy(needle)
                    );
                }
            }
        }
    }
}

fn seed_and_cache_file(
    backend: &VaultBackend,
    state_dir: &tempfile::TempDir,
    name: &str,
    contents: &[u8],
) -> raiun_core::backend::RemoteEntry {
    let mut source = NamedTempFile::new().unwrap();
    source.write_all(contents).unwrap();
    source.flush().unwrap();
    let entry = backend
        .upload(
            SPACE,
            &format!("/{name}"),
            source.path(),
            WriteCondition::Absent,
        )
        .unwrap();
    let mut listing = Vec::new();
    backend
        .list(SPACE, "/", &mut |entry| {
            listing.push(entry);
            Ok(())
        })
        .unwrap();
    let baseline = state_dir.path().join("rename-baseline.bin");
    backend
        .download(SPACE, &entry.path, Some(&entry.etag), &baseline)
        .unwrap();
    assert_eq!(std::fs::read(baseline).unwrap(), contents);
    entry
}

fn wait_for_content_get(fixture: &Fixture) {
    // Allow bounded setup time on slower Windows CI runners.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if fixture
            .requests()
            .iter()
            .any(|request| request.method == "GET" && request.target.starts_with("/dav/"))
        {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "timed out waiting for synthetic vault content GET; requests: {:?}",
        fixture
            .requests()
            .iter()
            .map(|request| (&request.method, &request.target))
            .collect::<Vec<_>>()
    );
}

fn copy_request(
    source_scope: &VaultSessionScope,
    destination_scope: &VaultSessionScope,
    source_entry: &raiun_core::backend::RemoteEntry,
    destination_root: &raiun_core::backend::RemoteEntry,
    destination_path: &str,
) -> VaultCopyRequest {
    VaultCopyRequest {
        source_scope: source_scope.clone(),
        destination_scope: destination_scope.clone(),
        source_path: source_entry.path.clone(),
        source_resource_id: source_entry.id.clone(),
        source_etag: source_entry.etag.clone(),
        destination_path: destination_path.to_owned(),
        destination_parent_resource_id: destination_root.id.clone(),
        destination_parent_etag: destination_root.etag.clone(),
        source_auth_generation: 1,
        destination_auth_generation: 1,
    }
}

#[test]
fn cross_vault_copy_is_conditional_and_reports_only_decrypted_readback() {
    let source_fixture = Fixture::start();
    let destination_fixture = Fixture::start();
    let (source, _source_sessions, source_scope, source_state, _) = setup_cached(&source_fixture);
    let (destination, _destination_sessions, destination_scope, _dest_state, _) =
        setup_cached(&destination_fixture);
    let bytes = b"bounded cross-vault file body";
    let local = source_state.path().join("copy-source.bin");
    std::fs::write(&local, bytes).unwrap();
    let source_entry = source
        .upload(SPACE, "/source.txt", &local, WriteCondition::Absent)
        .unwrap();
    let destination_root = destination.stat(SPACE, "/").unwrap();
    let before_puts = destination_fixture
        .requests()
        .iter()
        .filter(|request| request.method == "PUT")
        .count();

    let result = source
        .copy_file_to(
            &destination,
            &copy_request(
                &source_scope,
                &destination_scope,
                &source_entry,
                &destination_root,
                "/copied.txt",
            ),
        )
        .unwrap();
    let VaultCopyOutcome::Copied {
        destination: copied,
        plaintext_len,
        plaintext_sha256,
    } = result
    else {
        panic!("verified online copy should commit")
    };
    assert_eq!(copied.path, "/copied.txt");
    assert_eq!(plaintext_len, bytes.len() as u64);
    assert_eq!(plaintext_sha256, format!("{:x}", Sha256::digest(bytes)));
    let puts = destination_fixture
        .requests()
        .into_iter()
        .filter(|request| request.method == "PUT")
        .collect::<Vec<_>>();
    assert_eq!(puts.len(), before_puts + 1);
    assert_eq!(
        puts.last()
            .unwrap()
            .headers
            .get("if-none-match")
            .map(String::as_str),
        Some("*")
    );
    assert!(
        source_fixture
            .requests()
            .iter()
            .all(|request| request.method != "DELETE" && request.method != "MOVE")
    );
}

#[test]
fn cross_vault_copy_cancelled_before_read_sends_no_requests_or_journal_claim() {
    let source_fixture = Fixture::start();
    let destination_fixture = Fixture::start();
    let (source, _source_sessions, source_scope, source_state, _) = setup_cached(&source_fixture);
    let (destination, destination_sessions, destination_scope, _dest_state, adapter) =
        setup_cached(&destination_fixture);
    let local = source_state.path().join("cancelled-copy.bin");
    std::fs::write(&local, b"cancelled copy source").unwrap();
    let entry = source
        .upload(SPACE, "/source.txt", &local, WriteCondition::Absent)
        .unwrap();
    let root = destination.stat(SPACE, "/").unwrap();
    let source_before = source_fixture.requests().len();
    let destination_before = destination_fixture.requests().len();
    let binding_published = AtomicBool::new(false);
    assert!(
        source
            .copy_file_to_cancellable_with_binding(
                &destination,
                &copy_request(
                    &source_scope,
                    &destination_scope,
                    &entry,
                    &root,
                    "/cancelled.txt"
                ),
                &|| true,
                |_, _| binding_published.store(true, Ordering::Release),
            )
            .is_err()
    );
    assert!(!binding_published.load(Ordering::Acquire));
    assert_eq!(source_fixture.requests().len(), source_before);
    assert_eq!(destination_fixture.requests().len(), destination_before);
    match adapter.ciphertext_writes(&encrypted_cache_scope(&destination_scope), None, 100) {
        Ok((rows, _)) => assert!(rows.is_empty()),
        Err(raiun_cache::CacheError::NotFound) => {} // No destination journal scope was created.
        Err(error) => panic!("unexpected destination journal error: {error}"),
    }
    let _ = destination_sessions;
}

#[test]
fn cross_vault_copy_cancelled_after_queue_publishes_exact_never_attempted_binding() {
    let source_fixture = Fixture::start();
    let destination_fixture = Fixture::start();
    let (source, _source_sessions, source_scope, source_state, _) = setup_cached(&source_fixture);
    let (destination, destination_sessions, destination_scope, _dest_state, adapter) =
        setup_cached(&destination_fixture);
    let local = source_state.path().join("post-queue-cancel-copy.bin");
    std::fs::write(&local, b"cancel after durable queue").unwrap();
    let entry = source
        .upload(SPACE, "/source.txt", &local, WriteCondition::Absent)
        .unwrap();
    let root = destination.stat(SPACE, "/").unwrap();
    let cancelled = AtomicBool::new(false);
    let published = Mutex::new(None);

    let result = source.copy_file_to_cancellable_with_binding(
        &destination,
        &copy_request(
            &source_scope,
            &destination_scope,
            &entry,
            &root,
            "/post-queue-cancelled.txt",
        ),
        &|| cancelled.load(Ordering::Acquire),
        |write_id, revision| {
            *published.lock().unwrap() = Some((write_id.to_owned(), revision));
            cancelled.store(true, Ordering::Release);
        },
    );
    assert!(
        result.is_err(),
        "post-queue cancellation must stop before PUT"
    );

    let (write_id, revision) = published
        .into_inner()
        .unwrap()
        .expect("durable queue must publish its exact journal binding");
    let adapter = VaultOfflineCache::new(adapter, destination_scope, ROOT_PATH).unwrap();
    let row = adapter
        .pending_operation(&destination_sessions, &write_id, revision)
        .unwrap();
    assert_eq!(row.operation, VaultPendingOperationKind::CopyFile);
    assert_eq!(row.state, CiphertextWriteState::NeverAttempted);
    assert!(
        destination_fixture
            .requests()
            .iter()
            .all(|request| request.method != "PUT")
    );
}

#[test]
fn cross_vault_copy_rejects_wrong_scope_generation_and_occupied_target_before_put() {
    let source_fixture = Fixture::start();
    let destination_fixture = Fixture::start();
    let (source, _source_sessions, source_scope, source_state, _) = setup_cached(&source_fixture);
    let (destination, _destination_sessions, destination_scope, dest_state, _) =
        setup_cached(&destination_fixture);
    let local = source_state.path().join("copy-source.bin");
    std::fs::write(&local, b"copy guard fixture").unwrap();
    let source_entry = source
        .upload(SPACE, "/source.txt", &local, WriteCondition::Absent)
        .unwrap();
    let root = destination.stat(SPACE, "/").unwrap();

    let baseline_puts = destination_fixture
        .requests()
        .iter()
        .filter(|request| request.method == "PUT")
        .count();
    let mut wrong_scope = copy_request(
        &source_scope,
        &destination_scope,
        &source_entry,
        &root,
        "/x.txt",
    );
    wrong_scope.destination_scope = VaultSessionScope::new(
        "different-account",
        destination_scope.server_origin(),
        SPACE,
        ROOT_ID,
    )
    .unwrap();
    assert!(source.copy_file_to(&destination, &wrong_scope).is_err());
    let mut stale_generation = copy_request(
        &source_scope,
        &destination_scope,
        &source_entry,
        &root,
        "/x.txt",
    );
    stale_generation.source_auth_generation += 1;
    assert!(
        source
            .copy_file_to(&destination, &stale_generation)
            .is_err()
    );
    assert_eq!(
        destination_fixture
            .requests()
            .iter()
            .filter(|request| request.method == "PUT")
            .count(),
        baseline_puts
    );

    let occupied = dest_state.path().join("occupied.bin");
    std::fs::write(&occupied, b"do not replace").unwrap();
    destination
        .upload(SPACE, "/x.txt", &occupied, WriteCondition::Absent)
        .unwrap();
    let before_copy_puts = destination_fixture
        .requests()
        .iter()
        .filter(|request| request.method == "PUT")
        .count();
    let result = source
        .copy_file_to(
            &destination,
            &copy_request(
                &source_scope,
                &destination_scope,
                &source_entry,
                &root,
                "/x.txt",
            ),
        )
        .unwrap_err();
    assert_eq!(result.kind, raiun_core::backend::ErrorKind::Conflict);
    assert_eq!(
        destination_fixture
            .requests()
            .iter()
            .filter(|request| request.method == "PUT")
            .count(),
        before_copy_puts,
        "occupied destinations must never be overwritten"
    );
}

#[test]
fn cross_vault_copy_refuses_stale_source_or_destination_generation_before_put() {
    for rotate_source in [true, false] {
        let source_fixture = Fixture::start();
        let destination_fixture = Fixture::start();
        let (source, _source_sessions, source_scope, source_state, _source_cache, source_client) =
            setup_cached_with_client(&source_fixture);
        let (
            destination,
            _destination_sessions,
            destination_scope,
            _destination_state,
            _destination_cache,
            destination_client,
        ) = setup_cached_with_client(&destination_fixture);
        let local = source_state.path().join("generation-source.bin");
        std::fs::write(&local, b"source remains available").unwrap();
        let source_entry = source
            .upload(SPACE, "/source.txt", &local, WriteCondition::Absent)
            .unwrap();
        let destination_root = destination.stat(SPACE, "/").unwrap();
        let mut request = copy_request(
            &source_scope,
            &destination_scope,
            &source_entry,
            &destination_root,
            "/copy.txt",
        );
        request.source_auth_generation = source_client.token_generation();
        request.destination_auth_generation = destination_client.token_generation();
        let puts_before = destination_fixture
            .requests()
            .iter()
            .filter(|record| record.method == "PUT")
            .count();
        if rotate_source {
            source_client
                .set_bearer_token("rotated-source-token".to_owned())
                .unwrap();
        } else {
            destination_client
                .set_bearer_token("rotated-destination-token".to_owned())
                .unwrap();
        }
        let error = source.copy_file_to(&destination, &request).unwrap_err();
        assert_eq!(error.kind, raiun_core::backend::ErrorKind::Conflict);
        assert_eq!(
            destination_fixture
                .requests()
                .iter()
                .filter(|record| record.method == "PUT")
                .count(),
            puts_before,
            "a stale source or destination generation must be rejected before PUT"
        );
    }
}

#[test]
fn cross_vault_copy_cancels_stalled_upload_when_either_scope_generation_rotates() {
    for rotate_source in [true, false] {
        let source_fixture = Fixture::start();
        let destination_fixture = Fixture::start();
        let (source, _source_sessions, source_scope, source_state, _source_cache, source_client) =
            setup_cached_with_client(&source_fixture);
        let upload_budget = TransferBudget::new();
        upload_budget.set_limits(TransferLimits {
            upload_bytes_per_second: NonZeroU64::new(128 * 1024),
            download_bytes_per_second: None,
        });
        let (
            destination,
            destination_sessions,
            destination_scope,
            _destination_state,
            destination_cache,
            destination_client,
        ) = setup_cached_with_client_and_budget(&destination_fixture, upload_budget);
        let local = source_state.path().join("large-generation-source.bin");
        let bytes = vec![0x5a; 4 * 1024 * 1024];
        std::fs::write(&local, &bytes).unwrap();
        let source_entry = source
            .upload(SPACE, "/large-source.bin", &local, WriteCondition::Absent)
            .unwrap();
        let destination_root = destination.stat(SPACE, "/").unwrap();
        let mut request = copy_request(
            &source_scope,
            &destination_scope,
            &source_entry,
            &destination_root,
            "/copy-large.bin",
        );
        request.source_auth_generation = source_client.token_generation();
        request.destination_auth_generation = destination_client.token_generation();
        let gate = destination_fixture.pause_next_copy_put_body();
        let worker = thread::spawn(move || source.copy_file_to(&destination, &request));
        assert!(
            gate.wait_for_body_prefix(&worker),
            "copy did not reach the upload gate; worker outcome: {:?}",
            worker.join()
        );
        if rotate_source {
            source_client
                .set_bearer_token("rotated-source-token".to_owned())
                .unwrap();
        } else {
            destination_client
                .set_bearer_token("rotated-destination-token".to_owned())
                .unwrap();
        }
        gate.release();
        let outcome = worker.join().unwrap().unwrap();
        let VaultCopyOutcome::NeedsReconciliation {
            write_id,
            revision,
            reason,
            ..
        } = outcome
        else {
            panic!("generation revocation during upload must not report copied")
        };
        assert_eq!(
            reason,
            VaultCopyReconciliationReason::AuthenticationGenerationChanged
        );
        assert!(
            destination_fixture
                .requests()
                .iter()
                .all(|record| record.method != "PUT"),
            "the stalled conditional request must be abandoned before a complete PUT reaches the fixture"
        );
        assert!(destination_fixture.state.lock().unwrap().child.is_none());
        let adapter =
            VaultOfflineCache::new(destination_cache, destination_scope, ROOT_PATH).unwrap();
        let row = adapter
            .pending_operation(&destination_sessions, &write_id, revision)
            .unwrap();
        assert_eq!(row.operation, VaultPendingOperationKind::CopyFile);
        assert_eq!(row.state, CiphertextWriteState::Uncertain);
        assert!(
            adapter
                .retryable_pending_edits(&destination_sessions, 10)
                .unwrap()
                .0
                .is_empty()
        );
    }
}

#[test]
fn cross_vault_copy_caller_cancellation_aborts_stalled_put_and_retains_journal() {
    {
        let source_fixture = Fixture::start();
        let destination_fixture = Fixture::start();
        let (source, _source_sessions, source_scope, source_state, _source_cache, source_client) =
            setup_cached_with_client(&source_fixture);
        let upload_budget = TransferBudget::new();
        upload_budget.set_limits(TransferLimits {
            upload_bytes_per_second: NonZeroU64::new(128 * 1024),
            download_bytes_per_second: None,
        });
        let (
            destination,
            destination_sessions,
            destination_scope,
            _destination_state,
            destination_cache,
            destination_client,
        ) = setup_cached_with_client_and_budget(&destination_fixture, upload_budget);
        let local = source_state.path().join("large-generation-source.bin");
        let bytes = vec![0x5a; 4 * 1024 * 1024];
        std::fs::write(&local, &bytes).unwrap();
        let source_entry = source
            .upload(SPACE, "/large-source.bin", &local, WriteCondition::Absent)
            .unwrap();
        let destination_root = destination.stat(SPACE, "/").unwrap();
        let mut request = copy_request(
            &source_scope,
            &destination_scope,
            &source_entry,
            &destination_root,
            "/copy-large.bin",
        );
        request.source_auth_generation = source_client.token_generation();
        request.destination_auth_generation = destination_client.token_generation();
        let gate = destination_fixture.pause_next_copy_put_body();
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let published_binding = Arc::new(Mutex::new(None));
        let worker_binding = Arc::clone(&published_binding);
        let started = std::time::Instant::now();
        let worker = thread::spawn(move || {
            source.copy_file_to_cancellable_with_binding(
                &destination,
                &request,
                &|| worker_cancelled.load(Ordering::Acquire),
                |write_id, revision| {
                    *worker_binding.lock().unwrap() = Some((write_id.to_owned(), revision));
                },
            )
        });

        assert!(
            gate.wait_for_body_prefix(&worker),
            "copy did not reach the upload gate; worker outcome: {:?}",
            worker.join()
        );
        cancelled.store(true, Ordering::Release);
        gate.release();
        let outcome = worker.join().unwrap().unwrap();
        let published_binding = published_binding.lock().unwrap().clone().unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "cancellation must abort the rate-limited PUT promptly"
        );
        let VaultCopyOutcome::NeedsReconciliation {
            write_id,
            revision,
            reason,
            ..
        } = outcome
        else {
            panic!("caller cancellation during upload must not report copied")
        };
        assert_eq!(
            reason,
            VaultCopyReconciliationReason::DestinationCreateUncertain
        );
        assert_eq!(published_binding, (write_id.clone(), revision));
        assert!(
            destination_fixture
                .requests()
                .iter()
                .all(|record| record.method != "PUT"),
            "the stalled conditional request must be abandoned before a complete PUT reaches the fixture"
        );
        assert!(destination_fixture.state.lock().unwrap().child.is_none());
        let adapter =
            VaultOfflineCache::new(destination_cache, destination_scope, ROOT_PATH).unwrap();
        let row = adapter
            .pending_operation(&destination_sessions, &write_id, revision)
            .unwrap();
        assert_eq!(row.operation, VaultPendingOperationKind::CopyFile);
        assert_eq!(row.state, CiphertextWriteState::Uncertain);
        assert!(
            adapter
                .retryable_pending_edits(&destination_sessions, 10)
                .unwrap()
                .0
                .is_empty()
        );
    }
}

#[test]
fn cross_vault_copy_retains_journal_on_lost_put_or_failed_decrypt_readback() {
    for corrupt_readback in [false, true] {
        let source_fixture = Fixture::start();
        let destination_fixture = Fixture::start();
        let (source, _source_sessions, source_scope, source_state, _) =
            setup_cached(&source_fixture);
        let (destination, dest_sessions, destination_scope, _dest_state, dest_cache) =
            setup_cached(&destination_fixture);
        let local = source_state.path().join("copy-source.bin");
        std::fs::write(&local, b"preserve source after uncertain copy").unwrap();
        let source_entry = source
            .upload(SPACE, "/source.txt", &local, WriteCondition::Absent)
            .unwrap();
        let root = destination.stat(SPACE, "/").unwrap();
        if corrupt_readback {
            destination_fixture.corrupt_download();
        } else {
            destination_fixture.lose_put_response();
        }

        let outcome = source
            .copy_file_to(
                &destination,
                &copy_request(
                    &source_scope,
                    &destination_scope,
                    &source_entry,
                    &root,
                    "/copied.txt",
                ),
            )
            .unwrap();
        let VaultCopyOutcome::NeedsReconciliation {
            destination_path,
            write_id,
            revision,
            reason,
            ..
        } = outcome
        else {
            panic!("ambiguous or corrupt copy must not be reported complete")
        };
        assert_eq!(destination_path, "/copied.txt");
        assert_eq!(
            reason,
            if corrupt_readback {
                VaultCopyReconciliationReason::DestinationReadbackUnavailable
            } else {
                VaultCopyReconciliationReason::DestinationCreateUncertain
            }
        );
        let cache_adapter =
            VaultOfflineCache::new(dest_cache, destination_scope, ROOT_PATH).unwrap();
        let row = cache_adapter
            .pending_operation(&dest_sessions, &write_id, revision)
            .unwrap();
        assert_eq!(row.operation, VaultPendingOperationKind::CopyFile);
        assert_eq!(row.state, CiphertextWriteState::Uncertain);
        assert!(
            cache_adapter
                .retryable_pending_edits(&dest_sessions, 10)
                .unwrap()
                .0
                .is_empty(),
            "copy journals must never enter generic auto-retry"
        );
        let put_count = destination_fixture
            .requests()
            .iter()
            .filter(|request| request.method == "PUT")
            .count();
        assert!(
            destination
                .reconcile_pending_operation(&write_id, revision)
                .is_err(),
            "generic create reconciliation must not complete a copy journal"
        );
        assert_eq!(
            destination_fixture
                .requests()
                .iter()
                .filter(|request| request.method == "PUT")
                .count(),
            put_count,
            "generic reconciliation must not issue another copy PUT"
        );
        assert!(
            source_fixture
                .requests()
                .iter()
                .all(|request| request.method != "DELETE" && request.method != "MOVE")
        );
    }
}

#[test]
fn cross_vault_copy_lost_response_resolves_after_cache_reopen_without_mutation() {
    let source_fixture = Fixture::start();
    let destination_fixture = Fixture::start();
    let (source, _source_sessions, source_scope, source_state, _, source_client) =
        setup_cached_with_client(&source_fixture);
    let (
        destination,
        destination_sessions,
        destination_scope,
        destination_state,
        _old_cache,
        destination_client,
    ) = setup_cached_with_client(&destination_fixture);
    let bytes = b"copy journal survives process restart";
    let local = source_state.path().join("copy-source.bin");
    std::fs::write(&local, bytes).unwrap();
    let source_entry = source
        .upload(SPACE, "/source.txt", &local, WriteCondition::Absent)
        .unwrap();
    let root = destination.stat(SPACE, "/").unwrap();
    destination_fixture.lose_put_response();
    let outcome = source
        .copy_file_to(
            &destination,
            &copy_request(
                &source_scope,
                &destination_scope,
                &source_entry,
                &root,
                "/copied.txt",
            ),
        )
        .unwrap();
    let VaultCopyOutcome::NeedsReconciliation {
        write_id, revision, ..
    } = outcome
    else {
        panic!("lost PUT response must remain unresolved")
    };
    assert_tree_does_not_contain(
        destination_state.path(),
        &[
            b"/source.txt",
            b"child-resource-id",
            b"\"child-rev-2\"",
            source_scope.server_origin().as_bytes(),
        ],
    );
    let before = destination_fixture.requests();
    let puts_before = before
        .iter()
        .filter(|request| request.method == "PUT")
        .count();
    let deletes_before = before
        .iter()
        .filter(|request| matches!(request.method.as_str(), "DELETE" | "MOVE"))
        .count();

    // Reopen the exact destination cache as a fresh process would. The source
    // and destination sessions stay independently unlocked, but their runtime
    // token generations are captured anew by the resolver.
    let reopened = Cache::open(destination_state.path(), 16 * 1024 * 1024).unwrap();
    let reopened_adapter =
        VaultOfflineCache::new(reopened, destination_scope.clone(), ROOT_PATH).unwrap();
    let destination_client_for_rotation = destination_client.clone();
    let reopened_destination = VaultBackend::new_with_offline_cache(
        destination_client,
        Arc::clone(&destination_sessions),
        destination_scope.clone(),
        ROOT_PATH.to_owned(),
        reopened_adapter,
    )
    .unwrap();
    // A fresh process uses fresh token generations even when the credential is
    // unchanged. The sealed source binding contains no reusable generation.
    source_client
        .set_bearer_token("synthetic-token".to_owned())
        .unwrap();
    destination_client_for_rotation
        .set_bearer_token("synthetic-token".to_owned())
        .unwrap();
    let resolved = source
        .resolve_pending_copy_to(&reopened_destination, &write_id, revision)
        .unwrap();
    let VaultCopyResolutionOutcome::Verified {
        destination: verified,
        plaintext_len,
        plaintext_sha256,
    } = resolved
    else {
        panic!("matching source and destination should resolve as verified")
    };
    assert_eq!(verified.path, "/copied.txt");
    assert_eq!(plaintext_len, bytes.len() as u64);
    assert_eq!(plaintext_sha256, format!("{:x}", Sha256::digest(bytes)));
    let reopened_cache = Cache::open(destination_state.path(), 16 * 1024 * 1024).unwrap();
    let reopened_adapter =
        VaultOfflineCache::new(reopened_cache, destination_scope, ROOT_PATH).unwrap();
    assert!(
        reopened_adapter
            .pending_operation(&destination_sessions, &write_id, revision)
            .is_err()
    );
    let after = destination_fixture.requests();
    assert_eq!(
        after
            .iter()
            .filter(|request| request.method == "PUT")
            .count(),
        puts_before,
        "copy resolution must never replay PUT"
    );
    assert_eq!(
        after
            .iter()
            .filter(|request| matches!(request.method.as_str(), "DELETE" | "MOVE"))
            .count(),
        deletes_before,
        "copy resolution must not delete or move either side"
    );
    assert!(
        source_fixture
            .requests()
            .iter()
            .all(|request| !matches!(request.method.as_str(), "DELETE" | "MOVE"))
    );
}

#[test]
fn cross_vault_copy_resolution_requires_exact_unlocked_source_scope() {
    let source_fixture = Fixture::start();
    let destination_fixture = Fixture::start();
    let other_fixture = Fixture::start();
    let (source, _source_sessions, source_scope, source_state, _) = setup_cached(&source_fixture);
    let (other_source, _other_sessions, _, _, _) = setup_cached(&other_fixture);
    let (
        destination,
        destination_sessions,
        destination_scope,
        destination_state,
        destination_cache,
        _destination_client,
    ) = setup_cached_with_client(&destination_fixture);
    let local = source_state.path().join("source.txt");
    std::fs::write(&local, b"scope-bound source bytes").unwrap();
    let source_entry = source
        .upload(SPACE, "/source.txt", &local, WriteCondition::Absent)
        .unwrap();
    let root = destination.stat(SPACE, "/").unwrap();
    destination_fixture.lose_put_response();
    let VaultCopyOutcome::NeedsReconciliation {
        write_id, revision, ..
    } = source
        .copy_file_to(
            &destination,
            &copy_request(
                &source_scope,
                &destination_scope,
                &source_entry,
                &root,
                "/copied.txt",
            ),
        )
        .unwrap()
    else {
        panic!("lost response must remain unresolved")
    };

    let before = destination_fixture.requests();
    let wrong_scope = other_source
        .resolve_pending_copy_to(&destination, &write_id, revision)
        .unwrap();
    assert!(matches!(
        wrong_scope,
        VaultCopyResolutionOutcome::NeedsReview {
            reason: VaultCopyResolutionReason::SourceScopeMismatch,
            ..
        }
    ));

    // A backend with the exact scope but no unlocked key cannot inspect or
    // retire the sealed journal. It causes no DAV request.
    destination_sessions.lock(&destination_scope).unwrap();
    assert!(
        source
            .resolve_pending_copy_to(&destination, &write_id, revision)
            .is_err()
    );
    let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim();
    let mut password = b"potato".to_vec();
    destination_sessions
        .unlock(&destination_scope, &mut password, token)
        .unwrap();
    let after = destination_fixture.requests();
    assert_eq!(
        before.len(),
        after.len(),
        "scope/key rejection must be read-only"
    );
    assert_eq!(
        after
            .iter()
            .filter(|request| request.method == "PUT")
            .count(),
        1,
        "resolver must never retry a copy"
    );
    let adapter = VaultOfflineCache::new(destination_cache, destination_scope, ROOT_PATH).unwrap();
    assert_eq!(
        adapter
            .pending_operation(&destination_sessions, &write_id, revision)
            .unwrap()
            .state,
        CiphertextWriteState::Uncertain
    );
    assert!(destination_state.path().exists());
}

#[test]
fn cross_vault_copy_cancellation_at_completion_admission_preserves_journal() {
    let source_fixture = Fixture::start();
    let destination_fixture = Fixture::start();
    let (source, _source_sessions, source_scope, source_state, _) = setup_cached(&source_fixture);
    let (
        destination,
        destination_sessions,
        destination_scope,
        _destination_state,
        destination_cache,
    ) = setup_cached(&destination_fixture);
    let local = source_state.path().join("completion-admission-source.txt");
    std::fs::write(&local, b"copy completion admission fixture").unwrap();
    let source_entry = source
        .upload(SPACE, "/source.txt", &local, WriteCondition::Absent)
        .unwrap();
    let destination_root = destination.stat(SPACE, "/").unwrap();
    destination_fixture.lose_put_response();
    let VaultCopyOutcome::NeedsReconciliation {
        write_id, revision, ..
    } = source
        .copy_file_to(
            &destination,
            &copy_request(
                &source_scope,
                &destination_scope,
                &source_entry,
                &destination_root,
                "/copied.txt",
            ),
        )
        .unwrap()
    else {
        panic!("lost response must leave a copy journal row")
    };
    destination_fixture.restore_put_responses();
    let requests_before_resolution = destination_fixture.requests();
    let puts_before = requests_before_resolution
        .iter()
        .filter(|request| request.method == "PUT")
        .count();
    let cancelled = AtomicBool::new(false);
    let result = source.resolve_pending_copy_to_cancellable_with_hook(
        &destination,
        &write_id,
        revision,
        || cancelled.load(Ordering::Acquire),
        || cancelled.store(true, Ordering::Release),
    );
    assert!(
        result.is_err(),
        "cancellation must suppress local retirement"
    );

    let adapter = VaultOfflineCache::new(destination_cache, destination_scope, ROOT_PATH).unwrap();
    let row = adapter
        .pending_operation(&destination_sessions, &write_id, revision)
        .unwrap();
    assert_eq!(row.state, CiphertextWriteState::Uncertain);
    let after = destination_fixture.requests();
    assert_eq!(
        after
            .iter()
            .filter(|request| request.method == "PUT")
            .count(),
        puts_before,
        "read-only verification must never issue a second PUT"
    );
    assert!(
        after
            .iter()
            .all(|request| !matches!(request.method.as_str(), "DELETE" | "MOVE"))
    );
    assert!(
        source_fixture
            .requests()
            .iter()
            .all(|request| !matches!(request.method.as_str(), "DELETE" | "MOVE"))
    );
}

#[test]
fn copy_verification_backend_binds_from_cached_root_without_network_probe() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, _state, cache, client) = setup_cached_with_client(&fixture);
    backend.list(SPACE, "/", &mut |_| Ok(())).unwrap();
    let before = fixture.requests().len();
    let adapter = VaultOfflineCache::new(cache, scope.clone(), ROOT_PATH).unwrap();
    let _verifier = VaultBackend::new_for_copy_verification(
        client,
        sessions,
        scope,
        ROOT_PATH.to_owned(),
        adapter,
    )
    .unwrap();
    assert_eq!(fixture.requests().len(), before);
}

#[test]
fn cross_vault_copy_resolution_cancels_delayed_content_read() {
    let source_fixture = Fixture::start();
    let destination_fixture = Fixture::start();
    let (source, _source_sessions, source_scope, source_state, _) = setup_cached(&source_fixture);
    let (
        destination,
        destination_sessions,
        destination_scope,
        _destination_state,
        destination_cache,
    ) = setup_cached(&destination_fixture);
    let local = source_state.path().join("cancel-content-read-source.txt");
    std::fs::write(&local, b"cancel during remote content verification").unwrap();
    let source_entry = source
        .upload(SPACE, "/source.txt", &local, WriteCondition::Absent)
        .unwrap();
    let destination_root = destination.stat(SPACE, "/").unwrap();
    destination_fixture.lose_put_response();
    let VaultCopyOutcome::NeedsReconciliation {
        write_id, revision, ..
    } = source
        .copy_file_to(
            &destination,
            &copy_request(
                &source_scope,
                &destination_scope,
                &source_entry,
                &destination_root,
                "/copied.txt",
            ),
        )
        .unwrap()
    else {
        panic!("lost response must leave a copy journal row")
    };
    destination_fixture.restore_put_responses();
    let baseline = destination_fixture.requests().len();
    let puts_before = destination_fixture
        .requests()
        .iter()
        .filter(|request| request.method == "PUT")
        .count();
    destination_fixture.delay_get(500);
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let worker_write_id = write_id.clone();
    let worker = thread::spawn(move || {
        source.resolve_pending_copy_to_cancellable(&destination, &worker_write_id, revision, || {
            worker_cancelled.load(Ordering::Acquire)
        })
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if destination_fixture.requests()[baseline..]
            .iter()
            .any(|request| request.method == "GET")
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "resolver GET did not start"
        );
        thread::sleep(Duration::from_millis(2));
    }
    cancelled.store(true, Ordering::Release);
    let result = worker.join().unwrap().unwrap();
    assert!(matches!(
        result,
        VaultCopyResolutionOutcome::NeedsReview { .. }
    ));

    let adapter = VaultOfflineCache::new(destination_cache, destination_scope, ROOT_PATH).unwrap();
    let row = adapter
        .pending_operation(&destination_sessions, &write_id, revision)
        .unwrap();
    assert_eq!(row.state, CiphertextWriteState::Uncertain);
    let requests = destination_fixture.requests();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "PUT")
            .count(),
        puts_before,
        "cancelled resolution must not replay PUT"
    );
    assert!(
        requests
            .iter()
            .all(|request| !matches!(request.method.as_str(), "DELETE" | "MOVE"))
    );
}

#[test]
fn cross_vault_copy_resolution_keeps_changed_source_or_destination_for_review() {
    for mutate_source in [true, false] {
        let source_fixture = Fixture::start();
        let destination_fixture = Fixture::start();
        let (source, source_sessions, source_scope, source_state, _) =
            setup_cached(&source_fixture);
        let (
            destination,
            destination_sessions,
            destination_scope,
            _destination_state,
            destination_cache,
        ) = setup_cached(&destination_fixture);
        let original = source_state.path().join("source.txt");
        std::fs::write(&original, b"original bytes for copy").unwrap();
        let source_entry = source
            .upload(SPACE, "/source.txt", &original, WriteCondition::Absent)
            .unwrap();
        let root = destination.stat(SPACE, "/").unwrap();
        destination_fixture.lose_put_response();
        let VaultCopyOutcome::NeedsReconciliation {
            write_id, revision, ..
        } = source
            .copy_file_to(
                &destination,
                &copy_request(
                    &source_scope,
                    &destination_scope,
                    &source_entry,
                    &root,
                    "/copied.txt",
                ),
            )
            .unwrap()
        else {
            panic!("lost response must remain unresolved")
        };
        destination_fixture.restore_put_responses();
        if mutate_source {
            std::fs::write(&original, b"changed source bytes").unwrap();
            source
                .upload(
                    SPACE,
                    "/source.txt",
                    &original,
                    WriteCondition::Match(source_entry.etag.clone()),
                )
                .unwrap();
        } else {
            destination_fixture
                .replace_child_cipher_without_etag(b"damaged remote ciphertext".to_vec());
        }
        let requests_before_resolution = destination_fixture.requests();
        let puts_before = requests_before_resolution
            .iter()
            .filter(|request| request.method == "PUT")
            .count();
        let expected_reason = if mutate_source {
            VaultCopyResolutionReason::SourceChanged
        } else {
            VaultCopyResolutionReason::VerificationUnavailable
        };
        let result = source
            .resolve_pending_copy_to(&destination, &write_id, revision)
            .unwrap();
        assert!(matches!(
            result,
            VaultCopyResolutionOutcome::NeedsReview { reason, .. } if reason == expected_reason
        ));
        assert_eq!(
            destination_fixture
                .requests()
                .iter()
                .filter(|request| request.method == "PUT")
                .count(),
            puts_before,
            "failed verification must not issue another PUT"
        );
        assert!(
            destination_fixture
                .requests()
                .iter()
                .all(|request| !matches!(request.method.as_str(), "DELETE" | "MOVE"))
        );
        assert!(
            source_fixture
                .requests()
                .iter()
                .all(|request| !matches!(request.method.as_str(), "DELETE" | "MOVE"))
        );
        let adapter =
            VaultOfflineCache::new(destination_cache, destination_scope, ROOT_PATH).unwrap();
        let row = adapter
            .pending_operation(&destination_sessions, &write_id, revision)
            .unwrap();
        assert_eq!(row.operation, VaultPendingOperationKind::CopyFile);
        assert_eq!(row.state, CiphertextWriteState::Uncertain);
        let _ = source_sessions;
    }
}

#[test]
fn cross_vault_copy_resolution_stops_when_either_auth_generation_rotates_in_body() {
    for rotate_source in [true, false] {
        let source_fixture = Fixture::start();
        let destination_fixture = Fixture::start();
        let (source, _source_sessions, source_scope, source_state, _, source_client) =
            setup_cached_with_client(&source_fixture);
        let (
            destination,
            destination_sessions,
            destination_scope,
            _destination_state,
            destination_cache,
            destination_client,
        ) = setup_cached_with_client(&destination_fixture);
        let local = source_state.path().join("resolution-generation-source.txt");
        std::fs::write(&local, b"copy binding survives token replacement").unwrap();
        let source_entry = source
            .upload(SPACE, "/source.txt", &local, WriteCondition::Absent)
            .unwrap();
        let destination_root = destination.stat(SPACE, "/").unwrap();
        destination_fixture.lose_put_response();
        let VaultCopyOutcome::NeedsReconciliation {
            write_id, revision, ..
        } = source
            .copy_file_to(
                &destination,
                &copy_request(
                    &source_scope,
                    &destination_scope,
                    &source_entry,
                    &destination_root,
                    "/copy.txt",
                ),
            )
            .unwrap()
        else {
            panic!("lost PUT response must remain unresolved")
        };
        let fixture = if rotate_source {
            &source_fixture
        } else {
            &destination_fixture
        };
        let before_resolution = fixture.requests();
        let baseline = before_resolution.len();
        let destination_puts_before = destination_fixture
            .requests()
            .iter()
            .filter(|request| request.method == "PUT")
            .count();
        fixture.delay_get(500);
        let resolver_write_id = write_id.clone();
        let worker = thread::spawn(move || {
            source.resolve_pending_copy_to(&destination, &resolver_write_id, revision)
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let requests = fixture.requests();
            if requests[baseline..]
                .iter()
                .any(|request| request.method == "GET" && request.target.starts_with("/dav/"))
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "copy resolver did not start its bounded content GET"
            );
            thread::sleep(Duration::from_millis(2));
        }
        if rotate_source {
            source_client
                .set_bearer_token("rotated-resolution-source-token".to_owned())
                .unwrap();
        } else {
            destination_client
                .set_bearer_token("rotated-resolution-destination-token".to_owned())
                .unwrap();
        }
        let result = worker.join().unwrap().unwrap();
        assert!(matches!(
            result,
            VaultCopyResolutionOutcome::NeedsReview {
                reason: VaultCopyResolutionReason::AuthenticationGenerationChanged,
                ..
            }
        ));
        let adapter =
            VaultOfflineCache::new(destination_cache, destination_scope, ROOT_PATH).unwrap();
        assert_eq!(
            adapter
                .pending_operation(&destination_sessions, &write_id, revision)
                .unwrap()
                .state,
            CiphertextWriteState::Uncertain
        );
        let puts_after = destination_fixture
            .requests()
            .iter()
            .filter(|request| request.method == "PUT")
            .count();
        assert_eq!(
            destination_puts_before, puts_after,
            "token revocation during readback must not dispatch a retry"
        );
        assert!(
            destination_fixture
                .requests()
                .iter()
                .all(|request| !matches!(request.method.as_str(), "DELETE" | "MOVE"))
        );
    }
}

#[test]
fn cross_vault_copy_keeps_committed_but_mismatching_readback_for_reconciliation() {
    let source_fixture = Fixture::start();
    let destination_fixture = Fixture::start();
    let (source, _source_sessions, source_scope, source_state, _) = setup_cached(&source_fixture);
    let (destination, destination_sessions, destination_scope, dest_state, dest_cache) =
        setup_cached(&destination_fixture);
    let source_bytes = b"copy-body";
    let alternate_bytes = b"evil-body";
    assert_eq!(source_bytes.len(), alternate_bytes.len());
    let local = source_state.path().join("copy-source.bin");
    std::fs::write(&local, source_bytes).unwrap();
    let source_entry = source
        .upload(SPACE, "/source.txt", &local, WriteCondition::Absent)
        .unwrap();
    let root = destination.stat(SPACE, "/").unwrap();

    let alternate_path = dest_state.path().join("alternate-ciphertext.bin");
    let mut alternate = Cursor::new(alternate_bytes);
    destination_sessions
        .encrypt_file_transactional(
            &destination_scope,
            &mut alternate,
            &alternate_path,
            alternate_bytes.len() as u64,
            alternate_bytes.len() as u64,
        )
        .unwrap();
    destination_fixture.replace_next_put_body(std::fs::read(alternate_path).unwrap());

    let outcome = source
        .copy_file_to(
            &destination,
            &copy_request(
                &source_scope,
                &destination_scope,
                &source_entry,
                &root,
                "/copy.txt",
            ),
        )
        .unwrap();
    let VaultCopyOutcome::NeedsReconciliation {
        write_id,
        revision,
        reason,
        destination_resource_id,
        destination_etag,
        ..
    } = outcome
    else {
        panic!("different decrypted readback must not be reported copied")
    };
    assert_eq!(
        reason,
        VaultCopyReconciliationReason::DestinationReadbackMismatch
    );
    assert!(destination_resource_id.is_some());
    assert!(destination_etag.is_some());
    let adapter = VaultOfflineCache::new(dest_cache, destination_scope, ROOT_PATH).unwrap();
    assert_eq!(
        adapter
            .pending_operation(&destination_sessions, &write_id, revision)
            .unwrap()
            .state,
        CiphertextWriteState::Uncertain
    );
    assert!(
        source_fixture
            .requests()
            .iter()
            .all(|request| request.method != "DELETE" && request.method != "MOVE")
    );
}

#[test]
fn cross_vault_copy_rejects_a_source_changed_during_conditional_read() {
    let source_fixture = Fixture::start();
    let destination_fixture = Fixture::start();
    let (source, _source_sessions, source_scope, source_state, _) = setup_cached(&source_fixture);
    let (destination, _destination_sessions, destination_scope, _dest_state, _) =
        setup_cached(&destination_fixture);
    let local = source_state.path().join("copy-source.bin");
    std::fs::write(&local, b"source changes during the get").unwrap();
    let source_entry = source
        .upload(SPACE, "/source.txt", &local, WriteCondition::Absent)
        .unwrap();
    let root = destination.stat(SPACE, "/").unwrap();
    source_fixture.delay_get(150);
    let mutate_state = Arc::clone(&source_fixture.state);
    let mutate_fixture = Arc::clone(&source_fixture.state);
    let mutation = thread::spawn(move || {
        for _ in 0..500 {
            if mutate_fixture
                .lock()
                .unwrap()
                .requests
                .iter()
                .any(|request| request.method == "GET" && request.target.starts_with("/dav/"))
            {
                let mut state = mutate_state.lock().unwrap();
                state.etag_version = state.etag_version.saturating_add(1);
                return;
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("source content GET was not observed");
    });
    let result = source.copy_file_to(
        &destination,
        &copy_request(
            &source_scope,
            &destination_scope,
            &source_entry,
            &root,
            "/copy.txt",
        ),
    );
    mutation.join().unwrap();
    assert!(result.is_err());
    assert!(
        !destination_fixture
            .requests()
            .iter()
            .any(|request| request.method == "PUT")
    );
    assert!(
        source_fixture
            .requests()
            .iter()
            .all(|request| request.method != "DELETE" && request.method != "MOVE")
    );
}

fn encrypted_cache_scope(scope: &VaultSessionScope) -> CacheScope {
    CacheScope::new(
        scope.server_origin(),
        scope.account_id(),
        scope.space_id(),
        scope.resource_id(),
        ScopeProtection::CiphertextOnly,
    )
    .unwrap()
}

#[test]
fn encrypted_existing_file_edit_queues_offline_then_reconciles_after_readback() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, state_dir, cache) = setup_cached(&fixture);

    let mut original = NamedTempFile::new().unwrap();
    original.write_all(b"original remote body").unwrap();
    original.flush().unwrap();
    let base = backend
        .upload(SPACE, "/notes.txt", original.path(), WriteCondition::Absent)
        .unwrap();
    let mut listing = Vec::new();
    backend
        .list(SPACE, "/", &mut |entry| {
            listing.push(entry);
            Ok(())
        })
        .unwrap();
    let baseline_path = state_dir.path().join("baseline.bin");
    backend
        .download(SPACE, "/notes.txt", Some(&base.etag), &baseline_path)
        .unwrap();

    let encoded = backend
        .prepare_write_target("/notes.txt", &WriteCondition::Match(base.etag.clone()))
        .unwrap();
    fixture.disconnect(true);
    let replacement_bytes = b"replacement written offline";
    let mut replacement = std::io::Cursor::new(replacement_bytes.to_vec());
    let outcome = backend
        .upload_prepared_reader_with_queue(
            &encoded,
            &mut replacement,
            replacement_bytes.len() as u64,
            WriteCondition::Match(base.etag),
            None,
        )
        .unwrap();
    let (write_id, revision, pending_etag) = match outcome {
        raiun_opencloud::vault_backend::VaultUploadOutcome::Queued {
            entry,
            write_id,
            revision,
            uncertain,
        } => {
            assert!(
                !uncertain,
                "no PUT was attempted after root validation failed"
            );
            (write_id, revision, entry.etag)
        }
        raiun_opencloud::vault_backend::VaultUploadOutcome::Committed(_) => {
            panic!("disconnected edit must remain queued")
        }
        raiun_opencloud::vault_backend::VaultUploadOutcome::BuildingCreate { .. }
        | raiun_opencloud::vault_backend::VaultUploadOutcome::QueuedCreate { .. } => {
            panic!("overwrite must not produce a create outcome")
        }
    };

    let pending = backend.stat(SPACE, "/notes.txt").unwrap();
    assert_eq!(pending.etag, pending_etag);
    assert_eq!(pending.size, replacement_bytes.len() as u64);
    let mut refreshed = Vec::new();
    backend
        .list(SPACE, "/", &mut |entry| {
            refreshed.push(entry);
            Ok(())
        })
        .unwrap();
    assert_eq!(refreshed[0].etag, pending_etag);
    let pending_path = state_dir.path().join("pending.bin");
    backend
        .download(SPACE, "/notes.txt", Some(&pending_etag), &pending_path)
        .unwrap();
    assert_eq!(std::fs::read(&pending_path).unwrap(), replacement_bytes);

    fixture.disconnect(false);
    let reconciled = backend.reconcile_pending_edit(&write_id, revision).unwrap();
    assert_ne!(reconciled.etag, pending_etag);
    let verified_path = state_dir.path().join("verified.bin");
    backend
        .download(SPACE, "/notes.txt", Some(&reconciled.etag), &verified_path)
        .unwrap();
    assert_eq!(std::fs::read(&verified_path).unwrap(), replacement_bytes);
    let journal = VaultOfflineCache::new(cache, scope.clone(), ROOT_PATH).unwrap();
    assert!(
        journal
            .pending_edit(&sessions, &write_id, revision)
            .is_err()
    );
    assert_eq!(listing.len(), 1);
    assert_eq!(scope.resource_id(), ROOT_ID);
}

#[test]
fn encrypted_offline_edit_conflict_keeps_the_complete_local_revision() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, state_dir, cache) = setup_cached(&fixture);
    let mut original = NamedTempFile::new().unwrap();
    original.write_all(b"base body").unwrap();
    original.flush().unwrap();
    let base = backend
        .upload(SPACE, "/notes.txt", original.path(), WriteCondition::Absent)
        .unwrap();
    let mut entries = Vec::new();
    backend
        .list(SPACE, "/", &mut |entry| {
            entries.push(entry);
            Ok(())
        })
        .unwrap();
    let baseline = state_dir.path().join("base.bin");
    backend
        .download(SPACE, "/notes.txt", Some(&base.etag), &baseline)
        .unwrap();
    let target = backend
        .prepare_write_target("/notes.txt", &WriteCondition::Match(base.etag.clone()))
        .unwrap();

    fixture.disconnect(true);
    let local_bytes = b"offline copy that must survive a conflict";
    let mut local = std::io::Cursor::new(local_bytes.to_vec());
    let queued = backend
        .upload_prepared_reader_with_queue(
            &target,
            &mut local,
            local_bytes.len() as u64,
            WriteCondition::Match(base.etag.clone()),
            None,
        )
        .unwrap();
    let raiun_opencloud::vault_backend::VaultUploadOutcome::Queued {
        write_id, revision, ..
    } = queued
    else {
        panic!("disconnected edit must be queued")
    };

    fixture.disconnect(false);
    let mut competing = NamedTempFile::new().unwrap();
    competing.write_all(b"a different remote update").unwrap();
    competing.flush().unwrap();
    backend
        .upload(
            SPACE,
            "/notes.txt",
            competing.path(),
            WriteCondition::Match(base.etag),
        )
        .unwrap();
    assert_eq!(
        backend
            .reconcile_pending_edit(&write_id, revision)
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict
    );
    let journal = VaultOfflineCache::new(cache, scope.clone(), ROOT_PATH).unwrap();
    let metadata = journal
        .pending_edit(&sessions, &write_id, revision)
        .unwrap();
    assert_eq!(metadata.state, CiphertextWriteState::Conflict);
    let recovery_path = state_dir.path().join("recoverable.bin");
    journal
        .download_pending_edit(&sessions, &write_id, revision, &recovery_path)
        .unwrap();
    assert_eq!(std::fs::read(&recovery_path).unwrap(), local_bytes);
    assert_eq!(entries.len(), 1);
}

#[test]
fn cached_root_backend_queues_only_overwrites_and_denies_new_files() {
    let fixture = Fixture::start();
    let (backend, _sessions, scope, state_dir, cache) = setup_cached(&fixture);
    let mut original = NamedTempFile::new().unwrap();
    original.write_all(b"cached base").unwrap();
    original.flush().unwrap();
    let base = backend
        .upload(SPACE, "/notes.txt", original.path(), WriteCondition::Absent)
        .unwrap();
    let mut entries = Vec::new();
    backend
        .list(SPACE, "/", &mut |entry| {
            entries.push(entry);
            Ok(())
        })
        .unwrap();
    let baseline = state_dir.path().join("base.bin");
    backend
        .download(SPACE, "/notes.txt", Some(&base.etag), &baseline)
        .unwrap();

    let offline_cache = VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH).unwrap();
    let offline_sessions = Arc::new(VaultSessionCoordinator::new());
    let mut password = b"potato".to_vec();
    let (snapshot, _) = offline_cache
        .unlock_root(&offline_sessions, &mut password)
        .unwrap();
    let offline = VaultBackend::new_from_cached_root(
        OpenCloudClient::new(&fixture.origin(), "synthetic-token".to_owned()).unwrap(),
        Arc::clone(&offline_sessions),
        scope.clone(),
        ROOT_PATH.to_owned(),
        offline_cache,
        snapshot,
    )
    .unwrap();
    assert!(
        offline.stat(SPACE, "/").unwrap().writable,
        "sealed permission hints allow the FUSE layer to queue local file creates"
    );
    let encoded = offline
        .prepare_write_target("/notes.txt", &WriteCondition::Match(base.etag.clone()))
        .unwrap();
    assert_eq!(
        offline
            .prepare_write_target("/new.txt", &WriteCondition::Absent)
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Unsupported
    );
    let local_bytes = b"offline-only route edit";
    let mut source = std::io::Cursor::new(local_bytes.to_vec());
    let outcome = offline
        .upload_prepared_reader_with_queue(
            &encoded,
            &mut source,
            local_bytes.len() as u64,
            WriteCondition::Match(base.etag),
            None,
        )
        .unwrap();
    let raiun_opencloud::vault_backend::VaultUploadOutcome::Queued {
        entry,
        uncertain: false,
        ..
    } = outcome
    else {
        panic!("offline-only route must queue the overwrite")
    };
    let path = state_dir.path().join("offline-read.bin");
    offline
        .download(SPACE, "/notes.txt", Some(&entry.etag), &path)
        .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), local_bytes);
    assert_eq!(entries.len(), 1);
}

#[test]
fn later_online_edit_retires_prior_queue_only_after_content_readback() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, state_dir, cache) = setup_cached(&fixture);
    let mut original = NamedTempFile::new().unwrap();
    original.write_all(b"online base").unwrap();
    original.flush().unwrap();
    let base = backend
        .upload(SPACE, "/notes.txt", original.path(), WriteCondition::Absent)
        .unwrap();
    let mut listing = Vec::new();
    backend
        .list(SPACE, "/", &mut |entry| {
            listing.push(entry);
            Ok(())
        })
        .unwrap();
    let baseline = state_dir.path().join("base.bin");
    backend
        .download(SPACE, "/notes.txt", Some(&base.etag), &baseline)
        .unwrap();
    let target = backend
        .prepare_write_target("/notes.txt", &WriteCondition::Match(base.etag.clone()))
        .unwrap();

    fixture.disconnect(true);
    let queued_bytes = b"offline first revision";
    let mut queued_source = std::io::Cursor::new(queued_bytes.to_vec());
    let queued = backend
        .upload_prepared_reader_with_queue(
            &target,
            &mut queued_source,
            queued_bytes.len() as u64,
            WriteCondition::Match(base.etag.clone()),
            None,
        )
        .unwrap();
    let raiun_opencloud::vault_backend::VaultUploadOutcome::Queued {
        entry: queued_entry,
        write_id,
        revision,
        ..
    } = queued
    else {
        panic!("disconnected edit must be queued")
    };

    // A second save while still offline replaces the same durable revision.
    // Its condition is the local queue marker, but the authenticated journal
    // must continue to carry the original server base version.
    let second_bytes = b"same handle's later offline revision";
    let mut second_source = std::io::Cursor::new(second_bytes.to_vec());
    let second = backend
        .upload_prepared_reader_with_queue(
            &target,
            &mut second_source,
            second_bytes.len() as u64,
            WriteCondition::Match(queued_entry.etag.clone()),
            Some(&write_id),
        )
        .unwrap();
    let raiun_opencloud::vault_backend::VaultUploadOutcome::Queued {
        entry: latest_queued_entry,
        revision: latest_revision,
        ..
    } = second
    else {
        panic!("second disconnected save must replace the pending revision")
    };
    assert!(latest_revision > revision);
    let journal = VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH).unwrap();
    let pending = journal
        .pending_edit(&sessions, &write_id, latest_revision)
        .unwrap();
    assert_eq!(pending.base_etag, base.etag);
    assert_eq!(pending.base_resource_id, base.id);
    assert_eq!(pending.path, "/notes.txt");
    assert_eq!(pending.plaintext_len, second_bytes.len() as u64);

    fixture.disconnect(false);
    let final_bytes = b"newer edit replaces queued bytes";
    let mut final_source = std::io::Cursor::new(final_bytes.to_vec());
    let committed = backend
        .upload_prepared_reader_with_queue(
            &target,
            &mut final_source,
            final_bytes.len() as u64,
            WriteCondition::Match(latest_queued_entry.etag),
            Some(&write_id),
        )
        .unwrap();
    let raiun_opencloud::vault_backend::VaultUploadOutcome::Committed(final_entry) = committed
    else {
        panic!("verified online replacement should be committed")
    };
    assert!(
        journal
            .pending_edit(&sessions, &write_id, latest_revision)
            .is_err()
    );
    let actual = state_dir.path().join("final.bin");
    backend
        .download(SPACE, "/notes.txt", Some(&final_entry.etag), &actual)
        .unwrap();
    assert_eq!(std::fs::read(actual).unwrap(), final_bytes);
    assert_eq!(listing.len(), 1);
}

fn seed_cached_vault_file(backend: &VaultBackend, name: &str, contents: &[u8]) {
    let mut source = NamedTempFile::new().unwrap();
    source.write_all(contents).unwrap();
    source.flush().unwrap();
    backend
        .upload(
            SPACE,
            &format!("/{name}"),
            source.path(),
            WriteCondition::Absent,
        )
        .unwrap();
}

#[test]
fn encrypted_create_stays_building_until_a_complete_flush_and_commits_conditionally() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, _state_dir, cache) = setup_cached(&fixture);
    let target = backend.prepare_create_target("/new.txt").unwrap();
    let created = backend.begin_prepared_create(&target).unwrap();
    let raiun_opencloud::vault_backend::VaultUploadOutcome::BuildingCreate {
        entry,
        write_id,
        revision,
    } = created
    else {
        panic!("begin must persist a non-retryable create placeholder")
    };
    assert_eq!(entry.path, "/new.txt");
    let journal = VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH).unwrap();
    let building = journal
        .pending_operation(&sessions, &write_id, revision)
        .unwrap();
    assert_eq!(building.state, CiphertextWriteState::Building);
    assert!(
        journal
            .retryable_pending_edits(&sessions, 10)
            .unwrap()
            .0
            .is_empty()
    );
    let mut listed = Vec::new();
    backend
        .list(SPACE, "/", &mut |entry| {
            listed.push(entry);
            Ok(())
        })
        .unwrap();
    assert!(listed.iter().all(|item| item.path != "/new.txt"));

    let payload = b"first complete encrypted create";
    let mut source = std::io::Cursor::new(payload.to_vec());
    let outcome = backend
        .create_prepared_reader_with_queue(
            &target,
            &mut source,
            payload.len() as u64,
            Some((&write_id, revision)),
        )
        .unwrap();
    let raiun_opencloud::vault_backend::VaultUploadOutcome::Committed(remote) = outcome else {
        panic!("successful conditional create must be read back and committed")
    };
    assert_eq!(remote.path, "/new.txt");
    assert!(
        journal
            .pending_operation(&sessions, &write_id, revision)
            .is_err()
    );
    let puts: Vec<_> = fixture
        .requests()
        .into_iter()
        .filter(|request| request.method == "PUT")
        .collect();
    assert_eq!(puts.len(), 1);
    assert_eq!(
        puts[0].headers.get("if-none-match").map(String::as_str),
        Some("*")
    );
    let put_target = puts[0].target.clone();
    assert!(
        fixture
            .requests()
            .iter()
            .any(|request| { request.method == "PROPFIND" && request.target == put_target }),
        "post-upload metadata verification must stat the file without adding a collection slash"
    );
    assert!(!String::from_utf8_lossy(&puts[0].body).contains("first complete"));
}

#[test]
fn encrypted_offline_create_is_visible_and_reconciles_only_while_destination_is_absent() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, state_dir, cache) = setup_cached(&fixture);
    let mut initial_listing = Vec::new();
    backend
        .list(SPACE, "/", &mut |item| {
            initial_listing.push(item);
            Ok(())
        })
        .unwrap();
    let target = backend.prepare_create_target("/offline.txt").unwrap();
    let created = backend.begin_prepared_create(&target).unwrap();
    let raiun_opencloud::vault_backend::VaultUploadOutcome::BuildingCreate {
        write_id,
        revision,
        ..
    } = created
    else {
        panic!("new create should start as Building")
    };
    fixture.disconnect(true);
    let payload = b"offline new file";
    let mut source = std::io::Cursor::new(payload.to_vec());
    let outcome = backend
        .create_prepared_reader_with_queue(
            &target,
            &mut source,
            payload.len() as u64,
            Some((&write_id, revision)),
        )
        .unwrap();
    let raiun_opencloud::vault_backend::VaultUploadOutcome::QueuedCreate {
        entry,
        write_id: same_id,
        revision: queued_revision,
        uncertain: false,
    } = outcome
    else {
        panic!("no PUT should be attempted while the server is disconnected")
    };
    assert_eq!(same_id, write_id);
    assert!(queued_revision > revision);
    assert_eq!(entry.path, "/offline.txt");
    assert_eq!(
        backend.stat(SPACE, "/offline.txt").unwrap().etag,
        entry.etag
    );
    let mut listed = Vec::new();
    backend
        .list(SPACE, "/", &mut |item| {
            listed.push(item);
            Ok(())
        })
        .unwrap();
    assert!(listed.iter().any(|item| item.path == "/offline.txt"));
    let local_copy = state_dir.path().join("offline-create.bin");
    backend
        .download(SPACE, "/offline.txt", Some(&entry.etag), &local_copy)
        .unwrap();
    assert_eq!(std::fs::read(local_copy).unwrap(), payload);
    let journal = VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH).unwrap();
    let pending = journal
        .pending_operation(&sessions, &write_id, queued_revision)
        .unwrap();
    assert_eq!(pending.base, WriteCondition::Absent);
    assert_eq!(
        pending.operation,
        raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateFile
    );

    fixture.disconnect(false);
    let committed = backend
        .reconcile_pending_operation(&write_id, queued_revision)
        .unwrap();
    assert_eq!(committed.path, "/offline.txt");
    assert!(
        journal
            .pending_operation(&sessions, &write_id, queued_revision)
            .is_err()
    );
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|r| r.method == "PUT")
            .count(),
        1
    );
}

#[test]
fn interrupted_file_create_retry_is_explicit_conditional_and_readback_gated() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, _state_dir, cache) = setup_cached(&fixture);
    backend.list(SPACE, "/", &mut |_| Ok(())).unwrap();
    let target = backend
        .prepare_create_target("/recover-after-crash.txt")
        .unwrap();
    let created = backend.begin_prepared_create(&target).unwrap();
    let raiun_opencloud::vault_backend::VaultUploadOutcome::BuildingCreate {
        write_id,
        revision,
        ..
    } = created
    else {
        panic!("new create must start as Building")
    };
    fixture.disconnect(true);
    let payload = b"encrypted local recovery bytes";
    let mut source = std::io::Cursor::new(payload.to_vec());
    let queued = backend
        .create_prepared_reader_with_queue(
            &target,
            &mut source,
            payload.len() as u64,
            Some((&write_id, revision)),
        )
        .unwrap();
    let raiun_opencloud::vault_backend::VaultUploadOutcome::QueuedCreate {
        revision: queued_revision,
        ..
    } = queued
    else {
        panic!("disconnected create should be queued locally")
    };
    assert!(
        backend
            .retry_interrupted_file_create(
                &write_id,
                queued_revision,
                CiphertextWriteState::NeverAttempted,
                0,
            )
            .is_err()
    );
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request.method == "PUT")
            .count(),
        0,
        "invalid state tokens must fail before any remote mutation"
    );
    let cache_scope = CacheScope::new(
        scope.server_origin(),
        scope.account_id(),
        scope.space_id(),
        scope.resource_id(),
        ScopeProtection::CiphertextOnly,
    )
    .unwrap();
    cache
        .claim_ciphertext_file_create_attempt(&cache_scope, &write_id, queued_revision)
        .unwrap();
    let puts_before_generic_reconcile = fixture
        .requests()
        .iter()
        .filter(|request| request.method == "PUT")
        .count();
    assert!(
        backend
            .reconcile_pending_operation(&write_id, queued_revision)
            .is_err(),
        "generic recovery must leave Attempting creates for explicit verification"
    );
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request.method == "PUT")
            .count(),
        puts_before_generic_reconcile,
        "generic recovery must not replay an Attempting create"
    );
    fixture.disconnect(false);

    let uploaded = backend
        .retry_interrupted_file_create(
            &write_id,
            queued_revision,
            CiphertextWriteState::Attempting,
            0,
        )
        .unwrap();
    assert_eq!(uploaded.path, "/recover-after-crash.txt");
    assert!(
        VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH)
            .unwrap()
            .pending_operation(&sessions, &write_id, queued_revision)
            .is_err()
    );
    let put = fixture
        .requests()
        .into_iter()
        .find(|request| request.method == "PUT")
        .unwrap();
    assert_eq!(
        put.headers.get("if-none-match").map(String::as_str),
        Some("*")
    );
    assert!(!String::from_utf8_lossy(&put.body).contains("encrypted local recovery bytes"));

    // A response lost after the server commits is not proof of ownership.
    // A second explicit click observes the occupied destination and conflicts
    // without issuing a second PUT or discarding the encrypted recovery body.
    let fixture = Fixture::start();
    let (backend, sessions, scope, _state_dir, cache) = setup_cached(&fixture);
    backend.list(SPACE, "/", &mut |_| Ok(())).unwrap();
    let target = backend.prepare_create_target("/lost-response.txt").unwrap();
    let created = backend.begin_prepared_create(&target).unwrap();
    let raiun_opencloud::vault_backend::VaultUploadOutcome::BuildingCreate {
        write_id,
        revision,
        ..
    } = created
    else {
        panic!("new create must start as Building")
    };
    fixture.disconnect(true);
    let mut source = std::io::Cursor::new(payload.to_vec());
    let queued = backend
        .create_prepared_reader_with_queue(
            &target,
            &mut source,
            payload.len() as u64,
            Some((&write_id, revision)),
        )
        .unwrap();
    let raiun_opencloud::vault_backend::VaultUploadOutcome::QueuedCreate {
        revision: queued_revision,
        ..
    } = queued
    else {
        panic!("disconnected create should be queued locally")
    };
    let cache_scope = CacheScope::new(
        scope.server_origin(),
        scope.account_id(),
        scope.space_id(),
        scope.resource_id(),
        ScopeProtection::CiphertextOnly,
    )
    .unwrap();
    cache
        .claim_ciphertext_file_create_attempt(&cache_scope, &write_id, queued_revision)
        .unwrap();
    fixture.disconnect(false);
    fixture.lose_put_response();
    assert!(
        backend
            .retry_interrupted_file_create(
                &write_id,
                queued_revision,
                CiphertextWriteState::Attempting,
                0,
            )
            .is_err()
    );
    let journal = VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH).unwrap();
    let after_lost_response = journal
        .pending_operation(&sessions, &write_id, queued_revision)
        .unwrap();
    assert_eq!(
        after_lost_response.state,
        CiphertextWriteState::RecoveryAttempting
    );
    assert_eq!(
        after_lost_response.retry_generation, 1,
        "the explicit claim advances the durable retry generation"
    );
    let put_count_after_lost_response = fixture
        .requests()
        .iter()
        .filter(|request| request.method == "PUT")
        .count();
    assert!(
        backend
            .retry_interrupted_file_create(
                &write_id,
                queued_revision,
                CiphertextWriteState::Attempting,
                0,
            )
            .is_err()
    );
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request.method == "PUT")
            .count(),
        put_count_after_lost_response,
        "a stale retry state token must not cause a second PUT"
    );
    let retained_dir = tempfile::tempdir().unwrap();
    let retained = retained_dir.path().join("recovery.bin");
    journal
        .download_pending_edit(&sessions, &write_id, queued_revision, &retained)
        .unwrap();
    assert_eq!(std::fs::read(&retained).unwrap(), payload);
    assert!(
        backend
            .retry_interrupted_file_create(
                &write_id,
                queued_revision,
                CiphertextWriteState::RecoveryAttempting,
                1,
            )
            .is_err()
    );
    let conflict = journal
        .pending_operation(&sessions, &write_id, queued_revision)
        .unwrap();
    assert_eq!(conflict.state, CiphertextWriteState::Conflict);
    assert_eq!(
        conflict.retry_generation, 1,
        "preflight conflict is fenced without falsely claiming another dispatch"
    );
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request.method == "PUT")
            .count(),
        1,
        "the occupied path is never blindly uploaded a second time"
    );
    let retained_after_conflict = retained_dir.path().join("recovery-after-conflict.bin");
    journal
        .download_pending_edit(
            &sessions,
            &write_id,
            queued_revision,
            &retained_after_conflict,
        )
        .unwrap();
    assert_eq!(std::fs::read(&retained_after_conflict).unwrap(), payload);
}

#[test]
fn encrypted_offline_rename_overlays_cached_namespace_and_reconciles_conditionally() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, state_dir, cache) = setup_cached(&fixture);
    let source_bytes = b"cached encrypted rename source";
    let original = seed_and_cache_file(&backend, &state_dir, "before.txt", source_bytes);
    fixture.disconnect(true);

    let outcome = backend
        .rename_file_with_queue("/before.txt", "/after.txt", &original.id, &original.etag)
        .unwrap();
    let raiun_opencloud::vault_backend::VaultRenameOutcome::Queued {
        entry,
        write_id,
        revision,
        uncertain: false,
    } = outcome
    else {
        panic!("an offline rename should remain as a known durable operation")
    };
    assert_eq!(entry.path, "/after.txt");
    assert_eq!(entry.id, original.id);

    let journal = VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH).unwrap();
    let operation = journal
        .pending_operation(&sessions, &write_id, revision)
        .unwrap();
    assert_eq!(
        operation.operation,
        raiun_opencloud::vault_cache::VaultPendingOperationKind::RenameFile
    );
    assert_eq!(operation.path, "/before.txt");
    assert_eq!(operation.destination_path, "/after.txt");
    assert_eq!(operation.base_resource_id, original.id);
    assert_eq!(operation.base_etag, original.etag);
    assert_eq!(operation.base, WriteCondition::Match(original.etag.clone()));
    assert_eq!(
        operation.parent_resource_id,
        operation.destination_parent_resource_id
    );

    assert_eq!(
        backend
            .download(
                SPACE,
                "/before.txt",
                None,
                &state_dir.path().join("hidden.bin")
            )
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::NotFound
    );
    let mut listed = Vec::new();
    backend
        .list(SPACE, "/", &mut |item| {
            listed.push(item);
            Ok(())
        })
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].path, "/after.txt");
    assert_eq!(listed[0].id, original.id);
    assert_eq!(listed[0].etag, entry.etag);

    let offline_cache = VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH).unwrap();
    let offline_sessions = Arc::new(VaultSessionCoordinator::new());
    let mut password = b"potato".to_vec();
    let (snapshot, _) = offline_cache
        .unlock_root(&offline_sessions, &mut password)
        .unwrap();
    let offline = VaultBackend::new_from_cached_root(
        OpenCloudClient::new(&fixture.origin(), "synthetic-token".to_owned()).unwrap(),
        Arc::clone(&offline_sessions),
        scope.clone(),
        ROOT_PATH.to_owned(),
        offline_cache,
        snapshot,
    )
    .unwrap();
    let mut restarted_listing = Vec::new();
    offline
        .list(SPACE, "/", &mut |item| {
            restarted_listing.push(item);
            Ok(())
        })
        .unwrap();
    assert_eq!(restarted_listing.len(), 1);
    assert_eq!(restarted_listing[0].path, "/after.txt");
    let restarted_file = state_dir.path().join("renamed-after-restart.bin");
    offline
        .download(SPACE, "/after.txt", Some(&entry.etag), &restarted_file)
        .unwrap();
    assert_eq!(std::fs::read(restarted_file).unwrap(), source_bytes);

    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request.method == "MOVE")
            .count(),
        0,
        "no remote MOVE should be attempted during the disconnected overlay"
    );
    fixture.disconnect(false);
    let moved = backend
        .reconcile_pending_operation(&write_id, revision)
        .unwrap();
    assert_eq!(moved.path, "/after.txt");
    assert_eq!(moved.id, original.id);
    assert!(
        journal
            .pending_operation(&sessions, &write_id, revision)
            .is_err()
    );
    let move_requests: Vec<_> = fixture
        .requests()
        .into_iter()
        .filter(|request| request.method == "MOVE")
        .collect();
    assert_eq!(move_requests.len(), 1);
    assert_eq!(
        move_requests[0].headers.get("if-match").map(String::as_str),
        Some(original.etag.as_str())
    );
    assert_eq!(
        move_requests[0]
            .headers
            .get("overwrite")
            .map(String::as_str),
        Some("F")
    );
}

#[test]
fn encrypted_rename_lost_move_response_is_read_back_without_replay() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, state_dir, cache) = setup_cached(&fixture);
    let original = seed_and_cache_file(
        &backend,
        &state_dir,
        "before.txt",
        b"rename after lost response",
    );
    fixture.lose_move_response();

    let outcome = backend
        .rename_file_with_queue("/before.txt", "/after.txt", &original.id, &original.etag)
        .unwrap();
    let raiun_opencloud::vault_backend::VaultRenameOutcome::Queued {
        write_id,
        revision,
        uncertain: true,
        ..
    } = outcome
    else {
        panic!("a lost MOVE response must stay uncertain until readback")
    };
    let journal = VaultOfflineCache::new(cache, scope, ROOT_PATH).unwrap();
    let pending = journal
        .pending_operation(&sessions, &write_id, revision)
        .unwrap();
    assert_eq!(pending.state, CiphertextWriteState::Uncertain);

    let moved = backend
        .reconcile_pending_operation(&write_id, revision)
        .unwrap();
    assert_eq!(moved.path, "/after.txt");
    assert_eq!(moved.id, original.id);
    assert!(
        journal
            .pending_operation(&sessions, &write_id, revision)
            .is_err()
    );
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request.method == "MOVE")
            .count(),
        1,
        "exact destination/source readback must resolve ambiguity without a second MOVE"
    );
}

#[test]
fn encrypted_rename_same_id_size_but_changed_content_is_retained() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, state_dir, _) = setup_cached(&fixture);
    let original_plaintext = b"same-length source bytes";
    let original = seed_and_cache_file(&backend, &state_dir, "before.txt", original_plaintext);
    fixture.disconnect(true);
    let outcome = backend
        .rename_file_with_queue("/before.txt", "/after.txt", &original.id, &original.etag)
        .unwrap();
    let raiun_opencloud::vault_backend::VaultRenameOutcome::Queued {
        write_id, revision, ..
    } = outcome
    else {
        panic!("offline rename must remain queued")
    };

    let private = tempfile::tempdir().unwrap();
    let changed_cipher_path = private.path().join("changed-cipher.bin");
    let mut changed_plaintext = std::io::Cursor::new(b"Same-length source bytes".to_vec());
    sessions
        .encrypt_file_transactional(
            &scope,
            &mut changed_plaintext,
            &changed_cipher_path,
            original_plaintext.len() as u64,
            1024 * 1024,
        )
        .unwrap();
    fixture.replace_child_cipher_without_etag(std::fs::read(changed_cipher_path).unwrap());
    fixture.disconnect(false);

    let error = backend
        .reconcile_pending_operation(&write_id, revision)
        .unwrap_err();
    assert_eq!(
        error.kind,
        raiun_core::backend::ErrorKind::Conflict,
        "{error:?}; requests={:?}",
        fixture
            .requests()
            .iter()
            .map(|request| format!("{} {}", request.method, request.target))
            .collect::<Vec<_>>()
    );
    let journal = VaultOfflineCache::new(
        Cache::open(state_dir.path(), 16 * 1024 * 1024).unwrap(),
        scope.clone(),
        ROOT_PATH,
    )
    .unwrap();
    let retained = journal
        .pending_operation(&sessions, &write_id, revision)
        .unwrap();
    assert_eq!(retained.state, CiphertextWriteState::Conflict);
    assert_eq!(retained.source_size, original.size);
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request.method == "MOVE")
            .count(),
        1
    );
}

#[test]
fn encrypted_rename_directory_readback_is_never_retired() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, state_dir, cache) = setup_cached(&fixture);
    let original = seed_and_cache_file(&backend, &state_dir, "before.txt", b"rename file");
    fixture.lose_move_response();
    let outcome = backend
        .rename_file_with_queue("/before.txt", "/after.txt", &original.id, &original.etag)
        .unwrap();
    let raiun_opencloud::vault_backend::VaultRenameOutcome::Queued {
        write_id,
        revision,
        uncertain: true,
        ..
    } = outcome
    else {
        panic!("lost MOVE response must remain queued as uncertain")
    };
    // The MOVE completed, but the server now describes that same resource as
    // a directory. ID/ETag metadata alone must not retire a file rename.
    fixture.mark_child_directory(true);
    let error = backend
        .reconcile_pending_operation(&write_id, revision)
        .unwrap_err();
    assert_eq!(
        error.kind,
        raiun_core::backend::ErrorKind::Conflict,
        "{error:?}; requests={:?}",
        fixture
            .requests()
            .iter()
            .map(|request| format!("{} {}", request.method, request.target))
            .collect::<Vec<_>>()
    );
    let journal = VaultOfflineCache::new(cache, scope, ROOT_PATH).unwrap();
    assert_eq!(
        journal
            .pending_operation(&sessions, &write_id, revision)
            .unwrap()
            .state,
        CiphertextWriteState::Conflict
    );
}

#[test]
fn encrypted_rename_rejects_replaced_vault_root_without_moving_source() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, state_dir, cache) = setup_cached(&fixture);
    let original = seed_and_cache_file(&backend, &state_dir, "before.txt", b"root-bound rename");
    fixture.disconnect(true);
    let outcome = backend
        .rename_file_with_queue("/before.txt", "/after.txt", &original.id, &original.etag)
        .unwrap();
    let raiun_opencloud::vault_backend::VaultRenameOutcome::Queued {
        write_id, revision, ..
    } = outcome
    else {
        panic!("disconnected rename should be durably queued")
    };

    fixture.replace_root_id("replacement-root-id");
    fixture.disconnect(false);
    assert_eq!(
        backend
            .reconcile_pending_operation(&write_id, revision)
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict
    );
    let journal = VaultOfflineCache::new(cache, scope, ROOT_PATH).unwrap();
    assert_eq!(
        journal
            .pending_operation(&sessions, &write_id, revision)
            .unwrap()
            .state,
        CiphertextWriteState::Conflict
    );
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request.method == "MOVE")
            .count(),
        0,
        "a replaced vault root must be rejected before MOVE"
    );
}

#[test]
fn encrypted_rename_root_token_change_is_retained_as_conflict() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, state_dir, cache) = setup_cached(&fixture);
    let original = seed_and_cache_file(&backend, &state_dir, "before.txt", b"token-bound rename");
    fixture.disconnect(true);
    let outcome = backend
        .rename_file_with_queue("/before.txt", "/after.txt", &original.id, &original.etag)
        .unwrap();
    let raiun_opencloud::vault_backend::VaultRenameOutcome::Queued {
        write_id, revision, ..
    } = outcome
    else {
        panic!("disconnected rename should be durably queued")
    };

    fixture.replace_token("changed-root-integrity-token");
    fixture.disconnect(false);
    assert_eq!(
        backend
            .reconcile_pending_operation(&write_id, revision)
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict
    );
    let journal = VaultOfflineCache::new(cache, scope, ROOT_PATH).unwrap();
    assert_eq!(
        journal
            .pending_operation(&sessions, &write_id, revision)
            .unwrap()
            .state,
        CiphertextWriteState::Conflict
    );
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request.method == "MOVE")
            .count(),
        0,
        "a changed integrity token must block MOVE before mutation"
    );
}

#[test]
fn lost_create_put_response_is_retained_and_not_blindly_replayed() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, _state_dir, cache) = setup_cached(&fixture);
    let target = backend.prepare_create_target("/ambiguous.txt").unwrap();
    let created = backend.begin_prepared_create(&target).unwrap();
    let raiun_opencloud::vault_backend::VaultUploadOutcome::BuildingCreate {
        write_id,
        revision,
        ..
    } = created
    else {
        panic!("new create should start as Building")
    };
    fixture.lose_put_response();
    let payload = b"server accepted but response was lost";
    let mut source = std::io::Cursor::new(payload.to_vec());
    let outcome = backend
        .create_prepared_reader_with_queue(
            &target,
            &mut source,
            payload.len() as u64,
            Some((&write_id, revision)),
        )
        .unwrap();
    let raiun_opencloud::vault_backend::VaultUploadOutcome::QueuedCreate {
        uncertain: true,
        revision: uncertain_revision,
        ..
    } = outcome
    else {
        panic!("a lost PUT response must retain an uncertain create")
    };
    let journal = VaultOfflineCache::new(cache, scope.clone(), ROOT_PATH).unwrap();
    assert_eq!(
        journal
            .pending_operation(&sessions, &write_id, uncertain_revision)
            .unwrap()
            .state,
        CiphertextWriteState::Uncertain
    );
    assert!(
        backend
            .reconcile_pending_operation(&write_id, uncertain_revision)
            .is_err()
    );
    assert_eq!(
        journal
            .pending_operation(&sessions, &write_id, uncertain_revision)
            .unwrap()
            .state,
        CiphertextWriteState::Conflict
    );
    let unresolved = backend
        .resolve_pending_create_by_id(&write_id)
        .unwrap()
        .expect("uncertain operation remains discoverable by exact ID");
    assert_eq!(unresolved.metadata.revision, uncertain_revision);
    assert_eq!(unresolved.metadata.state, CiphertextWriteState::Conflict);
    assert_eq!(unresolved.plaintext_sha256, None);
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|r| r.method == "PUT")
            .count(),
        1
    );
}

#[test]
fn queued_create_is_not_reconciled_into_a_replaced_same_path_parent() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, _state_dir, cache) = setup_cached(&fixture);
    let encrypted_parent = sessions.encrypt_name(&scope, "parent").unwrap();
    {
        let mut state = fixture.state.lock().unwrap();
        state.child = Some((encrypted_parent, Vec::new()));
        state.child_directory = true;
        state.child_resource_id = "original-parent-id".to_owned();
        state.etag_version = 7;
    }
    let mut root_entries = Vec::new();
    backend
        .list(SPACE, "/", &mut |entry| {
            root_entries.push(entry);
            Ok(())
        })
        .unwrap();
    let mut parent_entries = Vec::new();
    backend
        .list(SPACE, "/parent", &mut |entry| {
            parent_entries.push(entry);
            Ok(())
        })
        .unwrap();
    assert!(root_entries.iter().any(|entry| entry.path == "/parent"));

    let target = backend.prepare_create_target("/parent/new.txt").unwrap();
    let created = backend.begin_prepared_create(&target).unwrap();
    let raiun_opencloud::vault_backend::VaultUploadOutcome::BuildingCreate {
        write_id,
        revision,
        ..
    } = created
    else {
        panic!("new nested file should reserve a Building revision")
    };
    fixture.disconnect(true);
    let bytes = b"must not move into a replacement parent";
    let mut source = std::io::Cursor::new(bytes.to_vec());
    let queued = backend
        .create_prepared_reader_with_queue(
            &target,
            &mut source,
            bytes.len() as u64,
            Some((&write_id, revision)),
        )
        .unwrap();
    let raiun_opencloud::vault_backend::VaultUploadOutcome::QueuedCreate {
        revision: queued_revision,
        ..
    } = queued
    else {
        panic!("disconnected create should remain queued")
    };
    fixture.replace_child_resource_id("replacement-parent-id");
    fixture.disconnect(false);

    assert!(
        backend
            .reconcile_pending_operation(&write_id, queued_revision)
            .is_err()
    );
    let journal = VaultOfflineCache::new(cache, scope, ROOT_PATH).unwrap();
    assert_eq!(
        journal
            .pending_operation(&sessions, &write_id, queued_revision)
            .unwrap()
            .state,
        CiphertextWriteState::Conflict
    );
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request.method == "PUT")
            .count(),
        0
    );
}

#[test]
fn encrypted_pin_publishes_only_a_complete_ciphertext_generation() {
    let fixture = Fixture::start();
    let (backend, _sessions, scope, _state, cache) = setup_cached(&fixture);
    seed_cached_vault_file(&backend, "notes.txt", b"pinned synthetic plaintext");

    let cancelled = AtomicBool::new(false);
    let pin = backend.pin_offline_tree(None, &cancelled).unwrap();
    assert_eq!(pin.state, CiphertextPinState::Ready);
    assert!(
        pin.item_count >= 2,
        "root listing and file content are pinned"
    );
    assert!(pin.byte_len > 0);

    let listed = cache
        .ciphertext_pins(&encrypted_cache_scope(&scope), None, 10)
        .unwrap();
    assert_eq!(listed.items, vec![pin]);
    assert!(!listed.truncated);
    assert!(fixture.requests().iter().any(|request| {
        request.method == "GET" && request.target.starts_with("/dav/personal/Travel.vault/")
    }));
}

#[test]
fn cancelled_refresh_keeps_the_previous_complete_generation_active() {
    let fixture = Fixture::start();
    let (backend, _sessions, scope, _state, cache) = setup_cached(&fixture);
    seed_cached_vault_file(&backend, "notes.txt", b"pinned synthetic plaintext");
    let never_cancelled = AtomicBool::new(false);
    let original = backend.pin_offline_tree(None, &never_cancelled).unwrap();
    assert_eq!(original.state, CiphertextPinState::Ready);

    fixture.delay_get(300);
    let backend = Arc::new(backend);
    let cancelled = Arc::new(AtomicBool::new(false));
    let refresh_backend = Arc::clone(&backend);
    let refresh_cancelled = Arc::clone(&cancelled);
    let pin_id = original.id.clone();
    let refresh =
        thread::spawn(move || refresh_backend.pin_offline_tree(Some(&pin_id), &refresh_cancelled));
    wait_for_content_get(&fixture);
    cancelled.store(true, Ordering::Release);
    assert!(refresh.join().unwrap().is_err());

    let current = cache
        .ciphertext_pin_info(&encrypted_cache_scope(&scope), &original.id)
        .unwrap();
    assert_eq!(current.state, CiphertextPinState::Ready);
    assert_eq!(current.generation, original.generation);
    assert_eq!(current.item_count, original.item_count);
}

#[test]
fn ciphertext_epoch_change_during_pin_never_activates_the_partial_generation() {
    let fixture = Fixture::start();
    let (backend, _sessions, scope, _state, cache) = setup_cached(&fixture);
    seed_cached_vault_file(&backend, "notes.txt", b"pinned synthetic plaintext");
    fixture.delay_get(300);

    let backend = Arc::new(backend);
    let cancelled = Arc::new(AtomicBool::new(false));
    let pin_backend = Arc::clone(&backend);
    let pin_cancelled = Arc::clone(&cancelled);
    let (result_sender, result_receiver) = std::sync::mpsc::channel();
    let pin = thread::spawn(move || {
        let result = pin_backend.pin_offline_tree(None, &pin_cancelled);
        result_sender.send(result).unwrap();
    });
    let mut observed_content_get = false;
    for _ in 0..500 {
        if fixture
            .requests()
            .iter()
            .any(|request| request.method == "GET" && request.target.starts_with("/dav/"))
        {
            observed_content_get = true;
            break;
        }
        if let Ok(result) = result_receiver.try_recv() {
            panic!("pin failed before downloading content: {result:?}");
        }
        thread::sleep(Duration::from_millis(2));
    }
    assert!(observed_content_get, "pin did not reach content download");
    cache
        .invalidate_ciphertext_scope(&encrypted_cache_scope(&scope))
        .unwrap();
    assert!(result_receiver.recv().unwrap().is_err());
    pin.join().unwrap();

    let page = cache
        .ciphertext_pins(&encrypted_cache_scope(&scope), None, 10)
        .unwrap();
    assert!(
        page.items
            .iter()
            .all(|item| item.state != CiphertextPinState::Ready)
    );
}

#[test]
fn locking_during_pin_prevents_publication_of_the_incomplete_snapshot() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, _state, cache) = setup_cached(&fixture);
    seed_cached_vault_file(&backend, "notes.txt", b"pinned synthetic plaintext");
    fixture.delay_get(300);

    let backend = Arc::new(backend);
    let cancelled = Arc::new(AtomicBool::new(false));
    let pin_backend = Arc::clone(&backend);
    let pin_cancelled = Arc::clone(&cancelled);
    let pin = thread::spawn(move || pin_backend.pin_offline_tree(None, &pin_cancelled));
    wait_for_content_get(&fixture);
    sessions.lock(&scope).unwrap();
    assert!(pin.join().unwrap().is_err());
    assert!(!sessions.is_unlocked(&scope).unwrap());

    let page = cache
        .ciphertext_pins(&encrypted_cache_scope(&scope), None, 10)
        .unwrap();
    assert!(
        page.items
            .iter()
            .all(|item| item.state != CiphertextPinState::Ready)
    );
}

#[test]
fn encrypted_vault_uses_sealed_cache_only_after_transport_failure() {
    let mut fixture = Fixture::start();
    let client = OpenCloudClient::new(&fixture.origin(), "synthetic-token".to_owned()).unwrap();
    let scope = VaultSessionScope::new("account-a", &fixture.origin(), SPACE, ROOT_ID).unwrap();
    let sessions = Arc::new(VaultSessionCoordinator::new());
    let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim();
    let mut password = b"potato".to_vec();
    sessions.unlock(&scope, &mut password, token).unwrap();

    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let cache = Cache::open(state.path(), 16 * 1024 * 1024).unwrap();
    let cache_adapter = VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH).unwrap();
    let backend = VaultBackend::new_with_offline_cache(
        client.clone(),
        Arc::clone(&sessions),
        scope.clone(),
        ROOT_PATH.to_owned(),
        cache_adapter,
    )
    .unwrap();

    let mut source = NamedTempFile::new().unwrap();
    source.write_all(b"offline encrypted content").unwrap();
    source.flush().unwrap();
    let created = backend
        .upload(SPACE, "/notes.txt", source.path(), WriteCondition::Absent)
        .unwrap();
    let mut listed = Vec::new();
    backend
        .list(SPACE, "/", &mut |entry| {
            listed.push(entry);
            Ok(())
        })
        .unwrap();
    assert_eq!(listed[0].id, created.id);

    let online_file = state.path().join("online-file");
    backend
        .download(SPACE, "/notes.txt", Some(&created.etag), &online_file)
        .unwrap();
    assert_eq!(
        std::fs::read(&online_file).unwrap(),
        b"offline encrypted content"
    );

    let cache_probe = VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH).unwrap();
    let before_mutation_epoch = cache_probe.ciphertext_epoch().unwrap();
    let mut second_source = NamedTempFile::new().unwrap();
    second_source.write_all(b"second encrypted file").unwrap();
    second_source.flush().unwrap();
    let created = backend
        .upload(
            SPACE,
            "/notes.txt",
            second_source.path(),
            WriteCondition::Match(created.etag.clone()),
        )
        .unwrap();
    assert_eq!(
        cache_probe.ciphertext_epoch().unwrap(),
        before_mutation_epoch + 1,
        "an encrypted write revokes the old cached generation before its PUT"
    );
    assert!(cache_probe.open_root_envelope().is_err());
    let mut refreshed_listing = Vec::new();
    backend
        .list(SPACE, "/", &mut |entry| {
            refreshed_listing.push(entry);
            Ok(())
        })
        .unwrap();
    assert!(refreshed_listing.iter().any(|entry| entry.id == created.id));
    let refreshed_file = state.path().join("refreshed-file");
    backend
        .download(SPACE, "/notes.txt", Some(&created.etag), &refreshed_file)
        .unwrap();

    fixture.replace_token("different-root-token");
    assert_eq!(
        backend.stat(SPACE, "/notes.txt").unwrap_err().kind,
        raiun_core::backend::ErrorKind::Conflict,
        "a changed root token must not fall back to stale cache data"
    );
    fixture.replace_token(token);
    fixture.set_unauthorized(true);
    assert_eq!(
        backend.stat(SPACE, "/notes.txt").unwrap_err().kind,
        raiun_core::backend::ErrorKind::Unauthorized,
        "authorization failures must not fall back to cached vault data"
    );
    fixture.set_unauthorized(false);

    let request_count_before_offline = fixture.requests().len();
    fixture.stop_server();
    let offline_adapter = VaultOfflineCache::new(cache, scope.clone(), ROOT_PATH).unwrap();
    let offline_sessions = Arc::new(VaultSessionCoordinator::new());
    let mut password = b"potato".to_vec();
    let (root_snapshot, _) = offline_adapter
        .unlock_root(&offline_sessions, &mut password)
        .unwrap();
    let offline_backend = VaultBackend::new_from_cached_root(
        client,
        Arc::clone(&offline_sessions),
        scope.clone(),
        ROOT_PATH.to_owned(),
        offline_adapter,
        root_snapshot,
    )
    .unwrap();
    assert_eq!(offline_backend.spaces().unwrap()[0].id, SPACE);
    assert_eq!(
        offline_backend.stat(SPACE, "/notes.txt").unwrap().etag,
        created.etag
    );
    let destination = state.path().join("offline-file");
    let offline_entry = offline_backend
        .download(SPACE, "/notes.txt", Some(&created.etag), &destination)
        .unwrap();
    assert_eq!(offline_entry.id, created.id);
    assert_eq!(
        std::fs::read(destination).unwrap(),
        b"second encrypted file"
    );
    assert_eq!(
        offline_backend
            .upload(
                SPACE,
                "/notes.txt",
                source.path(),
                WriteCondition::Match(created.etag.clone()),
            )
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Forbidden
    );

    offline_sessions.lock(&scope).unwrap();
    assert!(offline_backend.stat(SPACE, "/notes.txt").is_err());
    assert_eq!(fixture.requests().len(), request_count_before_offline);
}

#[test]
fn whole_encrypted_space_is_also_a_ciphertext_only_backend() {
    let fixture = Fixture::start_whole_space();
    let client = OpenCloudClient::new(&fixture.origin(), "synthetic-token".to_owned()).unwrap();
    let sessions = Arc::new(VaultSessionCoordinator::new());
    let scope =
        VaultSessionScope::new("account-a", &fixture.origin(), SPACE, "space-root-id").unwrap();
    let token = include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim();
    let mut password = b"potato".to_vec();
    sessions.unlock(&scope, &mut password, token).unwrap();
    let backend = VaultBackend::new(client, sessions, scope, "/".to_owned()).unwrap();

    let mut source = NamedTempFile::new().unwrap();
    source.write_all(b"whole Space stays encrypted").unwrap();
    source.flush().unwrap();
    let result = backend
        .upload(SPACE, "/whole.txt", source.path(), WriteCondition::Absent)
        .unwrap();
    assert_eq!(result.path, "/whole.txt");
    let put = fixture
        .requests()
        .into_iter()
        .find(|request| request.method == "PUT")
        .unwrap();
    assert!(!put.target.contains("whole.txt"));
    assert!(!String::from_utf8_lossy(&put.body).contains("whole Space stays encrypted"));
    let destination = NamedTempFile::new().unwrap();
    let (destination_file, destination_path) = destination.keep().unwrap();
    drop(destination_file);
    backend
        .download(SPACE, "/whole.txt", Some(&result.etag), &destination_path)
        .unwrap();
    assert_eq!(
        std::fs::read(&destination_path).unwrap(),
        b"whole Space stays encrypted"
    );
}

#[test]
fn engine_syncs_plaintext_through_vault_backend_and_resolves_conflicts_safely() {
    let fixture = Fixture::start();
    let (backend, _, _) = setup(&fixture);
    let backend = Arc::new(backend);
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("engine-state");
    let local_path = temp.path().join("local-files");
    std::fs::create_dir_all(&local_path).unwrap();
    let binding = VaultBinding {
        root_path: ROOT_PATH.to_owned(),
        root_resource_id: ROOT_ID.to_owned(),
    };
    let ordinary = Engine::open(&state_dir, backend.clone()).unwrap();
    let engine = ordinary.with_vault_backend(SPACE.to_owned(), binding.clone(), backend.clone());
    let pair = FolderPair {
        id: "vault-pair".to_owned(),
        local_path: local_path.clone(),
        space_id: SPACE.to_owned(),
        vault: Some(binding),
        remote_path: "/".to_owned(),
        mode: SyncMode::TwoWay,
        excluded_paths: Vec::new(),
        content_filter: raiun_core::MediaFilter::All,
        exclusions: Vec::new(),
    };

    std::fs::write(local_path.join("shared.txt"), b"initial local version").unwrap();
    let first = engine.sync_pair(&pair).unwrap();
    assert_eq!(first.uploaded, 1);
    let first_put = fixture
        .requests()
        .into_iter()
        .find(|request| request.method == "PUT")
        .unwrap();
    assert!(!first_put.target.contains("shared.txt"));
    assert!(!String::from_utf8_lossy(&first_put.body).contains("initial local version"));

    let remote_path = "/shared.txt";
    let before_remote = backend.stat(SPACE, remote_path).unwrap();
    let mut remote_update = NamedTempFile::new().unwrap();
    remote_update.write_all(b"remote-only version").unwrap();
    remote_update.flush().unwrap();
    backend
        .upload(
            SPACE,
            remote_path,
            remote_update.path(),
            WriteCondition::Match(before_remote.etag),
        )
        .unwrap();
    let remote_only = engine.sync_pair(&pair).unwrap();
    assert_eq!(remote_only.downloaded, 1);
    assert_eq!(
        std::fs::read(local_path.join("shared.txt")).unwrap(),
        b"remote-only version"
    );

    std::fs::write(local_path.join("shared.txt"), b"local conflict version").unwrap();
    let before_both = backend.stat(SPACE, remote_path).unwrap();
    let mut remote_conflict = NamedTempFile::new().unwrap();
    remote_conflict
        .write_all(b"remote conflict version")
        .unwrap();
    remote_conflict.flush().unwrap();
    backend
        .upload(
            SPACE,
            remote_path,
            remote_conflict.path(),
            WriteCondition::Match(before_both.etag),
        )
        .unwrap();
    let conflict_report = engine.sync_pair(&pair).unwrap();
    assert_eq!(conflict_report.conflicts, 1);
    assert_eq!(
        std::fs::read(local_path.join("shared.txt")).unwrap(),
        b"local conflict version"
    );
    let page = engine.conflicts(&pair, None, 10).unwrap();
    let conflict = page
        .items
        .iter()
        .find(|item| item.path == "shared.txt")
        .unwrap();
    let resolution = engine
        .resolve_conflict(
            &pair,
            &conflict.path,
            ConflictChoice::KeepLocal,
            &conflict.local_hash,
            &conflict.remote_etag,
        )
        .unwrap();
    assert_eq!(
        std::fs::read(local_path.join("shared.txt")).unwrap(),
        b"local conflict version"
    );
    assert_eq!(
        std::fs::read(&resolution.recovery_path).unwrap(),
        b"remote conflict version"
    );
    let verify_remote = NamedTempFile::new().unwrap();
    let (verify_remote_file, verify_remote_path) = verify_remote.keep().unwrap();
    drop(verify_remote_file);
    backend
        .download(SPACE, remote_path, None, &verify_remote_path)
        .unwrap();
    assert_eq!(
        std::fs::read(&verify_remote_path).unwrap(),
        b"local conflict version"
    );
}

#[test]
fn encrypted_offline_delete_hides_cached_source_then_reconciles_conditionally() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, state_dir, cache) = setup_cached(&fixture);
    let source = seed_and_cache_file(&backend, &state_dir, "remove.txt", b"recoverable bytes");

    fixture.disconnect(true);
    let (write_id, revision) = match backend
        .delete_file_with_queue("/remove.txt", &source.id, &source.etag)
        .unwrap()
    {
        VaultDeleteOutcome::Queued {
            write_id,
            revision,
            uncertain,
        } => {
            assert!(!uncertain);
            (write_id, revision)
        }
        VaultDeleteOutcome::Committed => panic!("offline delete cannot be reported committed"),
    };

    let mut offline_listing = Vec::new();
    backend
        .list(SPACE, "/", &mut |entry| {
            offline_listing.push(entry);
            Ok(())
        })
        .unwrap();
    assert!(offline_listing.is_empty());
    assert_eq!(
        backend.stat(SPACE, "/remove.txt").unwrap_err().kind,
        raiun_core::backend::ErrorKind::NotFound
    );
    let journal = VaultOfflineCache::new(cache, scope.clone(), ROOT_PATH).unwrap();
    let pending = journal
        .pending_operation(&sessions, &write_id, revision)
        .unwrap();
    assert_eq!(pending.path, "/remove.txt");
    assert_eq!(pending.base_resource_id, source.id);
    assert_eq!(pending.base_etag, source.etag);
    assert_eq!(pending.source_size, b"recoverable bytes".len() as u64);

    fixture.disconnect(false);
    backend
        .reconcile_pending_delete(&write_id, revision)
        .unwrap();
    assert_eq!(
        backend.stat(SPACE, "/remove.txt").unwrap_err().kind,
        raiun_core::backend::ErrorKind::NotFound
    );
    let deletion = fixture
        .requests()
        .into_iter()
        .find(|request| request.method == "DELETE")
        .expect("conditional DELETE should reach the synthetic server");
    assert_eq!(
        deletion.headers.get("if-match").map(String::as_str),
        Some(source.etag.as_str())
    );
}

#[test]
fn encrypted_offline_delete_conflicts_on_same_path_replacement_without_deleting_it() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, state_dir, cache) = setup_cached(&fixture);
    let source = seed_and_cache_file(&backend, &state_dir, "replace.txt", b"original bytes");

    fixture.disconnect(true);
    let (write_id, revision) = match backend
        .delete_file_with_queue("/replace.txt", &source.id, &source.etag)
        .unwrap()
    {
        VaultDeleteOutcome::Queued {
            write_id, revision, ..
        } => (write_id, revision),
        VaultDeleteOutcome::Committed => panic!("offline delete cannot be reported committed"),
    };
    fixture.replace_child_resource_id("replacement-resource-id");
    fixture.disconnect(false);

    assert_eq!(
        backend
            .reconcile_pending_delete(&write_id, revision)
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict
    );
    assert!(
        !fixture
            .requests()
            .iter()
            .any(|request| request.method == "DELETE"),
        "a replacement at the same URL must never be deleted"
    );
    let journal = VaultOfflineCache::new(cache, scope, ROOT_PATH).unwrap();
    assert_eq!(
        journal
            .pending_operation(&sessions, &write_id, revision)
            .unwrap()
            .state,
        CiphertextWriteState::Conflict
    );
    assert_eq!(
        backend.stat(SPACE, "/replace.txt").unwrap().id,
        "replacement-resource-id"
    );
}

#[test]
fn encrypted_offline_delete_conflicts_when_parent_resource_is_replaced() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, state_dir, cache) = setup_cached(&fixture);
    let source = seed_and_cache_file(&backend, &state_dir, "parent.txt", b"original bytes");

    fixture.disconnect(true);
    let (write_id, revision) = match backend
        .delete_file_with_queue("/parent.txt", &source.id, &source.etag)
        .unwrap()
    {
        VaultDeleteOutcome::Queued {
            write_id, revision, ..
        } => (write_id, revision),
        VaultDeleteOutcome::Committed => panic!("offline delete cannot be reported committed"),
    };
    fixture.replace_root_id("replacement-vault-root-id");
    fixture.disconnect(false);

    assert_eq!(
        backend
            .reconcile_pending_delete(&write_id, revision)
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict
    );
    assert!(
        !fixture
            .requests()
            .iter()
            .any(|request| request.method == "DELETE"),
        "a changed vault parent must never receive the queued delete"
    );
    let journal = VaultOfflineCache::new(cache, scope, ROOT_PATH).unwrap();
    assert_eq!(
        journal
            .pending_operation(&sessions, &write_id, revision)
            .unwrap()
            .state,
        CiphertextWriteState::Conflict
    );
}

#[test]
fn encrypted_delete_with_lost_success_response_reconciles_absence_without_redelete() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, state_dir, cache) = setup_cached(&fixture);
    let source = seed_and_cache_file(
        &backend,
        &state_dir,
        "lost-response.txt",
        b"preserved bytes",
    );
    fixture.lose_delete_response();

    let (write_id, revision, uncertain) = match backend
        .delete_file_with_queue("/lost-response.txt", &source.id, &source.etag)
        .unwrap()
    {
        VaultDeleteOutcome::Queued {
            write_id,
            revision,
            uncertain,
        } => (write_id, revision, uncertain),
        VaultDeleteOutcome::Committed => {
            panic!("a lost DELETE response cannot be reported as committed")
        }
    };
    assert!(uncertain);
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request.method == "DELETE")
            .count(),
        1
    );

    // The synthetic server applied the DELETE before dropping its response.
    // Reconciliation must recognize the exact source as absent and retire
    // the intent without sending a second destructive request.
    backend
        .reconcile_pending_delete(&write_id, revision)
        .unwrap();
    assert_eq!(
        backend.stat(SPACE, "/lost-response.txt").unwrap_err().kind,
        raiun_core::backend::ErrorKind::NotFound
    );
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request.method == "DELETE")
            .count(),
        1
    );
    let journal = VaultOfflineCache::new(cache, scope, ROOT_PATH).unwrap();
    assert!(
        journal
            .pending_operation(&sessions, &write_id, revision)
            .is_err()
    );
}

#[test]
fn encrypted_directory_create_uses_absent_condition_and_verified_readback() {
    let fixture = Fixture::start();
    let (backend, _, _, _state, _cache) = setup_cached(&fixture);
    let result = backend.create_directory_with_queue("/new-folder").unwrap();
    let VaultDirectoryCreateOutcome::Committed(created) = result else {
        panic!("a verified online MKCOL should be committed")
    };
    assert_eq!(created.path, "/new-folder");
    assert!(created.directory);
    assert!(!created.id.is_empty());

    let mkcols = fixture
        .requests()
        .into_iter()
        .filter(|request| request.method == "MKCOL")
        .collect::<Vec<_>>();
    assert_eq!(mkcols.len(), 1);
    assert_eq!(
        mkcols[0].headers.get("if-none-match").map(String::as_str),
        Some("*")
    );
    assert!(
        mkcols[0]
            .headers
            .get("if")
            .is_some_and(|condition| condition.contains("[\"root-rev-2\"]")),
        "MKCOL must carry the original strong parent validator"
    );
    assert!(!mkcols[0].target.contains("new-folder"));
}

#[test]
fn encrypted_directory_create_never_replaces_an_existing_file_or_directory() {
    let fixture = Fixture::start();
    let (backend, _, _, _state, _cache) = setup_cached(&fixture);
    let existing = backend.mkdir(SPACE, "/already-here").unwrap();
    assert!(existing.directory);
    let before = fixture
        .requests()
        .iter()
        .filter(|request| request.method == "MKCOL")
        .count();
    assert_eq!(
        backend
            .create_directory_with_queue("/already-here")
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict,
    );
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request.method == "MKCOL")
            .count(),
        before,
        "an existing directory must be rejected before issuing another MKCOL"
    );
}

#[test]
fn encrypted_directory_create_queues_and_overlays_only_while_unlocked() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, _state, cache) = setup_cached(&fixture);
    let mut initial = Vec::new();
    backend
        .list(SPACE, "/", &mut |entry| {
            initial.push(entry);
            Ok(())
        })
        .unwrap();
    fixture.disconnect(true);

    let VaultDirectoryCreateOutcome::Queued {
        entry,
        write_id,
        revision,
        uncertain,
    } = backend
        .create_directory_with_queue("/offline-folder")
        .unwrap()
    else {
        panic!("offline MKCOL must remain queued")
    };
    assert!(!uncertain);
    assert!(entry.directory);
    assert!(!entry.writable);
    assert!(entry.id.starts_with("raiun-pending-directory:"));
    assert_eq!(backend.stat(SPACE, "/offline-folder").unwrap(), entry);

    let mut names = Vec::new();
    backend
        .list(SPACE, "/", &mut |item| {
            names.push(item.path);
            Ok(())
        })
        .unwrap();
    assert!(names.iter().any(|path| path == "/offline-folder"));
    let mut pending_children = Vec::new();
    backend
        .list(SPACE, "/offline-folder", &mut |item| {
            pending_children.push(item.path);
            Ok(())
        })
        .unwrap();
    assert!(
        pending_children.is_empty(),
        "an offline queued directory is locally visible and has an empty listing"
    );
    fixture.disconnect(false);
    let committed = backend
        .reconcile_pending_directory_create(&write_id, revision)
        .unwrap();
    assert!(committed.directory);
    assert!(!committed.id.starts_with("raiun-pending-directory:"));
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request.method == "MKCOL")
            .count(),
        1
    );
    let journal = VaultOfflineCache::new(cache, scope, ROOT_PATH).unwrap();
    assert!(
        journal
            .pending_operation(&sessions, &write_id, revision)
            .is_err()
    );
}

#[test]
fn never_attempted_directory_create_can_be_cancelled_without_dav_mutation() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, _state, cache) = setup_cached(&fixture);
    backend.list(SPACE, "/", &mut |_| Ok(())).unwrap();
    fixture.disconnect(true);

    let VaultDirectoryCreateOutcome::Queued {
        entry,
        write_id,
        revision,
        uncertain,
    } = backend.create_directory_with_queue("/cancel-me").unwrap()
    else {
        panic!("offline directory create must remain queued")
    };
    assert!(!uncertain);
    assert!(entry.id.starts_with("raiun-pending-directory:"));
    assert_eq!(
        cache
            .ciphertext_writes(&encrypted_cache_scope(&scope), None, 100,)
            .unwrap()
            .0
            .iter()
            .find(|row| row.id == write_id)
            .unwrap()
            .state,
        CiphertextWriteState::NeverAttempted
    );

    assert_eq!(
        backend
            .cancel_never_attempted_directory_create(
                "/cancel-me",
                &write_id,
                revision,
                "raiun-pending-directory:wrong",
                &entry.etag,
            )
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict
    );
    assert_eq!(
        backend
            .cancel_never_attempted_directory_create(
                "/cancel-me",
                &write_id,
                revision,
                &entry.id,
                "raiun-pending-v1:wrong:1",
            )
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict
    );
    assert_eq!(
        VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH)
            .unwrap()
            .pending_operation(&sessions, &write_id, revision)
            .unwrap()
            .state,
        CiphertextWriteState::NeverAttempted,
        "a stale projection cannot erase the durable reservation"
    );

    backend
        .cancel_never_attempted_directory_create(
            "/cancel-me",
            &write_id,
            revision,
            &entry.id,
            &entry.etag,
        )
        .unwrap();
    let journal = VaultOfflineCache::new(cache, scope, ROOT_PATH).unwrap();
    assert!(
        journal
            .pending_operation(&sessions, &write_id, revision)
            .is_err()
    );
    let mut visible = Vec::new();
    backend
        .list(SPACE, "/", &mut |item| {
            visible.push(item.path);
            Ok(())
        })
        .unwrap();
    assert!(!visible.iter().any(|path| path == "/cancel-me"));
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request.method == "MKCOL")
            .count(),
        0,
        "local cancellation never issues DAV MKCOL"
    );
}

#[test]
fn never_attempted_empty_directory_retarget_preserves_identity_and_never_uses_dav() {
    let fixture = Fixture::start();
    let (backend, _sessions, _scope, _state, _cache) = setup_cached(&fixture);
    backend.list(SPACE, "/", &mut |_| Ok(())).unwrap();
    let root = backend.stat(SPACE, "/").unwrap();
    let root_ref = backend
        .parent_ref_for_directory("/", &root.id, &root.etag)
        .unwrap();
    fixture.disconnect(true);

    let queued_directory = |path: &str| {
        let VaultDirectoryCreateOutcome::Queued {
            entry,
            write_id,
            revision,
            uncertain,
        } = backend
            .create_directory_with_parent_queue(path, &root_ref)
            .unwrap()
        else {
            panic!("offline directory create must remain queued")
        };
        assert!(!uncertain);
        (entry, write_id, revision)
    };
    let (source, source_id, source_revision) = queued_directory("/old-folder");
    let (destination_parent, _, _) = queued_directory("/destination-parent");
    let destination_parent_ref = backend
        .parent_ref_for_directory(
            "/destination-parent",
            &destination_parent.id,
            &destination_parent.etag,
        )
        .unwrap();
    let before = fixture.requests().len();

    let moved = backend
        .rename_never_attempted_directory_create_with_queue(
            "/old-folder",
            "/destination-parent/moved-folder",
            &source.id,
            &source.etag,
            &destination_parent_ref,
        )
        .unwrap();
    assert_eq!(moved.id, source_id);
    assert_eq!(moved.revision, source_revision + 1);
    assert_eq!(
        moved.operation,
        raiun_opencloud::vault_cache::VaultPendingOperationKind::CreateDirectory
    );
    assert_eq!(moved.state, CiphertextWriteState::NeverAttempted);
    assert_eq!(moved.base, WriteCondition::Absent);
    assert_eq!(moved.path, "/destination-parent/moved-folder");
    assert_eq!(moved.parent_ref, Some(destination_parent_ref));
    assert_eq!(
        fixture.requests().len(),
        before,
        "queued retarget is local-only"
    );
    assert_eq!(
        backend.stat(SPACE, "/old-folder").unwrap_err().kind,
        raiun_core::backend::ErrorKind::NotFound
    );
    let projected = backend
        .stat(SPACE, "/destination-parent/moved-folder")
        .unwrap();
    assert_eq!(projected.id, source.id);
    assert_eq!(
        projected.etag,
        format!("raiun-pending-v1:{source_id}:{}", source_revision + 1)
    );
}

#[test]
fn populated_never_attempted_directory_retarget_reseals_nested_dependencies_without_dav() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, _state, cache) = setup_cached(&fixture);
    seed_and_cache_file(&backend, &_state, "occupied.txt", b"existing destination");
    backend.list(SPACE, "/", &mut |_| Ok(())).unwrap();
    let root = backend.stat(SPACE, "/").unwrap();
    let root_ref = backend
        .parent_ref_for_directory("/", &root.id, &root.etag)
        .unwrap();
    fixture.disconnect(true);

    let (root_entry, root_id, root_revision) = match backend
        .create_directory_with_parent_queue("/old-tree", &root_ref)
        .unwrap()
    {
        VaultDirectoryCreateOutcome::Queued {
            entry,
            write_id,
            revision,
            uncertain: false,
        } => (entry, write_id, revision),
        other => panic!("unexpected queued directory outcome: {other:?}"),
    };
    let old_root_ref = backend
        .parent_ref_for_directory("/old-tree", &root_entry.id, &root_entry.etag)
        .unwrap();
    let (child_entry, child_id, child_revision) = match backend
        .create_directory_with_parent_queue("/old-tree/nested", &old_root_ref)
        .unwrap()
    {
        VaultDirectoryCreateOutcome::Queued {
            entry,
            write_id,
            revision,
            uncertain: false,
        } => (entry, write_id, revision),
        other => panic!("unexpected nested directory outcome: {other:?}"),
    };
    let old_child_ref = backend
        .parent_ref_for_directory("/old-tree/nested", &child_entry.id, &child_entry.etag)
        .unwrap();
    let target = backend
        .prepare_file_create_target_for_parent("/old-tree/nested/file.txt", &old_child_ref, None)
        .unwrap();
    let contents = b"authenticated subtree body survives resealing";
    let mut source = std::io::Cursor::new(contents.to_vec());
    let VaultUploadOutcome::QueuedCreate {
        entry: file_entry,
        write_id: file_id,
        revision: file_revision,
        uncertain: false,
    } = backend
        .create_prepared_reader_with_queue_for_parent(
            &target,
            &mut source,
            contents.len() as u64,
            None,
            &old_child_ref,
        )
        .unwrap()
    else {
        panic!("offline child file must be queued")
    };

    let expected = vec![
        VaultPendingDirectorySubtreeRetargetExpectedRevision {
            write_id: root_id.clone(),
            previous_revision: root_revision,
            revision: root_revision + 1,
        },
        VaultPendingDirectorySubtreeRetargetExpectedRevision {
            write_id: child_id.clone(),
            previous_revision: child_revision,
            revision: child_revision + 1,
        },
        VaultPendingDirectorySubtreeRetargetExpectedRevision {
            write_id: file_id.clone(),
            previous_revision: file_revision,
            revision: file_revision + 1,
        },
    ];
    let old_resolution = backend
        .resolve_never_attempted_directory_subtree_retarget_by_ids(
            &root_id,
            root_revision,
            &expected,
        )
        .unwrap();
    assert_eq!(
        old_resolution.state,
        VaultPendingDirectorySubtreeRetargetResolutionState::AllOld
    );
    assert_eq!(old_resolution.scope, scope);
    assert_eq!(old_resolution.rows.len(), 3);
    assert!(
        old_resolution
            .rows
            .iter()
            .any(|row| row.path == "/old-tree")
    );
    assert!(
        old_resolution
            .rows
            .iter()
            .any(|row| row.path == "/old-tree/nested/file.txt")
    );

    let before = fixture.requests().len();
    assert_eq!(
        backend
            .retarget_never_attempted_directory_subtree_with_queue(
                "/old-tree",
                "/occupied.txt",
                &root_entry.id,
                &root_entry.etag,
                &root_ref,
            )
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict
    );
    assert_eq!(
        fixture.requests().len(),
        before,
        "collision is journal-only"
    );
    assert_eq!(
        VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH)
            .unwrap()
            .pending_operation(&sessions, &root_id, root_revision)
            .unwrap()
            .revision,
        root_revision
    );
    let mut wal_rows = 0;
    let abort = backend
        .retarget_never_attempted_directory_subtree_before_publish(
            "/old-tree",
            "/renamed-tree",
            &root_entry.id,
            &root_entry.etag,
            &root_ref,
            |plan| {
                wal_rows = plan.rows.len();
                Err(raiun_core::backend::CloudError::new(
                    raiun_core::backend::ErrorKind::Io,
                    "synthetic WAL persistence failure",
                ))
            },
        )
        .unwrap_err();
    assert_eq!(abort.kind, raiun_core::backend::ErrorKind::Io);
    assert_eq!(wal_rows, 3, "the callback sees the complete bounded plan");
    assert_eq!(
        backend
            .resolve_never_attempted_directory_subtree_retarget_by_ids(
                &root_id,
                root_revision,
                &expected,
            )
            .unwrap()
            .state,
        VaultPendingDirectorySubtreeRetargetResolutionState::AllOld,
        "a failed durable-WAL callback must not publish any journal row"
    );
    let before_actual_retarget = fixture.requests().len();
    let retarget = backend
        .retarget_never_attempted_directory_subtree_with_queue(
            "/old-tree",
            "/renamed-tree",
            &root_entry.id,
            &root_entry.etag,
            &root_ref,
        )
        .unwrap();
    assert_eq!(retarget.root_write_id, root_id);
    assert_eq!(retarget.root_previous_revision, root_revision);
    assert_eq!(retarget.root_revision, root_revision + 1);
    assert_eq!(retarget.rows.len(), 3);
    assert_eq!(
        fixture.requests().len(),
        before_actual_retarget,
        "retarget is journal-only"
    );
    let new_resolution = backend
        .resolve_never_attempted_directory_subtree_retarget_by_ids(
            &root_id,
            root_revision,
            &expected,
        )
        .unwrap();
    assert_eq!(
        new_resolution.state,
        VaultPendingDirectorySubtreeRetargetResolutionState::AllNew
    );
    assert_eq!(new_resolution.scope, scope);
    let mut incomplete = expected.clone();
    incomplete.pop();
    assert!(
        backend
            .resolve_never_attempted_directory_subtree_retarget_by_ids(
                &root_id,
                root_revision,
                &incomplete,
            )
            .is_err(),
        "a WAL missing a member cannot authorize partial recovery"
    );
    let root_row = retarget
        .rows
        .iter()
        .find(|row| row.write_id == root_id)
        .unwrap();
    let child_row = retarget
        .rows
        .iter()
        .find(|row| row.write_id == child_id)
        .unwrap();
    let file_row = retarget
        .rows
        .iter()
        .find(|row| row.write_id == file_id)
        .unwrap();
    assert_eq!(root_row.path, "/renamed-tree");
    assert_eq!(child_row.path, "/renamed-tree/nested");
    assert_eq!(file_row.path, "/renamed-tree/nested/file.txt");
    assert_eq!(root_row.revision, root_revision + 1);
    assert_eq!(child_row.revision, child_revision + 1);
    assert_eq!(file_row.revision, file_revision + 1);
    assert_eq!(root_row.parent_ref, root_ref);
    assert_eq!(
        child_row.parent_ref,
        VaultPendingParentRef::PendingCreate {
            write_id: root_id.clone(),
            revision: root_revision + 1,
        }
    );
    assert_eq!(
        file_row.parent_ref,
        VaultPendingParentRef::PendingCreate {
            write_id: child_id.clone(),
            revision: child_revision + 1,
        }
    );
    assert_eq!(root_row.plaintext_len, 0);
    assert!(root_row.plaintext_sha256.is_empty());
    assert_eq!(child_row.plaintext_len, 0);
    assert!(child_row.plaintext_sha256.is_empty());
    assert_eq!(file_row.plaintext_len, contents.len() as u64);
    assert_eq!(
        file_row.plaintext_sha256,
        Sha256::digest(contents)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    assert_eq!(
        backend.stat(SPACE, "/old-tree").unwrap_err().kind,
        raiun_core::backend::ErrorKind::NotFound
    );
    assert_eq!(
        backend
            .stat(SPACE, "/renamed-tree/nested/file.txt")
            .unwrap()
            .id,
        file_entry.id
    );

    let journal = VaultOfflineCache::new(cache, scope, ROOT_PATH).unwrap();
    let plaintext = tempfile::tempdir().unwrap();
    let output = plaintext.path().join("recovered.bin");
    journal
        .download_pending_edit(&sessions, &file_id, file_revision + 1, &output)
        .unwrap();
    assert_eq!(std::fs::read(output).unwrap(), contents);
}

#[test]
fn queued_directory_retarget_rejects_children_and_attempted_generations() {
    let fixture = Fixture::start();
    let (backend, _sessions, scope, _state, cache) = setup_cached(&fixture);
    backend.list(SPACE, "/", &mut |_| Ok(())).unwrap();
    let root = backend.stat(SPACE, "/").unwrap();
    let root_ref = backend
        .parent_ref_for_directory("/", &root.id, &root.etag)
        .unwrap();
    fixture.disconnect(true);
    let VaultDirectoryCreateOutcome::Queued {
        entry: parent,
        write_id,
        ..
    } = backend
        .create_directory_with_parent_queue("/parent", &root_ref)
        .unwrap()
    else {
        panic!("offline directory create must remain queued")
    };
    let parent_ref = backend
        .parent_ref_for_directory("/parent", &parent.id, &parent.etag)
        .unwrap();
    let VaultDirectoryCreateOutcome::Queued { .. } = backend
        .create_directory_with_parent_queue("/parent/child", &parent_ref)
        .unwrap()
    else {
        panic!("offline child directory must remain queued")
    };
    assert!(
        backend
            .rename_never_attempted_directory_create_with_queue(
                "/parent",
                "/renamed-parent",
                &parent.id,
                &parent.etag,
                &root_ref,
            )
            .is_err()
    );

    // A durable attempt claim wins even when a caller still presents the
    // previously valid synthetic ID and ETag.
    let attempted = backend
        .create_directory_with_parent_queue("/attempted", &root_ref)
        .unwrap();
    let VaultDirectoryCreateOutcome::Queued {
        entry,
        write_id: attempted_id,
        revision: attempted_revision,
        ..
    } = attempted
    else {
        panic!("offline directory create must remain queued")
    };
    cache
        .claim_ciphertext_directory_create_attempt(
            &encrypted_cache_scope(&scope),
            &attempted_id,
            attempted_revision,
        )
        .unwrap();
    assert!(
        backend
            .rename_never_attempted_directory_create_with_queue(
                "/attempted",
                "/attempted-new",
                &entry.id,
                &entry.etag,
                &root_ref,
            )
            .is_err()
    );
    assert!(
        cache
            .ciphertext_writes(&encrypted_cache_scope(&scope), None, 100)
            .unwrap()
            .0
            .iter()
            .any(|row| row.id == write_id && row.state == CiphertextWriteState::NeverAttempted)
    );
}

#[test]
fn never_attempted_file_create_can_be_cancelled_without_dav_mutation() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, _state, cache) = setup_cached(&fixture);
    backend.list(SPACE, "/", &mut |_| Ok(())).unwrap();
    let root = backend.stat(SPACE, "/").unwrap();
    let parent_ref = backend
        .parent_ref_for_directory("/", &root.id, &root.etag)
        .unwrap();
    fixture.disconnect(true);

    let path = "/cancel-file.txt";
    let target = backend
        .prepare_file_create_target_for_parent(path, &parent_ref, None)
        .unwrap();
    let body_bytes = b"local file bytes must be verified before cancellation";
    let mut body = std::io::Cursor::new(body_bytes.to_vec());
    let VaultUploadOutcome::QueuedCreate {
        entry,
        write_id,
        revision,
        uncertain: false,
    } = backend
        .create_prepared_reader_with_queue_for_parent(
            &target,
            &mut body,
            body_bytes.len() as u64,
            None,
            &parent_ref,
        )
        .unwrap()
    else {
        panic!("offline file create must remain a never-attempted local row")
    };
    assert!(entry.id.starts_with("raiun-pending-create:"));
    let journal = VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH).unwrap();
    let operation = journal
        .pending_operation(&sessions, &write_id, revision)
        .unwrap();
    assert_eq!(operation.state, CiphertextWriteState::NeverAttempted);
    assert_eq!(operation.base, WriteCondition::Absent);
    assert_eq!(operation.path, path);
    assert!(
        backend
            .resolve_pending_create_by_id(&write_id)
            .unwrap()
            .unwrap()
            .plaintext_sha256
            .is_some()
    );

    assert_eq!(
        backend
            .cancel_never_attempted_file_create(
                path,
                &write_id,
                revision,
                "raiun-pending-create:wrong",
                &entry.etag,
            )
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict
    );
    assert_eq!(
        backend
            .cancel_never_attempted_file_create(
                path,
                &write_id,
                revision,
                &entry.id,
                "raiun-pending-v1:wrong:1",
            )
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict
    );
    assert_eq!(
        backend
            .cancel_never_attempted_file_create(
                "/different-path.txt",
                &write_id,
                revision,
                &entry.id,
                &entry.etag,
            )
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict
    );
    assert_eq!(
        journal
            .pending_operation(&sessions, &write_id, revision)
            .unwrap(),
        operation,
        "stale identity/path attempts leave the exact recovery row untouched"
    );
    assert!(
        backend
            .resolve_cancelled_file_create_by_id(&write_id, revision)
            .unwrap()
            .is_none(),
        "a valid NeverAttempted row has no cancellation receipt until the exact CAS succeeds"
    );

    let receipt = backend
        .cancel_never_attempted_file_create(path, &write_id, revision, &entry.id, &entry.etag)
        .unwrap();
    assert_eq!(receipt.scope, scope);
    assert_eq!(receipt.metadata.id, write_id);
    assert_eq!(receipt.metadata.revision, revision);
    assert_eq!(
        receipt.metadata.state,
        CiphertextWriteState::CancelledReceipt
    );
    assert_eq!(receipt.metadata.path, path);
    assert_eq!(receipt.metadata.encoded_target, target);
    assert_eq!(receipt.metadata.plaintext_len, body_bytes.len() as u64);
    assert_eq!(
        receipt.plaintext_sha256,
        format!("{:x}", Sha256::digest(body_bytes))
    );

    let repeated = backend
        .cancel_never_attempted_file_create(path, &write_id, revision, &entry.id, &entry.etag)
        .unwrap();
    assert_eq!(
        repeated, receipt,
        "recovery can repeat exact cancellation after restart"
    );
    assert_eq!(
        journal
            .pending_operation(&sessions, &write_id, revision)
            .unwrap()
            .state,
        CiphertextWriteState::CancelledReceipt
    );

    assert_eq!(
        backend
            .acknowledge_cancelled_file_create(
                &write_id,
                revision,
                &receipt.metadata.encoded_target,
                receipt.metadata.plaintext_len,
                "00".repeat(32).as_str(),
            )
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict,
        "a mismatching local-recovery digest cannot retire the receipt"
    );

    // A new coordinator/backend can still resolve the exact receipt after a
    // crash between the cancellation CAS and local working-copy retirement.
    let reopened_cache = Cache::open(_state.path(), 16 * 1024 * 1024).unwrap();
    let offline_cache =
        VaultOfflineCache::new(reopened_cache.clone(), scope.clone(), ROOT_PATH).unwrap();
    let restarted_sessions = Arc::new(VaultSessionCoordinator::new());
    let mut password = b"potato".to_vec();
    let (snapshot, _) = offline_cache
        .unlock_root(&restarted_sessions, &mut password)
        .unwrap();
    let restarted = VaultBackend::new_from_cached_root(
        OpenCloudClient::new(&fixture.origin(), "synthetic-token".to_owned()).unwrap(),
        Arc::clone(&restarted_sessions),
        scope.clone(),
        ROOT_PATH.to_owned(),
        offline_cache,
        snapshot,
    )
    .unwrap();
    let recovered_receipt = restarted
        .resolve_cancelled_file_create_by_id(&write_id, revision)
        .unwrap()
        .expect("durable cancellation receipt survives restart");
    assert_eq!(recovered_receipt, receipt);
    assert_eq!(
        restarted
            .reconcile_pending_operation(&write_id, revision)
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict,
        "a cancellation receipt must never be replayed as an upload"
    );
    let mut while_receipt_retained = Vec::new();
    restarted
        .list(SPACE, "/", &mut |item| {
            while_receipt_retained.push(item.path);
            Ok(())
        })
        .unwrap();
    assert!(!while_receipt_retained.iter().any(|item| item == path));
    restarted
        .acknowledge_cancelled_file_create(
            &write_id,
            revision,
            &receipt.metadata.encoded_target,
            receipt.metadata.plaintext_len,
            &receipt.plaintext_sha256,
        )
        .unwrap();
    let acknowledged = restarted
        .resolve_cancelled_file_create_by_id(&write_id, revision)
        .unwrap()
        .expect("acknowledged receipt survives a crash before local WAL removal");
    assert_eq!(
        acknowledged.state,
        VaultCancelledCreateReceiptState::Acknowledged
    );
    assert_eq!(acknowledged.original_revision, revision);
    assert_eq!(acknowledged.current_revision, revision + 1);
    assert_eq!(acknowledged.plaintext_len, body_bytes.len() as u64);
    assert_eq!(acknowledged.plaintext_sha256, receipt.plaintext_sha256);
    assert_eq!(acknowledged.metadata.plaintext_len, 0);
    assert_eq!(
        acknowledged.metadata.state,
        CiphertextWriteState::AcknowledgedReceipt
    );
    assert_eq!(
        reopened_cache
            .open_ciphertext_write(
                &CacheScope::new(
                    &fixture.origin(),
                    scope.account_id(),
                    SPACE,
                    ROOT_ID,
                    ScopeProtection::CiphertextOnly,
                )
                .unwrap(),
                &write_id,
                revision,
            )
            .unwrap_err(),
        CacheError::NotFound,
        "the compact receipt must not retain the cancelled body"
    );
    restarted
        .acknowledge_cancelled_file_create(
            &write_id,
            revision,
            &receipt.metadata.encoded_target,
            receipt.metadata.plaintext_len,
            &receipt.plaintext_sha256,
        )
        .expect("repeated acknowledgement is idempotent after restart");
    assert_eq!(
        restarted
            .finalize_cancelled_file_create_ack(
                &write_id,
                revision,
                acknowledged.current_revision,
                "encrypted-parent/wrong-target",
                receipt.plaintext_len,
                &receipt.plaintext_sha256,
            )
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict,
        "finalization must match the exact acknowledged target"
    );
    restarted
        .finalize_cancelled_file_create_ack(
            &write_id,
            revision,
            acknowledged.current_revision,
            &receipt.metadata.encoded_target,
            receipt.plaintext_len,
            &receipt.plaintext_sha256,
        )
        .unwrap();
    assert!(
        journal
            .pending_operation_current(&sessions, &write_id)
            .unwrap()
            .is_none()
    );
    assert!(
        restarted
            .resolve_cancelled_file_create_by_id(&write_id, revision)
            .unwrap()
            .is_none()
    );
    assert!(
        restarted
            .cancel_never_attempted_file_create(path, &write_id, revision, &entry.id, &entry.etag)
            .is_err()
    );
    let mut visible = Vec::new();
    backend
        .list(SPACE, "/", &mut |item| {
            visible.push(item.path);
            Ok(())
        })
        .unwrap();
    assert!(!visible.iter().any(|item| item == path));
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| matches!(
                request.method.as_str(),
                "PUT" | "MKCOL" | "DELETE" | "MOVE"
            ))
            .count(),
        0,
        "local cancellation must never issue a remote mutation"
    );
}

#[test]
fn attempted_file_create_cannot_be_cancelled_or_drop_its_sealed_body() {
    let fixture = Fixture::start();
    let (backend, _sessions, scope, _state, cache) = setup_cached(&fixture);
    backend.list(SPACE, "/", &mut |_| Ok(())).unwrap();
    let root = backend.stat(SPACE, "/").unwrap();
    let parent_ref = backend
        .parent_ref_for_directory("/", &root.id, &root.etag)
        .unwrap();
    fixture.disconnect(true);
    let target = backend
        .prepare_file_create_target_for_parent("/attempted.txt", &parent_ref, None)
        .unwrap();
    let bytes = b"retain this body after an attempt claim";
    let mut body = std::io::Cursor::new(bytes.to_vec());
    let VaultUploadOutcome::QueuedCreate {
        entry,
        write_id,
        revision,
        ..
    } = backend
        .create_prepared_reader_with_queue_for_parent(
            &target,
            &mut body,
            bytes.len() as u64,
            None,
            &parent_ref,
        )
        .unwrap()
    else {
        panic!("offline file create must remain queued")
    };
    cache
        .claim_ciphertext_file_create_attempt(&encrypted_cache_scope(&scope), &write_id, revision)
        .unwrap();
    assert_eq!(
        backend
            .cancel_never_attempted_file_create(
                "/attempted.txt",
                &write_id,
                revision,
                &entry.id,
                &entry.etag,
            )
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict
    );
    assert_eq!(
        cache
            .ciphertext_write_info(&encrypted_cache_scope(&scope), &write_id)
            .unwrap()
            .state,
        CiphertextWriteState::Attempting
    );
}

#[test]
fn never_attempted_file_create_retargets_sealed_body_and_parent_without_dav_mutation() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, _state, cache) = setup_cached(&fixture);
    backend.list(SPACE, "/", &mut |_| Ok(())).unwrap();
    let root = backend.stat(SPACE, "/").unwrap();
    let parent_ref = backend
        .parent_ref_for_directory("/", &root.id, &root.etag)
        .unwrap();
    fixture.disconnect(true);

    let old_target = backend
        .prepare_file_create_target_for_parent("/draft.txt", &parent_ref, None)
        .unwrap();
    let mut body = std::io::Cursor::new(b"local encrypted draft".to_vec());
    let VaultUploadOutcome::QueuedCreate {
        entry: original,
        write_id,
        revision,
        uncertain,
    } = backend
        .create_prepared_reader_with_queue_for_parent(
            &old_target,
            &mut body,
            b"local encrypted draft".len() as u64,
            None,
            &parent_ref,
        )
        .unwrap()
    else {
        panic!("offline create must remain queued")
    };
    assert!(!uncertain);
    assert_eq!(original.path, "/draft.txt");
    assert_eq!(
        VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH)
            .unwrap()
            .pending_operation(&sessions, &write_id, revision)
            .unwrap()
            .state,
        CiphertextWriteState::NeverAttempted
    );

    let renamed = backend
        .rename_pending_create_with_queue(
            "/draft.txt",
            "/final.txt",
            &original.id,
            &original.etag,
            &parent_ref,
        )
        .unwrap();
    assert_eq!(renamed.id, write_id);
    assert_eq!(renamed.revision, revision + 1);
    assert_eq!(renamed.path, "/final.txt");
    assert_ne!(renamed.encoded_target, old_target);
    assert_eq!(renamed.base, WriteCondition::Absent);
    assert_eq!(renamed.parent_ref, Some(parent_ref.clone()));
    assert_eq!(renamed.state, CiphertextWriteState::NeverAttempted);
    let latest = VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH)
        .unwrap()
        .pending_operation(&sessions, &write_id, renamed.revision)
        .unwrap();
    assert_eq!(latest.path, "/final.txt");
    assert_eq!(latest.encoded_target, renamed.encoded_target);
    assert_eq!(latest.base, WriteCondition::Absent);
    let resolved = backend
        .resolve_pending_create_by_id(&write_id)
        .unwrap()
        .expect("retargeted operation resolves by exact ID");
    assert_eq!(resolved.scope, scope);
    assert_eq!(resolved.metadata, latest);
    assert_eq!(
        resolved.plaintext_sha256,
        Some(format!("{:x}", Sha256::digest(b"local encrypted draft")))
    );
    assert_eq!(
        backend.stat(SPACE, "/draft.txt").unwrap_err().kind,
        raiun_core::backend::ErrorKind::NotFound
    );
    let local_entry = backend.stat(SPACE, "/final.txt").unwrap();
    assert_eq!(local_entry.id, original.id);
    assert_eq!(
        local_entry.etag,
        format!("raiun-pending-v1:{write_id}:{}", revision + 1)
    );

    let recovered_dir = tempfile::tempdir().unwrap();
    let recovered = recovered_dir.path().join("recovered-create-body.bin");
    VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH)
        .unwrap()
        .download_pending_edit(&sessions, &write_id, renamed.revision, &recovered)
        .unwrap();
    assert_eq!(std::fs::read(&recovered).unwrap(), b"local encrypted draft");
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| matches!(request.method.as_str(), "PUT" | "MOVE" | "DELETE"))
            .count(),
        0,
        "a local create rename must not send any remote mutation"
    );
}

#[test]
fn never_attempted_file_retarget_rebinds_exact_pending_parent_dependency() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, _state, cache) = setup_cached(&fixture);
    backend.list(SPACE, "/", &mut |_| Ok(())).unwrap();
    let root = backend.stat(SPACE, "/").unwrap();
    let root_ref = backend
        .parent_ref_for_directory("/", &root.id, &root.etag)
        .unwrap();
    fixture.disconnect(true);
    let first = match backend
        .create_directory_with_parent_queue("/first", &root_ref)
        .unwrap()
    {
        raiun_opencloud::vault_backend::VaultDirectoryCreateOutcome::Queued {
            entry,
            write_id,
            revision,
            ..
        } => (entry, write_id, revision),
        _ => panic!("offline directory must be queued"),
    };
    let second = match backend
        .create_directory_with_parent_queue("/second", &root_ref)
        .unwrap()
    {
        raiun_opencloud::vault_backend::VaultDirectoryCreateOutcome::Queued {
            entry,
            write_id,
            revision,
            ..
        } => (entry, write_id, revision),
        _ => panic!("offline directory must be queued"),
    };
    let first_ref = backend
        .parent_ref_for_directory("/first", &first.0.id, &first.0.etag)
        .unwrap();
    let second_ref = backend
        .parent_ref_for_directory("/second", &second.0.id, &second.0.etag)
        .unwrap();
    let old_target = backend
        .prepare_file_create_target_for_parent("/first/draft.txt", &first_ref, None)
        .unwrap();
    let mut body = std::io::Cursor::new(b"body under old parent".to_vec());
    let VaultUploadOutcome::QueuedCreate {
        entry,
        write_id,
        revision,
        ..
    } = backend
        .create_prepared_reader_with_queue_for_parent(
            &old_target,
            &mut body,
            b"body under old parent".len() as u64,
            None,
            &first_ref,
        )
        .unwrap()
    else {
        panic!("offline file create must be queued")
    };

    let moved = backend
        .rename_pending_create_with_queue(
            "/first/draft.txt",
            "/second/final.txt",
            &entry.id,
            &entry.etag,
            &second_ref,
        )
        .unwrap();
    assert_eq!(moved.id, write_id);
    assert_eq!(moved.revision, revision + 1);
    assert_eq!(moved.parent_ref, Some(second_ref.clone()));
    assert_eq!(moved.parent_resource_id, "");
    assert_eq!(moved.path, "/second/final.txt");
    let journal = VaultOfflineCache::new(cache, scope, ROOT_PATH).unwrap();
    assert!(
        journal
            .pending_operations_for_parent_ref(&sessions, &first_ref, None, 10)
            .unwrap()
            .0
            .iter()
            .all(|child| child.id != write_id)
    );
    assert!(
        journal
            .pending_operations_for_parent_ref(&sessions, &second_ref, None, 10)
            .unwrap()
            .0
            .iter()
            .any(|child| child.id == write_id && child.revision == moved.revision)
    );
}

#[test]
fn legacy_pending_file_create_is_never_retargetable() {
    let fixture = Fixture::start();
    let (backend, _sessions, scope, _state, cache) = setup_cached(&fixture);
    backend.list(SPACE, "/", &mut |_| Ok(())).unwrap();
    let root = backend.stat(SPACE, "/").unwrap();
    let parent_ref = backend
        .parent_ref_for_directory("/", &root.id, &root.etag)
        .unwrap();
    fixture.disconnect(true);
    let target = backend
        .prepare_file_create_target_for_parent("/legacy.txt", &parent_ref, None)
        .unwrap();
    let mut body = std::io::Cursor::new(b"legacy".to_vec());
    let VaultUploadOutcome::QueuedCreate {
        entry,
        write_id,
        revision,
        ..
    } = backend
        .create_prepared_reader_with_queue_for_parent(&target, &mut body, 6, None, &parent_ref)
        .unwrap()
    else {
        panic!("offline create must remain queued")
    };
    cache
        .set_ciphertext_write_state(
            &encrypted_cache_scope(&scope),
            &write_id,
            revision,
            CiphertextWriteState::Pending,
        )
        .unwrap();
    assert_eq!(
        backend
            .rename_pending_create_with_queue(
                "/legacy.txt",
                "/new-name.txt",
                &entry.id,
                &entry.etag,
                &parent_ref,
            )
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict
    );
    assert_eq!(
        backend.stat(SPACE, "/legacy.txt").unwrap().path,
        "/legacy.txt"
    );
    assert!(
        backend.stat(SPACE, "/new-name.txt").is_err(),
        "a legacy Pending row must not be moved or reinterpreted as never sent"
    );
}

#[test]
fn encrypted_file_create_under_pending_directory_waits_for_receipt_and_retires_it_after_readback() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, state_dir, cache) = setup_cached(&fixture);
    backend.list(SPACE, "/", &mut |_| Ok(())).unwrap();
    fixture.disconnect(true);

    let VaultDirectoryCreateOutcome::Queued {
        entry: pending_directory,
        write_id: directory_id,
        revision: directory_revision,
        ..
    } = backend
        .create_directory_with_queue("/queued-parent")
        .unwrap()
    else {
        panic!("offline directory create must remain queued")
    };
    let parent_ref = backend
        .parent_ref_for_directory(
            "/queued-parent",
            &pending_directory.id,
            &pending_directory.etag,
        )
        .unwrap();
    assert_eq!(
        parent_ref,
        VaultPendingParentRef::PendingCreate {
            write_id: directory_id.clone(),
            revision: directory_revision,
        }
    );

    let VaultDirectoryCreateOutcome::Queued {
        entry: pending_nested,
        write_id: nested_id,
        revision: nested_revision,
        ..
    } = backend
        .create_directory_with_parent_queue("/queued-parent/nested", &parent_ref)
        .unwrap()
    else {
        panic!("offline nested directory create must remain queued")
    };
    let nested_ref = backend
        .parent_ref_for_directory(
            "/queued-parent/nested",
            &pending_nested.id,
            &pending_nested.etag,
        )
        .unwrap();

    let encoded = backend
        .prepare_file_create_target_for_parent("/queued-parent/nested/child.txt", &nested_ref, None)
        .unwrap();
    let mut contents = std::io::Cursor::new(b"nested child".to_vec());
    let VaultUploadOutcome::QueuedCreate {
        write_id: child_id,
        revision: child_revision,
        ..
    } = backend
        .create_prepared_reader_with_queue_for_parent(
            &encoded,
            &mut contents,
            12,
            None,
            &nested_ref,
        )
        .unwrap()
    else {
        panic!("offline nested file create must remain queued")
    };

    let revalidated = backend
        .prepare_file_create_target_for_parent(
            "/queued-parent/nested/child.txt",
            &nested_ref,
            Some((&child_id, child_revision)),
        )
        .unwrap();
    assert_eq!(
        revalidated, encoded,
        "a queued create can be revalidated against its exact operation without colliding with itself"
    );

    // A later child in the same pending directory must validate its name
    // against the first child's encrypted DAV name. The plaintext suffix has
    // punctuation that is not valid base32hex and must never be sent to the
    // encrypted-name decoder.
    let sibling_path = "/queued-parent/nested/after-restart.txt";
    let sibling_target = backend
        .prepare_file_create_target_for_parent(sibling_path, &nested_ref, None)
        .expect("pending sibling names are encrypted before collision validation");
    assert_eq!(
        sessions
            .decrypt_path(&scope, &sibling_target)
            .unwrap()
            .into_components()
            .join("/"),
        sibling_path.trim_start_matches('/')
    );

    let duplicate = backend.prepare_file_create_target_for_parent(
        "/queued-parent/nested/child.txt",
        &nested_ref,
        None,
    );
    assert_eq!(
        duplicate.unwrap_err().kind,
        raiun_core::backend::ErrorKind::Conflict,
        "a pending sibling collision must block another create"
    );

    assert_eq!(
        backend
            .reconcile_pending_operation(&child_id, child_revision)
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Offline,
        "a child cannot publish before its parent has an exact server receipt"
    );
    assert_eq!(
        backend
            .reconcile_pending_directory_create(&nested_id, nested_revision)
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Offline,
        "a nested directory cannot publish before its own parent has a receipt"
    );
    assert_eq!(
        VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH)
            .unwrap()
            .pending_operation(&sessions, &child_id, child_revision)
            .unwrap()
            .state,
        CiphertextWriteState::NeverAttempted,
        "a blocked child remains a never-dispatched create rather than becoming a conflict"
    );
    assert!(
        !fixture
            .requests()
            .iter()
            .any(|request| request.method == "PUT")
    );

    sessions.lock(&scope).unwrap();
    let reopened_cache = Cache::open(state_dir.path(), 16 * 1024 * 1024).unwrap();
    let offline_cache =
        VaultOfflineCache::new(reopened_cache.clone(), scope.clone(), ROOT_PATH).unwrap();
    let restarted_sessions = Arc::new(VaultSessionCoordinator::new());
    let mut password = b"potato".to_vec();
    let (snapshot, _) = offline_cache
        .unlock_root(&restarted_sessions, &mut password)
        .unwrap();
    let restarted = VaultBackend::new_from_cached_root(
        OpenCloudClient::new(&fixture.origin(), "synthetic-token".to_owned()).unwrap(),
        Arc::clone(&restarted_sessions),
        scope.clone(),
        ROOT_PATH.to_owned(),
        offline_cache,
        snapshot,
    )
    .unwrap();
    let mut nested_listing = Vec::new();
    restarted
        .list(SPACE, "/queued-parent/nested", &mut |entry| {
            nested_listing.push(entry.path);
            Ok(())
        })
        .unwrap();
    assert_eq!(nested_listing, vec!["/queued-parent/nested/child.txt"]);
    assert_eq!(
        restarted
            .reconcile_pending_operation(&child_id, child_revision)
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Offline,
        "a restarted cached backend cannot publish while transport is offline"
    );

    fixture.disconnect(false);
    let online_cache = VaultOfflineCache::new(reopened_cache, scope.clone(), ROOT_PATH).unwrap();
    let online = VaultBackend::new_with_offline_cache(
        OpenCloudClient::new(&fixture.origin(), "synthetic-token".to_owned()).unwrap(),
        Arc::clone(&restarted_sessions),
        scope.clone(),
        ROOT_PATH.to_owned(),
        online_cache,
    )
    .unwrap();
    let parent_entry = online
        .reconcile_pending_directory_create(&directory_id, directory_revision)
        .unwrap();
    assert!(parent_entry.directory);
    let receipt = VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH)
        .unwrap()
        .directory_create_receipt(&restarted_sessions, &directory_id, directory_revision)
        .unwrap()
        .expect("parent receipt must remain while the child depends on it");
    assert_eq!(receipt.receipt_resource_id, parent_entry.id);

    let nested_entry = online
        .reconcile_pending_directory_create(&nested_id, nested_revision)
        .unwrap();
    assert!(nested_entry.directory);
    let nested_receipt = VaultOfflineCache::new(cache.clone(), scope.clone(), ROOT_PATH)
        .unwrap()
        .directory_create_receipt(&restarted_sessions, &nested_id, nested_revision)
        .unwrap()
        .expect("nested parent receipt must remain while the child depends on it");
    assert_eq!(nested_receipt.receipt_resource_id, nested_entry.id);

    let child_entry = online
        .reconcile_pending_operation(&child_id, child_revision)
        .unwrap();
    assert_eq!(child_entry.path, "/queued-parent/nested/child.txt");
    assert!(!child_entry.directory);
    let journal = VaultOfflineCache::new(cache, scope, ROOT_PATH).unwrap();
    assert!(
        journal
            .directory_create_receipt(&restarted_sessions, &nested_id, nested_revision)
            .unwrap()
            .is_none(),
        "the exact nested receipt is retired only after its dependent child is committed"
    );
    assert!(
        journal
            .directory_create_receipt(&restarted_sessions, &directory_id, directory_revision)
            .unwrap()
            .is_none(),
        "the top-level receipt is retired after its nested directory is rebound"
    );
    let requests = fixture.requests();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "MKCOL")
            .count(),
        2
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "PUT")
            .count(),
        1
    );
}

#[test]
fn encrypted_directory_create_survives_eviction_lock_and_cached_backend_restart() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, state_dir, cache) = setup_cached(&fixture);
    let file = seed_and_cache_file(&backend, &state_dir, "recent.txt", b"recent bytes");

    // The pending folder record is protected journal state, while this
    // ordinary recent content is explicitly evicted before the restart.
    let cache_scope = CacheScope::new(
        scope.server_origin(),
        scope.account_id(),
        scope.space_id(),
        scope.resource_id(),
        ScopeProtection::CiphertextOnly,
    )
    .unwrap();
    cache
        .set_policy_at(
            &cache_scope,
            &file.id,
            &file.path,
            &file.etag,
            raiun_cache::AvailabilityPolicy::CloudOnly,
        )
        .unwrap();
    fixture.clear_child();

    fixture.disconnect(true);
    let VaultDirectoryCreateOutcome::Queued {
        write_id, revision, ..
    } = backend
        .create_directory_with_queue("/offline-after-restart")
        .unwrap()
    else {
        panic!("offline MKCOL must remain queued")
    };
    sessions.lock(&scope).unwrap();

    let reopened_cache = Cache::open(state_dir.path(), 16 * 1024 * 1024).unwrap();
    let offline_cache = VaultOfflineCache::new(reopened_cache, scope.clone(), ROOT_PATH).unwrap();
    let new_sessions = Arc::new(VaultSessionCoordinator::new());
    let mut password = b"potato".to_vec();
    let (snapshot, _) = offline_cache
        .unlock_root(&new_sessions, &mut password)
        .unwrap();
    let restarted = VaultBackend::new_from_cached_root(
        OpenCloudClient::new(&fixture.origin(), "synthetic-token".to_owned()).unwrap(),
        Arc::clone(&new_sessions),
        scope.clone(),
        ROOT_PATH.to_owned(),
        offline_cache,
        snapshot,
    )
    .unwrap();

    let pending = restarted.stat(SPACE, "/offline-after-restart").unwrap();
    assert!(pending.directory);
    assert!(!pending.writable);
    let mut pending_children = Vec::new();
    restarted
        .list(SPACE, "/offline-after-restart", &mut |item| {
            pending_children.push(item.path);
            Ok(())
        })
        .unwrap();
    assert!(pending_children.is_empty());
    let evicted_copy = state_dir.path().join("evicted-copy.bin");
    assert_eq!(
        restarted
            .download(SPACE, "/recent.txt", Some(&file.etag), &evicted_copy)
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::NotFound,
        "CloudOnly bytes must stay evicted across the backend restart"
    );

    fixture.disconnect(false);
    let online_cache = VaultOfflineCache::new(cache, scope.clone(), ROOT_PATH).unwrap();
    let online = VaultBackend::new_with_offline_cache(
        OpenCloudClient::new(&fixture.origin(), "synthetic-token".to_owned()).unwrap(),
        Arc::clone(&new_sessions),
        scope,
        ROOT_PATH.to_owned(),
        online_cache,
    )
    .unwrap();
    let committed = online
        .reconcile_pending_directory_create(&write_id, revision)
        .unwrap();
    assert!(committed.directory);
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request.method == "MKCOL")
            .count(),
        1
    );
}

#[test]
fn encrypted_directory_create_lost_mkcol_response_never_claims_existing_path() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, _state, cache) = setup_cached(&fixture);
    fixture.lose_mkcol_response();
    let VaultDirectoryCreateOutcome::Queued {
        write_id,
        revision,
        uncertain,
        ..
    } = backend
        .create_directory_with_queue("/maybe-created")
        .unwrap()
    else {
        panic!("a lost response must stay queued")
    };
    assert!(uncertain);
    let uncertain_parent = VaultPendingParentRef::PendingCreate {
        write_id: write_id.clone(),
        revision,
    };
    assert!(
        backend
            .prepare_file_create_target_for_parent(
                "/maybe-created/child.txt",
                &uncertain_parent,
                None,
            )
            .is_err(),
        "an uncertain parent must not accept dependent child operations"
    );
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request.method == "MKCOL")
            .count(),
        1
    );

    fixture.state.lock().unwrap().lose_mkcol_response = false;
    let reconcile_error = backend
        .reconcile_pending_directory_create(&write_id, revision)
        .unwrap_err();
    assert!(
        matches!(
            reconcile_error.kind,
            raiun_core::backend::ErrorKind::Conflict
                | raiun_core::backend::ErrorKind::InvalidResponse
        ),
        "an ambiguous MKCOL readback must remain fail-closed: {reconcile_error:?}"
    );
    assert_eq!(
        fixture
            .requests()
            .iter()
            .filter(|request| request.method == "MKCOL")
            .count(),
        1,
        "existing destination without an owned readback must never be recreated"
    );
    assert!(
        !fixture
            .requests()
            .iter()
            .any(|request| request.method == "PUT"),
        "rejecting children of an uncertain parent must issue no upload"
    );
    let journal = VaultOfflineCache::new(cache, scope, ROOT_PATH).unwrap();
    assert!(matches!(
        journal
            .pending_operation(&sessions, &write_id, revision)
            .unwrap()
            .state,
        CiphertextWriteState::Uncertain | CiphertextWriteState::Conflict
    ));
}

#[test]
fn encrypted_directory_create_rejects_replaced_parent_before_mkcol() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, _state, cache) = setup_cached(&fixture);
    backend.list(SPACE, "/", &mut |_| Ok(())).unwrap();
    fixture.disconnect(true);
    let VaultDirectoryCreateOutcome::Queued {
        write_id, revision, ..
    } = backend
        .create_directory_with_queue("/queued-folder")
        .unwrap()
    else {
        panic!("offline MKCOL must queue")
    };
    fixture.replace_root_id("replacement-vault-root-id");
    fixture.disconnect(false);
    assert_eq!(
        backend
            .reconcile_pending_directory_create(&write_id, revision)
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict
    );
    assert!(
        !fixture
            .requests()
            .iter()
            .any(|request| request.method == "MKCOL"),
        "a replacement vault parent must not receive the queued MKCOL"
    );
    let journal = VaultOfflineCache::new(cache, scope, ROOT_PATH).unwrap();
    assert_eq!(
        journal
            .pending_operation(&sessions, &write_id, revision)
            .unwrap()
            .state,
        CiphertextWriteState::Conflict
    );
}

#[test]
fn encrypted_directory_create_rejects_parent_etag_and_root_token_changes() {
    let fixture = Fixture::start();
    let (backend, sessions, scope, _state, cache) = setup_cached(&fixture);
    backend.list(SPACE, "/", &mut |_| Ok(())).unwrap();
    fixture.disconnect(true);
    let VaultDirectoryCreateOutcome::Queued {
        write_id, revision, ..
    } = backend
        .create_directory_with_queue("/parent-etag-folder")
        .unwrap()
    else {
        panic!("offline MKCOL must queue")
    };
    fixture.replace_root_etag("\"root-rev-replaced\"");
    fixture.disconnect(false);
    assert_eq!(
        backend
            .reconcile_pending_directory_create(&write_id, revision)
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict
    );
    assert!(
        !fixture
            .requests()
            .iter()
            .any(|request| request.method == "MKCOL")
    );
    let journal = VaultOfflineCache::new(cache, scope.clone(), ROOT_PATH).unwrap();
    assert_eq!(
        journal
            .pending_operation(&sessions, &write_id, revision)
            .unwrap()
            .state,
        CiphertextWriteState::Conflict
    );

    // A root-token replacement independently fences a later queued create.
    fixture.replace_root_etag("\"root-rev-2\"");
    fixture.disconnect(true);
    let VaultDirectoryCreateOutcome::Queued {
        write_id, revision, ..
    } = backend
        .create_directory_with_queue("/root-token-folder")
        .unwrap()
    else {
        panic!("offline MKCOL must queue")
    };
    fixture.replace_token("not-the-unlocked-token");
    fixture.disconnect(false);
    assert_eq!(
        backend
            .reconcile_pending_directory_create(&write_id, revision)
            .unwrap_err()
            .kind,
        raiun_core::backend::ErrorKind::Conflict
    );
    assert!(
        !fixture
            .requests()
            .iter()
            .any(|request| request.method == "MKCOL")
    );
    assert_eq!(
        journal
            .pending_operation(&sessions, &write_id, revision)
            .unwrap()
            .state,
        CiphertextWriteState::Conflict
    );
}

// Guarded overwrite uses the existing finite DAV fixture; no Windows provider,
// capture-store retirement or writable mount is activated by these tests.
struct GuardedExistingFixture {
    fixture: Fixture,
    client: OpenCloudClient,
    sessions: Arc<VaultSessionCoordinator>,
    scope: VaultSessionScope,
    backend: Arc<VaultBackend>,
    entry: raiun_core::backend::RemoteEntry,
    target: String,
}
fn guarded_existing_fixture() -> GuardedExistingFixture {
    let fixture = Fixture::start();
    let client = OpenCloudClient::new(&fixture.origin(), "synthetic-token".into()).unwrap();
    let sessions = Arc::new(VaultSessionCoordinator::new());
    let scope =
        VaultSessionScope::new("guarded-account", &fixture.origin(), SPACE, ROOT_ID).unwrap();
    let mut password = b"potato".to_vec();
    sessions
        .unlock(
            &scope,
            &mut password,
            include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim(),
        )
        .unwrap();
    let backend = Arc::new(
        VaultBackend::new(
            client.clone(),
            sessions.clone(),
            scope.clone(),
            ROOT_PATH.to_owned(),
        )
        .unwrap(),
    );
    let create = backend
        .prepare_write_target("/guarded.bin", &WriteCondition::Absent)
        .unwrap();
    let entry = backend
        .upload_prepared_reader(
            &create,
            &mut Cursor::new(b"base"),
            4,
            WriteCondition::Absent,
        )
        .unwrap();
    let target = backend
        .prepare_write_target(&entry.path, &WriteCondition::Match(entry.etag.clone()))
        .unwrap();
    fixture.state.lock().unwrap().requests.clear();
    GuardedExistingFixture {
        fixture,
        client,
        sessions,
        scope,
        backend,
        entry,
        target,
    }
}
fn guarded_existing_request<'a>(
    client: &OpenCloudClient,
    scope: &'a VaultSessionScope,
    epoch: &'a raiun_vault::session::VaultSessionEpoch,
    entry: &'a raiun_core::backend::RemoteEntry,
    target: &'a str,
    provider: Arc<AtomicU64>,
    cancelled: &'a dyn Fn() -> bool,
) -> raiun_opencloud::vault_backend::VaultExistingOverwriteRequest<'a> {
    raiun_opencloud::vault_backend::VaultExistingOverwriteRequest {
        scope,
        epoch,
        vault_root_path: ROOT_PATH,
        logical_path: &entry.path,
        original_resource_id: &entry.id,
        original_etag: &entry.etag,
        encoded_target: target,
        expected_token_generation: client.token_generation(),
        provider_generation: provider,
        expected_provider_generation: 7,
        cancelled,
    }
}
fn guarded_put_count(fixture: &Fixture) -> usize {
    fixture
        .requests()
        .iter()
        .filter(|r| r.method == "PUT")
        .count()
}
#[test]
fn guarded_existing_overwrite_changes_length_and_authenticates_exact_readback() {
    use raiun_opencloud::vault_backend::VaultExistingOverwriteOutcome;
    let f = guarded_existing_fixture();
    let epoch = f.sessions.capture_session_epoch(&f.scope).unwrap();
    let request = guarded_existing_request(
        &f.client,
        &f.scope,
        &epoch,
        &f.entry,
        &f.target,
        Arc::new(AtomicU64::new(7)),
        &|| false,
    );
    let bytes = vec![0x5a; 65553];
    let mut source = Cursor::new(bytes.clone());
    let private = tempfile::tempdir().unwrap();
    let result = f
        .backend
        .overwrite_existing_reader_guarded(
            &request,
            &mut source,
            bytes.len() as u64,
            private.path(),
        )
        .unwrap();
    let VaultExistingOverwriteOutcome::Verified(proof) = result else {
        panic!("expected authenticated remote byte proof")
    };
    assert_eq!(proof.entry().id, f.entry.id);
    assert_eq!(proof.entry().size, bytes.len() as u64);
    assert_eq!(
        proof.plaintext_sha256(),
        <[u8; 32]>::from(Sha256::digest(&bytes))
    );
    assert_eq!(source.into_inner(), bytes);
    let requests = f.fixture.requests();
    let puts = requests
        .iter()
        .filter(|r| r.method == "PUT")
        .collect::<Vec<_>>();
    assert_eq!(puts.len(), 1);
    assert_eq!(puts[0].headers.get("if-match"), Some(&f.entry.etag));
    assert_ne!(puts[0].body, bytes);
    let gets = requests
        .iter()
        .filter(|r| r.method == "GET" && r.target.starts_with("/dav/"))
        .collect::<Vec<_>>();
    assert_eq!(gets.len(), 1);
    assert_eq!(gets[0].headers.get("if-match"), Some(&proof.entry().etag));
    assert!(
        !private
            .path()
            .join("unpublished-overwrite-readback")
            .exists()
    );
    assert_eq!(std::fs::read_dir(private.path()).unwrap().count(), 0);
}
#[test]
fn guarded_existing_overwrite_refuses_original_identity_version_and_foreign_scope_before_put() {
    let f = guarded_existing_fixture();
    let epoch = f.sessions.capture_session_epoch(&f.scope).unwrap();
    let private = tempfile::tempdir().unwrap();
    for field in ["id", "etag", "scope", "encoded"] {
        let mut original = f.entry.clone();
        if field == "id" {
            original.id = "foreign-resource".into();
        }
        if field == "etag" {
            original.etag = "\"foreign-version\"".into();
        }
        let foreign =
            VaultSessionScope::new("foreign-account", &f.fixture.origin(), SPACE, ROOT_ID).unwrap();
        let scope = if field == "scope" { &foreign } else { &f.scope };
        let encoded = f.sessions.encrypt_path(&f.scope, "other.bin").unwrap();
        let target = if field == "encoded" {
            &encoded
        } else {
            &f.target
        };
        let request = guarded_existing_request(
            &f.client,
            scope,
            &epoch,
            &original,
            target,
            Arc::new(AtomicU64::new(7)),
            &|| false,
        );
        assert!(
            f.backend
                .overwrite_existing_reader_guarded(
                    &request,
                    &mut Cursor::new(b"edited"),
                    6,
                    private.path()
                )
                .is_err()
        );
        assert_eq!(guarded_put_count(&f.fixture), 0);
    }
}
#[test]
fn guarded_existing_overwrite_rejects_stale_epoch_and_revoked_admission_before_put() {
    let f = guarded_existing_fixture();
    let epoch = f.sessions.capture_session_epoch(&f.scope).unwrap();
    let private = tempfile::tempdir().unwrap();
    f.sessions.lock(&f.scope).unwrap();
    let mut password = b"potato".to_vec();
    f.sessions
        .unlock(
            &f.scope,
            &mut password,
            include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64").trim(),
        )
        .unwrap();
    assert!(f.sessions.is_unlocked(&f.scope).unwrap());
    let old = guarded_existing_request(
        &f.client,
        &f.scope,
        &epoch,
        &f.entry,
        &f.target,
        Arc::new(AtomicU64::new(7)),
        &|| false,
    );
    assert!(
        f.backend
            .overwrite_existing_reader_guarded(&old, &mut Cursor::new(b"edited"), 6, private.path())
            .is_err()
    );
    let current = f.sessions.capture_session_epoch(&f.scope).unwrap();
    let provider = Arc::new(AtomicU64::new(8));
    let request = guarded_existing_request(
        &f.client,
        &f.scope,
        &current,
        &f.entry,
        &f.target,
        provider,
        &|| false,
    );
    assert!(
        f.backend
            .overwrite_existing_reader_guarded(
                &request,
                &mut Cursor::new(b"edited"),
                6,
                private.path()
            )
            .is_err()
    );
    let request = guarded_existing_request(
        &f.client,
        &f.scope,
        &current,
        &f.entry,
        &f.target,
        Arc::new(AtomicU64::new(7)),
        &|| true,
    );
    assert!(
        f.backend
            .overwrite_existing_reader_guarded(
                &request,
                &mut Cursor::new(b"edited"),
                6,
                private.path()
            )
            .is_err()
    );
    assert_eq!(guarded_put_count(&f.fixture), 0);
}
#[test]
fn guarded_existing_overwrite_refuses_source_length_and_capacity_without_truncation_or_put() {
    use raiun_opencloud::vault_backend::MAX_GUARDED_VAULT_OVERWRITE_BYTES;
    let f = guarded_existing_fixture();
    let epoch = f.sessions.capture_session_epoch(&f.scope).unwrap();
    let private = tempfile::tempdir().unwrap();
    let request = guarded_existing_request(
        &f.client,
        &f.scope,
        &epoch,
        &f.entry,
        &f.target,
        Arc::new(AtomicU64::new(7)),
        &|| false,
    );
    for len in [2, MAX_GUARDED_VAULT_OVERWRITE_BYTES + 1] {
        let mut source = Cursor::new(b"extra".to_vec());
        assert!(
            f.backend
                .overwrite_existing_reader_guarded(&request, &mut source, len, private.path())
                .is_err()
        );
        assert_eq!(source.into_inner(), b"extra");
    }
    assert_eq!(guarded_put_count(&f.fixture), 0);
}
#[test]
fn guarded_existing_overwrite_lock_during_put_cancels_without_holding_registry_over_network() {
    use raiun_opencloud::vault_backend::VaultExistingOverwriteOutcome;
    let f = guarded_existing_fixture();
    let epoch = f.sessions.capture_session_epoch(&f.scope).unwrap();
    let gate = f.fixture.pause_next_copy_put_body();
    let backend = f.backend.clone();
    let client = f.client.clone();
    let scope = f.scope.clone();
    let entry = f.entry.clone();
    let target = f.target.clone();
    let worker = thread::spawn(move || {
        let request = guarded_existing_request(
            &client,
            &scope,
            &epoch,
            &entry,
            &target,
            Arc::new(AtomicU64::new(7)),
            &|| false,
        );
        let mut source = Cursor::new(vec![0x33; 131089]);
        let private = tempfile::tempdir().unwrap();
        let result = backend.overwrite_existing_reader_guarded(
            &request,
            &mut source,
            131089,
            private.path(),
        );
        (result, source.into_inner())
    });
    assert!(
        gate.wait_for_body_prefix(&worker),
        "PUT must reach the existing fixture gate"
    );
    f.sessions.lock(&f.scope).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !worker.is_finished() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let cancelled = worker.is_finished();
    gate.release();
    let (result, source) = worker.join().unwrap();
    assert!(
        cancelled,
        "epoch revocation must stop the pending network operation"
    );
    assert!(matches!(
        result,
        Ok(VaultExistingOverwriteOutcome::NeedsReconciliation { .. })
    ));
    assert_eq!(source, vec![0x33; 131089]);
}
#[test]
fn guarded_existing_overwrite_valid_ciphertext_with_wrong_plaintext_is_not_verified() {
    use raiun_opencloud::vault_backend::VaultExistingOverwriteOutcome;
    let f = guarded_existing_fixture();
    let epoch = f.sessions.capture_session_epoch(&f.scope).unwrap();
    let staging = tempfile::tempdir().unwrap();
    let cipher = staging.path().join("replacement-cipher.bin");
    f.sessions
        .encrypt_file_transactional(&f.scope, &mut Cursor::new(b"wrong!"), &cipher, 6, 6)
        .unwrap();
    f.fixture
        .replace_next_put_body(std::fs::read(cipher).unwrap());
    let request = guarded_existing_request(
        &f.client,
        &f.scope,
        &epoch,
        &f.entry,
        &f.target,
        Arc::new(AtomicU64::new(7)),
        &|| false,
    );
    let private = tempfile::tempdir().unwrap();
    let mut source = Cursor::new(b"edited".to_vec());
    assert!(matches!(
        f.backend
            .overwrite_existing_reader_guarded(&request, &mut source, 6, private.path()),
        Ok(VaultExistingOverwriteOutcome::NeedsReconciliation { .. })
    ));
    assert_eq!(source.into_inner(), b"edited");
    assert_eq!(guarded_put_count(&f.fixture), 1);
    assert_eq!(
        f.fixture
            .requests()
            .iter()
            .filter(|r| r.method == "GET" && r.target.starts_with("/dav/"))
            .count(),
        1
    );
}
#[test]
fn guarded_existing_overwrite_token_change_during_get_is_retained_uncertainty() {
    use raiun_opencloud::vault_backend::VaultExistingOverwriteOutcome;
    let f = guarded_existing_fixture();
    let epoch = f.sessions.capture_session_epoch(&f.scope).unwrap();
    f.fixture.state.lock().unwrap().get_delay_ms = 3000;
    let backend = f.backend.clone();
    let client = f.client.clone();
    let scope = f.scope.clone();
    let entry = f.entry.clone();
    let target = f.target.clone();
    let worker = thread::spawn(move || {
        let request = guarded_existing_request(
            &client,
            &scope,
            &epoch,
            &entry,
            &target,
            Arc::new(AtomicU64::new(7)),
            &|| false,
        );
        let mut source = Cursor::new(b"edited".to_vec());
        let private = tempfile::tempdir().unwrap();
        let result =
            backend.overwrite_existing_reader_guarded(&request, &mut source, 6, private.path());
        (result, source.into_inner())
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !f
        .fixture
        .requests()
        .iter()
        .any(|r| r.method == "GET" && r.target.starts_with("/dav/"))
        && !worker.is_finished()
        && std::time::Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        f.fixture
            .requests()
            .iter()
            .any(|r| r.method == "GET" && r.target.starts_with("/dav/")),
        "authenticated readback must start"
    );
    f.client.set_bearer_token("synthetic-token".into()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !worker.is_finished() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let cancelled = worker.is_finished();
    let (result, source) = worker.join().unwrap();
    assert!(cancelled, "generation change must stop an in-progress GET");
    assert!(matches!(
        result,
        Ok(VaultExistingOverwriteOutcome::NeedsReconciliation { .. })
    ));
    assert_eq!(source, b"edited");
    assert_eq!(guarded_put_count(&f.fixture), 1);
}
#[test]
fn guarded_existing_overwrite_lost_put_response_does_not_replay_or_claim_success() {
    use raiun_opencloud::vault_backend::VaultExistingOverwriteOutcome;
    let f = guarded_existing_fixture();
    let epoch = f.sessions.capture_session_epoch(&f.scope).unwrap();
    f.fixture.lose_put_response();
    let request = guarded_existing_request(
        &f.client,
        &f.scope,
        &epoch,
        &f.entry,
        &f.target,
        Arc::new(AtomicU64::new(7)),
        &|| false,
    );
    let private = tempfile::tempdir().unwrap();
    let mut source = Cursor::new(b"edited".to_vec());
    assert!(matches!(
        f.backend
            .overwrite_existing_reader_guarded(&request, &mut source, 6, private.path()),
        Ok(VaultExistingOverwriteOutcome::NeedsReconciliation { .. })
    ));
    assert_eq!(source.into_inner(), b"edited");
    assert_eq!(guarded_put_count(&f.fixture), 1);
}

#[test]
fn guarded_existing_overwrite_unchanged_strong_etag_is_retained_uncertainty() {
    use raiun_opencloud::vault_backend::VaultExistingOverwriteOutcome;
    let f = guarded_existing_fixture();
    f.fixture.state.lock().unwrap().preserve_put_etag = true;
    let epoch = f.sessions.capture_session_epoch(&f.scope).unwrap();
    let provider = Arc::new(AtomicU64::new(7));
    let request = guarded_existing_request(
        &f.client,
        &f.scope,
        &epoch,
        &f.entry,
        &f.target,
        provider,
        &|| false,
    );
    let private = tempfile::tempdir().unwrap();
    let mut source = std::io::Cursor::new(b"edited".to_vec());
    let outcome = f
        .backend
        .overwrite_existing_reader_guarded(&request, &mut source, 6, private.path())
        .unwrap();
    assert!(matches!(
        outcome,
        VaultExistingOverwriteOutcome::NeedsReconciliation { .. }
    ));
    assert_eq!(source.into_inner(), b"edited");
    assert_eq!(guarded_put_count(&f.fixture), 1);
    assert!(
        !f.fixture
            .requests()
            .iter()
            .any(|request| request.method == "GET" && request.target.starts_with("/dav/"))
    );
}

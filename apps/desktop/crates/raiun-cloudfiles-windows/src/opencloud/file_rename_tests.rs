use super::*;
use crate::namespace_file_rename::{
    FileRenameCompletionError, FileRenameJournal, FileRenameLocal, FileRenameOutcome,
    FileRenameReadback, reconcile_file_rename,
};
use crate::namespace_intent::*;
use crate::streamed_store::StoreError;
use crate::{ConfiguredRootIdentity, EditJournalScope, LocalFileIdentity};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

const ROOT_BAD: usize = 1;
const PARENT_BAD: usize = 2;
const SOURCE_BAD: usize = 4;
const DEST_EXISTS: usize = 8;
const READBACK_ID_BAD: usize = 16;
const READBACK_SIZE_BAD: usize = 32;
const SOURCE_REMAINS: usize = 64;
const PARENT_ID_CHANGES: usize = 128;
const PARENT_ETAG_CHANGES: usize = 256;
const ROTATE_TOKEN: usize = 512;
const ROOT_FORBIDDEN: usize = 1024;
const ROOT_NOT_FOUND: usize = 2048;
const PARENT_FORBIDDEN: usize = 4096;
const PARENT_NOT_FOUND: usize = 8192;
const SOURCE_FORBIDDEN: usize = 16384;
const SOURCE_NOT_FOUND: usize = 32768;
const SOURCE_SERVER_ERROR: usize = 65536;
const SOURCE_BODY_BAD: usize = 131072;
const DESTINATION_BODY_BAD: usize = 262144;
const DESTINATION_REVISION_CHANGES: usize = 524288;

struct Catalog {
    bindings: Mutex<Vec<ProviderIdentityBinding>>,
    fail_next: AtomicUsize,
}
impl ProviderIdentityCatalog for Catalog {
    fn load(
        &self,
        _: &ProviderIdentityCatalogScope,
    ) -> Result<Vec<ProviderIdentityBinding>, BackendError> {
        Ok(self.bindings.lock().unwrap().clone())
    }
    fn upsert(
        &self,
        _: &ProviderIdentityCatalogScope,
        binding: &ProviderIdentityBinding,
    ) -> Result<(), BackendError> {
        let failure = self.fail_next.swap(0, Ordering::AcqRel);
        if failure == 1 {
            return Err(BackendError::Unavailable);
        }
        let mut bindings = self.bindings.lock().unwrap();
        if let Some(existing) = bindings
            .iter_mut()
            .find(|existing| existing.identity() == binding.identity())
        {
            *existing = binding.clone();
        } else {
            bindings.push(binding.clone());
        }
        if failure == 2 {
            return Err(BackendError::Unavailable);
        }
        Ok(())
    }
    fn remove(
        &self,
        _: &ProviderIdentityCatalogScope,
        _: OpaqueIdentity,
    ) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }
}
impl Catalog {
    fn contains_file_path(&self, path: &str) -> bool {
        self.bindings.lock().unwrap().iter().any(|binding| {
            matches!(binding, ProviderIdentityBinding::File { path: bound, .. } if bound == path)
        })
    }
    fn count_file_paths(&self, path: &str) -> usize {
        self.bindings.lock().unwrap().iter().filter(|binding| {
            matches!(binding, ProviderIdentityBinding::File { path: bound, .. } if bound == path)
        }).count()
    }
    fn file_etag(&self, path: &str) -> Option<String> {
        self.bindings
            .lock()
            .unwrap()
            .iter()
            .find_map(|binding| match binding {
                ProviderIdentityBinding::File {
                    path: bound, etag, ..
                } if bound == path => Some(etag.clone()),
                _ => None,
            })
    }
}

struct Journal {
    intent: NamespaceIntent,
    progress: NamespaceIntentProgress,
    events: Vec<NamespaceEventKind>,
    fresh: bool,
}
impl Journal {
    fn new(intent: NamespaceIntent) -> Self {
        Self {
            progress: NamespaceIntentProgress::new(intent.clone()).unwrap(),
            intent,
            events: Vec::new(),
            fresh: true,
        }
    }
}
impl FileRenameJournal for Journal {
    fn owns_fresh_publication(&self) -> bool {
        self.fresh
    }
    fn intent(&self) -> &NamespaceIntent {
        &self.intent
    }
    fn progress(&self) -> NamespaceProgressSnapshot {
        self.progress.snapshot()
    }
    fn append_event(&mut self, event: NamespaceEventKind) -> Result<(), StoreError> {
        let event = NamespaceEvent {
            context: self
                .intent
                .event_context()
                .map_err(|_| StoreError::CorruptEvidence)?,
            sequence: self.progress.snapshot().sequence + 1,
            event,
        };
        self.progress
            .record(&event)
            .map_err(|_| StoreError::CorruptEvidence)?;
        self.events.push(event.event);
        Ok(())
    }
}

#[derive(Default)]
struct Local {
    admissions: usize,
    completions: usize,
}
impl FileRenameLocal for Local {
    fn admit(&mut self, _: &NamespaceIntent) -> Result<(), raiun_core::backend::CloudError> {
        self.admissions += 1;
        Ok(())
    }
    fn record_completion<F>(
        &mut self,
        _: &NamespaceIntent,
        _: &FileRenameReadback,
        record: F,
    ) -> Result<(), FileRenameCompletionError>
    where
        F: FnOnce() -> Result<(), StoreError>,
    {
        self.completions += 1;
        record().map_err(FileRenameCompletionError::Store)
    }
}

struct PublishingLocal<'session, 'backend> {
    session: &'session FileRenameSession<'backend>,
    catalog: &'session Catalog,
    completion_calls: Arc<AtomicUsize>,
    admissions: usize,
    revoke_at_completion: bool,
    owner_live: Arc<AtomicBool>,
    fail_completion: bool,
}
impl FileRenameLocal for PublishingLocal<'_, '_> {
    fn admit(&mut self, _: &NamespaceIntent) -> Result<(), raiun_core::backend::CloudError> {
        self.admissions += 1;
        if self.revoke_at_completion && self.admissions == 3 {
            self.owner_live.store(false, Ordering::Release);
        }
        Ok(())
    }
    fn record_completion<F>(
        &mut self,
        _: &NamespaceIntent,
        readback: &FileRenameReadback,
        record: F,
    ) -> Result<(), FileRenameCompletionError>
    where
        F: FnOnce() -> Result<(), StoreError>,
    {
        let capability = self
            .session
            .prepare_verified_file_rename(readback)
            .map_err(|_| FileRenameCompletionError::Unavailable)?;
        assert!(self.session.prepare_verified_file_rename(readback).is_err());
        let source_identity = capability.source_identity();
        let destination_identity = capability.identity();
        let (source, destination) = move_entries(self.session.intent()).unwrap();
        let source_path = source.local.name.clone();
        let destination_path = destination.name.clone();
        let backend = self.session.remote.backend;
        let calls = self.completion_calls.clone();
        let fail = self.fail_completion;
        let catalog = self.catalog;
        let published = capability.publish_and_complete(|| {
            calls.fetch_add(1, Ordering::AcqRel);
            assert!(catalog.contains_file_path(&format!("/parent/{destination_path}")));
            assert!(catalog.contains_file_path(&format!("/parent/{source_path}")));
            if fail {
                return Err(crate::Error::EditRecoveryUnavailable);
            }
            record().map_err(|_| crate::Error::EditRecoveryUnavailable)
        });
        if calls.load(Ordering::Acquire) != 0 {
            let state = backend.state.lock().unwrap();
            assert!(state.files.contains_key(&source_identity));
            assert!(state.files.contains_key(&destination_identity));
        }
        published.map_err(|_| FileRenameCompletionError::Unavailable)
    }
}

struct Fixture {
    backend: Arc<OpenCloudPlaceholderBackend>,
    catalog: Arc<Catalog>,
    parent: OpaqueIdentity,
    intent: NamespaceIntent,
    mode: Arc<AtomicUsize>,
    status: Arc<AtomicUsize>,
    owner_live: Arc<AtomicBool>,
    moves: Arc<AtomicUsize>,
    request_log: Arc<Mutex<Vec<String>>>,
    conditional_gets: Arc<Mutex<Vec<(String, String)>>>,
    stop: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let server = format!("http://{address}");
        let mode = Arc::new(AtomicUsize::new(0));
        let status = Arc::new(AtomicUsize::new(201));
        let owner_live = Arc::new(AtomicBool::new(true));
        let moves = Arc::new(AtomicUsize::new(0));
        let current_renamed = Arc::new(AtomicBool::new(false));
        let request_log = Arc::new(Mutex::new(Vec::new()));
        let conditional_gets = Arc::new(Mutex::new(Vec::new()));
        let (m, s, o, n, log, gets) = (
            mode.clone(),
            status.clone(),
            owner_live.clone(),
            moves.clone(),
            request_log.clone(),
            conditional_gets.clone(),
        );
        let worker_client = Arc::new(Mutex::new(None::<Arc<OpenCloudClient>>));
        let worker_client_ref = worker_client.clone();
        let renamed_state = current_renamed.clone();
        let (stop_tx, stop_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let began = Instant::now();
            let mut destination_body_finished = false;
            loop {
                if stop_rx.try_recv().is_ok() || began.elapsed() >= Duration::from_secs(10) {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("accepted loopback stream blocking");
                        let deadline = began + Duration::from_secs(10);
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            break;
                        }
                        let timeout = remaining.min(Duration::from_secs(2));
                        stream
                            .set_read_timeout(Some(timeout))
                            .expect("bounded read");
                        stream
                            .set_write_timeout(Some(timeout))
                            .expect("bounded write");
                        let Some(headers) = read_headers(&mut stream, deadline) else {
                            break;
                        };
                        if !consume_body(&mut stream, &headers) {
                            break;
                        }
                        let line = headers.lines().next().unwrap_or_default().to_owned();
                        {
                            let mut requests = log.lock().unwrap();
                            if requests.len() >= 512 {
                                break;
                            }
                            requests.push(line.clone());
                        }
                        let mut words = line.split_whitespace();
                        let method = words.next().unwrap_or_default();
                        let path = words.next().unwrap_or_default().trim_end_matches('/');
                        if method == "GET"
                            && (path == "/dav/personal/parent/source.txt"
                                || path == "/dav/personal/parent/renamed.txt")
                        {
                            let original_name = path.ends_with("/source.txt");
                            let flags = m.load(Ordering::Acquire);
                            let if_match = headers
                                .lines()
                                .find_map(|header| {
                                    header
                                        .split_once(':')
                                        .filter(|(name, _)| name.eq_ignore_ascii_case("if-match"))
                                        .map(|(_, value)| value.trim().to_owned())
                                })
                                .unwrap_or_default();
                            {
                                let mut recorded = gets.lock().unwrap();
                                if recorded.len() >= 512 {
                                    break;
                                }
                                recorded.push((path.to_owned(), if_match));
                            }
                            let bad_body = if original_name {
                                flags & SOURCE_BODY_BAD != 0
                            } else {
                                flags & DESTINATION_BODY_BAD != 0
                            };
                            let body = if bad_body {
                                b"evil".as_slice()
                            } else {
                                b"data".as_slice()
                            };
                            let etag = if original_name {
                                "\"source-etag\""
                            } else {
                                "\"source-v2\""
                            };
                            response_body(&mut stream, etag, body);
                            if !original_name {
                                destination_body_finished = true;
                            }
                            continue;
                        }
                        if method == "MOVE" {
                            n.fetch_add(1, Ordering::AcqRel);
                            renamed_state.store(path.ends_with("/source.txt"), Ordering::Release);
                            let flags = m.load(Ordering::Acquire);
                            if flags & ROTATE_TOKEN != 0 {
                                o.store(false, Ordering::Release);
                                if let Some(client) = worker_client_ref.lock().unwrap().as_ref() {
                                    client
                                        .set_bearer_token("rotated-fixture-token".into())
                                        .unwrap();
                                }
                            }
                            let code = s.load(Ordering::Acquire);
                            let status_line = match code {
                                403 => "403 Forbidden",
                                404 => "404 Not Found",
                                409 => "409 Conflict",
                                500 => "500 Internal Server Error",
                                204 => "204 No Content",
                                _ => "201 Created",
                            };
                            response(&mut stream, status_line, "");
                            continue;
                        }
                        if method == "GET" && path.starts_with("/graph/v1.0/me/drives") {
                            let graph = format!(
                                r#"{{"value":[{{"id":"drive","name":"Personal","driveType":"personal","root":{{"id":"root","webDavUrl":"http://{address}/dav/personal/"}}}}]}}"#
                            );
                            response(&mut stream, "200 OK", &graph);
                        } else if method == "PROPFIND" && path == "/dav/personal" {
                            let flags = m.load(Ordering::Acquire);
                            if flags & ROOT_FORBIDDEN != 0 {
                                response(&mut stream, "403 Forbidden", "");
                                continue;
                            }
                            if flags & ROOT_NOT_FOUND != 0 {
                                response(&mut stream, "404 Not Found", "");
                                continue;
                            }
                            let id = if m.load(Ordering::Acquire) & ROOT_BAD != 0 {
                                "replacement-root"
                            } else {
                                "root"
                            };
                            response(
                                &mut stream,
                                "207 Multi-Status",
                                &xml(path, id, "\"root-etag\"", true, false, 0),
                            );
                        } else if method == "PROPFIND" && path == "/dav/personal/parent" {
                            let flags = m.load(Ordering::Acquire);
                            if flags & PARENT_FORBIDDEN != 0 {
                                response(&mut stream, "403 Forbidden", "");
                                continue;
                            }
                            if flags & PARENT_NOT_FOUND != 0 {
                                response(&mut stream, "404 Not Found", "");
                                continue;
                            }
                            let id = if flags & PARENT_BAD != 0
                                || (flags & PARENT_ID_CHANGES != 0 && n.load(Ordering::Acquire) > 0)
                            {
                                "replacement-parent"
                            } else {
                                "parent"
                            };
                            let etag = if flags & PARENT_ETAG_CHANGES != 0
                                && n.load(Ordering::Acquire) > 0
                            {
                                "\"parent-v2\""
                            } else {
                                "\"parent-v1\""
                            };
                            response(
                                &mut stream,
                                "207 Multi-Status",
                                &xml(path, id, etag, true, false, 0),
                            );
                        } else if method == "PROPFIND"
                            && (path == "/dav/personal/parent/source.txt"
                                || path == "/dav/personal/parent/renamed.txt")
                        {
                            let flags = m.load(Ordering::Acquire);
                            let original_name = path.ends_with("/source.txt");
                            let is_source = original_name != renamed_state.load(Ordering::Acquire)
                                || (flags & SOURCE_REMAINS != 0 && n.load(Ordering::Acquire) > 0);
                            if original_name && is_source {
                                if flags & SOURCE_FORBIDDEN != 0 {
                                    response(&mut stream, "403 Forbidden", "");
                                    continue;
                                }
                                if flags & SOURCE_NOT_FOUND != 0 {
                                    response(&mut stream, "404 Not Found", "");
                                    continue;
                                }
                                if flags & SOURCE_SERVER_ERROR != 0 {
                                    response(&mut stream, "500 Internal Server Error", "");
                                    continue;
                                }
                            }
                            let is_existing_destination = !original_name
                                && n.load(Ordering::Acquire) == 0
                                && flags & DEST_EXISTS != 0;
                            if !is_source && !is_existing_destination {
                                response(&mut stream, "404 Not Found", "");
                            } else {
                                let bad_destination =
                                    !original_name && n.load(Ordering::Acquire) == 1;
                                let id = if (flags & SOURCE_BAD != 0 && is_source)
                                    || (flags & READBACK_ID_BAD != 0 && bad_destination)
                                {
                                    "replacement-file"
                                } else {
                                    "file-id"
                                };
                                let etag = if original_name {
                                    if n.load(Ordering::Acquire) > 0 {
                                        "\"source-v3\""
                                    } else {
                                        "\"source-etag\""
                                    }
                                } else if is_existing_destination {
                                    "\"existing-etag\""
                                } else if destination_body_finished
                                    && flags & DESTINATION_REVISION_CHANGES != 0
                                {
                                    "\"source-v3\""
                                } else {
                                    "\"source-v2\""
                                };
                                let size = if flags & READBACK_SIZE_BAD != 0 && bad_destination {
                                    8
                                } else {
                                    4
                                };
                                response(
                                    &mut stream,
                                    "207 Multi-Status",
                                    &xml(path, id, etag, false, false, size),
                                );
                            }
                        } else {
                            response(&mut stream, "500 Internal Server Error", "");
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => break,
                }
            }
        });
        let client = Arc::new(
            OpenCloudClient::new_with_proxy(
                &server,
                "synthetic-token".into(),
                &raiun_opencloud::ProxyConfig::Direct,
            )
            .unwrap(),
        );
        *worker_client.lock().unwrap() = Some(client.clone());
        let account = derive_account_id(&server, "drive");
        let provider = ProviderScope::new(
            &client,
            "profile".into(),
            account.clone(),
            client.server_origin().unwrap(),
        )
        .unwrap();
        let catalog = Arc::new(Catalog {
            bindings: Mutex::new(Vec::new()),
            fail_next: AtomicUsize::new(0),
        });
        let backend = Arc::new(
            OpenCloudPlaceholderBackend::new_with_identity_catalog(
                client.clone(),
                provider,
                ConfiguredRootIdentity {
                    volume_serial: 7,
                    file_index: 11,
                },
                catalog.clone(),
            )
            .unwrap(),
        );
        backend
            .register_composite_root_for("drive", "root")
            .unwrap();
        let parent = backend
            .register_directory("drive", "root", "/parent")
            .unwrap();
        backend
            .register_file("drive", "root", "/parent/source.txt")
            .unwrap();
        let intent = intent(&client, account);
        Self {
            backend,
            catalog,
            parent,
            intent,
            mode,
            status,
            owner_live,
            moves,
            request_log,
            conditional_gets,
            stop: stop_tx,
            worker: Some(worker),
        }
    }
    fn finish(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.expect("bounded rename fixture worker");
            }
        }
    }
    fn enable_cache(&mut self) {
        let cache_root = tempfile::tempdir().unwrap().keep();
        eprintln!("R33 isolated retained cache root={}", cache_root.display());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cache_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let cache = raiun_cache::Cache::open(&cache_root, 1024 * 1024).unwrap();
        Arc::get_mut(&mut self.backend)
            .expect("fixture backend has no extra owners before session start")
            .cache = Some(cache);
    }
    fn run(
        &self,
        journal: &mut Journal,
        local: &mut Local,
    ) -> Result<FileRenameOutcome, StoreError> {
        self.backend
            .with_file_rename_session(
                &self.intent,
                self.parent,
                &|auth| auth.agent_generation == 3 && self.owner_live.load(Ordering::Acquire),
                |session| reconcile_file_rename(journal, session.remote(), local),
            )
            .map_err(|_| StoreError::CorruptEvidence)?
    }
    fn run_with_publication(
        &self,
        journal: &mut Journal,
        revoke_at_completion: bool,
        fail_completion: bool,
    ) -> Result<(FileRenameOutcome, Arc<AtomicUsize>), StoreError> {
        self.run_intent_with_publication(
            &self.intent,
            journal,
            revoke_at_completion,
            fail_completion,
        )
    }
    fn run_intent_with_publication(
        &self,
        intent: &NamespaceIntent,
        journal: &mut Journal,
        revoke_at_completion: bool,
        fail_completion: bool,
    ) -> Result<(FileRenameOutcome, Arc<AtomicUsize>), StoreError> {
        self.backend
            .with_file_rename_session(
                intent,
                self.parent,
                &|auth| auth.agent_generation == 3 && self.owner_live.load(Ordering::Acquire),
                |session| {
                    let completion_calls = Arc::new(AtomicUsize::new(0));
                    let mut local = PublishingLocal {
                        session,
                        catalog: &self.catalog,
                        completion_calls: completion_calls.clone(),
                        admissions: 0,
                        revoke_at_completion,
                        owner_live: self.owner_live.clone(),
                        fail_completion,
                    };
                    reconcile_file_rename(journal, session.remote(), &mut local)
                        .map(|outcome| (outcome, completion_calls))
                },
            )
            .map_err(|_| StoreError::CorruptEvidence)?
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.finish();
    }
}

fn intent(client: &OpenCloudClient, account: String) -> NamespaceIntent {
    let parent = NamespaceParent {
        scope: EditJournalScope {
            profile_id: "profile".into(),
            server_origin: client.server_origin().unwrap(),
            account_subject: account,
            space_id: "drive".into(),
            root_resource_id: "root".into(),
            root_volume_serial: 7,
            root_file_index: 11,
        },
        authorization: CapturedAuthorization {
            agent_generation: 3,
            token_generation: client.token_generation(),
        },
        classification: StorageClassification::Ordinary,
        local_file: LocalFileIdentity {
            volume_serial: 7,
            file_index: 12,
        },
        local_components: vec!["Personal".into(), "parent".into()],
        remote: RemoteEditBaseline {
            resource_id: "parent".into(),
            etag: "\"parent-v1\"".into(),
            byte_len: 0,
        },
    };
    NamespaceIntent {
        schema_version: 1,
        record_id: "a".repeat(32),
        record_generation: 1,
        operation: NamespaceOperation::MoveWithinScope {
            source: ExistingNamespaceEntry {
                local: LocalNamespaceEntry {
                    parent: parent.clone(),
                    name: "source.txt".into(),
                    local_file: LocalFileIdentity {
                        volume_serial: 7,
                        file_index: 13,
                    },
                    object_kind: NamespaceObjectKind::File,
                },
                remote: RemoteEditBaseline {
                    resource_id: "file-id".into(),
                    etag: "\"source-etag\"".into(),
                    byte_len: 4,
                },
            },
            destination: LocalNamespaceEntry {
                parent,
                name: "renamed.txt".into(),
                local_file: LocalFileIdentity {
                    volume_serial: 7,
                    file_index: 13,
                },
                object_kind: NamespaceObjectKind::File,
            },
        },
    }
}

fn reverse_intent(forward: &NamespaceIntent) -> NamespaceIntent {
    let (source, destination) = match &forward.operation {
        NamespaceOperation::MoveWithinScope {
            source,
            destination,
        } => (source, destination),
        _ => unreachable!("fixture intent is a move"),
    };
    NamespaceIntent {
        schema_version: forward.schema_version,
        record_id: "b".repeat(32),
        record_generation: 2,
        operation: NamespaceOperation::MoveWithinScope {
            source: ExistingNamespaceEntry {
                local: destination.clone(),
                remote: RemoteEditBaseline {
                    resource_id: source.remote.resource_id.clone(),
                    etag: "\"source-v2\"".into(),
                    byte_len: source.remote.byte_len,
                },
            },
            destination: source.local.clone(),
        },
    }
}

fn read_headers(stream: &mut std::net::TcpStream, deadline: Instant) -> Option<String> {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") && bytes.len() < 32 * 1024 && Instant::now() < deadline {
        if stream.read_exact(&mut byte).is_err() {
            return None;
        }
        bytes.push(byte[0]);
    }
    bytes
        .ends_with(b"\r\n\r\n")
        .then(|| String::from_utf8_lossy(&bytes).into_owned())
}
fn consume_body(stream: &mut std::net::TcpStream, headers: &str) -> bool {
    let length = headers
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    if length > 64 * 1024 {
        return false;
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body).is_ok()
}
fn response(stream: &mut std::net::TcpStream, status: &str, body: &str) {
    write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n", body.len()).expect("write bounded response headers");
    stream
        .write_all(body.as_bytes())
        .expect("write bounded response body");
}
fn response_body(stream: &mut std::net::TcpStream, etag: &str, body: &[u8]) {
    write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: {etag}\r\nConnection: close\r\nContent-Type: application/octet-stream\r\n\r\n", body.len()).expect("write bounded GET response headers");
    stream
        .write_all(body)
        .expect("write bounded GET response body");
}
fn xml(path: &str, id: &str, etag: &str, directory: bool, encrypted: bool, size: u64) -> String {
    let resource_type = if directory { "<d:collection/>" } else { "" };
    let encrypted = if encrypted {
        "<lg:encrypted>true</lg:encrypted>"
    } else {
        ""
    };
    format!(
        r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:lg="http://graph.opencloud.eu/ns"><d:response><d:href>{path}</d:href><d:propstat><d:prop><d:resourcetype>{resource_type}</d:resourcetype><d:getcontentlength>{size}</d:getcontentlength><d:getetag>{etag}</d:getetag><oc:fileid>{id}</oc:fileid>{encrypted}<oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#
    )
}

#[test]
fn live_session_renames_once_and_observes_same_file_before_factual_completion() {
    let fixture = Fixture::new();
    let mut journal = Journal::new(fixture.intent.clone());
    let mut local = Local::default();
    assert_eq!(
        fixture.run(&mut journal, &mut local).unwrap(),
        FileRenameOutcome::Completed
    );
    assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
    assert_eq!(journal.events.len(), 4);
    assert!(journal.progress.snapshot().recorded_complete);
    assert_eq!(local.completions, 1);
}

#[test]
fn postcommit_forbidden_and_not_found_statuses_are_uncertain_without_readback_or_replay() {
    for status in [403, 404] {
        let fixture = Fixture::new();
        fixture.status.store(status, Ordering::Release);
        let mut journal = Journal::new(fixture.intent.clone());
        let mut local = Local::default();
        assert_eq!(
            fixture.run(&mut journal, &mut local).unwrap(),
            FileRenameOutcome::Uncertain
        );
        assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
        assert_eq!(journal.events.len(), 2);
        assert_eq!(local.completions, 0);
        let log = fixture.request_log.lock().unwrap();
        let move_index = log
            .iter()
            .position(|line| line.starts_with("MOVE "))
            .unwrap();
        assert!(
            !log[move_index + 1..]
                .iter()
                .any(|line| line.starts_with("PROPFIND "))
        );
        drop(log);
    }
}

#[test]
fn root_parent_source_and_existing_destination_mismatches_prevent_move() {
    for flags in [ROOT_BAD, PARENT_BAD, SOURCE_BAD, DEST_EXISTS] {
        let fixture = Fixture::new();
        fixture.mode.store(flags, Ordering::Release);
        let mut journal = Journal::new(fixture.intent.clone());
        let mut local = Local::default();
        let outcome = fixture.run(&mut journal, &mut local);
        if flags == ROOT_BAD {
            // Root mismatch refuses the session before the coordinator runs.
            assert!(outcome.is_err());
        } else {
            assert_eq!(outcome.unwrap(), FileRenameOutcome::Conflict);
        }
        assert_eq!(fixture.moves.load(Ordering::Acquire), 0);
        assert_eq!(local.completions, 0);
    }
}

#[test]
fn wrong_postmove_identity_size_or_persistent_source_never_completes() {
    for flags in [
        READBACK_ID_BAD,
        READBACK_SIZE_BAD,
        SOURCE_REMAINS,
        PARENT_ID_CHANGES,
    ] {
        let fixture = Fixture::new();
        fixture.mode.store(flags, Ordering::Release);
        let mut journal = Journal::new(fixture.intent.clone());
        let mut local = Local::default();
        assert_eq!(
            fixture.run(&mut journal, &mut local).unwrap(),
            FileRenameOutcome::Uncertain
        );
        assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
        assert_eq!(local.completions, 0);
    }
}

#[test]
fn parent_etag_change_after_success_is_observed_without_claiming_parent_cas() {
    let fixture = Fixture::new();
    fixture.mode.store(PARENT_ETAG_CHANGES, Ordering::Release);
    let mut journal = Journal::new(fixture.intent.clone());
    let mut local = Local::default();
    assert_eq!(
        fixture.run(&mut journal, &mut local).unwrap(),
        FileRenameOutcome::Completed
    );
    assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
}

#[test]
fn owner_revocation_after_move_is_uncertain_and_cannot_be_retried() {
    let fixture = Fixture::new();
    fixture.mode.store(ROTATE_TOKEN, Ordering::Release);
    let mut journal = Journal::new(fixture.intent.clone());
    let mut local = Local::default();
    assert_eq!(
        fixture.run(&mut journal, &mut local).unwrap(),
        FileRenameOutcome::Uncertain
    );
    assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
    assert_eq!(local.completions, 0);
}

#[test]
fn session_rejects_a_second_dispatch_after_the_first_attempt() {
    let fixture = Fixture::new();
    let mut journal = Journal::new(fixture.intent.clone());
    let second_refused = std::cell::Cell::new(false);
    fixture
        .backend
        .with_file_rename_session(
            &fixture.intent,
            fixture.parent,
            &|auth| auth.agent_generation == 3,
            |session| {
                let repeated = RepeatDispatchRemote {
                    inner: session.remote(),
                    second_refused: &second_refused,
                };
                reconcile_file_rename(&mut journal, &repeated, &mut Local::default()).unwrap();
            },
        )
        .unwrap();
    assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
    assert!(second_refused.get());
}

#[test]
fn publication_adds_new_path_binding_before_completion_and_keeps_source() {
    let fixture = Fixture::new();
    let mut journal = Journal::new(fixture.intent.clone());
    let (outcome, completion_calls) = fixture
        .run_with_publication(&mut journal, false, false)
        .unwrap();
    assert_eq!(outcome, FileRenameOutcome::Completed);
    assert_eq!(completion_calls.load(Ordering::Acquire), 1);
    assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
    assert_eq!(fixture.catalog.count_file_paths("/parent/source.txt"), 1);
    assert_eq!(fixture.catalog.count_file_paths("/parent/renamed.txt"), 1);
    assert_eq!(
        fixture.catalog.file_etag("/parent/source.txt").as_deref(),
        Some("\"source-etag\"")
    );
    assert_eq!(
        fixture.catalog.file_etag("/parent/renamed.txt").as_deref(),
        Some("\"source-v2\"")
    );
}

#[test]
fn publication_rename_back_uses_stable_path_tuple_without_tombstoning_or_retargeting() {
    let fixture = Fixture::new();
    let mut first_journal = Journal::new(fixture.intent.clone());
    assert_eq!(
        fixture
            .run_with_publication(&mut first_journal, false, false)
            .unwrap()
            .0,
        FileRenameOutcome::Completed
    );
    let reverse = reverse_intent(&fixture.intent);
    let mut reverse_journal = Journal::new(reverse.clone());
    assert_eq!(
        fixture
            .run_intent_with_publication(&reverse, &mut reverse_journal, false, false)
            .unwrap()
            .0,
        FileRenameOutcome::Completed
    );
    assert_eq!(fixture.moves.load(Ordering::Acquire), 2);
    assert_eq!(fixture.catalog.count_file_paths("/parent/source.txt"), 1);
    assert_eq!(fixture.catalog.count_file_paths("/parent/renamed.txt"), 1);
    assert_eq!(
        fixture.catalog.file_etag("/parent/source.txt").as_deref(),
        Some("\"source-v3\"")
    );
    assert_eq!(
        fixture.catalog.file_etag("/parent/renamed.txt").as_deref(),
        Some("\"source-v2\"")
    );
}

#[test]
fn publication_catalog_write_failures_never_call_completion_or_replay_move() {
    for failure in [1, 2] {
        let fixture = Fixture::new();
        fixture.catalog.fail_next.store(failure, Ordering::Release);
        let mut journal = Journal::new(fixture.intent.clone());
        let (outcome, completion_calls) = fixture
            .run_with_publication(&mut journal, false, false)
            .unwrap();
        assert_eq!(outcome, FileRenameOutcome::RemoteVerifiedLocalPending);
        assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
        assert_eq!(completion_calls.load(Ordering::Acquire), 0);
        assert_eq!(fixture.catalog.count_file_paths("/parent/source.txt"), 1);
        assert_eq!(
            fixture.catalog.count_file_paths("/parent/renamed.txt"),
            if failure == 2 { 1 } else { 0 }
        );
        assert_eq!(
            fixture
                .run_with_publication(&mut journal, false, false)
                .unwrap()
                .0,
            FileRenameOutcome::Retained
        );
        assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
    }
}

#[test]
fn publication_native_callback_failure_retains_added_binding_and_remote_verified_prefix() {
    let fixture = Fixture::new();
    let mut journal = Journal::new(fixture.intent.clone());
    let (outcome, completion_calls) = fixture
        .run_with_publication(&mut journal, false, true)
        .unwrap();
    assert_eq!(outcome, FileRenameOutcome::RemoteVerifiedLocalPending);
    assert_eq!(completion_calls.load(Ordering::Acquire), 1);
    assert_eq!(fixture.catalog.count_file_paths("/parent/source.txt"), 1);
    assert_eq!(fixture.catalog.count_file_paths("/parent/renamed.txt"), 1);
    assert_eq!(journal.progress.snapshot().remote, NamespacePhase::Verified);
    assert!(!journal.progress.snapshot().local_completed);
    assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
}

#[test]
fn publication_stale_owner_before_publication_writes_no_destination_binding() {
    let fixture = Fixture::new();
    let mut journal = Journal::new(fixture.intent.clone());
    let (outcome, completion_calls) = fixture
        .run_with_publication(&mut journal, true, false)
        .unwrap();
    assert_eq!(outcome, FileRenameOutcome::RemoteVerifiedLocalPending);
    assert_eq!(completion_calls.load(Ordering::Acquire), 0);
    assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
    assert_eq!(fixture.catalog.count_file_paths("/parent/source.txt"), 1);
    assert_eq!(fixture.catalog.count_file_paths("/parent/renamed.txt"), 0);
}

#[test]
fn publication_catalog_capacity_refuses_new_identity_but_refreshes_existing_identity() {
    for destination_exists in [false, true] {
        let fixture = Fixture::new();
        let catalog_scope = fixture.backend.catalog_scope_snapshot().unwrap().unwrap();
        let destination_identity = binding_identity(
            &catalog_scope,
            "file",
            &["drive", "root", "/parent/renamed.txt", "file-id"],
        );
        {
            let mut state = fixture.backend.state.lock().unwrap();
            if destination_exists {
                state.files.insert(
                    destination_identity,
                    FileBinding {
                        space_id: "drive".into(),
                        root_resource_id: "root".into(),
                        path: "/parent/renamed.txt".into(),
                        remote_id: "file-id".into(),
                        etag: "\"older-destination\"".into(),
                        size: 4,
                    },
                );
            }
            let mut index = 0u64;
            while binding_count(&state) < MAX_IDENTITY_CATALOG_ENTRIES {
                let path = format!("/filler/{index}");
                let remote_id = format!("filler-{index}");
                let identity = binding_identity(
                    &catalog_scope,
                    "file",
                    &["drive", "root", &path, &remote_id],
                );
                state.files.entry(identity).or_insert_with(|| FileBinding {
                    space_id: "drive".into(),
                    root_resource_id: "root".into(),
                    path,
                    remote_id,
                    etag: "\"filler\"".into(),
                    size: 1,
                });
                index += 1;
            }
        }
        let mut journal = Journal::new(fixture.intent.clone());
        let (outcome, completion_calls) = fixture
            .run_with_publication(&mut journal, false, false)
            .unwrap();
        assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
        if destination_exists {
            assert_eq!(outcome, FileRenameOutcome::Completed);
            assert_eq!(completion_calls.load(Ordering::Acquire), 1);
            assert_eq!(
                fixture.catalog.file_etag("/parent/renamed.txt").as_deref(),
                Some("\"source-v2\"")
            );
        } else {
            assert_eq!(outcome, FileRenameOutcome::RemoteVerifiedLocalPending);
            assert_eq!(completion_calls.load(Ordering::Acquire), 0);
            assert_eq!(fixture.catalog.count_file_paths("/parent/renamed.txt"), 0);
        }
    }
}

#[test]
fn cache_revocation_sticks_on_authoritative_metadata_denials_and_identity_mismatches() {
    for flags in [
        ROOT_FORBIDDEN,
        ROOT_NOT_FOUND,
        PARENT_FORBIDDEN,
        PARENT_NOT_FOUND,
        SOURCE_FORBIDDEN,
        SOURCE_NOT_FOUND,
        ROOT_BAD,
        PARENT_BAD,
        SOURCE_BAD,
    ] {
        let mut fixture = Fixture::new();
        fixture.enable_cache();
        fixture.mode.store(flags, Ordering::Release);
        let mut journal = Journal::new(fixture.intent.clone());
        let _ = fixture.run(&mut journal, &mut Local::default());
        assert_eq!(fixture.moves.load(Ordering::Acquire), 0);
        assert!(fixture.backend.ensure_active().is_err(), "flags={flags}");
        let requests = fixture.request_log.lock().unwrap().len();
        let mut new_journal = Journal::new(fixture.intent.clone());
        assert!(
            fixture
                .run(&mut new_journal, &mut Local::default())
                .is_err()
        );
        assert_eq!(fixture.request_log.lock().unwrap().len(), requests);
        assert_eq!(fixture.moves.load(Ordering::Acquire), 0);
        fixture.finish();
    }
}

#[test]
fn cache_revocation_sticks_after_postmove_authoritative_status_without_replay() {
    for status in [403, 404, 409] {
        let mut fixture = Fixture::new();
        fixture.enable_cache();
        fixture.status.store(status, Ordering::Release);
        let mut journal = Journal::new(fixture.intent.clone());
        assert_eq!(
            fixture.run(&mut journal, &mut Local::default()).unwrap(),
            FileRenameOutcome::Uncertain
        );
        assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
        assert!(fixture.backend.ensure_active().is_err());
        let requests = fixture.request_log.lock().unwrap().len();
        let mut new_journal = Journal::new(fixture.intent.clone());
        assert!(
            fixture
                .run(&mut new_journal, &mut Local::default())
                .is_err()
        );
        assert_eq!(fixture.request_log.lock().unwrap().len(), requests);
        assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
        fixture.finish();
    }
}

#[test]
fn cache_does_not_revoke_for_expected_destination_and_source_absence() {
    let mut fixture = Fixture::new();
    fixture.enable_cache();
    let mut journal = Journal::new(fixture.intent.clone());
    assert_eq!(
        fixture.run(&mut journal, &mut Local::default()).unwrap(),
        FileRenameOutcome::Completed
    );
    assert!(fixture.backend.ensure_active().is_ok());
    assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
    let requests = fixture.request_log.lock().unwrap();
    let move_index = requests
        .iter()
        .position(|line| line.starts_with("MOVE "))
        .unwrap();
    assert!(
        requests[..move_index]
            .iter()
            .any(|line| line.ends_with("/renamed.txt HTTP/1.1"))
    );
    assert!(
        requests[move_index + 1..]
            .iter()
            .any(|line| line.ends_with("/source.txt HTTP/1.1"))
    );
    drop(requests);
    fixture.finish();
}

#[test]
fn cache_does_not_revoke_transient_server_errors() {
    for (flags, move_status, expected_moves) in [(SOURCE_SERVER_ERROR, 201, 0), (0, 500, 1)] {
        let mut fixture = Fixture::new();
        fixture.enable_cache();
        fixture.mode.store(flags, Ordering::Release);
        fixture.status.store(move_status, Ordering::Release);
        let mut journal = Journal::new(fixture.intent.clone());
        let _ = fixture.run(&mut journal, &mut Local::default());
        assert_eq!(fixture.moves.load(Ordering::Acquire), expected_moves);
        assert!(fixture.backend.ensure_active().is_ok());
        fixture.finish();
    }
}

struct RepeatDispatchRemote<'a> {
    inner: &'a dyn FileRenameRemote,
    second_refused: &'a std::cell::Cell<bool>,
}

#[path = "file_rename_completion_tests.rs"]
mod completion_tests;
#[path = "file_rename_content_tests.rs"]
mod content_tests;
impl FileRenameRemote for RepeatDispatchRemote<'_> {
    fn ensure_authorized(
        &self,
        intent: &NamespaceIntent,
    ) -> Result<(), raiun_core::backend::CloudError> {
        self.inner.ensure_authorized(intent)
    }
    fn preflight(&self, intent: &NamespaceIntent) -> Result<(), raiun_core::backend::CloudError> {
        self.inner.preflight(intent)
    }
    fn rename(
        &self,
        dispatch: &crate::namespace_file_rename::FileRenameDispatch<'_>,
    ) -> Result<FileRenameSend, raiun_core::backend::CloudError> {
        let first = self.inner.rename(dispatch)?;
        self.second_refused
            .set(self.inner.rename(dispatch).is_err());
        Ok(first)
    }
    fn observe(
        &self,
        intent: &NamespaceIntent,
    ) -> Result<FileRenameObservation, raiun_core::backend::CloudError> {
        self.inner.observe(intent)
    }
}

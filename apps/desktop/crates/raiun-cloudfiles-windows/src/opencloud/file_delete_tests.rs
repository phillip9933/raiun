//! Four integrated synthetic HTTP cases; local receipts are injected, not SDK ACKs.
use super::*;
use crate::namespace_file_delete::{
    FileDeleteCompletionError, FileDeleteJournal, FileDeleteLocal, FileDeleteLocalObservation,
    FileDeleteOutcome, FileDeleteReadback, reconcile_file_delete,
};
use crate::namespace_intent::{
    LocalNamespaceEntry, NamespaceEvent, NamespaceEventKind, NamespaceIntentProgress,
    NamespaceParent, NamespaceProgressSnapshot,
};
use crate::streamed_store::StoreError;
use crate::{ConfiguredRootIdentity, EditJournalScope, LocalFileIdentity, RemoteEditBaseline};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{atomic::AtomicUsize, mpsc},
    thread,
};

const SUCCESS: usize = 0;
const STALE: usize = 1;
const ROOT_CHANGED: usize = 2;
const RESPONSE_LOST: usize = 3;
const REPLACEMENT: usize = 4;
const PARENT_MISSING: usize = 5;

#[derive(Default)]
struct Catalog(Mutex<Vec<ProviderIdentityBinding>>);
impl ProviderIdentityCatalog for Catalog {
    fn load(
        &self,
        _: &ProviderIdentityCatalogScope,
    ) -> Result<Vec<ProviderIdentityBinding>, BackendError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn upsert(
        &self,
        _: &ProviderIdentityCatalogScope,
        binding: &ProviderIdentityBinding,
    ) -> Result<(), BackendError> {
        let mut rows = self.0.lock().unwrap();
        rows.retain(|row| row.identity() != binding.identity());
        rows.push(binding.clone());
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
struct Journal {
    intent: NamespaceIntent,
    progress: NamespaceIntentProgress,
    events: Vec<NamespaceEventKind>,
}
impl Journal {
    fn new(intent: NamespaceIntent) -> Self {
        Self {
            progress: NamespaceIntentProgress::new(intent.clone()).unwrap(),
            intent,
            events: vec![],
        }
    }
}
impl FileDeleteJournal for Journal {
    fn owns_fresh_user_delete(&self) -> bool {
        true
    }
    fn intent(&self) -> &NamespaceIntent {
        &self.intent
    }
    fn progress(&self) -> NamespaceProgressSnapshot {
        self.progress.snapshot()
    }
    fn append_event(&mut self, event: NamespaceEventKind) -> Result<(), StoreError> {
        self.progress
            .record(&NamespaceEvent {
                context: self.intent.event_context().unwrap(),
                sequence: self.progress.snapshot().sequence + 1,
                event: event.clone(),
            })
            .map_err(|_| StoreError::CorruptEvidence)?;
        self.events.push(event);
        Ok(())
    }
}
struct Local {
    source: ExistingNamespaceEntry,
    completions: usize,
}
impl FileDeleteLocal for Local {
    fn observe_clean(
        &mut self,
        _: &NamespaceIntent,
    ) -> Result<FileDeleteLocalObservation, CloudError> {
        Ok(FileDeleteLocalObservation {
            source: self.source.clone(),
            ancestry: StorageClassification::Ordinary,
            dirty: false,
            pending: false,
        })
    }
    fn record_completion<F>(
        &mut self,
        _: &NamespaceIntent,
        readback: &FileDeleteReadback,
        record: F,
    ) -> Result<(), FileDeleteCompletionError>
    where
        F: FnOnce() -> Result<(), StoreError>,
    {
        assert_eq!(readback.source(), &self.source);
        record().map_err(FileDeleteCompletionError::Store)?;
        self.completions += 1;
        Ok(())
    }
}
struct Fixture {
    backend: OpenCloudPlaceholderBackend,
    parent: OpaqueIdentity,
    intent: NamespaceIntent,
    mode: Arc<AtomicUsize>,
    deleted: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
    stop: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}
fn xml(href: &str, id: &str, etag: &str, directory: bool) -> String {
    format!(
        "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\" xmlns:lg=\"http://graph.opencloud.eu/ns\"><d:response><d:href>{href}</d:href><d:propstat><d:prop><d:resourcetype>{}</d:resourcetype><d:getcontentlength>{}</d:getcontentlength><d:getetag>{etag}</d:getetag><oc:fileid>{id}</oc:fileid><oc:permissions>RDNVW</oc:permissions><lg:encrypted>false</lg:encrypted></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>",
        if directory { "<d:collection/>" } else { "" },
        if directory { 0 } else { 4 }
    )
}
fn response(stream: &mut std::net::TcpStream, status: &str, body: &str) {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
}
impl Fixture {
    fn new(explicit_root: bool, mismatched_root_provider: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = format!("http://{}", listener.local_addr().unwrap());
        let selected = if explicit_root {
            "provider$space!root"
        } else {
            "provider$space"
        }
        .to_owned();
        let root_opaque = if explicit_root { "root" } else { "space" };
        let root_id = format!(
            "{}$space!{root_opaque}",
            if mismatched_root_provider {
                "other"
            } else {
                "provider"
            }
        );
        let mode = Arc::new(AtomicUsize::new(SUCCESS));
        let deleted = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (stop, stop_rx) = mpsc::channel();
        let modes = mode.clone();
        let deletion = deleted.clone();
        let log = requests.clone();
        let url = server.clone();
        let drive = selected.clone();
        let root_identity = root_id.clone();
        let worker = thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(20) && stop_rx.try_recv().is_err() {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("synthetic listener: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 8192];
                let mut expected = None;
                loop {
                    let n = stream.read(&mut buffer).unwrap();
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..n]);
                    if expected.is_none()
                        && let Some(end) =
                            request.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        let headers = String::from_utf8_lossy(&request[..end]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|length| length.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        expected = Some(end + 4 + length);
                    }
                    if expected.is_some_and(|total| request.len() >= total) {
                        break;
                    }
                }
                let request = String::from_utf8(request).unwrap();
                let first = request.lines().next().unwrap().to_owned();
                log.lock().unwrap().push(request.clone());
                let mut words = first.split_whitespace();
                let method = words.next().unwrap();
                let raw = words.next().unwrap();
                let path = raw.replace("%24", "$").replace("%21", "!");
                let flag = modes.load(Ordering::Acquire);
                let after = deletion.load(Ordering::Acquire);
                if method == "GET" && path == "/graph/v1.0/me/drives" {
                    let body = serde_json::json!({"value":[{"id":drive,"name":"Personal","driveType":"personal","root":{"webDavUrl":format!("{url}/prefix/dav/spaces/{drive}/"),"permissions":[{"roles":["write"]}]}}]}).to_string();
                    response(&mut stream, "200 OK", &body);
                } else if method == "DELETE" {
                    assert_eq!(
                        raw, "/prefix/dav/spaces/provider%24space%21file/",
                        "DELETE must address exactly one encoded original resource-id segment"
                    );
                    assert!(
                        request
                            .lines()
                            .any(|line| line.eq_ignore_ascii_case("if-match: \"source-etag\""))
                    );
                    // Select ORIGINAL by id, even if a same-ETag replacement
                    // now occupies the old pathname. Its separate id survives.
                    deletion.store(true, Ordering::Release);
                    if flag != RESPONSE_LOST {
                        response(&mut stream, "204 No Content", "");
                    }
                } else if method == "PROPFIND" {
                    let base = format!("/prefix/dav/spaces/{drive}");
                    let logical = path.strip_prefix(&base).unwrap();
                    if logical.trim_end_matches('/').is_empty() {
                        let id = if flag == ROOT_CHANGED {
                            "provider$space!changed"
                        } else {
                            &root_identity
                        };
                        response(
                            &mut stream,
                            "207 Multi-Status",
                            &xml(raw, id, "\"root-etag\"", true),
                        );
                    } else if logical.trim_end_matches('/') == "/parent" {
                        if after && flag == PARENT_MISSING {
                            response(&mut stream, "404 Not Found", "");
                        } else {
                            response(
                                &mut stream,
                                "207 Multi-Status",
                                &xml(
                                    raw,
                                    "provider$space!parent",
                                    if after {
                                        "\"parent-after\""
                                    } else {
                                        "\"parent-etag\""
                                    },
                                    true,
                                ),
                            );
                        }
                    } else if logical == "/parent/source.txt" {
                        if after && flag != REPLACEMENT {
                            response(&mut stream, "404 Not Found", "");
                        } else {
                            response(
                                &mut stream,
                                "207 Multi-Status",
                                &xml(
                                    raw,
                                    if after {
                                        "provider$space!replacement"
                                    } else {
                                        "provider$space!file"
                                    },
                                    if flag == STALE {
                                        "\"new-etag\""
                                    } else {
                                        "\"source-etag\""
                                    },
                                    false,
                                ),
                            );
                        }
                    } else {
                        panic!("unexpected synthetic metadata path: {path}");
                    }
                } else {
                    panic!("unexpected synthetic request: {first}");
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
        let account = derive_account_id(&client.configured_server_url(), &selected);
        let provider = ProviderScope::new(
            &client,
            "profile".into(),
            account.clone(),
            client.server_origin().unwrap(),
        )
        .unwrap();
        let backend = OpenCloudPlaceholderBackend::new_with_identity_catalog(
            client.clone(),
            provider,
            ConfiguredRootIdentity {
                volume_serial: 7,
                file_index: 11,
            },
            Arc::new(Catalog::default()),
        )
        .unwrap();
        backend
            .register_composite_root_for(&selected, &root_id)
            .unwrap();
        let parent = backend
            .register_directory(&selected, &root_id, "/parent")
            .unwrap();
        backend
            .register_file(&selected, &root_id, "/parent/source.txt")
            .unwrap();
        let intent = NamespaceIntent {
            schema_version: 1,
            record_id: "d".repeat(32),
            record_generation: 4,
            operation: NamespaceOperation::DeleteFile {
                source: ExistingNamespaceEntry {
                    local: LocalNamespaceEntry {
                        parent: NamespaceParent {
                            scope: EditJournalScope {
                                profile_id: "profile".into(),
                                server_origin: client.server_origin().unwrap(),
                                account_subject: account,
                                space_id: selected,
                                root_resource_id: root_id,
                                root_volume_serial: 7,
                                root_file_index: 11,
                            },
                            authorization: CapturedAuthorization {
                                agent_generation: 4,
                                token_generation: client.token_generation(),
                            },
                            classification: StorageClassification::Ordinary,
                            local_file: LocalFileIdentity {
                                volume_serial: 7,
                                file_index: 21,
                            },
                            local_components: vec!["Personal".into(), "parent".into()],
                            remote: RemoteEditBaseline {
                                resource_id: "provider$space!parent".into(),
                                etag: "\"parent-etag\"".into(),
                                byte_len: 0,
                            },
                        },
                        name: "source.txt".into(),
                        local_file: LocalFileIdentity {
                            volume_serial: 7,
                            file_index: 22,
                        },
                        object_kind: NamespaceObjectKind::File,
                    },
                    remote: RemoteEditBaseline {
                        resource_id: "provider$space!file".into(),
                        etag: "\"source-etag\"".into(),
                        byte_len: 4,
                    },
                },
            },
        };
        Self {
            backend,
            parent,
            intent,
            mode,
            deleted,
            requests,
            stop,
            worker: Some(worker),
        }
    }
    fn execute(
        &self,
        journal: &mut Journal,
        local: &mut Local,
    ) -> Result<FileDeleteOutcome, BackendError> {
        self.backend
            .with_file_delete_session(&self.intent, self.parent, &|_| true, |session| {
                assert_eq!(session.intent(), &self.intent);
                reconcile_file_delete(journal, session.remote(), local).unwrap()
            })
    }
    fn actors(&self) -> (Journal, Local) {
        (
            Journal::new(self.intent.clone()),
            Local {
                source: source(&self.intent).unwrap().clone(),
                completions: 0,
            },
        )
    }
    fn delete_requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.starts_with("DELETE "))
            .cloned()
            .collect()
    }
}

#[test]
fn id_delete_succeeds_for_elided_and_explicit_graph_root_references_without_path_fallback() {
    for explicit_root in [false, true] {
        let fixture = Fixture::new(explicit_root, false);
        let (mut journal, mut local) = fixture.actors();
        assert_eq!(
            fixture.execute(&mut journal, &mut local).unwrap(),
            FileDeleteOutcome::Completed
        );
        assert!(fixture.deleted.load(Ordering::Acquire));
        assert_eq!(local.completions, 1);
        assert!(journal.progress().recorded_complete);
        let requests = fixture.delete_requests();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("DELETE /prefix/dav/spaces/provider%24space%21file/ "));
        assert!(!requests[0].contains("source.txt"));
    }
}
#[test]
fn stale_source_root_and_inconsistent_root_reference_refuse_without_delete_or_fallback() {
    for (mode, bad_shape) in [(STALE, false), (ROOT_CHANGED, false), (SUCCESS, true)] {
        let fixture = Fixture::new(false, bad_shape);
        fixture.mode.store(mode, Ordering::Release);
        let (mut journal, mut local) = fixture.actors();
        assert_ne!(
            fixture.execute(&mut journal, &mut local),
            Ok(FileDeleteOutcome::Completed)
        );
        assert!(fixture.delete_requests().is_empty());
        assert!(!fixture.deleted.load(Ordering::Acquire));
        assert_eq!(local.completions, 0);
    }
}
#[test]
fn lost_id_delete_response_records_uncertainty_and_never_replays() {
    let fixture = Fixture::new(true, false);
    fixture.mode.store(RESPONSE_LOST, Ordering::Release);
    let (mut journal, mut local) = fixture.actors();
    assert_eq!(
        fixture.execute(&mut journal, &mut local).unwrap(),
        FileDeleteOutcome::Uncertain
    );
    assert!(fixture.deleted.load(Ordering::Acquire));
    assert_eq!(local.completions, 0);
    assert!(matches!(
        journal.events.last(),
        Some(NamespaceEventKind::Uncertain)
    ));
    assert_eq!(
        fixture.execute(&mut journal, &mut local).unwrap(),
        FileDeleteOutcome::Retained
    );
    assert_eq!(fixture.delete_requests().len(), 1);
}
#[test]
fn same_etag_replacement_and_missing_parent_never_qualify_remote_absence() {
    for mode in [REPLACEMENT, PARENT_MISSING] {
        let fixture = Fixture::new(false, false);
        fixture.mode.store(mode, Ordering::Release);
        let (mut journal, mut local) = fixture.actors();
        assert_eq!(
            fixture.execute(&mut journal, &mut local).unwrap(),
            FileDeleteOutcome::Uncertain
        );
        assert!(fixture.deleted.load(Ordering::Acquire));
        assert_eq!(local.completions, 0);
        assert!(!journal.progress().local_completed);
        assert_eq!(fixture.delete_requests().len(), 1);
        assert!(
            fixture.delete_requests()[0]
                .starts_with("DELETE /prefix/dav/spaces/provider%24space%21file/ ")
        );
    }
}

use super::*;
use crate::namespace_intent::*;
use crate::{ConfiguredRootIdentity, EditJournalScope, LocalFileIdentity};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};
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
        b: &ProviderIdentityBinding,
    ) -> Result<(), BackendError> {
        self.0.lock().unwrap().push(b.clone());
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
struct Fixture {
    backend: Arc<OpenCloudPlaceholderBackend>,
    client: Arc<OpenCloudClient>,
    parent: OpaqueIdentity,
    intent: NamespaceIntent,
    mode: Arc<AtomicU64>,
    sends: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let server = format!("http://{address}");
        let mode = Arc::new(AtomicU64::new(0));
        let sends = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (m, n, s) = (mode.clone(), sends.clone(), stop.clone());
        let worker = thread::spawn(move || {
            let mut child_reads = 0;
            while !s.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Keep accept nonblocking for shutdown, but use bounded
                        // blocking I/O on each accepted synthetic connection.
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut request = Vec::new();
                        let mut one = [0];
                        while !request.ends_with(b"\r\n\r\n") && request.len() < 65536 {
                            stream.read_exact(&mut one).unwrap_or_else(|error| {
                                panic!(
                                    "synthetic namespace header read failed: kind={:?} native={:?}",
                                    error.kind(),
                                    error.raw_os_error()
                                )
                            });
                            request.push(one[0]);
                        }
                        assert!(
                            request.ends_with(b"\r\n\r\n"),
                            "synthetic namespace request headers exceeded the bound"
                        );
                        let request = String::from_utf8(request).unwrap();
                        let length = request
                            .lines()
                            .find_map(|l| {
                                l.split_once(':')
                                    .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                                    .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        assert!(length <= 65536);
                        let mut body = vec![0; length];
                        stream.read_exact(&mut body).unwrap();
                        let first = request.lines().next().unwrap();
                        let path = first.split_whitespace().nth(1).unwrap();
                        let mode = m.load(Ordering::Acquire);
                        let mut status = "207 Multi-Status";
                        let body = if first.starts_with("GET /graph/") {
                            status = "200 OK";
                            format!(
                                r#"{{"value":[{{"id":"drive","name":"Personal","driveType":"personal","root":{{"id":"root","webDavUrl":"http://{address}/dav/personal/"}}}}]}}"#
                            )
                        } else if first.starts_with("MKCOL ") {
                            n.fetch_add(1, Ordering::AcqRel);
                            status = match mode {
                                1 => "405 Method Not Allowed",
                                2 => "403 Forbidden",
                                _ => "201 Created",
                            };
                            String::new()
                        } else if path.trim_end_matches('/') == "/dav/personal/parent/new-directory"
                        {
                            if n.load(Ordering::Acquire) == 0 || mode == 5 {
                                status = "404 Not Found";
                                String::new()
                            } else {
                                child_reads += 1;
                                let id = if mode == 7 && child_reads > 1 {
                                    "changed-child"
                                } else {
                                    "child"
                                };
                                let etag = if mode == 3 {
                                    "W/\"weak\""
                                } else {
                                    "\"child-v1\""
                                };
                                xml(path, if mode == 4 { None } else { Some(id) }, etag, false)
                            }
                        } else {
                            let id = if path.trim_end_matches('/') == "/dav/personal" {
                                "root"
                            } else if mode == 6 && n.load(Ordering::Acquire) > 0 {
                                "changed-parent"
                            } else {
                                "parent"
                            };
                            xml(path, Some(id), "\"parent-v1\"", mode == 8 && id == "parent")
                        };
                        let response = format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        });
        let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
        let account = derive_account_id(&server, "drive");
        let provider = ProviderScope::new(
            &client,
            "profile".into(),
            account.clone(),
            client.server_origin().unwrap(),
        )
        .unwrap();
        let root = ConfiguredRootIdentity {
            volume_serial: 7,
            file_index: 11,
        };
        let backend = Arc::new(
            OpenCloudPlaceholderBackend::new_with_identity_catalog(
                client.clone(),
                provider,
                root,
                Arc::new(Catalog(Mutex::new(vec![]))),
            )
            .unwrap(),
        );
        backend
            .register_composite_root_for("drive", "root")
            .unwrap();
        let parent = backend
            .register_directory("drive", "root", "/parent")
            .unwrap();
        let intent = NamespaceIntent {
            schema_version: 1,
            record_id: "a".repeat(32),
            record_generation: 1,
            operation: NamespaceOperation::CreateDirectory {
                destination: LocalNamespaceEntry {
                    name: "new-directory".into(),
                    object_kind: NamespaceObjectKind::Directory,
                    local_file: LocalFileIdentity {
                        volume_serial: 7,
                        file_index: 13,
                    },
                    parent: NamespaceParent {
                        scope: EditJournalScope {
                            profile_id: "profile".into(),
                            account_subject: account,
                            server_origin: client.server_origin().unwrap(),
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
                    },
                },
            },
        };
        Self {
            backend,
            client,
            parent,
            intent,
            mode,
            sends,
            stop,
            worker: Some(worker),
        }
    }
}
fn xml(path: &str, id: Option<&str>, etag: &str, encrypted: bool) -> String {
    format!(
        "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\"><d:response><d:href>{path}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>{etag}</d:getetag><d:getcontenttype>{}</d:getcontenttype>{}<oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>",
        if encrypted {
            "application/vnd.opencloud.vault"
        } else {
            "httpd/unix-directory"
        },
        id.map(|id| format!("<oc:fileid>{id}</oc:fileid>"))
            .unwrap_or_default()
    )
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            // Preserve the original failing assertion and worker diagnostics
            // without aborting the entire suite by panicking during unwinding.
            if !thread::panicking() {
                result.expect("synthetic namespace server failed");
            }
        }
    }
}
#[test]
fn live_mkcol_sends_once_and_joins_repeated_observed_id_without_created_id_claim() {
    let f = Fixture::new();
    f.backend
        .with_directory_create_session(&f.intent, f.parent, &|a| a.agent_generation == 3, |r| {
            r.preflight(&f.intent).unwrap();
            assert!(matches!(
                r.create(&DirectoryCreateDispatch::for_test(&f.intent))
                    .unwrap(),
                DirectoryCreateResponse::Created
            ));
            assert!(
                r.create(&DirectoryCreateDispatch::for_test(&f.intent))
                    .is_err(),
                "same session must not send twice"
            );
            let report = r.observe(&f.intent).unwrap();
            assert_eq!(report.remote.resource_id, "child");
            assert_eq!(report.remote.etag, "\"child-v1\"");
        })
        .unwrap();
    assert_eq!(f.sends.load(Ordering::Acquire), 1);
}
#[test]
fn live_collision_forbidden_and_failed_post201_identity_joins_remain_distinct() {
    for mode in 1..=7 {
        let f = Fixture::new();
        f.mode.store(mode, Ordering::Release);
        f.backend
            .with_directory_create_session(&f.intent, f.parent, &|_| true, |r| {
                match r
                    .create(&DirectoryCreateDispatch::for_test(&f.intent))
                    .unwrap()
                {
                    DirectoryCreateResponse::Rejected(e) => assert_eq!(
                        e.kind,
                        if mode == 1 {
                            ErrorKind::Conflict
                        } else {
                            ErrorKind::Forbidden
                        }
                    ),
                    DirectoryCreateResponse::Created => assert!(r.observe(&f.intent).is_err()),
                    _ => panic!("unexpected outcome"),
                }
            })
            .unwrap();
        assert_eq!(f.sends.load(Ordering::Acquire), 1);
    }
}
#[test]
fn live_scope_parent_owner_token_and_encrypted_ancestor_refusals_send_nothing() {
    let f = Fixture::new();
    for variant in 0..5 {
        let mut intent = f.intent.clone();
        let NamespaceOperation::CreateDirectory { destination } = &mut intent.operation else {
            unreachable!()
        };
        match variant {
            0 => destination.parent.scope.account_subject.push('x'),
            1 => destination.parent.scope.root_resource_id.push('x'),
            2 => destination.parent.remote.resource_id.push('x'),
            3 => destination.parent.authorization.token_generation += 1,
            _ => destination.parent.scope.root_file_index += 1,
        }
        assert!(
            f.backend
                .with_directory_create_session(&intent, f.parent, &|_| true, |_| panic!(
                    "must refuse"
                ))
                .is_err()
        );
    }
    assert!(
        f.backend
            .with_directory_create_session(&f.intent, f.parent, &|_| false, |_| panic!(
                "owner refused"
            ))
            .is_err()
    );
    f.mode.store(8, Ordering::Release);
    f.backend
        .with_directory_create_session(&f.intent, f.parent, &|_| true, |r| {
            assert!(r.preflight(&f.intent).is_err())
        })
        .unwrap();
    assert_eq!(f.sends.load(Ordering::Acquire), 0);
}
#[test]
fn live_changed_token_and_owner_after201_refuse_readback() {
    let f = Fixture::new();
    let active = Cell::new(true);
    f.backend
        .with_directory_create_session(&f.intent, f.parent, &|_| active.get(), |r| {
            assert!(matches!(
                r.create(&DirectoryCreateDispatch::for_test(&f.intent))
                    .unwrap(),
                DirectoryCreateResponse::Created
            ));
            active.set(false);
            assert!(r.observe(&f.intent).is_err());
        })
        .unwrap();
    let f = Fixture::new();
    f.backend
        .with_directory_create_session(&f.intent, f.parent, &|_| true, |r| {
            assert!(matches!(
                r.create(&DirectoryCreateDispatch::for_test(&f.intent))
                    .unwrap(),
                DirectoryCreateResponse::Created
            ));
            f.client.set_bearer_token("replaced-token".into()).unwrap();
            assert!(r.observe(&f.intent).is_err());
        })
        .unwrap();
}

struct PublicationJournal {
    intent: NamespaceIntent,
    progress: NamespaceIntentProgress,
}
impl crate::namespace_reconcile::DirectoryCreateJournal for PublicationJournal {
    fn intent(&self) -> &NamespaceIntent {
        &self.intent
    }
    fn progress(&self) -> NamespaceProgressSnapshot {
        self.progress.snapshot()
    }
    fn append_event(
        &mut self,
        event: NamespaceEventKind,
    ) -> Result<(), crate::streamed_store::StoreError> {
        self.progress
            .record(&NamespaceEvent {
                context: self.intent.event_context().unwrap(),
                sequence: self.progress.snapshot().sequence + 1,
                event,
            })
            .map_err(|_| crate::streamed_store::StoreError::Invalid)
    }
}
struct PublicationProbe<'a, 'backend> {
    session: &'a DirectoryCreateSession<'backend>,
    published: usize,
    identity: Option<[u8; 16]>,
    mode: Option<(&'a AtomicU64, u64)>,
}
impl crate::namespace_reconcile::DirectoryCreateLocal for PublicationProbe<'_, '_> {
    fn admit(&mut self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        self.session.remote().ensure_authorized(intent)
    }
    fn publish(
        &mut self,
        _: &NamespaceIntent,
        readback: &DirectoryCreateReadback,
    ) -> Result<(), CloudError> {
        if let Some((mode, value)) = self.mode {
            mode.store(value, Ordering::Release);
        }
        let proof = self
            .session
            .prepare_verified_directory(readback)
            .map_err(|_| refusal(ErrorKind::Conflict))?;
        self.identity = Some(*proof.identity());
        proof
            .publish_and_complete(|| {
                assert!(
                    self.session.backend().lease_gate.try_write().is_err(),
                    "same backend lease must span native completion"
                );
                self.published += 1;
                Ok(())
            })
            .map_err(|_| refusal(ErrorKind::Conflict))
    }
    fn record_completion<F>(
        &mut self,
        _: &NamespaceIntent,
        readback: &DirectoryCreateReadback,
        record: F,
    ) -> Result<(), DirectoryCompletionError>
    where
        F: FnOnce() -> Result<(), crate::streamed_store::StoreError>,
    {
        let identity = self.identity.ok_or(DirectoryCompletionError::Unavailable)?;
        self.session
            .record_directory_completion(readback, &identity, || {
                assert!(
                    self.session.backend().publish_gate.try_lock().is_err(),
                    "final append must hold publication fence"
                );
                assert!(
                    self.session.backend().lease_gate.try_write().is_err(),
                    "same outer lease retained"
                );
                record().map_err(DirectoryCompletionError::Store)
            })
    }
}
fn publication_journal(intent: &NamespaceIntent) -> PublicationJournal {
    PublicationJournal {
        intent: intent.clone(),
        progress: NamespaceIntentProgress::new(intent.clone()).unwrap(),
    }
}
#[test]
fn live_publication_uses_same_lease_and_exact_observed_catalog_identity() {
    let f = Fixture::new();
    let mut journal = publication_journal(&f.intent);
    f.backend
        .with_directory_publication_session(&f.intent, f.parent, &|_| true, |session| {
            let mut local = PublicationProbe {
                session,
                published: 0,
                identity: None,
                mode: None,
            };
            assert_eq!(
                crate::namespace_reconcile::reconcile_directory_create(
                    &mut journal,
                    session.remote(),
                    &mut local
                )
                .unwrap(),
                crate::namespace_reconcile::DirectoryCreateOutcome::LocalCompleted
            );
            assert_eq!(local.published, 1);
            let state = f.backend.state.lock().unwrap();
            let child = state
                .directories
                .values()
                .find(|b| b.path == "/parent/new-directory")
                .unwrap();
            assert_eq!(child.remote_id, "child");
        })
        .unwrap();
    assert_eq!(f.sends.load(Ordering::Acquire), 1);
}
#[test]
fn changed_parent_child_or_lost_readback_after_remoteverified_never_completes_local() {
    for mode in [3, 4, 5, 6, 7] {
        let f = Fixture::new();
        let mut journal = publication_journal(&f.intent);
        f.backend
            .with_directory_publication_session(&f.intent, f.parent, &|_| true, |session| {
                let mut local = PublicationProbe {
                    session,
                    published: 0,
                    identity: None,
                    mode: Some((&f.mode, mode)),
                };
                assert_eq!(
                    crate::namespace_reconcile::reconcile_directory_create(
                        &mut journal,
                        session.remote(),
                        &mut local
                    )
                    .unwrap(),
                    crate::namespace_reconcile::DirectoryCreateOutcome::RemoteVerifiedLocalPending
                );
                assert_eq!(local.published, 0);
            })
            .unwrap();
        assert_eq!(f.sends.load(Ordering::Acquire), 1);
    }
}
struct ParsedReportRemote {
    report: NamespaceDestinationReport,
}
impl DirectoryCreateRemote for ParsedReportRemote {
    fn ensure_authorized(&self, _: &NamespaceIntent) -> Result<(), CloudError> {
        Ok(())
    }
    fn preflight(&self, _: &NamespaceIntent) -> Result<(), CloudError> {
        Ok(())
    }
    fn create(
        &self,
        _: &DirectoryCreateDispatch<'_>,
    ) -> Result<DirectoryCreateResponse, CloudError> {
        Ok(DirectoryCreateResponse::Created)
    }
    fn observe(&self, _: &NamespaceIntent) -> Result<NamespaceDestinationReport, CloudError> {
        Ok(self.report.clone())
    }
}
#[test]
fn parsed_remoteverified_report_cannot_mint_live_directory_publication() {
    let f = Fixture::new();
    let mut journal = publication_journal(&f.intent);
    let NamespaceOperation::CreateDirectory { destination } = &f.intent.operation else {
        unreachable!()
    };
    let serialized = serde_json::to_vec(&NamespaceDestinationReport {
        destination: destination.clone(),
        content: None,
        remote: RemoteEditBaseline {
            resource_id: "child".into(),
            etag: "\"child-v1\"".into(),
            byte_len: 0,
        },
    })
    .unwrap();
    let fake = ParsedReportRemote {
        report: serde_json::from_slice(&serialized).unwrap(),
    };
    f.backend
        .with_directory_publication_session(&f.intent, f.parent, &|_| true, |session| {
            let mut local = PublicationProbe {
                session,
                published: 0,
                identity: None,
                mode: None,
            };
            assert_eq!(
                crate::namespace_reconcile::reconcile_directory_create(
                    &mut journal,
                    &fake,
                    &mut local
                )
                .unwrap(),
                crate::namespace_reconcile::DirectoryCreateOutcome::RemoteVerifiedLocalPending
            );
            assert_eq!(local.published, 0);
        })
        .unwrap();
    assert_eq!(f.sends.load(Ordering::Acquire), 0);
}

struct EpochFenceProbe<'a, 'backend> {
    inner: PublicationProbe<'a, 'backend>,
    active: &'a Cell<bool>,
    before: bool,
}
impl crate::namespace_reconcile::DirectoryCreateLocal for EpochFenceProbe<'_, '_> {
    fn admit(&mut self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        crate::namespace_reconcile::DirectoryCreateLocal::admit(&mut self.inner, intent)
    }
    fn publish(
        &mut self,
        intent: &NamespaceIntent,
        readback: &DirectoryCreateReadback,
    ) -> Result<(), CloudError> {
        crate::namespace_reconcile::DirectoryCreateLocal::publish(&mut self.inner, intent, readback)
    }
    fn record_completion<F>(
        &mut self,
        _: &NamespaceIntent,
        readback: &DirectoryCreateReadback,
        record: F,
    ) -> Result<(), DirectoryCompletionError>
    where
        F: FnOnce() -> Result<(), crate::streamed_store::StoreError>,
    {
        let identity = self
            .inner
            .identity
            .ok_or(DirectoryCompletionError::Unavailable)?;
        if self.before {
            self.active.set(false);
        }
        self.inner
            .session
            .record_directory_completion(readback, &identity, || {
                assert!(
                    self.inner
                        .session
                        .backend()
                        .publish_gate
                        .try_lock()
                        .is_err()
                );
                record().map_err(DirectoryCompletionError::Store)?;
                self.active.set(false);
                Ok(())
            })
    }
}
#[test]
fn final_live_fence_refuses_prior_epoch_loss_and_preserves_admitted_facts_on_post_loss() {
    for before in [true, false] {
        let f = Fixture::new();
        let active = Cell::new(true);
        let mut journal = publication_journal(&f.intent);
        f.backend.with_directory_publication_session(&f.intent,f.parent,&|_|active.get(),|session|{
            let mut local=EpochFenceProbe{inner:PublicationProbe{session,published:0,identity:None,mode:None},active:&active,before};
            let outcome=crate::namespace_reconcile::reconcile_directory_create(&mut journal,session.remote(),&mut local);
            if before{assert_eq!(outcome.unwrap(),crate::namespace_reconcile::DirectoryCreateOutcome::RemoteVerifiedLocalPending);assert!(!journal.progress.snapshot().local_completed);}
            else{assert_eq!(outcome,Err(crate::streamed_store::StoreError::PublicationUncertain));assert!(journal.progress.snapshot().local_completed);}
        }).unwrap();
    }
}

#[test]
fn revoked_owner_refuses_before_waiting_for_backend_lease() {
    let f = Fixture::new();
    // Holding the writer on this thread makes any accidental recursive read
    // acquisition block. Refused ownership must return before touching it.
    let _writer = f.backend.lease_gate.write().unwrap();
    let result =
        f.backend
            .with_directory_publication_session(&f.intent, f.parent, &|_| false, |_| {
                panic!("retired owner entered session")
            });
    assert!(matches!(result, Err(BackendError::Unavailable)));
    assert_eq!(f.sends.load(Ordering::Acquire), 0);
}

#[test]
fn plain_capture_parent_has_one_lease_live_binding_path_and_original_job() {
    let f = Fixture::new();
    let NamespaceOperation::CreateDirectory { destination } = &f.intent.operation else {
        unreachable!()
    };
    let auth = destination.parent.authorization;
    let root = ConfiguredRootIdentity {
        volume_serial: 7,
        file_index: 11,
    };
    let job = CancellationToken::for_recovery_job(crate::StreamedRecoveryPolicy::default());
    let deadline = job.deadline();
    let result = f.backend.with_plain_file_capture_parent(
        root,
        &["Personal"],
        auth,
        &job,
        &|a| a == auth,
        |parent| {
            assert!(f.backend.lease_gate.try_write().is_err());
            assert_eq!(parent.components, ["Personal"]);
            assert_eq!(parent.captured.path, "/");
            assert_eq!(parent.captured.remote.resource_id, "root");
            assert_eq!(parent.captured.scope.root_file_index, 11);
            assert_eq!(parent.captured.route.len(), 1);
            assert_eq!(
                parent.captured.route[0].identity,
                parent.captured.identity.as_bytes()
            );
            assert_eq!(parent.job.deadline(), deadline);
            assert!(parent.check_current().is_ok());
            job.cancel();
            assert!(parent.check_current().is_err());
        },
    );
    assert!(result.is_err());
    assert_eq!(f.sends.load(Ordering::Acquire), 0);
}
#[test]
fn plain_capture_parent_refuses_cancelled_or_retired_owner_before_lease_wait() {
    let f = Fixture::new();
    let NamespaceOperation::CreateDirectory { destination } = &f.intent.operation else {
        unreachable!()
    };
    let auth = destination.parent.authorization;
    let root = ConfiguredRootIdentity {
        volume_serial: 7,
        file_index: 11,
    };
    let job = CancellationToken::for_recovery_job(crate::StreamedRecoveryPolicy::default());
    let _writer = f.backend.lease_gate.write().unwrap();
    assert!(
        f.backend
            .with_plain_file_capture_parent(
                root,
                &["Personal"],
                auth,
                &job,
                &|_| false,
                |_| panic!("retired owner entered")
            )
            .is_err()
    );
    job.cancel();
    assert!(
        f.backend
            .with_plain_file_capture_parent(root, &["Personal"], auth, &job, &|_| true, |_| panic!(
                "cancelled job entered"
            ))
            .is_err()
    );
}

use super::*;

struct Fixture {
    backend: OpenCloudPlaceholderBackend,
    identity: [u8; 16],
    worker: Option<thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl Fixture {
    fn new() -> Self {
        let (server, worker, stop) = start_namespace_fixture();
        let client = Arc::new(OpenCloudClient::new(&server, "test-token".into()).unwrap());
        let scope = ProviderScope::new(
            client.as_ref(),
            "profile-fetch-session-test".into(),
            derive_account_id(&server, "personal-drive"),
            client.server_origin().unwrap(),
        )
        .unwrap();
        let backend = OpenCloudPlaceholderBackend::new(client, scope).unwrap();
        let root = backend
            .register_composite_root_for("personal-drive", "personal-root")
            .unwrap();
        let root_children = backend
            .enumerate(root.as_bytes(), &CancellationToken::new())
            .unwrap();
        let spaces = root_children
            .iter()
            .find(|child| child.name == "Spaces")
            .unwrap();
        let spaces_children = backend
            .enumerate(&spaces.identity, &CancellationToken::new())
            .unwrap();
        let projects = spaces_children
            .iter()
            .find(|child| child.name == "Projects")
            .unwrap();
        let project_children = backend
            .enumerate(&projects.identity, &CancellationToken::new())
            .unwrap();
        let file = project_children
            .iter()
            .find(|child| child.name == "readme.txt")
            .unwrap();
        let identity = file.identity.as_slice().try_into().unwrap();

        Self {
            backend,
            identity,
            worker: Some(worker),
            stop,
        }
    }

    fn stop_server(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[test]
fn one_session_reads_multiple_bounded_windows_from_its_exact_file_binding() {
    let mut fixture = Fixture::new();
    let cancellation = CancellationToken::new();
    let session = fixture
        .backend
        .prepare_fetch_session(&fixture.identity, &cancellation)
        .unwrap();
    assert_eq!(session.metadata().length, 7);
    assert!(!session.metadata().is_directory);

    let first = session
        .prepare_window(FetchRange { offset: 0, end: 3 }, &cancellation)
        .unwrap();
    assert_eq!(first.bytes(), b"con");
    assert_eq!(first.metadata(), session.metadata());
    drop(first);

    let second = session
        .prepare_window(FetchRange { offset: 3, end: 7 }, &cancellation)
        .unwrap();
    assert_eq!(second.bytes(), b"tent");
    assert_eq!(second.metadata(), session.metadata());
    drop(second);
    drop(session);
    fixture.stop_server();
}

#[test]
fn cancellation_after_one_window_rejects_the_next_window() {
    let mut fixture = Fixture::new();
    let cancellation = CancellationToken::new();
    let session = fixture
        .backend
        .prepare_fetch_session(&fixture.identity, &cancellation)
        .unwrap();
    let first = session
        .prepare_window(FetchRange { offset: 0, end: 3 }, &cancellation)
        .unwrap();
    assert_eq!(first.bytes(), b"con");
    drop(first);

    // Remove the local server too: a later window must be rejected by the
    // shared cancellation token before it can make another HTTP request.
    fixture.stop.store(true, Ordering::Release);
    fixture.worker.take().unwrap().join().unwrap();
    cancellation.cancel();
    assert!(matches!(
        session.prepare_window(FetchRange { offset: 3, end: 7 }, &cancellation),
        Err(BackendError::Cancelled)
    ));
}

#[test]
fn malformed_and_over_limit_windows_are_refused_before_any_get() {
    let mut fixture = Fixture::new();
    let cancellation = CancellationToken::new();
    let session = fixture
        .backend
        .prepare_fetch_session(&fixture.identity, &cancellation)
        .unwrap();

    assert!(matches!(
        session.prepare_window(FetchRange { offset: 4, end: 3 }, &cancellation),
        Err(BackendError::InvalidRange)
    ));
    assert!(matches!(
        session.prepare_window(
            FetchRange {
                offset: 0,
                end: MAX_REQUEST_BYTES + 1,
            },
            &cancellation,
        ),
        Err(BackendError::InvalidRange)
    ));
    drop(session);
    // The namespace fixture panics on an unexpected nonconforming GET, so a
    // clean join also proves both invalid windows were rejected locally.
    fixture.stop_server();
}

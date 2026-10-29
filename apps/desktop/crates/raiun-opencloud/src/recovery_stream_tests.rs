use super::*;
use std::{
    io::{Read, Write},
    net::TcpListener,
    task::{Context, Poll},
    thread,
};
use tokio::io::ReadBuf;

// Generated source never allocates the file; poll sizes are recorded so the
// >16 MiB regression also checks the source-side allocation bound.
struct Generated {
    remaining: u64,
    max_poll: Arc<AtomicU64>,
}
impl AsyncRead for Generated {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.max_poll
            .fetch_max(out.remaining() as u64, Ordering::Relaxed);
        let n = self.remaining.min(out.remaining() as u64) as usize;
        out.put_slice(&[b'x'; CHUNK][..n]);
        self.remaining -= n as u64;
        Poll::Ready(Ok(()))
    }
}
fn digest(len: u64) -> [u8; 32] {
    let mut hash = Sha256::new();
    let mut left = len;
    while left != 0 {
        let n = left.min(CHUNK as u64);
        hash.update(&[b'x'; CHUNK][..n as usize]);
        left -= n;
    }
    hash.finalize().into()
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn strict_source_verifies_before_final_chunk_without_an_extra_poll() {
    runtime().block_on(async {
        for length in [0, 1, CHUNK as u64, CHUNK as u64 + 1, 17 * 1024 * 1024 + 7] {
            let seen = Arc::new(AtomicU64::new(0));
            let verified = Arc::new(AtomicBool::new(false));
            let mut source = StrictReader {
                reader: Generated {
                    remaining: length,
                    max_poll: seen.clone(),
                },
                remaining: length,
                hash: Sha256::new(),
                digest: digest(length),
                budget: TransferBudget::new(),
                cancelled: || false,
                progress: async_body::BodyProgress::channel().0,
                verified: verified.clone(),
            };
            let mut count = 0;
            while count < length {
                count += source.next().await.unwrap().unwrap().len() as u64;
            }
            if length == 0 {
                assert!(source.next().await.unwrap().is_none());
            }
            assert!(verified.load(Ordering::Acquire));
            assert_eq!(count, length);
            assert!(seen.load(Ordering::Relaxed) <= CHUNK as u64);
        }
    });
}
#[test]
fn strict_source_rejects_truncation_extra_eof_digest_and_cancel() {
    runtime().block_on(async {
        for (actual, planned, bad_digest, cancel) in [
            (0, 1, false, false),
            (2, 1, false, false),
            (1, 1, true, false),
            (1, 1, false, true),
            (1, 0, false, false),
            (0, 0, true, false),
        ] {
            let verified = Arc::new(AtomicBool::new(false));
            let mut source = StrictReader {
                reader: Generated {
                    remaining: actual,
                    max_poll: Arc::new(AtomicU64::new(0)),
                },
                remaining: planned,
                hash: Sha256::new(),
                digest: if bad_digest { [0; 32] } else { digest(planned) },
                budget: TransferBudget::new(),
                cancelled: move || cancel,
                progress: async_body::BodyProgress::channel().0,
                verified: verified.clone(),
            };
            assert!(source.next().await.is_err());
            assert!(!verified.load(Ordering::Acquire));
        }
    });
}

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    Root,
    Resource,
    Etag,
    Role,
    Digest,
    Truncated,
    ResponseLost,
    PartialPut,
    LateRoot,
    Redirect,
    ReadEtag,
    ReadLength,
    LateRole,
}
struct Fixture {
    url: String,
    done: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
    puts: Arc<AtomicU64>,
    gets: Arc<AtomicU64>,
    uploaded: Arc<AtomicU64>,
    size: u64,
    pin_observations: Arc<AtomicU64>,
}
impl Fixture {
    fn new(size: u64, fault: Fault) -> Self {
        Self::with_pin_observer(size, fault, None)
    }
    fn with_pin_observer(size: u64, fault: Fault, dropped: Option<Arc<AtomicU64>>) -> Self {
        let pin_observations = Arc::new(AtomicU64::new(0));
        let observed = pin_observations.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let stop = done.clone();
        let puts = Arc::new(AtomicU64::new(0));
        let put_count = puts.clone();
        let gets = Arc::new(AtomicU64::new(0));
        let get_count = gets.clone();
        let uploaded = Arc::new(AtomicU64::new(0));
        let received = uploaded.clone();
        let worker = thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                let (mut socket, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut header = Vec::new();
                let mut byte = [0];
                while !header.ends_with(b"\r\n\r\n") {
                    if socket.read_exact(&mut byte).is_err() {
                        break;
                    }
                    header.push(byte[0]);
                    assert!(header.len() < 32768);
                }
                let text = String::from_utf8(header).unwrap();
                if !text.ends_with("\r\n\r\n") {
                    continue;
                }
                let length = text
                    .lines()
                    .find_map(|line| {
                        let (k, v) = line.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<u64>().unwrap())
                    })
                    .unwrap_or(0);
                let is_put = text.starts_with("PUT ");
                let is_get = text.starts_with("GET /dav/");
                if let Some(dropped) = &dropped
                    && (is_get
                        || (text.starts_with("PROPFIND /dav/")
                            && get_count.load(Ordering::Acquire) > 0))
                {
                    assert_eq!(
                        dropped.load(Ordering::Acquire),
                        0,
                        "source pin released during independent readback"
                    );
                    observed.fetch_add(1, Ordering::Relaxed);
                }
                if is_put {
                    put_count.fetch_add(1, Ordering::Relaxed);
                    assert!(text.to_lowercase().contains("if-match: \"v1\""));
                    assert_eq!(length, size);
                }
                let mut left = length;
                let mut buffer = [0; CHUNK];
                let mut hash = Sha256::new();
                while left > 0 {
                    let n = left.min(CHUNK as u64) as usize;
                    match socket.read(&mut buffer[..n]) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            hash.update(&buffer[..n]);
                            left -= n as u64;
                            if is_put && matches!(fault, Fault::PartialPut) {
                                break;
                            }
                        }
                    }
                }
                if is_put {
                    received.store(length - left, Ordering::Release);
                    if left != 0 || matches!(fault, Fault::ResponseLost) {
                        continue;
                    }
                    assert_eq!(&hash.finalize()[..], &digest(size));
                }
                let (status, body, extra) = if text.starts_with("GET /graph/") {
                    (
                        "200 OK",
                        format!(
                            r#"{{"value":[{{"id":"drive-1","name":"Personal","driveType":"personal","root":{{"id":"root","webDavUrl":"http://{address}/dav/personal/"}}}}]}}"#
                        ),
                        String::new(),
                    )
                } else if is_put {
                    ("204 No Content", String::new(), String::new())
                } else if is_get {
                    get_count.fetch_add(1, Ordering::Relaxed);
                    assert!(text.to_lowercase().contains("if-match: \"v2\""));
                    if matches!(fault, Fault::Redirect) {
                        let _ = write!(
                            socket,
                            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/never\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        continue;
                    }
                    let response_size = if matches!(fault, Fault::ReadLength) {
                        size + 1
                    } else {
                        size
                    };
                    let response_etag = if matches!(fault, Fault::ReadEtag) {
                        "wrong"
                    } else {
                        "v2"
                    };
                    let _ = write!(
                        socket,
                        "HTTP/1.1 200 OK\r\nContent-Length: {response_size}\r\nETag: \"{response_etag}\"\r\nConnection: close\r\n\r\n"
                    );
                    let mut remaining = if matches!(fault, Fault::Truncated) {
                        size.saturating_sub(1)
                    } else {
                        size
                    };
                    let fill = if matches!(fault, Fault::Digest) {
                        b'y'
                    } else {
                        b'x'
                    };
                    let chunk = [fill; CHUNK];
                    while remaining > 0 {
                        let n = remaining.min(CHUNK as u64) as usize;
                        if socket.write_all(&chunk[..n]).is_err() {
                            break;
                        }
                        remaining -= n as u64;
                    }
                    continue;
                } else {
                    assert!(text.starts_with("PROPFIND /dav/"), "{text}");
                    let root = text.starts_with("PROPFIND /dav/personal/ HTTP");
                    let changed = put_count.load(Ordering::Relaxed) > 0;
                    let late = get_count.load(Ordering::Relaxed) > 0;
                    let id = if root {
                        if matches!(fault, Fault::Root)
                            || (matches!(fault, Fault::LateRoot) && late)
                        {
                            "wrong-root"
                        } else {
                            "root"
                        }
                    } else if matches!(fault, Fault::Resource) {
                        "wrong-file"
                    } else {
                        "file"
                    };
                    let etag = if root {
                        "root-tag"
                    } else if matches!(fault, Fault::Etag) {
                        "wrong"
                    } else if changed {
                        "v2"
                    } else {
                        "v1"
                    };
                    let path = if root { "" } else { "file.bin" };
                    let permissions = if !root
                        && (matches!(fault, Fault::Role)
                            || (matches!(fault, Fault::LateRole) && late))
                    {
                        "R"
                    } else {
                        "RDNVW"
                    };
                    (
                        "207 Multi-Status",
                        format!(
                            r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/{path}</d:href><d:propstat><d:prop><d:resourcetype>{}</d:resourcetype><d:getcontentlength>{}</d:getcontentlength><d:getetag>"{etag}"</d:getetag><oc:fileid>{id}</oc:fileid><oc:permissions>{permissions}</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#,
                            if root { "<d:collection/>" } else { "" },
                            if root {
                                0
                            } else if changed {
                                size
                            } else {
                                1
                            }
                        ),
                        String::new(),
                    )
                };
                let _ = write!(
                    socket,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
                    body.len()
                );
            }
        });
        Self {
            url: format!("http://{address}"),
            done,
            worker: Some(worker),
            puts,
            gets,
            uploaded,
            size,
            pin_observations,
        }
    }
    fn upload(&self, actual: u64) -> Result<RecoveryStreamReadback, CloudError> {
        let client =
            OpenCloudClient::new_with_proxy(&self.url, "synthetic".into(), &ProxyConfig::Direct)
                .unwrap();
        let context = RangeReadContext {
            deadline: Instant::now() + Duration::from_secs(10),
            token_generation: client.token_generation(),
        };
        client.recovery_upload_reader_with_context(
            "drive-1",
            "/",
            "root",
            "file.bin",
            "file",
            "\"v1\"",
            1,
            Generated {
                remaining: actual,
                max_poll: Arc::new(AtomicU64::new(0)),
            },
            self.size,
            digest(self.size),
            context,
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Release);
        let result = self.worker.take().unwrap().join();
        if !thread::panicking() {
            result.unwrap();
        }
    }
}

#[test]
fn generated_large_put_requires_complete_independent_digest_get() {
    let size = 17 * 1024 * 1024 + 7;
    let fixture = Fixture::new(size, Fault::None);
    let proof = fixture.upload(size).unwrap();
    assert_eq!(proof.bytes, size);
    assert_eq!(proof.sha256, digest(size));
    assert_eq!(proof.entry.id, "file");
    assert_eq!(fixture.puts.load(Ordering::Acquire), 1);
    assert_eq!(fixture.gets.load(Ordering::Acquire), 1);
    assert_eq!(fixture.uploaded.load(Ordering::Acquire), size);
}
#[test]
fn roots_resources_revisions_and_roles_refuse_before_put() {
    for fault in [Fault::Root, Fault::Resource, Fault::Etag, Fault::Role] {
        let fixture = Fixture::new(2, fault);
        assert!(fixture.upload(2).is_err());
        assert_eq!(fixture.puts.load(Ordering::Acquire), 0);
    }
}
#[test]
fn partial_put_lost_response_and_invalid_readback_never_mint_proof() {
    for fault in [
        Fault::Digest,
        Fault::Truncated,
        Fault::ResponseLost,
        Fault::PartialPut,
        Fault::LateRoot,
        Fault::Redirect,
        Fault::ReadEtag,
        Fault::ReadLength,
        Fault::LateRole,
    ] {
        let fixture = Fixture::new(CHUNK as u64 + 7, fault);
        assert!(fixture.upload(fixture.size).is_err());
        assert_eq!(fixture.puts.load(Ordering::Acquire), 1);
        if matches!(fault, Fault::PartialPut) {
            assert!(fixture.uploaded.load(Ordering::Acquire) > 0);
            assert!(fixture.uploaded.load(Ordering::Acquire) < fixture.size);
        }
    }
    let fixture = Fixture::new(CHUNK as u64 * 2 + 1, Fault::None);
    assert!(fixture.upload(CHUNK as u64 + 1).is_err());
    assert!(fixture.uploaded.load(Ordering::Acquire) < fixture.size);
    assert_eq!(fixture.gets.load(Ordering::Acquire), 0);
}
#[test]
fn stale_generation_expired_deadline_and_cancel_refuse_without_http() {
    let fixture = Fixture::new(1, Fault::None);
    let client =
        OpenCloudClient::new_with_proxy(&fixture.url, "synthetic".into(), &ProxyConfig::Direct)
            .unwrap();
    for context in [
        RangeReadContext {
            deadline: Instant::now() + Duration::from_secs(1),
            token_generation: client.token_generation() + 1,
        },
        RangeReadContext {
            deadline: Instant::now(),
            token_generation: client.token_generation(),
        },
    ] {
        assert!(
            client
                .recovery_read_digest_with_context(
                    "drive-1",
                    "/",
                    "root",
                    "file.bin",
                    "file",
                    "\"v1\"",
                    1,
                    digest(1),
                    context
                )
                .is_err()
        );
    }
    client.transfer_budget.set_paused(true);
    let context = RangeReadContext {
        deadline: Instant::now() + Duration::from_secs(1),
        token_generation: client.token_generation(),
    };
    assert!(
        client
            .recovery_read_digest_with_context(
                "drive-1",
                "/",
                "root",
                "file.bin",
                "file",
                "\"v1\"",
                1,
                digest(1),
                context
            )
            .is_err()
    );
    assert_eq!(fixture.puts.load(Ordering::Acquire), 0);
    assert_eq!(fixture.gets.load(Ordering::Acquire), 0);
}

#[test]
fn empty_and_small_http_uploads_require_the_same_full_readback() {
    for size in [0, 1, CHUNK as u64, CHUNK as u64 + 1] {
        let fixture = Fixture::new(size, Fault::None);
        let proof = fixture.upload(size).unwrap();
        assert_eq!(proof.bytes, size);
        assert_eq!(fixture.gets.load(Ordering::Acquire), 1);
    }
}

struct BlockingGenerated {
    remaining: u64,
    dropped: Arc<AtomicU64>,
    max_read: Arc<AtomicU64>,
    panic_on_drop: bool,
}
impl Read for BlockingGenerated {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.max_read
            .fetch_max(output.len() as u64, Ordering::Relaxed);
        let count = self.remaining.min(output.len() as u64) as usize;
        output[..count].fill(b'x');
        self.remaining -= count as u64;
        Ok(count)
    }
}
impl Drop for BlockingGenerated {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Release);
        assert!(
            !self.panic_on_drop,
            "synthetic protected source destructor panic"
        );
    }
}
impl Fixture {
    fn blocking_upload(
        &self,
        actual: u64,
        expected_digest: [u8; 32],
        dropped: Arc<AtomicU64>,
        max_read: Arc<AtomicU64>,
        panic_on_drop: bool,
    ) -> Result<RecoveryStreamReadback, CloudError> {
        let client =
            OpenCloudClient::new_with_proxy(&self.url, "synthetic".into(), &ProxyConfig::Direct)
                .unwrap();
        let context = RangeReadContext {
            deadline: Instant::now() + Duration::from_secs(10),
            token_generation: client.token_generation(),
        };
        client.recovery_upload_blocking_reader_with_context(
            "drive-1",
            "/",
            "root",
            "file.bin",
            "file",
            "\"v1\"",
            1,
            BlockingGenerated {
                remaining: actual,
                dropped,
                max_read,
                panic_on_drop,
            },
            self.size,
            expected_digest,
            context,
        )
    }
}
#[test]
fn blocking_large_and_empty_sources_stay_pinned_through_get_and_final_metadata() {
    for size in [0, 17 * 1024 * 1024 + 7] {
        let dropped = Arc::new(AtomicU64::new(0));
        let max_read = Arc::new(AtomicU64::new(0));
        let fixture = Fixture::with_pin_observer(size, Fault::None, Some(dropped.clone()));
        let proof = fixture
            .blocking_upload(size, digest(size), dropped.clone(), max_read.clone(), false)
            .unwrap();
        assert_eq!(proof.bytes, size);
        assert_eq!(proof.sha256, digest(size));
        assert_eq!(fixture.puts.load(Ordering::Acquire), 1);
        assert_eq!(fixture.gets.load(Ordering::Acquire), 1);
        assert!(
            fixture.pin_observations.load(Ordering::Acquire) >= 3,
            "GET plus final root/resource checks must observe held pin"
        );
        assert_eq!(dropped.load(Ordering::Acquire), 1);
        assert!(max_read.load(Ordering::Relaxed) <= CHUNK as u64);
    }
}
#[test]
fn blocking_partial_lost_response_extra_eof_and_bad_digest_join_without_success() {
    let size = CHUNK as u64 * 2 + 7;
    for (fault, actual, expected) in [
        (Fault::PartialPut, size, digest(size)),
        (Fault::ResponseLost, size, digest(size)),
        (Fault::None, size + 1, digest(size)),
        (Fault::None, size, [0; 32]),
    ] {
        let dropped = Arc::new(AtomicU64::new(0));
        let fixture = Fixture::with_pin_observer(size, fault, Some(dropped.clone()));
        assert!(
            fixture
                .blocking_upload(
                    actual,
                    expected,
                    dropped.clone(),
                    Arc::new(AtomicU64::new(0)),
                    false
                )
                .is_err()
        );
        assert_eq!(dropped.load(Ordering::Acquire), 1);
        assert_eq!(fixture.gets.load(Ordering::Acquire), 0);
    }
}
#[test]
fn blocking_admission_error_is_preserved_and_joined_destructor_failure_refuses_success() {
    let dropped = Arc::new(AtomicU64::new(0));
    let reads = Arc::new(AtomicU64::new(0));
    let fixture = Fixture::with_pin_observer(1, Fault::Root, Some(dropped.clone()));
    let error = fixture
        .blocking_upload(1, digest(1), dropped.clone(), reads.clone(), false)
        .err()
        .unwrap();
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    assert_eq!(dropped.load(Ordering::Acquire), 1);
    let dropped = Arc::new(AtomicU64::new(0));
    let fixture = Fixture::with_pin_observer(1, Fault::None, Some(dropped.clone()));
    let error = fixture
        .blocking_upload(
            1,
            digest(1),
            dropped.clone(),
            Arc::new(AtomicU64::new(0)),
            true,
        )
        .err()
        .unwrap();
    assert_eq!(
        error.message,
        "recovery source worker did not complete safely"
    );
    assert_eq!(fixture.gets.load(Ordering::Acquire), 1);
    assert!(fixture.pin_observations.load(Ordering::Acquire) >= 3);
    assert_eq!(dropped.load(Ordering::Acquire), 1);
}

struct RevokeOnDrop {
    content: io::Cursor<&'static [u8]>,
    generation: Option<Arc<AtomicU64>>,
    cancellation: Option<TransferBudget>,
}
impl Read for RevokeOnDrop {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        std::io::Read::read(&mut self.content, output)
    }
}
impl Drop for RevokeOnDrop {
    fn drop(&mut self) {
        if let Some(generation) = &self.generation {
            generation.fetch_add(1, Ordering::AcqRel);
        }
        if let Some(budget) = &self.cancellation {
            budget.set_paused(true);
            budget.cancel_waiters();
            budget.set_paused(false);
        }
    }
}
#[test]
fn blocking_source_shutdown_rechecks_generation_and_cancel_epoch_before_proof() {
    for revoke_generation in [true, false] {
        let fixture = Fixture::new(1, Fault::None);
        let client =
            OpenCloudClient::new_with_proxy(&fixture.url, "synthetic".into(), &ProxyConfig::Direct)
                .unwrap();
        let context = RangeReadContext {
            deadline: Instant::now() + Duration::from_secs(10),
            token_generation: client.token_generation(),
        };
        let source = RevokeOnDrop {
            content: io::Cursor::new(b"x"),
            generation: revoke_generation.then(|| Arc::clone(&client.token_generation)),
            cancellation: (!revoke_generation).then(|| client.transfer_budget.clone()),
        };
        let error = client
            .recovery_upload_blocking_reader_with_context(
                "drive-1",
                "/",
                "root",
                "file.bin",
                "file",
                "\"v1\"",
                1,
                source,
                1,
                digest(1),
                context,
            )
            .err()
            .unwrap();
        assert_eq!(fixture.gets.load(Ordering::Acquire), 1);
        assert!(!client.transfer_budget.is_paused());
        assert_eq!(
            error.kind,
            if revoke_generation {
                ErrorKind::Unauthorized
            } else {
                ErrorKind::Offline
            }
        );
    }
}

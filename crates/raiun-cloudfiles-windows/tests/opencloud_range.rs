use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
};

use raiun_cloudfiles_windows::{
    BackendError, CancellationToken, FetchRange, MAX_REQUEST_BYTES, OpenCloudPlaceholderBackend,
    PlaceholderBackend, ProviderScope,
};
use raiun_core::backend::CloudBackend;
use raiun_opencloud::{OpenCloudClient, RangeReadContext, RemoteRangeRequest};

const FILE_BODY: &[u8] = b"abcdefghij";
const RANGE_START: usize = 2;
const RANGE_END: usize = 9;

#[test]
fn scoped_adapter_registers_opaque_identity_and_reads_conditional_range() {
    let (server, worker, _) =
        start_fixture(21, false, false, false, None, std::time::Duration::ZERO);
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-synthetic".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let backend = OpenCloudPlaceholderBackend::new(client, scope).unwrap();
    let identity = match backend.register_file("drive-personal", "root-id", "/file.txt") {
        Ok(identity) => identity,
        Err(error) => {
            let requests = worker.join().unwrap();
            panic!("registration failed: {error:?}; requests={requests}");
        }
    };

    assert_eq!(identity.as_bytes().len(), 16);
    assert_eq!(
        backend.lookup(identity.as_bytes()).unwrap().unwrap().length,
        10
    );
    let mut bytes = [0xCC; 12];
    let result = backend.read_range(
        identity.as_bytes(),
        RANGE_START as u64,
        &mut bytes,
        &CancellationToken::new(),
    );
    let requests = worker.join().unwrap();
    assert_eq!(
        result,
        Ok(RANGE_END - RANGE_START + 1),
        "requests={requests}"
    );
    let count = result.unwrap();
    assert_eq!(count, RANGE_END - RANGE_START + 1);
    assert_eq!(&bytes[..count], &FILE_BODY[RANGE_START..=RANGE_END]);
    assert_eq!(
        bytes[count], 0xCC,
        "the backend must not over-write the range"
    );
    assert_eq!(requests, 21);
}

#[test]
fn scoped_adapter_enumerates_bounded_direct_children_and_reuses_identities() {
    let (server, stop, worker, requests) = start_directory_fixture(false);
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-synthetic".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let backend = OpenCloudPlaceholderBackend::new(client, scope).unwrap();
    let directory = backend
        .register_directory("drive-personal", "root-id", "/folder")
        .unwrap();
    assert_eq!(
        backend.lookup(directory.as_bytes()).unwrap().unwrap(),
        raiun_cloudfiles_windows::PlaceholderMetadata {
            is_directory: true,
            length: 0,
        }
    );
    let first = backend
        .enumerate(directory.as_bytes(), &CancellationToken::new())
        .unwrap();
    let second = backend
        .enumerate(directory.as_bytes(), &CancellationToken::new())
        .unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].name, "child.bin");
    assert_eq!(first[0].metadata.length, 10);
    assert_eq!(first[0].identity, second[0].identity);
    assert_eq!(
        backend.lookup(&first[0].identity).unwrap().unwrap().length,
        10
    );
    stop.store(false, std::sync::atomic::Ordering::Release);
    let request_count = worker.join().unwrap();
    assert!(
        request_count >= 10,
        "expected Graph and DAV identity checks"
    );
    assert_eq!(
        requests.load(std::sync::atomic::Ordering::Acquire),
        request_count
    );
}

#[test]
fn directory_publication_lease_blocks_revocation_until_publication_finishes() {
    let (server, stop, worker, _) = start_directory_fixture(false);
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-synthetic".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let backend = Arc::new(OpenCloudPlaceholderBackend::new(client, scope).unwrap());
    let directory = backend
        .register_directory("drive-personal", "root-id", "/folder")
        .unwrap();
    let prepared = backend
        .prepare_enumeration(directory.as_bytes(), &CancellationToken::new())
        .unwrap();
    assert_eq!(prepared.children().len(), 1);
    assert_eq!(prepared.children()[0].name, "child.bin");
    stop.store(false, std::sync::atomic::Ordering::Release);
    worker.join().unwrap();

    // The native callback holds this permit around CfExecute. Revocation must
    // not advance the auth generation or finish while the names are submitted.
    let permit = prepared.begin_publish(&CancellationToken::new()).unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    let revoking = {
        let backend = backend.clone();
        thread::spawn(move || {
            started_tx.send(()).unwrap();
            backend.revoke();
            done_tx.send(()).unwrap();
        })
    };
    started_rx.recv().unwrap();
    thread::sleep(std::time::Duration::from_millis(20));
    assert!(
        !backend.is_revoked(),
        "active publication serializes revoke"
    );
    assert!(done_rx.try_recv().is_err());

    drop(permit);
    let revoke_started = std::time::Instant::now();
    while !backend.is_revoked() {
        assert!(revoke_started.elapsed() < std::time::Duration::from_secs(2));
        thread::yield_now();
    }
    assert!(
        done_rx
            .recv_timeout(std::time::Duration::from_millis(30))
            .is_err(),
        "revoke must also drain the prepared listing lease"
    );
    drop(prepared);
    done_rx.recv().unwrap();
    revoking.join().unwrap();
    assert!(backend.is_revoked());
    assert_eq!(
        backend.lookup(directory.as_bytes()),
        Err(BackendError::Unavailable)
    );
}

#[test]
fn scoped_adapter_rejects_encrypted_direct_child_without_publishing_identity() {
    let (server, stop, worker, _) = start_directory_fixture(true);
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-synthetic".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let backend = OpenCloudPlaceholderBackend::new(client, scope).unwrap();
    let directory = backend
        .register_directory("drive-personal", "root-id", "/folder")
        .unwrap();
    assert_eq!(
        backend.enumerate(directory.as_bytes(), &CancellationToken::new()),
        Err(BackendError::Unavailable)
    );
    assert_eq!(
        backend.lookup(b"nonexistent-child!!"),
        Ok(None),
        "failed listings do not publish any children"
    );
    stop.store(false, std::sync::atomic::Ordering::Release);
    let _ = worker.join().unwrap();
}

#[test]
fn scoped_adapter_rejects_wrong_origin_and_cancelled_requests_before_network_io() {
    let (server, worker, _) =
        start_fixture(0, false, false, false, None, std::time::Duration::ZERO);
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    assert!(matches!(
        ProviderScope::new(
            client.as_ref(),
            "profile-synthetic".into(),
            "account-synthetic".into(),
            "https://elsewhere.invalid".into(),
        ),
        Err(BackendError::Unavailable)
    ));

    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-synthetic".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let backend = OpenCloudPlaceholderBackend::new(client, scope).unwrap();
    assert_eq!(
        backend.register_file("drive-personal", "root-id", "/../secret"),
        Err(BackendError::NotFound)
    );
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        backend.read_range(&[0; 16], 0, &mut [0; 4], &cancelled),
        Err(BackendError::Cancelled)
    );
    assert_eq!(worker.join().unwrap(), 0);
}

#[test]
fn bearer_rotation_invalidates_the_captured_provider_generation_before_io() {
    let (server, worker, _) =
        start_fixture(9, false, false, false, None, std::time::Duration::ZERO);
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-synthetic".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    assert_eq!(scope.token_generation(), 1);
    let backend = OpenCloudPlaceholderBackend::new(client.clone(), scope).unwrap();
    let identity = backend
        .register_file("drive-personal", "root-id", "/file.txt")
        .unwrap();

    client
        .set_bearer_token("rotated-synthetic-token".into())
        .unwrap();
    let mut output = [0xCC; 4];
    assert_eq!(
        backend.read_range(
            identity.as_bytes(),
            0,
            &mut output,
            &CancellationToken::new()
        ),
        Err(BackendError::Unavailable)
    );
    assert_eq!(output, [0xCC; 4]);
    assert_eq!(worker.join().unwrap(), 9);
}

#[test]
fn revocation_invalidates_provider_before_any_later_range_request() {
    let (server, worker, _) =
        start_fixture(9, false, false, false, None, std::time::Duration::ZERO);
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-synthetic".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let backend = OpenCloudPlaceholderBackend::new(client, scope).unwrap();
    let identity = backend
        .register_file("drive-personal", "root-id", "/file.txt")
        .unwrap();

    backend.revoke();
    let mut output = [0xCC; 4];
    assert_eq!(
        backend.read_range(
            identity.as_bytes(),
            0,
            &mut output,
            &CancellationToken::new()
        ),
        Err(BackendError::Unavailable)
    );
    assert_eq!(output, [0xCC; 4]);
    assert_eq!(worker.join().unwrap(), 9);
}

#[test]
fn file_registration_rejects_a_different_space_root_before_binding_identity() {
    let (server, worker, _) =
        start_fixture(3, false, false, false, None, std::time::Duration::ZERO);
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-synthetic".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let backend = OpenCloudPlaceholderBackend::new(client, scope).unwrap();
    assert_eq!(
        backend.register_file("drive-personal", "stale-root-id", "/file.txt"),
        Err(BackendError::Unavailable)
    );
    assert_eq!(worker.join().unwrap(), 3);
}

#[test]
fn registration_does_not_publish_identity_after_auth_generation_rotates_mid_stat() {
    let (server, worker, accepted) = start_fixture(
        4,
        false,
        false,
        false,
        Some(4),
        std::time::Duration::from_millis(180),
    );
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-synthetic".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let backend = Arc::new(OpenCloudPlaceholderBackend::new(client.clone(), scope).unwrap());
    let registering = {
        let backend = backend.clone();
        std::thread::spawn(move || backend.register_file("drive-personal", "root-id", "/file.txt"))
    };
    // The first three responses finish quickly; request four is the delayed
    // Graph metadata request for the file registration.
    let wait_started = std::time::Instant::now();
    while accepted.load(std::sync::atomic::Ordering::Acquire) < 4 {
        assert!(wait_started.elapsed() < std::time::Duration::from_secs(2));
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    client
        .set_bearer_token("rotated-during-registration".into())
        .unwrap();
    assert_eq!(registering.join().unwrap(), Err(BackendError::Unavailable));
    assert_eq!(worker.join().unwrap(), 4);
}

#[test]
fn registration_does_not_publish_identity_after_revocation_mid_stat() {
    let (server, worker, accepted) = start_fixture(
        9,
        false,
        false,
        false,
        Some(4),
        std::time::Duration::from_millis(180),
    );
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-synthetic".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let backend = Arc::new(OpenCloudPlaceholderBackend::new(client, scope).unwrap());
    let registering = {
        let backend = backend.clone();
        std::thread::spawn(move || backend.register_file("drive-personal", "root-id", "/file.txt"))
    };

    let wait_started = std::time::Instant::now();
    while accepted.load(std::sync::atomic::Ordering::Acquire) < 4 {
        assert!(wait_started.elapsed() < std::time::Duration::from_secs(2));
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let revoking = {
        let backend = backend.clone();
        std::thread::spawn(move || backend.revoke())
    };
    let revoke_started = std::time::Instant::now();
    while !backend.is_revoked() {
        assert!(revoke_started.elapsed() < std::time::Duration::from_secs(2));
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    // Revoke marks the provider inactive immediately, then waits for this
    // bounded registration lease. Registration must observe that mark before
    // publishing the generated identity.
    assert_eq!(registering.join().unwrap(), Err(BackendError::Unavailable));
    revoking.join().unwrap();
    assert_eq!(worker.join().unwrap(), 9);
}

#[test]
fn total_deadline_is_shared_across_metadata_requests_and_discards_output() {
    let (server, worker, _) = start_fixture(
        11,
        false,
        false,
        false,
        Some(10),
        std::time::Duration::from_millis(80),
    );
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-synthetic".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let backend = OpenCloudPlaceholderBackend::new(client, scope).unwrap();
    let identity = backend
        .register_file("drive-personal", "root-id", "/file.txt")
        .unwrap();

    let mut output = [0xCC; 8];
    let started = std::time::Instant::now();
    let result = backend.read_range(
        identity.as_bytes(),
        0,
        &mut output,
        &CancellationToken::with_timeout(std::time::Duration::from_millis(130)),
    );
    let elapsed = started.elapsed();
    let requests = worker.join().unwrap();
    assert_eq!(result, Err(BackendError::Unavailable));
    assert_eq!(
        output, [0xCC; 8],
        "timed-out reads never publish staged bytes"
    );
    assert!(
        elapsed < std::time::Duration::from_millis(350),
        "elapsed={elapsed:?}"
    );
    assert_eq!(requests, 11);
}

#[test]
fn scoped_adapter_rejects_mismatched_content_range_without_touching_output() {
    let (server, worker, _) =
        start_fixture(16, true, false, false, None, std::time::Duration::ZERO);
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-synthetic".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let backend = OpenCloudPlaceholderBackend::new(client, scope).unwrap();
    let identity = match backend.register_file("drive-personal", "root-id", "/file.txt") {
        Ok(identity) => identity,
        Err(error) => {
            let requests = worker.join().unwrap();
            panic!("corrupt-fixture registration failed: {error:?}; requests={requests}");
        }
    };
    let mut output = [0xCC; 12];
    assert_eq!(
        backend.read_range(
            identity.as_bytes(),
            RANGE_START as u64,
            &mut output,
            &CancellationToken::new(),
        ),
        Err(BackendError::Unavailable)
    );
    assert_eq!(output, [0xCC; 12]);
    assert_eq!(worker.join().unwrap(), 16);
}

#[test]
fn scoped_adapter_discards_range_if_path_becomes_encrypted_before_readback() {
    let (server, worker, _) =
        start_fixture(19, false, true, false, None, std::time::Duration::ZERO);
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-synthetic".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let backend = OpenCloudPlaceholderBackend::new(client, scope).unwrap();
    let identity = match backend.register_file("drive-personal", "root-id", "/file.txt") {
        Ok(identity) => identity,
        Err(error) => {
            let requests = worker.join().unwrap();
            panic!("registration failed: {error:?}; requests={requests}");
        }
    };
    let mut output = [0xCC; 12];
    assert_eq!(
        backend.read_range(
            identity.as_bytes(),
            RANGE_START as u64,
            &mut output,
            &CancellationToken::new(),
        ),
        Err(BackendError::Unavailable)
    );
    assert_eq!(output, [0xCC; 12], "staged plaintext must not escape");
    assert_eq!(worker.join().unwrap(), 19);
}

#[test]
fn scoped_adapter_discards_range_if_parent_becomes_encrypted_before_readback() {
    let (server, worker, _) =
        start_fixture(18, false, false, true, None, std::time::Duration::ZERO);
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-synthetic".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let backend = OpenCloudPlaceholderBackend::new(client, scope).unwrap();
    let identity = backend
        .register_file("drive-personal", "root-id", "/file.txt")
        .unwrap();
    let mut output = [0xCC; 12];
    assert_eq!(
        backend.read_range(
            identity.as_bytes(),
            RANGE_START as u64,
            &mut output,
            &CancellationToken::new(),
        ),
        Err(BackendError::Unavailable)
    );
    assert_eq!(output, [0xCC; 12], "staged plaintext must not escape");
    assert_eq!(worker.join().unwrap(), 18);
}

#[test]
fn callback_session_fetches_delayed_sixteen_mib_in_one_conditional_range() {
    let file_len = MAX_REQUEST_BYTES as usize;
    let (server, worker, _) = start_callback_fixture(
        21,
        file_len,
        CallbackFixtureMode::Valid,
        std::time::Duration::from_millis(150),
    );
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-synthetic".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let backend = OpenCloudPlaceholderBackend::new(client, scope).unwrap();
    let identity = backend
        .register_file("drive-personal", "root-id", "/file.txt")
        .unwrap();
    let started = std::time::Instant::now();
    let prepared = backend
        .prepare_fetch(
            identity.as_bytes(),
            FetchRange {
                offset: 0,
                end: file_len as u64,
            },
            &CancellationToken::new(),
        )
        .unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert_eq!(prepared.bytes().len(), file_len);
    assert_eq!(prepared.bytes()[0], 0);
    assert_eq!(prepared.bytes()[65_537], (65_537 % 251) as u8);
    assert_eq!(prepared.bytes()[file_len - 1], ((file_len - 1) % 251) as u8);
    assert_eq!(worker.join().unwrap(), 21);
}

#[test]
fn callback_session_discards_wrong_root_etag_and_short_ranges() {
    for mode in [
        CallbackFixtureMode::WrongRootAfterRead,
        CallbackFixtureMode::WrongRangeEtag,
        CallbackFixtureMode::ShortBody,
    ] {
        let expected_requests = if matches!(mode, CallbackFixtureMode::WrongRootAfterRead) {
            21
        } else {
            16
        };
        let (server, worker, _) =
            start_callback_fixture(expected_requests, 8192, mode, std::time::Duration::ZERO);
        let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
        let scope = ProviderScope::new(
            client.as_ref(),
            "profile-synthetic".into(),
            "account-synthetic".into(),
            client.server_origin().unwrap(),
        )
        .unwrap();
        let backend = OpenCloudPlaceholderBackend::new(client.clone(), scope).unwrap();
        let identity = backend
            .register_file("drive-personal", "root-id", "/file.txt")
            .unwrap();
        let _identity = identity;
        let mut sentinel = vec![0xCC; 8192];
        let result = client.read_callback_range_cancellable_with_context(
            RemoteRangeRequest {
                space: "drive-personal",
                expected_root_id: "root-id",
                path: "/file.txt",
                expected_id: "file-id-1",
                expected_etag: "\"revision-1\"",
                expected_size: 8192,
                offset: 0,
            },
            &mut sentinel,
            RangeReadContext {
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
                token_generation: client.token_generation(),
            },
            || false,
        );
        assert!(result.is_err(), "mode={mode:?}");
        assert!(sentinel.iter().all(|byte| *byte == 0xCC), "mode={mode:?}");
        assert_eq!(worker.join().unwrap(), expected_requests, "mode={mode:?}");
    }
}

#[test]
fn callback_session_discards_cancelled_or_revoked_staging() {
    for revoke in [false, true] {
        let (server, worker, accepted) = start_callback_fixture(
            16,
            8192,
            CallbackFixtureMode::Valid,
            std::time::Duration::from_millis(150),
        );
        let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
        let scope = ProviderScope::new(
            client.as_ref(),
            "profile-synthetic".into(),
            "account-synthetic".into(),
            client.server_origin().unwrap(),
        )
        .unwrap();
        let backend = Arc::new(OpenCloudPlaceholderBackend::new(client, scope).unwrap());
        let identity = backend
            .register_file("drive-personal", "root-id", "/file.txt")
            .unwrap();
        let cancellation = CancellationToken::new();
        let reader = {
            let backend = backend.clone();
            let cancellation = cancellation.clone();
            let identity = *identity.as_bytes();
            std::thread::spawn(move || {
                backend
                    .prepare_fetch(
                        &identity,
                        FetchRange {
                            offset: 0,
                            end: 8192,
                        },
                        &cancellation,
                    )
                    .is_err()
            })
        };
        if revoke {
            let wait_started = std::time::Instant::now();
            while accepted.load(std::sync::atomic::Ordering::Acquire) < 16 {
                assert!(wait_started.elapsed() < std::time::Duration::from_secs(2));
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            let revoking = {
                let backend = backend.clone();
                std::thread::spawn(move || backend.revoke())
            };
            while !backend.is_revoked() {
                assert!(wait_started.elapsed() < std::time::Duration::from_secs(2));
                std::thread::yield_now();
            }
            assert!(reader.join().unwrap());
            revoking.join().unwrap();
        } else {
            let wait_started = std::time::Instant::now();
            while accepted.load(std::sync::atomic::Ordering::Acquire) < 16 {
                assert!(wait_started.elapsed() < std::time::Duration::from_secs(2));
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            cancellation.cancel();
            assert!(reader.join().unwrap());
        }
        assert_eq!(worker.join().unwrap(), 16);
    }
}

#[test]
fn publish_permit_serializes_each_slice_with_provider_revocation() {
    let (server, worker, _) = start_callback_fixture(
        21,
        8192,
        CallbackFixtureMode::Valid,
        std::time::Duration::ZERO,
    );
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-synthetic".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let backend = Arc::new(OpenCloudPlaceholderBackend::new(client, scope).unwrap());
    let identity = backend
        .register_file("drive-personal", "root-id", "/file.txt")
        .unwrap();
    let prepared = backend
        .prepare_fetch(
            identity.as_bytes(),
            FetchRange {
                offset: 0,
                end: 8192,
            },
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(worker.join().unwrap(), 21);

    let permit = prepared.begin_publish(&CancellationToken::new()).unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let revoking = {
        let backend = backend.clone();
        thread::spawn(move || {
            started_tx.send(()).unwrap();
            backend.revoke();
        })
    };
    started_rx.recv().unwrap();
    thread::sleep(std::time::Duration::from_millis(20));
    assert!(
        !backend.is_revoked(),
        "revocation waits for active publication"
    );
    drop(permit);
    drop(prepared);
    revoking.join().unwrap();
    assert!(backend.is_revoked());
    assert_eq!(
        backend.lookup(identity.as_bytes()),
        Err(BackendError::Unavailable)
    );
}

#[test]
fn per_file_retirement_waits_for_prepared_callback_publication() {
    let (server, worker, _) = start_callback_fixture(
        21,
        8192,
        CallbackFixtureMode::Valid,
        std::time::Duration::ZERO,
    );
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-synthetic".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let backend = Arc::new(OpenCloudPlaceholderBackend::new(client, scope).unwrap());
    let identity = backend
        .register_file("drive-personal", "root-id", "/file.txt")
        .unwrap();
    let prepared = backend
        .prepare_fetch(
            identity.as_bytes(),
            FetchRange {
                offset: 0,
                end: 8192,
            },
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(worker.join().unwrap(), 21);

    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    let retiring = {
        let backend = backend.clone();
        thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = backend.unregister_file(identity);
            done_tx.send(result).unwrap();
        })
    };
    started_rx.recv().unwrap();
    assert!(
        done_rx
            .recv_timeout(std::time::Duration::from_millis(30))
            .is_err(),
        "retirement must wait while the prepared callback retains its lease"
    );

    // The native callback retains PreparedFetch through every CfExecute slice.
    // Releasing it is therefore the point at which the binding can be retired.
    drop(prepared);
    assert_eq!(done_rx.recv().unwrap(), Ok(()));
    retiring.join().unwrap();
    assert_eq!(
        backend.lookup(identity.as_bytes()),
        Ok(None),
        "after retirement, later callbacks cannot resolve the old identity"
    );
}

#[test]
fn publish_permit_holds_authenticated_generation_stable_for_one_slice() {
    let (server, worker, _) = start_callback_fixture(
        21,
        8192,
        CallbackFixtureMode::Valid,
        std::time::Duration::ZERO,
    );
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-synthetic".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let backend = OpenCloudPlaceholderBackend::new(client.clone(), scope).unwrap();
    let identity = backend
        .register_file("drive-personal", "root-id", "/file.txt")
        .unwrap();
    let prepared = backend
        .prepare_fetch(
            identity.as_bytes(),
            FetchRange {
                offset: 0,
                end: 8192,
            },
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(worker.join().unwrap(), 21);

    let permit = prepared.begin_publish(&CancellationToken::new()).unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let rotating = {
        let client = client.clone();
        thread::spawn(move || {
            started_tx.send(()).unwrap();
            client.set_bearer_token("rotated-synthetic-token".into())
        })
    };
    started_rx.recv().unwrap();
    thread::sleep(std::time::Duration::from_millis(20));
    assert_eq!(client.token_generation(), 1);
    drop(permit);
    rotating.join().unwrap().unwrap();
    assert_eq!(client.token_generation(), 2);
    assert!(prepared.begin_publish(&CancellationToken::new()).is_err());
}

#[derive(Clone, Copy, Debug)]
enum CallbackFixtureMode {
    Valid,
    WrongRootAfterRead,
    WrongRangeEtag,
    ShortBody,
    EtagChangesAfterRead,
    UnauthorizedAfterRead,
    ForbiddenAfterRead,
}

fn cached_test_backend(
    server: &str,
    cache: raiun_cache::Cache,
    account_id: &str,
) -> (
    Arc<OpenCloudClient>,
    OpenCloudPlaceholderBackend,
    ProviderScope,
) {
    let client = Arc::new(OpenCloudClient::new(server, "synthetic-token".into()).unwrap());
    let scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        account_id.into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let backend =
        OpenCloudPlaceholderBackend::new_with_cache(client.clone(), scope.clone(), cache).unwrap();
    (client, backend, scope)
}

fn seed_callback_file_listing(cache: &raiun_cache::Cache, scope: &ProviderScope, file_len: usize) {
    let cache_scope = raiun_cache::CacheScope::new(
        scope.server_origin(),
        scope.account_id(),
        "drive-personal",
        "root-id",
        raiun_cache::ScopeProtection::PlaintextAllowed,
    )
    .unwrap();
    cache
        .publish_listing(
            &cache_scope,
            "root-id",
            &[raiun_cache::CachedEntry {
                parent_resource_id: "root-id".into(),
                entry: raiun_core::backend::RemoteEntry {
                    id: "file-id-1".into(),
                    path: "/file.txt".into(),
                    etag: "\"revision-1\"".into(),
                    size: file_len as u64,
                    directory: false,
                    modified_unix: 1,
                    writable: true,
                    encrypted: false,
                },
            }],
            1,
        )
        .unwrap();
}

fn test_cache() -> (raiun_cache::Cache, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(
        directory.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let cache = raiun_cache::Cache::open(directory.path(), 64 * 1024 * 1024).unwrap();
    (cache, directory)
}

#[test]
fn complete_callback_is_available_offline_for_partial_callback_and_range_reads() {
    let file_len = 8192;
    let (cache, _cache_directory) = test_cache();
    let (server, worker, _) = start_callback_fixture(
        21,
        file_len,
        CallbackFixtureMode::Valid,
        std::time::Duration::ZERO,
    );
    let (client, backend, scope) = cached_test_backend(&server, cache.clone(), "account-synthetic");
    seed_callback_file_listing(&cache, &scope, file_len);
    let identity = backend
        .register_file("drive-personal", "root-id", "/file.txt")
        .unwrap();
    let empty_status = backend
        .file_cache_status(
            identity.as_bytes(),
            "file-id-1",
            "\"revision-1\"",
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(empty_status.policy, raiun_cache::AvailabilityPolicy::Recent);
    assert!(!empty_status.recorded_complete_version);
    assert_eq!(empty_status.recorded_bytes, 0);

    let mut unknown_identity = identity.as_bytes().to_vec();
    unknown_identity[0] ^= 0xff;
    assert_eq!(
        backend.file_cache_status(
            &unknown_identity,
            "file-id-1",
            "\"revision-1\"",
            &CancellationToken::new(),
        ),
        Err(BackendError::NotFound)
    );
    assert_eq!(
        backend.file_cache_status(
            identity.as_bytes(),
            "different-file-id",
            "\"revision-1\"",
            &CancellationToken::new(),
        ),
        Err(BackendError::NotFound)
    );
    assert_eq!(
        backend.file_cache_status(
            identity.as_bytes(),
            "file-id-1",
            "\"stale-revision\"",
            &CancellationToken::new(),
        ),
        Err(BackendError::NotFound)
    );
    let full = backend
        .prepare_fetch(
            identity.as_bytes(),
            FetchRange {
                offset: 0,
                end: file_len as u64,
            },
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(full.bytes().len(), file_len);
    assert_eq!(full.bytes()[123], 123);
    drop(full);
    assert_eq!(worker.join().unwrap(), 21);

    let cached_status = backend
        .file_cache_status(
            identity.as_bytes(),
            "file-id-1",
            "\"revision-1\"",
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(
        cached_status.policy,
        raiun_cache::AvailabilityPolicy::Recent
    );
    assert!(cached_status.recorded_complete_version);
    assert_eq!(cached_status.recorded_bytes, file_len as u64);

    let partial = backend
        .prepare_fetch(
            identity.as_bytes(),
            FetchRange {
                offset: 13,
                end: 71,
            },
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(
        partial.bytes(),
        &(13..71).map(|n| (n % 251) as u8).collect::<Vec<_>>()
    );

    // A policy change must drain callback work before changing cache metadata.
    // Keep this prepared fetch alive while the setter uses its short bounded
    // deadline; after it expires, metadata and cached bytes must be untouched.
    assert_eq!(
        backend.set_file_cache_policy(
            identity.as_bytes(),
            "file-id-1",
            "\"revision-1\"",
            raiun_cache::AvailabilityPolicy::CloudOnly,
            &CancellationToken::with_timeout(std::time::Duration::from_millis(25)),
        ),
        Err(BackendError::Unavailable)
    );
    let still_recent = backend
        .file_cache_status(
            identity.as_bytes(),
            "file-id-1",
            "\"revision-1\"",
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(still_recent.policy, raiun_cache::AvailabilityPolicy::Recent);
    assert!(still_recent.recorded_complete_version);
    assert_eq!(still_recent.recorded_bytes, file_len as u64);
    drop(partial);

    let mut ranged = [0xCC; 12];
    let count = backend
        .read_range(
            identity.as_bytes(),
            101,
            &mut ranged,
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(count, ranged.len());
    assert_eq!(
        ranged,
        std::array::from_fn(|index| ((101 + index) % 251) as u8)
    );

    assert_eq!(
        backend.set_file_cache_policy(
            &unknown_identity,
            "file-id-1",
            "\"revision-1\"",
            raiun_cache::AvailabilityPolicy::CloudOnly,
            &CancellationToken::new(),
        ),
        Err(BackendError::NotFound)
    );
    assert_eq!(
        backend.set_file_cache_policy(
            identity.as_bytes(),
            "different-file-id",
            "\"revision-1\"",
            raiun_cache::AvailabilityPolicy::CloudOnly,
            &CancellationToken::new(),
        ),
        Err(BackendError::NotFound)
    );
    assert_eq!(
        backend.set_file_cache_policy(
            identity.as_bytes(),
            "file-id-1",
            "\"stale-revision\"",
            raiun_cache::AvailabilityPolicy::CloudOnly,
            &CancellationToken::new(),
        ),
        Err(BackendError::NotFound)
    );
    assert_eq!(
        backend.set_file_cache_policy(
            identity.as_bytes(),
            "file-id-1",
            "\"revision-1\"",
            raiun_cache::AvailabilityPolicy::AlwaysOffline,
            &CancellationToken::new(),
        ),
        Err(BackendError::Unavailable)
    );
    let cancelled_policy = CancellationToken::new();
    cancelled_policy.cancel();
    assert_eq!(
        backend.set_file_cache_policy(
            identity.as_bytes(),
            "file-id-1",
            "\"revision-1\"",
            raiun_cache::AvailabilityPolicy::CloudOnly,
            &cancelled_policy,
        ),
        Err(BackendError::Cancelled)
    );
    assert_eq!(
        backend
            .file_cache_status(
                identity.as_bytes(),
                "file-id-1",
                "\"revision-1\"",
                &CancellationToken::new(),
            )
            .unwrap(),
        still_recent,
        "refused policy changes must leave policy and content metadata unchanged"
    );
    backend
        .set_file_cache_policy(
            identity.as_bytes(),
            "file-id-1",
            "\"revision-1\"",
            raiun_cache::AvailabilityPolicy::CloudOnly,
            &CancellationToken::new(),
        )
        .unwrap();
    let cloud_only_status = backend
        .file_cache_status(
            identity.as_bytes(),
            "file-id-1",
            "\"revision-1\"",
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(
        cloud_only_status.policy,
        raiun_cache::AvailabilityPolicy::CloudOnly
    );
    assert!(!cloud_only_status.recorded_complete_version);
    assert_eq!(cloud_only_status.recorded_bytes, 0);

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        backend.file_cache_status(
            identity.as_bytes(),
            "file-id-1",
            "\"revision-1\"",
            &cancelled,
        ),
        Err(BackendError::Cancelled)
    );

    client
        .set_bearer_token("rotated-synthetic-token".into())
        .unwrap();
    assert_eq!(
        backend.file_cache_status(
            identity.as_bytes(),
            "file-id-1",
            "\"revision-1\"",
            &CancellationToken::new(),
        ),
        Err(BackendError::Unavailable),
        "a stale provider token must not authorize a cache-status read"
    );

    assert_eq!(
        backend.set_file_cache_policy(
            identity.as_bytes(),
            "file-id-1",
            "\"revision-1\"",
            raiun_cache::AvailabilityPolicy::Recent,
            &CancellationToken::new(),
        ),
        Err(BackendError::Unavailable),
        "a rotated account token cannot change policy"
    );

    backend.revoke();
    assert_eq!(
        backend.file_cache_status(
            identity.as_bytes(),
            "file-id-1",
            "\"revision-1\"",
            &CancellationToken::new(),
        ),
        Err(BackendError::Unavailable)
    );
}

#[test]
fn partial_callback_does_not_publish_an_offline_complete_version() {
    let file_len = 8192;
    let (server, worker, _) = start_callback_fixture(
        21,
        file_len,
        CallbackFixtureMode::Valid,
        std::time::Duration::ZERO,
    );
    let (cache, _cache_directory) = test_cache();
    let (_, backend, _) = cached_test_backend(&server, cache, "account-synthetic");
    let identity = backend
        .register_file("drive-personal", "root-id", "/file.txt")
        .unwrap();
    let partial = backend
        .prepare_fetch(
            identity.as_bytes(),
            FetchRange { offset: 7, end: 99 },
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(partial.bytes().len(), 92);
    drop(partial);
    assert_eq!(worker.join().unwrap(), 21);

    assert_eq!(
        backend
            .prepare_fetch(
                identity.as_bytes(),
                FetchRange {
                    offset: 0,
                    end: file_len as u64,
                },
                &CancellationToken::new(),
            )
            .err(),
        Some(BackendError::Unavailable)
    );
}

#[test]
fn online_full_read_succeeds_without_cached_listing_but_is_not_reusable_offline() {
    let file_len = 8192;
    let (server, worker, _) = start_callback_fixture(
        21,
        file_len,
        CallbackFixtureMode::Valid,
        std::time::Duration::ZERO,
    );
    let (cache, _cache_directory) = test_cache();
    let (_, backend, _) = cached_test_backend(&server, cache, "account-synthetic");
    let identity = backend
        .register_file("drive-personal", "root-id", "/file.txt")
        .unwrap();
    let full = backend
        .prepare_fetch(
            identity.as_bytes(),
            FetchRange {
                offset: 0,
                end: file_len as u64,
            },
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(full.bytes().len(), file_len);
    drop(full);
    assert_eq!(worker.join().unwrap(), 21);

    assert_eq!(
        backend
            .prepare_fetch(
                identity.as_bytes(),
                FetchRange {
                    offset: 10,
                    end: 30
                },
                &CancellationToken::new(),
            )
            .err(),
        Some(BackendError::Unavailable),
        "content without its complete parent listing cannot be used offline"
    );
}

#[test]
fn account_scope_and_remote_version_changes_cannot_reuse_cached_content() {
    let file_len = 8192;
    let (server, worker, accepted, stop) = start_callback_fixture_stoppable(
        10_000,
        file_len,
        CallbackFixtureMode::Valid,
        std::time::Duration::ZERO,
    );
    let (cache, _cache_directory) = test_cache();
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
    let first_scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-one".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let first_scope_for_listing = first_scope.clone();
    let first =
        OpenCloudPlaceholderBackend::new_with_cache(client.clone(), first_scope, cache.clone())
            .unwrap();
    seed_callback_file_listing(&cache, &first_scope_for_listing, file_len);
    let first_identity = first
        .register_file("drive-personal", "root-id", "/file.txt")
        .unwrap();
    let full = first
        .prepare_fetch(
            first_identity.as_bytes(),
            FetchRange {
                offset: 0,
                end: file_len as u64,
            },
            &CancellationToken::new(),
        )
        .unwrap();
    drop(full);

    let second_scope = ProviderScope::new(
        client.as_ref(),
        "profile-synthetic".into(),
        "account-two".into(),
        client.server_origin().unwrap(),
    )
    .unwrap();
    let second = OpenCloudPlaceholderBackend::new_with_cache(client, second_scope, cache).unwrap();
    let second_identity = second
        .register_file("drive-personal", "root-id", "/file.txt")
        .unwrap_or_else(|error| {
            panic!(
                "second registration failed {error:?}; requests={}",
                accepted.load(std::sync::atomic::Ordering::Acquire)
            )
        });
    stop.store(false, std::sync::atomic::Ordering::Release);
    let request_count = worker.join().unwrap();
    assert_eq!(
        request_count,
        accepted.load(std::sync::atomic::Ordering::Acquire)
    );
    assert_eq!(
        second
            .prepare_fetch(
                second_identity.as_bytes(),
                FetchRange {
                    offset: 10,
                    end: 30
                },
                &CancellationToken::new(),
            )
            .err(),
        Some(BackendError::Unavailable),
        "account two cannot use account one's content after transport stops"
    );
}

#[test]
fn callback_cache_does_not_fallback_after_auth_failure_or_version_change() {
    for (mode, expected_status) in [
        (CallbackFixtureMode::UnauthorizedAfterRead, "401"),
        (CallbackFixtureMode::ForbiddenAfterRead, "403"),
        (CallbackFixtureMode::EtagChangesAfterRead, "etag"),
    ] {
        let file_len = 8192;
        let expected_requests = 28;
        let (server, worker, _) =
            start_callback_fixture(expected_requests, file_len, mode, std::time::Duration::ZERO);
        let (cache, _cache_directory) = test_cache();
        let (_, backend, scope) = cached_test_backend(&server, cache.clone(), "account-synthetic");
        seed_callback_file_listing(&cache, &scope, file_len);
        let identity = backend
            .register_file("drive-personal", "root-id", "/file.txt")
            .unwrap();
        let full = backend
            .prepare_fetch(
                identity.as_bytes(),
                FetchRange {
                    offset: 0,
                    end: file_len as u64,
                },
                &CancellationToken::new(),
            )
            .unwrap();
        drop(full);

        let result = backend.prepare_fetch(
            identity.as_bytes(),
            FetchRange {
                offset: 10,
                end: 30,
            },
            &CancellationToken::new(),
        );
        assert!(result.is_err(), "mode={mode:?}, expected {expected_status}");
        assert_eq!(
            backend
                .prepare_fetch(
                    identity.as_bytes(),
                    FetchRange {
                        offset: 10,
                        end: 30,
                    },
                    &CancellationToken::new(),
                )
                .err(),
            Some(BackendError::Unavailable),
            "failed authoritative online state must disable this stale cache binding: {mode:?}"
        );
        assert_eq!(worker.join().unwrap(), expected_requests, "mode={mode:?}");
    }
}

#[test]
fn cached_offline_reads_still_obey_cancellation_and_revocation() {
    let file_len = 8192;
    let (server, worker, _) = start_callback_fixture(
        21,
        file_len,
        CallbackFixtureMode::Valid,
        std::time::Duration::ZERO,
    );
    let (cache, _cache_directory) = test_cache();
    let (_, backend, scope) = cached_test_backend(&server, cache.clone(), "account-synthetic");
    seed_callback_file_listing(&cache, &scope, file_len);
    let identity = backend
        .register_file("drive-personal", "root-id", "/file.txt")
        .unwrap();
    let full = backend
        .prepare_fetch(
            identity.as_bytes(),
            FetchRange {
                offset: 0,
                end: file_len as u64,
            },
            &CancellationToken::new(),
        )
        .unwrap();
    drop(full);
    assert_eq!(worker.join().unwrap(), 21);

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let mut output = [0xCC; 12];
    assert_eq!(
        backend.read_range(identity.as_bytes(), 100, &mut output, &cancelled),
        Err(BackendError::Cancelled)
    );
    assert_eq!(output, [0xCC; 12]);

    backend.revoke();
    assert_eq!(
        backend.read_range(
            identity.as_bytes(),
            100,
            &mut output,
            &CancellationToken::new(),
        ),
        Err(BackendError::Unavailable)
    );
    assert_eq!(output, [0xCC; 12]);
}

#[test]
fn complete_verified_directory_listing_is_available_after_transport_stops() {
    let (server, stop, worker, _) = start_directory_fixture(false);
    let (cache, _cache_directory) = test_cache();
    let (_, backend, _) = cached_test_backend(&server, cache, "account-synthetic");
    let directory = backend
        .register_directory("drive-personal", "root-id", "/folder")
        .unwrap();
    let online = backend
        .enumerate(directory.as_bytes(), &CancellationToken::new())
        .unwrap();
    assert_eq!(online.len(), 1);
    assert_eq!(online[0].name, "child.bin");
    assert_eq!(online[0].metadata.length, 10);

    stop.store(false, std::sync::atomic::Ordering::Release);
    assert!(worker.join().unwrap() >= 10);
    let offline = backend
        .enumerate(directory.as_bytes(), &CancellationToken::new())
        .unwrap();
    assert_eq!(offline, online);
}

#[test]
fn incomplete_or_encrypted_directory_listing_is_not_available_offline() {
    let (server, stop, worker, _) = start_directory_fixture(true);
    let (cache, _cache_directory) = test_cache();
    let (_, backend, _) = cached_test_backend(&server, cache, "account-synthetic");
    let directory = backend
        .register_directory("drive-personal", "root-id", "/folder")
        .unwrap();
    assert_eq!(
        backend.enumerate(directory.as_bytes(), &CancellationToken::new()),
        Err(BackendError::Unavailable)
    );

    stop.store(false, std::sync::atomic::Ordering::Release);
    assert!(worker.join().unwrap() >= 10);
    assert_eq!(
        backend.enumerate(directory.as_bytes(), &CancellationToken::new()),
        Err(BackendError::Unavailable),
        "a failed online listing cannot leave reusable offline entries"
    );
}

fn start_directory_fixture(
    encrypted_child: bool,
) -> (
    String,
    Arc<std::sync::atomic::AtomicBool>,
    thread::JoinHandle<usize>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let worker_running = running.clone();
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let worker_requests = requests.clone();
    let worker = thread::spawn(move || {
        let mut handled = 0;
        let mut idle = 0;
        while worker_running.load(std::sync::atomic::Ordering::Acquire) || idle < 100 {
            let (mut stream, _) = match listener.accept() {
                Ok(value) => {
                    idle = 0;
                    value
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    idle += 1;
                    thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("directory fixture listener failed: {error}"),
            };
            stream.set_nonblocking(false).unwrap();
            let request = read_request(&mut stream);
            let request_line = request.lines().next().unwrap_or("");
            let lower = request.to_ascii_lowercase();
            worker_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let (status, content_type, body) = if request_line.starts_with("GET /graph/") {
                (
                    "200 OK",
                    "application/json",
                    format!(
                        r#"{{"value":[{{"id":"drive-personal","name":"Personal","driveType":"personal","root":{{"id":"root-id","webDavUrl":"http://{address}/dav/personal/"}}}}]}}"#
                    ),
                )
            } else if request_line.starts_with("PROPFIND ") {
                let path = request_line.split_whitespace().nth(1).unwrap_or("");
                let depth_one = lower.contains("depth: 1");
                let mut entries = Vec::new();
                if path == "/dav/personal/" {
                    entries.push(directory_entry_xml(
                        "/dav/personal/",
                        "root-id",
                        true,
                        false,
                    ));
                } else if path.trim_end_matches('/') == "/dav/personal/folder" {
                    entries.push(directory_entry_xml(
                        "/dav/personal/folder/",
                        "folder-id",
                        true,
                        false,
                    ));
                    if depth_one {
                        entries.push(directory_entry_xml(
                            "/dav/personal/folder/child.bin",
                            "child-id",
                            false,
                            encrypted_child,
                        ));
                    }
                } else {
                    panic!("unexpected directory DAV path: {path}");
                }
                (
                    "207 Multi-Status",
                    "application/xml",
                    format!(
                        r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:lg="http://graph.opencloud.eu/ns">{}</d:multistatus>"#,
                        entries.concat()
                    ),
                )
            } else {
                panic!("unexpected directory fixture request: {request_line}");
            };
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            handled += 1;
        }
        handled
    });
    (format!("http://{address}"), running, worker, requests)
}

fn directory_entry_xml(href: &str, id: &str, is_directory: bool, encrypted: bool) -> String {
    let resource_type = if is_directory { "<d:collection/>" } else { "" };
    let encryption = if encrypted {
        "<lg:encrypted>true</lg:encrypted>"
    } else {
        ""
    };
    let size = if is_directory { 0 } else { 10 };
    let etag = if is_directory {
        "dir-revision"
    } else {
        "\"file-revision\""
    };
    format!(
        r#"<d:response><d:href>{href}</d:href><d:propstat><d:prop><d:resourcetype>{resource_type}</d:resourcetype><d:getcontentlength>{size}</d:getcontentlength><d:getetag>{etag}</d:getetag><oc:fileid>{id}</oc:fileid>{encryption}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"#
    )
}

fn start_callback_fixture(
    expected_requests: usize,
    file_len: usize,
    mode: CallbackFixtureMode,
    range_delay: std::time::Duration,
) -> (
    String,
    thread::JoinHandle<usize>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let (server, worker, accepted, _stop) =
        start_callback_fixture_stoppable(expected_requests, file_len, mode, range_delay);
    (server, worker, accepted)
}

fn start_callback_fixture_stoppable(
    expected_requests: usize,
    file_len: usize,
    mode: CallbackFixtureMode,
    range_delay: std::time::Duration,
) -> (
    String,
    thread::JoinHandle<usize>,
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<std::sync::atomic::AtomicBool>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let worker_accepted = accepted.clone();
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let worker_running = running.clone();
    let worker = thread::spawn(move || {
        let mut handled = 0;
        let mut range_reads = 0usize;
        let mut idle_polls = 0;
        while worker_running.load(std::sync::atomic::Ordering::Acquire)
            && handled < expected_requests
            && idle_polls < 1_000
        {
            let (mut stream, _) = match listener.accept() {
                Ok(value) => {
                    idle_polls = 0;
                    value
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    idle_polls += 1;
                    thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(error) => panic!("synthetic listener failed: {error}"),
            };
            stream.set_nonblocking(false).unwrap();
            let request = read_request(&mut stream);
            worker_accepted.fetch_add(1, std::sync::atomic::Ordering::Release);
            let lower = request.to_ascii_lowercase();
            let had_prior_range_read = range_reads > 0;
            let (status, headers, body, content_type, advertised_len) = if request
                .starts_with("GET /graph/")
            {
                (
                        "200 OK",
                        String::new(),
                        format!(
                            r#"{{"value":[{{"id":"drive-personal","name":"Personal","driveType":"personal","root":{{"id":"root","webDavUrl":"http://{address}/dav/personal/"}}}}]}}"#
                        )
                        .into_bytes(),
                        "application/json",
                        None,
                    )
            } else if request.starts_with("PROPFIND ") {
                let path = request.split_whitespace().nth(1).unwrap();
                let is_root = path == "/dav/personal/";
                let root_id = if is_root
                    && range_reads >= 1
                    && matches!(mode, CallbackFixtureMode::WrongRootAfterRead)
                {
                    "changed-root-id"
                } else {
                    "root-id"
                };
                let (href, item) = if is_root {
                    (
                        "/dav/personal/",
                        format!(
                            "<d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>root-etag</d:getetag><oc:fileid>{root_id}</oc:fileid>"
                        ),
                    )
                } else {
                    (
                        "/dav/personal/file.txt",
                        format!(
                            "<d:resourcetype/><d:getcontentlength>{file_len}</d:getcontentlength><d:getetag>\"revision-1\"</d:getetag><oc:fileid>file-id-1</oc:fileid>"
                        ),
                    )
                };
                let xml = format!(
                    r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>{href}</d:href><d:propstat><d:prop>{item}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#
                );
                (
                    "207 Multi-Status",
                    String::new(),
                    xml.into_bytes(),
                    "application/xml",
                    None,
                )
            } else if request.starts_with("GET /dav/personal/file.txt") {
                range_reads += 1;
                thread::sleep(range_delay);
                if had_prior_range_read
                    && matches!(
                        mode,
                        CallbackFixtureMode::UnauthorizedAfterRead
                            | CallbackFixtureMode::ForbiddenAfterRead
                    )
                {
                    let status = if matches!(mode, CallbackFixtureMode::UnauthorizedAfterRead) {
                        "401 Unauthorized"
                    } else {
                        "403 Forbidden"
                    };
                    (
                        status,
                        String::new(),
                        b"denied".to_vec(),
                        "text/plain",
                        None,
                    )
                } else {
                    let range = lower
                        .lines()
                        .find_map(|line| line.strip_prefix("range: bytes="))
                        .expect("conditional range header")
                        .trim();
                    let (start, end) = range.split_once('-').unwrap();
                    let start = start.parse::<usize>().unwrap();
                    let end = end.parse::<usize>().unwrap();
                    assert!(end >= start && end < file_len);
                    assert!(lower.contains("if-match: \"revision-1\""));
                    let expected_len = end - start + 1;
                    let mut body = (start..=end)
                        .map(|offset| (offset % 251) as u8)
                        .collect::<Vec<_>>();
                    let etag = if matches!(mode, CallbackFixtureMode::WrongRangeEtag)
                        || (had_prior_range_read
                            && matches!(mode, CallbackFixtureMode::EtagChangesAfterRead))
                    {
                        "\"other-revision\""
                    } else {
                        "\"revision-1\""
                    };
                    let advertised = if matches!(mode, CallbackFixtureMode::ShortBody) {
                        body.pop();
                        Some(expected_len)
                    } else {
                        None
                    };
                    (
                        "206 Partial Content",
                        format!(
                            "ETag: {etag}\r\nContent-Range: bytes {start}-{end}/{file_len}\r\nAccept-Ranges: bytes\r\n"
                        ),
                        body,
                        "application/octet-stream",
                        advertised,
                    )
                }
            } else {
                panic!("unexpected synthetic request: {request}");
            };
            let length = advertised_len.unwrap_or(body.len());
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {length}\r\nContent-Type: {content_type}\r\n{headers}Connection: close\r\n\r\n"
            );
            let _ = stream.write_all(&body);
            handled += 1;
        }
        handled
    });
    (format!("http://{address}"), worker, accepted, running)
}

fn start_fixture(
    expected_requests: usize,
    corrupt_range: bool,
    encrypted_after_read: bool,
    encrypted_root_after_read: bool,
    delay_from_request: Option<usize>,
    response_delay: std::time::Duration,
) -> (
    String,
    thread::JoinHandle<usize>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let worker_accepted = accepted.clone();
    let worker = thread::spawn(move || {
        let mut handled = 0;
        let mut range_read_seen = false;
        let mut idle_polls = 0;
        while handled < expected_requests && idle_polls < 1_000 {
            let (mut stream, _) = match listener.accept() {
                Ok(value) => {
                    idle_polls = 0;
                    value
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    idle_polls += 1;
                    thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(error) => panic!("synthetic listener failed: {error}"),
            };
            // Windows accepted sockets inherit the listener's nonblocking
            // mode; the fixture reads a complete bounded request below.
            stream
                .set_nonblocking(false)
                .expect("fixture stream should be blocking");
            let request = read_request(&mut stream);
            worker_accepted.fetch_add(1, std::sync::atomic::Ordering::Release);
            if delay_from_request.is_some_and(|first| handled + 1 >= first) {
                thread::sleep(response_delay);
            }
            let lower = request.to_ascii_lowercase();
            let (status, headers, body, content_type) = if request.starts_with("GET /graph/") {
                (
                    "200 OK",
                    String::new(),
                    format!(
                        r#"{{"value":[{{"id":"drive-personal","name":"Personal","driveType":"personal","root":{{"id":"root","webDavUrl":"http://{address}/dav/personal/"}}}}]}}"#
                    ),
                    "application/json",
                )
            } else if request.starts_with("PROPFIND ") {
                let path = request.split_whitespace().nth(1).unwrap();
                let href = if path == "/dav/personal/" {
                    "/dav/personal/"
                } else {
                    "/dav/personal/file.txt"
                };
                let is_root = path == "/dav/personal/";
                let encrypted_marker = if encrypted_after_read && range_read_seen && !is_root {
                    "<lg:encrypted>true</lg:encrypted>"
                } else {
                    ""
                };
                let root_encrypted_marker =
                    if encrypted_root_after_read && range_read_seen && is_root {
                        "<lg:encrypted>true</lg:encrypted>"
                    } else {
                        ""
                    };
                let xml = if is_root {
                    format!(
                        r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:lg="http://graph.opencloud.eu/ns"><d:response><d:href>{href}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>root-etag</d:getetag><oc:fileid>root-id</oc:fileid>{root_encrypted_marker}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#
                    )
                } else {
                    format!(
                        r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:lg="http://graph.opencloud.eu/ns"><d:response><d:href>{href}</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>10</d:getcontentlength><d:getetag>"revision-1"</d:getetag><oc:fileid>file-id-1</oc:fileid>{encrypted_marker}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#
                    )
                };
                ("207 Multi-Status", String::new(), xml, "application/xml")
            } else if request.starts_with("GET /dav/personal/file.txt") {
                range_read_seen = true;
                assert!(lower.contains("range: bytes=2-9"), "request: {request}");
                assert!(lower.contains("if-match: \"revision-1\""));
                let body = &FILE_BODY[RANGE_START..=RANGE_END];
                let content_range = if corrupt_range {
                    "bytes 0-3/10"
                } else {
                    "bytes 2-9/10"
                };
                (
                    "206 Partial Content",
                    format!(
                        "ETag: \"revision-1\"\r\nContent-Range: {content_range}\r\nAccept-Ranges: bytes\r\n"
                    ),
                    String::from_utf8(body.to_vec()).unwrap(),
                    "application/octet-stream",
                )
            } else {
                panic!("unexpected synthetic request: {request}");
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\n{headers}Connection: close\r\n\r\n{body}",
                body.len()
            );
            handled += 1;
        }
        handled
    });
    (format!("http://{address}"), worker, accepted)
}

fn read_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut byte = [0; 1];
    while !request.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).unwrap();
        request.push(byte[0]);
        assert!(request.len() <= 32 * 1024, "request headers are bounded");
    }
    let headers = String::from_utf8(request).unwrap();
    let body_len = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    assert!(body_len <= 32 * 1024, "request body is bounded");
    let mut body = vec![0; body_len];
    stream.read_exact(&mut body).unwrap();
    headers
}

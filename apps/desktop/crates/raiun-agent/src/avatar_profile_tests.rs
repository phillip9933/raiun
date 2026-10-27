#[test]
fn stale_avatar_completion_is_rejected_after_profile_generation_changes() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
        time::Duration,
    };

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = !0u32;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & (0u32.wrapping_sub(crc & 1)));
            }
        }
        !crc
    }

    fn append_chunk(bytes: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
        bytes.extend_from_slice(kind);
        bytes.extend_from_slice(data);
        let start = bytes.len() - data.len() - 4;
        bytes.extend_from_slice(&crc32(&bytes[start..]).to_be_bytes());
    }

    fn valid_synthetic_png() -> Vec<u8> {
        let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
        let mut header = Vec::new();
        header.extend_from_slice(&1u32.to_be_bytes());
        header.extend_from_slice(&1u32.to_be_bytes());
        header.extend_from_slice(&[8, 2, 0, 0, 0]);
        append_chunk(&mut bytes, b"IHDR", &header);
        append_chunk(&mut bytes, b"IDAT", b"synthetic-test-data");
        append_chunk(&mut bytes, b"IEND", &[]);
        bytes
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_address = listener.local_addr().unwrap();
    let (request_seen_tx, request_seen_rx) = mpsc::channel();
    let (release_response_tx, release_response_rx) = mpsc::channel();
    let image_bytes = valid_synthetic_png();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            assert!(request.len() < 16 * 1024);
        }
        request_seen_tx.send(request).unwrap();
        release_response_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("test releases the held synthetic response");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: image/png\r\nConnection: close\r\n\r\n",
            image_bytes.len()
        )
        .unwrap();
        stream.write_all(&image_bytes).unwrap();
    });

    let temp = tempdir().unwrap();
    let (manager, _) = removal_fixture(temp.path(), false);
    let runtime = manager
        .state
        .lock()
        .unwrap()
        .runtimes
        .get(DEFAULT_ID)
        .unwrap()
        .clone();
    let client = raiun_opencloud::OpenCloudClient::new(
        &format!("http://{server_address}"),
        "synthetic-avatar-session-token".to_owned(),
    )
    .unwrap();
    runtime.auth_state.lock().unwrap().client = Some(client);
    runtime.restoring.store(false, Ordering::Release);

    let request_manager = manager.clone();
    let request = thread::spawn(move || {
        request_manager.handle(serde_json::json!({
            "action": "account_avatar",
            "profile_id": DEFAULT_ID,
            "expected_auth_generation": 0
        }))
    });

    let request_bytes = request_seen_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("avatar request reached the synthetic Graph endpoint");
    let request_text = String::from_utf8(request_bytes)
        .unwrap()
        .to_ascii_lowercase();
    assert!(request_text.starts_with("get /graph/v1.0/me/photo/$value http/1.1\r\n"));
    assert!(request_text.contains("authorization: bearer synthetic-avatar-session-token\r\n"));

    // Model account replacement/revocation while the old request is in flight.
    // The request owns only a clone of the synthetic client; no OS session store
    // or live profile is consulted by this fixture.
    runtime.auth_generation.fetch_add(1, Ordering::AcqRel);
    runtime.auth_state.lock().unwrap().client = None;
    release_response_tx.send(()).unwrap();

    let error = request
        .join()
        .unwrap()
        .expect_err("stale avatar must be refused");
    assert_eq!(error, "The account changed while loading its photo");
    server.join().unwrap();
}

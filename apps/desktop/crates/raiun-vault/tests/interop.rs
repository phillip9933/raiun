use base64::Engine as _;
use raiun_vault::VaultCipher;
use std::{fs, io::Cursor};

fn pattern(size: usize) -> Vec<u8> {
    (0..size).map(|index| (index * 31 + 7) as u8).collect()
}

fn make_cipher(password: &str) -> VaultCipher {
    let mut password = password.as_bytes().to_vec();
    let result = VaultCipher::from_password(&mut password);
    assert!(password.iter().all(|byte| *byte == 0));
    result.unwrap()
}

fn hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("invalid hex fixture"),
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

#[test]
fn derives_the_opencloud_web_key_and_verifies_web_token() {
    let cipher = make_cipher("potato");
    let token = include_str!("fixtures/web-integrity-token.b64").trim();
    assert!(cipher.verify_integrity_token(token));
    assert!(!cipher.verify_integrity_token("not-base64"));
    assert!(!cipher.verify_integrity_token(""));
}

#[test]
fn published_android_key_bundle_becomes_verified_session_only_with_uuid_token() {
    let material = hex(concat!(
        "7455c71ab17c865b8471f47b79acb07eb31d5678b80c7e2eaf4fc8066a9ee468",
        "765da27ab15d77f95796711f7b93ad63bbb484072e7180a8d17a9bbec14270d0",
        "c18d5932f55b2828c5e1e87215520310",
    ));
    assert_eq!(material.len(), 80);
    let raw = VaultCipher::from_key_material(&material).unwrap();
    let token = include_str!("fixtures/web-integrity-token.b64").trim();
    let session = raw.verify_and_unlock(token).unwrap();
    let path = session
        .decrypt_path("um9jr7t436jbmsgpub5sfni4qk/ap8un5letkkhetgjpn9528qi4c")
        .unwrap();
    assert_eq!(
        path.components().collect::<Vec<_>>(),
        ["folder", "école.txt"]
    );

    let wrong = VaultCipher::from_key_material(&material).unwrap();
    assert!(wrong.verify_and_unlock("not a valid token").is_err());
    let header_only =
        base64::engine::general_purpose::STANDARD.encode(include_bytes!("fixtures/web-0.bin"));
    let header_only_cipher = VaultCipher::from_key_material(&material).unwrap();
    assert!(header_only_cipher.verify_and_unlock(&header_only).is_err());
}

#[test]
fn rejects_and_clears_invalid_utf8_password_input() {
    let mut password = vec![0xff, 0x80];
    assert!(VaultCipher::from_password(&mut password).is_err());
    assert_eq!(password, [0, 0]);
}

#[test]
fn decrypts_web_and_official_rclone_files_across_block_boundaries() {
    let cipher = make_cipher("potato");
    for size in [0, 1, 65_535, 65_536, 65_537] {
        for encrypted in [
            match size {
                0 => include_bytes!("fixtures/web-0.bin").as_slice(),
                1 => include_bytes!("fixtures/web-1.bin").as_slice(),
                65_535 => include_bytes!("fixtures/web-65535.bin").as_slice(),
                65_536 => include_bytes!("fixtures/web-65536.bin").as_slice(),
                _ => include_bytes!("fixtures/web-65537.bin").as_slice(),
            },
            match size {
                0 => include_bytes!("fixtures/rclone-0.bin").as_slice(),
                1 => include_bytes!("fixtures/rclone-1.bin").as_slice(),
                65_535 => include_bytes!("fixtures/rclone-65535.bin").as_slice(),
                65_536 => include_bytes!("fixtures/rclone-65536.bin").as_slice(),
                _ => include_bytes!("fixtures/rclone-65537.bin").as_slice(),
            },
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("plain.bin");
            let count = cipher
                .decrypt_file_transactional(
                    &mut Cursor::new(encrypted),
                    &path,
                    size as u64,
                    Some(size as u64),
                )
                .unwrap();
            assert_eq!(count, size as u64);
            assert_eq!(fs::read(path).unwrap(), pattern(size));
        }
    }
}

#[test]
fn decodes_web_and_rclone_unicode_paths() {
    let cipher = make_cipher("potato");
    let web_names = [
        ("1", "9cmn80lns8obm4t3koceogil20"),
        ("123456789012345", "39pfuflp0u10iqi88m20aq3i28"),
        (
            "1234567890123456",
            "9qg6n1iouahpupqlekm1k6sa5psf32kr83f3vv36c5kqrhij022g",
        ),
        (
            "12345678901234567",
            "q954vaqdql2tkn1g9g546an1oo9npnm6m8vk4ausf4cq5i364jig",
        ),
        ("写真🗃️", "m9t62nq5a92ncslf90dorqurss"),
    ];
    for (plain, encrypted) in web_names {
        assert_eq!(cipher.decrypt_name(encrypted).unwrap(), plain);
    }
    assert_eq!(
        cipher
            .decrypt_path("um9jr7t436jbmsgpub5sfni4qk/ap8un5letkkhetgjpn9528qi4c")
            .unwrap(),
        "folder/école.txt",
    );
    assert_eq!(
        cipher
            .decrypt_path(
                "f5qevq76he1rhpr8cjg4vbit6k/1sjbdv65fk0ih90u44je3u9oo548bi5ppg9q023n6aklqemohseg"
            )
            .unwrap(),
        "interop/写真🗃️-65537.bin",
    );
    assert_eq!(cipher.decrypt_path("").unwrap(), "");
}

#[test]
fn refuses_wrong_keys_tampering_unsafe_names_and_length_mismatch_without_publish() {
    let cipher = make_cipher("potato");
    let wrong = make_cipher("wrong password");
    let mut ciphertext = include_bytes!("fixtures/web-65537.bin").to_vec();
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("plain.bin");

    assert!(
        wrong
            .decrypt_file_transactional(
                &mut Cursor::new(&ciphertext),
                &target,
                65_537,
                Some(65_537)
            )
            .is_err()
    );
    assert!(!target.exists());

    *ciphertext.last_mut().unwrap() ^= 1;
    assert!(
        cipher
            .decrypt_file_transactional(
                &mut Cursor::new(&ciphertext),
                &target,
                65_537,
                Some(65_537)
            )
            .is_err()
    );
    assert!(!target.exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);

    let mut valid = include_bytes!("fixtures/web-1.bin").as_slice();
    assert!(
        cipher
            .decrypt_file_transactional(&mut valid, &target, 1, Some(2))
            .is_err()
    );
    assert!(!target.exists());

    for unsafe_name in ["..", "a/", "a//b", "/etc/passwd", "a\\b"] {
        assert!(cipher.decrypt_path(unsafe_name).is_err());
    }
    for invalid_name in [
        "!",
        "p0e52nreeaj0a5ea7s64m4j72s=",
        "00000000000000000000000000",
    ] {
        assert!(cipher.decrypt_name(invalid_name).is_err());
    }
}

#[test]
fn no_clobber_preserves_existing_destination_and_removes_stage_file() {
    let cipher = make_cipher("potato");
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("existing.bin");
    fs::write(&destination, b"keep me").unwrap();
    let mut encrypted = include_bytes!("fixtures/web-1.bin").as_slice();

    assert!(
        cipher
            .decrypt_file_transactional(&mut encrypted, &destination, 1, Some(1))
            .is_err()
    );
    assert_eq!(fs::read(&destination).unwrap(), b"keep me");
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn rejects_corrupt_header_and_plaintext_limit_without_publishing() {
    let cipher = make_cipher("potato");
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("plain.bin");
    let mut corrupt = include_bytes!("fixtures/web-1.bin").to_vec();
    corrupt[0] ^= 1;
    assert!(
        cipher
            .decrypt_file_transactional(&mut Cursor::new(corrupt), &destination, 1, Some(1))
            .is_err()
    );
    assert!(!destination.exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);

    let mut encrypted = include_bytes!("fixtures/web-1.bin").as_slice();
    assert!(
        cipher
            .decrypt_file_transactional(&mut encrypted, &destination, 0, None)
            .is_err()
    );
    assert!(!destination.exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn trusted_length_detects_truncation_at_a_full_block_boundary() {
    let cipher = make_cipher("potato");
    let complete = include_bytes!("fixtures/web-65537.bin").as_slice();
    let truncated = &complete[..32 + 65_536 + 16];
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("truncated.bin");

    assert!(
        cipher
            .decrypt_file_transactional(
                &mut Cursor::new(truncated),
                &destination,
                65_537,
                Some(65_537)
            )
            .is_err()
    );
    assert!(!destination.exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);

    // Without trusted length metadata, the boundary truncation is a valid
    // shorter rclone object. Integrations must pass the trusted length when one exists.
    let short_destination = directory.path().join("short.bin");
    assert_eq!(
        cipher
            .decrypt_file_transactional(
                &mut Cursor::new(truncated),
                &short_destination,
                65_536,
                None,
            )
            .unwrap(),
        65_536,
    );
    assert_eq!(fs::read(short_destination).unwrap(), pattern(65_536));
}

#[test]
fn header_only_empty_file_is_not_password_proof() {
    let wrong = make_cipher("wrong password");
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("empty.bin");
    let mut header_only = include_bytes!("fixtures/web-0.bin").as_slice();

    assert_eq!(
        wrong
            .decrypt_file_transactional(&mut header_only, &destination, 0, Some(0))
            .unwrap(),
        0,
    );
    assert!(fs::read(destination).unwrap().is_empty());
    let token = include_str!("fixtures/web-integrity-token.b64").trim();
    assert!(!wrong.verify_integrity_token(token));
}

#[test]
fn retries_interrupted_and_short_reads() {
    struct Fragmented<'a> {
        remaining: &'a [u8],
        consumed: usize,
        interrupt_at: usize,
        interrupted: bool,
    }

    impl std::io::Read for Fragmented<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted && self.consumed == self.interrupt_at {
                self.interrupted = true;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            if self.remaining.is_empty() {
                return Ok(0);
            }
            let count = output.len().min(self.remaining.len()).min(17);
            output[..count].copy_from_slice(&self.remaining[..count]);
            self.remaining = &self.remaining[count..];
            self.consumed += count;
            Ok(count)
        }
    }

    let cipher = make_cipher("potato");
    let bytes = include_bytes!("fixtures/web-65537.bin");
    let directory = tempfile::tempdir().unwrap();
    for (index, interrupt_at) in [0, 32].into_iter().enumerate() {
        let mut input = Fragmented {
            remaining: bytes,
            consumed: 0,
            interrupt_at,
            interrupted: false,
        };
        let destination = directory.path().join(format!("fragmented-{index}.bin"));
        assert_eq!(
            cipher
                .decrypt_file_transactional(&mut input, &destination, 65_537, Some(65_537))
                .unwrap(),
            65_537,
        );
        assert_eq!(fs::read(destination).unwrap(), pattern(65_537));
    }
}

#[test]
#[cfg(unix)]
fn published_plaintext_file_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let cipher = make_cipher("potato");
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("plain.bin");
    let mut encrypted = include_bytes!("fixtures/web-1.bin").as_slice();
    cipher
        .decrypt_file_transactional(&mut encrypted, &destination, 1, Some(1))
        .unwrap();
    assert_eq!(
        fs::metadata(destination).unwrap().permissions().mode() & 0o777,
        0o600,
    );
}

#[test]
fn bounds_and_clears_password_buffer() {
    let mut oversized = vec![b'x'; 4_097];
    assert!(VaultCipher::from_password(&mut oversized).is_err());
    assert!(oversized.iter().all(|byte| *byte == 0));
}

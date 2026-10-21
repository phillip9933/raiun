use raiun_vault::VaultCipher;
use std::{
    fs,
    io::{self, Cursor, Read},
};
use tempfile::tempdir;

fn verified() -> raiun_vault::VerifiedVaultSession {
    let mut password = b"potato".to_vec();
    let cipher = VaultCipher::from_password(&mut password).unwrap();
    assert!(password.iter().all(|byte| *byte == 0));
    cipher
        .verify_and_unlock(include_str!("fixtures/web-integrity-token.b64").trim())
        .unwrap()
}

fn pattern(size: usize) -> Vec<u8> {
    (0..size).map(|index| (index * 31 + 7) as u8).collect()
}

#[test]
fn initializes_new_vault_with_random_valid_uuid_token() {
    let mut password = b"potato".to_vec();
    let cipher = VaultCipher::from_password(&mut password).unwrap();
    let first_draft = cipher.initialize_new_vault().unwrap();
    let first = first_draft.integrity_token().to_owned();
    let session = first_draft.verify_created_root(&first).unwrap();
    assert!(session.encrypt_name("created-after-readback").is_ok());

    let mut password = b"potato".to_vec();
    let second_draft = VaultCipher::from_password(&mut password)
        .unwrap()
        .initialize_new_vault()
        .unwrap();
    let second = second_draft.integrity_token().to_owned();
    assert_ne!(first, second);
    assert!(
        second_draft
            .verify_created_root("different readback")
            .is_err()
    );
    let mut password = b"potato".to_vec();
    assert!(
        VaultCipher::from_password(&mut password)
            .unwrap()
            .verify_integrity_token(&first)
    );
}

#[test]
fn random_file_encryption_roundtrips_web_and_rclone_sizes() {
    let session = verified();
    for size in [0, 1, 65_535, 65_536, 65_537] {
        let directory = tempdir().unwrap();
        let encrypted_path = directory.path().join("encrypted.bin");
        let plaintext = pattern(size);
        assert_eq!(
            session
                .encrypt_file_transactional(
                    &mut Cursor::new(&plaintext),
                    &encrypted_path,
                    size as u64,
                    size as u64,
                )
                .unwrap(),
            size as u64
        );
        let encrypted = fs::read(&encrypted_path).unwrap();
        assert_eq!(&encrypted[..8], b"RCLONE\0\0");
        assert_eq!(encrypted.len(), 32 + size + 16 * size.div_ceil(65_536));
        let decrypted_path = directory.path().join("decrypted.bin");
        assert_eq!(
            session
                .decrypt_file_transactional(
                    &mut Cursor::new(&encrypted),
                    &decrypted_path,
                    size as u64,
                    Some(size as u64),
                )
                .unwrap(),
            size as u64
        );
        assert_eq!(fs::read(decrypted_path).unwrap(), plaintext);
    }
}

#[test]
fn each_file_uses_a_fresh_random_nonce() {
    let session = verified();
    let directory = tempdir().unwrap();
    let first = directory.path().join("first");
    let second = directory.path().join("second");
    let plaintext = b"same data";
    for path in [&first, &second] {
        session
            .encrypt_file_transactional(
                &mut Cursor::new(plaintext),
                path,
                plaintext.len() as u64,
                100,
            )
            .unwrap();
    }
    let first = fs::read(first).unwrap();
    let second = fs::read(second).unwrap();
    assert_eq!(&first[..8], &second[..8]);
    assert_ne!(&first[8..32], &second[8..32]);
    assert_ne!(first, second);
}

#[test]
fn exact_size_mismatch_limit_and_no_clobber_leave_no_partial_file() {
    let session = verified();
    let directory = tempdir().unwrap();
    let destination = directory.path().join("encrypted.bin");

    assert!(
        session
            .encrypt_file_transactional(&mut Cursor::new(b"short"), &destination, 6, 10)
            .is_err()
    );
    assert!(!destination.exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);

    assert!(
        session
            .encrypt_file_transactional(&mut Cursor::new(b"too long"), &destination, 3, 10)
            .is_err()
    );
    assert!(!destination.exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);

    assert!(
        session
            .encrypt_file_transactional(&mut Cursor::new(b"large"), &destination, 5, 4)
            .is_err()
    );
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);

    fs::write(&destination, b"existing ciphertext").unwrap();
    assert!(
        session
            .encrypt_file_transactional(&mut Cursor::new(b"new"), &destination, 3, 3)
            .is_err()
    );
    assert_eq!(fs::read(&destination).unwrap(), b"existing ciphertext");
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn short_reads_and_interrupted_reads_are_supported() {
    struct Choppy<'a> {
        bytes: &'a [u8],
        offset: usize,
        interrupt: bool,
    }
    impl Read for Choppy<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.interrupt {
                self.interrupt = false;
                return Err(io::ErrorKind::Interrupted.into());
            }
            if self.offset == self.bytes.len() {
                return Ok(0);
            }
            self.interrupt = true;
            let count = buffer.len().min(3).min(self.bytes.len() - self.offset);
            buffer[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            Ok(count)
        }
    }
    let session = verified();
    let directory = tempdir().unwrap();
    let destination = directory.path().join("encrypted.bin");
    let source = b"bounded short-read source";
    let mut input = Choppy {
        bytes: source,
        offset: 0,
        interrupt: true,
    };
    session
        .encrypt_file_transactional(&mut input, &destination, source.len() as u64, 100)
        .unwrap();
    let ciphertext = fs::read(destination).unwrap();
    let decrypted = directory.path().join("decrypted.bin");
    session
        .decrypt_file_transactional(
            &mut Cursor::new(ciphertext),
            &decrypted,
            100,
            Some(source.len() as u64),
        )
        .unwrap();
    assert_eq!(fs::read(decrypted).unwrap(), source);
}

#[test]
fn encrypted_output_is_private_on_unix() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let session = verified();
        let directory = tempdir().unwrap();
        let destination = directory.path().join("encrypted.bin");
        session
            .encrypt_file_transactional(&mut Cursor::new(b"secret"), &destination, 6, 6)
            .unwrap();
        assert_eq!(
            fs::metadata(destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

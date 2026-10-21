use super::*;
use std::io::{Cursor, Read};

fn cache() -> (tempfile::TempDir, Cache) {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    set_private_dir(temp.path()).unwrap();
    let cache = Cache::open(temp.path(), 1024).unwrap();
    (temp, cache)
}

fn scope(protection: ScopeProtection) -> CacheScope {
    CacheScope::new(
        "https://retry-admission.example.test/",
        "retry-account",
        "retry-space",
        "retry-root",
        protection,
    )
    .unwrap()
}

#[test]
fn copy_file_journal_stays_out_of_generic_retry_across_restart() {
    let (temp, cache) = cache();
    let target = scope(ScopeProtection::CiphertextOnly);
    let build = cache
        .begin_ciphertext_operation_with_state_and_parent(
            &target,
            None,
            "enc-parent/enc-copy",
            Some("enc-parent"),
            5,
            CiphertextWriteOperation::CopyFile,
            CiphertextWriteState::NeverAttempted,
        )
        .unwrap();
    let row = cache
        .publish_ciphertext_write(&target, &build, &mut Cursor::new(b"copy!"), 5)
        .unwrap();
    assert_eq!(row.operation, CiphertextWriteOperation::CopyFile);

    drop(cache);
    let reopened = Cache::open(temp.path(), 1024).unwrap();
    let persisted = reopened.ciphertext_write_info(&target, &row.id).unwrap();
    assert_eq!(persisted.operation, CiphertextWriteOperation::CopyFile);
    assert_eq!(persisted.state, CiphertextWriteState::NeverAttempted);
    assert!(
        reopened
            .retryable_ciphertext_writes(&target, 10)
            .unwrap()
            .0
            .is_empty()
    );
    assert!(!reopened.has_retryable_ciphertext_writes(&target).unwrap());
    assert!(matches!(
        reopened.claim_ciphertext_file_create_attempt(&target, &row.id, row.revision),
        Err(CacheError::Conflict)
    ));
    reopened
        .claim_ciphertext_copy_attempt(&target, &row.id, row.revision)
        .unwrap();
    assert_eq!(
        reopened
            .ciphertext_write_info(&target, &row.id)
            .unwrap()
            .state,
        CiphertextWriteState::Attempting
    );
    assert!(
        reopened
            .retryable_ciphertext_writes(&target, 10)
            .unwrap()
            .0
            .is_empty()
    );
}

#[test]
fn generic_ciphertext_retry_excludes_unknown_operation_classes_after_restart() {
    let (temp, cache) = cache();
    let target = scope(ScopeProtection::CiphertextOnly);
    let build = cache
        .begin_ciphertext_operation_with_state_and_parent(
            &target,
            None,
            "enc-parent/enc-future-transfer",
            Some("enc-parent"),
            5,
            CiphertextWriteOperation::CopyFile,
            CiphertextWriteState::NeverAttempted,
        )
        .unwrap();
    let row = cache
        .publish_ciphertext_write(&target, &build, &mut Cursor::new(b"saved"), 5)
        .unwrap();
    drop(cache);
    let reopened = Cache::open(temp.path(), 1024).unwrap();
    // Simulate a newer operation discriminator. Older generic recovery
    // must not route it through ordinary create/delete processing.
    for operation in [6_i64, 99, -1] {
        reopened
            .lock_db()
            .unwrap()
            .execute(
                "UPDATE ciphertext_writes SET operation=?3 WHERE scope_key=?1 AND write_id=?2",
                params![target.key, row.id, operation],
            )
            .unwrap();
        assert!(
            reopened
                .retryable_ciphertext_writes(&target, 10)
                .unwrap()
                .0
                .is_empty()
        );
        assert!(!reopened.has_retryable_ciphertext_writes(&target).unwrap());
        assert!(matches!(
            reopened.ciphertext_write_info(&target, &row.id),
            Err(CacheError::Corrupt)
        ));
    }
    // A known ordinary operation in the same durable row remains visible;
    // the empty results above are due to the allowlist, not lost content.
    reopened
        .lock_db()
        .unwrap()
        .execute(
            "UPDATE ciphertext_writes SET operation=?3,state=?4 WHERE scope_key=?1 AND write_id=?2",
            params![
                target.key,
                row.id,
                CiphertextWriteOperation::Overwrite as i64,
                CiphertextWriteState::Pending as i64
            ],
        )
        .unwrap();
    assert!(reopened.has_retryable_ciphertext_writes(&target).unwrap());
    assert_eq!(
        reopened
            .retryable_ciphertext_writes(&target, 10)
            .unwrap()
            .0
            .len(),
        1
    );
    let mut content = reopened
        .open_ciphertext_write(&target, &row.id, row.revision)
        .unwrap();
    let mut bytes = Vec::new();
    content.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"saved");
}

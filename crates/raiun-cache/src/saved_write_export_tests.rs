// Included from the cache crate's existing Unix test module so these tests
// share its private synthetic cache/scope/listing helpers.

#[derive(Default)]
struct SavedWriteExportStage {
    bytes: Vec<u8>,
    published: Option<Vec<u8>>,
}

impl std::io::Write for SavedWriteExportStage {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct FailingSavedWriteExportStage {
    bytes: Vec<u8>,
    published: Option<Vec<u8>>,
}

impl std::io::Write for FailingSavedWriteExportStage {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len() >= 3 {
            return Err(std::io::Error::other("synthetic staging failure"));
        }
        let accepted = bytes.len().min(3 - self.bytes.len());
        self.bytes.extend_from_slice(&bytes[..accepted]);
        Ok(accepted)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn saved_write_export_request(path: &str, name: &str, bytes: &[u8]) -> ConditionalWriteRequest {
    ConditionalWriteRequest {
        parent_resource_id: "root-a".into(),
        name: name.into(),
        logical_path: path.into(),
        resource_id: Some("file-a".into()),
        base: WriteCondition::Match("base-etag".into()),
        expected_len: bytes.len() as u64,
        protection: ContentProtection::Plaintext,
    }
}

fn queue_saved_write_export_fixture(
    cache: &Cache,
    scope: &CacheScope,
    path: &str,
    name: &str,
    bytes: &[u8],
) -> QueuedWrite {
    cache
        .publish_listing(
            scope,
            "root-a",
            &[entry(
                "file-a",
                name,
                path,
                "base-etag",
                bytes.len() as u64,
                false,
            )],
            1,
        )
        .unwrap();
    cache
        .queue_conditional_write(
            scope,
            saved_write_export_request(path, name, bytes),
            &mut Cursor::new(bytes),
        )
        .unwrap()
}

fn cached_saved_write_bytes(cache: &Cache, scope: &CacheScope, write: &QueuedWrite) -> Vec<u8> {
    let mut bytes = Vec::new();
    cache
        .open_content(scope, &write.content)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    bytes
}

#[test]
fn pending_saved_write_exports_exact_bytes_after_listing_invalidation_without_retiring_it() {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    let dirty = b"retained synthetic edit";
    let write =
        queue_saved_write_export_fixture(&cache, &scope, "/folder/file.txt", "file.txt", dirty);
    let content_before = cache.content_record(&scope, &write.content).unwrap();
    let journal_before = cache.pending_writes(&scope).unwrap();
    assert_eq!(journal_before, vec![write.clone()]);

    // Mutation invalidation deliberately removes the ordinary listing; the
    // separate retained write must remain recoverable without restoring it.
    cache
        .invalidate_paths(&scope, &["/folder/file.txt"])
        .unwrap();
    assert!(matches!(
        cache.listing(&scope, "root-a"),
        Err(CacheError::IncompleteListing)
    ));

    let mut stage = SavedWriteExportStage::default();
    let copied = cache
        .copy_saved_write(&scope, write.id, &mut stage)
        .unwrap();
    stage.published = Some(stage.bytes.clone());
    assert_eq!(stage.published.as_deref(), Some(dirty.as_slice()));
    assert_eq!(copied.write_id, write.id);
    assert_eq!(copied.path, "/folder/file.txt");
    assert_eq!(copied.state, WriteState::Pending);
    assert_eq!(copied.bytes, dirty.len() as u64);
    assert_eq!(cache.pending_writes(&scope).unwrap(), journal_before);
    assert_eq!(
        cache.content_record(&scope, &write.content).unwrap(),
        content_before
    );
    assert_eq!(cached_saved_write_bytes(&cache, &scope, &write), dirty);
}

#[test]
fn saved_write_export_rejects_wrong_origin_account_space_root_and_missing_id() {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    let dirty = b"same-path scoped edit";
    let write = queue_saved_write_export_fixture(&cache, &scope, "/same.txt", "same.txt", dirty);
    let journal_before = cache.pending_writes(&scope).unwrap();
    let content_before = cache.content_record(&scope, &write.content).unwrap();

    let wrong_scopes = [
        CacheScope::new(
            "https://other.example.test/",
            "account-a",
            "space-a",
            "root-a",
            ScopeProtection::PlaintextAllowed,
        )
        .unwrap(),
        CacheScope::new(
            "https://cloud.example.test/",
            "other-account",
            "space-a",
            "root-a",
            ScopeProtection::PlaintextAllowed,
        )
        .unwrap(),
        CacheScope::new(
            "https://cloud.example.test/",
            "account-a",
            "other-space",
            "root-a",
            ScopeProtection::PlaintextAllowed,
        )
        .unwrap(),
        CacheScope::new(
            "https://cloud.example.test/",
            "account-a",
            "space-a",
            "other-root",
            ScopeProtection::PlaintextAllowed,
        )
        .unwrap(),
    ];
    for wrong_scope in &wrong_scopes {
        let mut stage = SavedWriteExportStage::default();
        let result = cache.copy_saved_write(wrong_scope, write.id, &mut stage);
        assert_eq!(result, Err(CacheError::NotFound));
        assert!(
            stage.published.is_none(),
            "failed copy must never publish staged bytes"
        );
    }

    let mut stage = SavedWriteExportStage::default();
    assert_eq!(
        cache.copy_saved_write(&scope, write.id.saturating_add(10_000), &mut stage),
        Err(CacheError::NotFound)
    );
    assert!(stage.published.is_none());
    assert_eq!(cache.pending_writes(&scope).unwrap(), journal_before);
    assert_eq!(
        cache.content_record(&scope, &write.content).unwrap(),
        content_before
    );
    assert_eq!(cached_saved_write_bytes(&cache, &scope, &write), dirty);
}

#[test]
fn saved_write_export_rejects_verified_nondirty_and_ciphertext_scopes() {
    let (_temp, cache) = cache();
    let plain_scope = scope(ScopeProtection::PlaintextAllowed);
    let dirty = b"state-gated edit";
    let write =
        queue_saved_write_export_fixture(&cache, &plain_scope, "/state.txt", "state.txt", dirty);

    cache.mark_write_verified(&plain_scope, write.id).unwrap();
    let mut stage = SavedWriteExportStage::default();
    assert_eq!(
        cache.copy_saved_write(&plain_scope, write.id, &mut stage),
        Err(CacheError::Conflict)
    );
    assert!(stage.published.is_none());
    assert_eq!(
        cache.pending_writes(&plain_scope).unwrap()[0].state,
        WriteState::Verified
    );
    assert_eq!(
        cached_saved_write_bytes(&cache, &plain_scope, &write),
        dirty
    );

    // A ciphertext-only scope is never a plaintext saved-write export scope.
    let ciphertext_scope = scope(ScopeProtection::CiphertextOnly);
    let mut stage = SavedWriteExportStage::default();
    assert_eq!(
        cache.copy_saved_write(&ciphertext_scope, write.id, &mut stage),
        Err(CacheError::InvalidScope)
    );
    assert!(stage.published.is_none());
}

#[test]
fn saved_write_export_rejects_nondirty_content_and_keeps_failed_output_staged() {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    let dirty = b"non-dirty retention";
    let write =
        queue_saved_write_export_fixture(&cache, &scope, "/retention.txt", "retention.txt", dirty);
    let content_before = cache.content_record(&scope, &write.content).unwrap();
    assert_eq!(content_before.retention, Retention::Dirty);
    cache
        .lock_db()
        .unwrap()
        .execute(
            "UPDATE contents SET retention=?3 WHERE scope_key=?1 AND resource_id=?2",
            params![
                scope.key,
                write.content.resource_id,
                Retention::Recent as i64
            ],
        )
        .unwrap();

    let mut stage = SavedWriteExportStage::default();
    assert_eq!(
        cache.copy_saved_write(&scope, write.id, &mut stage),
        Err(CacheError::Corrupt)
    );
    assert_eq!(stage.published, None);
    assert_eq!(
        stage.bytes, b"",
        "retention rejection occurs before plaintext is copied"
    );
    assert_eq!(cache.pending_writes(&scope).unwrap(), vec![write.clone()]);
}

#[test]
fn saved_write_export_detects_corruption_without_publishing_partial_plaintext() {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    let dirty = b"integrity checked edit";
    let write =
        queue_saved_write_export_fixture(&cache, &scope, "/integrity.txt", "integrity.txt", dirty);
    let content_before = cache.content_record(&scope, &write.content).unwrap();
    let blob = cache
        .inner
        .content_dir
        .join(format!("{}.blob", content_key(&scope, &write.content)));
    let corrupted = b"integrity checked evil";
    assert_eq!(corrupted.len(), dirty.len());
    fs::write(&blob, corrupted).unwrap();

    let mut stage = SavedWriteExportStage::default();
    assert_eq!(
        cache.copy_saved_write(&scope, write.id, &mut stage),
        Err(CacheError::Corrupt)
    );
    assert_eq!(stage.published, None);
    // The ordinary cache reader validates the complete blob before returning
    // a stream, so corrupted bytes never reach the export staging writer.
    assert!(stage.bytes.is_empty());
    assert_eq!(cache.pending_writes(&scope).unwrap(), vec![write.clone()]);
    assert_eq!(
        cache.content_record(&scope, &write.content).unwrap(),
        content_before
    );
}

#[test]
fn saved_write_export_writer_failure_never_publishes_partial_staging_bytes() {
    let (_temp, cache) = cache();
    let scope = scope(ScopeProtection::PlaintextAllowed);
    let dirty = b"staging writer failure";
    let write = queue_saved_write_export_fixture(&cache, &scope, "/stage.txt", "stage.txt", dirty);
    let journal_before = cache.pending_writes(&scope).unwrap();
    let content_before = cache.content_record(&scope, &write.content).unwrap();

    let mut stage = FailingSavedWriteExportStage::default();
    let result = cache.copy_saved_write(&scope, write.id, &mut stage);
    if result.is_ok() {
        stage.published = Some(stage.bytes.clone());
    }
    assert!(matches!(result, Err(CacheError::Io(_))));
    assert_eq!(stage.bytes, &dirty[..3]);
    assert!(stage.published.is_none());
    assert_eq!(cache.pending_writes(&scope).unwrap(), journal_before);
    assert_eq!(
        cache.content_record(&scope, &write.content).unwrap(),
        content_before
    );
    assert_eq!(cached_saved_write_bytes(&cache, &scope, &write), dirty);
}

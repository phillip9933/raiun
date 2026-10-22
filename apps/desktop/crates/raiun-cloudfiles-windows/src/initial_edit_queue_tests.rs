use super::InitialEditQueue;
use std::sync::{Arc, Mutex};

use raiun_core::backend::{CloudBackend, CloudError, ErrorKind, WriteCondition};
use raiun_opencloud::OpenCloudClient;

use crate::{
    BackendError, ConfiguredRootIdentity, DurableEditRecoveryProvider, EditJournal,
    EditJournalScope, EditRecordProtector, EditRecoveryProvider, LocalFileIdentity,
    MAX_PENDING_INITIAL_EDITS, PlaceholderEditBinding, PreparedEditRecovery, ProviderScope,
    ReconciliationOutcome, RecoveryRemote, RecoveryRemoteBody, RecoveryRemoteVersion,
};

fn private_tempdir() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    temp
}

#[derive(Clone)]
struct TestProtector;

impl EditRecordProtector for TestProtector {
    fn seal(
        &self,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, crate::JournalError> {
        let mut output = Vec::with_capacity(4 + associated_data.len() + plaintext.len());
        output.extend_from_slice(&(associated_data.len() as u32).to_le_bytes());
        output.extend_from_slice(associated_data);
        output.extend_from_slice(plaintext);
        Ok(output)
    }

    fn open(&self, associated_data: &[u8], sealed: &[u8]) -> Result<Vec<u8>, crate::JournalError> {
        if sealed.len() < 4 {
            return Err(crate::JournalError::ProtectionFailed);
        }
        let length = u32::from_le_bytes(sealed[..4].try_into().unwrap()) as usize;
        if sealed.get(4..4 + length) != Some(associated_data) {
            return Err(crate::JournalError::ProtectionFailed);
        }
        Ok(sealed[4 + length..].to_vec())
    }
}

fn fixture_scope(account: &str) -> ProviderScope {
    let client = OpenCloudClient::new("https://example.test", "fixture".into()).unwrap();
    ProviderScope::new(
        &client,
        "queue-test-profile".into(),
        account.into(),
        client.server_origin().unwrap(),
    )
    .unwrap()
}

fn root_identity() -> ConfiguredRootIdentity {
    ConfiguredRootIdentity {
        volume_serial: 17,
        file_index: 29,
    }
}

fn prepared(
    state_directory: &std::path::Path,
    scope: &ProviderScope,
) -> Arc<dyn PreparedEditRecovery> {
    let provider = DurableEditRecoveryProvider::new(
        state_directory.to_path_buf(),
        scope.clone(),
        root_identity(),
        TestProtector,
    );
    provider.prepare(scope, root_identity()).unwrap()
}

fn journal_scope(scope: &ProviderScope, space_id: &str) -> EditJournalScope {
    EditJournalScope {
        profile_id: scope.profile_id().to_owned(),
        server_origin: scope.server_origin().to_owned(),
        account_subject: scope.account_id().to_owned(),
        space_id: space_id.to_owned(),
        root_resource_id: format!("root-{space_id}"),
        root_volume_serial: root_identity().volume_serial,
        root_file_index: root_identity().file_index,
    }
}

fn append_receipt(
    recovery: &dyn PreparedEditRecovery,
    space_id: &str,
    content: &[u8],
) -> crate::InitialEditReceipt {
    let scope = recovery.provider_scope();
    let root = recovery.root_identity();
    let binding = PlaceholderEditBinding {
        profile_id: scope.profile_id().to_owned(),
        server_origin: scope.server_origin().to_owned(),
        account_subject: scope.account_id().to_owned(),
        account_generation: scope.token_generation(),
        space_id: space_id.to_owned(),
        root_resource_id: format!("root-{space_id}"),
        remote_resource_id: format!("file-{space_id}"),
        virtual_path: "/notes.txt".into(),
        base_etag: "\"v1\"".into(),
        base_size: 5,
    };
    recovery
        .append_edit_for_initial_dispatch(
            &binding,
            root,
            LocalFileIdentity {
                volume_serial: root.volume_serial,
                file_index: 55,
            },
            "notes.txt",
            content,
        )
        .unwrap()
        .expect("durable provider returns a receipt for a published edit")
}

fn read_records(state_directory: &std::path::Path, scope: EditJournalScope) -> Vec<Vec<u8>> {
    EditJournal::open(state_directory, scope, TestProtector)
        .unwrap()
        .recover_all()
        .unwrap()
        .records
        .into_iter()
        .map(|record| record.content.clone())
        .collect()
}

struct RevokedRemote {
    authorization_checks: Mutex<usize>,
}

impl RecoveryRemote for RevokedRemote {
    fn server_origin(&self) -> Option<&str> {
        Some("https://example.test")
    }

    fn ensure_authorized(&self, _: &EditJournalScope) -> Result<(), CloudError> {
        *self.authorization_checks.lock().unwrap() += 1;
        Err(CloudError::new(ErrorKind::Unauthorized, "fixture revoked"))
    }

    fn stat(&self, _: &EditJournalScope, _: &str) -> Result<RecoveryRemoteVersion, CloudError> {
        panic!("revoked remote must not be queried")
    }

    fn conditional_upload(
        &self,
        _: &EditJournalScope,
        _: &str,
        _: &[u8],
        _: &str,
        _: WriteCondition,
        _: u64,
    ) -> Result<RecoveryRemoteVersion, CloudError> {
        panic!("revoked remote must not receive an upload")
    }

    fn readback(
        &self,
        _: &EditJournalScope,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: usize,
    ) -> Result<RecoveryRemoteBody, CloudError> {
        panic!("revoked remote must not be read back")
    }
}

#[test]
fn queue_is_fifo_and_reports_exact_provider_scope() {
    let temp = private_tempdir();
    let scope = fixture_scope("account-one");
    let recovery = prepared(temp.path(), &scope);
    let queue = InitialEditQueue::default();

    let first = append_receipt(recovery.as_ref(), "personal", b"first");
    let first_scope = first.scope().clone();
    queue.push(Arc::clone(&recovery), first).unwrap();
    let second = append_receipt(recovery.as_ref(), "spaces", b"second");
    let second_scope = second.scope().clone();
    queue.push(Arc::clone(&recovery), second).unwrap();

    let first = queue.take().unwrap().unwrap();
    assert_eq!(first.scope(), &first_scope);
    assert!(first.location().is_none());
    assert!(first.matches_provider(&scope, root_identity()));
    assert!(!first.matches_provider(&fixture_scope("other-account"), root_identity()));
    assert!(!first.matches_provider(
        &scope,
        ConfiguredRootIdentity {
            volume_serial: root_identity().volume_serial + 1,
            ..root_identity()
        }
    ));

    let second = queue.take().unwrap().unwrap();
    assert_eq!(second.scope(), &second_scope);
    assert!(second.matches_provider(&scope, root_identity()));
    assert!(queue.take().unwrap().is_none());
}

#[test]
fn overflow_drops_only_receipt_and_preserves_all_seventeen_journal_bodies() {
    let temp = private_tempdir();
    let scope = fixture_scope("account-overflow");
    let recovery = prepared(temp.path(), &scope);
    let queue = InitialEditQueue::default();
    let journal_scope = journal_scope(&scope, "personal");
    let mut expected = Vec::new();

    for index in 0..=MAX_PENDING_INITIAL_EDITS {
        let content = format!("durable-edit-{index}").into_bytes();
        let receipt = append_receipt(recovery.as_ref(), "personal", &content);
        expected.push(content);
        let result = queue.push(Arc::clone(&recovery), receipt);
        if index < MAX_PENDING_INITIAL_EDITS {
            result.unwrap();
        } else {
            assert_eq!(result, Err(BackendError::Unavailable));
        }
    }

    let mut actual = read_records(temp.path(), journal_scope);
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
    for _ in 0..MAX_PENDING_INITIAL_EDITS {
        assert!(queue.take().unwrap().is_some());
    }
    assert!(queue.take().unwrap().is_none());
}

#[test]
fn dropping_queue_preserves_records_across_provider_reopen() {
    let temp = private_tempdir();
    let scope = fixture_scope("account-drop");
    let journal_scope = journal_scope(&scope, "personal");
    let recovery = prepared(temp.path(), &scope);
    let queue = InitialEditQueue::default();
    let receipt = append_receipt(recovery.as_ref(), "personal", b"survives-queue-drop");
    queue.push(Arc::clone(&recovery), receipt).unwrap();
    drop(queue);
    drop(recovery);

    let reopened = prepared(temp.path(), &scope);
    assert_eq!(
        read_records(temp.path(), journal_scope),
        [b"survives-queue-drop".to_vec()]
    );
    let remote = RevokedRemote {
        authorization_checks: Mutex::new(0),
    };
    // There is deliberately no API to recover a receipt from the reopened
    // provider; only a fresh append can enqueue another initial dispatch.
    assert_eq!(*remote.authorization_checks.lock().unwrap(), 0);
    assert!(reopened.provider_scope() == &scope);
}

#[test]
fn queued_capability_keeps_prepared_instance_until_revocation_check() {
    let temp = private_tempdir();
    let scope = fixture_scope("account-revoked");
    let recovery = prepared(temp.path(), &scope);
    let queue = InitialEditQueue::default();
    let journal_scope = journal_scope(&scope, "personal");
    let receipt = append_receipt(recovery.as_ref(), "personal", b"retained-after-revoke");
    queue.push(Arc::clone(&recovery), receipt).unwrap();
    drop(recovery);

    let pending = queue.take().unwrap().unwrap();
    assert!(pending.matches_provider(&scope, root_identity()));
    let remote = RevokedRemote {
        authorization_checks: Mutex::new(0),
    };
    assert_eq!(
        pending.dispatch(&remote).unwrap(),
        ReconciliationOutcome::Deferred
    );
    assert_eq!(*remote.authorization_checks.lock().unwrap(), 1);
    assert_eq!(
        read_records(temp.path(), journal_scope),
        [b"retained-after-revoke".to_vec()]
    );
}

fn location_for(
    receipt: &crate::InitialEditReceipt,
    components: Vec<String>,
) -> crate::InitialEditLocation {
    crate::InitialEditLocation::new(
        components,
        [7; 16],
        root_identity(),
        receipt.local_file(),
        receipt,
    )
    .unwrap()
}

#[test]
fn local_location_preserves_actual_components_without_remote_path_derivation() {
    let temp = private_tempdir();
    let scope = fixture_scope("local-location");
    let recovery = prepared(temp.path(), &scope);
    let receipt = append_receipt(recovery.as_ref(), "personal", b"local-body");
    // The receipt remote-relative path is notes.txt; the local callback route
    // can include namespace directories and must be retained independently.
    let location = location_for(
        &receipt,
        vec!["Spaces".into(), "Example".into(), "notes.txt".into()],
    );
    let queue = InitialEditQueue::default();
    queue
        .push_with_location(Arc::clone(&recovery), receipt, location)
        .unwrap();
    let pending = queue.take().unwrap().unwrap();
    let location = pending.location().unwrap();
    assert_eq!(location.components(), &["Spaces", "Example", "notes.txt"]);
    assert_eq!(location.identity(), &[7; 16]);
    assert_eq!(location.root_identity(), root_identity());
    assert_eq!(location.local_file_identity().file_index, 55);
    let remote = RevokedRemote {
        authorization_checks: Mutex::new(0),
    };
    assert_eq!(
        pending.dispatch(&remote).unwrap(),
        ReconciliationOutcome::Deferred
    );
    assert_eq!(
        read_records(temp.path(), journal_scope(&scope, "personal")),
        [b"local-body".to_vec()]
    );
}

#[test]
fn local_location_rejects_invalid_paths_and_receipt_identity_drift() {
    let temp = private_tempdir();
    let scope = fixture_scope("local-invalid");
    let recovery = prepared(temp.path(), &scope);
    let receipt = append_receipt(recovery.as_ref(), "personal", b"unchanged");
    let mut invalid = vec![vec![]];
    for name in ["", ".", "..", "/absolute", "a/b", "a\\b", "C:drive", "a\n"] {
        invalid.push(vec![name.into()]);
    }
    invalid.push(vec!["x".repeat(256)]);
    invalid.push(vec!["x".into(); 257]);
    invalid.push(vec!["x".repeat(255); 129]);
    for components in invalid {
        assert!(
            crate::InitialEditLocation::new(
                components,
                [7; 16],
                root_identity(),
                receipt.local_file(),
                &receipt
            )
            .is_err()
        );
    }
    let wrong_root = ConfiguredRootIdentity {
        file_index: 30,
        ..root_identity()
    };
    assert!(
        crate::InitialEditLocation::new(
            vec!["notes.txt".into()],
            [7; 16],
            wrong_root,
            receipt.local_file(),
            &receipt
        )
        .is_err()
    );
    let wrong_file = LocalFileIdentity {
        file_index: 56,
        ..receipt.local_file()
    };
    assert!(
        crate::InitialEditLocation::new(
            vec!["notes.txt".into()],
            [7; 16],
            root_identity(),
            wrong_file,
            &receipt
        )
        .is_err()
    );
    assert_eq!(
        read_records(temp.path(), journal_scope(&scope, "personal")),
        [b"unchanged".to_vec()]
    );
}

#[test]
fn location_cannot_be_rebound_and_full_queue_preserves_new_durable_edit() {
    let temp = private_tempdir();
    let scope = fixture_scope("local-binding");
    let recovery = prepared(temp.path(), &scope);
    let first = append_receipt(recovery.as_ref(), "personal", b"first");
    let location = location_for(&first, vec!["notes.txt".into()]);
    let second = append_receipt(recovery.as_ref(), "personal", b"second");
    let queue = InitialEditQueue::default();
    assert_eq!(
        queue.push_with_location(Arc::clone(&recovery), second, location),
        Err(BackendError::Unavailable)
    );
    assert!(queue.take().unwrap().is_none());
    let location = location_for(&first, vec!["notes.txt".into()]);
    let reopened = prepared(temp.path(), &scope);
    // Same root/file and record metadata never transfers the location's
    // original prepared owner capability to a reopened provider receipt.
    let other = append_receipt(reopened.as_ref(), "personal", b"other-owner");
    assert_eq!(
        queue.push_with_location(reopened, other, location),
        Err(BackendError::Unavailable)
    );
    for _ in 0..MAX_PENDING_INITIAL_EDITS {
        let receipt = append_receipt(recovery.as_ref(), "personal", b"filler");
        queue.push(Arc::clone(&recovery), receipt).unwrap();
    }
    let location = location_for(&first, vec!["notes.txt".into()]);
    assert_eq!(
        queue.push_with_location(recovery, first, location),
        Err(BackendError::Unavailable)
    );
    assert_eq!(
        read_records(temp.path(), journal_scope(&scope, "personal")).len(),
        MAX_PENDING_INITIAL_EDITS + 3
    );
}

struct LegacyRecovery(Arc<dyn PreparedEditRecovery>);

impl PreparedEditRecovery for LegacyRecovery {
    fn provider_scope(&self) -> &ProviderScope {
        self.0.provider_scope()
    }
    fn root_identity(&self) -> ConfiguredRootIdentity {
        self.0.root_identity()
    }
    fn append_edit(
        &self,
        _: &PlaceholderEditBinding,
        _: ConfiguredRootIdentity,
        _: LocalFileIdentity,
        _: &str,
        _: &[u8],
    ) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }
    fn has_unresolved(&self) -> Result<bool, BackendError> {
        self.0.has_unresolved()
    }
    fn dispatch_initial_receipt(
        &self,
        receipt: crate::InitialEditReceipt,
        remote: &dyn RecoveryRemote,
    ) -> Result<ReconciliationOutcome, crate::JournalError> {
        self.0.dispatch_initial_receipt(receipt, remote)
    }
    // Intentionally no verified-dispatch override: exercise trait compatibility.
}

#[test]
fn verified_dispatch_default_returns_no_proof_and_retains_owned_location() {
    let temp = private_tempdir();
    let scope = fixture_scope("legacy-verified-dispatch");
    let recovery = prepared(temp.path(), &scope);
    let receipt = append_receipt(recovery.as_ref(), "personal", b"legacy-durable");
    let location = location_for(&receipt, vec!["Personal".into(), "notes.txt".into()]);
    let legacy: Arc<dyn PreparedEditRecovery> = Arc::new(LegacyRecovery(recovery));
    let queue = InitialEditQueue::default();
    queue.push_with_location(legacy, receipt, location).unwrap();
    let remote = RevokedRemote {
        authorization_checks: Mutex::new(0),
    };
    let dispatched = queue
        .take()
        .unwrap()
        .unwrap()
        .dispatch_verified(&remote)
        .unwrap();
    assert_eq!(dispatched.outcome, ReconciliationOutcome::Deferred);
    assert!(dispatched.proof.is_none());
    let location = dispatched.location.unwrap();
    assert_eq!(location.components(), &["Personal", "notes.txt"]);
    assert_eq!(location.identity(), &[7; 16]);
    assert_eq!(location.root_identity(), root_identity());
    assert_eq!(location.local_file_identity().file_index, 55);
    assert_eq!(*remote.authorization_checks.lock().unwrap(), 1);
    assert!(queue.take().unwrap().is_none());
    assert_eq!(
        read_records(temp.path(), journal_scope(&scope, "personal")),
        [b"legacy-durable".to_vec()]
    );
}

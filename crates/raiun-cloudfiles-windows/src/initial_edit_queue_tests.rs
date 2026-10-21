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

use super::*;
use crate::{
    CompletedLocalEdit, EditJournal, EditJournalScope, EditRecordProtector, EditRecoveryProvider,
    InitialEditReceipt, LocalFileIdentity, PlaceholderEditBinding, PreparedEditRecovery,
    ProviderScope,
};
use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
use raiun_core::backend::CloudBackend;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

const OWNER: &[u8] = b"raiun-r54-legacy-auth-owned-v1\n";

#[derive(Clone)]
struct CountingDpapiProtector {
    inner: Arc<crate::DpapiEditRecordProtector>,
    body_open_count: Arc<AtomicUsize>,
}

impl CountingDpapiProtector {
    fn from_state(state: Arc<PrivateDirectory>) -> Self {
        let inner = crate::DpapiEditRecordProtector::from_existing_private_directory(state)
            .expect("DPAPI protector from exact owned private state");
        Self {
            inner: Arc::new(inner),
            body_open_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn reset_body_open_count(&self) {
        self.body_open_count.store(0, Ordering::Relaxed);
    }

    fn body_open_count(&self) -> usize {
        self.body_open_count.load(Ordering::Relaxed)
    }
}

impl EditRecordProtector for CountingDpapiProtector {
    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, crate::JournalError> {
        self.inner.seal(aad, plaintext)
    }

    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, crate::JournalError> {
        let plaintext = self.inner.open(aad, sealed)?;
        // The legacy edit encoding is a binary body-inclusive record. Catalogs
        // and recovery events have different authenticated plaintext formats.
        if plaintext.starts_with(b"RAIUNED1") {
            self.body_open_count.fetch_add(1, Ordering::Relaxed);
        }
        Ok(plaintext)
    }

    fn protect_directory(&self, path: &Path) -> Result<(), crate::JournalError> {
        self.inner.protect_directory(path)
    }
}

struct OwnedCase {
    case_path: PathBuf,
    state: Arc<PrivateDirectory>,
    protector: CountingDpapiProtector,
    provider_scope: ProviderScope,
    root: ConfiguredRootIdentity,
    edit_scope: EditJournalScope,
    local_file: LocalFileIdentity,
    prepared: Arc<dyn PreparedEditRecovery>,
}

fn owned_case(name: &str, store_policy: crate::streamed_store::StorePolicy) -> OwnedCase {
    // Coordinated legacy writes reserve MAX_SEALED_BYTES before knowing the
    // final ciphertext size: 16 MiB body + 256 KiB metadata + 64 KiB overhead.
    // Keep independent headroom for the catalogs and other retained evidence.
    let legacy_reservation = 16 * 1024 * 1024 + 256 * 1024 + 64 * 1024;
    assert!(store_policy.max_state_bytes > legacy_reservation + 1024 * 1024);
    assert_eq!(
        std::env::var("RAIUN_R54_NATIVE").as_deref(),
        Ok("1"),
        "R54 requires a fresh retained DPAPI fixture guard"
    );
    let fixture = PathBuf::from(
        std::env::var_os("RAIUN_R54_FIXTURE_DIR").expect("R54 fixture directory is required"),
    );
    assert!(fixture.is_absolute(), "R54 fixture path must be absolute");
    assert_eq!(fs::read(fixture.join("OWNER")).unwrap(), OWNER);
    let case_path = fixture.join(name);
    fs::create_dir(&case_path).expect("R54 case names are always fresh and retained");

    let case_pin = PinnedDirectory::open(&case_path).expect("pin owned fixture case");
    let logical = case_pin
        .create_child_directory(std::ffi::OsStr::new("logical-root"))
        .expect("create owned logical root");
    let personal = logical
        .create_child_directory(std::ffi::OsStr::new("Personal"))
        .expect("create owned Personal directory");
    let (_, source_identity) = personal
        .create_new_file(std::ffi::OsStr::new("notes.txt"))
        .expect("create synthetic source identity");
    let logical_identity = logical.identity();
    let root = ConfiguredRootIdentity {
        volume_serial: logical_identity.volume_serial,
        file_index: logical_identity.file_index,
    };
    let local_file = LocalFileIdentity {
        volume_serial: source_identity.volume_serial,
        file_index: source_identity.file_index,
    };

    let state = Arc::new(
        PrivateDirectory::create_or_open_under(&case_pin, std::ffi::OsStr::new("state"))
            .expect("create private state beneath fresh owned case"),
    );
    let protector = CountingDpapiProtector::from_state(Arc::clone(&state));
    let client =
        raiun_opencloud::OpenCloudClient::new("https://example.test", "r54-synthetic-token".into())
            .expect("synthetic offline client config");
    let provider_scope = ProviderScope::new(
        &client,
        "r54-profile".into(),
        "r54-account".into(),
        client.server_origin().unwrap(),
    )
    .expect("synthetic exact provider scope");
    let edit_scope = EditJournalScope {
        profile_id: provider_scope.profile_id().to_owned(),
        server_origin: provider_scope.server_origin().to_owned(),
        account_subject: provider_scope.account_id().to_owned(),
        space_id: "personal".into(),
        root_resource_id: "root-1".into(),
        root_volume_serial: root.volume_serial,
        root_file_index: root.file_index,
    };
    let provider = DurableEditRecoveryProvider::new(
        state.path().to_path_buf(),
        provider_scope.clone(),
        root,
        protector.clone(),
    )
    .with_modern_namespace_file_rename(store_policy)
    .expect("explicit same-state namespace admission for synthetic test");
    let prepared = provider
        .prepare(&provider_scope, root)
        .expect("prepare exact provider/root");
    OwnedCase {
        case_path,
        state,
        protector,
        provider_scope,
        root,
        edit_scope,
        local_file,
        prepared,
    }
}

fn policy() -> crate::streamed_store::StorePolicy {
    crate::streamed_store::StorePolicy {
        max_content_bytes: 1024 * 1024,
        max_state_bytes: 64 * 1024 * 1024,
        max_entries: 512,
        max_metadata_bytes_per_scan: 1024 * 1024,
    }
}

fn append_receipt(case: &OwnedCase, content: &[u8]) -> InitialEditReceipt {
    let binding = PlaceholderEditBinding {
        profile_id: case.provider_scope.profile_id().to_owned(),
        server_origin: case.provider_scope.server_origin().to_owned(),
        account_subject: case.provider_scope.account_id().to_owned(),
        account_generation: case.provider_scope.token_generation(),
        space_id: case.edit_scope.space_id.clone(),
        root_resource_id: case.edit_scope.root_resource_id.clone(),
        remote_resource_id: "file-1".into(),
        virtual_path: "/notes.txt".into(),
        base_etag: "\"v1\"".into(),
        base_size: 5,
    };
    case.prepared
        .append_edit_for_initial_dispatch(
            &binding,
            case.root,
            case.local_file,
            "notes.txt",
            content,
        )
        .expect("append through exact prepared provider")
        .expect("durable legacy receipt")
}

fn journal_directory(case: &OwnedCase) -> PathBuf {
    EditJournal::storage_root(case.state.path())
        .join(EditJournal::scope_directory_key(&case.edit_scope).unwrap())
}

#[test]
#[ignore = "requires a fresh retained R54 DPAPI fixture root"]
fn r54_verified_local_ack_is_clean_only_after_full_legacy_body_authentication() {
    let case = owned_case("verified-ack", policy());
    let receipt = append_receipt(&case, b"proof");
    let record_path = journal_directory(&case).join(format!("{}.edit", receipt.metadata.record_id));
    let (outcome, proof) = case
        .prepared
        .dispatch_initial_receipt_verified(receipt, &super::tests::ReceiptRemote::new(b"proof"))
        .expect("synthetic bounded remote proof path");
    assert!(matches!(
        outcome,
        crate::ReconciliationOutcome::VerifiedApplied { .. }
    ));
    let proof = proof.expect("exact synthetic readback proof");
    let completion = CompletedLocalEdit::from_verified_native_completion(&proof)
        .expect("typed completion derived from verified proof");
    case.prepared
        .record_local_completion(completion)
        .expect("append local acknowledgement through provider API");
    let retained_before = fs::read(&record_path).unwrap();

    case.protector.reset_body_open_count();
    assert!(case.prepared.has_unresolved_content().unwrap());
    assert_eq!(
        case.protector.body_open_count(),
        0,
        "the strict metadata-only method stays conservative and body-free"
    );
    case.protector.reset_body_open_count();
    assert!(
        !case
            .prepared
            .has_unresolved_content_authenticated_legacy()
            .unwrap()
    );
    assert!(
        case.protector.body_open_count() > 0,
        "the authenticated compatibility method must actually decode the retained legacy body"
    );
    assert!(case.state.path().starts_with(&case.case_path));
    assert!(
        fs::read(&record_path).unwrap() == retained_before,
        "retained record changed"
    );
}

#[test]
#[ignore = "requires a fresh retained R54 DPAPI fixture root"]
fn r54_pending_and_remote_verified_without_local_ack_remain_unresolved() {
    let pending_case = owned_case("pending-only", policy());
    let pending = append_receipt(&pending_case, b"first");
    drop(pending);
    pending_case.protector.reset_body_open_count();
    assert!(
        pending_case
            .prepared
            .has_unresolved_content_authenticated_legacy()
            .unwrap()
    );
    assert!(pending_case.protector.body_open_count() > 0);

    let case = owned_case("verified-without-ack", policy());
    let verified = append_receipt(&case, b"proof");
    let (outcome, proof) = case
        .prepared
        .dispatch_initial_receipt_verified(verified, &super::tests::ReceiptRemote::new(b"proof"))
        .expect("synthetic bounded remote proof path");
    assert!(matches!(
        outcome,
        crate::ReconciliationOutcome::VerifiedApplied { .. }
    ));
    assert!(
        proof.is_some(),
        "remote verification alone retains no local ack"
    );

    case.protector.reset_body_open_count();
    assert!(
        case.prepared
            .has_unresolved_content_authenticated_legacy()
            .unwrap()
    );
    assert!(
        case.protector.body_open_count() > 0,
        "remote verification alone must remain unresolved after full body authentication"
    );
}

#[test]
#[ignore = "requires a fresh retained R54 DPAPI fixture root"]
fn r54_incomplete_corrupt_and_overbudget_legacy_evidence_refuses_without_mutation() {
    let staged = owned_case("incomplete-stage", policy());
    let receipt = append_receipt(&staged, b"first");
    drop(receipt);
    let stage = journal_directory(&staged).join(".stage-0123456789abcdef");
    fs::write(&stage, b"retained synthetic stage").unwrap();
    let stage_before = fs::read(&stage).unwrap();
    assert!(
        staged
            .prepared
            .has_unresolved_content_authenticated_legacy()
            .is_err()
    );
    assert!(
        fs::read(&stage).unwrap() == stage_before,
        "stage bytes changed"
    );

    let corrupt = owned_case("corrupt-body", policy());
    let receipt = append_receipt(&corrupt, b"proof");
    let record_path =
        journal_directory(&corrupt).join(format!("{}.edit", receipt.metadata.record_id));
    drop(receipt);
    let mut damaged = fs::read(&record_path).unwrap();
    let last = damaged.len().checked_sub(1).unwrap();
    damaged[last] ^= 0x01;
    fs::write(&record_path, &damaged).unwrap();
    let damaged_before = fs::read(&record_path).unwrap();
    assert!(
        corrupt
            .prepared
            .has_unresolved_content_authenticated_legacy()
            .is_err()
    );
    assert!(
        fs::read(&record_path).unwrap() == damaged_before,
        "ciphertext changed"
    );

    let overbudget = owned_case("overbudget", policy());
    let overbudget_content = vec![b'x'; 768 * 1024];
    let receipt = append_receipt(&overbudget, &overbudget_content);
    let record_path =
        journal_directory(&overbudget).join(format!("{}.edit", receipt.metadata.record_id));
    drop(receipt);
    let record_before = fs::read(&record_path).unwrap();
    let mut narrow_policy = policy();
    narrow_policy.max_metadata_bytes_per_scan = 512 * 1024;
    let narrow_provider = DurableEditRecoveryProvider::new(
        overbudget.state.path().to_path_buf(),
        overbudget.provider_scope.clone(),
        overbudget.root,
        overbudget.protector.clone(),
    )
    .with_modern_namespace_file_rename(narrow_policy)
    .unwrap();
    let narrow_prepared = narrow_provider
        .prepare(&overbudget.provider_scope, overbudget.root)
        .unwrap();
    assert!(
        narrow_prepared
            .has_unresolved_content_authenticated_legacy()
            .is_err()
    );
    assert!(
        fs::read(&record_path).unwrap() == record_before,
        "record bytes changed"
    );
}

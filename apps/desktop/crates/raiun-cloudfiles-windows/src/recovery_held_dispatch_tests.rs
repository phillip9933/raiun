use super::*;
use crate::namespace_intent::{
    CapturedAuthorization, ExistingNamespaceEntry, LocalNamespaceEntry, NamespaceIntent,
    NamespaceObjectKind, NamespaceOperation, NamespaceParent, NamespacePhase,
    StorageClassification,
};
use crate::streamed_store::namespace_rename_store::{FileRenamePublishResult, FileRenameStore};
use std::{
    fs, io,
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
};

const OWNER: &[u8] = b"raiun-r57-held-dispatch-owned-v1\n";
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
const MAX_SNAPSHOT_ENTRIES: usize = 4096;
const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;

fn r57_case(name: &str) -> OwnedCase {
    assert_eq!(
        std::env::var("RAIUN_R57_NATIVE").as_deref(),
        Ok("1"),
        "R57 requires a fresh retained DPAPI fixture guard"
    );
    let fixture = PathBuf::from(
        std::env::var_os("RAIUN_R57_FIXTURE_DIR").expect("R57 fixture directory is required"),
    );
    assert!(fixture.is_absolute(), "R57 fixture path must be absolute");
    let marker = fs::symlink_metadata(fixture.join("OWNER")).expect("R57 OWNER metadata");
    assert!(
        marker.is_file() && marker.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "R57 OWNER must be a plain file"
    );
    assert_eq!(fs::read(fixture.join("OWNER")).unwrap(), OWNER);
    owned_case_in(name, policy(), &fixture, OWNER)
}

fn namespace_intent(
    case: &OwnedCase,
) -> (EditJournalScope, CapturedAuthorization, NamespaceIntent) {
    let scope = case.edit_scope.clone();
    let authorization = CapturedAuthorization {
        agent_generation: 57,
        token_generation: case.provider_scope.token_generation(),
    };
    let parent = NamespaceParent {
        scope: scope.clone(),
        authorization,
        classification: StorageClassification::Ordinary,
        local_file: case.parent_file,
        local_components: vec!["Personal".into()],
        remote: crate::RemoteEditBaseline {
            resource_id: "r57-parent".into(),
            etag: "\"r57-parent-v1\"".into(),
            byte_len: 0,
        },
    };
    let source = LocalNamespaceEntry {
        parent: parent.clone(),
        name: "notes.txt".into(),
        local_file: case.local_file,
        object_kind: NamespaceObjectKind::File,
    };
    let intent = NamespaceIntent {
        schema_version: 1,
        record_id: "b".repeat(32),
        record_generation: 1,
        operation: NamespaceOperation::MoveWithinScope {
            source: ExistingNamespaceEntry {
                local: source.clone(),
                remote: crate::RemoteEditBaseline {
                    resource_id: "file-1".into(),
                    etag: "\"v1\"".into(),
                    byte_len: 5,
                },
            },
            destination: LocalNamespaceEntry {
                name: "renamed.txt".into(),
                ..source
            },
        },
    };
    (scope, authorization, intent)
}

fn fresh_namespace_lease(
    case: &OwnedCase,
) -> (
    Arc<FileRenameStore>,
    crate::streamed_store::namespace_rename_store::FileRenameLease,
) {
    let (scope, authorization, intent) = namespace_intent(case);
    // Exercise only the exact prepared capability attached to this owned case.
    let store = case
        .prepared
        .file_rename_store(&scope, authorization)
        .expect("R57 exact prepared store factory")
        .expect("explicit namespace store opt-in");
    let same = case
        .prepared
        .file_rename_store(&scope, authorization)
        .expect("R57 repeated exact prepared store factory")
        .expect("same explicit namespace store opt-in");
    assert!(
        store
            .same_admitted_binding(&same)
            .expect("compare the actual admitted storage binding"),
        "both factory results must be the same admitted state/scope/policy/protector"
    );
    let fresh = match store
        .publish_intent(intent)
        .expect("publish only the test's new same-parent namespace intent")
    {
        FileRenamePublishResult::Fresh(fresh) => fresh,
        FileRenamePublishResult::Retained => panic!("R57 case is a unique fresh operation"),
    };
    let lease = fresh
        .acquire_dispatch()
        .expect("hold exact fresh dispatch lease");
    let progress = lease.progress();
    assert_eq!(progress.sequence, 0);
    assert_eq!(progress.remote, NamespacePhase::Pending);
    assert_eq!(progress.source_removal, Some(NamespacePhase::Pending));
    assert_eq!(progress.attention, None);
    assert!(!progress.local_completed && !progress.recorded_complete);
    (store, lease)
}

#[derive(Eq, PartialEq)]
struct StateEntry {
    relative: String,
    directory: bool,
    length: u64,
    bytes: Option<Vec<u8>>,
}

fn snapshot_state(case: &OwnedCase) -> io::Result<Vec<StateEntry>> {
    fn walk(
        root: &Path,
        path: &Path,
        entries: &mut Vec<StateEntry>,
        total: &mut u64,
    ) -> io::Result<()> {
        if entries.len() >= MAX_SNAPSHOT_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "snapshot entry cap",
            ));
        }
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "reparse in owned state",
            ));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "state path escaped"))?
            .to_string_lossy()
            .into_owned();
        if metadata.is_dir() {
            entries.push(StateEntry {
                relative,
                directory: true,
                length: 0,
                bytes: None,
            });
            for child in fs::read_dir(path)? {
                walk(root, &child?.path(), entries, total)?;
            }
        } else if metadata.is_file() {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            let lock_file = name.ends_with(".lock");
            if lock_file && metadata.len() != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "lock file not empty",
                ));
            }
            *total = total.checked_add(metadata.len()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "snapshot byte overflow")
            })?;
            if *total > MAX_SNAPSHOT_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snapshot byte cap",
                ));
            }
            let bytes = if lock_file {
                None
            } else {
                Some(fs::read(path)?)
            };
            entries.push(StateEntry {
                relative,
                directory: false,
                length: metadata.len(),
                bytes,
            });
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported state entry",
            ));
        }
        Ok(())
    }

    let root = case.state.path();
    let mut entries = Vec::new();
    let mut total = 0;
    walk(root, root, &mut entries, &mut total)?;
    entries.sort_by(|left, right| left.relative.cmp(&right.relative));
    Ok(entries)
}

#[test]
#[ignore = "requires a fresh retained R57 DPAPI fixture root"]
fn r57_held_dispatch_authenticated_clean_history_excludes_own_namespace() {
    let case = r57_case("authenticated-clean");
    let receipt = append_receipt(&case, b"proof");
    let record_path = journal_directory(&case).join(format!("{}.edit", receipt.metadata.record_id));
    let (outcome, proof) = case
        .prepared
        .dispatch_initial_receipt_verified(
            receipt,
            &super::super::tests::ReceiptRemote::new(b"proof"),
        )
        .expect("synthetic bounded legacy verification");
    assert!(matches!(
        outcome,
        crate::ReconciliationOutcome::VerifiedApplied { .. }
    ));
    let completion = CompletedLocalEdit::from_verified_native_completion(
        &proof.expect("verified synthetic legacy readback"),
    )
    .expect("typed completion from proof");
    case.prepared
        .record_local_completion(completion)
        .expect("durable local acknowledgement");
    let retained_record = fs::read(&record_path).expect("retained acknowledged legacy record");

    let (_store, lease) = fresh_namespace_lease(&case);
    let progress_before = lease.progress();
    let before = snapshot_state(&case).expect("bounded owned state snapshot before health queries");
    assert!(
        case.prepared
            .has_unresolved()
            .expect("whole-history health")
    );
    case.protector.reset_body_open_count();
    assert!(
        !case
            .prepared
            .has_unresolved_content_authenticated_legacy()
            .expect("full authenticated content health"),
        "completed legacy content and this operation's own namespace Pending are content-clean"
    );
    assert!(case.protector.body_open_count() > 0);
    let after = snapshot_state(&case).expect("bounded owned state snapshot after content auth");
    assert!(
        before == after,
        "authenticated content health mutated protected state"
    );
    assert!(
        fs::read(&record_path).unwrap() == retained_record,
        "legacy record changed"
    );
    assert_eq!(lease.progress(), progress_before);
    assert_eq!(progress_before.sequence, 0);
}

#[test]
#[ignore = "requires a fresh retained R57 DPAPI fixture root"]
fn r57_held_dispatch_pending_content_is_nonclean_without_mutation() {
    let case = r57_case("pending-content");
    let receipt = append_receipt(&case, b"proof");
    let record_path = journal_directory(&case).join(format!("{}.edit", receipt.metadata.record_id));
    drop(receipt);
    let retained_record = fs::read(&record_path).expect("retained pending legacy record");

    let (_store, lease) = fresh_namespace_lease(&case);
    let progress_before = lease.progress();
    let before = snapshot_state(&case).expect("bounded owned state snapshot before health queries");
    assert!(
        case.prepared
            .has_unresolved()
            .expect("whole-history health")
    );
    case.protector.reset_body_open_count();
    assert!(
        case.prepared
            .has_unresolved_content_authenticated_legacy()
            .expect("full authenticated content health"),
        "pending legacy content remains nonclean despite an owned namespace dispatch lease"
    );
    assert!(case.protector.body_open_count() > 0);
    let after = snapshot_state(&case).expect("bounded owned state snapshot after content auth");
    assert!(
        before == after,
        "authenticated content health mutated protected state"
    );
    assert!(
        fs::read(&record_path).unwrap() == retained_record,
        "legacy record changed"
    );
    assert_eq!(lease.progress(), progress_before);
    assert_eq!(progress_before.sequence, 0);
}

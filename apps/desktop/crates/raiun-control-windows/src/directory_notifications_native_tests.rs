use super::*;
use std::{path::PathBuf, time::SystemTime};

fn fixture() -> PathBuf {
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    for attempt in 0..32 {
        let path = std::env::temp_dir().join(format!(
            "raiun-directory-observer-{}-{seed}-{attempt}",
            std::process::id()
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
            Err(error) => panic!("create isolated directory fixture: {error}"),
        }
    }
    panic!("isolated fixture allocation exhausted");
}

fn stop(observer: &mut DirectoryObserver) {
    for _ in 0..100 {
        let _ = observer.cancel_and_drain(Duration::from_millis(50));
        if !observer.has_pending_io() {
            assert_eq!(observer.arm(), ObserverPoll::Stopped);
            return;
        }
        assert_eq!(observer.arm(), ObserverPoll::Pending);
    }
    panic!("native cancellation did not drain in fixture deadline; Drop still waits safely");
}

#[test]
#[ignore = "opt-in disconnected native Windows temporary-directory observer test"]
fn directory_notifications_observes_owned_hints_and_drains_exact_pending_io() {
    let path = fixture();
    let root = Arc::new(PinnedDirectory::open(&path).unwrap());
    let expected = root.identity();
    let mut wrong = expected;
    wrong.file_index ^= 1;
    assert!(DirectoryObserver::new(root.clone(), wrong).is_err());
    let mut observer = DirectoryObserver::new(root.clone(), expected).unwrap();
    assert_eq!(observer.root_identity(), expected);
    assert_eq!(observer.poll(Duration::ZERO), ObserverPoll::Idle);
    assert_eq!(observer.arm(), ObserverPoll::Pending);
    assert_eq!(observer.arm(), ObserverPoll::Pending);
    std::fs::write(path.join("created.txt"), b"disconnected synthetic bytes").unwrap();
    let mut found = false;
    for _ in 0..100 {
        match observer.poll(Duration::from_millis(50)) {
            ObserverPoll::Pending => (),
            ObserverPoll::Batch(NotificationBatch::Hints(hints)) => {
                found = hints.iter().any(|hint| {
                    hint.components() == ["created.txt"]
                        && hint.action() == super::super::DirectoryAction::Added
                });
                if found {
                    break;
                }
                assert_eq!(observer.arm(), ObserverPoll::Pending);
            }
            other => panic!("unexpected observer result: {other:?}"),
        }
    }
    assert!(
        found,
        "expected independent create hint, not cloud authority"
    );
    assert_eq!(
        std::fs::read(path.join("created.txt")).unwrap(),
        b"disconnected synthetic bytes"
    );
    assert!(std::fs::rename(&path, path.with_extension("moved")).is_err());
    assert_eq!(observer.arm(), ObserverPoll::Pending);
    stop(&mut observer);
    drop(observer);
    drop(root);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
#[ignore = "opt-in disconnected native Windows pending observer Drop/drain test"]
fn directory_notifications_drop_drains_before_freeing_io_or_ancestor_pins() {
    let path = fixture();
    let root = Arc::new(PinnedDirectory::open(&path).unwrap());
    let mut observer = DirectoryObserver::new(root.clone(), root.identity()).unwrap();
    assert_eq!(observer.arm(), ObserverPoll::Pending);
    drop(observer);
    drop(root);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
#[ignore = "opt-in native Windows ordinary borrowed-handle ownership test; not connected CF root acceptance"]
fn borrowed_directory_observer_owns_reopened_handle_after_borrow_and_pins_end() {
    let path = fixture();
    let root = Arc::new(PinnedDirectory::open(&path).unwrap());
    let weak = Arc::downgrade(&root);
    let expected = root.identity();
    let original = root.try_clone_directory_file().unwrap();
    #[cfg(all(feature = "synthetic-agent-integration", debug_assertions))]
    let created =
        DirectoryObserver::from_borrowed_directory_diagnostic(original.as_handle(), expected)
            .map_err(|failure| {
                eprintln!(
                    "synthetic ordinary observer construction stage={} kind={:?} native_code={:?}",
                    failure.stage(),
                    failure.kind(),
                    failure.native_code()
                );
                failure.into_io_error()
            });
    #[cfg(not(all(feature = "synthetic-agent-integration", debug_assertions)))]
    let created = DirectoryObserver::from_borrowed_directory(original.as_handle(), expected);
    let mut observer = created.expect("own independently reopened overlapped directory");
    drop(original);
    drop(root);
    assert!(
        weak.upgrade().is_none(),
        "handle-only mode owns no generic ancestor pin"
    );
    assert_eq!(observer.root_identity(), expected);
    assert_eq!(observer.arm(), ObserverPoll::Pending);
    std::fs::write(path.join("borrow-ended.txt"), b"owned physical observer").unwrap();
    let mut found = false;
    for _ in 0..100 {
        match observer.poll(Duration::from_millis(50)) {
            ObserverPoll::Pending => (),
            ObserverPoll::Batch(NotificationBatch::Hints(hints)) => {
                found = hints
                    .iter()
                    .any(|hint| hint.components() == ["borrow-ended.txt"]);
                if found {
                    break;
                }
                assert_eq!(observer.arm(), ObserverPoll::Pending);
            }
            other => panic!("unexpected ordinary borrowed-handle result: {other:?}"),
        }
    }
    assert!(found);
    assert!(std::fs::rename(&path, path.with_extension("moved")).is_err());
    assert_eq!(observer.arm(), ObserverPoll::Pending);
    stop(&mut observer);
    let actual_drained = !observer.has_pending_io();
    assert!(actual_drained);
    drop(observer);
    let retained_root = PinnedDirectory::open(&path).unwrap();
    assert_eq!(retained_root.identity(), expected);
    let retained_bytes = std::fs::read(path.join("borrow-ended.txt")).unwrap();
    assert_eq!(retained_bytes, b"owned physical observer");
    let result = serde_json::json!({
        "passed": true,
        "root_identity_retained": retained_root.identity() == expected,
        "root_bytes_retained": retained_bytes == b"owned physical observer",
        "actual_drained": actual_drained,
        "no_forced_cleanup": true
    });
    std::fs::write(
        path.join("RESULTS.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    // Retain this exact root, file and receipt for the native handoff.
}

#[test]
#[ignore = "opt-in native Windows borrowed regular-file refusal; not connected CF root acceptance"]
fn borrowed_directory_factory_rejects_exact_regular_file_without_consuming_borrow() {
    let path = fixture();
    let root = Arc::new(PinnedDirectory::open(&path).unwrap());
    std::fs::write(path.join("ordinary.bin"), b"retained fixture bytes").unwrap();
    let (original, identity) = root
        .open_regular_file(std::ffi::OsStr::new("ordinary.bin"))
        .unwrap();
    assert!(DirectoryObserver::from_borrowed_directory(original.as_handle(), identity).is_err());
    assert!(
        original.metadata().unwrap().is_file(),
        "factory never closes a borrowed handle"
    );
    drop(original);
    drop(root);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
#[ignore = "opt-in native Windows incompatible DELETE handle refusal; no weaker sharing fallback"]
fn borrowed_directory_factory_preserves_delete_sharing_refusal() {
    use std::os::windows::fs::OpenOptionsExt;
    let path = fixture();
    let root = PinnedDirectory::open(&path).unwrap();
    let expected = root.identity();
    drop(root);
    // Existing DELETE access must conflict with the observer's no-delete-sharing
    // reopen. Only this ordinary task-created root is opened; no deletion occurs.
    let original = std::fs::OpenOptions::new()
        .access_mode(0x0001_0080) // DELETE | FILE_READ_ATTRIBUTES
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | 4) // FILE_SHARE_DELETE
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path)
        .unwrap();
    assert!(DirectoryObserver::from_borrowed_directory(original.as_handle(), expected).is_err());
    assert!(original.metadata().unwrap().is_dir());
    drop(original);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn constructor_diagnostic_preserves_original_native_and_policy_error() {
    let native = ObserverConstructionFailure::at(
        ConstructionStage::SameObjectOpen,
        io::Error::from_raw_os_error(5),
    );
    assert_eq!(native.stage.code(), "same_object_open");
    assert_eq!(native.error.raw_os_error(), Some(5));
    let error = native.into_io_error();
    assert_eq!(error.raw_os_error(), Some(5));
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    let policy =
        ObserverConstructionFailure::at(ConstructionStage::MetadataChanged, root_changed());
    assert_eq!(policy.stage.code(), "metadata_changed");
    assert_eq!(policy.error.raw_os_error(), None);
    let error = policy.into_io_error();
    assert_eq!(error.raw_os_error(), None);
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}

#[test]
fn kernel_locator_accepts_only_bounded_normalized_volume_guid_paths() {
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }
    let prefix = r"\\?\Volume{01234567-89ab-CDEF-0123-456789abcdef}\";
    assert!(valid_kernel_volume_path(&wide(prefix)));
    assert!(valid_kernel_volume_path(&wide(&format!(
        "{prefix}owned\\日本語"
    ))));
    for value in [
        r"C:\owned",
        r"\\?\C:\owned",
        r"\\server\share\owned",
        r"\\?\UNC\server\share\owned",
        r"\\.\owned",
        r"\Device\HarddiskVolume1\owned",
        r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdeg}\owned",
        r"\\?\Volume{0123456789ab-cdef-0123-456789abcdef}\owned",
    ] {
        assert!(!valid_kernel_volume_path(&wide(value)));
    }
    for suffix in [
        ".",
        "..",
        "a\\..\\b",
        "a\\\\b",
        "a/child",
        "a:stream",
        "trailing.",
        "trailing ",
        "a\\",
        "*",
        "?",
    ] {
        assert!(!valid_kernel_volume_path(&wide(&format!(
            "{prefix}{suffix}"
        ))));
    }
    let valid = wide(&format!("{prefix}owned"));
    assert!(!valid_kernel_volume_path(&valid[..valid.len() - 1]));
    let mut nul = valid.clone();
    nul[50] = 0;
    assert!(!valid_kernel_volume_path(&nul));
    let mut invalid = wide(prefix);
    invalid.pop();
    invalid.extend([0xd800, 0]);
    assert!(!valid_kernel_volume_path(&invalid));
    assert!(!valid_kernel_volume_path(&wide(&format!(
        "{prefix}{}",
        "a".repeat(256)
    ))));
    let mut maximum = prefix.to_owned();
    while MAX_KERNEL_PATH_UNITS - 1 - maximum.len() > 255 {
        maximum.push_str(&"a".repeat(255));
        maximum.push('\\');
    }
    maximum.push_str(&"a".repeat(MAX_KERNEL_PATH_UNITS - 1 - maximum.len()));
    assert_eq!(wide(&maximum).len(), MAX_KERNEL_PATH_UNITS);
    assert!(valid_kernel_volume_path(&wide(&maximum)));
    assert!(!valid_kernel_volume_path(&wide(&(maximum + "a"))));
}

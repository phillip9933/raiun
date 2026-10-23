use super::super::{OpenCloudClient, windows_folder_requests, windows_folder_sync};
use super::*;
use raiun_core::backend::CloudBackend;

#[test]
#[ignore = "requires isolated Windows test environment, loopback synthetic server and private ordinary folders; no Cloud Files registration or GUI acceptance"]
fn ordinary_folder_worker_download_upload_exclude_remove_and_reopen() {
    use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
    use raiun_core::{FolderPair, SyncMode};
    use raiun_engine::folder_pairs::AccountScope;
    use std::ffi::OsStr;
    use windows_folder_requests::FolderRequest;

    let root = std::env::temp_dir().join(format!(
        "raiun-folder-worker-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let local = root.join("ordinary-pair");
    std::fs::create_dir(&local).unwrap();
    let parent = PinnedDirectory::open(&root).unwrap();
    let (server, fixture) = synthetic_personal_spaces_server_with_native_read_files(|_| {});
    let original = fixture.recovery.lock().unwrap().body.clone();
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-access-token".into()).unwrap());
    let (_, account_id, _, spaces, _) = verified_account_roots(&client, &server).unwrap();
    let project = spaces
        .iter()
        .find(|space| space.id == "synthetic-project-drive")
        .unwrap()
        .id
        .clone();
    let scope = AccountScope::new(
        "default".into(),
        url::Url::parse(&server).unwrap().to_string(),
        "synthetic-client".into(),
        None,
        account_id.clone(),
    )
    .unwrap();
    let origin = client.server_origin().unwrap();
    let generation = 1;
    let manager = ProviderManager::new();
    assert!(
        !manager.is_connected(),
        "ordinary pairs need no native registration"
    );
    manager
        .install_folders(windows_folder_sync::Setup {
            generation,
            scope: scope.clone(),
            account_id: account_id.clone(),
            origin: origin.clone(),
            client: client.clone(),
            spaces: spaces.clone(),
            directory: PrivateDirectory::create_or_open_under(&parent, OsStr::new("engine-state"))
                .unwrap(),
            cloud_root: None,
        })
        .unwrap();
    let pair = FolderPair {
        id: "ordinary-project-pair".into(),
        local_path: local.clone(),
        space_id: project.clone(),
        vault: None,
        remote_path: "/RecoveryRoot".into(),
        mode: SyncMode::TwoWay,
        excluded_paths: vec![],
    };
    manager
        .folder_request(generation, FolderRequest::Add(pair.clone()))
        .unwrap();
    let accepted = manager
        .folder_request(
            generation,
            FolderRequest::Sync {
                space_id: Some(project.clone()),
            },
        )
        .unwrap();
    assert_eq!(accepted, json!({"accepted":true,"space_id":project}));
    // A following command is the serial worker barrier; queued ACK is not completion.
    let pairs = manager
        .folder_request(generation, FolderRequest::Pairs)
        .unwrap();
    assert_eq!(pairs.as_array().unwrap().len(), 1);
    assert!(manager.folder_error.lock().unwrap().is_none());
    let document = local.join("document.bin");
    assert_eq!(std::fs::read(&document).unwrap(), original);
    assert_eq!(fixture.recovery.lock().unwrap().put_count, 0);

    let edited = b"ordinary synthetic closed local edit";
    std::fs::write(&document, edited).unwrap();
    manager
        .folder_request(
            generation,
            FolderRequest::Sync {
                space_id: Some(project.clone()),
            },
        )
        .unwrap();
    manager
        .folder_request(generation, FolderRequest::Pairs)
        .unwrap();
    assert!(manager.folder_error.lock().unwrap().is_none());
    {
        let remote = fixture.recovery.lock().unwrap();
        assert_eq!(remote.put_count, 1);
        assert_eq!(remote.body, edited);
        assert_eq!(
            remote.last_put_if_match.as_deref(),
            Some("\"synthetic-file-v1\"")
        );
    }
    assert_eq!(std::fs::read(&document).unwrap(), edited);
    manager
        .folder_request(generation, FolderRequest::Pause { paused: true })
        .unwrap();
    {
        let snapshot = manager.folder_pause.lock().unwrap();
        let snapshot = snapshot.as_ref().expect("persisted pause snapshot");
        assert_eq!(snapshot.generation, generation);
        assert!(snapshot.paused);
        assert!(snapshot.paused_space_ids.is_empty());
    }
    let resumed_edit = b"closed local edit retained during global pause";
    std::fs::write(&document, resumed_edit).unwrap();
    assert!(
        manager
            .folder_request(
                generation,
                FolderRequest::Sync {
                    space_id: Some(project.clone())
                }
            )
            .is_err()
    );
    manager
        .folder_request(generation, FolderRequest::Pairs)
        .unwrap();
    assert_eq!(std::fs::read(&document).unwrap(), resumed_edit);
    {
        let remote = fixture.recovery.lock().unwrap();
        assert_eq!(remote.put_count, 1);
        assert_eq!(remote.body, edited);
    }
    manager
        .folder_request(generation, FolderRequest::Pause { paused: false })
        .unwrap();
    assert!(
        !manager
            .folder_pause
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .paused
    );
    manager
        .folder_request(
            generation,
            FolderRequest::Sync {
                space_id: Some(project.clone()),
            },
        )
        .unwrap();
    manager
        .folder_request(generation, FolderRequest::Pairs)
        .unwrap();
    assert!(manager.folder_error.lock().unwrap().is_none());
    assert_eq!(std::fs::read(&document).unwrap(), resumed_edit);
    {
        let remote = fixture.recovery.lock().unwrap();
        assert_eq!(remote.put_count, 2);
        assert_eq!(remote.body, resumed_edit);
    }
    manager
        .folder_request(
            generation,
            FolderRequest::Exclusions {
                id: pair.id.clone(),
                excluded_paths: vec!["document.bin".into()],
            },
        )
        .unwrap();
    let excluded = b"retained excluded local bytes";
    std::fs::write(&document, excluded).unwrap();
    manager
        .folder_request(
            generation,
            FolderRequest::Sync {
                space_id: Some(project),
            },
        )
        .unwrap();
    manager
        .folder_request(generation, FolderRequest::Pairs)
        .unwrap();
    assert!(manager.folder_error.lock().unwrap().is_none());
    assert_eq!(std::fs::read(&document).unwrap(), excluded);
    assert_eq!(fixture.recovery.lock().unwrap().put_count, 2);
    manager
        .folder_request(
            generation,
            FolderRequest::Remove {
                id: pair.id.clone(),
            },
        )
        .unwrap();
    // Persist pause once more after removal, proving reopen loads state even with no pairs.
    manager
        .folder_request(generation, FolderRequest::Pause { paused: true })
        .unwrap();
    manager.disconnect().unwrap();
    assert!(manager.folder_pause.lock().unwrap().is_none());
    drop(manager);

    let reopened = ProviderManager::new();
    reopened
        .install_folders(windows_folder_sync::Setup {
            generation,
            scope,
            account_id,
            origin,
            client,
            spaces,
            directory: PrivateDirectory::open_under(&parent, OsStr::new("engine-state")).unwrap(),
            cloud_root: None,
        })
        .unwrap();
    {
        let snapshot = reopened.folder_pause.lock().unwrap();
        let snapshot = snapshot.as_ref().expect("pause restored from scoped store");
        assert_eq!(snapshot.generation, generation);
        assert!(snapshot.paused);
        assert!(snapshot.paused_space_ids.is_empty());
    }
    assert_eq!(
        reopened
            .folder_request(generation, FolderRequest::Pairs)
            .unwrap(),
        json!([])
    );
    assert!(
        reopened
            .folder_request(generation, FolderRequest::Add(pair))
            .is_err(),
        "retired ID must remain unusable after runtime reopen"
    );
    assert_eq!(std::fs::read(&document).unwrap(), excluded);
    {
        let remote = fixture.recovery.lock().unwrap();
        assert_eq!(remote.body, resumed_edit);
        assert_eq!(remote.put_count, 2);
    }
    assert_eq!(
        fixture.native_reads.lock().unwrap().mutation_attempt_count,
        0,
        "no unsupported PUT/DELETE/MOVE routes"
    );
    reopened.disconnect().unwrap();
    drop(reopened);
    drop(parent);
    fixture.join().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

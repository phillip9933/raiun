use super::super::{
    OpenCloudClient, windows_folder_requests, windows_folder_sync, windows_media_requests,
};
use super::*;
use raiun_core::backend::CloudBackend;

#[test]
#[ignore = "requires isolated Windows ordinary-user private storage and loopback synthetic server; no Cloud Files activation, real account, or GUI acceptance"]
fn ordinary_media_worker_observes_uploads_pauses_and_reads_local_recovery() {
    use super::super::windows_profile_registry::{
        Registry, RootReservation, SourceKind, SourceReservation,
    };
    use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
    use raiun_core::{FolderPair, MediaFilter, MediaImportJob, MediaOrganization, SyncMode};
    use raiun_engine::folder_pairs::AccountScope;
    use sha2::Digest;
    use std::ffi::OsStr;
    use std::sync::Mutex;
    use windows_folder_requests::FolderRequest;
    use windows_media_requests::MediaRequest;
    let root = std::env::temp_dir().join(format!(
        "raiun-media-worker-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    eprintln!("synthetic_media_worker_root={}", root.display());
    let source = root.join("source");
    std::fs::create_dir(&source).unwrap();
    let source_file = source.join("document.bin");
    let bytes: &[u8] = &[
        0xff, 0xd8, 0xff, 0xe0, 0, 16, b'J', b'F', b'I', b'F', 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0xff,
        0xd9,
    ];
    std::fs::write(&source_file, bytes).unwrap();
    let parent = PinnedDirectory::open(&root).unwrap();
    let (server, fixture) = synthetic_personal_spaces_server_with_absent_media_leaf(|_| {});
    assert!(!fixture.recovery.lock().unwrap().present);
    let client = Arc::new(OpenCloudClient::new(&server, "synthetic-access-token".into()).unwrap());
    let (_, account_id, _, spaces, _) = verified_account_roots(&client, &server).unwrap();
    let space_id = spaces
        .iter()
        .find(|space| space.id == "synthetic-project-drive")
        .unwrap()
        .id
        .clone();
    let profile = "default";
    let scope = AccountScope::new(
        profile.into(),
        url::Url::parse(&server).unwrap().to_string(),
        "synthetic-client".into(),
        None,
        account_id.clone(),
    )
    .unwrap();
    let ordinary = root.join("ordinary-disabled");
    std::fs::create_dir(&ordinary).unwrap();
    let scope_digest = format!(
        "{:x}",
        sha2::Sha256::digest(serde_json::to_vec(&scope).unwrap())
    );
    let mut registry = Registry::decode_or_default(None).unwrap();
    // Both later mutations use exact pre-admitted synthetic sources; neither
    // the media run nor the disabled ordinary pair gets a fixture bypass.
    for (kind, id, path) in [
        (SourceKind::MediaJob, "media-worker", source.as_path()),
        (
            SourceKind::FolderPair,
            "disabled-background-pair",
            ordinary.as_path(),
        ),
    ] {
        let pin = PinnedDirectory::open(path).unwrap();
        let identity = pin.identity();
        pin.verify_path().unwrap();
        registry = registry
            .with_reserved_source(
                profile,
                SourceReservation::new(
                    scope_digest.clone(),
                    kind,
                    id.into(),
                    RootReservation::new(
                        path.to_str().unwrap().into(),
                        identity.volume_serial,
                        identity.file_index,
                        false,
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
    }
    let source_admissions = Arc::new(Mutex::new(Arc::new(registry)));
    let generation = 1;
    let manager = ProviderManager::new();
    manager
        .install_folders(windows_folder_sync::Setup {
            source_admissions: windows_folder_sync::SourceAdmissions::Broker {
                profile: profile.into(),
                registry: source_admissions.clone(),
            },
            generation,
            scope,
            account_id: account_id.clone(),
            origin: client.server_origin().unwrap(),
            client,
            spaces,
            directory: PrivateDirectory::create_or_open_under(&parent, OsStr::new("engine-state"))
                .unwrap(),
            cloud_root: None,
        })
        .unwrap();
    let installed_at = std::time::Instant::now();
    assert!(!manager.is_connected());
    manager
        .folder_request(
            generation,
            FolderRequest::Add(FolderPair {
                id: "disabled-background-pair".into(),
                local_path: ordinary.clone(),
                space_id: space_id.clone(),
                vault: None,
                remote_path: "/RecoveryRoot".into(),
                mode: SyncMode::DownloadOnly,
                excluded_paths: vec![],
                content_filter: raiun_core::MediaFilter::All,
                exclusions: Vec::new(),
            }),
        )
        .unwrap();
    let request = |request| manager.folder_request(generation, FolderRequest::Media(request));
    let destination = request(MediaRequest::Destination {
        space_id: space_id.clone(),
        path: "/RecoveryRoot".into(),
    })
    .unwrap();
    let job = MediaImportJob {
        id: "media-worker".into(),
        revision: 0,
        account_id: account_id.clone(),
        source_root: source.clone(),
        space_id,
        destination_root: "/RecoveryRoot".into(),
        destination_root_resource_id: destination["id"].as_str().unwrap().into(),
        filter: MediaFilter::All,
        exclusions: Vec::new(),
        organization: MediaOrganization::PreserveRelativePath,
        filesystem_mtime_utc: false,
        interval_seconds: 3600,
        enabled: true,
    };
    let saved = request(MediaRequest::Set {
        job,
        expected_revision: 0,
        expected_account_id: account_id.clone(),
    })
    .unwrap();
    let job: MediaImportJob = serde_json::from_value(saved["job"].clone()).unwrap();
    assert_eq!(job.revision, 1);
    let accepted = request(MediaRequest::Run {
        job_id: job.id.clone(),
        expected_revision: job.revision,
        expected_account_id: account_id.clone(),
    })
    .unwrap();
    assert_eq!(
        accepted,
        json!({"accepted":true,"job_id":job.id,"revision":job.revision,"queued":true})
    );
    // Pairs is a same-thread barrier, unlike the queued ACK.
    manager
        .folder_request(generation, FolderRequest::Pairs)
        .unwrap();
    assert!(manager.folder_error.lock().unwrap().is_none());
    let first = request(MediaRequest::Status {
        job_id: job.id.clone(),
    })
    .unwrap();
    assert_eq!(first["status"]["uploaded"], 0);
    assert_eq!(first["status"]["waiting_for_stability"], 1);
    assert_eq!(fixture.recovery.lock().unwrap().put_count, 0);
    std::thread::sleep(Duration::from_secs(
        raiun_engine::MEDIA_STABLE_FILE_SECONDS as u64,
    ));
    request(MediaRequest::Run {
        job_id: job.id.clone(),
        expected_revision: job.revision,
        expected_account_id: account_id.clone(),
    })
    .unwrap();
    manager
        .folder_request(generation, FolderRequest::Pairs)
        .unwrap();
    assert!(manager.folder_error.lock().unwrap().is_none());
    let status = request(MediaRequest::Status {
        job_id: job.id.clone(),
    })
    .unwrap();
    assert_eq!(status["status"]["uploaded"], 1);
    {
        let remote = fixture.recovery.lock().unwrap();
        assert!(remote.present);
        assert_eq!(remote.put_count, 1);
        assert_eq!(remote.body, bytes);
        assert!(remote.last_put_if_match.is_none());
        assert!(remote.get_count >= 1, "verified full readback occurred");
    }
    assert_eq!(std::fs::read(&source_file).unwrap(), bytes);
    // Reuse the earlier real stability wait; total wait is only ~31s from install.
    // The saved DownloadOnly pair would fetch this now-existing remote leaf if
    // the disabled ordinary background tick accidentally ran.
    std::thread::sleep(Duration::from_secs(31).saturating_sub(installed_at.elapsed()));
    manager
        .folder_request(generation, FolderRequest::Pairs)
        .unwrap();
    assert!(
        !ordinary.join("document.bin").exists(),
        "disabled folder background work must not transfer"
    );
    assert_eq!(fixture.recovery.lock().unwrap().put_count, 1);
    assert_eq!(std::fs::read(&source_file).unwrap(), bytes);
    manager
        .folder_request(generation, FolderRequest::Pause { paused: true })
        .unwrap();
    assert!(
        request(MediaRequest::Run {
            job_id: job.id.clone(),
            expected_revision: job.revision,
            expected_account_id: account_id.clone()
        })
        .is_err()
    );
    manager
        .folder_request(generation, FolderRequest::Pairs)
        .unwrap();
    assert_eq!(fixture.recovery.lock().unwrap().put_count, 1);
    let recovery = request(MediaRequest::Recovery {
        job_id: job.id.clone(),
        expected_revision: job.revision,
        expected_account_id: account_id.clone(),
        limit: 1,
        cursor: None,
    })
    .unwrap();
    assert_eq!(recovery["account_id"], account_id);
    assert_eq!(recovery["revision"], job.revision);
    assert!(recovery["page"]["items"].as_array().unwrap().is_empty());
    assert!(
        request(MediaRequest::Recovery {
            job_id: job.id,
            expected_revision: job.revision,
            expected_account_id: "other-account".into(),
            limit: 1,
            cursor: None
        })
        .is_err()
    );
    assert_eq!(std::fs::read(&source_file).unwrap(), bytes);
    assert_eq!(
        fixture.native_reads.lock().unwrap().mutation_attempt_count,
        0
    );
    manager.disconnect().unwrap();
    drop(manager);
    drop(parent);
    fixture.join().unwrap();
    // Reached only after complete success; panic preserves synthetic source/state.
    std::fs::remove_dir_all(root).unwrap();
}

use super::*;
use crate::folder_pairs::{AccountScope, FolderPairsStore};
use raiun_core::{
    CONFIG_SCHEMA_VERSION, Config, FolderPair, MediaFilter, MediaImportJob, MediaOrganization,
    SyncMode,
};
fn scope() -> AccountScope {
    AccountScope::new(
        "default".into(),
        "https://example.invalid/".into(),
        "client".into(),
        None,
        "subject".into(),
    )
    .unwrap()
}
fn config() -> Config {
    Config {
        schema_version: CONFIG_SCHEMA_VERSION,
        cloud_root: std::env::temp_dir().join("raiun-synthetic-offline-cloud-config"),
        pairs: vec![FolderPair {
            id: "pair".into(),
            local_path: std::env::temp_dir().join("raiun-synthetic-offline-pair-config"),
            space_id: "space".into(),
            remote_path: "/".into(),
            mode: SyncMode::TwoWay,
            vault: None,
            excluded_paths: vec![],
            content_filter: raiun_core::MediaFilter::All,
            exclusions: Vec::new(),
        }],
    }
}
fn job() -> MediaImportJob {
    MediaImportJob {
        id: "job".into(),
        revision: 0,
        account_id: "account".into(),
        source_root: std::env::temp_dir().join("raiun-synthetic-offline-media-config"),
        space_id: "space".into(),
        destination_root: "/Photos".into(),
        destination_root_resource_id: "destination".into(),
        filter: MediaFilter::Photos,
        exclusions: Vec::new(),
        organization: MediaOrganization::PreserveRelativePath,
        filesystem_mtime_utc: false,
        interval_seconds: 3600,
        enabled: true,
    }
}
// Windows recovery inspection requires the protected engine layout, including
// its local drive-absolute private state and media-staging directories.
fn open_fixture_engine(state_directory: &std::path::Path) -> Engine {
    #[cfg(windows)]
    {
        use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
        let parent = PinnedDirectory::open(state_directory.parent().unwrap()).unwrap();
        let directory =
            PrivateDirectory::create_or_open_under(&parent, state_directory.file_name().unwrap())
                .unwrap();
        Engine::open_private_windows(directory, Arc::new(FakeCloud::default())).unwrap()
    }
    #[cfg(not(windows))]
    {
        Engine::open(state_directory, Arc::new(FakeCloud::default())).unwrap()
    }
}

#[test]
fn jobs_legacy_reopen_and_pair_pause_retirement_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let state_directory = dir.path().join("state");
    let engine = open_fixture_engine(&state_directory);
    let store = FolderPairsStore::new(engine.clone(), scope()).unwrap();
    let created = store.create(config()).unwrap();
    let old = created.encode().unwrap();
    let mut legacy: serde_json::Value = serde_json::from_slice(&old).unwrap();
    legacy.as_object_mut().unwrap().remove("media_jobs");
    engine
        .compare_exchange_folder_pair_document(
            &serde_json::to_vec(&scope()).unwrap(),
            Some(&old),
            &serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
    assert!(store.load().unwrap().unwrap().media_jobs().is_empty());
    store.set_pause(0, true, vec!["space".into()]).unwrap();
    let saved = store.set_media_job(1, 0, job()).unwrap();
    assert_eq!(saved.config(), &config());
    assert!(saved.paused());
    assert_eq!(saved.media_jobs()[0].revision, 1);
    let mut empty = config();
    empty.pairs.clear();
    store.replace(2, empty.clone()).unwrap();
    drop(store);
    drop(engine);
    let store = FolderPairsStore::new(open_fixture_engine(&state_directory), scope()).unwrap();
    let saved = store.load().unwrap().unwrap();
    assert_eq!(saved.retired_pair_ids(), &["pair"]);
    assert_eq!(saved.media_jobs().len(), 1);
    assert!(saved.paused());
    assert_eq!(saved.paused_space_ids(), &["space"]);
    let removed = store.remove_media_job(3, "job", 1).unwrap();
    assert!(removed.media_jobs().is_empty());
    assert_eq!(removed.config(), &empty);
    assert_eq!(removed.retired_pair_ids(), &["pair"]);
    assert!(removed.paused());
}
#[test]
fn job_updates_and_removal_reject_stale_and_invalid_without_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let state_directory = dir.path().join("state");
    let a = FolderPairsStore::new(open_fixture_engine(&state_directory), scope()).unwrap();
    let b = FolderPairsStore::new(open_fixture_engine(&state_directory), scope()).unwrap();
    a.create(config()).unwrap();
    a.set_media_job(0, 0, job()).unwrap();
    assert!(b.set_media_job(0, 0, job()).is_err());
    let mut changed = a.load().unwrap().unwrap().media_jobs()[0].clone();
    changed.enabled = false;
    a.set_media_job(1, 1, changed.clone()).unwrap();
    assert!(b.remove_media_job(1, "job", 1).is_err());
    assert!(b.remove_media_job(2, "job", 1).is_err());
    changed.revision = 2;
    changed.account_id = "other".into();
    assert!(b.set_media_job(2, 2, changed).is_err());
    let mut invalid = job();
    invalid.id = "invalid".into();
    invalid.interval_seconds = 0;
    assert!(b.set_media_job(2, 0, invalid).is_err());
    let saved = b.load().unwrap().unwrap();
    assert_eq!(saved.revision(), 2);
    assert_eq!(saved.media_jobs()[0].revision, 2);
    assert!(!saved.media_jobs()[0].enabled);
    assert_eq!(saved.config(), &config());
}

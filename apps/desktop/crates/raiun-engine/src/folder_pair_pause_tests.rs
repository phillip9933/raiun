use super::*;
use crate::folder_pairs::{AccountScope, FolderPairsStore};
use raiun_core::{CONFIG_SCHEMA_VERSION, Config, FolderPair, SyncMode};

fn scope() -> AccountScope {
    AccountScope::new(
        "default".into(),
        "https://example.invalid/".into(),
        "desktop".into(),
        None,
        "alice".into(),
    )
    .unwrap()
}
fn config() -> Config {
    Config {
        schema_version: CONFIG_SCHEMA_VERSION,
        cloud_root: "Z:\\offline-cloud".into(),
        pairs: vec![FolderPair {
            id: "pair".into(),
            local_path: "Z:\\offline-local".into(),
            space_id: "space".into(),
            remote_path: "/".into(),
            mode: SyncMode::TwoWay,
            vault: None,
            excluded_paths: vec!["private".into()],
        }],
    }
}
#[test]
fn typed_pause_legacy_defaults_and_reopen_preserve_config_and_retirement() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let engine = Engine::open(&state, Arc::new(FakeCloud::default())).unwrap();
    let store = FolderPairsStore::new(engine.clone(), scope()).unwrap();
    let document = store.create(config()).unwrap();
    // Restore an actual legacy v1 document through the exact opaque-byte CAS.
    let old = document.encode().unwrap();
    let mut legacy: serde_json::Value = serde_json::from_slice(&old).unwrap();
    legacy.as_object_mut().unwrap().remove("paused");
    legacy.as_object_mut().unwrap().remove("paused_space_ids");
    let scope_bytes = serde_json::to_vec(&scope()).unwrap();
    engine
        .compare_exchange_folder_pair_document(
            &scope_bytes,
            Some(&old),
            &serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
    let restored = store.load().unwrap().unwrap();
    assert!(!restored.paused());
    assert!(restored.paused_space_ids().is_empty());
    let paused = store.set_pause(0, true, vec!["space".into()]).unwrap();
    assert_eq!(paused.config(), &config());
    assert_eq!(paused.revision(), 1);
    let mut empty = config();
    empty.pairs.clear();
    store.replace(1, empty.clone()).unwrap();
    drop(store);
    drop(engine);
    let reopened = FolderPairsStore::new(
        Engine::open(&state, Arc::new(FakeCloud::default())).unwrap(),
        scope(),
    )
    .unwrap();
    let retained = reopened.load().unwrap().unwrap();
    assert!(retained.paused());
    assert_eq!(retained.paused_space_ids(), &["space"]);
    assert_eq!(retained.config(), &empty);
    assert_eq!(retained.retired_pair_ids(), &["pair"]);
    let resumed = reopened.set_pause(2, false, vec![]).unwrap();
    assert!(!resumed.paused());
    assert_eq!(resumed.config(), &empty);
    assert_eq!(resumed.retired_pair_ids(), &["pair"]);
    assert!(reopened.replace(3, config()).is_err());
}
#[test]
fn typed_pause_second_handle_stale_and_invalid_updates_preserve_saved_state() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let a = FolderPairsStore::new(
        Engine::open(&state, Arc::new(FakeCloud::default())).unwrap(),
        scope(),
    )
    .unwrap();
    let b = FolderPairsStore::new(
        Engine::open(&state, Arc::new(FakeCloud::default())).unwrap(),
        scope(),
    )
    .unwrap();
    a.create(config()).unwrap();
    a.set_pause(0, true, vec!["space".into()]).unwrap();
    assert!(b.set_pause(0, false, vec![]).is_err());
    assert!(
        b.set_pause(1, false, vec!["duplicate".into(), "duplicate".into()])
            .is_err()
    );
    assert!(b.set_pause(1, false, vec!["x".repeat(513)]).is_err());
    let retained = b.load().unwrap().unwrap();
    assert!(retained.paused());
    assert_eq!(retained.revision(), 1);
    assert_eq!(retained.config(), &config());
    assert_eq!(retained.paused_space_ids(), &["space"]);
    assert_eq!(b.set_pause(1, false, vec![]).unwrap().revision(), 2);
    assert!(!a.load().unwrap().unwrap().paused());
}

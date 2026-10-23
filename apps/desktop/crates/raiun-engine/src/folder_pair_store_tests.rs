use super::*;
use crate::folder_pairs::{AccountScope, FolderPairsStore};
use raiun_core::{CONFIG_SCHEMA_VERSION, Config, FolderPair, SyncMode};
fn scope(subject: &str) -> AccountScope {
    AccountScope::new(
        "default".into(),
        "https://example.invalid/".into(),
        "desktop".into(),
        None,
        subject.into(),
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
            excluded_paths: vec![],
        }],
    }
}
#[test]
fn typed_create_reopen_and_scope_isolation() {
    let dir = tempfile::tempdir().unwrap();
    let state_directory = dir.path().join("state");
    let store = FolderPairsStore::new(
        Engine::open(&state_directory, Arc::new(FakeCloud::default())).unwrap(),
        scope("alice"),
    )
    .unwrap();
    assert!(store.load().unwrap().is_none());
    assert_eq!(store.create(config()).unwrap().revision(), 0);
    drop(store);
    let engine = Engine::open(&state_directory, Arc::new(FakeCloud::default())).unwrap();
    let store = FolderPairsStore::new(engine.clone(), scope("alice")).unwrap();
    assert_eq!(store.load().unwrap().unwrap().config(), &config());
    assert!(store.create(config()).is_err());
    let other = FolderPairsStore::new(engine, scope("bob")).unwrap();
    assert!(other.load().is_err());
    assert!(other.create(config()).is_err());
    assert!(other.replace(0, config()).is_err());
    assert_eq!(store.load().unwrap().unwrap().revision(), 0);
}
#[test]
fn stale_revision_and_retired_id_survive_second_handle_restart() {
    let dir = tempfile::tempdir().unwrap();
    let state_directory = dir.path().join("state");
    let a = FolderPairsStore::new(
        Engine::open(&state_directory, Arc::new(FakeCloud::default())).unwrap(),
        scope("alice"),
    )
    .unwrap();
    a.create(config()).unwrap();
    let b = FolderPairsStore::new(
        Engine::open(&state_directory, Arc::new(FakeCloud::default())).unwrap(),
        scope("alice"),
    )
    .unwrap();
    let stale = b.load().unwrap().unwrap().revision();
    let mut removed = config();
    removed.pairs.clear();
    assert_eq!(a.replace(0, removed.clone()).unwrap().revision(), 1);
    assert!(b.replace(stale, config()).is_err());
    drop(a);
    drop(b);
    let c = FolderPairsStore::new(
        Engine::open(&state_directory, Arc::new(FakeCloud::default())).unwrap(),
        scope("alice"),
    )
    .unwrap();
    assert_eq!(c.load().unwrap().unwrap().retired_pair_ids(), &["pair"]);
    assert!(c.replace(1, config()).is_err());
    assert_eq!(c.replace(1, removed).unwrap().revision(), 2);
}

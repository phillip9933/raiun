use super::*;

#[test]
fn revocation_handle_crosses_thread_without_moving_engine_and_fences_sync() {
    let (_state, _local_parent, cloud, engine, pair) = setup();
    let local = pair.local_path.join("must-not-upload.txt");
    let expected = b"retained ordinary local bytes";
    fs::write(&local, expected).unwrap();
    let cloud_before = cloud
        .entries
        .lock()
        .unwrap()
        .iter()
        .map(|(path, (_, bytes))| (path.clone(), bytes.clone()))
        .collect::<BTreeMap<_, _>>();
    let handle = engine.revocation_handle();
    assert!(!handle.is_revoked());
    let observation = handle.clone();
    // The closure owns only the cancellation handle; Engine/DbOwner stays here.
    std::thread::spawn(move || handle.revoke()).join().unwrap();
    assert!(observation.is_revoked());
    let error = engine
        .sync_pair(&pair)
        .expect_err("revoked sync must refuse");
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert_eq!(fs::read(&local).unwrap(), expected);
    assert!(cloud.bytes("/sync/must-not-upload.txt").is_none());
    let cloud_after = cloud
        .entries
        .lock()
        .unwrap()
        .iter()
        .map(|(path, (_, bytes))| (path.clone(), bytes.clone()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(cloud_after, cloud_before);
    assert_eq!(*cloud.delete_calls.lock().unwrap(), 0);
}

//! Windows inventory tests for versioned download-stage reservations.

use super::*;
use raiun_control_windows::{PinnedDirectory, PinnedPrivateFile};
use std::ffi::OsStr;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

fn store(state: &Path, max_bytes: u64, max_objects: usize) -> WindowsBlobStore {
    let parent = PinnedDirectory::open(state).unwrap();
    WindowsBlobStore {
        max_bytes,
        max_objects,
        directory: Arc::new(
            PrivateDirectory::create_or_open_under(&parent, OsStr::new("blobs")).unwrap(),
        ),
    }
}

fn reservation_name(nonce: u128, promised: u64) -> String {
    format!(".stage-v1-{nonce:032x}-{promised:016x}")
}

fn inventory(store: &WindowsBlobStore) -> StorageInventory {
    let lease = store.publication_lease().unwrap();
    store.inventory(&lease, &BTreeSet::new()).unwrap()
}

fn create_reservation<'a>(store: &'a WindowsBlobStore, name: &str) -> PinnedPrivateFile<'a> {
    store
        .directory
        .create_new_pinned_file(OsStr::new(name))
        .unwrap()
}

#[test]
fn zero_length_reservation_is_charged_before_first_chunk_and_after_reopen() {
    let state = tempfile::tempdir().unwrap();
    let name = reservation_name(1, 13);
    let mut store = store(state.path(), 32, 8);
    let mut writer = create_reservation(&store, &name);

    let before_chunk = inventory(&store);
    assert_eq!(before_chunk.physical_bytes, 13);
    assert_eq!(before_chunk.unindexed_bytes, 13);
    assert_eq!(writer.seek(SeekFrom::End(0)).unwrap(), 0);
    drop(writer);
    drop(store);

    store = self::store(state.path(), 32, 8);
    let after_reopen = inventory(&store);
    assert_eq!(after_reopen.physical_bytes, 13);
    assert_eq!(after_reopen.unindexed_bytes, 13);
    assert_eq!(
        std::fs::metadata(store.directory.path().join(name))
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn live_pinned_writer_can_be_inventoried_and_charge_is_max_of_promise_and_eof() {
    let state = tempfile::tempdir().unwrap();
    let store = store(state.path(), 64, 8);
    let name = reservation_name(2, 5);
    let mut writer = create_reservation(&store, &name);

    writer.write_all(b"123").unwrap();
    writer.flush().unwrap();
    let promise_larger_than_eof = inventory(&store);
    assert_eq!(promise_larger_than_eof.physical_bytes, 5);
    assert_eq!(promise_larger_than_eof.unindexed_bytes, 5);

    writer.write_all(b"4567").unwrap();
    writer.flush().unwrap();
    let larger_eof = inventory(&store);
    assert_eq!(larger_eof.physical_bytes, 7);
    assert_eq!(larger_eof.unindexed_bytes, 7);
    assert_eq!(writer.seek(SeekFrom::End(0)).unwrap(), 7);
    drop(writer);
    assert_eq!(
        std::fs::read(store.directory.path().join(name)).unwrap(),
        b"1234567"
    );
}

#[test]
fn malformed_and_oversized_reservations_fail_inventory_without_deletion() {
    let malformed_state = tempfile::tempdir().unwrap();
    let malformed_store = store(malformed_state.path(), 64, 8);
    let malformed_name = ".stage-v1-not-a-valid-reservation";
    drop(create_reservation(&malformed_store, malformed_name));
    assert!(matches!(
        malformed_store
            .publication_lease()
            .and_then(|lease| { malformed_store.inventory(&lease, &BTreeSet::new()) }),
        Err(CacheError::InvalidEntry)
    ));
    assert!(
        malformed_store
            .directory
            .path()
            .join(malformed_name)
            .is_file()
    );

    let oversized_state = tempfile::tempdir().unwrap();
    let oversized_store = store(oversized_state.path(), 64, 8);
    let oversized_name = reservation_name(3, MAX_CONTENT_BYTES + 1);
    drop(create_reservation(&oversized_store, &oversized_name));
    assert!(matches!(
        oversized_store
            .publication_lease()
            .and_then(|lease| { oversized_store.inventory(&lease, &BTreeSet::new()) }),
        Err(CacheError::LimitExceeded)
    ));
    assert!(
        oversized_store
            .directory
            .path()
            .join(oversized_name)
            .is_file()
    );
}

#[test]
fn multiple_promised_reservations_block_publication_and_preserve_stage_bytes() {
    let state = tempfile::tempdir().unwrap();
    let store = store(state.path(), 12, 8);
    let first_name = reservation_name(4, 8);
    let second_name = reservation_name(5, 8);
    let mut first = create_reservation(&store, &first_name);
    first.write_all(b"one").unwrap();
    first.flush().unwrap();
    drop(first);
    let mut second = create_reservation(&store, &second_name);
    second.write_all(b"two!").unwrap();
    second.flush().unwrap();
    drop(second);

    let before = inventory(&store);
    assert_eq!(before.physical_bytes, 16);
    assert_eq!(before.unindexed_bytes, 16);
    let key = format!("{}.blob", "a".repeat(64));
    assert!(matches!(
        store.publish(&key, &mut &b"x"[..], 1),
        Err(CacheError::InsufficientSpace)
    ));
    assert!(!store.directory.path().join(key).exists());
    assert_eq!(
        std::fs::read(store.directory.path().join(first_name)).unwrap(),
        b"one"
    );
    assert_eq!(
        std::fs::read(store.directory.path().join(second_name)).unwrap(),
        b"two!"
    );
    let after = inventory(&store);
    assert_eq!(after.physical_bytes, before.physical_bytes);
    assert_eq!(after.unindexed_bytes, before.unindexed_bytes);
}

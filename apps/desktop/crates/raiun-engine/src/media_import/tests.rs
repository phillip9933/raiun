use super::*;
use raiun_core::backend::{CloudBackend, CloudSpace};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

#[derive(Default)]
struct FakeCloud {
    entries: Mutex<HashMap<String, (RemoteEntry, Vec<u8>)>>,
    uploads: Mutex<Vec<(String, WriteCondition)>>,
    lose_upload_response: Mutex<bool>,
    mutate_source_after_upload: Mutex<Option<(PathBuf, Vec<u8>)>>,
    etag_counter: Mutex<u64>,
}

impl FakeCloud {
    fn new() -> Self {
        let backend = Self::default();
        backend.insert_dir("/Photos");
        backend
    }

    fn insert_dir(&self, path: &str) {
        let entry = RemoteEntry {
            id: format!("id:{path}"),
            path: path.to_owned(),
            directory: true,
            size: 0,
            etag: format!("etag:{path}:1"),
            modified_unix: 1,
            writable: true,
            encrypted: false,
        };
        self.entries
            .lock()
            .expect("entries lock")
            .insert(path.to_owned(), (entry, Vec::new()));
    }

    fn current(&self, path: &str) -> Result<RemoteEntry, CloudError> {
        self.entries
            .lock()
            .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?
            .get(path)
            .map(|value| value.0.clone())
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "not found"))
    }

    fn file_bytes(&self, path: &str) -> Option<Vec<u8>> {
        self.entries
            .lock()
            .ok()?
            .get(path)
            .map(|value| value.1.clone())
    }
}

impl CloudBackend for FakeCloud {
    fn server_origin(&self) -> Option<String> {
        Some("https://cloud.example".into())
    }

    fn spaces(&self) -> Result<Vec<CloudSpace>, CloudError> {
        Ok(vec![CloudSpace {
            id: "space-1".into(),
            name: "Photos".into(),
            dav_url: "https://cloud.example/dav/photos".into(),
            personal: false,
            writable: true,
            encrypted: false,
        }])
    }

    fn list(
        &self,
        _space: &str,
        _path: &str,
        _visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
    ) -> Result<(), CloudError> {
        Ok(())
    }

    fn stat(&self, _space: &str, path: &str) -> Result<RemoteEntry, CloudError> {
        self.current(path)
    }

    fn download(
        &self,
        _space: &str,
        path: &str,
        expected_etag: Option<&str>,
        destination: &Path,
    ) -> Result<RemoteEntry, CloudError> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?;
        let (entry, bytes) = entries
            .get(path)
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "not found"))?;
        if expected_etag.is_some_and(|expected| expected != entry.etag) {
            return Err(CloudError::new(ErrorKind::Conflict, "etag changed"));
        }
        fs::write(destination, bytes).map_err(io_error)?;
        Ok(entry.clone())
    }

    fn upload(
        &self,
        _space: &str,
        path: &str,
        source: &Path,
        condition: WriteCondition,
    ) -> Result<RemoteEntry, CloudError> {
        self.uploads
            .lock()
            .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?
            .push((path.to_owned(), condition.clone()));
        let bytes = fs::read(source).map_err(io_error)?;
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?;
        match (&condition, entries.get(path)) {
            (WriteCondition::Absent, Some(_)) => {
                return Err(CloudError::new(ErrorKind::Conflict, "destination exists"));
            }
            (WriteCondition::Match(expected), Some((current, _))) if current.etag == *expected => {}
            (WriteCondition::Match(_), _) => {
                return Err(CloudError::new(ErrorKind::Conflict, "destination changed"));
            }
            (WriteCondition::Absent, None) => {}
        }
        let parent = path
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .unwrap_or("");
        if !entries
            .get(parent)
            .is_some_and(|(entry, _)| entry.directory)
        {
            return Err(CloudError::new(ErrorKind::NotFound, "parent not found"));
        }
        let mut counter = self
            .etag_counter
            .lock()
            .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?;
        *counter += 1;
        let entry = RemoteEntry {
            id: entries
                .get(path)
                .map(|(entry, _)| entry.id.clone())
                .unwrap_or_else(|| format!("id:{path}")),
            path: path.to_owned(),
            directory: false,
            size: bytes.len() as u64,
            etag: format!("etag:{path}:{}", *counter),
            modified_unix: *counter as i64,
            writable: true,
            encrypted: false,
        };
        entries.insert(path.to_owned(), (entry.clone(), bytes));
        drop(entries);
        if let Some((source, replacement)) = self
            .mutate_source_after_upload
            .lock()
            .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?
            .take()
        {
            fs::write(source, replacement).map_err(io_error)?;
        }
        if std::mem::take(
            &mut *self
                .lose_upload_response
                .lock()
                .map_err(|_| CloudError::new(ErrorKind::Io, "poisoned"))?,
        ) {
            return Err(CloudError::new(
                ErrorKind::Offline,
                "response lost after remote commit",
            ));
        }
        Ok(entry)
    }

    fn mkdir(&self, _space: &str, path: &str) -> Result<RemoteEntry, CloudError> {
        if self.current(path).is_ok() {
            return Err(CloudError::new(ErrorKind::Conflict, "exists"));
        }
        let parent = path
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .unwrap_or("");
        if !self.current(parent)?.directory {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "parent is not a directory",
            ));
        }
        self.insert_dir(path);
        self.current(path)
    }

    fn delete(&self, _space: &str, _path: &str, _expected_etag: &str) -> Result<(), CloudError> {
        Err(CloudError::new(ErrorKind::Unsupported, "not used"))
    }

    fn rename(
        &self,
        _space: &str,
        _from: &str,
        _to: &str,
        _expected_etag: &str,
    ) -> Result<RemoteEntry, CloudError> {
        Err(CloudError::new(ErrorKind::Unsupported, "not used"))
    }
}

fn job(root: &Path) -> MediaImportJob {
    MediaImportJob {
        id: "phone-import".into(),
        revision: 1,
        account_id: "account-1".into(),
        source_root: root.to_path_buf(),
        space_id: "space-1".into(),
        destination_root: "/Photos".into(),
        destination_root_resource_id: "id:/Photos".into(),
        filter: raiun_core::MediaFilter::Photos,
        organization: raiun_core::MediaOrganization::PreserveRelativePath,
        filesystem_mtime_utc: false,
        interval_seconds: 3600,
        enabled: true,
    }
}

fn engine(state: &TempDir, cloud: &Arc<FakeCloud>) -> Engine {
    Engine::open(state.path(), cloud.clone())
        .expect("engine")
        .with_account_scope("account-1".into(), "https://cloud.example".into())
        .expect("account scope")
}

fn image_source(root: &Path, bytes: &[u8]) {
    fs::create_dir_all(root.join("Camera")).expect("source folder");
    fs::write(root.join("Camera/photo.jpg"), bytes).expect("source file");
}

#[test]
fn recovery_pages_are_bounded_and_continue_after_the_exact_last_key() {
    let state = TempDir::new().expect("state");
    let cloud = Arc::new(FakeCloud::new());
    let engine = engine(&state, &cloud);
    {
        let db = engine.db().expect("db");
        for name in ["a.jpg", "b.jpg"] {
            db.execute(
                "INSERT INTO media_upload_stages(job_id,account_id,origin,space_id,source_root,relative_path,destination_path,attempt_generation,staged_path,staged_size) VALUES('phone-import','account-1','https://cloud.example','space-1','/source','Camera/'||?1,'/Photos/Camera/'||?1,1,'/stage/'||?1,12)",
                [name],
            )
            .expect("orphan stage fixture");
        }
    }

    let first =
        Engine::media_import_recovery_at(state.path(), "phone-import", "account-1", 1, None)
            .expect("first recovery page");
    assert_eq!(first.items.len(), 1);
    assert_eq!(first.items[0].source_relative_path, "Camera/a.jpg");
    assert_eq!(first.items[0].state, "stage_only");
    assert!(!first.items[0].staged_copy_present);
    assert!(first.has_more);
    let second = Engine::media_import_recovery_at(
        state.path(),
        "phone-import",
        "account-1",
        1,
        first.next_cursor.as_ref(),
    )
    .expect("next recovery page");
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].source_relative_path, "Camera/b.jpg");
    assert!(!second.has_more);
    assert!(second.next_cursor.is_none());
}

#[test]
fn recovery_cursor_keeps_identical_paths_from_distinct_spaces_separate() {
    let state = TempDir::new().expect("state");
    let cloud = Arc::new(FakeCloud::new());
    let engine = engine(&state, &cloud);
    {
        let db = engine.db().expect("db");
        for space in ["space-a", "space-b"] {
            db.execute(
                "INSERT INTO media_upload_stages(job_id,account_id,origin,space_id,source_root,relative_path,destination_path,attempt_generation,staged_path,staged_size) VALUES('phone-import','account-1','https://cloud.example',?1,'/source','Camera/photo.jpg','/Photos/Camera/photo.jpg',1,?2,12)",
                params![space, format!("/stage/{space}")],
            )
            .expect("orphan stage fixture");
        }
    }

    let first =
        Engine::media_import_recovery_at(state.path(), "phone-import", "account-1", 1, None)
            .expect("first page");
    assert_eq!(first.items.len(), 1);
    assert_eq!(first.items[0].space_id, "space-a");
    assert!(first.has_more);
    let cursor = first.next_cursor.as_ref().expect("next cursor");
    assert_eq!(cursor.origin, "https://cloud.example");
    assert_eq!(cursor.space_id, "space-a");

    let second = Engine::media_import_recovery_at(
        state.path(),
        "phone-import",
        "account-1",
        1,
        Some(cursor),
    )
    .expect("second page");
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].space_id, "space-b");
    assert_eq!(second.items[0].source_relative_path, "Camera/photo.jpg");
    assert!(!second.has_more);
    assert!(second.next_cursor.is_none());
}

#[test]
fn stable_media_import_verifies_receipts_and_updates_only_its_exact_remote_identity() {
    let source = TempDir::new().expect("source");
    let state = TempDir::new().expect("state");
    let cloud = Arc::new(FakeCloud::new());
    let engine = engine(&state, &cloud);
    let import_job = job(source.path());
    let bytes = [0xff, 0xd8, 0xff, 0x00, 0x10];
    image_source(source.path(), &bytes);

    let first = engine
        .run_media_import_job_at(&import_job, 100)
        .expect("first scan");
    assert_eq!(first.waiting_for_stability, 1);
    assert_eq!(cloud.uploads.lock().expect("uploads").len(), 0);
    let second = engine
        .run_media_import_job_at(&import_job, 111)
        .expect("stable upload");
    assert_eq!(second.uploaded, 1);
    assert_eq!(
        cloud.file_bytes("/Photos/Camera/photo.jpg"),
        Some(bytes.to_vec())
    );
    let receipt = engine
        .media_import_receipt(&import_job, "Camera/photo.jpg", "/Photos/Camera/photo.jpg")
        .expect("receipt query")
        .expect("verified receipt");
    assert_eq!(
        receipt.source_sha256,
        format!("{:x}", Sha256::digest(bytes))
    );
    assert_eq!(
        fs::read(source.path().join("Camera/photo.jpg")).expect("source remains"),
        bytes
    );

    let third = engine
        .run_media_import_job_at(&import_job, 122)
        .expect("repeat scan");
    assert_eq!(third.unchanged, 1);
    assert_eq!(cloud.uploads.lock().expect("uploads").len(), 1);

    let changed = [0xff, 0xd8, 0xff, 0x11, 0x22, 0x33];
    fs::write(source.path().join("Camera/photo.jpg"), changed).expect("edit source");
    assert_eq!(
        engine
            .run_media_import_job_at(&import_job, 133)
            .unwrap()
            .waiting_for_stability,
        1
    );
    assert_eq!(
        engine
            .run_media_import_job_at(&import_job, 144)
            .unwrap()
            .uploaded,
        1
    );
    let uploads = cloud.uploads.lock().expect("uploads");
    assert_eq!(uploads.len(), 2);
    assert_eq!(uploads[1].1, WriteCondition::Match(receipt.remote_etag));
    assert_eq!(
        cloud.file_bytes("/Photos/Camera/photo.jpg"),
        Some(changed.to_vec())
    );
}

#[test]
fn cancelled_media_pass_is_interrupted_and_preserves_its_source() {
    let source = TempDir::new().expect("source");
    let state = TempDir::new().expect("state");
    let cloud = Arc::new(FakeCloud::new());
    let engine = engine(&state, &cloud);
    let import_job = job(source.path());
    let bytes = [0xff, 0xd8, 0xff, 0x41, 0x42];
    image_source(source.path(), &bytes);

    let result = engine.run_media_import_job_cancellable(&import_job, &|| true);
    assert_eq!(result.unwrap_err().kind, ErrorKind::Offline);
    assert_eq!(cloud.uploads.lock().expect("uploads").len(), 0);
    assert_eq!(
        fs::read(source.path().join("Camera/photo.jpg")).expect("source remains"),
        bytes
    );
    let status = engine
        .media_import_status(&import_job.id)
        .expect("status query")
        .expect("durable status");
    assert_eq!(status.state, "interrupted");
    assert!(
        !engine
            .media_import_has_unresolved(&import_job.id)
            .expect("unresolved query")
    );
}

#[test]
fn crash_orphaned_stage_is_accounted_and_blocks_job_removal() {
    let state = TempDir::new().expect("state");
    let cloud = Arc::new(FakeCloud::new());
    let engine = engine(&state, &cloud);
    let staging = state.path().join("media-staging");
    fs::create_dir(&staging).expect("staging directory");
    let orphan = staging.join("crash-orphan");
    fs::write(&orphan, b"retained staged bytes").expect("orphan stage");

    assert!(
        engine
            .media_import_has_unresolved("backup")
            .expect("unresolved query")
    );
    assert!(
        Engine::media_import_has_unresolved_at(state.path(), "backup")
            .expect("offline unresolved query")
    );
    assert_eq!(
        fs::read(orphan).expect("orphan preserved"),
        b"retained staged bytes"
    );
    assert_eq!(
        staging_directory_bytes(&staging).expect("quota accounting"),
        b"retained staged bytes".len() as u64
    );
}

#[test]
fn collision_is_never_overwritten_and_lost_response_stays_uncertain_across_restart() {
    let source = TempDir::new().expect("source");
    let state = TempDir::new().expect("state");
    let cloud = Arc::new(FakeCloud::new());
    let import_job = job(source.path());
    image_source(source.path(), &[0xff, 0xd8, 0xff, 1]);
    cloud.insert_dir("/Photos/Camera");
    // An unrelated file at the final path is not adopted as a media receipt.
    {
        let mut entries = cloud.entries.lock().expect("entries");
        entries.insert(
            "/Photos/Camera/photo.jpg".into(),
            (
                RemoteEntry {
                    id: "unrelated".into(),
                    path: "/Photos/Camera/photo.jpg".into(),
                    directory: false,
                    size: 4,
                    etag: "other-etag".into(),
                    modified_unix: 1,
                    writable: true,
                    encrypted: false,
                },
                b"keep".to_vec(),
            ),
        );
    }
    let collision_engine = engine(&state, &cloud);
    assert_eq!(
        collision_engine
            .run_media_import_job_at(&import_job, 100)
            .unwrap()
            .waiting_for_stability,
        1
    );
    assert_eq!(
        collision_engine
            .run_media_import_job_at(&import_job, 111)
            .unwrap()
            .conflicts,
        1
    );
    assert_eq!(
        cloud.file_bytes("/Photos/Camera/photo.jpg"),
        Some(b"keep".to_vec())
    );
    assert!(cloud.uploads.lock().expect("uploads").is_empty());
    drop(collision_engine);

    // A different job/path exercises a response lost after the server committed.
    let lost_source = TempDir::new().expect("lost source");
    let mut lost_job = job(lost_source.path());
    lost_job.id = "lost-response".into();
    image_source(lost_source.path(), &[0xff, 0xd8, 0xff, 9]);
    lost_job.destination_root = "/Photos/Lost".into();
    lost_job.destination_root_resource_id = "id:/Photos/Lost".into();
    cloud.insert_dir("/Photos/Lost");
    *cloud.lose_upload_response.lock().expect("lost flag") = true;
    let first_attempt_engine = engine(&state, &cloud);
    first_attempt_engine
        .run_media_import_job_at(&lost_job, 200)
        .expect("first lost scan");
    let report = first_attempt_engine
        .run_media_import_job_at(&lost_job, 211)
        .expect("ambiguous upload is reported");
    assert_eq!(report.needs_attention, 1);
    let recovery =
        Engine::media_import_recovery_at(state.path(), &lost_job.id, "account-1", 100, None)
            .expect("scoped recovery inspection");
    assert_eq!(recovery.items.len(), 1);
    let item = &recovery.items[0];
    assert_eq!(item.origin, "https://cloud.example");
    assert_eq!(item.space_id, "space-1");
    assert_eq!(item.source_relative_path, "Camera/photo.jpg");
    assert_eq!(item.destination_path, "/Photos/Lost/Camera/photo.jpg");
    assert_eq!(item.state, "uncertain");
    assert_eq!(item.configuration_revision, Some(1));
    assert_eq!(item.attempt_generation, Some(1));
    assert!(item.staged_copy_present);
    assert_eq!(item.staged_copy_size, Some(4));
    let debug = format!("{item:?}");
    assert!(!debug.contains("staged_path"));
    assert!(!debug.contains("source_sha256"));
    assert!(!debug.contains("remote_resource_id"));
    let wrong_account =
        Engine::media_import_recovery_at(state.path(), &lost_job.id, "other-account", 100, None)
            .expect("wrong account is an empty page");
    assert!(wrong_account.items.is_empty());
    let stage_count: i64 = first_attempt_engine
        .db()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM media_upload_stages", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(stage_count, 1);
    let staged_path: String = first_attempt_engine
        .db()
        .unwrap()
        .query_row(
            "SELECT staged_path FROM media_upload_stages LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(Path::new(&staged_path).is_file());
    drop(first_attempt_engine);

    let restarted = engine(&state, &cloud);
    let report = restarted
        .run_media_import_job_at(&lost_job, 222)
        .expect("restart does not replay");
    assert_eq!(report.needs_attention, 1);
    assert_eq!(
        cloud.file_bytes("/Photos/Lost/Camera/photo.jpg"),
        Some(vec![0xff, 0xd8, 0xff, 9])
    );
    assert_eq!(
        cloud
            .uploads
            .lock()
            .expect("uploads")
            .iter()
            .filter(|(path, _)| path == "/Photos/Lost/Camera/photo.jpg")
            .count(),
        1
    );
    assert_eq!(
        fs::read(lost_source.path().join("Camera/photo.jpg")).unwrap(),
        vec![0xff, 0xd8, 0xff, 9]
    );
}

#[test]
fn upload_uses_the_staged_signature_when_the_source_changes_during_transfer() {
    let source = TempDir::new().expect("source");
    let state = TempDir::new().expect("state");
    let cloud = Arc::new(FakeCloud::new());
    let import_job = job(source.path());
    let initial = vec![0xff, 0xd8, 0xff, 0x01, 0x02];
    let changed = vec![0xff, 0xd8, 0xff, 0x09, 0x08, 0x07];
    image_source(source.path(), &initial);
    let engine = engine(&state, &cloud);
    engine
        .run_media_import_job_at(&import_job, 100)
        .expect("first scan");
    *cloud
        .mutate_source_after_upload
        .lock()
        .expect("mutation hook") = Some((source.path().join("Camera/photo.jpg"), changed.clone()));
    let report = engine
        .run_media_import_job_at(&import_job, 111)
        .expect("upload returns attention");
    assert_eq!(report.needs_attention, 1);
    assert_eq!(cloud.file_bytes("/Photos/Camera/photo.jpg"), Some(initial));
    assert_eq!(
        fs::read(source.path().join("Camera/photo.jpg")).unwrap(),
        changed
    );
    assert!(
        engine
            .media_import_receipt(&import_job, "Camera/photo.jpg", "/Photos/Camera/photo.jpg")
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_replaced_destination_root_at_the_same_path_is_not_adopted() {
    let source = TempDir::new().expect("source");
    let state = TempDir::new().expect("state");
    let cloud = Arc::new(FakeCloud::new());
    let import_job = job(source.path());
    image_source(source.path(), &[0xff, 0xd8, 0xff, 1]);
    let engine = engine(&state, &cloud);
    engine
        .run_media_import_job_at(&import_job, 100)
        .expect("first scan");
    assert_eq!(
        engine
            .run_media_import_job_at(&import_job, 111)
            .unwrap()
            .uploaded,
        1
    );
    let upload_count = cloud.uploads.lock().expect("uploads").len();

    cloud
        .entries
        .lock()
        .unwrap()
        .get_mut("/Photos")
        .unwrap()
        .0
        .id = "replacement-root".into();
    let error = engine
        .run_media_import_job_at(&import_job, 122)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Forbidden);
    assert_eq!(cloud.uploads.lock().expect("uploads").len(), upload_count);
    assert_eq!(
        cloud.file_bytes("/Photos/Camera/photo.jpg"),
        Some(vec![0xff, 0xd8, 0xff, 1])
    );
}

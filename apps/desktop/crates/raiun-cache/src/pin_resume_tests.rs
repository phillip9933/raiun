use super::*;
use std::io::{Cursor, Read};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

const PIN_ID_CHILD_MARKER: &str = "RAIUN_CACHE_PIN_ID_CHILD";
const PIN_ID_CHILD_PATH: &str = "RAIUN_CACHE_PIN_ID_CHILD_PATH";
const PIN_ID_CHILD_MARKER_VALUE: &str = "fixture-v1";
const PIN_ID_CHILD_TIMEOUT: Duration = Duration::from_secs(15);
const PIN_ID_CHILD_OUTPUT_LIMIT: usize = 16 * 1024;
const PIN_ID_FIXTURE_ID: &str = "cross-process-file";
const PIN_ID_FIXTURE_PATH: &str = "/cross-process-file.bin";
const PIN_ID_FIXTURE_ETAG: &str = "cross-process-etag";
const PIN_ID_FIXTURE_BODY: &[u8] = b"cross-process fixture bytes";
const PIN_ID_FIXTURE_ROOT_PATH: &str = "/cross-process-stage";

fn cache() -> (tempfile::TempDir, Cache) {
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    set_private_dir(state.path()).unwrap();
    let cache = Cache::open(state.path(), 16 * 1024 * 1024).unwrap();
    (state, cache)
}

fn scope() -> CacheScope {
    CacheScope::new(
        "https://pin-resume.example.test/",
        "resume-account",
        "resume-space",
        "resume-root",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap()
}

fn other_scope() -> CacheScope {
    CacheScope::new(
        "https://pin-resume.example.test/",
        "other-account",
        "resume-space",
        "resume-root",
        ScopeProtection::PlaintextAllowed,
    )
    .unwrap()
}

fn entry(id: &str, path: &str, etag: &str, bytes: &[u8]) -> RemoteEntry {
    RemoteEntry {
        id: id.to_owned(),
        path: path.to_owned(),
        etag: etag.to_owned(),
        size: bytes.len() as u64,
        directory: false,
        modified_unix: 1,
        writable: true,
        encrypted: false,
    }
}

fn manifest(scope: &CacheScope, item: &RemoteEntry) -> Vec<PinManifestEntry> {
    vec![PinManifestEntry {
        parent_resource_id: scope.root_resource_id().to_owned(),
        entry: item.clone(),
    }]
}

fn publish_listing(cache: &Cache, scope: &CacheScope, item: &RemoteEntry, fetched: i64) {
    cache
        .publish_listing(
            scope,
            scope.root_resource_id(),
            &[CachedEntry {
                parent_resource_id: scope.root_resource_id().to_owned(),
                entry: item.clone(),
            }],
            fetched,
        )
        .unwrap();
}

fn version(item: &RemoteEntry) -> ContentVersion {
    ContentVersion {
        resource_id: item.id.clone(),
        etag: item.etag.clone(),
        protection: ContentProtection::Plaintext,
    }
}

fn publish_body(cache: &Cache, scope: &CacheScope, item: &RemoteEntry, body: &[u8]) {
    cache
        .publish_content(
            scope,
            &version(item),
            &mut Cursor::new(body),
            body.len() as u64,
            Retention::Recent,
        )
        .unwrap();
}

fn read_body(cache: &Cache, scope: &CacheScope, item: &RemoteEntry) -> Vec<u8> {
    let mut reader = cache.open_content(scope, &version(item)).unwrap();
    let mut body = Vec::new();
    reader.read_to_end(&mut body).unwrap();
    body
}

type RawItem = (String, String, String, String, String, i64, i64, i64);

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawPin {
    id: String,
    scope: String,
    root: String,
    path: String,
    state: i64,
    items: Vec<RawItem>,
}

fn raw_pin(cache: &Cache, pin_id: &str) -> RawPin {
    let db = cache.lock_db().unwrap();
    let (scope, root, path, state) = db
        .query_row(
            "SELECT scope_key,root_id,root_path,state FROM pins WHERE pin_id=?1",
            [pin_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .unwrap();
    let mut statement = db
        .prepare("SELECT resource_id,parent_id,name,path,etag,size,directory,encrypted FROM pin_items WHERE pin_id=?1 ORDER BY resource_id")
        .unwrap();
    let items = statement
        .query_map([pin_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    RawPin {
        id: pin_id.to_owned(),
        scope,
        root,
        path,
        state,
        items,
    }
}

fn pin_count(cache: &Cache) -> i64 {
    cache
        .lock_db()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM pins", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn exact_building_manifest_resumes_after_reopen_and_can_make_progress() {
    let (state, cache) = cache();
    let scope = scope();
    let body = b"verified bytes after reopening";
    let item = entry("file-a", "/file-a.bin", "etag-a", body);
    publish_listing(&cache, &scope, &item, 1);
    let original = cache
        .begin_pin_manifest_at_cancellable(
            &scope,
            scope.root_resource_id(),
            "/",
            &manifest(&scope, &item),
            || false,
        )
        .unwrap();
    assert_eq!(original.state, PinState::Building);
    drop(cache);

    let reopened = Cache::open(state.path(), 16 * 1024 * 1024).unwrap();
    let resumed = reopened
        .resume_pin_manifest_at_cancellable(
            &scope,
            &original.id,
            scope.root_resource_id(),
            "/",
            &manifest(&scope, &item),
            || false,
        )
        .unwrap();
    assert_eq!(resumed.id, original.id);
    assert_eq!(resumed.state, PinState::Building);
    assert_eq!(resumed.ready_content_count, 0);
    assert_eq!(resumed.required_content_count, 1);
    assert_eq!(pin_count(&reopened), 1, "resume must not allocate a pin");

    publish_body(&reopened, &scope, &item, body);
    let ready = reopened.refresh_pin(&original.id).unwrap();
    assert_eq!(ready.id, original.id);
    assert_eq!(ready.state, PinState::Ready);
    assert_eq!(ready.ready_content_count, 1);
    assert_eq!(read_body(&reopened, &scope, &item), body);
}

#[test]
fn changed_inputs_and_other_scope_cannot_rebind_building_pin() {
    let (_state, cache) = cache();
    let scope = scope();
    let body = b"durable but not ready";
    let item = entry("file-a", "/file-a.bin", "etag-a", body);
    publish_listing(&cache, &scope, &item, 1);
    let pin = cache
        .begin_pin_manifest_at_cancellable(
            &scope,
            scope.root_resource_id(),
            "/",
            &manifest(&scope, &item),
            || false,
        )
        .unwrap();
    publish_body(&cache, &scope, &item, body);
    let before = raw_pin(&cache, &pin.id);

    let mut changed_etag = item.clone();
    changed_etag.etag = "etag-b".to_owned();
    let mut changed_path = item.clone();
    changed_path.path = "/renamed.bin".to_owned();
    let mut changed_size = item.clone();
    changed_size.size += 1;
    for (root_path, changed) in [
        ("/renamed-root/", item.clone()),
        ("/", changed_etag),
        ("/", changed_path),
        ("/", changed_size),
    ] {
        let result = cache.resume_pin_manifest_at_cancellable(
            &scope,
            &pin.id,
            scope.root_resource_id(),
            root_path,
            &manifest(&scope, &changed),
            || false,
        );
        assert!(result.is_err(), "changed manifest/root path was accepted");
        assert_eq!(raw_pin(&cache, &pin.id), before);
    }

    let other = other_scope();
    publish_listing(&cache, &other, &item, 1);
    assert!(
        cache
            .resume_pin_manifest_at_cancellable(
                &other,
                &pin.id,
                other.root_resource_id(),
                "/",
                &manifest(&other, &item),
                || false,
            )
            .is_err()
    );
    assert_eq!(raw_pin(&cache, &pin.id), before);
    assert_eq!(pin_count(&cache), 1);
    assert_eq!(read_body(&cache, &scope, &item), body);
}

#[test]
fn resume_refuses_ready_or_stale_pins_without_changing_retained_bytes() {
    let (_state, cache) = cache();
    let scope = scope();
    let body = b"retained snapshot bytes";
    let item = entry("file-a", "/file-a.bin", "etag-a", body);
    publish_listing(&cache, &scope, &item, 1);
    let ready_pin = cache
        .begin_pin_manifest_at_cancellable(
            &scope,
            scope.root_resource_id(),
            "/",
            &manifest(&scope, &item),
            || false,
        )
        .unwrap();
    publish_body(&cache, &scope, &item, body);
    assert_eq!(
        cache.refresh_pin(&ready_pin.id).unwrap().state,
        PinState::Ready
    );
    let ready_before = raw_pin(&cache, &ready_pin.id);
    assert!(
        cache
            .resume_pin_manifest_at_cancellable(
                &scope,
                &ready_pin.id,
                scope.root_resource_id(),
                "/",
                &manifest(&scope, &item),
                || false,
            )
            .is_err()
    );
    assert_eq!(raw_pin(&cache, &ready_pin.id), ready_before);
    assert_eq!(read_body(&cache, &scope, &item), body);

    let stale_item = entry("file-b", "/file-b.bin", "etag-b", body);
    publish_listing(&cache, &scope, &stale_item, 2);
    let stale_pin = cache
        .begin_pin_manifest_at_cancellable(
            &scope,
            scope.root_resource_id(),
            "/",
            &manifest(&scope, &stale_item),
            || false,
        )
        .unwrap();
    publish_body(&cache, &scope, &stale_item, body);
    assert_eq!(
        cache.refresh_pin(&stale_pin.id).unwrap().state,
        PinState::Ready
    );
    // A newer complete listing invalidates both snapshots without deleting data.
    let changed = entry("file-b", "/file-b.bin", "etag-c", body);
    publish_listing(&cache, &scope, &changed, 3);
    let stale_before = raw_pin(&cache, &stale_pin.id);
    assert_eq!(stale_before.state, 2, "pin should be durably Stale");
    assert!(
        cache
            .resume_pin_manifest_at_cancellable(
                &scope,
                &stale_pin.id,
                scope.root_resource_id(),
                "/",
                &manifest(&scope, &stale_item),
                || false,
            )
            .is_err()
    );
    assert_eq!(raw_pin(&cache, &stale_pin.id), stale_before);
    assert_eq!(read_body(&cache, &scope, &stale_item), body);
}

#[test]
fn cancellation_preserves_pin_manifest_bytes_and_pin_count() {
    let (_state, cache) = cache();
    let scope = scope();
    let body = b"keep these bytes";
    let item = entry("file-a", "/file-a.bin", "etag-a", body);
    publish_listing(&cache, &scope, &item, 1);
    let pin = cache
        .begin_pin_manifest_at_cancellable(
            &scope,
            scope.root_resource_id(),
            "/",
            &manifest(&scope, &item),
            || false,
        )
        .unwrap();
    publish_body(&cache, &scope, &item, body);
    let before = raw_pin(&cache, &pin.id);
    let count_before = pin_count(&cache);

    let result = cache.resume_pin_manifest_at_cancellable(
        &scope,
        &pin.id,
        scope.root_resource_id(),
        "/",
        &manifest(&scope, &item),
        || true,
    );
    assert!(matches!(result, Err(CacheError::Cancelled)));
    assert_eq!(raw_pin(&cache, &pin.id), before);
    assert_eq!(pin_count(&cache), count_before);
    assert_eq!(read_body(&cache, &scope, &item), body);
}

#[test]
fn staging_resume_reuses_ready_id_without_rewriting_persisted_readiness() {
    let (_state, cache) = cache();
    let scope = scope();
    let body = b"verified staged content";
    let item = entry("file-a", "/file-a.bin", "etag-a", body);
    publish_listing(&cache, &scope, &item, 1);
    let staged = cache
        .begin_pin_manifest_at_cancellable(
            &scope,
            scope.root_resource_id(),
            "/",
            &manifest(&scope, &item),
            || false,
        )
        .unwrap();
    publish_body(&cache, &scope, &item, body);

    // The usual listing/readiness API can promote the staged record to Ready
    // before the operation has recovered its already-durable ID.
    let listed = cache.pins(&scope).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, staged.id);
    assert_eq!(listed[0].state, PinState::Ready);
    let persisted_before = raw_pin(&cache, &staged.id);
    assert_eq!(persisted_before.state, 1);

    let resumed = cache
        .resume_staging_pin_manifest_at_cancellable(
            &scope,
            &staged.id,
            scope.root_resource_id(),
            "/",
            &manifest(&scope, &item),
            || false,
        )
        .unwrap();
    assert_eq!(resumed.id, staged.id);
    assert_eq!(resumed.state, PinState::Building);
    assert_eq!(resumed.ready_content_count, 0);
    assert_eq!(resumed.required_content_count, 1);
    assert_eq!(raw_pin(&cache, &staged.id), persisted_before);
    assert_eq!(pin_count(&cache), 1);
    assert_eq!(read_body(&cache, &scope, &item), body);

    // Ordinary recovery still refuses Ready pins; the exception is scoped to
    // the explicitly identified staging snapshot above.
    assert!(matches!(
        cache.resume_pin_manifest_at_cancellable(
            &scope,
            &staged.id,
            scope.root_resource_id(),
            "/",
            &manifest(&scope, &item),
            || false,
        ),
        Err(CacheError::Conflict)
    ));
    assert_eq!(raw_pin(&cache, &staged.id), persisted_before);
    assert_eq!(read_body(&cache, &scope, &item), body);
}

#[test]
fn staging_resume_rejects_changed_or_stale_snapshot_and_cancellation_without_mutation() {
    let (_state, cache) = cache();
    let scope = scope();
    let body = b"preserve staged bytes";
    let item = entry("file-a", "/file-a.bin", "etag-a", body);
    publish_listing(&cache, &scope, &item, 1);
    let staged = cache
        .begin_pin_manifest_at_cancellable(
            &scope,
            scope.root_resource_id(),
            "/",
            &manifest(&scope, &item),
            || false,
        )
        .unwrap();
    publish_body(&cache, &scope, &item, body);
    assert_eq!(cache.pins(&scope).unwrap()[0].state, PinState::Ready);
    let ready_before = raw_pin(&cache, &staged.id);
    let count_before = pin_count(&cache);

    let mut changed_etag = item.clone();
    changed_etag.etag = "etag-changed".into();
    let mut changed_path = item.clone();
    changed_path.path = "/other.bin".into();
    let mut changed_size = item.clone();
    changed_size.size += 1;
    for changed in [changed_etag, changed_path, changed_size] {
        assert!(
            cache
                .resume_staging_pin_manifest_at_cancellable(
                    &scope,
                    &staged.id,
                    scope.root_resource_id(),
                    "/",
                    &manifest(&scope, &changed),
                    || false,
                )
                .is_err()
        );
        assert_eq!(raw_pin(&cache, &staged.id), ready_before);
    }

    let cancelled = cache.resume_staging_pin_manifest_at_cancellable(
        &scope,
        &staged.id,
        scope.root_resource_id(),
        "/",
        &manifest(&scope, &item),
        || true,
    );
    assert!(matches!(cancelled, Err(CacheError::Cancelled)));
    assert_eq!(raw_pin(&cache, &staged.id), ready_before);
    assert_eq!(pin_count(&cache), count_before);

    let current = entry("file-a", "/file-a.bin", "etag-new", body);
    publish_listing(&cache, &scope, &current, 2);
    let stale_before = raw_pin(&cache, &staged.id);
    assert_eq!(stale_before.state, 2);
    assert!(
        cache
            .resume_staging_pin_manifest_at_cancellable(
                &scope,
                &staged.id,
                scope.root_resource_id(),
                "/",
                &manifest(&scope, &item),
                || false,
            )
            .is_err()
    );
    assert_eq!(raw_pin(&cache, &staged.id), stale_before);
    assert_eq!(pin_count(&cache), count_before);
    assert_eq!(read_body(&cache, &scope, &item), body);
}

#[test]
fn initial_pin_rejects_duplicate_after_reopen_and_preserves_dirty_bytes() {
    let (state, cache) = cache();
    let scope = scope();
    let body = b"dirty bytes remain attached to the saved folder";
    let item = entry("file-a", "/file-a.bin", "etag-a", body);
    publish_listing(&cache, &scope, &item, 1);
    let original = cache
        .begin_initial_pin_manifest_at_cancellable(
            &scope,
            scope.root_resource_id(),
            "/",
            &manifest(&scope, &item),
            || false,
        )
        .unwrap();
    cache
        .publish_content(
            &scope,
            &version(&item),
            &mut Cursor::new(body),
            body.len() as u64,
            Retention::Dirty,
        )
        .unwrap();
    let before = raw_pin(&cache, &original.id);
    drop(cache);

    let reopened = Cache::open(state.path(), 16 * 1024 * 1024).unwrap();
    assert!(matches!(
        reopened.begin_initial_pin_manifest_at_cancellable(
            &scope,
            scope.root_resource_id(),
            "/",
            &manifest(&scope, &item),
            || false,
        ),
        Err(CacheError::Conflict)
    ));
    assert_eq!(raw_pin(&reopened, &original.id), before);
    assert_eq!(pin_count(&reopened), 1);
    assert_eq!(read_body(&reopened, &scope, &item), body);
    assert_eq!(
        reopened
            .content_record(&scope, &version(&item))
            .unwrap()
            .retention,
        Retention::Dirty
    );
}

#[test]
fn generic_pin_staging_remains_available_and_initial_cancellation_adds_nothing() {
    let (_state, cache) = cache();
    let scope = scope();
    let body = b"listed content";
    let item = entry("file-a", "/file-a.bin", "etag-a", body);
    publish_listing(&cache, &scope, &item, 1);

    let initial = cache
        .begin_initial_pin_manifest_at_cancellable(
            &scope,
            scope.root_resource_id(),
            "/",
            &manifest(&scope, &item),
            || false,
        )
        .unwrap();
    let staged = cache
        .begin_pin_manifest_at_cancellable(
            &scope,
            scope.root_resource_id(),
            "/alternate-stage",
            &manifest(&scope, &item),
            || false,
        )
        .unwrap();
    assert_ne!(initial.id, staged.id);
    assert_eq!(pin_count(&cache), 2);

    let before = pin_count(&cache);
    assert!(matches!(
        cache.begin_initial_pin_manifest_at_cancellable(
            &scope,
            "other-root",
            "/other",
            &manifest(&scope, &item),
            || true,
        ),
        Err(CacheError::Cancelled)
    ));
    assert_eq!(pin_count(&cache), before);
    assert_eq!(raw_pin(&cache, &initial.id).state, 0);
    assert_eq!(raw_pin(&cache, &staged.id).state, 0);
}

#[test]
fn concurrent_handles_admit_only_one_initial_pin_for_the_same_target() {
    let (state, cache) = cache();
    let scope = scope();
    let item = entry("file-a", "/file-a.bin", "etag-a", b"listed");
    publish_listing(&cache, &scope, &item, 1);
    // This checks concurrent pin admission through independent handles, not
    // concurrent database initialization. Prepare both fallible opens before
    // the barrier so a startup error cannot strand the remaining participants.
    let handles = (0..2)
        .map(|_| Cache::open(state.path(), 16 * 1024 * 1024).unwrap())
        .collect::<Vec<_>>();
    let start = Arc::new(Barrier::new(3));

    let workers = handles
        .into_iter()
        .map(|cache| {
            let barrier = Arc::clone(&start);
            let scope = scope.clone();
            let item = item.clone();
            std::thread::spawn(move || {
                barrier.wait();
                cache.begin_initial_pin_manifest_at_cancellable(
                    &scope,
                    scope.root_resource_id(),
                    "/",
                    &manifest(&scope, &item),
                    || false,
                )
            })
        })
        .collect::<Vec<_>>();
    start.wait();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(CacheError::Conflict)))
            .count(),
        1
    );
    assert_eq!(pin_count(&cache), 1);
}

fn pin_id_fixture_item() -> RemoteEntry {
    entry(
        PIN_ID_FIXTURE_ID,
        PIN_ID_FIXTURE_PATH,
        PIN_ID_FIXTURE_ETAG,
        PIN_ID_FIXTURE_BODY,
    )
}

type PinIdReader = std::thread::JoinHandle<(Vec<u8>, bool)>;
type PinIdChild = (Child, PinIdReader, PinIdReader);
type PinIdChildOutput = (ExitStatus, Vec<u8>, Vec<u8>);

fn read_bounded<R: Read + Send + 'static>(
    mut reader: R,
) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let mut output = Vec::with_capacity(PIN_ID_CHILD_OUTPUT_LIMIT);
        let mut truncated = false;
        let mut chunk = [0u8; 1024];
        loop {
            let count = match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(count) => count,
            };
            let available = PIN_ID_CHILD_OUTPUT_LIMIT.saturating_sub(output.len());
            let retained = available.min(count);
            output.extend_from_slice(&chunk[..retained]);
            truncated |= retained != count;
        }
        (output, truncated)
    })
}

fn spawn_pin_id_child(state_path: &Path) -> std::io::Result<PinIdChild> {
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "pin_resume_tests::pin_id_child_helper",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PIN_ID_CHILD_MARKER, PIN_ID_CHILD_MARKER_VALUE)
        .env(PIN_ID_CHILD_PATH, state_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("missing child stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("missing child stderr"))?;
    Ok((child, read_bounded(stdout), read_bounded(stderr)))
}

fn await_pin_id_children(
    mut children: Vec<PinIdChild>,
) -> Result<Vec<PinIdChildOutput>, &'static str> {
    let started = Instant::now();
    let mut statuses = vec![None; children.len()];
    while statuses.iter().any(Option::is_none) {
        for (index, (child, _, _)) in children.iter_mut().enumerate() {
            if statuses[index].is_none() {
                match child.try_wait() {
                    Ok(status) => statuses[index] = status,
                    Err(_) => return Err("pin ID child process status could not be established"),
                }
            }
        }
        if statuses.iter().all(Option::is_some) {
            break;
        }
        if started.elapsed() >= PIN_ID_CHILD_TIMEOUT {
            // The caller leaks the fixture on this error so a child of
            // uncertain state cannot observe a removed cache path.
            return Err("pin ID child process exceeded its bounded wait");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let outputs = children
        .into_iter()
        .enumerate()
        .map(|(index, (_, stdout, stderr))| {
            let (stdout, stdout_truncated) = stdout.join().unwrap();
            let (stderr, stderr_truncated) = stderr.join().unwrap();
            assert!(
                !stdout_truncated && !stderr_truncated,
                "pin ID child output exceeded its bound"
            );
            (statuses[index].unwrap(), stdout, stderr)
        })
        .collect::<Vec<_>>();
    Ok(outputs)
}

#[test]
#[ignore = "marker-gated helper used only by the persistent-cache child-process regression"]
fn pin_id_child_helper() {
    if std::env::var(PIN_ID_CHILD_MARKER).as_deref() != Ok(PIN_ID_CHILD_MARKER_VALUE) {
        return;
    }
    let Ok(path) = std::env::var(PIN_ID_CHILD_PATH) else {
        return;
    };
    if path.len() > 4096 || path.chars().any(char::is_control) {
        return;
    }
    let state_path = PathBuf::from(path);
    if !state_path.is_absolute() {
        return;
    }
    let cache = Cache::open(&state_path, 16 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("synthetic pin-ID cache open refused: {error:?}"));
    let scope = scope();
    let item = pin_id_fixture_item();
    let pin = cache
        .begin_pin_manifest_at_cancellable(
            &scope,
            scope.root_resource_id(),
            PIN_ID_FIXTURE_ROOT_PATH,
            &manifest(&scope, &item),
            || false,
        )
        .unwrap_or_else(|_| panic!("synthetic generic pin admission refused"));
    if pin.id.len() == 64 && pin.id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        println!("\n{}", pin.id);
    }
}

#[test]
fn generic_pin_ids_are_unique_across_processes_with_one_persistent_cache() {
    let (state, cache) = cache();
    let scope = scope();
    let item = pin_id_fixture_item();
    publish_listing(&cache, &scope, &item, 1);
    cache
        .publish_content(
            &scope,
            &version(&item),
            &mut Cursor::new(PIN_ID_FIXTURE_BODY),
            PIN_ID_FIXTURE_BODY.len() as u64,
            Retention::Dirty,
        )
        .unwrap();

    // Model a restart: close each owner before another process opens the
    // persistent cache. Concurrent Windows private-cache owners are a separate
    // contract and must not be required to exercise process-local ID reuse.
    drop(cache);
    let mut outputs = Vec::with_capacity(3);
    for _ in 0..3 {
        let child = match spawn_pin_id_child(state.path()) {
            Ok(child) => child,
            Err(_) => panic!("pin ID child process could not be started"),
        };
        match await_pin_id_children(vec![child]) {
            Ok(mut output) => outputs.append(&mut output),
            Err(error) => {
                // Preserve the fixture while a child may still use it.
                std::mem::forget(state);
                panic!("{error}");
            }
        }
    }
    let mut ids = Vec::with_capacity(outputs.len());
    for (status, stdout, stderr) in outputs {
        assert!(
            status.success(),
            "pin ID child exited unsuccessfully: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(
            stderr.is_empty(),
            "pin ID child wrote unexpected diagnostics"
        );
        let stdout = String::from_utf8(stdout).expect("child output must be UTF-8");
        let child_ids = stdout
            .lines()
            .map(str::trim)
            .filter(|line| line.len() == 64 && line.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .collect::<Vec<_>>();
        assert_eq!(
            child_ids.len(),
            1,
            "child output must contain exactly one opaque pin ID"
        );
        ids.push(child_ids[0].to_owned());
    }
    let unique = ids.iter().collect::<std::collections::HashSet<_>>();
    assert_eq!(unique.len(), 3, "independent processes reused a pin ID");

    let reopened = Cache::open(state.path(), 16 * 1024 * 1024).unwrap();
    assert_eq!(pin_count(&reopened), 3);
    let expected_item = (
        item.id.clone(),
        scope.root_resource_id().to_owned(),
        "cross-process-file.bin".to_owned(),
        item.path.clone(),
        item.etag.clone(),
        item.size as i64,
        0,
        0,
    );
    for id in ids {
        assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(id.len(), 64);
        let stored = raw_pin(&reopened, &id);
        assert_eq!(stored.scope, scope.key);
        assert_eq!(stored.root, scope.root_resource_id());
        assert_eq!(stored.path, PIN_ID_FIXTURE_ROOT_PATH);
        assert_eq!(
            stored.state, 0,
            "newly admitted generic pins must remain Building"
        );
        assert_eq!(stored.items, vec![expected_item.clone()]);
    }
    assert_eq!(read_body(&reopened, &scope, &item), PIN_ID_FIXTURE_BODY);
    assert_eq!(
        reopened
            .content_record(&scope, &version(&item))
            .unwrap()
            .retention,
        Retention::Dirty
    );
}

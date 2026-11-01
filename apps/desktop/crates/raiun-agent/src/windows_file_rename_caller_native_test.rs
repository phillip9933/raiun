//! R59: actual owner-loop qualification. Ignored, fresh synthetic native roots only.
//! Never calls a producer tick, reconcile entry, independent provider factory,
//! completion permit, capture tracker setter, or diagnostic recovery override.
use super::*;
use raiun_cloudfiles_windows::{
    ConfiguredRootConnection, DpapiEditRecordProtector, EditJournal, EditJournalScope,
    OpenCloudPlaceholderBackend,
    namespace_intent::{CapturedAuthorization, NamespaceOperation},
};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const FLAG: &str = "RAIUN_OWNER_RENAME_NATIVE";
const DIRECTORY: &str = "RAIUN_OWNER_RENAME_FIXTURE_DIR";
const ROLE: &str = "RAIUN_OWNER_RENAME_CHILD";
const IO: &str = "RAIUN_OWNER_RENAME_IO";
const OWNER: &[u8] = b"raiun-r59-owner-loop-native-owned-v1\n";
const PERSONAL: &str = "/remote.php/dav/personal/synthetic-personal-drive";
const PREFIX: &str = "agent_windows::windows_file_rename_caller_native_test::";
const GUI: &str = "caller_gui_same_parent_personal_rename_completes_once";
const HEADLESS: &str = "caller_headless_pending_save_then_retired_generation_never_moves";

fn body(modified: bool) -> Vec<u8> {
    let mut value = (0..4096).map(|n| (n % 251) as u8).collect::<Vec<_>>();
    if modified {
        value[37] ^= 0x5a;
    }
    value
}
fn sha(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Clone, Copy)]
pub(super) enum ObservedPath {
    Status,
    Source,
    Destination,
}

/// Owner-thread-only, copied observations. Fixed paths; no caller-chosen scope,
/// store, backend, native handle, proof, lease or mutation capability escapes.
pub(super) fn observe_owner(
    connection: &ConfiguredRootConnection,
    backend: &Arc<OpenCloudPlaceholderBackend>,
    producer: &windows_file_rename_producer::Producer,
    binding: &ActiveProviderBinding,
    path: ObservedPath,
) -> Result<Value, String> {
    if backend.is_revoked() {
        return Err("Rename owner scope unavailable".into());
    }
    let status = producer.native_fixture_snapshot();
    let catalog = producer.native_fixture_catalog().map_err(str::to_owned)?;
    if status["agent_generation"] != binding.generation
        || status["token_generation"] != backend.scope().token_generation()
        || status["root_volume_serial"] != binding.identity.volume_serial
        || status["root_file_index"] != binding.identity.file_index
    {
        return Err("Rename owner generation unavailable".into());
    }
    let scope = EditJournalScope {
        profile_id: backend.scope().profile_id().into(),
        server_origin: backend.scope().server_origin().into(),
        account_subject: backend.scope().account_id().into(),
        space_id: binding.personal_space_id.clone(),
        root_resource_id: binding.personal_root_resource_id.clone(),
        root_volume_serial: binding.identity.volume_serial,
        root_file_index: binding.identity.file_index,
    };
    // Same already-prepared live connection/store; never construct a second
    // recovery provider or accept an arbitrary store as the test authority.
    let store = connection
        .file_rename_store(
            backend,
            &scope,
            CapturedAuthorization {
                agent_generation: binding.generation,
                token_generation: backend.scope().token_generation(),
            },
        )
        .map_err(|_| "Rename owner store unavailable")?
        .ok_or("Rename owner namespace not configured")?;
    let histories = store
        .discover_account_root()
        .map_err(|_| "Rename history unavailable")?;
    if histories.len() > 1 {
        return Err("Unexpected rename history; preserve fixture".into());
    }
    let mut history = Vec::new();
    for record in histories {
        let NamespaceOperation::MoveWithinScope {
            source,
            destination,
        } = record.intent.operation
        else {
            return Err("Unexpected rename operation".into());
        };
        if source.local.parent.scope != scope
            || destination.parent.scope != scope
            || source.local.name != "source.bin"
            || destination.name != "renamed.bin"
        {
            return Err("Rename history is outside exact fixture scope".into());
        }
        history.push(json!({"sequence":record.progress.sequence,
            "local_completed":record.progress.local_completed,
            "recorded_complete":record.progress.recorded_complete,
            "remote":format!("{:?}",record.progress.remote),
            "source_removal":format!("{:?}",record.progress.source_removal)}));
    }
    let file = match path {
        ObservedPath::Status => Value::Null,
        ObservedPath::Source | ObservedPath::Destination => {
            let name = if matches!(path, ObservedPath::Source) {
                "source.bin"
            } else {
                "renamed.bin"
            };
            let observed = connection
                .observe_namespace_file(&["Personal", name])
                .map_err(|_| "Native file metadata unavailable")?;
            json!({"file_index":observed.local_file.file_index,
                "volume_serial":observed.local_file.volume_serial,
                "state":observed.placeholder_state,"bytes":observed.byte_len})
        }
    };
    // Catalog identities are explicitly catalog observations, not a fresh OS
    // opaque-ID measurement. Native opaque-ID acceptance remains R58 scoped.
    if backend.is_revoked() {
        return Err("Rename observation retired".into());
    }
    Ok(json!({"producer":status,"scope":scope,"history":history,"file":file,"catalog":catalog}))
}

struct RemoteState {
    renamed: bool,
    modified: bool,
    moves: usize,
    puts: usize,
    invalid: usize,
    put_response_written: Option<bool>,
}
/// Small opt-in DAV adapter, behind the existing server's authorization gate.
/// PUT wait owns no model/Agent/provider mutex. It records factual remote PUT
/// before waiting; cancellation never rewrites that fact as no side effect.
pub(super) struct RenameModel {
    state: Mutex<RemoteState>,
    barrier: Option<PathBuf>,
}
impl RenameModel {
    fn new(barrier: Option<PathBuf>) -> Self {
        Self {
            state: Mutex::new(RemoteState {
                renamed: false,
                modified: false,
                moves: 0,
                puts: 0,
                invalid: 0,
                put_response_written: None,
            }),
            barrier,
        }
    }
    fn snapshot(&self) -> Value {
        let s = self.state.lock().unwrap();
        json!({"moves":s.moves,"puts":s.puts,"invalid":s.invalid,"remote_renamed":s.renamed,"remote_modified":s.modified,"put_response_written":s.put_response_written})
    }
    fn respond(stream: &mut TcpStream, status: u16, extra: &str, bytes: &[u8]) {
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(
            stream,
            "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
            bytes.len()
        )
        .unwrap();
        stream.write_all(bytes).unwrap();
    }
    pub(super) fn handle(
        &self,
        origin: &str,
        request: &str,
        headers: &[(String, String)],
        bytes: &[u8],
        stream: &mut TcpStream,
    ) -> bool {
        let mut words = request.split_whitespace();
        let method = words.next().unwrap_or("");
        let path = words.next().unwrap_or("").trim_end_matches('/');
        if path != PERSONAL
            && path != format!("{PERSONAL}/source.bin")
            && path != format!("{PERSONAL}/renamed.bin")
        {
            return false;
        }
        let header = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };
        let mut state = self.state.lock().unwrap();
        let exists = path == PERSONAL
            || if state.renamed {
                path.ends_with("/renamed.bin")
            } else {
                path.ends_with("/source.bin")
            };
        let etag = if state.modified {
            "\"caller-v2\""
        } else {
            "\"caller-v1\""
        };
        if method == "PUT" {
            if self.barrier.is_none()
                || !exists
                || path == PERSONAL
                || header("if-match") != Some(etag)
                || bytes != body(true)
                || state.puts != 0
            {
                state.invalid += 1;
                drop(state);
                Self::respond(stream, 412, "", b"");
                return true;
            }
            state.puts += 1;
            state.modified = true;
            drop(state);
            let barrier = self.barrier.as_ref().unwrap();
            retain(
                &barrier.join("put.entered"),
                &json!({"actual_conditional_put_received":true}),
            );
            wait_for(|| Ok(barrier.join("put.release").is_file()))
                .expect("owned PUT response barrier timed out; no replay");
            // Retirement may cancel the real HTTP client after the PUT body
            // reached this server. Record the response result without claiming
            // completion or failing the negative solely for expected cancellation.
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let written=stream.write_all(b"HTTP/1.1 204 Fixture\r\nContent-Length: 0\r\nETag: \"caller-v2\"\r\nConnection: close\r\n\r\n").is_ok();
            self.state.lock().unwrap().put_response_written = Some(written);
            return true;
        }
        if method == "MOVE" {
            if state.renamed
                || !exists
                || path != format!("{PERSONAL}/source.bin")
                || header("if-match") != Some(etag)
                || header("overwrite") != Some("F")
                || header("destination") != Some(format!("{origin}{PERSONAL}/renamed.bin").as_str())
                || !bytes.is_empty()
            {
                state.invalid += 1;
                drop(state);
                Self::respond(stream, 412, "", b"");
                return true;
            }
            state.moves += 1;
            state.renamed = true;
            drop(state);
            Self::respond(stream, 201, "", b"");
            return true;
        }
        if !exists {
            drop(state);
            Self::respond(stream, 404, "", b"");
            return true;
        }
        if method == "PROPFIND" {
            if !matches!(header("depth"), Some("0" | "1")) {
                state.invalid += 1;
                drop(state);
                Self::respond(stream, 400, "", b"");
                return true;
            }
            let child = if state.renamed {
                "renamed.bin"
            } else {
                "source.bin"
            };
            let mut entries = Vec::new();
            if path == PERSONAL {
                entries.push((
                    PERSONAL.to_owned(),
                    "synthetic-personal-root",
                    "Personal",
                    "<d:collection/>",
                    0,
                    "\"root-v1\"",
                ));
            }
            if path != PERSONAL || header("depth") == Some("1") {
                entries.push((
                    format!("{PERSONAL}/{child}"),
                    "caller-source-resource",
                    child,
                    "",
                    4096,
                    etag,
                ));
            }
            let xml=entries.into_iter().map(|(p,id,name,kind,len,tag)|format!("<d:response><d:href>{origin}{p}</d:href><d:propstat><d:prop><d:resourcetype>{kind}</d:resourcetype><d:getcontentlength>{len}</d:getcontentlength><d:getetag>{tag}</d:getetag><oc:fileid>{id}</oc:fileid><oc:name>{name}</oc:name><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>")).collect::<String>();
            drop(state);
            Self::respond(stream,207,"Content-Type: application/xml\r\n",format!("<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">{xml}</d:multistatus>").as_bytes());
            return true;
        }
        if method == "GET" && path != PERSONAL {
            if header("if-match") != Some(etag) {
                state.invalid += 1;
                drop(state);
                Self::respond(stream, 412, "", b"");
                return true;
            }
            let content = body(state.modified);
            let tag = etag.to_owned();
            drop(state);
            if let Some(range) = header("range") {
                let (start, end) = range
                    .strip_prefix("bytes=")
                    .and_then(|s| s.split_once('-'))
                    .and_then(|(a, b)| {
                        Some((
                            a.parse::<usize>().ok()?,
                            if b.is_empty() { 4095 } else { b.parse().ok()? },
                        ))
                    })
                    .expect("bounded fixture range");
                assert!(start <= end && end < 4096);
                Self::respond(
                    stream,
                    206,
                    &format!("ETag: {tag}\r\nContent-Range: bytes {start}-{end}/4096\r\n"),
                    &content[start..=end],
                );
            } else {
                Self::respond(stream, 200, &format!("ETag: {tag}\r\n"), &content);
            }
            return true;
        }
        state.invalid += 1;
        drop(state);
        Self::respond(stream, 405, "", b"");
        true
    }
}

fn retain(path: &Path, value: &Value) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("retain fresh fixture receipt, never overwrite/replay");
    serde_json::to_writer(&mut file, value).unwrap();
    file.write_all(b"\n").unwrap();
    file.sync_all().unwrap();
}
fn wait_for(mut condition: impl FnMut() -> Result<bool, String>) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if condition()? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("bounded native fixture observation timed out; preserve cohort".into());
        }
        // The production worker ticks only on an idle250ms receive. Space
        // observational commands beyond that interval so the test cannot
        // starve the real owner tick. Readiness still comes from real values.
        thread::sleep(Duration::from_millis(300));
    }
}
fn wrapper() -> PathBuf {
    assert_eq!(
        std::env::var(FLAG).as_deref(),
        Ok("fresh-owned-state"),
        "explicit native opt-in required"
    );
    let path =
        PathBuf::from(std::env::var_os(DIRECTORY).expect("explicit fresh owned wrapper required"));
    assert!(path.is_absolute());
    use std::os::windows::fs::MetadataExt;
    for ancestor in path.ancestors() {
        assert_eq!(
            fs::symlink_metadata(ancestor).unwrap().file_attributes() & 0x400,
            0,
            "wrapper reparse ancestor refused"
        );
        assert!(
            !fs::symlink_metadata(ancestor)
                .expect("existing wrapper ancestry")
                .file_type()
                .is_symlink()
        );
    }
    assert_eq!(fs::read(path.join("OWNER.txt")).unwrap(), OWNER);
    assert!(
        !fs::symlink_metadata(path.join("OWNER.txt"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    path
}
fn child_command(path: &Path, selector: &str, role: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--ignored",
            "--exact",
            selector,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(FLAG, "fresh-owned-state")
        .env(DIRECTORY, path)
        .env(ROLE, role)
        .stdin(Stdio::null());
    // Test roles inherit ordinary OS user context only. No accidental old
    // diagnostics/headless activation is adopted by a fresh worker process.
    let remove = std::env::vars_os()
        .filter_map(|(k, _)| {
            let name = k.to_string_lossy();
            (name.starts_with("RAIUN_") && ![FLAG, DIRECTORY].contains(&name.as_ref())).then_some(k)
        })
        .collect::<Vec<_>>();
    for key in remove {
        command.env_remove(key);
    }
    command.env(ROLE, role);
    command
}
fn launch(mut command: Command, path: &Path, label: &str) -> Child {
    let log = |suffix: &str| {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path.join(format!("{label}.{suffix}.log")))
            .unwrap()
    };
    let child = command
        .stdout(log("stdout"))
        .stderr(log("stderr"))
        .spawn()
        .expect("start owned fixture child once");
    retain(
        &path.join(format!("{label}.process.json")),
        &json!({"pid":child.id(),"forced_stop":false}),
    );
    child
}
fn terminal(mut child: Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(status) = child.try_wait().expect("observe owned fixture child") {
            return status;
        }
        if Instant::now() >= deadline {
            // Never kill/replay/unregister. Keep the wrapper and all native
            // state; the external supervisor owns normal guest shutdown.
            std::mem::forget(child);
            panic!("owned child timeout HOLD; normal guest shutdown required");
        }
        thread::sleep(Duration::from_millis(25));
    }
}
fn io_child(path: &Path, selector: &str, operation: &str) {
    let mut command = child_command(path, selector, "io");
    command.env(IO, operation);
    assert!(
        terminal(launch(command, path, &format!("io-{operation}"))).success(),
        "owned filesystem child failed; no retry"
    );
}
fn filesystem_io(path: &Path) {
    assert!(std::env::var_os("RAIUN_HEADLESS_CONTEXT").is_none());
    let personal = path.join("cloud-root/Personal");
    match std::env::var(IO).unwrap().as_str() {
        "populate" => {
            let _ = fs::read_dir(path.join("cloud-root"))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let entries = fs::read_dir(&personal)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert!(entries.iter().any(|e| e.file_name() == "source.bin"));
        }
        "hydrate" => assert_eq!(fs::read(personal.join("source.bin")).unwrap(), body(false)),
        "rename" => fs::rename(personal.join("source.bin"), personal.join("renamed.bin"))
            .expect("one actual OS rename, no retry"),
        "edit" => {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(personal.join("source.bin"))
                .unwrap();
            let mut old = Vec::new();
            file.read_to_end(&mut old).unwrap();
            assert_eq!(old, body(false));
            file.seek(SeekFrom::Start(0)).unwrap();
            file.write_all(&body(true)).unwrap();
            file.sync_all().unwrap();
            drop(file);
        }
        "verify" => {
            assert!(!personal.join("source.bin").try_exists().unwrap());
            assert_eq!(fs::read(personal.join("renamed.bin")).unwrap(), body(false));
        }
        _ => panic!("unknown fixed filesystem role"),
    }
}
fn owner_runtime(path: &Path, selector: &str, headless: bool) {
    let server = fs::read_to_string(path.join("server.txt")).unwrap();
    assert!(
        server
            .strip_prefix("http://")
            .and_then(|v| v.parse::<std::net::SocketAddr>().ok())
            .is_some_and(|a| a.ip() == std::net::Ipv4Addr::LOCALHOST && a.port() != 0)
    );
    assert_eq!(mount_only(), headless);
    if headless {
        let context = raiun_control_windows::headless_context().unwrap().unwrap();
        assert_eq!(context.state_root(), path.join("headless-state"));
        let config = crate::headless_runtime::config().unwrap().unwrap();
        assert_eq!(config.server, server);
        assert!(!config.remember_login);
        assert!(!config.auto_mount);
    } else {
        assert_eq!(
            std::env::var_os("LOCALAPPDATA").unwrap(),
            path.join("gui-localappdata")
        );
        assert!(raiun_control_windows::headless_context().unwrap().is_none());
    }
    let store = Arc::new(tests::MemoryStore::default());
    if !headless {
        tests::seed_active_session(
            &store,
            "default",
            tests::synthetic_session(&server, "synthetic-client", unix_time_now() + 3600),
        );
    }
    let agent = Arc::new(
        WindowsAgent::new_for_profile_with_services(
            "default",
            store,
            None,
            Arc::new(raiun_vault::session::VaultSessionCoordinator::new()),
        )
        .unwrap(),
    );
    agent.attach_existing_file_save_owner().unwrap();
    agent
        .provider
        .lifecycle_test_activation
        .store(true, Ordering::Release);
    agent
        .provider
        .initial_save_test_activation
        .store(true, Ordering::Release);
    if headless {
        agent.handle_request(&json!({"action":"auth_app_token","required_mode":"mount_only","profile_id":"default","server":server,"username":"synthetic-user","app_token":"synthetic-headless-app-token"})).unwrap();
        wait_for(|| Ok(agent.state.lock().unwrap().online_authenticated)).unwrap();
        fs::create_dir(path.join("cloud-root")).unwrap();
        agent.handle_request(&json!({"action":"mount","required_mode":"mount_only","profile_id":"default","cloud_root":path.join("cloud-root")})).unwrap();
    } else {
        {
            let mut state = agent.state.lock().unwrap();
            state.online_authenticated = true;
            state.needs_refresh = false;
            state.active_generation = agent.generation.load(Ordering::Acquire);
        }
        fs::create_dir(path.join("cloud-root")).unwrap();
        agent
            .handle_request(&json!({"action":"configure","cloud_root":path.join("cloud-root")}))
            .unwrap();
    }
    assert!(
        agent.provider.is_connected(),
        "normal configure/mount must own the connection"
    );
    wait_for(|| {
        let value = agent
            .provider
            .rename_caller_observation(ObservedPath::Status)?;
        Ok(value["producer"]["attached"] == true
            && value["producer"]["instance"].as_u64().is_some()
            && value["producer"]["held"] == false)
    })
    .unwrap();
    io_child(path, selector, "populate");
    io_child(path, selector, "hydrate");
    let before = agent
        .provider
        .rename_caller_observation(ObservedPath::Source)
        .unwrap();
    assert_eq!(before["file"]["bytes"], 4096);
    assert_eq!(
        before["file"]["state"], 9,
        "source must actually be clean before one OS rename"
    );
    assert!(before["history"].as_array().unwrap().is_empty());
    let original_generation = agent.generation.load(Ordering::Acquire);
    if !headless {
        io_child(path, selector, "rename");
        let mut after = Value::Null;
        wait_for(|| {
            after = agent
                .provider
                .rename_caller_observation(ObservedPath::Destination)?;
            Ok(after["history"].as_array().is_some_and(|r| {
                r.len() == 1 && r[0]["recorded_complete"] == true && r[0]["sequence"] == 4
            }))
        })
        .unwrap();
        assert_eq!(after["file"]["file_index"], before["file"]["file_index"]);
        assert_eq!(
            after["file"]["volume_serial"],
            before["file"]["volume_serial"]
        );
        assert_eq!(after["file"]["state"], 1);
        assert_eq!(after["file"]["bytes"], 4096);
        assert!(before["catalog"]["source"].is_array());
        assert!(after["catalog"]["destination"].is_array());
        assert_ne!(
            before["catalog"]["source"], after["catalog"]["destination"],
            "catalog identity must change; this is not an independent native opaque-ID query"
        );
        io_child(path, selector, "verify");
        agent.provider.disconnect().unwrap();
        agent.stop_and_join().unwrap();
        retain(
            &path.join("OWNER-RESULTS.json"),
            &json!({"case":"gui-positive","original_generation":original_generation,"before":before,"after":after,"body_sha256":sha(&body(false)),"normal_stop":true,"independent_native_opaque_id_query":false}),
        );
    } else {
        let scope: EditJournalScope = serde_json::from_value(before["scope"].clone()).unwrap();
        let protector = DpapiEditRecordProtector::current_user().unwrap();
        assert!(
            protector
                .local_state_directory()
                .starts_with(path.join("headless-state"))
        );
        io_child(path, selector, "edit");
        wait_for(|| Ok(path.join("put.entered").is_file())).unwrap();
        // Owner is in the actual initial PUT. Do not queue a synchronous owner
        // observation here or hold an Agent mutex over the wait/logout.
        io_child(path, selector, "rename");
        let logout_agent = Arc::clone(&agent);
        let logout = thread::spawn(move || logout_agent.logout());
        wait_for(|| Ok(agent.generation.load(Ordering::Acquire) != original_generation)).unwrap();
        let retired_generation = agent.generation.load(Ordering::Acquire);
        retain(
            &path.join("put.release"),
            &json!({"original_generation_retired":true}),
        );
        let logout_result = logout.join().unwrap();
        assert!(
            logout_result.is_ok(),
            "normal logout/drain failed; retain cohort"
        );
        agent.stop_and_join().unwrap();
        assert!(!agent.provider.is_connected());
        // Existing DPAPI protector + exact captured scope; no provider factory,
        // public rename entry, recovery approval or dispatch capability minted.
        assert!(
            protector
                .local_state_directory()
                .join("cloud-files-edit-journal-v1")
                .is_dir(),
            "real capture must have created retained legacy journal; never initialize a missing history as empty"
        );
        let journal = EditJournal::open(
            protector.local_state_directory(),
            scope.clone(),
            protector.clone(),
        )
        .unwrap();
        let snapshot = journal
            .recover_all()
            .expect("authenticate full retained protected body after logout");
        assert_eq!(snapshot.incomplete_staging_files, 0);
        assert_eq!(snapshot.records.len(), 1);
        assert_eq!(snapshot.records[0].metadata.scope, scope);
        assert_eq!(snapshot.records[0].metadata.relative_path, "/source.bin");
        assert_eq!(snapshot.records[0].content, body(true));
        retain(
            &path.join("OWNER-RESULTS.json"),
            &json!({"case":"headless-pending-retired","original_generation":original_generation,"retired_generation":retired_generation,"before":before,"retained_body_sha256":sha(&snapshot.records[0].content),"retained_bytes":4096,"normal_logout_stop":true,"put_may_have_remote_side_effect":true,"postretirement_namespace_prefix":"not_independently_queried"}),
        );
    }
}
fn exercise(name: &str, headless: bool) {
    let path = wrapper();
    let selector = format!("{PREFIX}{name}");
    let args = std::env::args().collect::<Vec<_>>();
    assert!(
        args.windows(2)
            .any(|pair| pair[0] == "--exact" && pair[1] == selector)
            && args.iter().any(|arg| arg == "--ignored"),
        "exact ignored selector must be supplied"
    );
    if let Some(role) = std::env::var_os(ROLE) {
        match role.to_str().unwrap() {
            "owner" => owner_runtime(&path, &selector, headless),
            "io" => filesystem_io(&path),
            _ => panic!("unknown fixture role"),
        };
        return;
    }
    assert!(std::env::var_os("RAIUN_HEADLESS_CONTEXT").is_none());
    assert!(std::env::var_os("RAIUN_HEADLESS_CONFIG").is_none());
    assert!(std::env::var_os("RAIUN_STATE_DIR").is_none());
    for entry in fs::read_dir(&path).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        assert!(
            ["OWNER.txt", "runner.json", "stdout.log", "stderr.log"]
                .iter()
                .any(|allowed| name == *allowed),
            "unexpected pre-existing wrapper entry; no replay"
        );
        assert!(entry.file_type().unwrap().is_file());
    }
    for child in [
        "cloud-root",
        "gui-localappdata",
        "headless-state",
        "config.json",
        "server.txt",
        "OWNER-RESULTS.json",
        "CALLER-RESULTS.json",
        "put.entered",
        "put.release",
    ] {
        assert!(
            !path.join(child).try_exists().unwrap(),
            "fresh absent native child path required; no replay"
        );
    }
    let model = Arc::new(RenameModel::new(headless.then(|| path.clone())));
    let (server, fixture) = tests::synthetic_caller_rename_server(headless, Arc::clone(&model));
    let mut server_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.join("server.txt"))
        .unwrap();
    server_file.write_all(server.as_bytes()).unwrap();
    server_file.sync_all().unwrap();
    drop(server_file);
    let mut command = child_command(&path, &selector, "owner");
    if headless {
        retain(
            &path.join("config.json"),
            &json!({"schema_version":1,"server":server,"auth":"app_token","username":"synthetic-user","mount_path":path.join("cloud-root"),"auto_mount":false,"remember_login":false,"reconnect_interval_seconds":1,"profile":"default"}),
        );
        command
            .env("RAIUN_HEADLESS_CONTEXT", "1")
            .env("RAIUN_STATE_DIR", path.join("headless-state"))
            .env("RAIUN_HEADLESS_CONFIG", path.join("config.json"));
    } else {
        fs::create_dir(path.join("gui-localappdata")).unwrap();
        command.env("LOCALAPPDATA", path.join("gui-localappdata"));
    }
    let outcome = terminal(launch(command, &path, "owner"));
    let remote = model.snapshot();
    let all_mutation_attempts = fixture.global_mutation_attempts();
    fixture.join().expect("owned synthetic server joined");
    let retained = path.join("cloud-root").is_dir()
        && path
            .join(if headless {
                "headless-state"
            } else {
                "gui-localappdata"
            })
            .is_dir();
    retain(
        &path.join("CALLER-RESULTS.json"),
        &json!({"selector":selector,"owner_normal_exit":outcome.success(),"remote":remote,"all_mutation_attempts":all_mutation_attempts,"guarded_owner_loop":true,"direct_public_entry_called_by_test":false,"independent_native_opaque_id_query":false,"root_and_private_base_exist":retained}),
    );
    assert!(retained, "root/private base missing; preserve cohort");
    assert!(
        outcome.success(),
        "actual owner fixture failed; keep private logs/state, no replay"
    );
    assert_eq!(
        all_mutation_attempts, 1,
        "exactly one GUI MOVE or one headless PUT; any other mutation attempt fails the cohort"
    );
    assert_eq!(remote["invalid"], 0);
    assert_eq!(remote["moves"], if headless { 0 } else { 1 });
    assert_eq!(remote["puts"], if headless { 1 } else { 0 });
}

#[test]
#[ignore = "explicit fresh ordinary-user Windows native fixture only; R58 admission required"]
fn caller_gui_same_parent_personal_rename_completes_once() {
    exercise(GUI, false);
}

#[test]
#[ignore = "explicit fresh ordinary-user Windows native fixture only; R58 admission required"]
fn caller_headless_pending_save_then_retired_generation_never_moves() {
    exercise(HEADLESS, true);
}

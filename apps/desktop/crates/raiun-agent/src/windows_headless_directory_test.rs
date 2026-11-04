//! Explicit synthetic automatic OS-mkdir acceptance; never production activation.
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::Write, net::TcpStream};

const PERSONAL: &str = "/remote.php/dav/personal/synthetic-personal-drive";
const PROJECTS: &str = "/remote.php/dav/projects/synthetic-project-drive";
const NAME: &str = "automatic-directory";

const CASES: [&str; 6] = [
    "personal-success",
    "space-success",
    "personal-nested",
    "personal-bootstrap",
    "personal-losthint",
    "personal-lostresponse",
];
fn selected(input: Option<&std::ffi::OsStr>) -> Result<Vec<&'static str>, &'static str> {
    match input {
        None => Ok(CASES.to_vec()),
        Some(s) => CASES
            .iter()
            .copied()
            .find(|case| Some(*case) == s.to_str())
            .map(|case| vec![case])
            .ok_or("unsupported exact directory selector"),
    }
}
fn loopback(origin: &str) -> bool {
    origin
        .strip_prefix("http://")
        .and_then(|s| s.parse::<std::net::SocketAddr>().ok())
        .is_some_and(|a| a.ip() == std::net::Ipv4Addr::LOCALHOST && a.port() != 0)
}

/// Strict test-only dynamic DAV contract. Does not prove real OC9 semantics.
pub(in super::super) struct DirectoryModel {
    nodes: BTreeMap<String, (String, String)>,
    attempts: Vec<String>,
    created: Vec<String>,
    lost_response: bool,
    invalid: u64,
    propfinds: u64,
}
impl DirectoryModel {
    pub(in super::super) fn new(lost_response: bool) -> Self {
        Self {
            nodes: BTreeMap::from([
                (
                    PERSONAL.into(),
                    ("synthetic-personal-root".into(), "Personal".into()),
                ),
                (
                    PROJECTS.into(),
                    ("synthetic-project-root".into(), "Projects".into()),
                ),
            ]),
            attempts: Vec::new(),
            created: Vec::new(),
            lost_response,
            invalid: 0,
            propfinds: 0,
        }
    }
    #[cfg(debug_assertions)]
    pub(in super::super) fn for_fixture(lost_response: bool, mixed: bool) -> Self {
        let mut model = Self::new(lost_response);
        if mixed {
            model.nodes.insert(
                format!("{PERSONAL}/provider-directory"),
                (
                    "synthetic-provider-directory".into(),
                    "provider-directory".into(),
                ),
            );
        }
        model
    }
    pub(in super::super) fn observation(&self) -> Value {
        json!({"attempts":self.attempts,"created":self.created,"invalid":self.invalid,"propfinds":self.propfinds,"lost_response":self.lost_response})
    }
    fn response(stream: &mut TcpStream, status: u16, body: &str) {
        let _ = write!(
            stream,
            "HTTP/1.1 {status} Fixture\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
    }
    pub(in super::super) fn handle(
        &mut self,
        origin: &str,
        request: &str,
        headers: &[(String, String)],
        body: &[u8],
        stream: &mut TcpStream,
    ) -> bool {
        let mut words = request.split_whitespace();
        let method = words.next().unwrap_or("");
        let raw = words.next().unwrap_or("");
        let path = raw.trim_end_matches('/');
        if ![PERSONAL, PROJECTS]
            .iter()
            .any(|root| path == *root || path.starts_with(&format!("{root}/")))
        {
            return false;
        }
        let root = if path.starts_with(PERSONAL) {
            PERSONAL
        } else {
            PROJECTS
        };
        let relative = path.strip_prefix(root).unwrap();
        if !body.is_empty() && method != "PROPFIND"
            || !matches!(
                relative,
                "" | "/automatic-directory" | "/automatic-directory/nested"
            ) && !(path == format!("{PERSONAL}/provider-directory")
                && self.nodes.contains_key(path))
            || headers
                .iter()
                .any(|(name, _)| matches!(name.as_str(), "destination" | "overwrite"))
        {
            self.invalid += 1;
            Self::response(stream, 400, "");
            return true;
        }
        if method == "MKCOL" {
            self.attempts.push(path.into());
            if relative.is_empty() {
                self.invalid += 1;
                Self::response(stream, 403, "");
                return true;
            }
            let parent = path.rsplit_once('/').unwrap().0;
            if !self.nodes.contains_key(parent) {
                self.invalid += 1;
                Self::response(stream, 409, "");
                return true;
            }
            if self.nodes.contains_key(path) {
                Self::response(stream, 405, "");
                return true;
            }
            let id = format!("synthetic-auto-directory-{}", self.created.len() + 1);
            self.nodes
                .insert(path.into(), (id, path.rsplit('/').next().unwrap().into()));
            self.created.push(path.into());
            if !(self.lost_response && self.created.len() == 1) {
                Self::response(stream, 201, "");
            }
            return true;
        }
        if method != "PROPFIND" {
            self.invalid += 1;
            Self::response(stream, 405, "");
            return true;
        }
        self.propfinds += 1;
        let depth = headers
            .iter()
            .find(|(name, _)| name == "depth")
            .map(|(_, value)| value.as_str());
        if !matches!(depth, Some("0" | "1")) {
            self.invalid += 1;
            Self::response(stream, 400, "");
            return true;
        }
        if !self.nodes.contains_key(path) {
            Self::response(stream, 404, "");
            return true;
        }
        let mut xml = String::new();
        for (node, (id, name)) in &self.nodes {
            if node != path
                && !(depth == Some("1")
                    && node
                        .rsplit_once('/')
                        .is_some_and(|(parent, _)| parent == path))
            {
                continue;
            }
            xml.push_str(&format!("<d:response><d:href>{origin}{node}/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>\"{id}-v1\"</d:getetag><oc:fileid>{id}</oc:fileid><oc:name>{name}</oc:name><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"));
        }
        Self::response(
            stream,
            207,
            &format!(
                "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">{xml}</d:multistatus>"
            ),
        );
        true
    }
}

#[cfg(all(windows, debug_assertions))]
mod native {
    use super::super::*;
    use super::*;
    use raiun_cloudfiles_windows::{
        EditJournalScope,
        namespace_intent::{NamespaceAttention, NamespaceOperation, NamespacePhase},
        namespace_store::DirectoryIntentStore,
    };
    use std::{
        path::{Path, PathBuf},
        sync::{Arc, atomic::Ordering},
        time::{Duration, Instant},
    };
    const TEST: &str = "agent_windows::windows_profiles::windows_headless_directory_test::native::synthetic_headless_automatic_directory_create";
    const DIRECTORY: &str = "RAIUN_HEADLESS_DIRECTORY_FIXTURE_DIR";
    const ROLE: &str = "RAIUN_HEADLESS_DIRECTORY_FIXTURE_CHILD";
    const CASE: &str = "RAIUN_HEADLESS_DIRECTORY_FIXTURE_CASE";
    const OWNER: &str = "raiun-headless-automatic-directory-v1\n";
    const MIXED_TEST: &str = "agent_windows::windows_profiles::windows_headless_directory_test::native::synthetic_shared_mixed_cloud_directory_and_ordinary_mkdir";
    const MIXED_OWNER: &str = "raiun-shared-mixed-directory-v1\n";
    const MIXED_FLAG: &str = "RAIUN_MIXED_DIRECTORY_NATIVE";
    const CONTENT: &[u8] = b"retained automatic directory child\0\x01\xff";
    static REPORT_FAILED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    fn report(path: &Path, value: Value) {
        // Do not unwind away a live child/server owner when evidence storage
        // fails. Finish normal cleanup, then refuse acceptance.
        if std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).is_err() {
            REPORT_FAILED.store(true, Ordering::Release);
        }
    }
    fn owned(path: &Path) -> bool {
        use std::os::windows::fs::MetadataExt;
        std::fs::symlink_metadata(path.join("OWNER.txt"))
            .is_ok_and(|m| m.is_file() && m.file_attributes() & 0x400 == 0)
            && std::fs::read_to_string(path.join("OWNER.txt")).is_ok_and(|s| {
                s == if case(path) == "personal-mixed" {
                    MIXED_OWNER
                } else {
                    OWNER
                }
            })
    }
    fn same(a: &Path, b: &Path) -> bool {
        matches!((std::fs::canonicalize(a),std::fs::canonicalize(b)),(Ok(a),Ok(b)) if a==b)
    }
    fn case(path: &Path) -> &str {
        path.file_name().unwrap().to_str().unwrap()
    }
    fn parts(path: &Path) -> Vec<&'static str> {
        if case(path) == "space-success" {
            vec!["Spaces", "Projects", NAME]
        } else {
            vec!["Personal", NAME]
        }
    }
    fn create_io(path: &Path) -> Result<(), String> {
        let mut cursor = path.join("cloud-root");
        let parts = parts(path);
        for (index, part) in parts.iter().enumerate() {
            let names = std::fs::read_dir(&cursor)
                .map_err(|_| format!("enumeration open failed at{index}"))?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| format!("enumeration entry failed at{index}"))?;
            if index + 1 < parts.len() && !names.iter().any(|name| name == *part) {
                return Err(format!("expected namespace child missing at{index}"));
            }
            cursor.push(part);
        }
        std::fs::create_dir(&cursor).map_err(|_| "OS mkdir failed")?;
        if case(path) == "personal-nested" {
            cursor.push("nested");
            std::fs::create_dir(&cursor).map_err(|_| "OS nested mkdir failed")?;
        }
        if case(path) == "personal-mixed" {
            return Ok(());
        }
        std::fs::write(cursor.join("retained-child.bin"), CONTENT)
            .map_err(|_| "retained child write failed")?;
        Ok(())
    }
    fn verify_io(path: &Path) -> Result<(), String> {
        let mut local = path.join("cloud-root");
        for part in parts(path) {
            local.push(part);
        }
        if case(path) == "personal-nested" {
            local.push("nested");
        }
        if case(path) == "personal-mixed" {
            return if local.is_dir() {
                Ok(())
            } else {
                Err("retained mixed directory unavailable".into())
            };
        }
        if std::fs::read(local.join("retained-child.bin"))
            .map_err(|_| "post-stop child unavailable")?
            != CONTENT
        {
            return Err("post-stop child content changed".into());
        }
        Ok(())
    }
    fn spawn(path: &Path, role: &str) -> Result<std::process::Child, String> {
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "--ignored",
            "--exact",
            if case(path) == "personal-mixed" {
                MIXED_TEST
            } else {
                TEST
            },
            "--nocapture",
            "--test-threads=1",
        ])
        .env(DIRECTORY, path)
        .env(ROLE, role)
        .stdin(std::process::Stdio::null());
        if matches!(role, "io" | "populate" | "verify-save" | "verify-restart") {
            cmd.env_remove("RAIUN_HEADLESS_CONTEXT")
                .env_remove("RAIUN_STATE_DIR")
                .env_remove("RAIUN_HEADLESS_CONFIG");
        } else {
            cmd.env("RAIUN_HEADLESS_CONTEXT", "1")
                .env("RAIUN_STATE_DIR", path.join("state"))
                .env("RAIUN_HEADLESS_CONFIG", path.join("config.json"));
        }
        let log = |suffix| {
            std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(path.join(format!("{role}.{suffix}.log")))
                .map_err(|_| "cannot create retained log".to_string())
        };
        let child = cmd
            .stdout(log("stdout")?)
            .stderr(log("stderr")?)
            .spawn()
            .map_err(|_| "cannot spawn child")?;
        report(
            &path.join(format!("{role}.process.json")),
            json!({"pid":child.id(),"running":true,"forced_stop":false}),
        );
        Ok(child)
    }
    fn wait_child(mut child: std::process::Child, path: &Path, role: &str) -> Result<(), String> {
        let end = Instant::now() + Duration::from_secs(180);
        let mut expired = false;
        let mut wait_error = false;
        loop {
            let observed = child.try_wait();
            if observed.is_err() && !wait_error {
                wait_error = true;
                report(
                    &path.join(format!("{role}.wait-error.json")),
                    json!({"pid":child.id(),"observation_error":true,"acceptance_failed":true,"server_owner_retained":true,"forced_stop":false}),
                );
            }
            match observed {
                Ok(Some(status)) => {
                    report(
                        &path.join(format!("{role}.process.json")),
                        json!({"pid":child.id(),"exited":true,"success":status.success(),"timed_out":expired,"observation_error":wait_error,"forced_stop":false}),
                    );
                    return if status.success() && !expired && !wait_error {
                        Ok(())
                    } else {
                        Err(
                            "child failed, observation failed or cap exceeded; evidence retained"
                                .into(),
                        )
                    };
                }
                Ok(None) | Err(_) => {
                    if Instant::now() >= end && !expired {
                        expired = true;
                        report(
                            &path.join(format!("{role}.pending.json")),
                            json!({"pid":child.id(),"timed_out":true,"server_owner_retained":true,"forced_stop":false}),
                        );
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        }
    }
    fn wait_for(mut ready: impl FnMut() -> Result<bool, String>) -> Result<(), String> {
        let end = Instant::now() + Duration::from_secs(60);
        loop {
            if ready()? {
                return Ok(());
            }
            if Instant::now() >= end {
                return Err("bounded directory observation timed out".into());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    fn request(action: &str) -> Value {
        json!({"action":action,"required_mode":"mount_only","profile_id":"default"})
    }
    fn runtime(path: &Path, role: &str) {
        let config = crate::headless_runtime::config().unwrap().unwrap();
        assert!(loopback(&config.server) && same(&config.mount_path, &path.join("cloud-root")));
        assert!(
            config.profile == "default"
                && config.auth == raiun_headless::AuthMethod::AppToken
                && config.username.as_deref() == Some("synthetic-user")
        );
        let context = raiun_control_windows::headless_context().unwrap().unwrap();
        assert!(same(context.state_root(), &path.join("state")));
        let broker =
            Arc::new(WindowsProfiles::open(DpapiSessionStore::current_user().unwrap()).unwrap());
        let agent = broker.state.lock().unwrap().runtimes["default"].clone();
        agent
            .provider
            .lifecycle_test_activation
            .store(true, Ordering::Release);
        let mixed = case(path) == "personal-mixed";
        if mixed {
            assert_eq!(
                std::env::var(MIXED_FLAG).as_deref(),
                Ok("fresh-owned-state")
            );
            agent
                .provider
                .mixed_namespace_test_activation
                .store(true, Ordering::Release);
        } else {
            agent
                .provider
                .namespace_test_activation
                .store(true, Ordering::Release);
        }
        let paused = matches!(case(path), "personal-nested" | "personal-bootstrap");
        agent
            .provider
            .namespace_controls
            .paused
            .store(paused, Ordering::Release);
        agent
            .provider
            .namespace_controls
            .discard_hints
            .store(case(path) == "personal-losthint", Ordering::Release);
        let history_polls = std::cell::Cell::new([0u64; 4]);
        let latest_history = std::cell::RefCell::new(Value::Null);
        let latest_fatal_history_error_class = std::cell::Cell::new("none");
        let exercise = || -> Result<Value, String> {
            broker.handle_owned(windows_vault_requests::OwnedControlRequest::new(json!({"action":"auth_app_token","required_mode":"mount_only","profile_id":"default","server":config.server,"username":"synthetic-user","app_token":"synthetic-headless-app-token"})))?;
            wait_for(|| Ok(agent.state.lock().unwrap().online_authenticated))?;
            let mount = agent
                .headless_configured_mount_request()?
                .ok_or("configured mount missing")?;
            broker.handle(&mount)?;
            if !agent.provider.is_connected() {
                return Err("actual broker mount not connected".into());
            }
            let verified = agent.prepare_recovery_context()?;
            let is_space = case(path) == "space-success";
            let space = verified
                .spaces
                .iter()
                .find(|space| {
                    if is_space {
                        space.id == "synthetic-project-drive"
                    } else {
                        space.personal
                    }
                })
                .ok_or("Space not discovered")?;
            let remote_root = verified
                .client
                .stat_discovered_space_root_with_context(space, verified.context)
                .map_err(|_| "root metadata unavailable")?;
            let root = agent
                .state
                .lock()
                .unwrap()
                .root_configuration
                .clone()
                .ok_or("local root unavailable")?;
            let scope = EditJournalScope {
                profile_id: verified.provider_scope.profile_id().into(),
                server_origin: verified.provider_scope.server_origin().into(),
                account_subject: verified.provider_scope.account_id().into(),
                space_id: space.id.clone(),
                root_resource_id: remote_root.id,
                root_volume_serial: root.volume_serial,
                root_file_index: root.file_index,
            };
            let original_generation = agent.generation.load(Ordering::Acquire);
            let mut mixed_instance = Value::Null;
            let mut discarded_before_io = 0;
            if mixed {
                wait_for(|| {
                    let o = agent.provider.mixed_namespace_observation()?;
                    if o["held"] == true {
                        return Err("shared dispatcher held before materialization".into());
                    }
                    if o["attached"] == true && o["instance"].as_u64().is_some() {
                        mixed_instance = o["instance"].clone();
                        return Ok(true);
                    }
                    Ok(false)
                })?;
                let before = agent.provider.mixed_namespace_observation()?;
                wait_child(spawn(path, "populate")?, path, "populate")?;
                wait_for(|| {
                    let o = agent.provider.mixed_namespace_observation()?;
                    if o["held"] == true
                        || o["instance"] != mixed_instance
                        || o["directory_offers"] != 0
                    {
                        return Err("cloud materialization mutated or retired shared owner".into());
                    }
                    Ok(o["provider_directory_skipped"] == true
                        && o["cloud_directories_skipped"]
                            .as_u64()
                            .ok_or("missing actual skip count")?
                            > before["cloud_directories_skipped"]
                                .as_u64()
                                .ok_or("missing actual skip count")?)
                })?;
                let cloud = agent.provider.namespace_directory_observation(vec![
                    "Personal".into(),
                    "provider-directory".into(),
                ])?;
                if cloud.opaque_identity.is_none() || cloud.placeholder_state == 0 {
                    return Err("actual provider directory was not cloud-shaped".into());
                }
                let initial = DirectoryIntentStore::current_user(
                    scope.clone(),
                    super::super::super::windows_recovery_policy::directory_storage_policy()?,
                )
                .map_err(|_| "mixed namespace store unavailable")?;
                if !initial
                    .discover_account_root()
                    .map_err(|_| "mixed initial history unavailable")?
                    .is_empty()
                    || agent.provider.namespace_status.lock().unwrap().completed != 0
                {
                    return Err("cloud materialization published directory history".into());
                }
            }
            if role == "save" {
                if !paused && !mixed {
                    wait_for(|| Ok(agent.provider.namespace_status.lock().unwrap().ticks > 0))?;
                }
                discarded_before_io = agent
                    .provider
                    .namespace_status
                    .lock()
                    .unwrap()
                    .discarded_hints;
                wait_child(spawn(path, "io")?, path, "io")?;
                if paused && agent.provider.namespace_status.lock().unwrap().ticks != 0 {
                    return Err("bootstrap candidate was not created before producer tick".into());
                }
                agent
                    .provider
                    .namespace_controls
                    .paused
                    .store(false, Ordering::Release);
            }
            let store = DirectoryIntentStore::current_user(
                scope.clone(),
                super::super::super::windows_recovery_policy::directory_storage_policy()?,
            )
            .map_err(|_| "namespace store unavailable")?;
            let expected = if case(path) == "personal-nested" {
                2
            } else {
                1
            };
            let lost = case(path) == "personal-lostresponse";
            let mut summary = Value::Null;
            let mut captured_intents = Vec::new();
            wait_for(|| {
                let records = match store.discover_account_root() {
                    Ok(r) => {
                        let mut counts = history_polls.get();
                        counts[0] += 1;
                        history_polls.set(counts);
                        // Bounded progress-only evidence, including on timeout.
                        // Never emit record identifiers, names, paths or bodies.
                        let sample = r
                            .iter()
                            .take(4)
                            .map(|record| {
                                let (scope_matches, name_matches) = match &record.intent.operation {
                                    NamespaceOperation::CreateDirectory { destination } => (
                                        destination.parent.scope == scope,
                                        matches!(destination.name.as_str(), NAME | "nested"),
                                    ),
                                    _ => (false, false),
                                };
                                json!({"sequence":record.progress.sequence,
                                "remote":format!("{:?}",record.progress.remote),
                                "attention":format!("{:?}",record.progress.attention),
                                "local_completed":record.progress.local_completed,
                                "recorded_complete":record.progress.recorded_complete,
                                "source_removal":format!("{:?}",record.progress.source_removal),
                                "scope_matches":scope_matches,"name_matches":name_matches})
                            })
                            .collect::<Vec<_>>();
                        latest_history.replace(
                            json!({"record_count":r.len(),"sample_limit":4,"sample":sample}),
                        );
                        r
                    }
                    Err(error) => {
                        use raiun_cloudfiles_windows::streamed_store::StoreError;
                        let class = match &error {
                            StoreError::Busy => "busy",
                            StoreError::IncompleteEvidence => "incomplete_evidence",
                            StoreError::Io => "io",
                            StoreError::Invalid => "invalid",
                            StoreError::Quota => "quota",
                            StoreError::ScanLimit => "scan_limit",
                            StoreError::CorruptEvidence => "corrupt_evidence",
                            StoreError::PublicationUncertain => "publication_uncertain",
                            StoreError::Snapshot(_) => "snapshot",
                        };
                        let index = match error {
                            StoreError::Busy => 1,
                            StoreError::IncompleteEvidence => 2,
                            _ => 3,
                        };
                        let mut counts = history_polls.get();
                        counts[index] += 1;
                        history_polls.set(counts);
                        if index == 3 {
                            latest_fatal_history_error_class.set(class);
                            return Err("authenticated directory histories unavailable".into());
                        }
                        return Ok(false);
                    }
                };
                if records.len() != expected {
                    return if records.len() > expected {
                        Err("extra durable directory intent".into())
                    } else {
                        Ok(false)
                    };
                }
                let mut detail = Vec::new();
                let mut intents = Vec::new();
                for record in records {
                    let NamespaceOperation::CreateDirectory { destination } =
                        &record.intent.operation
                    else {
                        return Err("unexpected operation".into());
                    };
                    if destination.parent.scope != scope
                        || !matches!(destination.name.as_str(), NAME | "nested")
                    {
                        return Err("directory binding mismatch".into());
                    }
                    if mixed
                        && (destination.parent.authorization.agent_generation
                            != original_generation
                            || destination.parent.authorization.token_generation
                                != verified.provider_scope.token_generation()
                            || record.intent.record_generation == 0)
                    {
                        return Err("mixed history original authorization changed".into());
                    }
                    if mixed && !record.progress.recorded_complete {
                        return Ok(false);
                    }
                    let terminal = if lost {
                        record.progress.remote == NamespacePhase::Submitted
                            && record.progress.attention == Some(NamespaceAttention::Uncertain)
                            && !record.progress.local_completed
                    } else {
                        record.progress.local_completed
                            && record.progress.remote == NamespacePhase::Verified
                            && record.progress.attention.is_none()
                    };
                    if !terminal {
                        return Ok(false);
                    }
                    let mut components = destination.parent.local_components.clone();
                    components.push(destination.name.clone());
                    let observation = agent.provider.namespace_directory_observation(components)?;
                    if observation.local_file != destination.local_file
                        || if lost {
                            observation.placeholder_state != 0
                                || observation.attributes & 0x400 != 0
                        } else {
                            observation.placeholder_state & 1 == 0
                                || observation.placeholder_state & 8 != 0
                                || observation.attributes & 0x400 == 0
                                || observation.opaque_identity.is_none()
                        }
                    {
                        return Err("native directory identity/conversion mismatch".into());
                    }
                    intents.push(record.intent.clone());
                    detail.push(json!({"record_id":record.intent.record_id,"generation":record.intent.record_generation,"commitment":record.commitment,"name":destination.name,"local_file":destination.local_file.file_index,"sequence":record.progress.sequence,"local_completed":record.progress.local_completed,"remote":format!("{:?}",record.progress.remote),"attention":format!("{:?}",record.progress.attention),"placeholder_state":observation.placeholder_state,"identity_present":observation.opaque_identity.is_some()}));
                }
                detail.sort_by_key(|item| item["name"].as_str().unwrap().to_owned());
                summary = json!(detail);
                captured_intents = intents;
                Ok(true)
            })?;
            if case(path) == "personal-losthint" {
                wait_for(|| {
                    Ok(agent
                        .provider
                        .namespace_status
                        .lock()
                        .unwrap()
                        .discarded_hints
                        > discarded_before_io)
                })?;
            }
            if lost {
                let before = agent.provider.namespace_status.lock().unwrap().clone();
                wait_for(|| {
                    let s = agent.provider.namespace_status.lock().unwrap();
                    Ok(s.ticks >= before.ticks + 24 && s.pages > before.pages)
                })?;
                // The owner inspection above was serialized after dispatch.
                // Submitted may initially have been projected as Uncertain
                // before the owner durably appended its truthful final event.
                // Refresh history only; never freeze the initial sequence/hash.
                wait_for(|| {
                    let records = match store.discover_account_root() {
                        Ok(records) => records,
                        Err(raiun_cloudfiles_windows::streamed_store::StoreError::Busy
                            | raiun_cloudfiles_windows::streamed_store::StoreError::IncompleteEvidence) => return Ok(false),
                        Err(_) => return Err("final authenticated history unavailable".into()),
                    };
                    if records.len() != 1
                        || captured_intents.len() != 1
                        || records[0].intent != captured_intents[0]
                    {
                        return Err("lost-response record identity or scope changed".into());
                    }
                    let record = &records[0];
                    if record.progress.remote != NamespacePhase::Submitted
                        || record.progress.attention != Some(NamespaceAttention::Uncertain)
                        || record.progress.local_completed
                    {
                        return Err("lost-response final retained state changed".into());
                    }
                    let mut settled = summary[0].clone();
                    settled["commitment"] = json!(record.commitment);
                    settled["sequence"] = json!(record.progress.sequence);
                    settled["local_completed"] = json!(record.progress.local_completed);
                    settled["remote"] = json!(format!("{:?}", record.progress.remote));
                    settled["attention"] = json!(format!("{:?}", record.progress.attention));
                    summary = json!([settled]);
                    Ok(true)
                })?;
            }
            if role == "save" {
                report(&path.join("RECORD.json"), summary.clone());
            } else {
                let old: Value = serde_json::from_slice(
                    &std::fs::read(path.join("RECORD.json"))
                        .map_err(|_| "restart receipt missing")?,
                )
                .map_err(|_| "restart receipt malformed")?;
                if old != summary {
                    return Err("durable identity/history changed across restart".into());
                }
            }
            let mut local = path.join("cloud-root");
            for part in parts(path) {
                local.push(part);
            }
            if case(path) == "personal-nested" {
                local.push("nested");
            }
            if !mixed
                && std::fs::read(local.join("retained-child.bin"))
                    .map_err(|_| "retained child unavailable")?
                    != CONTENT
            {
                return Err("retained child changed".into());
            }
            if agent.provider.folder_generation.load(Ordering::Acquire) != 0 {
                return Err("folder worker unexpectedly active".into());
            }
            let mixed_observation = if mixed {
                let o = agent.provider.mixed_namespace_observation()?;
                if o["held"] != false
                    || o["instance"] != mixed_instance
                    || o["directory_offers"] != 1
                {
                    return Err("shared dispatcher did not preserve one observer/one offer".into());
                }
                o
            } else {
                Value::Null
            };
            let observation = agent.provider.namespace_status.lock().unwrap().clone();
            Ok(
                json!({"shared_dispatcher":mixed_observation,"records":summary,"ticks":observation.ticks,"pages":observation.pages,"hints":observation.hints,"discarded_hints":observation.discarded_hints,"discarded_hints_after_io":observation.discarded_hints.saturating_sub(discarded_before_io),"continuity_lost":observation.continuity_lost,"retained":observation.retained,"retained_submitted_or_uncertain":observation.retained_submitted_or_uncertain,"producer_core_only":false,"inventory_unknown":true}),
            )
        };
        let exercise = std::panic::catch_unwind(std::panic::AssertUnwindSafe(exercise))
            .unwrap_or_else(|_| Err("automatic directory fixture assertion failed".into()));
        let counts = history_polls.get();
        let owner_before_cleanup = agent.provider.namespace_status.lock().ok().map(|s| {
            json!({"ticks":s.ticks,"pages":s.pages,"hints":s.hints,
                "completed":s.completed,"retained":s.retained,"attention":s.attention,
                "deferred":s.deferred,"retained_pre_send_deferred":s.retained_pre_send_deferred,
                "retained_submitted_or_uncertain":s.retained_submitted_or_uncertain,
                "continuity_lost":s.continuity_lost,"limit_reached":s.limit_reached})
        });
        let diagnostic = json!({"successful_history_polls":counts[0],"busy_history_polls":counts[1],
            "incomplete_history_polls":counts[2],"fatal_history_polls":counts[3],
            "latest_fatal_history_error_class":latest_fatal_history_error_class.get(),
            "latest_successful_history":latest_history.borrow().clone(),
            "owner_before_cleanup":owner_before_cleanup});
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let cleanup = broker.clone();
        std::thread::spawn(move || {
            let u = cleanup.handle(&request("unmount"));
            let s = cleanup.stop_all();
            let _ = send.send((u, s));
        });
        let mut cleanup_expired = false;
        let end = Instant::now() + Duration::from_secs(60);
        let cleanup = loop {
            match receive.recv_timeout(Duration::from_millis(100)) {
                Ok(value) => break Ok(value),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    break Err("cleanup owner disconnected");
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if Instant::now() >= end && !cleanup_expired {
                        cleanup_expired = true;
                        report(
                            &path.join(format!("{role}.cleanup-pending.json")),
                            json!({"pid":std::process::id(),"pending":true,"forced_stop":false}),
                        );
                    }
                }
            }
        };
        let normal = !cleanup_expired && cleanup.is_ok_and(|(u, s)| u.is_ok() && s.is_ok());
        let retained = if normal {
            let identity = agent
                .state
                .lock()
                .unwrap()
                .root_configuration
                .as_ref()
                .map(|root| raiun_cloudfiles_windows::ConfiguredRootIdentity {
                    volume_serial: root.volume_serial,
                    file_index: root.file_index,
                });
            identity.is_some_and(|identity| {
                raiun_cloudfiles_windows::pin_registered_configured_root(
                    &config.mount_path,
                    identity,
                )
                .is_ok()
            }) && spawn(path, &format!("verify-{role}"))
                .and_then(|child| wait_child(child, path, &format!("verify-{role}")))
                .is_ok()
        } else {
            false
        };
        let passed =
            exercise.is_ok() && normal && retained && !REPORT_FAILED.load(Ordering::Acquire);
        report(
            &path.join(format!("{role}.RESULTS.json")),
            json!({"passed":passed,"detail":exercise.as_ref().ok(),"error":exercise.as_ref().err(),"diagnostic":diagnostic,"normal_unmount_stop":normal,"forced_cleanup":false,"registrations_and_state_retained":retained}),
        );
        assert!(
            passed && !REPORT_FAILED.load(Ordering::Acquire),
            "automatic native directory case incomplete; evidence retained"
        );
    }
    fn populate_mixed(path: &Path) -> Result<(), String> {
        let root = path.join("cloud-root");
        let _ = std::fs::read_dir(&root)
            .map_err(|_| "mixed root enumeration failed")?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "mixed root entry failed")?;
        let entries = std::fs::read_dir(root.join("Personal"))
            .map_err(|_| "mixed Personal enumeration failed")?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "mixed Personal entry failed")?;
        if !entries
            .iter()
            .any(|e| e.file_name() == "provider-directory")
        {
            return Err("provider directory was not materialized".into());
        }
        Ok(())
    }
    #[test]
    #[ignore = "real single-observer shared directory owner; explicit fresh native wrapper only"]
    fn synthetic_shared_mixed_cloud_directory_and_ordinary_mkdir() {
        assert_eq!(
            std::env::var(MIXED_FLAG).as_deref(),
            Ok("fresh-owned-state")
        );
        let directory = PathBuf::from(std::env::var_os(DIRECTORY).expect("explicit mixed wrapper"));
        assert!(directory.is_absolute());
        let args = std::env::args().collect::<Vec<_>>();
        assert!(
            args.iter().any(|a| a == "--ignored")
                && args
                    .windows(2)
                    .any(|p| p[0] == "--exact" && p[1] == MIXED_TEST)
        );
        if let Ok(role) = std::env::var(ROLE) {
            assert_eq!(case(&directory), "personal-mixed");
            assert!(owned(&directory));
            match role.as_str() {
                "save" => runtime(&directory, &role),
                "populate" => populate_mixed(&directory).unwrap(),
                "io" => create_io(&directory).unwrap(),
                "verify-save" => verify_io(&directory).unwrap(),
                _ => panic!("unsupported mixed child"),
            }
            return;
        }
        use std::os::windows::fs::MetadataExt;
        assert!(
            std::fs::symlink_metadata(&directory)
                .is_ok_and(|m| m.is_dir() && m.file_attributes() & 0x400 == 0)
        );
        assert!(
            std::fs::symlink_metadata(directory.join("OWNER.txt"))
                .is_ok_and(|m| m.is_file() && m.file_attributes() & 0x400 == 0)
        );
        assert_eq!(
            std::fs::read(directory.join("OWNER.txt")).unwrap(),
            MIXED_OWNER.as_bytes()
        );
        let entries = std::fs::read_dir(&directory)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(entries.iter().all(|e| matches!(
            e.file_name().to_str(),
            Some("OWNER.txt" | "runner.json" | "supervisor.stdout.log" | "supervisor.stderr.log")
        )));
        let path = directory.join("personal-mixed");
        std::fs::create_dir(&path).unwrap();
        std::fs::create_dir(path.join("cloud-root")).unwrap();
        std::fs::write(path.join("OWNER.txt"), MIXED_OWNER).unwrap();
        let (server, fixture) = super::super::super::tests::synthetic_mixed_directory_server();
        report(
            &path.join("config.json"),
            json!({"schema_version":1,"server":server,"auth":"app_token","username":"synthetic-user","mount_path":path.join("cloud-root"),"auto_mount":true,"remember_login":true,"reconnect_interval_seconds":1,"profile":"default"}),
        );
        let save = spawn(&path, "save").and_then(|child| wait_child(child, &path, "save"));
        let remote = fixture.directory_observation();
        let expected = json!([format!("{PERSONAL}/{NAME}")]);
        let passed = save.is_ok()
            && !REPORT_FAILED.load(Ordering::Acquire)
            && remote["attempts"] == expected
            && remote["created"] == expected
            && remote["invalid"] == 0
            && fixture.global_mutation_attempts() == 1;
        report(
            &directory.join("RESULTS.json"),
            json!({"fixture":"shared-mixed-directory-v1","passed":passed,"save":save,"remote":remote,"global_mutations":fixture.global_mutation_attempts(),"native_execution":true,"production_enabled":false,"directory_routing_ready":false,"state_deletion_requested":false,"replay":false}),
        );
        fixture.join().unwrap();
        assert!(
            passed && !REPORT_FAILED.load(Ordering::Acquire),
            "mixed native directory failed; preserve cohort, no replay"
        );
    }
    #[test]
    #[ignore = "actual automatic OS mkdir via real Broker; explicit authorized fresh local NTFS diagnostic only"]
    fn synthetic_headless_automatic_directory_create() {
        let requested =
            selected(std::env::var_os(CASE).as_deref()).expect("exact diagnostic selector");
        let directory =
            PathBuf::from(std::env::var_os(DIRECTORY).expect("explicit fixture directory"));
        assert!(directory.is_absolute() && owned(&directory));
        let args = std::env::args().collect::<Vec<_>>();
        assert!(
            args.iter().any(|a| a == "--ignored")
                && args.windows(2).any(|p| p[0] == "--exact" && p[1] == TEST)
        );
        if let Ok(role) = std::env::var(ROLE) {
            assert!(requested.contains(&case(&directory)));
            match role.as_str() {
                "save" | "restart" => runtime(&directory, &role),
                "io" => create_io(&directory).unwrap(),
                "verify-save" | "verify-restart" => verify_io(&directory).unwrap(),
                _ => panic!("unsupported role"),
            };
            return;
        }
        let entries = std::fs::read_dir(&directory)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(entries.iter().all(|entry| matches!(
            entry.file_name().to_str(),
            Some("OWNER.txt" | "runner.json" | "supervisor.stdout.log" | "supervisor.stderr.log")
        )));
        let mut results = Vec::new();
        for case in &requested {
            let path = directory.join(case);
            std::fs::create_dir(&path).unwrap();
            std::fs::create_dir(path.join("cloud-root")).unwrap();
            std::fs::write(path.join("OWNER.txt"), OWNER).unwrap();
            let lost = *case == "personal-lostresponse";
            let (server, fixture) =
                super::super::super::tests::synthetic_headless_directory_server(lost);
            report(
                &path.join("config.json"),
                json!({"schema_version":1,"server":server,"auth":"app_token","username":"synthetic-user","mount_path":path.join("cloud-root"),"auto_mount":true,"remember_login":true,"reconnect_interval_seconds":1,"profile":"default"}),
            );
            let save = spawn(&path, "save").and_then(|child| wait_child(child, &path, "save"));
            let restart = if save.is_ok() && lost {
                spawn(&path, "restart").and_then(|child| wait_child(child, &path, "restart"))
            } else {
                Ok(())
            };
            let remote = fixture.directory_observation();
            let expected = if *case == "personal-nested" { 2 } else { 1 };
            let passed = !REPORT_FAILED.load(Ordering::Acquire)
                && save.is_ok()
                && restart.is_ok()
                && remote["attempts"]
                    .as_array()
                    .is_some_and(|v| v.len() == expected)
                && remote["created"]
                    .as_array()
                    .is_some_and(|v| v.len() == expected)
                && remote["invalid"] == 0
                && fixture.global_mutation_attempts() == expected;
            results.push(json!({"case":case,"passed":passed,"save":save,"restart":restart,"remote":remote,"global_mutations":fixture.global_mutation_attempts()}));
            report(
                &directory.join("RESULTS.json"),
                json!({"fixture":"headless-automatic-directory-v1","requested_cases":requested,"passed":results.len()==requested.len()&&results.iter().all(|r|r["passed"]==true),"cases":results,"native_execution":true,"automatic_os_discovery":true,"folder_sync":false,"live_server":false,"production_enabled":false,"forced_cleanup":false,"registrations_and_state_retained":passed}),
            );
            fixture.join().unwrap();
            assert!(
                passed && !REPORT_FAILED.load(Ordering::Acquire),
                "automatic directory case failed; preserve evidence and stop selectors"
            );
        }
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    use std::io::Read;
    fn send(
        model: &mut DirectoryModel,
        method: &str,
        path: &str,
        depth: Option<&str>,
        body: &[u8],
    ) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let headers = depth
            .map(|value| vec![("depth".to_string(), value.to_string())])
            .unwrap_or_default();
        assert!(model.handle(
            "http://127.0.0.1:1234",
            &format!("{method} {path} HTTP/1.1"),
            &headers,
            body,
            &mut server
        ));
        drop(server);
        let mut reply = String::new();
        client.read_to_string(&mut reply).unwrap();
        reply
    }
    #[test]
    fn dynamic_contract_has_exact_root_ids_create_only_and_independent_listing() {
        let mut model = DirectoryModel::new(false);
        let path = format!("{PROJECTS}/{NAME}");
        let root = send(&mut model, "PROPFIND", PROJECTS, Some("0"), b"<propfind/>");
        assert!(root.contains("synthetic-project-root"));
        assert!(root.contains("<d:getetag>\"synthetic-project-root-v1\"</d:getetag>"));
        assert!(!root.contains("&quot;"));
        assert!(send(&mut model, "PROPFIND", &path, Some("0"), b"").starts_with("HTTP/1.1 404"));
        assert!(send(&mut model, "MKCOL", &path, None, b"").starts_with("HTTP/1.1 201"));
        assert!(
            send(&mut model, "PROPFIND", &path, Some("0"), b"")
                .contains("synthetic-auto-directory-1")
        );
        assert!(send(&mut model, "MKCOL", &path, None, b"").starts_with("HTTP/1.1 405"));
        assert!(send(&mut model, "PROPFIND", PROJECTS, Some("1"), b"").contains(&path));
        assert_eq!(model.observation()["created"].as_array().unwrap().len(), 1);
    }
    #[test]
    fn lost_response_commits_once_and_nested_requires_existing_parent() {
        let mut model = DirectoryModel::new(true);
        let path = format!("{PERSONAL}/{NAME}");
        assert!(
            send(&mut model, "MKCOL", &format!("{path}/nested"), None, b"")
                .starts_with("HTTP/1.1 409")
        );
        assert!(send(&mut model, "MKCOL", &path, None, b"").is_empty());
        assert!(
            send(&mut model, "PROPFIND", &path, Some("0"), b"")
                .contains("synthetic-auto-directory-1")
        );
        assert!(send(&mut model, "MKCOL", &path, None, b"").starts_with("HTTP/1.1 405"));
        assert!(
            send(&mut model, "MKCOL", &format!("{path}/nested"), None, b"")
                .starts_with("HTTP/1.1 201")
        );
        assert_eq!(model.observation()["created"].as_array().unwrap().len(), 2);
    }
    #[test]
    fn strict_contract_refuses_unplanned_routes_mutations_and_bodies() {
        let mut model = DirectoryModel::new(false);
        let path = format!("{PERSONAL}/{NAME}");
        assert!(send(&mut model, "MKCOL", &path, None, b"unexpected").starts_with("HTTP/1.1 400"));
        assert!(send(&mut model, "DELETE", &path, None, b"").starts_with("HTTP/1.1 405"));
        assert!(
            send(
                &mut model,
                "PROPFIND",
                &format!("{PERSONAL}/unknown"),
                Some("0"),
                b""
            )
            .starts_with("HTTP/1.1 400")
        );
        assert_eq!(model.observation()["created"], json!([]));
    }
    #[test]
    fn selectors_and_loopback_guard_are_exact() {
        assert_eq!(selected(None).unwrap(), CASES);
        assert_eq!(
            selected(Some(std::ffi::OsStr::new("space-success"))).unwrap(),
            vec!["space-success"]
        );
        for bad in ["", "all", "SPACE-SUCCESS", "../personal-success"] {
            assert!(selected(Some(std::ffi::OsStr::new(bad))).is_err());
        }
        assert!(loopback("http://127.0.0.1:1234"));
        assert!(!loopback("https://127.0.0.1:1234"));
        assert!(!loopback("http://localhost:1234"));
    }
}

//! Read-only inspection of the active Windows provider's authenticated catalog.
use super::*;

#[derive(Clone)]
pub(super) struct CacheStatusRow {
    space_id: String,
    root_resource_id: String,
    path: String,
    resource_id: String,
    etag: String,
    size: u64,
}

impl CacheStatusRow {
    fn parse(request: &Value) -> Result<Self, String> {
        fn field(request: &Value, name: &str, limit: usize) -> Result<String, String> {
            request
                .get(name)
                .and_then(Value::as_str)
                .filter(|value| {
                    !value.trim().is_empty()
                        && value.len() <= limit
                        && !value.chars().any(char::is_control)
                })
                .map(str::to_owned)
                .ok_or_else(|| "Refresh the listed file before checking its saved status".into())
        }
        let row = Self {
            space_id: field(request, "space_id", 512)?,
            root_resource_id: field(request, "root_resource_id", 16 * 1024)?,
            path: field(request, "path", 16 * 1024)?,
            resource_id: field(request, "resource_id", 16 * 1024)?,
            etag: field(request, "etag", 16 * 1024)?,
            size: request
                .get("size")
                .and_then(Value::as_u64)
                .ok_or("Refresh the listed file size")?,
        };
        if !row.path.starts_with('/')
            || row.path.ends_with('/')
            || row.path.contains("//")
            || row.path.contains('\\')
            || row.path.split('/').any(|part| matches!(part, "." | ".."))
        {
            return Err("Refresh the listed file path".into());
        }
        Ok(row)
    }

    pub(super) fn expectation(&self) -> raiun_cloudfiles_windows::FileCacheBindingExpectation<'_> {
        raiun_cloudfiles_windows::FileCacheBindingExpectation {
            space_id: &self.space_id,
            root_resource_id: &self.root_resource_id,
            path: &self.path,
            resource_id: &self.resource_id,
            etag: &self.etag,
            size: self.size,
        }
    }
}

pub(super) struct FolderJobRequest {
    job_id: String,
    space_id: String,
    root_resource_id: String,
    path: String,
    resource_id: String,
    mode: FolderJobMode,
}

enum FolderJobMode {
    Create,
    Resume(String),
    Refresh {
        active: String,
        staging: Option<String>,
    },
}

impl FolderJobRequest {
    fn parse(request: &Value, operation: &str) -> Result<Self, String> {
        fn field(request: &Value, name: &str, limit: usize) -> Result<String, String> {
            request
                .get(name)
                .and_then(Value::as_str)
                .filter(|s| {
                    !s.trim().is_empty() && s.len() <= limit && !s.chars().any(char::is_control)
                })
                .map(str::to_owned)
                .ok_or_else(|| "Refresh the listed folder".into())
        }
        fn pin(request: &Value, name: &str) -> Result<String, String> {
            let id = field(request, name, 64)?;
            if id.len() != 64
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("Select the exact saved folder snapshot".into());
            }
            Ok(id)
        }
        let job_id = field(request, "job_id", 32)?;
        if job_id.len() != 32
            || !job_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("Prepare the offline folder job first".into());
        }
        let path = field(request, "path", 16 * 1024)?;
        if !path.starts_with('/')
            || (path != "/" && path.ends_with('/'))
            || path.contains("//")
            || path.contains('\\')
            || path.split('/').any(|part| matches!(part, "." | ".."))
        {
            return Err("Refresh the listed folder path".into());
        }
        let mode = match operation {
            "folder_start" => FolderJobMode::Create,
            "folder_resume" => FolderJobMode::Resume(pin(request, "pin_id")?),
            "folder_refresh" => FolderJobMode::Refresh {
                active: pin(request, "pin_id")?,
                staging: match request.get("staging_pin_id") {
                    None | Some(Value::Null) => None,
                    Some(_) => Some(pin(request, "staging_pin_id")?),
                },
            },
            _ => return Err("Unsupported offline folder operation".into()),
        };
        Ok(Self {
            job_id,
            space_id: field(request, "space_id", 512)?,
            root_resource_id: field(request, "root_resource_id", 16 * 1024)?,
            resource_id: field(request, "resource_id", 16 * 1024)?,
            path,
            mode,
        })
    }

    pub(super) fn job_id(&self) -> &str {
        &self.job_id
    }

    pub(super) fn run(
        self,
        backend: &raiun_cloudfiles_windows::OpenCloudPlaceholderBackend,
        cancellation: &raiun_cloudfiles_windows::CancellationToken,
        progress: &mut dyn FnMut(raiun_cache::PinInfo),
    ) -> Result<(), raiun_cloudfiles_windows::OfflineDownloadError> {
        let expected = raiun_cloudfiles_windows::FolderCacheBindingExpectation {
            space_id: &self.space_id,
            root_resource_id: &self.root_resource_id,
            path: &self.path,
            resource_id: &self.resource_id,
        };
        match self.mode {
            FolderJobMode::Create => {
                backend.pin_folder_offline_for_binding(&expected, cancellation, progress)
            }
            FolderJobMode::Resume(pin) => {
                backend.resume_folder_offline_for_binding(&expected, &pin, cancellation, progress)
            }
            FolderJobMode::Refresh { active, staging } => backend
                .refresh_folder_offline_for_binding(
                    &expected,
                    &active,
                    staging.as_deref(),
                    cancellation,
                    progress,
                ),
        }
        .map(|_| ())
    }
}

pub(super) fn inspect_worker_folder_page(
    generation: u64,
    expected: &ActiveProviderBinding,
    active: Option<&ActiveProviderBinding>,
    connected: bool,
    backend: Option<&raiun_cloudfiles_windows::OpenCloudPlaceholderBackend>,
    cursor: Option<&str>,
    cancellation: &raiun_cloudfiles_windows::CancellationToken,
) -> Result<Value, String> {
    if generation == 0
        || generation != expected.generation
        || !connected
        || active != Some(expected)
    {
        return Err("The Windows drive changed; refresh the folder list".into());
    }
    let backend = backend
        .filter(|b| !b.is_revoked())
        .ok_or("The Windows drive is disconnected")?;
    let page = backend
        .listed_folder_page(cursor, cancellation)
        .map_err(|_| "The listed folders changed; refresh the folder list")?;
    serde_json::to_value(page).map_err(|_| "The folder list is unavailable".to_owned())
}

pub(super) fn inspect_worker_cache_status(
    generation: u64,
    expected: &ActiveProviderBinding,
    active: Option<&ActiveProviderBinding>,
    connected: bool,
    backend: Option<&raiun_cloudfiles_windows::OpenCloudPlaceholderBackend>,
    row: &CacheStatusRow,
) -> Result<raiun_cloudfiles_windows::FileCacheStatus, String> {
    if generation == 0
        || generation != expected.generation
        || !connected
        || active != Some(expected)
    {
        return Err("The Windows drive changed; refresh the file status".into());
    }
    let backend = backend
        .filter(|backend| !backend.is_revoked())
        .ok_or("The Windows drive is disconnected")?;
    backend
        .file_cache_status_for_binding(
            &row.expectation(),
            &raiun_cloudfiles_windows::CancellationToken::new(),
        )
        .map_err(|_| "The saved file status no longer matches this listed version".into())
}

pub(super) fn inspect_worker_file_page(
    generation: u64,
    expected: &ActiveProviderBinding,
    active: Option<&ActiveProviderBinding>,
    connected: bool,
    backend: Option<&raiun_cloudfiles_windows::OpenCloudPlaceholderBackend>,
    cursor: Option<&str>,
    cancellation: &raiun_cloudfiles_windows::CancellationToken,
) -> Result<Value, String> {
    if generation == 0
        || generation != expected.generation
        || !connected
        || active != Some(expected)
    {
        return Err("The Windows drive changed; refresh the file list".into());
    }
    let backend = backend
        .filter(|backend| !backend.is_revoked())
        .ok_or("The Windows drive is disconnected")?;
    let page = backend
        .listed_file_page(cursor, cancellation)
        .map_err(|_| "The listed files changed; refresh the file list")?;
    serde_json::to_value(page).map_err(|_| "The file list is unavailable".to_owned())
}

struct CancelFilePageOnDrop(raiun_cloudfiles_windows::CancellationToken);
impl Drop for CancelFilePageOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

impl WindowsAgent {
    pub(super) fn windows_file_cache_status(&self, request: &Value) -> Result<Value, String> {
        self.windows_file_request(request, None)
    }

    pub(super) fn windows_offline_file_request(
        &self,
        request: &Value,
        operation: &str,
    ) -> Result<Value, String> {
        self.windows_file_request(request, Some(operation))
    }

    pub(super) fn windows_offline_folder_request(
        &self,
        request: &Value,
        operation: &str,
    ) -> Result<Value, String> {
        let operation = match operation {
            "list" => "folder_list",
            "prepare" => "folder_prepare",
            "start" => "folder_start",
            "resume" => "folder_resume",
            "refresh" => "folder_refresh",
            "status" => "folder_status",
            "cancel" => "folder_cancel",
            _ => return Err("Unsupported offline folder operation".into()),
        };
        self.windows_file_request(request, Some(operation))
    }

    fn windows_file_request(
        &self,
        request: &Value,
        operation: Option<&str>,
    ) -> Result<Value, String> {
        if request.get("profile_id").and_then(Value::as_str) != Some(self.profile_scope.as_str()) {
            return Err("Select the current Windows account".into());
        }
        let generation = request
            .get("expected_generation")
            .and_then(Value::as_u64)
            .filter(|value| *value != 0)
            .ok_or("Refresh the Windows drive status")?;
        let token = request
            .get("expected_recovery_scope_token")
            .and_then(Value::as_str)
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or("Refresh the Windows drive identity")?;
        let row = if operation.is_none() || operation == Some("start") {
            Some(CacheStatusRow::parse(request)?)
        } else {
            None
        };
        let folder = match operation {
            Some(op @ ("folder_start" | "folder_resume" | "folder_refresh")) => {
                Some(FolderJobRequest::parse(request, op)?)
            }
            _ => None,
        };
        // No refresh or discovery is started by this read. The active backend,
        // not request fields, owns account/origin/cache/catalog authority.
        let (session, configuration) = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            self.check_cache_status_account(&state, generation, token)?;
            (
                state.session.clone().ok_or("Connect this account")?,
                state
                    .root_configuration
                    .clone()
                    .ok_or("Choose the Windows drive")?,
            )
        };
        let owner = configuration
            .registration_ownership
            .as_ref()
            .ok_or("The drive identity is unavailable")?;
        let identity = raiun_cloudfiles_windows::ConfiguredRootIdentity {
            volume_serial: configuration.volume_serial,
            file_index: configuration.file_index,
        };
        // Retain the exact local root pin through the worker round trip.
        let root_lease = pin_registered_configured_root(Path::new(&configuration.path), identity)
            .map_err(root_error_text)?;
        if root_lease.identity() != identity {
            return Err("The Windows drive identity changed".into());
        }
        let binding = ActiveProviderBinding {
            generation,
            path: PathBuf::from(&configuration.path),
            identity,
            personal_space_id: owner.personal_drive_id.clone(),
            personal_root_resource_id: owner
                .personal_root_resource_id
                .clone()
                .ok_or("Refresh the Windows drive identity")?,
        };
        let (cache_status, job_status) = match operation {
            Some("list" | "folder_list") => {
                let cursor = match request.get("cursor") {
                    None | Some(Value::Null) => None,
                    Some(value) => Some(
                        value
                            .as_str()
                            .filter(|value| {
                                value.len() == 32
                                    && value
                                        .bytes()
                                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                            })
                            .ok_or("Refresh the file list")?
                            .to_owned(),
                    ),
                };
                let cancellation = raiun_cloudfiles_windows::CancellationToken::with_timeout(
                    Duration::from_secs(5),
                );
                let _cancel_on_return = CancelFilePageOnDrop(cancellation.clone());
                let (response, result) = std::sync::mpsc::sync_channel(1);
                let command = if operation == Some("folder_list") {
                    ProviderCommand::ListOfflineFolders {
                        binding,
                        cursor,
                        cancellation,
                        response,
                    }
                } else {
                    ProviderCommand::ListOfflineFiles {
                        binding,
                        cursor,
                        cancellation,
                        response,
                    }
                };
                self.provider
                    .commands
                    .try_send(command)
                    .map_err(|_| "Windows file inspection is unavailable")?;
                (
                    None,
                    Some(
                        result
                            .recv_timeout(Duration::from_secs(30))
                            .map_err(|_| "Windows file inspection stopped")??,
                    ),
                )
            }
            None => {
                let (response, result) = std::sync::mpsc::sync_channel(1);
                self.provider
                    .commands
                    .try_send(ProviderCommand::FileCacheStatus {
                        binding,
                        row: row.ok_or("Refresh the listed file")?,
                        response,
                    })
                    .map_err(|_| "Windows drive inspection is unavailable")?;
                (
                    Some(
                        result
                            .recv_timeout(Duration::from_secs(30))
                            .map_err(|_| "Windows drive inspection stopped")??,
                    ),
                    None,
                )
            }
            Some("start") => {
                let (response, result) = std::sync::mpsc::sync_channel(1);
                self.provider
                    .commands
                    .try_send(ProviderCommand::StartOfflineFile {
                        binding,
                        row: row.ok_or("Refresh the listed file")?,
                        response,
                    })
                    .map_err(|_| "Offline file admission is unavailable")?;
                (
                    None,
                    Some(
                        result
                            .recv_timeout(Duration::from_secs(30))
                            .map_err(|_| "Offline file admission stopped")??,
                    ),
                )
            }
            Some("folder_prepare") => {
                let (response, result) = std::sync::mpsc::sync_channel(1);
                self.provider
                    .commands
                    .try_send(ProviderCommand::PrepareOfflineFolder { binding, response })
                    .map_err(|_| "Offline folder preparation is unavailable")?;
                (
                    None,
                    Some(
                        result
                            .recv_timeout(Duration::from_secs(30))
                            .map_err(|_| "Offline folder preparation stopped")??,
                    ),
                )
            }
            Some("folder_start" | "folder_resume" | "folder_refresh") => {
                let (response, result) = std::sync::mpsc::sync_channel(1);
                self.provider
                    .commands
                    .try_send(ProviderCommand::StartOfflineFolder {
                        binding,
                        request: folder.ok_or("Refresh the listed folder")?,
                        response,
                    })
                    .map_err(|_| "Offline folder admission is unavailable")?;
                (
                    None,
                    Some(
                        result
                            .recv_timeout(Duration::from_secs(30))
                            .map_err(|_| "Offline folder admission stopped")??,
                    ),
                )
            }
            Some("status" | "cancel" | "folder_status" | "folder_cancel") => {
                let id = request
                    .get("job_id")
                    .and_then(Value::as_str)
                    .filter(|id| {
                        id.len() == 32
                            && id
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                    .ok_or("Select the current offline job")?;
                (
                    None,
                    Some(self.provider.offline_jobs.inspect(
                        &binding,
                        id,
                        matches!(operation, Some("cancel" | "folder_cancel")),
                    )?),
                )
            }
            _ => return Err("Unsupported offline file operation".into()),
        };
        let state = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?;
        self.check_cache_status_account(&state, generation, token)?;
        if state.root_configuration.as_ref() != Some(&configuration)
            || state.session.as_ref().is_none_or(|current| {
                current.server != session.server
                    || current.client_id != session.client_id
                    || current.access_token != session.access_token
                    || current.expires_at != session.expires_at
            })
        {
            return Err("The account changed; refresh the file status".into());
        }
        if let Some(mut status) = job_status {
            if matches!(operation, Some("list" | "folder_list")) {
                // Attach scope only after the account/session/root postflight.
                status["profile_id"] = json!(self.profile_scope.as_str());
                status["auth_generation"] = json!(generation);
                status["recovery_scope_token"] = json!(token);
            }
            return Ok(status);
        }
        let status = cache_status.ok_or("The file status is unavailable")?;
        let policy = match status.policy {
            raiun_cache::AvailabilityPolicy::Recent => "recent",
            raiun_cache::AvailabilityPolicy::AlwaysOffline => "always_offline",
            raiun_cache::AvailabilityPolicy::CloudOnly => "cloud_only",
        };
        Ok(
            json!({"profile_id":self.profile_scope.as_str(), "auth_generation":generation,
            "recovery_scope_token":token, "read_only":true, "last_observed":true,
            "atomic_snapshot":false, "policy":policy,
            "pending_offline_intent":status.pending_offline_intent,
            "recorded_complete_version":status.recorded_complete_version,
            "recorded_bytes":status.recorded_bytes}),
        )
    }

    pub(super) fn check_cache_status_account(
        &self,
        state: &AccountState,
        generation: u64,
        token: &str,
    ) -> Result<(), String> {
        if state.active_generation != generation
            || self.generation.load(Ordering::Acquire) != generation
            || self.provider.authorized_generation.load(Ordering::Acquire) != generation
            || !state.online_authenticated
            || state.logout_pending
            || state.authenticating
            || state.refreshing
            || state.needs_refresh
            || state.session_cleanup_uncertain
        {
            return Err("The account changed; refresh the file status".into());
        }
        let session = state.session.as_ref().ok_or("Connect this account")?;
        let configuration = state
            .root_configuration
            .as_ref()
            .ok_or("Choose the Windows drive")?;
        if session.expires_at <= unix_time_now().saturating_add(30)
            || !configuration.valid
            || configuration.profile_scope != self.profile_scope
            || configuration.server != session.server
            || configuration.client_id != session.client_id
        {
            return Err("The file status does not match the connected account".into());
        }
        let owner = configuration
            .registration_ownership
            .as_ref()
            .filter(|owner| owner.state == "registered")
            .ok_or("The Windows drive is not registered")?;
        validate_registration_ownership(
            owner,
            &session.server,
            configuration.volume_serial,
            configuration.file_index,
        )?;
        if owner
            .personal_root_resource_id
            .as_ref()
            .is_none_or(|root| root.trim().is_empty())
            || self
                .provider
                .configuration_recovery_scope_token(configuration, generation)?
                != token
        {
            return Err("The Windows drive identity changed; refresh the file status".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const PIN_B: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    fn folder_value(path: &str) -> Value {
        json!({
            "job_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "space_id":"space",
            "root_resource_id":"root",
            "path":path,
            "resource_id":"folder",
        })
    }

    fn folder_binding(generation: u64) -> ActiveProviderBinding {
        ActiveProviderBinding {
            generation,
            path: PathBuf::from(r"C:\Synthetic"),
            identity: raiun_cloudfiles_windows::ConfiguredRootIdentity {
                volume_serial: 1,
                file_index: 2,
            },
            personal_space_id: "personal".into(),
            personal_root_resource_id: "root".into(),
        }
    }

    fn row_value() -> Value {
        json!({"space_id":"space", "root_resource_id":"root", "path":"/folder/file",
            "resource_id":"file", "etag":"\"v1\"", "size":42})
    }

    #[test]
    fn cache_status_row_requires_complete_exact_metadata_without_path_aliases() {
        let value = row_value();
        let row = CacheStatusRow::parse(&value).unwrap();
        let expected = row.expectation();
        assert_eq!(expected.path, "/folder/file");
        assert_eq!(expected.root_resource_id, "root");
        assert_eq!(expected.size, 42);
        for key in [
            "space_id",
            "root_resource_id",
            "path",
            "resource_id",
            "etag",
            "size",
        ] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(CacheStatusRow::parse(&missing).is_err(), "{key}");
        }
        for path in [
            "/",
            "relative",
            "/folder/",
            "/folder//file",
            "/folder/../file",
            "/folder/./file",
            "/folder\\file",
            "/folder/fi\nle",
        ] {
            let mut invalid = value.clone();
            invalid["path"] = json!(path);
            assert!(CacheStatusRow::parse(&invalid).is_err(), "{path:?}");
        }
        for size in [json!(-1), json!(1.5), json!("42"), Value::Null] {
            let mut invalid = value.clone();
            invalid["size"] = size;
            assert!(CacheStatusRow::parse(&invalid).is_err());
        }
    }

    #[test]
    fn cache_status_worker_rejects_missing_or_different_connection_before_backend() {
        let row = CacheStatusRow::parse(&row_value()).unwrap();
        let binding = ActiveProviderBinding {
            generation: 7,
            path: PathBuf::from(r"C:\Synthetic"),
            identity: raiun_cloudfiles_windows::ConfiguredRootIdentity {
                volume_serial: 1,
                file_index: 2,
            },
            personal_space_id: "personal".into(),
            personal_root_resource_id: "root".into(),
        };
        assert!(inspect_worker_cache_status(7, &binding, None, false, None, &row).is_err());
        assert!(
            inspect_worker_cache_status(8, &binding, Some(&binding), true, None, &row).is_err()
        );
        let mut other = binding.clone();
        other.personal_root_resource_id = "different".into();
        assert!(inspect_worker_cache_status(7, &binding, Some(&other), true, None, &row).is_err());
        // Even an otherwise matching connection cannot default missing storage
        // to Recent/zero bytes or synthesize a successful status.
        assert!(
            inspect_worker_cache_status(7, &binding, Some(&binding), true, None, &row).is_err()
        );
    }

    #[test]
    fn folder_job_parser_accepts_root_start_and_exact_resume_refresh_ids() {
        let start = FolderJobRequest::parse(&folder_value("/"), "folder_start").unwrap();
        assert_eq!(start.path, "/");
        assert!(matches!(start.mode, FolderJobMode::Create));

        let mut resume_value = folder_value("/Documents");
        resume_value["pin_id"] = json!(PIN_A);
        let resume = FolderJobRequest::parse(&resume_value, "folder_resume").unwrap();
        assert_eq!(resume.path, "/Documents");
        assert!(matches!(resume.mode, FolderJobMode::Resume(id) if id == PIN_A));

        let mut refresh_value = folder_value("/");
        refresh_value["pin_id"] = json!(PIN_A);
        refresh_value["staging_pin_id"] = json!(PIN_B);
        let refresh = FolderJobRequest::parse(&refresh_value, "folder_refresh").unwrap();
        assert!(matches!(
            refresh.mode,
            FolderJobMode::Refresh { active, staging: Some(staging) }
                if active == PIN_A && staging == PIN_B
        ));

        refresh_value["staging_pin_id"] = Value::Null;
        let refresh_without_stage =
            FolderJobRequest::parse(&refresh_value, "folder_refresh").unwrap();
        assert!(matches!(
            refresh_without_stage.mode,
            FolderJobMode::Refresh { active, staging: None } if active == PIN_A
        ));
    }

    #[test]
    fn folder_job_parser_rejects_invalid_paths_fields_and_snapshot_ids() {
        for path in [
            "",
            "relative",
            "/folder/",
            "/folder//child",
            "/folder/../child",
            "/folder/./child",
            "/folder\\child",
            "/folder/with\ncontrol",
        ] {
            assert!(
                FolderJobRequest::parse(&folder_value(path), "folder_start").is_err(),
                "accepted invalid folder path {path:?}"
            );
        }

        let mut invalid = folder_value("/");
        invalid["space_id"] = json!("x".repeat(513));
        assert!(FolderJobRequest::parse(&invalid, "folder_start").is_err());
        invalid = folder_value("/");
        invalid["resource_id"] = json!("x".repeat(16 * 1024 + 1));
        assert!(FolderJobRequest::parse(&invalid, "folder_start").is_err());
        invalid = folder_value("/");
        invalid["path"] = json!(format!("/{}", "x".repeat(16 * 1024)));
        assert!(FolderJobRequest::parse(&invalid, "folder_start").is_err());
        invalid = folder_value("/");
        invalid["root_resource_id"] = json!("bad\nroot");
        assert!(FolderJobRequest::parse(&invalid, "folder_start").is_err());
        assert!(FolderJobRequest::parse(&folder_value("/"), "unknown").is_err());

        let bad_ids = [
            String::new(),
            "0".repeat(63),
            "0".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
        ];
        for bad_id in bad_ids {
            let mut resume = folder_value("/");
            resume["pin_id"] = json!(bad_id);
            assert!(FolderJobRequest::parse(&resume, "folder_resume").is_err());
        }

        let mut refresh = folder_value("/");
        refresh["pin_id"] = json!(PIN_A);
        refresh["staging_pin_id"] = json!("not-a-pin");
        assert!(FolderJobRequest::parse(&refresh, "folder_refresh").is_err());
    }

    #[test]
    fn folder_worker_rejects_stale_or_unbound_connection_before_backend_access() {
        let expected = folder_binding(17);
        let cancellation = raiun_cloudfiles_windows::CancellationToken::new();

        assert!(
            inspect_worker_folder_page(
                18,
                &expected,
                Some(&expected),
                true,
                None,
                None,
                &cancellation,
            )
            .is_err()
        );

        let mut other_binding = expected.clone();
        other_binding.personal_root_resource_id = "other-root".into();
        assert!(
            inspect_worker_folder_page(
                17,
                &expected,
                Some(&other_binding),
                true,
                None,
                None,
                &cancellation,
            )
            .is_err()
        );

        assert!(
            inspect_worker_folder_page(
                17,
                &expected,
                Some(&expected),
                false,
                None,
                None,
                &cancellation,
            )
            .is_err()
        );
        assert!(
            inspect_worker_folder_page(
                17,
                &expected,
                Some(&expected),
                true,
                None,
                None,
                &cancellation,
            )
            .is_err()
        );
    }
}

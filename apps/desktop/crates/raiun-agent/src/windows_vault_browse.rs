//! Online read-only dialog listing. No native catalogue or custody publication.
use super::*;
use raiun_core::{backend::RemoteEntry, validate_remote_path};
use raiun_vault::session::VaultSessionScope;

const REFUSED: &str =
    "Encrypted folder browsing is unavailable; reconnect and unlock this location";
const INVALID: &str = "Invalid encrypted folder browsing request";
const RESPONSE_LIMIT: usize = raiun_control::MAX_CONTROL_MESSAGE_BYTES / 2;

struct BrowseRequest {
    profile: String,
    generation: u64,
    space: String,
    root: String,
    resource: String,
    path: String,
}
fn decode(value: &Value) -> Result<BrowseRequest, String> {
    let fields = value.as_object().ok_or(INVALID)?;
    const KEYS: [&str; 7] = [
        "action",
        "profile_id",
        "expected_auth_generation",
        "space_id",
        "root_path",
        "root_resource_id",
        "path",
    ];
    if fields.len() != KEYS.len()
        || fields.keys().any(|key| !KEYS.contains(&key.as_str()))
        || fields.get("action").and_then(Value::as_str) != Some("vault_list")
    {
        return Err(INVALID.into());
    }
    let text = |key: &str, max: usize| -> Result<String, String> {
        fields
            .get(key)
            .and_then(Value::as_str)
            .filter(|v| !v.trim().is_empty() && v.len() <= max && !v.chars().any(char::is_control))
            .map(str::to_owned)
            .ok_or_else(|| INVALID.into())
    };
    let request = BrowseRequest {
        profile: text("profile_id", 128)?,
        generation: fields
            .get("expected_auth_generation")
            .and_then(Value::as_u64)
            .filter(|v| *v != 0)
            .ok_or(INVALID)?,
        space: text("space_id", 512)?,
        root: text("root_path", 4096)?,
        resource: text("root_resource_id", 512)?,
        path: text("path", 4096)?,
    };
    if !valid_runtime_profile(&request.profile)
        || validate_remote_path(&request.root).is_err()
        || validate_remote_path(&request.path).is_err()
        || request.root.contains('\\')
        || request.path.contains('\\')
        || serde_json::to_vec(value).map_err(|_| INVALID)?.len()
            > raiun_control::MAX_CONTROL_MESSAGE_BYTES
    {
        return Err(INVALID.into());
    }
    Ok(request)
}
fn state_matches(
    state: &AccountState,
    generation: u64,
    session: &auth::Session,
    configuration: &RootConfiguration,
) -> bool {
    state.active_generation == generation
        && state.online_authenticated
        && !state.logout_pending
        && !state.needs_refresh
        && !state.refreshing
        && !state.authenticating
        && !state.session_cleanup_uncertain
        && !state.retiring
        && state.root_configuration.as_ref() == Some(configuration)
        && session.expires_at > unix_time_now().saturating_add(30)
        && state.session.as_ref().is_some_and(|current| {
            current.server == session.server
                && current.client_id == session.client_id
                && current.expected_issuer == session.expected_issuer
                && current.access_token == session.access_token
                && current.expires_at == session.expires_at
        })
}
fn project(entries: &[RemoteEntry]) -> Result<Value, String> {
    struct Budget(usize);
    impl std::io::Write for Budget {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|n| *n <= RESPONSE_LIMIT)
                .ok_or_else(|| std::io::Error::other("Listing exceeds response limit"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Budget(0), entries).map_err(|_| REFUSED)?;
    serde_json::to_value(entries).map_err(|_| REFUSED.into())
}
impl WindowsAgent {
    pub(super) fn browse_windows_vault(&self, value: &Value) -> Result<Value, String> {
        let request = decode(value)?;
        if request.profile != self.profile_scope {
            return Err(REFUSED.into());
        }
        // Serialize with explicit Lock/unlock/Forget, never holding state or
        // session locks during network I/O. Account transitions still invalidate
        // the independent generation/token and are checked again at publication.
        let _operation = self
            .vault_credential_operation
            .lock()
            .map_err(|_| REFUSED)?;
        let (session, configuration) = {
            let state = self.state.lock().map_err(|_| REFUSED)?;
            let session = state.session.clone().ok_or(REFUSED)?;
            let configuration = state.root_configuration.clone().ok_or(REFUSED)?;
            if !state_matches(&state, request.generation, &session, &configuration)
                || self.generation.load(Ordering::Acquire) != request.generation
            {
                return Err(REFUSED.into());
            }
            (session, configuration)
        };
        let owner = configuration
            .registration_ownership
            .as_ref()
            .ok_or(REFUSED)?;
        if !configuration.valid
            || configuration.profile_scope != self.profile_scope
            || configuration.server != session.server
            || configuration.client_id != session.client_id
            || owner.state != "registered"
        {
            return Err(REFUSED.into());
        }
        let identity = raiun_cloudfiles_windows::ConfiguredRootIdentity {
            volume_serial: configuration.volume_serial,
            file_index: configuration.file_index,
        };
        let _root = pin_registered_configured_root(Path::new(&configuration.path), identity)
            .map_err(|_| REFUSED)?;
        let active = ActiveProviderBinding {
            generation: request.generation,
            path: PathBuf::from(&configuration.path),
            identity,
            personal_space_id: owner.personal_drive_id.clone(),
            personal_root_resource_id: owner.personal_root_resource_id.clone().ok_or(REFUSED)?,
        };
        let verified = self
            .provider
            .verified_vault_backend(active.clone())
            .map_err(|_| REFUSED)?;
        let (client, trusted) = verified
            .backend
            .vault_read_context(identity)
            .map_err(|_| REFUSED)?;
        if trusted.profile_id() != self.profile_scope
            || trusted.account_id() != owner.account_id
            || client.server_origin().as_deref() != Some(trusted.server_origin())
        {
            return Err(REFUSED.into());
        }
        let scope = VaultSessionScope::new(
            &self.profile_scope,
            trusted.server_origin(),
            &request.space,
            &request.resource,
        )
        .map_err(|_| REFUSED)?;
        let metadata_client = client.clone();
        let (binding, entries) = metadata_client
            .with_vault_metadata_deadline(|| {
                let binding =
                    raiun_cloudfiles_windows::vault_read::WindowsVaultReadBinding::new_online(
                        trusted,
                        client,
                        self.vault_sessions.clone(),
                        scope,
                        request.root,
                    )?;
                let entries = binding.list(&request.path)?;
                Ok((binding, entries))
            })
            .map_err(|_| REFUSED)?;
        // Check the same live provider and physical root after remote work.
        let current = self
            .provider
            .verified_vault_backend(active)
            .map_err(|_| REFUSED)?;
        if !Arc::ptr_eq(&current.backend, &verified.backend) || verified.backend.is_revoked() {
            return Err(REFUSED.into());
        }
        let _final_root = pin_registered_configured_root(Path::new(&configuration.path), identity)
            .map_err(|_| REFUSED)?;
        // Acquire account state before route/token/session publication fences;
        // the bounded local projection does no network or lock re-entry.
        let state = self.state.lock().map_err(|_| REFUSED)?;
        if !state_matches(&state, request.generation, &session, &configuration)
            || self.generation.load(Ordering::Acquire) != request.generation
        {
            return Err(REFUSED.into());
        }
        binding
            .with_publication(|| {
                if verified.backend.is_revoked()
                    || self.generation.load(Ordering::Acquire) != request.generation
                {
                    return Err(raiun_core::backend::CloudError::new(
                        raiun_core::backend::ErrorKind::Forbidden,
                        REFUSED,
                    ));
                }
                project(&entries).map_err(|_| {
                    raiun_core::backend::CloudError::new(
                        raiun_core::backend::ErrorKind::Forbidden,
                        REFUSED,
                    )
                })
            })
            .map_err(|_| REFUSED.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Value {
        json!({"action":"vault_list","profile_id":"default","expected_auth_generation":1,"space_id":"space","root_path":"/Vault","root_resource_id":"root","path":"/"})
    }
    #[test]
    fn browse_decoder_is_exact_and_secret_free() {
        assert!(decode(&request()).is_ok());
        for key in ["password", "offline", "unknown"] {
            let mut value = request();
            value[key] = json!(false);
            assert!(decode(&value).is_err());
        }
        for (key, value) in [
            ("profile_id", json!("../other")),
            ("expected_auth_generation", json!(0)),
            ("expected_auth_generation", json!(-1)),
            ("root_path", json!("/../Vault")),
            ("path", json!("/a/../b")),
            ("path", json!("/a\\b")),
            ("space_id", json!("a\n")),
            ("root_resource_id", json!("a".repeat(513))),
        ] {
            let mut input = request();
            input[key] = value;
            assert!(decode(&input).is_err());
        }
        for key in ["profile_id", "expected_auth_generation", "root_resource_id"] {
            let mut value = request();
            value.as_object_mut().unwrap().remove(key);
            assert!(decode(&value).is_err());
        }
    }
    #[test]
    fn browse_projection_has_no_partial_or_over_budget_result() {
        assert_eq!(project(&[]).unwrap(), json!([]));
        let entry = RemoteEntry {
            id: "item".into(),
            path: format!("/{}", "x".repeat(RESPONSE_LIMIT)),
            directory: false,
            size: 1,
            etag: "\"v1\"".into(),
            writable: false,
            modified_unix: 0,
            encrypted: true,
        };
        assert!(project(&[entry]).is_err());
    }
    #[test]
    fn browse_runtime_refuses_wrong_profile_and_signed_out_generation_before_io() {
        let (runtime, _) = super::super::tests::synthetic_profile_runtime(
            "default",
            None,
            Arc::new(raiun_vault::session::VaultSessionCoordinator::new()),
        );
        let mut input = request();
        input["profile_id"] = json!("profile-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(runtime.browse_windows_vault(&input).unwrap_err(), REFUSED);
        assert_eq!(
            runtime.browse_windows_vault(&request()).unwrap_err(),
            REFUSED
        );
        input = request();
        input["expected_auth_generation"] = json!(u64::MAX);
        assert_eq!(runtime.browse_windows_vault(&input).unwrap_err(), REFUSED);
        runtime.stop_and_join().unwrap();
    }
    #[test]
    fn browse_locked_scope_cannot_construct_read_binding() {
        let client = Arc::new(
            OpenCloudClient::new("https://synthetic.invalid", "synthetic-token".into()).unwrap(),
        );
        let trusted = raiun_cloudfiles_windows::ProviderScope::new(
            &client,
            "default".into(),
            "subject".into(),
            "https://synthetic.invalid".into(),
        )
        .unwrap();
        let sessions = Arc::new(raiun_vault::session::VaultSessionCoordinator::new());
        let scope = VaultSessionScope::new("default", "https://synthetic.invalid", "space", "root")
            .unwrap();
        // is_unlocked/epoch checks reject before any metadata network request.
        assert!(
            raiun_cloudfiles_windows::vault_read::WindowsVaultReadBinding::new_online(
                trusted,
                client,
                sessions,
                scope,
                "/Vault".into()
            )
            .is_err()
        );
    }
}

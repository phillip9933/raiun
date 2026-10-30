//! Immutable nonsecret deployment configuration. Never read by Desktop mode.
use crate::auth;
use raiun_headless::{AuthMethod, HeadlessConfig};
use std::sync::OnceLock;

/// Decoded requests can outlive raw input buffers on error paths.
pub(crate) struct SecretRequest(pub serde_json::Value);
impl Drop for SecretRequest {
    fn drop(&mut self) {
        for key in ["app_token", "password"] {
            if let Some(secret) = self.0.get_mut(key) {
                wipe_value(secret);
            }
        }
    }
}

fn wipe_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => zeroize::Zeroize::zeroize(text),
        serde_json::Value::Array(values) => values.iter_mut().for_each(wipe_value),
        serde_json::Value::Object(values) => values.values_mut().for_each(wipe_value),
        _ => {}
    }
}

#[cfg(unix)]
pub(crate) fn take_secret(
    request: &mut serde_json::Value,
    key: &str,
) -> Result<Option<zeroize::Zeroizing<String>>, String> {
    match request
        .as_object_mut()
        .and_then(|object| object.remove(key))
    {
        Some(serde_json::Value::String(secret)) => Ok(Some(zeroize::Zeroizing::new(secret))),
        Some(mut invalid) => {
            wipe_value(&mut invalid);
            Err("Secret input must be text".into())
        }
        None => Ok(None),
    }
}

pub(crate) fn config() -> Result<Option<&'static HeadlessConfig>, String> {
    static CONFIG: OnceLock<Result<Option<HeadlessConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| raiun_headless::config_from_env().map_err(|e| e.to_string()))
        .as_ref()
        .map(Option::as_ref)
        .map_err(Clone::clone)
}

fn normalized_server(raw: &str) -> Option<String> {
    let raw = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let mut url = url::Url::parse(&raw).ok()?;
    url.set_path(url.path().trim_end_matches('/').to_owned().as_str());
    Some(url.to_string().trim_end_matches('/').to_owned())
}

pub(crate) fn session_matches(config: &HeadlessConfig, session: &auth::Session) -> bool {
    normalized_server(&config.server) == normalized_server(&session.server)
        && match config.auth {
            AuthMethod::AppToken => {
                session.app_token_username.as_deref() == config.username.as_deref()
            }
            AuthMethod::Browser => {
                session.app_token_username.is_none()
                    && config
                        .client_id
                        .as_ref()
                        .is_none_or(|id| id == &session.client_id)
            }
        }
}

pub(crate) fn validate_login(
    profile: &str,
    server: &str,
    app_username: Option<&str>,
) -> Result<(), String> {
    let Some(config) = config()? else {
        return Ok(());
    };
    if config.profile != profile
        || normalized_server(&config.server) != normalized_server(server)
        || match config.auth {
            AuthMethod::Browser => app_username.is_some(),
            AuthMethod::AppToken => app_username != config.username.as_deref(),
        }
    {
        return Err("Sign-in does not match this headless deployment configuration; edit the config and restart first".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture_config() -> HeadlessConfig {
        HeadlessConfig {
            schema_version: 1,
            server: "https://fixture.example.test".into(),
            auth: AuthMethod::AppToken,
            username: Some("synthetic-user".into()),
            client_id: None,
            mount_path: std::env::temp_dir().join("raiun-synthetic-drive"),
            auto_mount: false,
            remember_login: false,
            reconnect_interval_seconds: 31,
            profile: "default".into(),
            windows_recovery: None,
        }
    }

    #[test]
    fn configured_identity_binding_is_independent_of_credential_persistence() {
        let mut config = fixture_config();
        let mut session = auth::Session::for_app_token(
            &config.server,
            "synthetic-user",
            "synthetic-token".into(),
            raiun_opencloud::ProxyConfig::Direct,
        )
        .unwrap();
        assert!(session_matches(&config, &session));
        config.username = Some("different-user".into());
        assert!(!session_matches(&config, &session));
        config.auth = AuthMethod::Browser;
        assert!(!session_matches(&config, &session));
        session.app_token_username = None;
        session.client_id = "configured-client".into();
        config.client_id = Some("configured-client".into());
        assert!(session_matches(&config, &session));
        session.client_id = "other-client".into();
        assert!(!session_matches(&config, &session));
    }

    #[cfg(unix)]
    #[test]
    fn malformed_sibling_secret_cannot_escape_the_request_wiping_owner() {
        let mut owned =
            SecretRequest(serde_json::json!({"password":false,"app_token":"synthetic-token"}));
        assert!(take_secret(&mut owned.0, "password").is_err());
        // This is the same owner retained across ProfileManager's early error.
        wipe_value(owned.0.get_mut("app_token").unwrap());
        assert_eq!(owned.0["app_token"], "");
        let mut malformed = serde_json::json!(["synthetic", {"nested":"synthetic"}]);
        wipe_value(&mut malformed);
        assert_eq!(malformed, serde_json::json!(["", {"nested":""}]));
    }

    #[cfg(unix)]
    #[test]
    fn configured_reconnect_interval_above_thirty_seconds_reaches_the_scheduler() {
        use std::sync::{Arc, atomic::Ordering};
        use std::time::{Duration, Instant};
        let temp = tempfile::tempdir().unwrap();
        let mut runtime = crate::new_runtime_with_mode(
            temp.path().into(),
            None,
            Arc::new(raiun_vault::session::VaultSessionCoordinator::new()),
            crate::runtime_mode::RuntimeMode::MountOnly,
        )
        .unwrap();
        let mut config = fixture_config();
        config.mount_path = temp.path().join("drive");
        config.auto_mount = true;
        Arc::get_mut(&mut runtime).unwrap().headless_config = Some(config);
        runtime.settings.lock().unwrap().mount_enabled = true;
        runtime.wake.store(false, Ordering::Release);
        runtime.restoring.store(false, Ordering::Release);
        let worker_runtime = runtime.clone();
        let worker = std::thread::spawn(move || crate::scheduler_loop(worker_runtime));
        let deadline = Instant::now() + Duration::from_secs(36);
        while runtime.error.lock().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        let observed = runtime.error.lock().unwrap().clone();
        runtime.shutdown.store(true, Ordering::Release);
        worker.join().unwrap();
        // No session exists, so this tests scheduling without reaching FUSE.
        assert_eq!(observed.as_deref(), Some("Sign in first"));
    }
}

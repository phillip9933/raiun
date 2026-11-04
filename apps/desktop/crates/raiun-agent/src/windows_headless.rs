//! The admitted process context is immutable. Credential and worker policy must
//! follow it even when reached outside the public request allowlist.
use super::*;
use crate::runtime_mode::RuntimeMode;

pub(super) fn runtime_mode() -> Result<RuntimeMode, String> {
    raiun_control_windows::headless_context()
        .map(|context| {
            if context.is_some() {
                RuntimeMode::MountOnly
            } else {
                RuntimeMode::Desktop
            }
        })
        .map_err(|_| "The headless Windows state context could not be admitted".into())
}

pub(super) fn mount_only() -> bool {
    // Fail closed if admission failed; entry points surface the actual error.
    runtime_mode().unwrap_or(RuntimeMode::MountOnly) == RuntimeMode::MountOnly
}

pub(super) fn configured_remember_login() -> Result<bool, String> {
    if !mount_only() {
        return Ok(false);
    }
    Ok(crate::headless_runtime::config()?.is_some_and(|config| config.remember_login))
}

pub(super) fn remember_login(profile: &str) -> Result<bool, String> {
    if !mount_only() {
        return Ok(true);
    }
    Ok(crate::headless_runtime::config()?
        .is_some_and(|config| config.profile == profile && config.remember_login))
}

pub(super) fn session_allowed(profile: &str, session: &auth::Session) -> Result<bool, String> {
    if !mount_only() {
        return Ok(true);
    }
    Ok(crate::headless_runtime::config()?.is_none_or(|config| {
        config.profile == profile && crate::headless_runtime::session_matches(config, session)
    }))
}

pub(super) fn root_allowed(profile: &str, root: &RootConfiguration) -> Result<bool, String> {
    if !mount_only() {
        return Ok(true);
    }
    Ok(crate::headless_runtime::config()?.is_none_or(|config| {
        config.profile == profile && root.path == config.mount_path.to_string_lossy()
    }))
}

pub(super) fn retry_seconds() -> u64 {
    if !mount_only() {
        return 30;
    }
    crate::headless_runtime::config()
        .ok()
        .flatten()
        .map_or(30, |config| config.reconnect_interval_seconds)
}

/// Prepared OAuth flow or terminal app credential; both share the exact same
/// cancellation, pending-store and active-identity publication transaction.
pub(super) enum PreparedWindowsAuth {
    Browser(auth::AuthFlow),
    AppToken(auth::Session),
}
impl PreparedWindowsAuth {
    pub(super) fn public_info(&self) -> Value {
        match self {
            Self::Browser(flow) => flow.public_info(),
            Self::AppToken(_) => json!({"started":true,"auth_method":"app_token"}),
        }
    }
    pub(super) fn configured_identity(&self) -> (&str, &str) {
        match self {
            Self::Browser(flow) => flow.configured_identity(),
            Self::AppToken(session) => (&session.server, &session.client_id),
        }
    }
    pub(super) fn wait_with_cancel(
        self,
        cancelled: impl Fn() -> bool,
    ) -> Result<auth::Session, String> {
        match self {
            Self::Browser(flow) => flow.wait_with_cancel(cancelled),
            Self::AppToken(session) => {
                if cancelled() {
                    Err("Sign-in was cancelled".into())
                } else {
                    Ok(session)
                }
            }
        }
    }
}

pub(super) fn validate_serve(requested: bool, mode: RuntimeMode) -> Result<(), String> {
    if requested != (mode == RuntimeMode::MountOnly) {
        return Err("Windows --mount-only requires the explicit headless state context; start this agent through raiun drive serve".into());
    }
    Ok(())
}

pub(super) fn annotate_status(status: &mut Value, mode: RuntimeMode) {
    status["runtime_mode"] = json!(mode.name());
    if mode == RuntimeMode::MountOnly {
        status["credential_storage"] = json!(if configured_remember_login().unwrap_or(false) {
            "windows_dpapi"
        } else {
            "memory_only"
        });
        status["folder_sync_enabled"] = json!(false);
        status["autostart"] = Value::Null;
        for key in [
            "folder_sync_supported",
            "folder_settings_supported",
            "bandwidth_limits_supported",
            "network_proxy_supported",
            "media_jobs_supported",
            "vaults_supported",
            "pause_supported",
            "account_removal_supported",
        ] {
            status[key] = json!(false);
        }
        if status.get("provider_supported").is_none() {
            status["provider_supported"] = json!(WINDOWS_PROVIDER_ACTIVATION_ENABLED);
        }
    }
}

impl WindowsAgent {
    /// Let the broker perform configured mounts so root pinning, exclusion
    /// publication and cross-account reservations remain one transaction.
    pub(super) fn headless_configured_mount_request(&self) -> Result<Option<Value>, String> {
        if !mount_only() {
            return Ok(None);
        }
        let Some(config) = crate::headless_runtime::config()? else {
            return Ok(None);
        };
        if config.profile != self.profile_scope
            || !config.auto_mount
            || self.provider.is_connected()
        {
            return Ok(None);
        }
        let preference = self
            .provider
            .mount_preference
            .lock()
            .map_err(|_| "Mount preference is unavailable")?;
        if !*preference {
            return Ok(None);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?;
        if !state.online_authenticated
            || state.authenticating
            || state.refreshing
            || state.logout_pending
            || state.retiring
            || state.session_cleanup_uncertain
            || state.headless_mount_retry_at > unix_time_now()
            || state
                .session
                .as_ref()
                .is_none_or(|session| !crate::headless_runtime::session_matches(config, session))
        {
            return Ok(None);
        }
        state.headless_mount_retry_at =
            unix_time_now().saturating_add(config.reconnect_interval_seconds);
        let mut request = json!({"action":"mount", "required_mode":"mount_only", "profile_id":config.profile,"automatic_mount":true,"expected_generation":state.active_generation});
        if state
            .root_configuration
            .as_ref()
            .is_none_or(|root| !root_allowed(&self.profile_scope, root).unwrap_or(false))
        {
            request["cloud_root"] = json!(config.mount_path);
        }
        Ok(Some(request))
    }

    pub(super) fn headless_mount(&self, request: &Value) -> Result<Value, String> {
        // Configuration performs all normal provider ownership checks; the
        // broker also publishes the cross-account root reservation first.
        let automatic = request
            .get("automatic_mount")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if automatic {
            if !*self
                .provider
                .mount_preference
                .lock()
                .map_err(|_| "Mount preference is unavailable")?
            {
                return Err("Automatic mounting was cancelled by unmount".into());
            }
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if request.get("expected_generation").and_then(Value::as_u64)
                != Some(state.active_generation)
            {
                return Err("The account changed before automatic mounting".into());
            }
        }
        if request.get("cloud_root").is_some() {
            self.configure_root(request)?;
        }
        {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if !state.online_authenticated
                || state.authenticating
                || state.refreshing
                || state.logout_pending
                || state.session_cleanup_uncertain
                || state.session.is_none()
                || state.root_configuration.is_none()
            {
                return Err("Sign in and choose a Windows drive folder before mounting".into());
            }
        }
        // A queued automatic request never re-enables a preference revoked
        // by unmount. Every actual connect separately holds this same lock.
        if !automatic {
            *self
                .provider
                .mount_preference
                .lock()
                .map_err(|_| "Mount preference is unavailable")? = true;
        }
        Self::maybe_connect_provider_with_exclusions(
            &self.session_store,
            &self.state,
            &self.provider,
            self.source_admissions.as_ref(),
        )?;
        Ok(
            json!({"mounted":self.provider.is_connected(),"provider_supported":self.provider.activation_enabled()}),
        )
    }

    pub(super) fn headless_unmount(&self) -> Result<Value, String> {
        // The preference lock also spans every automatic connection attempt.
        // Once this returns, neither refresh nor a late auth completion can
        // reconnect. The protected root registration and local bytes remain.
        let mut preference = self
            .provider
            .mount_preference
            .lock()
            .map_err(|_| "Mount preference is unavailable")?;
        *preference = false;
        self.provider.disconnect()?;
        Ok(json!({"mounted":false,"registration_preserved":true}))
    }

    pub(super) fn headless_spaces(&self) -> Result<Value, String> {
        let (session, generation) = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if !state.online_authenticated
                || state.authenticating
                || state.refreshing
                || state.logout_pending
                || state.needs_refresh
                || state.retiring
            {
                return Err("Connect this account before listing Spaces".into());
            }
            (
                state
                    .session
                    .clone()
                    .ok_or("Sign in before listing Spaces")?,
                state.active_generation,
            )
        };
        let client = Arc::new(
            session
                .opencloud_client()
                .map_err(|_| "Could not prepare the connected account")?,
        );
        let (_, _, _, spaces, _) = verified_account_roots(&client, &session.server)?;
        let state = self
            .state
            .lock()
            .map_err(|_| "Account state is unavailable")?;
        if state.active_generation != generation
            || self.generation.load(Ordering::Acquire) != generation
            || !state.online_authenticated
            || state.authenticating
            || state.refreshing
            || state.logout_pending
            || state.session.as_ref().is_none_or(|current| {
                current.access_token != session.access_token
                    || current.server != session.server
                    || current.client_id != session.client_id
            })
        {
            return Err("The account changed while listing Spaces".into());
        }
        serde_json::to_value(spaces).map_err(|_| "Could not encode Spaces".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serve_requires_matching_explicit_context_and_flag() {
        assert!(validate_serve(false, RuntimeMode::Desktop).is_ok());
        assert!(validate_serve(true, RuntimeMode::MountOnly).is_ok());
        assert!(validate_serve(true, RuntimeMode::Desktop).is_err());
        assert!(validate_serve(false, RuntimeMode::MountOnly).is_err());
    }

    #[test]
    fn every_headless_status_shape_reports_memory_credentials_and_no_workers() {
        for mut status in [
            json!({"accounts_empty":true}),
            json!({"connected":true,"mounted":true,"provider_supported":false}),
        ] {
            annotate_status(&mut status, RuntimeMode::MountOnly);
            assert_eq!(status["runtime_mode"], "mount_only");
            assert_eq!(status["credential_storage"], "memory_only");
            assert_eq!(status["folder_sync_enabled"], false);
            assert_eq!(status["folder_sync_supported"], false);
            assert_eq!(status["media_jobs_supported"], false);
            assert_eq!(status["vaults_supported"], false);
            assert_eq!(status["bandwidth_limits_supported"], false);
            assert_eq!(status["network_proxy_supported"], false);
            assert!(status["autostart"].is_null());
        }
        let mut desktop = json!({"folder_sync_supported":true});
        annotate_status(&mut desktop, RuntimeMode::Desktop);
        assert_eq!(desktop["folder_sync_supported"], true);
        assert!(desktop.get("credential_storage").is_none());
    }
}

#[cfg(all(test, debug_assertions))]
mod native_tests {
    use super::*;

    // A fresh child process is necessary: the context is immutable and ordinary
    // Desktop tests in this binary must never inherit a test's changed policy.
    #[test]
    fn isolated_headless_credentials_and_unmount_policy() {
        const CHILD: &str = "RAIUN_HEADLESS_RUNTIME_POLICY_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let mut nonce = [0_u8; 16];
            getrandom::fill(&mut nonce).unwrap();
            let suffix = nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let directory =
                std::env::temp_dir().join(format!("raiun-headless-runtime-policy-{suffix}"));
            std::fs::create_dir(&directory).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "agent_windows::windows_headless::native_tests::isolated_headless_credentials_and_unmount_policy", "--nocapture"])
                .env(CHILD, "1")
                .env("RAIUN_HEADLESS_CONTEXT", "1")
                .env_remove("RAIUN_HEADLESS_CONFIG")
                .env("RAIUN_STATE_DIR", directory.join("state"))
                .stdin(std::process::Stdio::null())
                .output().unwrap();
            assert!(
                output.status.success(),
                "isolated child failed: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            std::fs::remove_dir_all(directory).unwrap();
            return;
        }
        assert!(mount_only());
        let raw = DpapiSessionStore::current_user()
            .unwrap()
            .for_profile("default")
            .unwrap();
        let session = auth::Session {
            app_token_username: None,
            server: "https://synthetic.example.test".into(),
            client_id: "synthetic-client".into(),
            access_token: "synthetic-access".into(),
            refresh_token: Some("synthetic-refresh".into()),
            expires_at: unix_time_now() + 3600,
            token_endpoint: "https://synthetic.example.test/token".into(),
            expected_issuer: None,
            last_refresh_at: None,
            proxy: Default::default(),
        };
        // Seed an exact synthetic old record through the raw metadata fixture.
        // The runtime adapter must neither restore it nor overwrite/delete it.
        let bytes = serde_json::to_vec(&session).unwrap();
        raw.save(Some("default"), &session.server, &session.client_id, &bytes)
            .unwrap();
        raw.set_active_identity("default", &session.server, &session.client_id)
            .unwrap();
        let adapter = DpapiStore::current_user().unwrap();
        assert!(adapter.load_vault_credentials("default").unwrap().is_none());
        assert!(
            adapter
                .compare_exchange_vault_credentials("default", None, b"synthetic-vault")
                .is_err()
        );
        let context = raiun_control_windows::headless_context().unwrap().unwrap();
        assert!(overlaps_private_state(context.state_root(), None).unwrap());
        assert!(overlaps_private_state(context.state_root().parent().unwrap(), None).unwrap());
        adapter.save_pending("default", &session).unwrap();
        adapter.publish_active("default", &session).unwrap();
        assert!(adapter.load_active("default").unwrap().is_none());
        assert!(adapter.revoke_active().unwrap().is_none());
        adapter
            .remove("default", &session.server, &session.client_id)
            .unwrap();
        assert_eq!(
            raw.load(Some("default"), &session.server, &session.client_id)
                .unwrap()
                .map(|body| body.to_vec()),
            Some(bytes.clone())
        );
        assert_eq!(
            raw.active_identity().unwrap(),
            Some((
                "default".into(),
                session.server.clone(),
                session.client_id.clone()
            ))
        );
        assert!(adapter.save_pending("foreign", &session).is_err());
        assert!(adapter.publish_active("foreign", &session).is_err());
        assert!(adapter.load_active("foreign").is_err());
        assert!(
            adapter
                .remove("foreign", &session.server, &session.client_id)
                .is_err()
        );
        adapter
            .save_root_config(
                "default",
                &session.server,
                &session.client_id,
                b"synthetic-root-metadata",
            )
            .unwrap();
        assert_eq!(
            adapter
                .load_root_config("default", &session.server, &session.client_id)
                .unwrap()
                .as_deref(),
            Some(b"synthetic-root-metadata".as_slice())
        );

        let agent = Arc::new(WindowsAgent::new(adapter));
        assert!(
            agent.state.lock().unwrap().session.is_none(),
            "headless startup must not restore seeded credentials"
        );
        assert!(!*agent.provider.mount_preference.lock().unwrap());
        for request in [
            json!({"action":"pair_add"}),
            json!({"action":"media_job_run"}),
            json!({"action":"vault_unlock","password":"synthetic"}),
            json!({"action":"autostart_set"}),
            json!({"action":"status","required_mode":"desktop"}),
        ] {
            assert!(agent.handle_request(&request).is_err());
        }
        assert!(agent.folder_request(&json!({"action":"spaces"})).is_err());
        assert_eq!(agent.provider.folder_generation.load(Ordering::Acquire), 0);
        let root = RootConfiguration {
            profile_scope: "default".into(),
            server: session.server.clone(),
            client_id: session.client_id.clone(),
            issuer: None,
            path: r"C:\synthetic-headless-never-mounted".into(),
            volume_serial: 1,
            file_index: 2,
            registration_ownership: None,
            valid: true,
        };
        {
            let mut state = agent.state.lock().unwrap();
            state.session = Some(session);
            state.root_configuration = Some(root.clone());
            state.online_authenticated = true;
        }
        *agent.provider.mount_preference.lock().unwrap() = true;
        agent.headless_unmount().unwrap();
        assert_eq!(
            agent.state.lock().unwrap().root_configuration.as_ref(),
            Some(&root)
        );
        // Enabling the test's provider seam makes a connection attempt reject
        // the deliberately unowned fake root. The false preference must stop
        // before that path during every automatic lifecycle hook.
        agent
            .provider
            .lifecycle_test_activation
            .store(true, Ordering::Release);
        for _ in 0..2 {
            WindowsAgent::maybe_connect_provider_with_exclusions(
                &agent.session_store,
                &agent.state,
                &agent.provider,
                None,
            )
            .unwrap();
        }
        assert!(agent.headless_mount(&json!({"action":"mount"})).is_err());
        assert!(!agent.provider.is_connected());
        agent.headless_unmount().unwrap();
        agent.stop_and_join().unwrap();
        let restarted = WindowsAgent::new(DpapiStore::current_user().unwrap());
        assert!(restarted.state.lock().unwrap().session.is_none());
        assert!(!*restarted.provider.mount_preference.lock().unwrap());
        // The old no-config save/load policy stays ephemeral, but an explicit
        // logout must revoke a previously saved scoped identity anyway.
        let result = restarted.logout().unwrap();
        assert_eq!(result["logged_out"], true);
        assert_eq!(result["session_cleanup_uncertain"], false);
        assert!(raw.active_identity().unwrap().is_none());
        assert!(
            raw.load(Some("default"), &root.server, &root.client_id)
                .unwrap()
                .is_none()
        );
        restarted.stop_and_join().unwrap();
    }
}

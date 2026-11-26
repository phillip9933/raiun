//! Process policy for the first headless, mount-only client.
use serde_json::Value;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RuntimeMode {
    #[default]
    Desktop,
    MountOnly,
}

impl RuntimeMode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::MountOnly => "mount_only",
        }
    }

    pub fn validate_request(self, request: &Value) -> Result<(), String> {
        if let Some(required) = request.get("required_mode") {
            if required.as_str() != Some(self.name()) {
                return Err(
                    "Agent mode does not match this client; use its separate state directory"
                        .into(),
                );
            }
        }
        if self == Self::MountOnly {
            let action = request
                .get("action")
                .and_then(Value::as_str)
                .ok_or("Missing action")?;
            if request.get("password").is_some()
                || !mount_only_action_allowed(action, cfg!(windows))
            {
                return Err("This headless agent supports drive mounting only; folder sync and other desktop operations are unavailable".into());
            }
        }
        Ok(())
    }
}

fn mount_only_action_allowed(action: &str, windows: bool) -> bool {
    matches!(
        action,
        "status"
            | "accounts"
            | "account_add"
            | "configure"
            | "auth_begin"
            | "auth_app_token"
            | "logout"
            | "spaces"
            | "mount"
            | "unmount"
            | "shutdown"
    ) || (windows
        && matches!(
            action,
            "windows_recovery_list" | "windows_recovery_retry" | "windows_recovery_check_cloud"
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[cfg(unix)]
    use std::sync::Arc;

    #[test]
    fn ordinary_saved_edit_policy_is_windows_only_and_never_opens_other_recovery_or_sync() {
        for action in ["windows_recovery_list", "windows_recovery_retry"] {
            assert!(mount_only_action_allowed(action, true));
            assert!(!mount_only_action_allowed(action, false));
            assert_eq!(
                RuntimeMode::MountOnly
                    .validate_request(&json!({"action":action}))
                    .is_ok(),
                cfg!(windows)
            );
            assert!(
                RuntimeMode::MountOnly
                    .validate_request(&json!({"action":action,"password":"synthetic"}))
                    .is_err()
            );
            assert!(
                RuntimeMode::Desktop
                    .validate_request(&json!({"action":action,"required_mode":"mount_only"}))
                    .is_err()
            );
        }
        for action in [
            "request",
            "sync_now",
            "pair_add",
            "space_sync_now",
            "windows_recovery_save_copy",
            "windows_vault_capture_recovery_list",
            "windows_vault_capture_save_copy",
            "vault_upload_capture",
            "set_autostart",
        ] {
            assert!(!mount_only_action_allowed(action, true));
            assert!(!mount_only_action_allowed(action, false));
        }
    }

    #[cfg(unix)]
    #[test]
    fn headless_credentials_never_persist_and_sync_settings_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let vaults = Arc::new(raiun_vault::session::VaultSessionCoordinator::new());
        let runtime = crate::new_runtime_with_mode(
            dir.path().into(),
            None,
            vaults.clone(),
            RuntimeMode::MountOnly,
        )
        .unwrap();
        let session = crate::auth::Session {
            server: "https://synthetic.example.test".into(),
            client_id: "synthetic".into(),
            access_token: "synthetic-access".into(),
            app_token_username: None,
            refresh_token: Some("synthetic-refresh".into()),
            expires_at: 1,
            token_endpoint: "https://synthetic.example.test/token".into(),
            expected_issuer: None,
            last_refresh_at: None,
            proxy: Default::default(),
        };
        runtime.session_store.save(&session).unwrap();
        assert!(
            runtime
                .session_store
                .load(&session.server, &session.client_id)
                .unwrap()
                .is_none()
        );
        runtime
            .session_store
            .remove(&session.server, &session.client_id)
            .unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

        let mut settings = runtime.settings.lock().unwrap().clone();
        settings.config.pairs.push(raiun_core::FolderPair {
            id: "synthetic".into(),
            local_path: dir.path().join("local"),
            space_id: "synthetic".into(),
            remote_path: "/".into(),
            mode: raiun_core::SyncMode::TwoWay,
            vault: None,
            excluded_paths: vec![],
            content_filter: Default::default(),
            exclusions: vec![],
        });
        settings.save(dir.path()).unwrap();
        assert!(
            crate::new_runtime_with_mode(dir.path().into(), None, vaults, RuntimeMode::MountOnly)
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn explicit_headless_logout_removes_old_credentials_without_a_config_or_server() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("private-state");
        raiun_headless::save_session(&state, "default", b"synthetic-saved-credential").unwrap();
        let runtime = crate::new_runtime_with_mode(
            state.clone(),
            None,
            Arc::new(raiun_vault::session::VaultSessionCoordinator::new()),
            RuntimeMode::MountOnly,
        )
        .unwrap();
        runtime.settings.lock().unwrap().config.cloud_root = dir.path().join("drive");
        assert!(runtime.settings.lock().unwrap().server.is_none());
        assert!(runtime.headless_config.is_none());
        runtime.logout().unwrap();
        assert!(
            raiun_headless::load_session(&state, "default")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn mount_only_refuses_sync_vault_and_autostart_operations() {
        for action in [
            "pair_add",
            "pair_update",
            "sync_now",
            "space_sync_now",
            "media_job_run",
            "vault_unlock",
            "set_autostart",
            "pause",
            "account_remove",
        ] {
            assert!(
                RuntimeMode::MountOnly
                    .validate_request(&json!({"action":action}))
                    .is_err()
            );
            assert!(
                RuntimeMode::Desktop
                    .validate_request(&json!({"action":action}))
                    .is_ok()
            );
        }
        assert!(
            RuntimeMode::MountOnly
                .validate_request(&json!({"action":"status", "password":"synthetic"}))
                .is_err()
        );
    }

    #[test]
    fn mount_only_accepts_drive_operations_and_enforces_client_mode() {
        for action in [
            "status",
            "accounts",
            "account_add",
            "configure",
            "auth_begin",
            "logout",
            "spaces",
            "mount",
            "unmount",
            "shutdown",
        ] {
            assert!(
                RuntimeMode::MountOnly
                    .validate_request(&json!({"action":action,"required_mode":"mount_only"}))
                    .is_ok()
            );
            assert!(
                RuntimeMode::Desktop
                    .validate_request(&json!({"action":action,"required_mode":"mount_only"}))
                    .is_err()
            );
        }
        assert!(
            RuntimeMode::MountOnly
                .validate_request(&json!({"action":"status","required_mode":false}))
                .is_err()
        );
    }
}

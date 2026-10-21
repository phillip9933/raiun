use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) const TRAY_SYNC_IDLE_LABEL: &str = "Force Sync Now";

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AgentStartAction {
    UseExistingEndpoint,
    WaitForOwnedProcess,
    SpawnAgent,
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn agent_start_action(
    endpoint_available: bool,
    owned_process_running: bool,
) -> AgentStartAction {
    if endpoint_available {
        AgentStartAction::UseExistingEndpoint
    } else if owned_process_running {
        AgentStartAction::WaitForOwnedProcess
    } else {
        AgentStartAction::SpawnAgent
    }
}

pub(crate) fn agent_action_waits_for_completion(action: &str) -> bool {
    matches!(
        action,
        "shutdown"
            | "space_pause"
            | "space_disconnect"
            | "vault_lock"
            | "vault_create"
            | "cache_saved_write_export"
            | "cache_conflict_export"
    )
}

pub(crate) fn agent_response_timeout(action: &str) -> Duration {
    if action == "auth_begin" {
        Duration::from_secs(65)
    } else {
        Duration::from_secs(10)
    }
}

pub(crate) fn has_background_argument(args: &[String]) -> bool {
    args.iter().any(|argument| argument == "--background")
}

pub(crate) fn sibling_agent_path(shell_executable: &Path) -> Result<PathBuf, String> {
    let parent = shell_executable
        .parent()
        .ok_or_else(|| "Raiun Desktop executable has no parent directory".to_string())?;
    #[cfg(windows)]
    let path = parent.join("raiun-agent.exe");
    #[cfg(not(windows))]
    let path = parent.join("raiun-agent");
    Ok(path)
}

pub(crate) fn should_prevent_exit(code: Option<i32>, tray_available: bool) -> bool {
    code.is_none() && tray_available
}

pub(crate) fn should_show_initial_window(background_launch: bool, tray_available: bool) -> bool {
    !background_launch || !tray_available
}

pub(crate) fn tray_status_label(
    agent_available: bool,
    has_error: bool,
    connected: bool,
    paused: bool,
) -> &'static str {
    if !agent_available {
        "Status · Agent unavailable"
    } else if has_error {
        "Status · Needs attention"
    } else if connected && paused {
        "Status · Sync paused"
    } else if connected {
        "Status · Connected"
    } else {
        "Status · Sign-in required"
    }
}

pub(crate) fn tray_pause_menu_label(paused: bool) -> &'static str {
    if paused { "Resume sync" } else { "Pause sync" }
}

#[cfg(test)]
mod tests {
    use super::{
        AgentStartAction, TRAY_SYNC_IDLE_LABEL, agent_action_waits_for_completion,
        agent_response_timeout, agent_start_action, has_background_argument, should_prevent_exit,
        should_show_initial_window, sibling_agent_path, tray_pause_menu_label, tray_status_label,
    };
    use std::path::Path;

    #[test]
    fn agent_resolution_uses_only_the_shell_sibling() {
        #[cfg(windows)]
        let (shell, expected) = (
            Path::new(r"C:\opt\raiun\raiun-desktop.exe"),
            Path::new(r"C:\opt\raiun\raiun-agent.exe"),
        );
        #[cfg(not(windows))]
        let (shell, expected) = (
            Path::new("/opt/raiun/raiun-desktop"),
            Path::new("/opt/raiun/raiun-agent"),
        );
        assert_eq!(sibling_agent_path(shell).expect("agent path"), expected);
    }

    #[test]
    fn agent_retry_never_spawns_when_endpoint_or_owned_process_is_live() {
        assert_eq!(
            agent_start_action(true, false),
            AgentStartAction::UseExistingEndpoint
        );
        assert_eq!(
            agent_start_action(true, true),
            AgentStartAction::UseExistingEndpoint
        );
        assert_eq!(
            agent_start_action(false, true),
            AgentStartAction::WaitForOwnedProcess
        );
        assert_eq!(
            agent_start_action(false, false),
            AgentStartAction::SpawnAgent
        );
    }

    #[test]
    fn only_user_close_requests_are_kept_alive_by_a_working_tray() {
        assert!(should_prevent_exit(None, true));
        assert!(!should_prevent_exit(Some(0), true));
        assert!(!should_prevent_exit(Some(1), true));
        assert!(!should_prevent_exit(None, false));
    }

    #[test]
    fn background_argument_is_recognized_without_affecting_normal_launch() {
        assert!(has_background_argument(&[
            "--background".to_string(),
            "--some-other-flag".to_string()
        ]));
        assert!(!has_background_argument(&["--some-other-flag".to_string()]));
        assert!(!has_background_argument(&[]));
    }

    #[test]
    fn initial_window_is_hidden_only_for_background_launch_with_tray() {
        assert!(should_show_initial_window(false, true));
        assert!(should_show_initial_window(false, false));
        assert!(!should_show_initial_window(true, true));
        assert!(should_show_initial_window(true, false));
    }

    #[test]
    fn long_lived_mutations_wait_for_completion_without_an_ipc_timeout() {
        assert!(agent_action_waits_for_completion("shutdown"));
        assert!(agent_action_waits_for_completion("space_pause"));
        assert!(agent_action_waits_for_completion("space_disconnect"));
        assert!(agent_action_waits_for_completion("vault_lock"));
        assert!(agent_action_waits_for_completion("vault_create"));
        assert!(agent_action_waits_for_completion(
            "cache_saved_write_export"
        ));
        assert!(agent_action_waits_for_completion("cache_conflict_export"));
        assert!(!agent_action_waits_for_completion("vault_list"));
        assert!(!agent_action_waits_for_completion("status"));
        assert!(!agent_action_waits_for_completion("auth_begin"));
    }

    #[test]
    fn auth_begin_has_room_for_discovery_before_the_bounded_ipc_timeout() {
        assert_eq!(agent_response_timeout("auth_begin").as_secs(), 65);
        assert_eq!(agent_response_timeout("status").as_secs(), 10);
        assert_eq!(agent_response_timeout("resolve_conflict").as_secs(), 10);
    }

    #[test]
    fn tray_status_prioritizes_errors_and_handles_disconnection() {
        assert_eq!(
            tray_status_label(true, true, true, false),
            "Status · Needs attention"
        );
        assert_eq!(
            tray_status_label(true, false, true, true),
            "Status · Sync paused"
        );
        assert_eq!(
            tray_status_label(true, false, true, false),
            "Status · Connected"
        );
        assert_eq!(
            tray_status_label(true, false, false, false),
            "Status · Sign-in required"
        );
        assert_eq!(
            tray_status_label(false, false, false, false),
            "Status · Agent unavailable"
        );
    }

    #[test]
    fn pause_menu_label_reflects_the_reported_agent_state() {
        assert_eq!(tray_pause_menu_label(false), "Pause sync");
        assert_eq!(tray_pause_menu_label(true), "Resume sync");
        assert_eq!(TRAY_SYNC_IDLE_LABEL, "Force Sync Now");
    }
}

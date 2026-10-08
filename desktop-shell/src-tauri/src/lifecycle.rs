use std::path::{Path, PathBuf};
use std::time::Duration;

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
    Ok(parent.join("raiun-agent"))
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

#[cfg(test)]
mod tests {
    use super::{
        agent_response_timeout, has_background_argument, should_prevent_exit,
        should_show_initial_window, sibling_agent_path, tray_status_label,
    };
    use std::path::Path;

    #[test]
    fn agent_resolution_uses_only_the_shell_sibling() {
        assert_eq!(
            sibling_agent_path(Path::new("/opt/raiun/raiun-desktop")).expect("agent path"),
            Path::new("/opt/raiun/raiun-agent")
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
}

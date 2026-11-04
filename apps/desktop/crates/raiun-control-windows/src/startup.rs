//! Explicit local, current-account startup registration. Constructing a spec
//! or rendering XML does not contact Task Scheduler or change startup state.
use std::{io, path::Path};

#[cfg(windows)]
#[path = "startup_native.rs"]
#[allow(unsafe_code)]
mod native;
#[cfg(windows)]
pub use native::TaskScheduler;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupKind {
    Boot,
    Logon,
}

/// Exact owned identity and action. The opaque instance ID is a name, never
/// sufficient authority to modify an existing task.
#[derive(Clone, Debug)]
pub struct OwnedTaskSpec {
    task_name: String,
    source: String,
    executable: String,
    arguments: String,
    working_directory: String,
}

impl OwnedTaskSpec {
    pub fn new(
        instance_id: &str,
        executable: &Path,
        arguments: &str,
        working_directory: &Path,
    ) -> io::Result<Self> {
        if instance_id.len() != 16
            || !instance_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || arguments.is_empty()
            || arguments.chars().any(char::is_control)
        {
            return Err(invalid("Invalid startup identity or arguments"));
        }
        Ok(Self {
            task_name: format!("Raiun Headless CLI {instance_id}"),
            source: format!("RaiunHeadlessCLI-v1:{instance_id}"),
            executable: local_path(executable)?,
            arguments: arguments.into(),
            working_directory: local_path(working_directory)?,
        })
    }

    pub fn task_name(&self) -> &str {
        &self.task_name
    }

    /// A reviewable plan using the actual current-account SID obtained by the
    /// adapter. Never put a password in the definition or action arguments.
    pub fn definition_xml(&self, kind: StartupKind, sid: &str) -> io::Result<String> {
        if !crate::is_sid_shape(sid) {
            return Err(invalid("Invalid startup account SID"));
        }
        let (trigger, logon) = match kind {
            StartupKind::Boot => (
                "<BootTrigger><Enabled>true</Enabled><Delay>PT30S</Delay></BootTrigger>".into(),
                "Password",
            ),
            StartupKind::Logon => (
                format!(
                    "<LogonTrigger><Enabled>true</Enabled><UserId>{sid}</UserId><Delay>PT10S</Delay></LogonTrigger>"
                ),
                "InteractiveToken",
            ),
        };
        Ok(format!(
            r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo><Description>Raiun isolated headless CLI; config and state preserved on disable.</Description><Source>{}</Source></RegistrationInfo>
<Triggers>{trigger}</Triggers>
<Principals><Principal id="RaiunUser"><UserId>{sid}</UserId><LogonType>{logon}</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><Enabled>true</Enabled><Hidden>false</Hidden><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure></Settings>
<Actions Context="RaiunUser"><Exec><Command>{}</Command><Arguments>{}</Arguments><WorkingDirectory>{}</WorkingDirectory></Exec></Actions>
</Task>
"#,
            xml(&self.source),
            xml(&self.executable),
            xml(&self.arguments),
            xml(&self.working_directory)
        ))
    }
}

/// Native numeric state avoids localized command output. LastTaskResult can
/// legitimately be 0x41301 while a foreground agent is still running.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskStatus {
    pub enabled: bool,
    pub state: i32,
    pub last_task_result: i32,
    pub active_instance_count: i32,
    pub kind: StartupKind,
    pub user_sid: String,
}

impl TaskStatus {
    pub fn is_active(&self) -> bool {
        self.active_instance_count > 0 || matches!(self.state, 2 | 4)
    }
}

#[cfg(any(windows, test))]
#[derive(Clone, Debug)]
struct TaskBinding {
    source: String,
    user_sid: String,
    run_level: i32,
    action_count: i32,
    action_type: i32,
    executable: String,
    arguments: String,
    working_directory: String,
    logon_type: i32,
    trigger_count: i32,
    trigger_type: i32,
    trigger_user_sid: String,
    trigger_enabled: bool,
    trigger_delay: String,
    allow_hard_terminate: bool,
    instances: i32,
    execution_limit: String,
    restart_interval: String,
    restart_count: i32,
    stop_on_battery: bool,
    disallow_on_battery: bool,
    start_when_available: bool,
    network_only: bool,
    hidden: bool,
    wake: bool,
    demand_start: bool,
    group_id: String,
    start_boundary: String,
    end_boundary: String,
    repetition_interval: String,
    repetition_duration: String,
}

#[cfg(any(windows, test))]
impl TaskBinding {
    fn admit(&self, spec: &OwnedTaskSpec, current_sid: &str) -> io::Result<StartupKind> {
        let kind = match (self.logon_type, self.trigger_type) {
            (1, 8) if self.trigger_delay == "PT30S" && self.trigger_user_sid.is_empty() => {
                StartupKind::Boot
            }
            (3, 9) if self.trigger_delay == "PT10S" && self.trigger_user_sid == current_sid => {
                StartupKind::Logon
            }
            _ => return Err(foreign()),
        };
        if !crate::is_sid_shape(current_sid)
            || self.user_sid != current_sid
            || self.source != spec.source
            || self.run_level != 0
            || self.action_count != 1
            || self.action_type != 0
            || self.executable != spec.executable
            || self.arguments != spec.arguments
            || self.working_directory != spec.working_directory
            || self.trigger_count != 1
            || !self.trigger_enabled
            || self.allow_hard_terminate
            || self.instances != 2
            || self.execution_limit != "PT0S"
            || self.restart_interval != "PT1M"
            || self.restart_count != 999
            || self.stop_on_battery
            || self.disallow_on_battery
            || !self.start_when_available
            || self.network_only
            || self.hidden
            || self.wake
            || !self.demand_start
            || !self.group_id.is_empty()
            || !self.start_boundary.is_empty()
            || !self.end_boundary.is_empty()
            || !self.repetition_interval.is_empty()
            || !self.repetition_duration.is_empty()
        {
            return Err(foreign());
        }
        Ok(kind)
    }
}

fn local_path(path: &Path) -> io::Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid("Startup paths must be valid Unicode"))?;
    let bytes = value.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || !matches!(bytes[2], b'\\' | b'/')
        || value.chars().any(char::is_control)
        || value[2..].contains(':')
        || value
            .split(['\\', '/'])
            .any(|part| matches!(part, "." | ".."))
    {
        return Err(invalid(
            "Startup paths must use local drive-absolute paths without aliases",
        ));
    }
    Ok(value.into())
}

fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(any(windows, test))]
fn foreign() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "An unrelated or differently configured startup task uses this name; it was preserved",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn spec() -> OwnedTaskSpec {
        OwnedTaskSpec::new(
            "0123456789abcdef",
            Path::new(r"C:\Raiun\raiun.exe"),
            r#"--config "C:\private\config.json" drive --state-dir "C:\private\state" serve"#,
            Path::new(r"C:\Raiun"),
        )
        .unwrap()
    }
    fn binding() -> TaskBinding {
        let s = spec();
        TaskBinding {
            source: s.source,
            user_sid: "S-1-5-21-1-2-3-1001".into(),
            run_level: 0,
            action_count: 1,
            action_type: 0,
            executable: s.executable,
            arguments: s.arguments,
            working_directory: s.working_directory,
            logon_type: 3,
            trigger_count: 1,
            trigger_type: 9,
            trigger_user_sid: "S-1-5-21-1-2-3-1001".into(),
            trigger_enabled: true,
            trigger_delay: "PT10S".into(),
            allow_hard_terminate: false,
            instances: 2,
            execution_limit: "PT0S".into(),
            restart_interval: "PT1M".into(),
            restart_count: 999,
            stop_on_battery: false,
            disallow_on_battery: false,
            start_when_available: true,
            network_only: false,
            hidden: false,
            wake: false,
            demand_start: true,
            group_id: String::new(),
            start_boundary: String::new(),
            end_boundary: String::new(),
            repetition_interval: String::new(),
            repetition_duration: String::new(),
        }
    }
    #[test]
    fn owned_binding_refuses_foreign_stale_and_unsafe_definitions() {
        let good = binding();
        let sid = good.user_sid.clone();
        assert_eq!(good.admit(&spec(), &sid).unwrap(), StartupKind::Logon);
        let changes: &[fn(&mut TaskBinding)] = &[
            |b| b.source.push('x'),
            |b| b.user_sid.push('0'),
            |b| b.run_level = 1,
            |b| b.action_count = 2,
            |b| b.action_type = 5,
            |b| b.executable.push('x'),
            |b| b.arguments.push('x'),
            |b| b.working_directory.push('x'),
            |b| b.logon_type = 2,
            |b| b.trigger_count = 2,
            |b| b.trigger_type = 1,
            |b| b.trigger_user_sid.push('0'),
            |b| b.trigger_enabled = false,
            |b| b.trigger_delay = "PT0S".into(),
            |b| b.allow_hard_terminate = true,
            |b| b.instances = 0,
            |b| b.execution_limit = "PT1H".into(),
            |b| b.restart_interval = "PT1S".into(),
            |b| b.restart_count = 0,
            |b| b.stop_on_battery = true,
            |b| b.disallow_on_battery = true,
            |b| b.start_when_available = false,
            |b| b.network_only = true,
            |b| b.hidden = true,
            |b| b.wake = true,
            |b| b.demand_start = false,
            |b| b.group_id = "S-1-5-32-544".into(),
            |b| b.start_boundary = "2026-10-29T10:00:00".into(),
            |b| b.end_boundary = "2026-10-30T10:00:00".into(),
            |b| b.repetition_interval = "PT1M".into(),
            |b| b.repetition_duration = "PT1H".into(),
        ];
        for change in changes {
            let mut bad = good.clone();
            change(&mut bad);
            assert!(bad.admit(&spec(), &sid).is_err());
        }
        assert!(good.admit(&spec(), "not-a-sid").is_err());
        let mut boot = good;
        boot.logon_type = 1;
        boot.trigger_type = 8;
        boot.trigger_delay = "PT30S".into();
        boot.trigger_user_sid.clear();
        assert_eq!(boot.admit(&spec(), &sid).unwrap(), StartupKind::Boot);
    }
    #[test]
    fn definitions_escape_paths_and_never_accept_remote_or_ambiguous_paths() {
        let special = OwnedTaskSpec::new(
            "0123456789abcdef",
            Path::new(r"C:\Raiun & Co\raiun.exe"),
            "--config \"C:\\a&b'c.json\" drive serve",
            Path::new(r"C:\Raiun & Co"),
        )
        .unwrap();
        let rendered = special
            .definition_xml(StartupKind::Logon, "S-1-5-21-1-2-3-1001")
            .unwrap();
        assert!(rendered.contains("Raiun &amp; Co"));
        assert!(rendered.contains("&quot;C:\\a&amp;b&apos;c.json&quot;"));
        assert!(rendered.contains("<RunLevel>LeastPrivilege</RunLevel>"));
        for bad in [
            r"relative.exe",
            r"\\server\share\raiun.exe",
            r"\\?\C:\raiun.exe",
            r"C:\..\raiun.exe",
            r"C:\raiun.exe:other",
        ] {
            assert!(
                OwnedTaskSpec::new(
                    "0123456789abcdef",
                    Path::new(bad),
                    "serve",
                    Path::new(r"C:\Raiun")
                )
                .is_err()
            );
        }
        assert!(spec().definition_xml(StartupKind::Boot, "bad").is_err());
        assert!(
            OwnedTaskSpec::new(
                "../bad",
                Path::new(r"C:\raiun.exe"),
                "serve",
                Path::new(r"C:\Raiun")
            )
            .is_err()
        );
    }
}

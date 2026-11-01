// Platform entry points share protocol helpers; native capabilities are
// implemented and validated by their respective Unix and Windows adapters.
#[cfg(any(unix, windows))]
mod account_avatar_wire;
#[cfg(any(unix, windows))]
mod guest_sharing_wire;
#[cfg(any(unix, windows))]
mod sharing_wire;

#[cfg(any(unix, windows))]
mod runtime_mode;

#[cfg(any(unix, windows))]
mod headless_runtime;

#[cfg(windows)]
use agent_windows::auth;

#[cfg(unix)]
include!("agent_unix.rs");

#[cfg(any(windows, test))]
mod windows_recovery_request;

#[cfg(windows)]
mod agent_windows;

#[cfg(windows)]
fn main() {
    if let Err(error) = agent_windows::run() {
        eprintln!("Raiun: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(any(unix, windows)))]
fn main() {
    eprintln!("Raiun: This target is not supported");
    std::process::exit(1);
}

#[cfg(all(test, not(windows)))]
#[path = "windows_file_rename_producer.rs"]
mod windows_file_rename_producer;

#[cfg(all(test, not(windows)))]
#[path = "windows_namespace_dispatcher.rs"]
mod windows_namespace_dispatcher;

#[cfg(all(test, not(windows)))]
#[path = "windows_create_executor.rs"]
mod windows_create_executor;

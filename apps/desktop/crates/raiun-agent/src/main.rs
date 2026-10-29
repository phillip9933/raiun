// Platform entry points share protocol helpers; native capabilities are
// implemented and validated by their respective Unix and Windows adapters.
#[cfg(any(unix, windows))]
mod account_avatar_wire;
#[cfg(any(unix, windows))]
mod guest_sharing_wire;
#[cfg(any(unix, windows))]
mod sharing_wire;

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

// The complete mount-capable agent remains a Unix implementation until a
// native Windows Cloud Files provider is available. Windows builds use the
// separate named-pipe entry point, which reports the missing provider instead
// of simulating a drive.
#[cfg(unix)]
include!("agent_unix.rs");

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

//! Windows named-pipe transport for the shared bounded Raiun control protocol.
//!
//! The adapter opens no privileged service, never requests elevation, and
//! creates a pipe whose DACL grants access only to the current user's SID.
//! Remote pipe clients are rejected by the kernel. JSON framing and limits
//! remain implemented in `raiun-control`.

#[cfg(any(windows, test))]
pub mod autostart;

#[cfg(windows)]
#[allow(unsafe_code)]
mod private_directory;
#[cfg(windows)]
#[allow(unsafe_code)]
mod session_store;
#[cfg(windows)]
#[allow(unsafe_code)]
mod win32;

/// A pinned Windows directory handle for safe private-journal operations.
#[cfg(windows)]
pub use private_directory::{
    OwnedPrivateReader, OwnedPrivateStagedReader, PinnedDirectory, PinnedFileIdentity,
    PinnedPrivateFile, PinnedPrivateFileAccess, PrivateDirectory,
};
/// DPAPI-protected, current-user-only storage for bounded serialized sessions.
#[cfg(windows)]
pub use session_store::DpapiSessionStore;
/// A one-shot listener bound to the current Windows user's private pipe.
#[cfg(windows)]
pub use win32::{NamedPipeListener, PipeStream, connect_current_user};

/// Construct the stable, per-user pipe path from an already-resolved SID.
///
/// The SID must come from the current token, not UI or IPC input.
pub fn pipe_path_for_sid(sid: &str) -> Option<String> {
    if !is_sid_shape(sid) {
        return None;
    }
    Some(format!(r"\\.\pipe\raiun-control-{sid}"))
}

fn is_sid_shape(sid: &str) -> bool {
    if sid.len() > 184 {
        return false;
    }
    let Some(rest) = sid.strip_prefix("S-") else {
        return false;
    };
    let mut components = rest.split('-');
    let Some(revision) = components.next() else {
        return false;
    };
    if revision != "1" {
        return false;
    }
    let Some(authority) = components.next() else {
        return false;
    };
    if authority.is_empty() || !authority.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let subauthorities: Vec<_> = components.collect();
    !subauthorities.is_empty()
        && subauthorities.len() <= 15
        && subauthorities
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::pipe_path_for_sid;
    use raiun_control::{encode_json_line, read_json_value};
    use serde_json::{Value, json};
    use std::io::Cursor;

    #[test]
    fn pipe_path_is_derived_only_from_a_bounded_sid_shape() {
        assert_eq!(
            pipe_path_for_sid("S-1-5-21-123-456-789-1001").as_deref(),
            Some(r"\\.\pipe\raiun-control-S-1-5-21-123-456-789-1001")
        );
        for invalid in [
            "",
            "S-1-5",
            "S-2-5-1",
            "S-1--1",
            "S-1-5-1/name",
            "S-1-5-1-💥",
        ] {
            assert!(pipe_path_for_sid(invalid).is_none(), "accepted {invalid}");
        }
    }

    #[test]
    fn shared_protocol_keeps_the_full_supported_session_blob_inside_its_bound() {
        let session_blob = "s".repeat(65_536);
        let request = json!({"action":"auth_restore","session":session_blob});
        let frame = encode_json_line(&request).expect("encode a maximum-size session field");
        let decoded: Value = read_json_value(&mut Cursor::new(&*frame)).expect("decode frame");
        assert_eq!(decoded["session"].as_str().unwrap().len(), 65_536);
    }
}

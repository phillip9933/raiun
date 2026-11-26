//! Bounded, untrusted directory-change hints. No namespace mutation authority.
//!
//! A hint never establishes ordinary classification, ancestry, FileID, remote
//! identity, an upload decision or a user deletion. Consumers must reconcile
//! through independently pinned objects and a durable inventory. This module
//! does not integrate with any live provider or perform namespace mutations.

use std::fmt;

pub const NOTIFICATION_BUFFER_BYTES: usize = 64 * 1024;
pub const MAX_NOTIFICATION_HINTS: usize = 1024;
const HEADER_BYTES: usize = 12;
const MAX_COMPONENTS: usize = 256;

#[cfg(any(windows, test))]
const OBSERVER_ACCESS_MASK: u32 = 0x0001 | 0x0080; // LIST_DIRECTORY | READ_ATTRIBUTES

#[cfg(any(windows, test))]
#[derive(Clone, Copy)]
enum ConstructionStage {
    OriginalMetadata,
    KernelPath,
    SameObjectOpen,
    ReopenedMetadata,
    OriginalPostMetadata,
    ReopenedPostMetadata,
    MetadataChanged,
    Event,
}
#[cfg(any(windows, test))]
impl ConstructionStage {
    const fn code(self) -> &'static str {
        match self {
            Self::OriginalMetadata => "original_metadata",
            Self::KernelPath => "kernel_path",
            Self::SameObjectOpen => "same_object_open",
            Self::ReopenedMetadata => "reopened_metadata",
            Self::OriginalPostMetadata => "original_post_metadata",
            Self::ReopenedPostMetadata => "reopened_post_metadata",
            Self::MetadataChanged => "metadata_changed",
            Self::Event => "event",
        }
    }
}

/// Physical metadata only; a recognized cloud tag authenticates no provider,
/// account, root registration, ordinary storage ancestry or mutation authority.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectoryForm {
    Ordinary,
    Cloud,
}

#[cfg(any(windows, test))]
fn directory_form(attributes: u32, tag: u32) -> Option<DirectoryForm> {
    const DIRECTORY: u32 = 0x10;
    const REPARSE_POINT: u32 = 0x400;
    const NAME_SURROGATE: u32 = 0x2000_0000;
    if attributes & DIRECTORY == 0 || tag & NAME_SURROGATE != 0 {
        return None;
    }
    if attributes & REPARSE_POINT == 0 {
        return (tag == 0).then_some(DirectoryForm::Ordinary);
    }
    // Precisely CLOUD and documented CLOUD_1..F: only bits 12..15 vary.
    (tag & !0x0000_f000 == 0x9000_001a).then_some(DirectoryForm::Cloud)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryAction {
    Added,
    Removed,
    Modified,
    RenamedOldName,
    RenamedNewName,
}

/// Relative components are hints only, never a host pathname or identity.
#[derive(Clone, Eq, PartialEq)]
pub struct DirectoryHint {
    action: DirectoryAction,
    components: Vec<String>,
}
impl DirectoryHint {
    pub fn action(&self) -> DirectoryAction {
        self.action
    }
    pub fn components(&self) -> &[String] {
        &self.components
    }
}
impl fmt::Debug for DirectoryHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectoryHint")
            .field("action", &self.action)
            .field("components", &"[UNTRUSTED RELATIVE HINT]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RescanReason {
    EmptyCompletion,
    MalformedBuffer,
    Limit,
    NativeError(u32),
    RootChanged,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotificationBatch {
    Hints(Vec<DirectoryHint>),
    RescanRequired(RescanReason),
}

/// Parse only the byte count returned by the OS, with no casts/alignment
/// assumptions about the input slice. Any bad record discards the whole batch;
/// a valid prefix cannot conceal a lost or malformed suffix.
pub fn parse_notification_buffer(bytes: &[u8]) -> NotificationBatch {
    match parse_records(bytes) {
        Ok(hints) => NotificationBatch::Hints(hints),
        Err(reason) => NotificationBatch::RescanRequired(reason),
    }
}

fn parse_records(bytes: &[u8]) -> Result<Vec<DirectoryHint>, RescanReason> {
    if bytes.is_empty() {
        return Err(RescanReason::EmptyCompletion);
    }
    if bytes.len() > NOTIFICATION_BUFFER_BYTES {
        return Err(RescanReason::Limit);
    }
    let malformed = RescanReason::MalformedBuffer;
    let mut hints = Vec::new();
    let mut offset = 0usize;
    loop {
        if hints.len() >= MAX_NOTIFICATION_HINTS {
            return Err(RescanReason::Limit);
        }
        let header_end = offset.checked_add(HEADER_BYTES).ok_or(malformed)?;
        let header = bytes.get(offset..header_end).ok_or(malformed)?;
        let field = |start| {
            u32::from_le_bytes([
                header[start],
                header[start + 1],
                header[start + 2],
                header[start + 3],
            ])
        };
        let next = usize::try_from(field(0)).map_err(|_| malformed)?;
        let action = match field(4) {
            1 => DirectoryAction::Added,
            2 => DirectoryAction::Removed,
            3 => DirectoryAction::Modified,
            4 => DirectoryAction::RenamedOldName,
            5 => DirectoryAction::RenamedNewName,
            _ => return Err(malformed),
        };
        let length = usize::try_from(field(8)).map_err(|_| malformed)?;
        if length == 0 || length % 2 != 0 {
            return Err(malformed);
        }
        let end = header_end.checked_add(length).ok_or(malformed)?;
        let name = bytes.get(header_end..end).ok_or(malformed)?;
        let units = (0..length)
            .step_by(2)
            .map(|index| u16::from_le_bytes([name[index], name[index + 1]]));
        let name: String = char::decode_utf16(units)
            .collect::<Result<_, _>>()
            .map_err(|_| malformed)?;
        let components: Vec<_> = name
            .split('\\')
            .take(MAX_COMPONENTS + 1)
            .map(String::from)
            .collect();
        if components.len() > MAX_COMPONENTS {
            return Err(RescanReason::Limit);
        }
        if components.iter().any(|s| !valid_component(s)) {
            return Err(malformed);
        }
        hints.push(DirectoryHint { action, components });
        if next == 0 {
            // FILE_NOTIFY_INFORMATION can end with DWORD alignment padding.
            let padding = bytes.len() - end;
            let aligned_padding = (4 - (end & 3)) & 3;
            if padding != 0 && padding != aligned_padding {
                return Err(malformed);
            }
            return Ok(hints);
        }
        let extent = HEADER_BYTES.checked_add(length).ok_or(malformed)?;
        if next & 3 != 0 || next < extent {
            return Err(malformed);
        }
        offset = offset.checked_add(next).ok_or(malformed)?;
        // A nonzero offset must point to an actual next header, not EOF.
        if offset & 3 != 0 || offset >= bytes.len() {
            return Err(malformed);
        }
    }
}

fn valid_component(s: &str) -> bool {
    if s.is_empty()
        || s.encode_utf16().count() > 255
        || matches!(s, "." | "..")
        || s.ends_with(['.', ' '])
        || s.chars()
            .any(|c| c.is_control() || matches!(c, '/' | ':' | '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return false;
    }
    let base = s.split('.').next().unwrap_or("").trim_end();
    let base = base.to_ascii_uppercase();
    !matches!(
        base.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) && !(base.chars().count() == 4
        && (base.starts_with("COM") || base.starts_with("LPT"))
        && matches!(base.chars().last(), Some('1'..='9' | '¹' | '²' | '³')))
}

/// Same-batch rename pairing over untrusted names only. The returned pairs
/// grant no identity, ancestry or namespace-mutation authority.
#[path = "directory_rename_hints.rs"]
pub mod directory_rename_hints;

#[cfg(windows)]
#[allow(unsafe_code)]
#[path = "directory_notifications_native.rs"]
mod native;
#[cfg(all(windows, feature = "synthetic-agent-integration", debug_assertions))]
pub use native::ObserverConstructionFailure;
#[cfg(windows)]
pub use native::{DirectoryObserver, ObserverPoll};

#[cfg(windows)]
#[path = "directory_notifications_pump.rs"]
mod pump;
#[cfg(windows)]
pub use pump::DirectoryObserverPump;

#[cfg(test)]
#[path = "directory_notifications_tests.rs"]
mod tests;

//! Ordinary namespace coordination records, never mutation or native authority.
//!
//! Parsed records, classification labels and reported verification events are
//! untrusted evidence. A future consumer must authenticate storage and freshly
//! reclassify the full ancestry, account/root/generation, permissions and native
//! identity before every action. This module performs no I/O, dispatch or replay.
use crate::{EditJournalScope, LocalFileIdentity, RemoteEditBaseline};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub const NAMESPACE_INTENT_VERSION: u32 = 1;
pub const MAX_NAMESPACE_COMPONENTS: usize = 256;
pub const MAX_NAMESPACE_PATH_BYTES: usize = 32 * 1024;
const MAX_FIELD_BYTES: usize = 4096;
const MAX_EVENTS: u64 = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceIntentError {
    InvalidMetadata,
    ScopeMismatch,
    StorageClassificationUnavailable,
    InvalidTransition,
    EvidenceMismatch,
    Limit,
}
impl fmt::Display for NamespaceIntentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ordinary namespace intent validation failed")
    }
}
impl std::error::Error for NamespaceIntentError {}
type Result<T> = std::result::Result<T, NamespaceIntentError>;

/// A stored classification observation, NOT a live ordinary-storage capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageClassification {
    Ordinary,
    Encrypted,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedAuthorization {
    pub agent_generation: u64,
    pub token_generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceObjectKind {
    File,
    Directory,
}

/// Exact captured parent provenance. No parent is admitted from its name alone.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceParent {
    pub scope: EditJournalScope,
    pub authorization: CapturedAuthorization,
    /// Captured classification of the complete ancestry through this parent.
    /// Ordinary must never mean only that the final directory was inspected.
    /// This stored observation still cannot substitute for fresh classification.
    pub classification: StorageClassification,
    pub local_file: LocalFileIdentity,
    pub local_components: Vec<String>,
    pub remote: RemoteEditBaseline,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalNamespaceEntry {
    pub parent: NamespaceParent,
    pub name: String,
    pub local_file: LocalFileIdentity,
    pub object_kind: NamespaceObjectKind,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExistingNamespaceEntry {
    pub local: LocalNamespaceEntry,
    pub remote: RemoteEditBaseline,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceFileContent {
    pub byte_len: u64,
    pub sha256: String,
}

/// Delete is an explicit ordinary user operation. Provider cleanup is not an
/// alternative spelling of this intent and has no deserializable variant here.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NamespaceOperation {
    CreateFile {
        destination: LocalNamespaceEntry,
        content: NamespaceFileContent,
    },
    CreateDirectory {
        destination: LocalNamespaceEntry,
    },
    ReplaceContents {
        source: ExistingNamespaceEntry,
        content: NamespaceFileContent,
    },
    AtomicReplacement {
        source: ExistingNamespaceEntry,
        replacement: LocalNamespaceEntry,
        content: NamespaceFileContent,
    },
    MoveWithinScope {
        source: ExistingNamespaceEntry,
        destination: LocalNamespaceEntry,
    },
    /// One file copy followed by conditional removal. Cross-scope directories
    /// require a separately verified child/tree plan, not an atomic MOVE claim.
    CopyThenRemove {
        source: ExistingNamespaceEntry,
        destination: LocalNamespaceEntry,
        content: NamespaceFileContent,
    },
    DeleteFile {
        source: ExistingNamespaceEntry,
    },
    DeleteDirectory {
        source: ExistingNamespaceEntry,
    },
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceIntent {
    pub schema_version: u32,
    pub record_id: String,
    pub record_generation: u64,
    pub operation: NamespaceOperation,
}

/// Report context retains BOTH independently captured authorizations for copy
/// across accounts/Spaces. Matching this data does not authenticate the reporter.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceEventContext {
    pub intent_sha256: String,
    pub record_id: String,
    pub record_generation: u64,
    pub source_parent: Option<NamespaceParent>,
    pub destination_parent: Option<NamespaceParent>,
}
/// A verification REPORT, not VerifiedEditReadback or native completion proof.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceDestinationReport {
    pub destination: LocalNamespaceEntry,
    pub remote: RemoteEditBaseline,
    pub content: Option<NamespaceFileContent>,
}
/// Durable link to a separately protected, conditionally reconciled successor.
/// This metadata is a history report, never native or dispatch authority.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuedEditReference {
    pub record_id: String,
    pub generation: u64,
    pub manifest_commitment: [u8; 32],
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NamespaceEventKind {
    RemoteSubmitted,
    RemoteVerified {
        report: NamespaceDestinationReport,
    },
    RemoteDeleted {
        source: ExistingNamespaceEntry,
    },
    LocalCompleted {
        destination: LocalNamespaceEntry,
    },
    LocalContinued {
        destination: LocalNamespaceEntry,
        edit: ContinuedEditReference,
    },
    LocalDeleted {
        source: ExistingNamespaceEntry,
    },
    SourceRemovalSubmitted {
        source: ExistingNamespaceEntry,
    },
    SourceRemovalVerified {
        source: ExistingNamespaceEntry,
    },
    Conflict,
    Deferred,
    Uncertain,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceEvent {
    pub context: NamespaceEventContext,
    pub sequence: u64,
    pub event: NamespaceEventKind,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespacePhase {
    Pending,
    Submitted,
    Verified,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceAttention {
    Conflict,
    Deferred,
    Uncertain,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceProgressSnapshot {
    pub local_completed: bool,
    pub continued: bool,
    pub remote: NamespacePhase,
    pub source_removal: Option<NamespacePhase>,
    pub attention: Option<NamespaceAttention>,
    pub recorded_complete: bool,
    pub sequence: u64,
}

/// Nonserializable consistency checker for an intent's reported history. It has
/// no conversion into a cloud/native capability and no automatic retry method.
pub struct NamespaceIntentProgress {
    intent: NamespaceIntent,
    local_completed: bool,
    continued: bool,
    remote: NamespacePhase,
    source_removal: Option<NamespacePhase>,
    attention: Option<NamespaceAttention>,
    sequence: u64,
}
macro_rules! redacted_debug {
    ($($kind:ty),+ $(,)?) => {$ (
        impl fmt::Debug for $kind {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($kind), "([BOUND EVIDENCE])"))
            }
        }
    )+ };
}
redacted_debug!(
    NamespaceParent,
    LocalNamespaceEntry,
    ExistingNamespaceEntry,
    NamespaceFileContent,
    NamespaceOperation,
    NamespaceIntent,
    NamespaceEventContext,
    NamespaceDestinationReport,
    ContinuedEditReference,
    NamespaceEventKind,
    NamespaceEvent,
    NamespaceIntentProgress
);

fn valid_field(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_FIELD_BYTES && s.trim() == s && !s.chars().any(char::is_control)
}
fn valid_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn valid_etag(s: &str) -> bool {
    s.len() >= 3
        && s.len() <= MAX_FIELD_BYTES
        && s.starts_with('"')
        && s.ends_with('"')
        && !s[1..s.len() - 1]
            .bytes()
            .any(|c| c == b'"' || c < 0x21 || c == 0x7f)
}
fn valid_component(s: &str) -> bool {
    if s.is_empty()
        || s.len() > 255
        || s.encode_utf16().count() > 255
        || matches!(s, "." | "..")
        || s.ends_with(['.', ' '])
        || s.chars().any(|c| {
            c.is_control() || matches!(c, '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*')
        })
    {
        return false;
    }
    let base = s
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_ascii_uppercase();
    !matches!(
        base.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) && !(base.len() == 4
        && (base.starts_with("COM") || base.starts_with("LPT"))
        && matches!(base.as_bytes()[3], b'1'..=b'9'))
}
fn validate_components(parts: &[String]) -> Result<()> {
    if parts.is_empty()
        || parts.len() > MAX_NAMESPACE_COMPONENTS
        || parts.iter().any(|part| !valid_component(part))
    {
        return Err(NamespaceIntentError::InvalidMetadata);
    }
    let bytes = parts
        .iter()
        .try_fold(0usize, |sum, part| sum.checked_add(part.len() + 1))
        .ok_or(NamespaceIntentError::Limit)?;
    if bytes - 1 > MAX_NAMESPACE_PATH_BYTES {
        return Err(NamespaceIntentError::Limit);
    }
    Ok(())
}
fn validate_remote(remote: &RemoteEditBaseline) -> Result<()> {
    if !valid_field(&remote.resource_id) || !valid_etag(&remote.etag) {
        return Err(NamespaceIntentError::InvalidMetadata);
    }
    Ok(())
}

// Profiles and captured generations are not remote namespaces: two profiles
// may address the same account/Space. This comparison only rejects known aliases;
// a consumer still needs fresh native/server alias and ancestry checks.
fn same_remote_namespace(a: &NamespaceParent, b: &NamespaceParent) -> bool {
    a.scope.server_origin == b.scope.server_origin
        && a.scope.account_subject == b.scope.account_subject
        && a.scope.space_id == b.scope.space_id
        && a.scope.root_resource_id == b.scope.root_resource_id
}
impl NamespaceParent {
    pub fn validate(&self) -> Result<()> {
        let scope = &self.scope;
        if ![
            &scope.profile_id,
            &scope.server_origin,
            &scope.account_subject,
            &scope.space_id,
            &scope.root_resource_id,
        ]
        .into_iter()
        .all(|s| valid_field(s))
            || raiun_opencloud::validate_captured_server_origin(&scope.server_origin).is_err()
            || scope
                .server_origin
                .split_once("://")
                .is_none_or(|(_, authority)| authority.contains('/'))
            || scope.root_file_index == 0
            || self.authorization.agent_generation == 0
            || self.authorization.token_generation == 0
            || self.local_file.volume_serial != scope.root_volume_serial
            || self.local_file.file_index == 0
            || self.local_file.file_index == scope.root_file_index
        {
            return Err(NamespaceIntentError::InvalidMetadata);
        }
        if self.classification != StorageClassification::Ordinary {
            return Err(NamespaceIntentError::StorageClassificationUnavailable);
        }
        validate_components(&self.local_components)?;
        validate_remote(&self.remote)
    }
}
impl LocalNamespaceEntry {
    pub fn validate(&self) -> Result<()> {
        self.parent.validate()?;
        if !valid_component(&self.name)
            || self.local_file.volume_serial != self.parent.scope.root_volume_serial
            || self.local_file.file_index == 0
            || self.local_file == self.parent.local_file
            || self.local_file.file_index == self.parent.scope.root_file_index
        {
            return Err(NamespaceIntentError::InvalidMetadata);
        }
        let mut parts = self.parent.local_components.clone();
        parts.push(self.name.clone());
        validate_components(&parts)
    }
}
impl ExistingNamespaceEntry {
    pub fn validate(&self) -> Result<()> {
        self.local.validate()?;
        validate_remote(&self.remote)?;
        if self.remote.resource_id == self.local.parent.remote.resource_id
            || self.remote.resource_id == self.local.parent.scope.root_resource_id
        {
            return Err(NamespaceIntentError::ScopeMismatch);
        }
        Ok(())
    }
}
impl NamespaceFileContent {
    pub fn validate(&self) -> Result<()> {
        if !valid_hex(&self.sha256, 64) {
            return Err(NamespaceIntentError::InvalidMetadata);
        }
        Ok(())
    }
}
impl NamespaceOperation {
    fn source(&self) -> Option<&ExistingNamespaceEntry> {
        match self {
            Self::CreateFile { .. } | Self::CreateDirectory { .. } => None,
            Self::ReplaceContents { source, .. }
            | Self::AtomicReplacement { source, .. }
            | Self::MoveWithinScope { source, .. }
            | Self::CopyThenRemove { source, .. }
            | Self::DeleteFile { source }
            | Self::DeleteDirectory { source } => Some(source),
        }
    }
    fn destination(&self) -> Option<&LocalNamespaceEntry> {
        match self {
            Self::CreateFile { destination, .. }
            | Self::CreateDirectory { destination }
            | Self::MoveWithinScope { destination, .. }
            | Self::CopyThenRemove { destination, .. } => Some(destination),
            Self::ReplaceContents { source, .. } => Some(&source.local),
            Self::AtomicReplacement { replacement, .. } => Some(replacement),
            Self::DeleteFile { .. } | Self::DeleteDirectory { .. } => None,
        }
    }
    fn content(&self) -> Option<&NamespaceFileContent> {
        match self {
            Self::CreateFile { content, .. }
            | Self::ReplaceContents { content, .. }
            | Self::AtomicReplacement { content, .. }
            | Self::CopyThenRemove { content, .. } => Some(content),
            _ => None,
        }
    }
    fn requires_source_removal(&self) -> bool {
        matches!(
            self,
            Self::MoveWithinScope { .. } | Self::CopyThenRemove { .. }
        )
    }
    fn validate(&self) -> Result<()> {
        if let Some(source) = self.source() {
            source.validate()?;
        }
        if let Some(destination) = self.destination() {
            destination.validate()?;
        }
        if let Some(content) = self.content() {
            content.validate()?;
        }
        let invalid = NamespaceIntentError::InvalidMetadata;
        match self {
            Self::CreateFile { destination, .. }
                if destination.object_kind != NamespaceObjectKind::File =>
            {
                Err(invalid)
            }
            Self::CreateDirectory { destination }
                if destination.object_kind != NamespaceObjectKind::Directory =>
            {
                Err(invalid)
            }
            Self::ReplaceContents { source, .. } | Self::DeleteFile { source }
                if source.local.object_kind != NamespaceObjectKind::File =>
            {
                Err(invalid)
            }
            Self::DeleteDirectory { source }
                if source.local.object_kind != NamespaceObjectKind::Directory =>
            {
                Err(invalid)
            }
            Self::AtomicReplacement {
                source,
                replacement,
                ..
            } => {
                if source.local.object_kind != NamespaceObjectKind::File
                    || replacement.object_kind != NamespaceObjectKind::File
                    || source.local.parent != replacement.parent
                    || source.local.name != replacement.name
                    || source.local.local_file == replacement.local_file
                {
                    Err(NamespaceIntentError::ScopeMismatch)
                } else {
                    Ok(())
                }
            }
            Self::MoveWithinScope {
                source,
                destination,
            } => {
                if source.local.parent.scope != destination.parent.scope
                    || source.local.parent.authorization != destination.parent.authorization
                    || source.local.local_file != destination.local_file
                    || source.local.object_kind != destination.object_kind
                    || (source.local.parent == destination.parent
                        && source.local.name == destination.name)
                    || (source.local.object_kind == NamespaceObjectKind::Directory
                        && destination.parent.local_components.len()
                            > source.local.parent.local_components.len()
                        && destination
                            .parent
                            .local_components
                            .iter()
                            .zip({
                                let mut path = source.local.parent.local_components.clone();
                                path.push(source.local.name.clone());
                                path
                            })
                            .all(|(destination, source)| destination.eq_ignore_ascii_case(&source)))
                {
                    Err(NamespaceIntentError::ScopeMismatch)
                } else {
                    Ok(())
                }
            }
            Self::CopyThenRemove {
                source,
                destination,
                content,
            } => {
                if source.local.object_kind != NamespaceObjectKind::File
                    || destination.object_kind != NamespaceObjectKind::File
                    || source.remote.byte_len != content.byte_len
                    || source.local == *destination
                    || (source.local.parent.scope.root_volume_serial
                        == destination.parent.scope.root_volume_serial
                        && source.local.local_file == destination.local_file)
                    || (same_remote_namespace(&source.local.parent, &destination.parent)
                        && source.local.parent.remote.resource_id
                            == destination.parent.remote.resource_id
                        && source.local.name.eq_ignore_ascii_case(&destination.name))
                    || (source.local.parent.local_file == destination.parent.local_file
                        && source.local.name.eq_ignore_ascii_case(&destination.name))
                {
                    Err(NamespaceIntentError::ScopeMismatch)
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }
}
impl NamespaceIntent {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != NAMESPACE_INTENT_VERSION
            || !valid_hex(&self.record_id, 32)
            || self.record_generation == 0
        {
            return Err(NamespaceIntentError::InvalidMetadata);
        }
        self.operation.validate()
    }
    pub fn event_context(&self) -> Result<NamespaceEventContext> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| NamespaceIntentError::InvalidMetadata)?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let intent_sha256 = Sha256::digest(bytes)
            .iter()
            .flat_map(|byte| {
                [
                    HEX[(byte >> 4) as usize] as char,
                    HEX[(byte & 15) as usize] as char,
                ]
            })
            .collect();
        Ok(NamespaceEventContext {
            intent_sha256,
            record_id: self.record_id.clone(),
            record_generation: self.record_generation,
            source_parent: self.operation.source().map(|s| s.local.parent.clone()),
            destination_parent: self.operation.destination().map(|d| d.parent.clone()),
        })
    }
}
impl NamespaceIntentProgress {
    pub fn new(intent: NamespaceIntent) -> Result<Self> {
        intent.validate()?;
        let source_removal = intent
            .operation
            .requires_source_removal()
            .then_some(NamespacePhase::Pending);
        Ok(Self {
            intent,
            local_completed: false,
            continued: false,
            remote: NamespacePhase::Pending,
            source_removal,
            attention: None,
            sequence: 0,
        })
    }
    pub fn snapshot(&self) -> NamespaceProgressSnapshot {
        NamespaceProgressSnapshot {
            local_completed: self.local_completed,
            continued: self.continued,
            remote: self.remote,
            source_removal: self.source_removal,
            attention: self.attention,
            recorded_complete: self.attention.is_none()
                && (self.local_completed || self.continued)
                && self.remote == NamespacePhase::Verified
                && self
                    .source_removal
                    .is_none_or(|p| p == NamespacePhase::Verified),
            sequence: self.sequence,
        }
    }
    /// Record a consistent REPORT only. Callers must independently authenticate
    /// evidence and obtain fresh capabilities; even recorded_complete is not one.
    pub fn record(&mut self, event: &NamespaceEvent) -> Result<()> {
        self.intent.validate()?;
        if event.context != self.intent.event_context()? {
            return Err(NamespaceIntentError::ScopeMismatch);
        }
        if event.sequence
            != self
                .sequence
                .checked_add(1)
                .ok_or(NamespaceIntentError::Limit)?
            || event.sequence > MAX_EVENTS
        {
            return Err(NamespaceIntentError::InvalidTransition);
        }
        if self.attention.is_some() || self.snapshot().recorded_complete {
            return Err(NamespaceIntentError::InvalidTransition);
        }
        use NamespaceEventKind as E;
        match &event.event {
            E::Conflict => self.attention = Some(NamespaceAttention::Conflict),
            E::Deferred => self.attention = Some(NamespaceAttention::Deferred),
            E::Uncertain => self.attention = Some(NamespaceAttention::Uncertain),
            E::RemoteSubmitted if self.remote == NamespacePhase::Pending => {
                self.remote = NamespacePhase::Submitted
            }
            E::RemoteVerified { report } if self.remote == NamespacePhase::Submitted => {
                self.validate_destination_report(report)?;
                self.remote = NamespacePhase::Verified;
            }
            E::RemoteDeleted { source }
                if self.remote == NamespacePhase::Submitted
                    && self.intent.operation.destination().is_none() =>
            {
                self.match_source(source)?;
                self.remote = NamespacePhase::Verified;
            }
            E::LocalContinued { destination, edit }
                if !self.local_completed
                    && !self.continued
                    && self.remote == NamespacePhase::Verified
                    && matches!(self.intent.operation, NamespaceOperation::CreateFile { .. }) =>
            {
                destination.validate()?;
                if self.intent.operation.destination() != Some(destination)
                    || !valid_hex(&edit.record_id, 32)
                    || edit.record_id == self.intent.record_id
                    || edit.generation == 0
                    || edit.manifest_commitment == [0; 32]
                {
                    return Err(NamespaceIntentError::EvidenceMismatch);
                }
                self.continued = true;
            }
            E::LocalCompleted { destination } if !self.local_completed => {
                destination.validate()?;
                if self.intent.operation.destination() != Some(destination) {
                    return Err(NamespaceIntentError::EvidenceMismatch);
                }
                self.local_completed = true;
            }
            E::LocalDeleted { source }
                if !self.local_completed && self.intent.operation.destination().is_none() =>
            {
                self.match_source(source)?;
                self.local_completed = true;
            }
            E::SourceRemovalSubmitted { source }
                if matches!(
                    self.intent.operation,
                    NamespaceOperation::CopyThenRemove { .. }
                ) && self.local_completed
                    && self.remote == NamespacePhase::Verified
                    && self.source_removal == Some(NamespacePhase::Pending) =>
            {
                self.match_source(source)?;
                self.source_removal = Some(NamespacePhase::Submitted);
            }
            E::SourceRemovalVerified { source }
                if self.local_completed
                    && self.remote == NamespacePhase::Verified
                    && (self.source_removal == Some(NamespacePhase::Submitted)
                        || (matches!(
                            self.intent.operation,
                            NamespaceOperation::MoveWithinScope { .. }
                        ) && self.source_removal == Some(NamespacePhase::Pending))) =>
            {
                self.match_source(source)?;
                self.source_removal = Some(NamespacePhase::Verified);
            }
            _ => return Err(NamespaceIntentError::InvalidTransition),
        }
        self.sequence = event.sequence;
        Ok(())
    }
    fn match_source(&self, source: &ExistingNamespaceEntry) -> Result<()> {
        source.validate()?;
        if self.intent.operation.source() != Some(source) {
            Err(NamespaceIntentError::EvidenceMismatch)
        } else {
            Ok(())
        }
    }
    fn validate_destination_report(&self, report: &NamespaceDestinationReport) -> Result<()> {
        report.destination.validate()?;
        validate_remote(&report.remote)?;
        if self.intent.operation.destination() != Some(&report.destination)
            || self.intent.operation.content() != report.content.as_ref()
            || report.remote.resource_id == report.destination.parent.remote.resource_id
            || report.remote.resource_id == report.destination.parent.scope.root_resource_id
        {
            return Err(NamespaceIntentError::EvidenceMismatch);
        }
        if let NamespaceOperation::CopyThenRemove { source, .. } = &self.intent.operation
            && same_remote_namespace(&source.local.parent, &report.destination.parent)
            && source.remote.resource_id == report.remote.resource_id
        {
            return Err(NamespaceIntentError::EvidenceMismatch);
        }
        if let Some(content) = &report.content {
            content.validate()?;
            if content.byte_len != report.remote.byte_len {
                return Err(NamespaceIntentError::EvidenceMismatch);
            }
        }
        if matches!(
            self.intent.operation,
            NamespaceOperation::ReplaceContents { .. }
                | NamespaceOperation::AtomicReplacement { .. }
                | NamespaceOperation::MoveWithinScope { .. }
        ) && self
            .intent
            .operation
            .source()
            .is_none_or(|source| source.remote.resource_id != report.remote.resource_id)
        {
            return Err(NamespaceIntentError::EvidenceMismatch);
        }
        if matches!(
            self.intent.operation,
            NamespaceOperation::MoveWithinScope { .. }
        ) && self
            .intent
            .operation
            .source()
            .is_none_or(|source| source.remote.byte_len != report.remote.byte_len)
        {
            return Err(NamespaceIntentError::EvidenceMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "namespace_intent_tests.rs"]
mod tests;

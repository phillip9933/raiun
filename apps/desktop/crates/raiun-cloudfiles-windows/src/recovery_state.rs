//! Admission of the original recovery-state root, separate from v2 payload
//! authority. A legacy session root is only attested through metadata; all v2
//! children and files still require the unchanged modern private-store policy.
#![cfg(windows)]

use raiun_control_windows::{
    LegacyRecoveryMetadataDirectory, PinnedDirectory, PinnedFileIdentity, PrivateDirectory,
};
use std::{io, path::Path, sync::Arc};

enum StateRoot {
    Modern(Arc<PrivateDirectory>),
    Legacy(Arc<LegacyRecoveryMetadataDirectory>),
}

/// No file/body, mutation or raw-handle API. The path and identity always name
/// the ORIGINAL state root, including for legacy quota/catalog accounting.
pub(crate) struct RecoveryStateRoot(StateRoot);

impl RecoveryStateRoot {
    pub(crate) fn modern(state: Arc<PrivateDirectory>) -> Arc<Self> {
        Arc::new(Self(StateRoot::Modern(state)))
    }

    /// Called only by the explicit GUI compatibility builder with the exact
    /// state path captured from its DPAPI protector. Does not repair ACLs,
    /// relocate records or adopt any legacy body as authenticated v2 content.
    pub(crate) fn existing_gui(path: &Path) -> io::Result<Arc<Self>> {
        let parent = path.parent().ok_or_else(invalid_root)?;
        let name = path.file_name().ok_or_else(invalid_root)?;
        let parent = PinnedDirectory::open(parent)?;
        let metadata = Arc::new(LegacyRecoveryMetadataDirectory::open_under(&parent, name)?);
        metadata.verify_path()?;
        parent.verify_path()?;
        Ok(Arc::new(Self(StateRoot::Legacy(metadata))))
    }

    pub(crate) fn path(&self) -> &Path {
        match &self.0 {
            StateRoot::Modern(root) => root.path(),
            StateRoot::Legacy(root) => root.path(),
        }
    }

    pub(crate) fn identity(&self) -> PinnedFileIdentity {
        match &self.0 {
            StateRoot::Modern(root) => root.identity(),
            StateRoot::Legacy(root) => root.identity(),
        }
    }

    pub(crate) fn verify_path(&self) -> io::Result<()> {
        match &self.0 {
            StateRoot::Modern(root) => root.verify_path(),
            StateRoot::Legacy(root) => root.verify_path(),
        }
    }
}

fn invalid_root() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "Invalid recovery state root")
}

#[cfg(test)]
#[path = "recovery_state_tests.rs"]
mod tests;

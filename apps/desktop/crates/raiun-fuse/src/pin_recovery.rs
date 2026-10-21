//! A separate, read-only namespace of retained ordinary-file snapshots.
//! These nodes never enter current cloud listings, paths or sync baselines.
use super::*;
use raiun_cache::{RetainedPinManifest, RetainedPinSummary};
use sha2::{Digest, Sha256};

pub(super) const NOTICE: &[u8] = b"Saved offline copies\n\nThese are historical, read-only copies retained on this computer. They may differ from the cloud. Some incomplete copies may not have file content available. This view does not confirm that other cloud files are absent. Copy files out to keep a separate local copy; this view never uploads or deletes cloud data.\n";

#[derive(Clone)]
pub(super) struct Snapshot {
    pub manifest: RetainedPinManifest,
    fingerprint: String,
}
impl Snapshot {
    fn new(manifest: RetainedPinManifest) -> Self {
        let mut hash = Sha256::new();
        for value in [
            &manifest.pin_id,
            &manifest.root_resource_id,
            &manifest.root_path,
        ] {
            field(&mut hash, value);
        }
        field(&mut hash, state_tag(manifest.state));
        for item in &manifest.entries {
            for value in [
                &item.parent_resource_id,
                &item.entry.id,
                &item.entry.path,
                &item.entry.etag,
            ] {
                field(&mut hash, value);
            }
            hash.update(item.entry.size.to_le_bytes());
            hash.update([u8::from(item.entry.directory)]);
        }
        Self {
            manifest,
            fingerprint: format!("{:x}", hash.finalize()),
        }
    }
}
fn field(hash: &mut Sha256, value: &str) {
    hash.update((value.len() as u64).to_le_bytes());
    hash.update(value.as_bytes());
}
fn state_tag(state: raiun_cache::PinState) -> &'static str {
    match state {
        raiun_cache::PinState::Building => "incomplete",
        raiun_cache::PinState::Ready => "ready",
        raiun_cache::PinState::Stale => "stale",
        raiun_cache::PinState::Unavailable => "unavailable",
    }
}

#[derive(Clone)]
pub(super) enum RecoveryNode {
    Catalog {
        space: String,
    },
    Pin {
        space: String,
        summary: RetainedPinSummary,
    },
    Entry {
        space: String,
        snapshot: Arc<Snapshot>,
        index: usize,
    },
    Notice {
        space: String,
    },
}
impl RecoveryNode {
    pub fn key(&self) -> String {
        let mut h = Sha256::new();
        match self {
            Self::Catalog { space } => {
                field(&mut h, "catalog");
                field(&mut h, space);
            }
            Self::Notice { space } => {
                field(&mut h, "notice");
                field(&mut h, space);
            }
            Self::Pin { space, summary } => {
                for v in [
                    "pin",
                    space,
                    &summary.pin_id,
                    &summary.root_resource_id,
                    &summary.root_path,
                    state_tag(summary.state),
                ] {
                    field(&mut h, v);
                }
            }
            Self::Entry {
                space,
                snapshot,
                index,
            } => {
                for v in ["entry", space, &snapshot.fingerprint] {
                    field(&mut h, v);
                }
                h.update((*index as u64).to_le_bytes());
            }
        }
        format!("{:x}", h.finalize())
    }
    pub fn directory(&self) -> bool {
        match self {
            Self::Catalog { .. } | Self::Pin { .. } => true,
            Self::Entry {
                snapshot, index, ..
            } => snapshot.manifest.entries[*index].entry.directory,
            Self::Notice { .. } => false,
        }
    }
    pub fn size(&self) -> u64 {
        match self {
            Self::Notice { .. } => NOTICE.len() as u64,
            Self::Entry {
                snapshot, index, ..
            } => snapshot.manifest.entries[*index].entry.size,
            _ => 0,
        }
    }
}

impl RaiunFilesystem {
    pub(super) fn append_recovery_catalog(
        &self,
        parent: u64,
        space: &str,
        entries: &[RemoteEntry],
        result: &mut Vec<Node>,
    ) -> Result<(), CloudError> {
        let catalog = match self.engine.offline_pin_recovery_catalog(space) {
            Ok(catalog) => catalog,
            Err(e)
                if matches!(
                    e.kind,
                    ErrorKind::Unsupported | ErrorKind::NotFound | ErrorKind::Conflict
                ) =>
            {
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        if !catalog.iter().any(|pin| {
            matches!(
                pin.state,
                raiun_cache::PinState::Stale | raiun_cache::PinState::Building
            )
        }) {
            return Ok(());
        }
        let used = entries
            .iter()
            .map(|e| e.path.rsplit('/').next().unwrap_or_default())
            .chain(result.iter().map(|n| n.name.as_str()))
            .collect::<std::collections::HashSet<_>>();
        let mut name = "Saved offline copies".to_owned();
        for i in 1..=MAX_DIRECTORY_ENTRIES + 1 {
            if !used.contains(name.as_str()) {
                break;
            }
            name = format!("Saved offline copies (Raiun {i})");
        }
        if used.contains(name.as_str()) {
            return Err(io_error("recovery folder name is unavailable"));
        }
        let ino = self.add_node(
            parent,
            name,
            NodeKind::Recovery(RecoveryNode::Catalog {
                space: space.into(),
            }),
        )?;
        result.push(self.node(ino)?);
        Ok(())
    }

    pub(super) fn validate_recovery_node(&self, view: &RecoveryNode) -> Result<(), CloudError> {
        match view {
            RecoveryNode::Pin { space, summary } => {
                let current = self
                    .engine
                    .offline_pin_recovery_manifest(space, &summary.pin_id)?;
                if current.root_resource_id != summary.root_resource_id
                    || current.root_path != summary.root_path
                    || current.state != summary.state
                {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "saved snapshot changed; reopen its folder",
                    ));
                }
            }
            RecoveryNode::Entry {
                space, snapshot, ..
            } => {
                if self
                    .engine
                    .offline_pin_recovery_manifest(space, &snapshot.manifest.pin_id)?
                    != snapshot.manifest
                {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "saved snapshot changed; reopen its folder",
                    ));
                }
            }
            RecoveryNode::Catalog { space } | RecoveryNode::Notice { space } => {
                self.engine.offline_pin_recovery_catalog(space)?;
            }
        }
        Ok(())
    }

    pub(super) fn recovery_children(
        &self,
        parent: u64,
        view: &RecoveryNode,
    ) -> Result<Vec<Node>, CloudError> {
        self.validate_recovery_node(view)?;
        let mut result = Vec::new();
        let (space, snapshot, parent_id) = match view {
            RecoveryNode::Catalog { space } => {
                let notice = self.add_node(
                    parent,
                    "README.txt".into(),
                    NodeKind::Recovery(RecoveryNode::Notice {
                        space: space.clone(),
                    }),
                )?;
                result.push(self.node(notice)?);
                let mut used = std::collections::HashSet::from(["README.txt".to_owned()]);
                for summary in self.engine.offline_pin_recovery_catalog(space)? {
                    let label = summary
                        .root_path
                        .rsplit('/')
                        .find(|v| !v.is_empty())
                        .unwrap_or("All files");
                    if !safe_component(label) {
                        return Err(CloudError::new(
                            ErrorKind::InvalidResponse,
                            "saved snapshot name is invalid",
                        ));
                    }
                    let mut name = label.to_owned();
                    for suffix in 1..=MAX_DIRECTORY_ENTRIES + 1 {
                        if !used.contains(&name) {
                            break;
                        }
                        name = format!("{label} (saved copy {suffix})");
                    }
                    if !used.insert(name.clone()) {
                        return Err(CloudError::new(
                            ErrorKind::Conflict,
                            "saved snapshot names are ambiguous",
                        ));
                    }
                    let ino = self.add_node(
                        parent,
                        name,
                        NodeKind::Recovery(RecoveryNode::Pin {
                            space: space.clone(),
                            summary,
                        }),
                    )?;
                    result.push(self.node(ino)?);
                }
                return Ok(result);
            }
            RecoveryNode::Pin { space, summary } => {
                let manifest = self
                    .engine
                    .offline_pin_recovery_manifest(space, &summary.pin_id)?;
                if manifest.root_resource_id != summary.root_resource_id
                    || manifest.root_path != summary.root_path
                    || manifest.state != summary.state
                {
                    return Err(CloudError::new(
                        ErrorKind::Conflict,
                        "saved snapshot changed; reopen its folder",
                    ));
                }
                let snapshot = Arc::new(Snapshot::new(manifest));
                (space.clone(), snapshot, summary.root_resource_id.clone())
            }
            RecoveryNode::Entry {
                space,
                snapshot,
                index,
            } if snapshot.manifest.entries[*index].entry.directory => (
                space.clone(),
                snapshot.clone(),
                snapshot.manifest.entries[*index].entry.id.clone(),
            ),
            _ => {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "saved copy is not a directory",
                ));
            }
        };
        for (index, item) in snapshot
            .manifest
            .entries
            .iter()
            .enumerate()
            .filter(|(_, item)| item.parent_resource_id == parent_id)
        {
            if result.len() >= MAX_DIRECTORY_ENTRIES {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "saved directory exceeds the provider listing limit",
                ));
            }
            let name = item.entry.path.rsplit('/').next().unwrap_or_default();
            if !safe_component(name) {
                return Err(CloudError::new(
                    ErrorKind::InvalidResponse,
                    "saved filename is invalid",
                ));
            }
            let ino = self.add_node(
                parent,
                name.into(),
                NodeKind::Recovery(RecoveryNode::Entry {
                    space: space.clone(),
                    snapshot: snapshot.clone(),
                    index,
                }),
            )?;
            result.push(self.node(ino)?);
        }
        Ok(result)
    }

    pub(super) fn open_recovery_node(
        &self,
        view: &RecoveryNode,
        flags: i32,
    ) -> Result<u64, CloudError> {
        if flags & libc::O_ACCMODE != libc::O_RDONLY
            || flags & (libc::O_TRUNC | libc::O_APPEND | libc::O_CREAT | libc::O_EXCL) != 0
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "saved offline copies are read-only",
            ));
        }
        self.validate_recovery_node(view)?;
        match view {
            RecoveryNode::Notice { .. } => self.register_handle(OpenFile::Read(
                ReadHandle::Static(Cursor::new(NOTICE.to_vec())),
            )),
            RecoveryNode::Entry {
                space,
                snapshot,
                index,
            } if !snapshot.manifest.entries[*index].entry.directory => {
                let engine = self.engine.clone();
                let space = space.clone();
                let snapshot = snapshot.clone();
                let index = *index;
                let reader = self.pool.call(move || {
                    let reader = engine.open_offline_pin_recovery_content(
                        &space,
                        &snapshot.manifest.pin_id,
                        &snapshot.manifest.entries[index],
                    )?;
                    // The queued open may run after the inode's validation.
                    // Fence the complete captured view again before returning
                    // its immutable reader, not merely the selected member.
                    if engine.offline_pin_recovery_manifest(&space, &snapshot.manifest.pin_id)?
                        != snapshot.manifest
                    {
                        return Err(CloudError::new(
                            ErrorKind::Conflict,
                            "saved snapshot changed; reopen its folder",
                        ));
                    }
                    Ok(reader)
                })??;
                self.register_handle(OpenFile::Read(ReadHandle::Recovery(reader)))
            }
            _ => Err(CloudError::new(
                ErrorKind::Unsupported,
                "saved folder cannot be opened as a file",
            )),
        }
    }
}

#[cfg(test)]
#[path = "pin_recovery_tests.rs"]
mod tests;

//! Per-file unresolved observations. Counters are telemetry, never completion authority.
use crate::LocalFileIdentity;
use std::collections::BTreeMap;
const MAX_DIRTY_FILES: usize = 1024;
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Observation {
    pub identity: [u8; 16],
    pub file: LocalFileIdentity,
    pub length: u64,
    pub sha256: [u8; 32],
    pub components: Vec<String>,
    sequence: u64,
}
#[derive(Default)]
pub(crate) struct VaultDirtyFiles {
    files: BTreeMap<[u8; 16], Observation>,
    sequence: u64,
    unknown: bool,
}
impl VaultDirtyFiles {
    pub fn record(
        &mut self,
        identity: [u8; 16],
        file: LocalFileIdentity,
        length: u64,
        sha256: [u8; 32],
        components: Vec<String>,
    ) -> Result<(), ()> {
        if identity == [0; 16]
            || file.file_index == 0
            || file.volume_serial == 0
            || components.is_empty()
            || (!self.files.contains_key(&identity) && self.files.len() >= MAX_DIRTY_FILES)
        {
            self.unknown = true;
            return Err(());
        }
        self.sequence = self.sequence.checked_add(1).ok_or_else(|| {
            self.unknown = true;
        })?;
        self.files.insert(
            identity,
            Observation {
                identity,
                file,
                length,
                sha256,
                components,
                sequence: self.sequence,
            },
        );
        Ok(())
    }
    pub fn has_pending(&self) -> bool {
        self.unknown || !self.files.is_empty()
    }
    #[cfg(any(test, feature = "synthetic-agent-integration"))]
    pub fn pending(&self, identity: &[u8; 16]) -> bool {
        self.unknown || self.files.contains_key(identity)
    }
    pub fn snapshot(&self, identity: &[u8; 16]) -> Result<Observation, ()> {
        if self.unknown {
            return Err(());
        }
        self.files.get(identity).cloned().ok_or(())
    }
    pub fn resolve(&mut self, observation: &Observation) -> Result<(), ()> {
        if self.unknown || self.files.get(&observation.identity) != Some(observation) {
            return Err(());
        }
        self.files.remove(&observation.identity);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn record(t: &mut VaultDirtyFiles, id: u8, hash: u8) {
        t.record(
            [id; 16],
            LocalFileIdentity {
                volume_serial: 7,
                file_index: id as u64,
            },
            11,
            [hash; 32],
            vec![format!("file{id}")],
        )
        .unwrap();
    }
    #[test]
    fn exact_observation_only_resolves_one_file_and_never_late_history() {
        let mut t = VaultDirtyFiles::default();
        record(&mut t, 1, 1);
        record(&mut t, 2, 2);
        let first = t.snapshot(&[1; 16]).unwrap();
        record(&mut t, 1, 1);
        assert!(t.resolve(&first).is_err());
        assert!(t.pending(&[1; 16]));
        let current = t.snapshot(&[1; 16]).unwrap();
        t.resolve(&current).unwrap();
        assert!(!t.pending(&[1; 16]));
        assert!(t.pending(&[2; 16]));
        assert!(t.has_pending());
        t.resolve(&t.snapshot(&[2; 16]).unwrap()).unwrap();
        assert!(!t.has_pending());
    }
    #[test]
    fn unknown_or_exhausted_history_never_becomes_clean() {
        let mut t = VaultDirtyFiles::default();
        record(&mut t, 1, 1);
        let prior = t.snapshot(&[1; 16]).unwrap();
        assert!(t.record([0; 16], prior.file, 0, [0; 32], vec![]).is_err());
        assert!(t.resolve(&prior).is_err());
        assert!(t.has_pending());
        let mut t = VaultDirtyFiles {
            sequence: u64::MAX,
            ..Default::default()
        };
        assert!(
            t.record([1; 16], prior.file, 0, [0; 32], vec!["file".into()])
                .is_err()
        );
        assert!(t.has_pending());
    }
}

//! Fresh authenticated stage provenance, never native completion or history authority.
use crate::{BackendError, MAX_RANGE_BYTES, MAX_VAULT_EDIT_CAPTURE_BYTES};
use sha2::{Digest, Sha256};
use std::io::Read;
use zeroize::Zeroizing;

pub(crate) fn bounded_stage_sha(
    reader: &mut impl Read,
    expected: u64,
) -> Result<[u8; 32], BackendError> {
    if expected > MAX_VAULT_EDIT_CAPTURE_BYTES as u64 {
        return Err(BackendError::Unavailable);
    }
    let mut bytes = Zeroizing::new(vec![0u8; MAX_RANGE_BYTES]);
    let mut total = 0u64;
    let mut sha = Sha256::new();
    loop {
        let count = reader
            .read(&mut bytes)
            .map_err(|_| BackendError::Unavailable)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(BackendError::Unavailable)?;
        if total > expected {
            return Err(BackendError::Unavailable);
        }
        sha.update(&bytes[..count]);
    }
    if total != expected {
        return Err(BackendError::Unavailable);
    }
    Ok(sha.finalize().into())
}

pub(crate) fn same_original(
    left: &raiun_core::backend::RemoteEntry,
    right: &raiun_core::backend::RemoteEntry,
) -> bool {
    left.id == right.id
        && left.path == right.path
        && left.etag == right.etag
        && left.size == right.size
        && left.directory == right.directory
        && !left.directory
        && !left.writable
        && !right.writable
    // encrypted/modified_unix are presentation fields; protected restoration
    // legitimately differs there. Originals are retained without normalization.
}

pub(crate) fn ranges_cover_file(ranges: impl IntoIterator<Item = (i64, i64)>, length: u64) -> bool {
    if length == 0 || length > MAX_VAULT_EDIT_CAPTURE_BYTES as u64 {
        return false;
    }
    let mut end = 0u64;
    for (offset, count) in ranges {
        if offset < 0 || count <= 0 || offset as u64 != end {
            return false;
        }
        let Some(next) = end.checked_add(count as u64) else {
            return false;
        };
        end = next;
    }
    // Coverage beyond logical EOF does not cause a read beyond that independently
    // verified length. Missing, malformed or noncontiguous cached bytes refuse.
    end >= length
}

#[cfg(windows)]
mod live {
    use super::*;
    use crate::{
        ConfiguredRootIdentity, FreshVaultCaptureDispatch, LocalFileIdentity,
        vault_custody::VaultHydrationIntent, vault_read::WindowsVaultReadBinding,
    };
    use raiun_core::backend::RemoteEntry;
    use std::sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };
    pub(crate) struct HydrationContext {
        pub root: ConfiguredRootIdentity,
        pub identity: [u8; 16],
        pub file: LocalFileIdentity,
        pub components: Vec<String>,
        pub length: u64,
        pub sha256: [u8; 32],
        pub original: RemoteEntry,
    }
    pub(crate) struct HydrationAcknowledgement {
        pub context: HydrationContext,
        pub dispatch: FreshVaultCaptureDispatch,
    }
    /// Opaque, one-use process-local provenance. No public constructor, Clone,
    /// Debug, serialization, private path, plaintext or session/key ownership.
    pub struct FreshVaultHydration {
        binding: Weak<WindowsVaultReadBinding>,
        revision: u64,
        active: Arc<AtomicBool>,
        generation: Arc<AtomicU64>,
        expected: u64,
        context: HydrationContext,
    }
    impl FreshVaultHydration {
        pub(crate) fn from_prepared(
            binding: &Arc<WindowsVaultReadBinding>,
            revision: u64,
            gate: (Arc<AtomicBool>, Arc<AtomicU64>, u64),
            original: RemoteEntry,
            sha256: [u8; 32],
            intent: &VaultHydrationIntent,
        ) -> Result<Self, BackendError> {
            if intent.root.volume_serial == 0
                || intent.root.file_index == 0
                || intent.file_index == 0
                || intent.identity == [0; 16]
                || intent.components.is_empty()
                || intent.components.len() > 256
                || intent
                    .components
                    .iter()
                    .any(|part| !crate::opencloud::valid_windows_component(part))
                || original.directory
                || original.size != intent.length
                || intent.length > MAX_VAULT_EDIT_CAPTURE_BYTES as u64
            {
                return Err(BackendError::Unavailable);
            }
            let capsule = Self {
                binding: Arc::downgrade(binding),
                revision,
                active: gate.0,
                generation: gate.1,
                expected: gate.2,
                context: HydrationContext {
                    root: intent.root,
                    identity: intent.identity,
                    file: LocalFileIdentity {
                        volume_serial: intent.root.volume_serial,
                        file_index: intent.file_index,
                    },
                    components: intent.components.clone(),
                    length: intent.length,
                    sha256,
                    original,
                },
            };
            capsule.current_binding()?;
            Ok(capsule)
        }
        fn current_binding(&self) -> Result<Arc<WindowsVaultReadBinding>, BackendError> {
            let binding = self.binding.upgrade().ok_or(BackendError::Unavailable)?;
            // Pure posthook: native already retains the actual token/opaque-epoch
            // publication permits. Never reacquire registry/auth or perform I/O.
            if self.expected == 0
                || !self.active.load(Ordering::Acquire)
                || self.generation.load(Ordering::Acquire) != self.expected
                || binding.is_revoked()
                || binding.publication_revision() != self.revision
            {
                return Err(BackendError::Unavailable);
            }
            Ok(binding)
        }
        pub(crate) fn check_current(&self) -> Result<(), BackendError> {
            self.current_binding().map(|_| ())
        }
        pub(crate) fn context(&self) -> &HydrationContext {
            &self.context
        }
        pub(crate) fn is_new_binding(
            &self,
            old: &FreshVaultCaptureDispatch,
        ) -> Result<bool, BackendError> {
            Ok(!self.current_binding()?.matches_cleanup_dispatch(old))
        }
        pub(crate) fn acknowledge(self) -> Result<HydrationAcknowledgement, BackendError> {
            let dispatch = self.current_binding()?.capture_dispatch_stamp();
            Ok(HydrationAcknowledgement {
                context: self.context,
                dispatch,
            })
        }
    }
}
#[cfg(windows)]
pub use live::FreshVaultHydration;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_stage_hash_requires_exact_bounded_body() {
        let bytes = vec![19u8; MAX_VAULT_EDIT_CAPTURE_BYTES];
        assert_eq!(
            bounded_stage_sha(&mut bytes.as_slice(), bytes.len() as u64).unwrap(),
            <[u8; 32]>::from(Sha256::digest(&bytes))
        );
        assert!(bounded_stage_sha(&mut bytes.as_slice(), bytes.len() as u64 - 1).is_err());
        assert!(
            bounded_stage_sha(&mut bytes[..bytes.len() - 1].as_ref(), bytes.len() as u64).is_err()
        );
        assert!(
            bounded_stage_sha(&mut [].as_slice(), MAX_VAULT_EDIT_CAPTURE_BYTES as u64 + 1).is_err()
        );
    }
    #[test]
    fn current_native_coverage_refuses_holes_and_empty_or_malformed_cache() {
        assert!(ranges_cover_file([(0, 65536), (65536, 4096)], 65537));
        assert!(!ranges_cover_file([], 65537));
        assert!(!ranges_cover_file([(0, 4096), (8192, 4096)], 12288));
        assert!(!ranges_cover_file([(0, 4096)], 65537));
        assert!(!ranges_cover_file([(0, -1)], 4));
        assert!(!ranges_cover_file(
            [(0, 1)],
            MAX_VAULT_EDIT_CAPTURE_BYTES as u64 + 1
        ));
    }
    #[test]
    fn rollover_keeps_original_version_and_rejects_logical_rebinding() {
        use raiun_core::backend::RemoteEntry;
        let original = RemoteEntry {
            id: "file".into(),
            path: "/file".into(),
            directory: false,
            size: 4,
            etag: "\"v1\"".into(),
            modified_unix: 1,
            writable: false,
            encrypted: false,
        };
        let mut restored = original.clone();
        restored.encrypted = true;
        restored.modified_unix = 0;
        assert!(same_original(&original, &restored));
        let mut foreign = restored.clone();
        foreign.id = "foreign".into();
        assert!(!same_original(&original, &foreign));
        foreign = restored.clone();
        foreign.path = "/other".into();
        assert!(!same_original(&original, &foreign));
        foreign = restored.clone();
        foreign.etag = "\"v2\"".into();
        assert!(!same_original(&original, &foreign));
        foreign = restored.clone();
        foreign.size = 5;
        assert!(!same_original(&original, &foreign));
        foreign = restored.clone();
        foreign.directory = true;
        assert!(!same_original(&original, &foreign));
        foreign = restored;
        foreign.writable = true;
        assert!(!same_original(&original, &foreign));
    }
    #[test]
    fn failed_stage_read_is_never_a_fingerprint() {
        struct Refused;
        impl Read for Refused {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("synthetic read refusal"))
            }
        }
        assert!(bounded_stage_sha(&mut Refused, 4).is_err());
    }
}

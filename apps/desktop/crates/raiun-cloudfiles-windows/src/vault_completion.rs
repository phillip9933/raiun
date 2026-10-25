//! Fresh live upload capabilities and borrowed native-only completion proofs.
//! Structural locators and historical receipts never mint completion authority.
use crate::{
    BackendError, CancellationToken, ConfiguredRootIdentity, ExistingVaultUploadTarget,
    LocalFileIdentity, OpenCloudPlaceholderBackend,
};
use raiun_core::backend::{ErrorKind, RemoteEntry};
use raiun_opencloud::vault_backend::VaultVerifiedOverwrite;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use zeroize::Zeroizing;

pub struct VaultUploadControl {
    generation: Arc<AtomicU64>,
    expected: u64,
    cancellation: CancellationToken,
    deadline: Instant,
}
impl VaultUploadControl {
    pub fn new(
        generation: Arc<AtomicU64>,
        expected: u64,
        cancellation: CancellationToken,
        deadline: Instant,
    ) -> Result<Self, BackendError> {
        let control = Self {
            generation,
            expected,
            cancellation,
            deadline,
        };
        if control.is_cancelled() {
            return Err(BackendError::Unavailable);
        }
        Ok(control)
    }
    pub(crate) fn is_cancelled(&self) -> bool {
        self.expected == 0
            || self.generation.load(Ordering::Acquire) != self.expected
            || self.cancellation.is_cancelled()
            || self.cancellation.is_expired()
            || Instant::now() >= self.deadline
    }
    pub(crate) fn generation(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.generation)
    }
    pub(crate) fn expected(&self) -> u64 {
        self.expected
    }
}

pub enum VaultLiveUploadOutcome {
    Verified(FreshVaultUpload),
    NeedsReconciliation { reason: ErrorKind },
}
/// Owned Send continuation of one successful live HTTP operation. No public
/// constructor, Clone, deserialization or historical reconstruction exists.
pub struct FreshVaultUpload {
    pub(crate) composite: Arc<OpenCloudPlaceholderBackend>,
    pub(crate) route: Arc<crate::vault_routes::VerifiedVaultRoute>,
    pub(crate) target: Box<ExistingVaultUploadTarget>,
    pub(crate) verified: Box<VaultVerifiedOverwrite>,
    pub(crate) control: VaultUploadControl,
}
impl FreshVaultUpload {
    pub fn remote_evidence(&self) -> &VaultVerifiedOverwrite {
        &self.verified
    }
    pub fn root(&self) -> ConfiguredRootIdentity {
        self.target.root()
    }
    pub fn identity(&self) -> [u8; 16] {
        *self.target.identity()
    }
    pub(crate) fn check_current(&self) -> Result<(), crate::Error> {
        if self.control.is_cancelled()
            || self.composite.is_revoked()
            || self.route.backend().binding().is_revoked()
        {
            return Err(crate::Error::EditRecoveryUnavailable);
        }
        Ok(())
    }
}

/// Broker-authenticated descriptor locator only, never current native authority.
/// The callback independently compares these bytes to its exact protected scope,
/// capture frame and hydration row before either durable transition.
#[derive(Clone)]
pub struct VaultLocalCompletionTarget {
    scope_binding: Zeroizing<Vec<u8>>,
    capture_id: String,
    frame_sha256: [u8; 32],
    frame_len: u64,
    local_file: LocalFileIdentity,
    components: Vec<String>,
}
impl VaultLocalCompletionTarget {
    pub fn new(
        scope_binding: Zeroizing<Vec<u8>>,
        capture_id: String,
        frame_sha256: [u8; 32],
        frame_len: u64,
        local_file: LocalFileIdentity,
        components: Vec<String>,
    ) -> Result<Self, BackendError> {
        if scope_binding.is_empty()
            || scope_binding.len() > 128 * 1024
            || capture_id.is_empty()
            || capture_id.len() > 128
            || !capture_id.bytes().all(|b| b.is_ascii_graphic())
            || frame_len == 0
            || frame_len > 1024 * 1024
            || local_file.volume_serial == 0
            || local_file.file_index == 0
            || components.is_empty()
            || components.len() > 256
            || components.iter().map(String::len).sum::<usize>() > 32000
            || components
                .iter()
                .any(|s| !crate::opencloud::valid_windows_component(s))
        {
            return Err(BackendError::Unavailable);
        }
        Ok(Self {
            scope_binding,
            capture_id,
            frame_sha256,
            frame_len,
            local_file,
            components,
        })
    }
    pub fn scope_binding(&self) -> &[u8] {
        &self.scope_binding
    }
    pub fn capture_id(&self) -> &str {
        &self.capture_id
    }
    pub fn frame_sha256(&self) -> [u8; 32] {
        self.frame_sha256
    }
    pub fn frame_len(&self) -> u64 {
        self.frame_len
    }
    pub fn local_file(&self) -> LocalFileIdentity {
        self.local_file
    }
    pub fn components(&self) -> &[String] {
        &self.components
    }
}

pub trait VaultLocalCompletionStore: Send {
    fn target(&self) -> &VaultLocalCompletionTarget;
    fn prepare(&mut self, proof: &VaultNativePreparation<'_>) -> Result<(), BackendError>;
    fn complete(&mut self, proof: &VaultNativeCompletionProof<'_>) -> Result<(), BackendError>;
    #[cfg(feature = "synthetic-agent-integration")]
    fn before_in_sync_for_test(&mut self) -> Result<(), BackendError> {
        Ok(())
    }
    #[cfg(feature = "synthetic-agent-integration")]
    fn before_completion_guard_release_for_test(&mut self) -> Result<(), BackendError> {
        Ok(())
    }
}
/// Minted only by native.rs after the exact exclusive referenced file's complete
/// resident bytes/hash and stable positive USN match this live upload capability.
pub struct VaultNativePreparation<'a> {
    upload: &'a FreshVaultUpload,
    target: &'a VaultLocalCompletionTarget,
}
/// Minted only by native.rs after in-sync and exact native postproof, while the
/// same exclusive file reference and route/token/opaque epoch fences remain held.
pub struct VaultNativeCompletionProof<'a> {
    upload: &'a FreshVaultUpload,
    target: &'a VaultLocalCompletionTarget,
}
macro_rules! proof_accessors {
    ($name:ident) => {
        impl<'a> $name<'a> {
            pub(crate) fn from_native(
                upload: &'a FreshVaultUpload,
                target: &'a VaultLocalCompletionTarget,
            ) -> Self {
                Self { upload, target }
            }
            pub fn scope_binding(&self) -> &[u8] {
                self.target.scope_binding()
            }
            pub fn capture_id(&self) -> &str {
                self.target.capture_id()
            }
            pub fn frame_sha256(&self) -> [u8; 32] {
                self.target.frame_sha256()
            }
            pub fn frame_len(&self) -> u64 {
                self.target.frame_len()
            }
            pub fn root(&self) -> ConfiguredRootIdentity {
                self.upload.root()
            }
            pub fn identity(&self) -> [u8; 16] {
                self.upload.identity()
            }
            pub fn local_file(&self) -> LocalFileIdentity {
                self.target.local_file()
            }
            pub fn components(&self) -> &[String] {
                self.target.components()
            }
            pub fn original(&self) -> &RemoteEntry {
                self.upload.target.original()
            }
            pub fn verified(&self) -> &RemoteEntry {
                self.upload.verified.entry()
            }
            pub fn body_len(&self) -> u64 {
                self.upload.verified.entry().size
            }
            pub fn body_sha256(&self) -> [u8; 32] {
                self.upload.verified.plaintext_sha256()
            }
        }
    };
}
proof_accessors!(VaultNativePreparation);
proof_accessors!(VaultNativeCompletionProof);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fresh_continuation_is_send_and_owned_deadline_cannot_extend_token() {
        fn assert_send<T: Send>() {}
        assert_send::<FreshVaultUpload>();
        let generation = Arc::new(AtomicU64::new(7));
        assert!(
            VaultUploadControl::new(
                Arc::clone(&generation),
                7,
                CancellationToken::for_offline_job(),
                Instant::now()
            )
            .is_err()
        );
        let cancel = CancellationToken::for_offline_job();
        let control = VaultUploadControl::new(
            Arc::clone(&generation),
            7,
            cancel.clone(),
            Instant::now() + std::time::Duration::from_secs(300),
        )
        .unwrap();
        assert!(!control.is_cancelled());
        generation.store(8, Ordering::Release);
        assert!(control.is_cancelled());
        generation.store(7, Ordering::Release);
        cancel.cancel();
        assert!(control.is_cancelled());
    }
}

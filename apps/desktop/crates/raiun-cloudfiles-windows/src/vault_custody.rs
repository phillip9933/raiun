//! Immutable, scope-bound durable publication interface. These records are
//! evidence only; they never confer native file, route, or unlock authority.
use crate::{BackendError, ConfiguredRootIdentity, LocalFileIdentity, ProviderScope};
use raiun_core::backend::RemoteEntry;
use raiun_vault::session::VaultSessionScope;
use zeroize::Zeroizing;

/// Decrypted root-relative metadata. Deliberately no Debug implementation.
#[derive(Clone)]
pub struct VaultCatalogueEntry {
    pub identity: [u8; 16],
    pub metadata: RemoteEntry,
}

/// Trusted broker input for one already-live vault route. Construction validates
/// structure only: the broker must first authenticate the full protected account/
/// custody/index/frame and retain its real configured-root pin and attempt lease.
/// Original resource/path/ETag/length are immutable; no historical labels grant
/// current session authority. Deliberately no Debug/Clone/deserialization.
pub struct ExistingVaultUploadTarget {
    current_owner: ProviderScope,
    vault: VaultSessionScope,
    remote_root: String,
    configured_root: ConfiguredRootIdentity,
    opaque: [u8; 16],
    original: RemoteEntry,
    fresh_dispatch: Option<crate::FreshVaultCaptureDispatch>,
}
impl ExistingVaultUploadTarget {
    pub fn new(
        current_owner: ProviderScope,
        vault: VaultSessionScope,
        remote_root: String,
        configured_root: ConfiguredRootIdentity,
        opaque: [u8; 16],
        original: RemoteEntry,
    ) -> Result<Self, BackendError> {
        let etag = original.etag.as_bytes();
        if opaque == [0; 16]
            || original.directory
            || original.id.trim().is_empty()
            || original.id.len() > 4096
            || original.id.chars().any(char::is_control)
            || original.path == "/"
            || raiun_core::validate_remote_path(&original.path).is_err()
            || etag.len() < 2
            || etag.len() > 4096
            || etag.first() != Some(&b'"')
            || etag.last() != Some(&b'"')
            || !etag[1..etag.len() - 1]
                .iter()
                .all(|b| *b == 0x21 || (0x23..=0x7e).contains(b))
            || remote_root.len() > 4096
            || raiun_core::validate_remote_path(&remote_root).is_err()
            || (remote_root != "/" && remote_root.ends_with('/'))
            || current_owner.profile_id() != vault.account_id()
            || current_owner.server_origin() != vault.server_origin()
            || current_owner.token_generation() == 0
            || configured_root.volume_serial == 0
            || configured_root.file_index == 0
        {
            return Err(BackendError::Unavailable);
        }
        Ok(Self {
            current_owner,
            vault,
            remote_root,
            configured_root,
            opaque,
            original,
            fresh_dispatch: None,
        })
    }
    /// Attach the producer's opaque route-instance stamp. This locator grants
    /// no authority: a current live binding must validate it before any upload.
    pub fn with_fresh_dispatch(mut self, dispatch: crate::FreshVaultCaptureDispatch) -> Self {
        self.fresh_dispatch = Some(dispatch);
        self
    }
    pub(crate) fn dispatch(&self) -> Option<&crate::FreshVaultCaptureDispatch> {
        self.fresh_dispatch.as_ref()
    }
    pub(crate) fn owner(&self) -> &ProviderScope {
        &self.current_owner
    }
    pub(crate) fn vault(&self) -> &VaultSessionScope {
        &self.vault
    }
    pub(crate) fn remote_root(&self) -> &str {
        &self.remote_root
    }
    pub(crate) fn root(&self) -> ConfiguredRootIdentity {
        self.configured_root
    }
    pub(crate) fn identity(&self) -> &[u8; 16] {
        &self.opaque
    }
    pub(crate) fn original(&self) -> &RemoteEntry {
        &self.original
    }
    pub(crate) fn matches_original(&self, other: &RemoteEntry) -> bool {
        !other.directory
            && self.original.id == other.id
            && self.original.path == other.path
            && self.original.etag == other.etag
            && self.original.size == other.size
        // encrypted/writable are presentation flags, never custody authority.
    }
}

pub(crate) struct VaultUploadCancellation<'a> {
    pub generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub expected: u64,
    pub cancelled: &'a dyn Fn() -> bool,
}
impl VaultUploadCancellation<'_> {
    pub fn is_cancelled(&self) -> bool {
        self.expected == 0
            || self.generation.load(std::sync::atomic::Ordering::Acquire) != self.expected
            || (self.cancelled)()
    }
}

/// Native caller must independently pin the exact root/file/opaque identity
/// and validate these components before invoking the durable publication hook.
/// Physical components are discovered at fetch, not guessed from remote names.
pub struct VaultHydrationIntent {
    pub root: ConfiguredRootIdentity,
    pub identity: [u8; 16],
    pub file_index: u64,
    pub length: u64,
    pub components: Vec<String>,
}

/// Immutable original existing-file baseline, constructed by the verified read
/// binding inside its publication fence. Numeric generations are labels only;
/// the caller's opaque epoch/token leases provide the actual live authority.
/// Deliberately no Debug, Clone or deserialization implementation.
pub struct ExistingVaultEditBaseline {
    identity: [u8; 16],
    metadata: RemoteEntry,
    owner: ProviderScope,
    vault: VaultSessionScope,
    remote_root: String,
    root: ConfiguredRootIdentity,
    unlock_epoch: u64,
}
impl ExistingVaultEditBaseline {
    pub(crate) fn new(
        identity: [u8; 16],
        metadata: RemoteEntry,
        owner: ProviderScope,
        vault: VaultSessionScope,
        remote_root: String,
        root: ConfiguredRootIdentity,
        unlock_epoch: u64,
    ) -> Result<Self, BackendError> {
        let etag = metadata.etag.as_bytes();
        if identity == [0; 16]
            || metadata.directory
            || metadata.id.is_empty()
            || metadata.path == "/"
            || raiun_core::validate_remote_path(&metadata.path).is_err()
            || etag.len() < 2
            || etag.len() > 4096
            || etag.first() != Some(&b'"')
            || etag.last() != Some(&b'"')
            || !etag[1..etag.len() - 1]
                .iter()
                .all(|b| *b == 0x21 || (0x23..=0x7e).contains(b))
            || owner.profile_id() != vault.account_id()
            || owner.server_origin() != vault.server_origin()
            || owner.token_generation() == 0
            || unlock_epoch == 0
            || root.volume_serial == 0
            || root.file_index == 0
        {
            return Err(BackendError::Unavailable);
        }
        Ok(Self {
            identity,
            metadata,
            owner,
            vault,
            remote_root,
            root,
            unlock_epoch,
        })
    }
    pub fn identity(&self) -> [u8; 16] {
        self.identity
    }
    pub fn metadata(&self) -> &RemoteEntry {
        &self.metadata
    }
    pub fn owner(&self) -> &ProviderScope {
        &self.owner
    }
    pub fn vault(&self) -> &VaultSessionScope {
        &self.vault
    }
    pub fn remote_root(&self) -> &str {
        &self.remote_root
    }
    pub fn root(&self) -> ConfiguredRootIdentity {
        self.root
    }
    pub fn unlock_epoch(&self) -> u64 {
        self.unlock_epoch
    }
    pub fn token_generation(&self) -> u64 {
        self.owner.token_generation()
    }
}
/// Native-owned bytes and proofs from its already pinned no-follow handles.
/// The broker must independently match its protected catalogue/hydration rows.
/// Dropping the payload zeroizes bytes, including every refused retain path.
pub struct ExistingVaultEditPayload {
    pub root: ConfiguredRootIdentity,
    pub file: LocalFileIdentity,
    pub components: Vec<String>,
    pub bytes: Zeroizing<Vec<u8>>,
}

/// The trusted broker supplies a full-account/vault/root-bound implementation.
/// Store calls must never reenter the backend, token/session coordinator, or
/// route publication locks: the caller already holds its publication permit.
/// Ok means durable protected write-through/readback, never permission to read
/// or clear native incomplete history. Failure denies the pending publication.
pub trait VaultPublicationCustody: Send + Sync {
    fn root_identity(&self) -> ConfiguredRootIdentity;
    /// Local protected index-first retention only. The exact live lexical
    /// fences are already held: do not acquire account/route/token/session locks
    /// or perform network work. Default refusal keeps old fixtures fail closed.
    /// Ok is historical retention, never dirty-bit/dehydration/cleanup authority.
    fn retain_existing_edit(
        &self,
        _baseline: &ExistingVaultEditBaseline,
        _payload: ExistingVaultEditPayload,
        _dispatch: crate::FreshVaultCaptureDispatch,
    ) -> Result<Option<Box<dyn crate::DeferredVaultCaptureNotification>>, BackendError> {
        Err(BackendError::Unavailable)
    }

    fn verify_context(
        &self,
        owner: &ProviderScope,
        vault: &VaultSessionScope,
        remote_root: &str,
    ) -> Result<(), BackendError>;
    /// Authenticated metadata evidence only. The adapter still requires a fresh
    /// verified vault/session and revalidates remote objects before each read.
    fn catalogue_snapshot(&self) -> Result<Vec<VaultCatalogueEntry>, BackendError>;
    /// One atomic catalogue batch must precede publishing any of its names/IDs.
    fn persist_catalogue(&self, entries: &[VaultCatalogueEntry]) -> Result<(), BackendError>;
    /// Retain this intent even if the subsequent native transfer fails/crashes.
    fn persist_hydration(&self, intent: &VaultHydrationIntent) -> Result<(), BackendError>;
}

/// Trusted broker source of authenticated, append-only provider publication
/// history, initialized only from a proven new empty root. This is evidence,
/// not a native cleanup permit. Called AFTER exclusive native connection and
/// BEFORE Ready, so an old provider cannot publish unrecorded bytes meanwhile.
/// Reopen every manifest child; no adoption, healing, row removal or rollback
/// protection is implied. Arbitrary same-user copies/restored old documents
/// are outside this provider-publication lineage.
pub trait VaultPublishedHistorySource: Send + Sync {
    fn snapshot(
        &self,
        owner: &ProviderScope,
        root: ConfiguredRootIdentity,
        registration: &str,
    ) -> Result<Vec<VaultHydrationIntent>, BackendError>;
}

#[cfg(test)]
mod upload_target_tests {
    use super::*;
    fn target() -> ExistingVaultUploadTarget {
        let client = raiun_opencloud::OpenCloudClient::new(
            "https://synthetic.invalid",
            "synthetic-token".into(),
        )
        .unwrap();
        let owner = ProviderScope::new(
            &client,
            "profile".into(),
            "subject".into(),
            "https://synthetic.invalid".into(),
        )
        .unwrap();
        ExistingVaultUploadTarget::new(
            owner,
            VaultSessionScope::new("profile", "https://synthetic.invalid", "space", "vault")
                .unwrap(),
            "/Travel.vault".into(),
            ConfiguredRootIdentity {
                volume_serial: 7,
                file_index: 9,
            },
            [3; 16],
            RemoteEntry {
                id: "existing".into(),
                path: "/original.bin".into(),
                etag: "\"original\"".into(),
                size: 123,
                directory: false,
                encrypted: false,
                writable: false,
                modified_unix: 0,
            },
        )
        .unwrap()
    }
    #[test]
    fn original_version_is_never_rebased_and_presentation_flags_are_not_authority() {
        let target = target();
        let mut other = target.original().clone();
        other.encrypted = true;
        other.writable = true;
        assert!(target.matches_original(&other));
        for field in ["id", "path", "etag", "size", "directory"] {
            let mut other = target.original().clone();
            match field {
                "id" => other.id = "replacement".into(),
                "path" => other.path = "/replacement.bin".into(),
                "etag" => other.etag = "\"replacement\"".into(),
                "size" => other.size += 1,
                "directory" => other.directory = true,
                _ => unreachable!(),
            }
            assert!(!target.matches_original(&other));
        }
    }
    #[test]
    fn foreign_or_malformed_target_context_cannot_construct_upload_target() {
        let t = target();
        for field in ["vault", "root", "opaque", "etag"] {
            let vault = if field == "vault" {
                VaultSessionScope::new(
                    "foreign-profile",
                    "https://synthetic.invalid",
                    "space",
                    "vault",
                )
                .unwrap()
            } else {
                t.vault().clone()
            };
            let root = if field == "root" {
                ConfiguredRootIdentity {
                    volume_serial: 0,
                    file_index: 9,
                }
            } else {
                t.root()
            };
            let opaque = if field == "opaque" {
                [0; 16]
            } else {
                *t.identity()
            };
            let mut original = t.original().clone();
            if field == "etag" {
                original.etag = "W/\"original\"".into();
            }
            assert!(
                ExistingVaultUploadTarget::new(
                    t.owner().clone(),
                    vault,
                    t.remote_root().into(),
                    root,
                    opaque,
                    original
                )
                .is_err()
            );
        }
    }
}

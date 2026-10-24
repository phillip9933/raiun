//! Immutable, scope-bound durable publication interface. These records are
//! evidence only; they never confer native file, route, or unlock authority.
use crate::{BackendError, ConfiguredRootIdentity, ProviderScope};
use raiun_core::backend::RemoteEntry;
use raiun_vault::session::VaultSessionScope;

/// Decrypted root-relative metadata. Deliberately no Debug implementation.
#[derive(Clone)]
pub struct VaultCatalogueEntry {
    pub identity: [u8; 16],
    pub metadata: RemoteEntry,
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

/// The trusted broker supplies a full-account/vault/root-bound implementation.
/// Store calls must never reenter the backend, token/session coordinator, or
/// route publication locks: the caller already holds its publication permit.
/// Ok means durable protected write-through/readback, never permission to read
/// or clear native incomplete history. Failure denies the pending publication.
pub trait VaultPublicationCustody: Send + Sync {
    fn root_identity(&self) -> ConfiguredRootIdentity;
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

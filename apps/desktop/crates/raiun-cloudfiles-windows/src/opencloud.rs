//! Portable OpenCloud implementation of the Cloud Files callback data seam.
//!
//! This module is not connected to Cloud Files registration or Explorer. A
//! trusted agent constructs it for one already-authenticated OpenCloud client
//! and one exact profile/account/origin. Callers register validated ordinary
//! files to obtain opaque identities; callback identities are never treated
//! as paths or URLs.

mod initial_save;
mod verified_edit;
pub use initial_save::InitialEditSession;
pub use verified_edit::VerifiedEditPublication;

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use raiun_core::backend::{CloudBackend, ErrorKind};
use raiun_opencloud::{
    MAX_CALLBACK_RANGE_BYTES, OpenCloudClient, RangeReadContext, RemoteRangeRequest,
    TokenGenerationLease,
};

use crate::{
    BackendError, CancellationToken, DEFAULT_FETCH_TIMEOUT, FetchRange, MAX_DIRECTORY_CHILDREN,
    MAX_RANGE_BYTES, MAX_REQUEST_BYTES, PlaceholderBackend, PlaceholderChild,
    PlaceholderEditBinding, PlaceholderMetadata, PreparedEditBinding, PreparedEnumeration,
    PreparedFetch, PreparedFetchSession, PublishPermit,
};

#[cfg(test)]
mod cache_binding_tests;
mod content_cache;
#[cfg(windows)]
mod offline_download;
#[cfg(windows)]
pub use offline_download::OfflineDownloadError;
#[cfg(windows)]
mod offline_folders;
#[cfg(windows)]
pub use offline_folders::FolderCacheBindingExpectation;
mod listed_files;
#[cfg(windows)]
mod listed_folders;
#[cfg(windows)]
pub use listed_folders::{ListedFolderPage, ListedFolderRow};
mod listing_cache;
pub use listed_files::{ListedFilePage, ListedFileRow};

const MAX_PROVIDER_SPACES: usize = 128;
const MAX_IDENTITY_CATALOG_ENTRIES: usize = 100_000;
static NEXT_BACKEND_ID: AtomicU64 = AtomicU64::new(1);

/// Authentication and namespace binding supplied by the trusted agent, not
/// by a Cloud Files callback or UI request.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderScope {
    profile_id: String,
    account_id: String,
    server_origin: String,
    token_generation: u64,
}

impl ProviderScope {
    pub fn new(
        client: &OpenCloudClient,
        profile_id: String,
        account_id: String,
        server_origin: String,
    ) -> Result<Self, BackendError> {
        let token_generation = client.token_generation();
        if !valid_scope_part(&profile_id)
            || !valid_scope_part(&account_id)
            || !valid_scope_part(&server_origin)
            || token_generation == 0
            || client.server_origin().as_deref() != Some(server_origin.as_str())
        {
            return Err(BackendError::Unavailable);
        }
        Ok(Self {
            profile_id,
            account_id,
            server_origin,
            token_generation,
        })
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn server_origin(&self) -> &str {
        &self.server_origin
    }

    /// Monotonic generation captured from the authenticated OpenCloud client.
    pub fn token_generation(&self) -> u64 {
        self.token_generation
    }
}

impl std::fmt::Debug for ProviderScope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderScope")
            .field("profile_id", &"[BOUND]")
            .field("account_id", &"[BOUND]")
            .field("server_origin", &"[BOUND]")
            .field("token_generation", &self.token_generation)
            .finish()
    }
}

/// Opaque identity generated for a single validated ordinary remote file.
/// Its bytes contain no path, server URL, account ID, or bearer credential.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct OpaqueIdentity([u8; 16]);

impl OpaqueIdentity {
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Immutable catalog key for descendant identities. Token generation is
/// deliberately excluded so identities survive refresh and process restart;
/// callers must still revalidate every binding against the current token.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderIdentityCatalogScope {
    pub profile_id: String,
    pub account_id: String,
    pub server_origin: String,
    pub root_volume_serial: u32,
    pub root_file_index: u64,
    pub personal_space_id: String,
    pub personal_root_resource_id: String,
}

impl ProviderIdentityCatalogScope {
    pub fn new(
        provider: &ProviderScope,
        local_root: crate::ConfiguredRootIdentity,
        personal_space_id: &str,
        personal_root_resource_id: &str,
    ) -> Result<Self, BackendError> {
        if !valid_scope_part(&provider.profile_id)
            || !valid_scope_part(&provider.account_id)
            || !valid_scope_part(&provider.server_origin)
            || local_root.file_index == 0
            || !valid_remote_id(personal_space_id)
            || !valid_remote_id(personal_root_resource_id)
        {
            return Err(BackendError::Unavailable);
        }
        Ok(Self {
            profile_id: provider.profile_id.clone(),
            account_id: provider.account_id.clone(),
            server_origin: provider.server_origin.clone(),
            root_volume_serial: local_root.volume_serial,
            root_file_index: local_root.file_index,
            personal_space_id: personal_space_id.to_owned(),
            personal_root_resource_id: personal_root_resource_id.to_owned(),
        })
    }

    pub fn local_root(&self) -> crate::ConfiguredRootIdentity {
        crate::ConfiguredRootIdentity {
            volume_serial: self.root_volume_serial,
            file_index: self.root_file_index,
        }
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    pub fn server_origin(&self) -> &str {
        &self.server_origin
    }
    pub fn personal_space_id(&self) -> &str {
        &self.personal_space_id
    }
    pub fn personal_root_resource_id(&self) -> &str {
        &self.personal_root_resource_id
    }
}

impl std::fmt::Debug for ProviderIdentityCatalogScope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderIdentityCatalogScope")
            .field("profile_id", &"[BOUND]")
            .field("account_id", &"[BOUND]")
            .field("server_origin", &"[BOUND]")
            .field("local_root", &self.local_root())
            .field("personal_space_id", &"[BOUND]")
            .field("personal_root_resource_id", &"[BOUND]")
            .finish()
    }
}

/// Protected metadata needed to resolve a Cloud Files identity after process
/// restart. Paths are stored only inside the current-user protected catalog;
/// every use still revalidates the exact Space/root/resource with the server.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderIdentityBinding {
    Directory {
        identity: [u8; 16],
        space_id: String,
        root_resource_id: String,
        path: String,
        remote_id: String,
    },
    File {
        identity: [u8; 16],
        space_id: String,
        root_resource_id: String,
        path: String,
        remote_id: String,
        etag: String,
        size: u64,
    },
    SpacesNamespace {
        identity: [u8; 16],
        personal_space_id: String,
        personal_root_resource_id: String,
    },
}

impl ProviderIdentityBinding {
    pub fn identity(&self) -> OpaqueIdentity {
        match self {
            Self::Directory { identity, .. }
            | Self::File { identity, .. }
            | Self::SpacesNamespace { identity, .. } => OpaqueIdentity(*identity),
        }
    }
}

impl std::fmt::Debug for ProviderIdentityBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Directory { .. } => "Directory",
            Self::File { .. } => "File",
            Self::SpacesNamespace { .. } => "SpacesNamespace",
        };
        formatter
            .debug_struct("ProviderIdentityBinding")
            .field("kind", &kind)
            .field("identity", &"[BOUND]")
            .field("scope", &"[BOUND]")
            .field("path", &"[BOUND]")
            .finish()
    }
}

/// Durable implementation must authenticate the complete immutable scope
/// and fail closed on corruption, unknown files, or scope mismatch. `upsert`
/// is an atomic merge for one binding; it must reject an identity whose stable
/// object tuple differs. File ETag/size may be refreshed after fresh server
/// validation without changing that stable tuple.
pub trait ProviderIdentityCatalog: Send + Sync {
    fn load(
        &self,
        scope: &ProviderIdentityCatalogScope,
    ) -> Result<Vec<ProviderIdentityBinding>, BackendError>;
    fn upsert(
        &self,
        scope: &ProviderIdentityCatalogScope,
        binding: &ProviderIdentityBinding,
    ) -> Result<(), BackendError>;
    fn remove(
        &self,
        scope: &ProviderIdentityCatalogScope,
        identity: OpaqueIdentity,
    ) -> Result<(), BackendError>;
}

impl std::fmt::Debug for OpaqueIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OpaqueIdentity([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
struct FileBinding {
    space_id: String,
    root_resource_id: String,
    path: String,
    remote_id: String,
    etag: String,
    size: u64,
}

#[derive(Clone, PartialEq, Eq)]
struct DirectoryBinding {
    space_id: String,
    root_resource_id: String,
    path: String,
    remote_id: String,
}

#[derive(Clone)]
enum NamespaceDirectory {
    Root {
        account_id: String,
        personal_space_id: String,
        personal_root_id: String,
    },
    Spaces {
        account_id: String,
        personal_space_id: String,
        personal_root_id: String,
    },
}

struct State {
    next_identity: u64,
    files: HashMap<OpaqueIdentity, FileBinding>,
    directories: HashMap<OpaqueIdentity, DirectoryBinding>,
    namespace_directories: HashMap<OpaqueIdentity, NamespaceDirectory>,
    // Display-only names from a validated namespace enumeration. Restoring
    // identity bindings does not restore authority to display a stale name.
    location_labels: HashMap<(String, String), String>,
}

struct OpenCloudPublishPermit<'a> {
    _publication: MutexGuard<'a, ()>,
    _token: TokenGenerationLease<'a>,
}

struct OpenCloudPreparedEnumeration<'a> {
    backend: &'a OpenCloudPlaceholderBackend,
    // Retained from before the first server lookup through native publication.
    _lease: RwLockReadGuard<'a, ()>,
    children: Vec<PlaceholderChild>,
}

struct OpenCloudPreparedEdit<'a> {
    // Prevents account/root revocation or replacement while the native close
    // callback writes the encrypted local recovery snapshot.
    _lease: RwLockReadGuard<'a, ()>,
    binding: PlaceholderEditBinding,
}

impl PreparedEditBinding for OpenCloudPreparedEdit<'_> {
    fn binding(&self) -> &PlaceholderEditBinding {
        &self.binding
    }
}

impl PreparedEnumeration for OpenCloudPreparedEnumeration<'_> {
    fn children(&self) -> &[PlaceholderChild] {
        &self.children
    }

    fn begin_publish<'a>(
        &'a self,
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn PublishPermit + 'a>, BackendError> {
        self.backend.begin_scoped_publish(cancellation)
    }
}

struct OpenCloudPreparedFetch<'a> {
    backend: &'a OpenCloudPlaceholderBackend,
    // Retained until the native callback has published every staged slice.
    _lease: Option<RwLockReadGuard<'a, ()>>,
    metadata: PlaceholderMetadata,
    bytes: Vec<u8>,
}

impl PreparedFetch for OpenCloudPreparedFetch<'_> {
    fn metadata(&self) -> PlaceholderMetadata {
        self.metadata
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn begin_publish<'a>(
        &'a self,
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn PublishPermit + 'a>, BackendError> {
        self.backend.begin_scoped_publish(cancellation)
    }
}

struct OpenCloudFetchSession<'a> {
    backend: &'a OpenCloudPlaceholderBackend,
    _lease: RwLockReadGuard<'a, ()>,
    binding: FileBinding,
}

impl PreparedFetchSession for OpenCloudFetchSession<'_> {
    fn metadata(&self) -> PlaceholderMetadata {
        PlaceholderMetadata {
            is_directory: false,
            length: self.binding.size,
        }
    }

    fn prepare_window<'a>(
        &'a self,
        range: FetchRange,
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn PreparedFetch + 'a>, BackendError> {
        // The returned window borrows this session, which owns the root lease.
        self.backend
            .prepare_bound_fetch(&self.binding, range, cancellation, None)
    }
}

/// Last-observed cache metadata, not a promise of future offline reads.
/// Policy and content fields are independently observed: concurrent eviction or
/// policy changes can occur between them. This is not an atomic cache snapshot.
/// It contains neither cached file bytes nor local cache paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileCacheStatus {
    /// Saved unfinished intent for this exact current path/version; not resumable stage bytes.
    pub pending_offline_intent: bool,
    pub policy: raiun_cache::AvailabilityPolicy,
    pub recorded_complete_version: bool,
    pub recorded_bytes: u64,
}

/// Exact last-observed listed file metadata supplied by the trusted owner.
/// This carries no account, origin, local directory, or opaque callback identity;
/// those authorities remain inside the authenticated backend/catalog scope.
pub struct FileCacheBindingExpectation<'a> {
    pub space_id: &'a str,
    pub root_resource_id: &'a str,
    pub path: &'a str,
    pub resource_id: &'a str,
    pub etag: &'a str,
    pub size: u64,
}

/// Range backend pinned to one authenticated OpenCloud session identity.
///
/// Creating this value does not report a mounted drive and does not register
/// a Cloud Files root. It is a safe transport adapter for synthetic tests and
/// future integration work. The agent must provide the scope from its current
/// authenticated profile; callers must not construct it from callback data.
pub struct OpenCloudPlaceholderBackend {
    backend_id: u64,
    client: Arc<OpenCloudClient>,
    cache: Option<raiun_cache::Cache>,
    scope: ProviderScope,
    local_root_identity: Option<crate::ConfiguredRootIdentity>,
    identity_catalog: Option<Arc<dyn ProviderIdentityCatalog>>,
    catalog_scope: Mutex<Option<ProviderIdentityCatalogScope>>,
    #[cfg(windows)]
    vault_routes: Option<Arc<crate::vault_routes::VaultRouteRegistry>>,
    token_generation: u64,
    revoked: AtomicBool,
    lease_gate: RwLock<()>,
    publish_gate: Mutex<()>,
    state: Mutex<State>,
}

impl OpenCloudPlaceholderBackend {
    pub fn new(client: Arc<OpenCloudClient>, scope: ProviderScope) -> Result<Self, BackendError> {
        Self::new_inner(client, scope, None, None)
    }

    /// Trusted account-bound adapter with optional complete-version storage.
    pub fn new_with_cache(
        client: Arc<OpenCloudClient>,
        scope: ProviderScope,
        cache: raiun_cache::Cache,
    ) -> Result<Self, BackendError> {
        let mut backend = Self::new(client, scope)?;
        backend.cache = Some(cache);
        Ok(backend)
    }

    pub fn new_with_identity_catalog(
        client: Arc<OpenCloudClient>,
        scope: ProviderScope,
        local_root_identity: crate::ConfiguredRootIdentity,
        identity_catalog: Arc<dyn ProviderIdentityCatalog>,
    ) -> Result<Self, BackendError> {
        if local_root_identity.file_index == 0 {
            return Err(BackendError::Unavailable);
        }
        Self::new_inner(
            client,
            scope,
            Some(local_root_identity),
            Some(identity_catalog),
        )
    }

    /// Bind optional persistent content storage only after the trusted agent
    /// has verified the account and configured root. Callback identities never
    /// select an account, origin or cache directory.
    pub fn new_with_identity_catalog_and_cache(
        client: Arc<OpenCloudClient>,
        scope: ProviderScope,
        local_root_identity: crate::ConfiguredRootIdentity,
        identity_catalog: Arc<dyn ProviderIdentityCatalog>,
        cache: raiun_cache::Cache,
    ) -> Result<Self, BackendError> {
        let mut backend =
            Self::new_with_identity_catalog(client, scope, local_root_identity, identity_catalog)?;
        backend.cache = Some(cache);
        Ok(backend)
    }

    fn new_inner(
        client: Arc<OpenCloudClient>,
        scope: ProviderScope,
        local_root_identity: Option<crate::ConfiguredRootIdentity>,
        identity_catalog: Option<Arc<dyn ProviderIdentityCatalog>>,
    ) -> Result<Self, BackendError> {
        let client_origin = client.server_origin().ok_or(BackendError::Unavailable)?;
        if client_origin != scope.server_origin
            || client.token_generation() != scope.token_generation
        {
            return Err(BackendError::Unavailable);
        }
        let token_generation = client.token_generation();
        Ok(Self {
            backend_id: NEXT_BACKEND_ID.fetch_add(1, Ordering::Relaxed),
            client,
            cache: None,
            #[cfg(windows)]
            vault_routes: local_root_identity.map(|root| {
                Arc::new(crate::vault_routes::VaultRouteRegistry::new(
                    scope.clone(),
                    root,
                ))
            }),
            scope,
            local_root_identity,
            identity_catalog,
            catalog_scope: Mutex::new(None),
            token_generation,
            revoked: AtomicBool::new(false),
            lease_gate: RwLock::new(()),
            publish_gate: Mutex::new(()),
            state: Mutex::new(State {
                next_identity: 1,
                files: HashMap::new(),
                directories: HashMap::new(),
                namespace_directories: HashMap::new(),
                location_labels: HashMap::new(),
            }),
        })
    }

    /// Create the stable opaque root for the Personal/Spaces namespace.
    /// The trusted account ID must be the agent's canonical identity derived
    /// from this configured server and the freshly discovered Personal Space
    /// ID. No Cloud Files root is registered by this adapter.
    pub fn register_composite_root(&self) -> Result<OpaqueIdentity, BackendError> {
        self.register_composite_root_exact(None, None)
    }

    /// Resolve the composite root only if it still matches the persisted
    /// Personal Space and DAV root IDs supplied by the trusted agent. The
    /// resulting identity is deterministic for this exact provider scope and
    /// root, so it can be used as Cloud Files' persisted sync-root FileIdentity
    /// and resolved after process restart without accepting callback paths.
    pub fn register_composite_root_for(
        &self,
        expected_personal_space_id: &str,
        expected_personal_root_id: &str,
    ) -> Result<OpaqueIdentity, BackendError> {
        if !valid_remote_id(expected_personal_space_id)
            || !valid_remote_id(expected_personal_root_id)
        {
            return Err(BackendError::Unavailable);
        }
        self.register_composite_root_exact(
            Some(expected_personal_space_id),
            Some(expected_personal_root_id),
        )
    }

    fn register_composite_root_exact(
        &self,
        expected_personal_space_id: Option<&str>,
        expected_personal_root_id: Option<&str>,
    ) -> Result<OpaqueIdentity, BackendError> {
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        self.ensure_active()?;
        let deadline = std::time::Instant::now() + DEFAULT_FETCH_TIMEOUT;
        let spaces = self.discover_spaces(deadline)?;
        let personal = verified_personal(&spaces)?;
        if expected_personal_space_id.is_some_and(|expected| expected != personal.id) {
            return Err(BackendError::Unavailable);
        }
        let root = self
            .client
            .stat_discovered_space_root_with_context(
                personal,
                RangeReadContext {
                    deadline,
                    token_generation: self.token_generation,
                },
            )
            .map_err(|error| self.reject_cached_cloud_error(error))?;
        if !root.directory || root.encrypted || !valid_remote_id(&root.id) {
            return Err(BackendError::Unavailable);
        }
        let root_after = self
            .client
            .stat_discovered_space_root_with_context(
                personal,
                RangeReadContext {
                    deadline,
                    token_generation: self.token_generation,
                },
            )
            .map_err(|error| self.reject_cached_cloud_error(error))?;
        if !root_after.directory
            || root_after.encrypted
            || root_after.id != root.id
            || expected_personal_root_id.is_some_and(|expected| expected != root.id)
        {
            return Err(BackendError::Unavailable);
        }
        let account_id = derive_account_id(&self.client.configured_server_url(), &personal.id);
        if account_id != self.scope.account_id {
            return Err(BackendError::Unavailable);
        }
        let catalog_scope = self.load_catalog_for_root(&personal.id, &root.id)?;
        let mut state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
        self.client
            .with_token_generation(self.token_generation, || {
                if self.revoked.load(Ordering::Acquire) {
                    return Err(BackendError::Unavailable);
                }
                let identity = composite_root_identity(&self.scope, &personal.id, &root.id);
                if let Some(NamespaceDirectory::Root {
                    account_id: existing_account,
                    personal_space_id: existing_space,
                    personal_root_id: existing_root,
                }) = state.namespace_directories.get(&identity)
                {
                    return if existing_account == self.scope.account_id()
                        && existing_space == &personal.id
                        && existing_root == &root.id
                    {
                        Ok(identity)
                    } else {
                        Err(BackendError::Unavailable)
                    };
                }
                if identity_in_use(&state, identity) {
                    return Err(BackendError::Unavailable);
                }
                if let Some(catalog_scope) = catalog_scope.as_ref() {
                    let personal_identity = binding_identity(
                        catalog_scope,
                        "directory",
                        &[&personal.id, &root.id, "/", &root.id],
                    );
                    let personal_binding = ProviderIdentityBinding::Directory {
                        identity: *personal_identity.as_bytes(),
                        space_id: personal.id.clone(),
                        root_resource_id: root.id.clone(),
                        path: "/".to_owned(),
                        remote_id: root.id.clone(),
                    };
                    self.upsert_identity_binding(catalog_scope, &personal_binding)?;
                    state.directories.insert(
                        personal_identity,
                        DirectoryBinding {
                            space_id: personal.id.clone(),
                            root_resource_id: root.id.clone(),
                            path: "/".to_owned(),
                            remote_id: root.id.clone(),
                        },
                    );
                }
                state.namespace_directories.insert(
                    identity,
                    NamespaceDirectory::Root {
                        account_id,
                        personal_space_id: personal.id.clone(),
                        personal_root_id: root.id,
                    },
                );
                Ok(identity)
            })
            .map_err(|error| self.reject_cached_cloud_error(error))?
    }

    fn discover_spaces(
        &self,
        deadline: std::time::Instant,
    ) -> Result<Vec<raiun_core::backend::CloudSpace>, BackendError> {
        let spaces = self
            .client
            .spaces_with_context_limited(
                RangeReadContext {
                    deadline,
                    token_generation: self.token_generation,
                },
                MAX_PROVIDER_SPACES,
            )
            .map_err(|error| self.reject_cached_cloud_error(error))?;
        if spaces.iter().any(|space| {
            space.id.is_empty() || space.id.len() > 512 || space.id.chars().any(char::is_control)
        }) {
            return Err(BackendError::Unavailable);
        }
        verified_personal(&spaces)?;
        Ok(spaces)
    }

    fn load_catalog_for_root(
        &self,
        personal_space_id: &str,
        personal_root_resource_id: &str,
    ) -> Result<Option<ProviderIdentityCatalogScope>, BackendError> {
        let (Some(local_root), Some(catalog)) =
            (self.local_root_identity, self.identity_catalog.as_ref())
        else {
            return Ok(None);
        };
        let catalog_scope = ProviderIdentityCatalogScope::new(
            &self.scope,
            local_root,
            personal_space_id,
            personal_root_resource_id,
        )?;
        let mut scope_slot = self
            .catalog_scope
            .lock()
            .map_err(|_| BackendError::Unavailable)?;
        if let Some(existing) = scope_slot.as_ref() {
            return if existing == &catalog_scope {
                Ok(Some(catalog_scope))
            } else {
                Err(BackendError::Unavailable)
            };
        }

        let bindings = catalog.load(&catalog_scope)?;
        if bindings.len() > MAX_IDENTITY_CATALOG_ENTRIES {
            return Err(BackendError::Unavailable);
        }
        let mut loaded = State {
            next_identity: 1,
            files: HashMap::new(),
            directories: HashMap::new(),
            namespace_directories: HashMap::new(),
            location_labels: HashMap::new(),
        };
        for binding in bindings {
            let identity = validate_catalog_binding(&catalog_scope, &binding)?;
            #[cfg(windows)]
            match &binding {
                ProviderIdentityBinding::Directory { space_id, path, .. }
                | ProviderIdentityBinding::File { space_id, path, .. } => {
                    if self
                        .vault_routes
                        .as_ref()
                        .is_some_and(|routes| routes.covers_path(space_id, path).unwrap_or(true))
                    {
                        // Keep durable evidence unchanged, but never restore an
                        // ordinary identity for a historically encrypted path.
                        continue;
                    }
                }
                ProviderIdentityBinding::SpacesNamespace { .. } => {}
            }
            if identity_in_use(&loaded, identity) {
                return Err(BackendError::Unavailable);
            }
            match binding {
                ProviderIdentityBinding::Directory {
                    space_id,
                    root_resource_id,
                    path,
                    remote_id,
                    ..
                } => {
                    loaded.directories.insert(
                        identity,
                        DirectoryBinding {
                            space_id,
                            root_resource_id,
                            path,
                            remote_id,
                        },
                    );
                }
                ProviderIdentityBinding::File {
                    space_id,
                    root_resource_id,
                    path,
                    remote_id,
                    etag,
                    size,
                    ..
                } => {
                    loaded.files.insert(
                        identity,
                        FileBinding {
                            space_id,
                            root_resource_id,
                            path,
                            remote_id,
                            etag,
                            size,
                        },
                    );
                }
                ProviderIdentityBinding::SpacesNamespace { .. } => {
                    loaded.namespace_directories.insert(
                        identity,
                        NamespaceDirectory::Spaces {
                            account_id: self.scope.account_id.clone(),
                            personal_space_id: personal_space_id.to_owned(),
                            personal_root_id: personal_root_resource_id.to_owned(),
                        },
                    );
                }
            }
        }
        let mut state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
        if binding_count(&state) != 0 {
            return Err(BackendError::Unavailable);
        }
        state.files = loaded.files;
        state.directories = loaded.directories;
        state.namespace_directories = loaded.namespace_directories;
        *scope_slot = Some(catalog_scope.clone());
        Ok(Some(catalog_scope))
    }

    fn upsert_identity_binding(
        &self,
        scope: &ProviderIdentityCatalogScope,
        binding: &ProviderIdentityBinding,
    ) -> Result<(), BackendError> {
        let catalog = self
            .identity_catalog
            .as_ref()
            .ok_or(BackendError::Unavailable)?;
        if validate_catalog_binding(scope, binding)? != binding.identity() {
            return Err(BackendError::Unavailable);
        }
        catalog.upsert(scope, binding)
    }

    fn catalog_scope_snapshot(&self) -> Result<Option<ProviderIdentityCatalogScope>, BackendError> {
        if self.identity_catalog.is_none() {
            return Ok(None);
        }
        self.catalog_scope
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .clone()
            .map(Some)
            .ok_or(BackendError::Unavailable)
    }

    fn remove_identity_binding(&self, identity: OpaqueIdentity) -> Result<(), BackendError> {
        let Some(catalog) = self.identity_catalog.as_ref() else {
            return Ok(());
        };
        let scope = self
            .catalog_scope
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .clone()
            .ok_or(BackendError::Unavailable)?;
        catalog.remove(&scope, identity)
    }

    /// Bind one ordinary directory as a Cloud Files population identity.
    /// The selected Space root and directory resource are revalidated before
    /// the binding is published; encrypted locations are rejected.
    pub fn register_directory(
        &self,
        space_id: &str,
        expected_root_resource_id: &str,
        logical_path: &str,
    ) -> Result<OpaqueIdentity, BackendError> {
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        self.ensure_active()?;
        if !valid_remote_path(space_id, expected_root_resource_id, logical_path, true) {
            return Err(BackendError::NotFound);
        }
        let context = RangeReadContext {
            deadline: std::time::Instant::now() + DEFAULT_FETCH_TIMEOUT,
            token_generation: self.token_generation,
        };
        let root = self
            .client
            .stat_with_context(space_id, "/", context)
            .map_err(|error| self.reject_cached_cloud_error(error))?;
        if !root.directory || root.encrypted || root.id != expected_root_resource_id {
            return Err(BackendError::Unavailable);
        }
        let entry = self
            .client
            .stat_with_context(space_id, logical_path, context)
            .map_err(|error| self.reject_cached_cloud_error(error))?;
        if !entry.directory || entry.encrypted || !valid_remote_id(&entry.id) {
            return Err(BackendError::Unavailable);
        }
        let root_after = self
            .client
            .stat_with_context(space_id, "/", context)
            .map_err(|error| self.reject_cached_cloud_error(error))?;
        if !root_after.directory
            || root_after.encrypted
            || root_after.id != expected_root_resource_id
        {
            return Err(BackendError::Unavailable);
        }
        let directory_after = self
            .client
            .stat_with_context(space_id, logical_path, context)
            .map_err(|error| self.reject_cached_cloud_error(error))?;
        if !directory_after.directory || directory_after.encrypted || directory_after.id != entry.id
        {
            return Err(BackendError::Unavailable);
        }
        let catalog_scope = self.catalog_scope_snapshot()?;
        let mut state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
        self.client
            .with_token_generation(self.token_generation, || {
                if self.revoked.load(Ordering::Acquire)
                    || binding_count(&state) >= MAX_IDENTITY_CATALOG_ENTRIES
                {
                    return Err(BackendError::Unavailable);
                }
                let binding = catalog_scope.as_ref().map(|catalog_scope| {
                    let identity = binding_identity(
                        catalog_scope,
                        "directory",
                        &[space_id, &root.id, logical_path, &entry.id],
                    );
                    ProviderIdentityBinding::Directory {
                        identity: *identity.as_bytes(),
                        space_id: space_id.to_owned(),
                        root_resource_id: root.id.clone(),
                        path: logical_path.to_owned(),
                        remote_id: entry.id.clone(),
                    }
                });
                let identity = if let Some(binding) = binding.as_ref() {
                    let identity = binding.identity();
                    self.upsert_identity_binding(catalog_scope.as_ref().unwrap(), binding)?;
                    identity
                } else {
                    next_identity(self.backend_id, &mut state)?
                };
                state.directories.insert(
                    identity,
                    DirectoryBinding {
                        space_id: space_id.to_owned(),
                        root_resource_id: root.id,
                        path: logical_path.to_owned(),
                        remote_id: entry.id,
                    },
                );
                Ok(identity)
            })
            .map_err(|error| self.reject_cached_cloud_error(error))?
    }

    /// Bind a trusted logical Space/path to a generated callback identity.
    /// The remote object is freshly statted and must be an ordinary file.
    /// Paths are retained only inside this exact backend instance.
    pub fn register_file(
        &self,
        space_id: &str,
        expected_root_resource_id: &str,
        logical_path: &str,
    ) -> Result<OpaqueIdentity, BackendError> {
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        self.ensure_active()?;
        if space_id.is_empty()
            || space_id.len() > 512
            || space_id.chars().any(char::is_control)
            || expected_root_resource_id.is_empty()
            || expected_root_resource_id.len() > 256 * 1024
            || expected_root_resource_id.chars().any(char::is_control)
            || logical_path.len() > 16 * 1024
            || !logical_path.starts_with('/')
            || logical_path.ends_with('/')
            || logical_path.contains("//")
            || logical_path.contains('\\')
            || logical_path.chars().any(char::is_control)
            || logical_path
                .split('/')
                .any(|component| matches!(component, "." | ".."))
        {
            return Err(BackendError::NotFound);
        }
        let context = RangeReadContext {
            deadline: std::time::Instant::now() + DEFAULT_FETCH_TIMEOUT,
            token_generation: self.token_generation,
        };
        let root = self
            .client
            .stat_with_context(space_id, "/", context)
            .map_err(|error| self.reject_cached_cloud_error(error))?;
        if !root.directory || root.encrypted || root.id != expected_root_resource_id {
            return Err(BackendError::Unavailable);
        }
        let entry = self
            .client
            .stat_with_context(space_id, logical_path, context)
            .map_err(|error| self.reject_cached_cloud_error(error))?;
        if entry.encrypted
            || entry.directory
            || !valid_remote_id(&entry.id)
            || entry.etag.is_empty()
        {
            return Err(BackendError::Unavailable);
        }
        let root_after_file = self
            .client
            .stat_with_context(space_id, "/", context)
            .map_err(|error| self.reject_cached_cloud_error(error))?;
        if !root_after_file.directory
            || root_after_file.encrypted
            || root_after_file.id != expected_root_resource_id
        {
            return Err(BackendError::Unavailable);
        }
        let catalog_scope = self.catalog_scope_snapshot()?;
        let mut state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
        self.client
            .with_token_generation(self.token_generation, || {
                if self.revoked.load(Ordering::Acquire)
                    || binding_count(&state) >= MAX_IDENTITY_CATALOG_ENTRIES
                {
                    return Err(BackendError::Unavailable);
                }
                let binding = catalog_scope.as_ref().map(|catalog_scope| {
                    let identity = binding_identity(
                        catalog_scope,
                        "file",
                        &[space_id, &root.id, logical_path, &entry.id],
                    );
                    ProviderIdentityBinding::File {
                        identity: *identity.as_bytes(),
                        space_id: space_id.to_owned(),
                        root_resource_id: root.id.clone(),
                        path: logical_path.to_owned(),
                        remote_id: entry.id.clone(),
                        etag: entry.etag.clone(),
                        size: entry.size,
                    }
                });
                let identity = if let Some(binding) = binding.as_ref() {
                    let identity = binding.identity();
                    self.upsert_identity_binding(catalog_scope.as_ref().unwrap(), binding)?;
                    identity
                } else {
                    next_identity(self.backend_id, &mut state)?
                };
                state.files.insert(
                    identity,
                    FileBinding {
                        space_id: space_id.to_owned(),
                        root_resource_id: root.id,
                        path: logical_path.to_owned(),
                        remote_id: entry.id,
                        etag: entry.etag,
                        size: entry.size,
                    },
                );
                Ok(identity)
            })
            .map_err(|error| self.reject_cached_cloud_error(error))?
    }

    /// Retire one identity binding after all callbacks which captured it have
    /// finished publishing. A callback using it afterwards fails closed; no
    /// remote mutation or cache deletion occurs.
    pub fn unregister_file(&self, identity: OpaqueIdentity) -> Result<(), BackendError> {
        // `prepare_fetch` holds a shared lease through callback publication.
        // Taking the exclusive lease first makes this a per-file retirement
        // barrier: it waits for staged reads to finish, prevents another
        // callback from entering while the binding is removed, and ensures
        // no caller can publish bytes for the retired identity after return.
        let _drained = self
            .lease_gate
            .write()
            .map_err(|_| BackendError::Unavailable)?;
        let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
        if !identity_in_use(&state, identity) {
            return Err(BackendError::NotFound);
        }
        drop(state);
        self.remove_identity_binding(identity)?;
        let mut state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
        state.files.remove(&identity);
        state.directories.remove(&identity);
        state.namespace_directories.remove(&identity);
        Ok(())
    }

    /// Snapshot for the trusted agent's vault preparation, never UI authority.
    #[cfg(windows)]
    pub fn vault_read_context(
        &self,
        expected_root: crate::ConfiguredRootIdentity,
    ) -> Result<(Arc<OpenCloudClient>, ProviderScope), BackendError> {
        self.ensure_active()?;
        if self.local_root_identity != Some(expected_root) {
            return Err(BackendError::Unavailable);
        }
        Ok((self.client.clone(), self.scope.clone()))
    }

    #[cfg(windows)]
    pub fn has_vault_root(&self, space: &str, root_id: &str) -> Result<bool, BackendError> {
        self.ensure_active()?;
        match &self.vault_routes {
            Some(routes) => routes.has_root_id(space, root_id),
            None => Err(BackendError::Unavailable),
        }
    }

    pub fn scope(&self) -> &ProviderScope {
        &self.scope
    }

    /// Confirm that this exact backend has a freshly registered composite
    /// root binding for the supplied opaque Cloud Files identity.
    pub fn owns_composite_root_identity(&self, identity: OpaqueIdentity) -> bool {
        self.state.lock().is_ok_and(|state| {
            matches!(
                state.namespace_directories.get(&identity),
                Some(NamespaceDirectory::Root {
                    account_id,
                    personal_space_id,
                    personal_root_id,
                }) if account_id == self.scope.account_id()
                    && composite_root_identity(
                        &self.scope,
                        personal_space_id,
                        personal_root_id,
                    ) == identity
            ) && !self.revoked.load(Ordering::Acquire)
                && self.client.token_generation() == self.token_generation
        })
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn bind_composite_root_for_test(
        &self,
        personal_space_id: &str,
        personal_root_id: &str,
    ) -> OpaqueIdentity {
        let identity = composite_root_identity(&self.scope, personal_space_id, personal_root_id);
        let mut state = self.state.lock().unwrap();
        state.namespace_directories.insert(
            identity,
            NamespaceDirectory::Root {
                account_id: self.scope.account_id().to_owned(),
                personal_space_id: personal_space_id.to_owned(),
                personal_root_id: personal_root_id.to_owned(),
            },
        );
        identity
    }

    /// Seed durable encrypted-location exclusions before loading the ordinary
    /// identity catalogue or registering native callbacks. This grants no unlock.
    #[cfg(windows)]
    pub fn restore_vault_exclusions(
        &self,
        expected_root: crate::ConfiguredRootIdentity,
        locations: &[(String, String)],
    ) -> Result<(), BackendError> {
        let _drained = self
            .lease_gate
            .write()
            .map_err(|_| BackendError::Unavailable)?;
        let _publication = self
            .publish_gate
            .lock()
            .map_err(|_| BackendError::Unavailable)?;
        self.ensure_active()?;
        if self
            .catalog_scope
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .is_some()
        {
            return Err(BackendError::Unavailable);
        }
        self.vault_routes
            .as_ref()
            .ok_or(BackendError::Unavailable)?
            .restore_exclusions(expected_root, locations)
    }

    #[cfg(windows)]
    pub fn retire_vault_route(
        &self,
        space: &str,
        root_id: &str,
        root_path: &str,
    ) -> Result<Option<Arc<crate::vault_routes::VerifiedVaultRoute>>, BackendError> {
        self.ensure_active()?;
        self.vault_routes
            .as_ref()
            .ok_or(BackendError::Unavailable)?
            .retire_one(space, root_id, root_path)
    }

    /// Retain revoked route ownership for native plaintext cleanup on disconnect.
    /// Taking the inventory grants no unlock and blocks further vault admission.
    #[cfg(windows)]
    pub fn retire_vault_routes(
        &self,
    ) -> Result<Vec<Arc<crate::vault_routes::VerifiedVaultRoute>>, BackendError> {
        match &self.vault_routes {
            Some(routes) => routes.retire_all(),
            None => Ok(Vec::new()),
        }
    }

    /// Publish a durable encrypted-location exclusion to this live backend
    /// before fallible unlock-route admission. Retained ordinary leases drain
    /// first, and known paths stay excluded even if active route setup fails.
    #[cfg(windows)]
    pub fn reserve_live_vault_exclusion(
        &self,
        expected_root: crate::ConfiguredRootIdentity,
        space: &str,
        path: &str,
    ) -> Result<(), BackendError> {
        let _drained = self
            .lease_gate
            .write()
            .map_err(|_| BackendError::Unavailable)?;
        let _publication = self
            .publish_gate
            .lock()
            .map_err(|_| BackendError::Unavailable)?;
        self.ensure_active()?;
        self.vault_routes
            .as_ref()
            .ok_or(BackendError::Unavailable)?
            .restore_exclusions(expected_root, &[(space.to_owned(), path.to_owned())])
    }

    /// Request future parent enumeration, never removal of existing children.
    /// The live provider fences and exact native identity remain held together.
    #[cfg(windows)]
    pub fn refresh_vault_parent_population(
        &self,
        connection: &crate::ConfiguredRootConnection,
        expected_root: crate::ConfiguredRootIdentity,
        space_id: &str,
        root_id: &str,
        root_path: &str,
    ) -> Result<(), BackendError> {
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        let route = self
            .vault_routes
            .as_ref()
            .ok_or(BackendError::Unavailable)?
            .exact_root(space_id, root_path, root_id)?
            .ok_or(BackendError::NotFound)?;
        if route.local_root() != expected_root {
            return Err(BackendError::Unavailable);
        }
        let (parent, components) =
            self.vault_parent_population_descriptor(space_id, root_id, root_path)?;
        let cancellation = CancellationToken::new();
        let _publication = self.begin_scoped_publish(&cancellation)?;
        let references = components.iter().map(String::as_str).collect::<Vec<_>>();
        connection
            .inner
            .refresh_namespace_parent_population(expected_root, &references, &parent)
            .map_err(|_| BackendError::Unavailable)
    }

    /// Resolve only a currently verified vault route's immediate namespace
    /// parent. Components are locators; native code must pin and verify the
    /// returned opaque directory identity before requesting population.
    #[cfg(windows)]
    fn vault_parent_population_descriptor(
        &self,
        space_id: &str,
        vault_root_resource_id: &str,
        vault_root_path: &str,
    ) -> Result<(PlaceholderChild, Vec<String>), BackendError> {
        self.ensure_active()?;
        let routes = self
            .vault_routes
            .as_ref()
            .ok_or(BackendError::Unavailable)?;
        let route = routes
            .exact_root(space_id, vault_root_path, vault_root_resource_id)?
            .ok_or(BackendError::NotFound)?;
        let path = route.root_path();
        let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
        self.client
            .with_token_generation(self.token_generation, || {
                if self.revoked.load(Ordering::Acquire) {
                    return Err(BackendError::Unavailable);
                }
                let mut roots =
                    state
                        .namespace_directories
                        .values()
                        .filter_map(|entry| match entry {
                            NamespaceDirectory::Root {
                                account_id,
                                personal_space_id,
                                personal_root_id,
                            } if account_id == self.scope.account_id() => {
                                Some((personal_space_id, personal_root_id))
                            }
                            _ => None,
                        });
                let (personal_space, personal_root) =
                    roots.next().ok_or(BackendError::Unavailable)?;
                if roots.next().is_some()
                    || state
                        .location_labels
                        .get(&(personal_space.clone(), personal_root.clone()))
                        .map(String::as_str)
                        != Some("Personal")
                {
                    // Restored catalogue entries alone do not prove a current label.
                    return Err(BackendError::Unavailable);
                }
                let (identity, name, components) =
                    if path == "/" {
                        // An entire Personal location is directly beneath the native
                        // sync root, which this child-directory API cannot refresh.
                        if space_id == personal_space {
                            return Err(BackendError::Unavailable);
                        }
                        let mut matches = state.namespace_directories.iter().filter_map(
                            |(id, entry)| match entry {
                                NamespaceDirectory::Spaces {
                                    account_id,
                                    personal_space_id,
                                    personal_root_id,
                                } if account_id == self.scope.account_id()
                                    && personal_space_id == personal_space
                                    && personal_root_id == personal_root =>
                                {
                                    Some(*id)
                                }
                                _ => None,
                            },
                        );
                        let id = matches.next().ok_or(BackendError::Unavailable)?;
                        if matches.next().is_some() {
                            return Err(BackendError::Unavailable);
                        }
                        (id, "Spaces".to_owned(), vec!["Spaces".to_owned()])
                    } else {
                        if direct_child_name("/", path).is_none() {
                            // Nested directory bindings may have been restored without
                            // current local label provenance; refuse rather than guess.
                            return Err(BackendError::Unavailable);
                        }
                        let mut matches = state.directories.iter().filter(|(_, entry)| {
                            entry.space_id == space_id
                                && entry.path == "/"
                                && entry.remote_id == entry.root_resource_id
                        });
                        let (id, directory) = matches.next().ok_or(BackendError::Unavailable)?;
                        if matches.next().is_some() {
                            return Err(BackendError::Unavailable);
                        }
                        let label = state
                            .location_labels
                            .get(&(
                                directory.space_id.clone(),
                                directory.root_resource_id.clone(),
                            ))
                            .ok_or(BackendError::Unavailable)?;
                        let components = if space_id == personal_space
                            && directory.root_resource_id == *personal_root
                            && label == "Personal"
                        {
                            vec!["Personal".to_owned()]
                        } else {
                            let name = label
                                .strip_prefix("Spaces / ")
                                .ok_or(BackendError::Unavailable)?;
                            if !valid_windows_component(name) {
                                return Err(BackendError::Unavailable);
                            }
                            vec!["Spaces".to_owned(), name.to_owned()]
                        };
                        let name = components
                            .last()
                            .cloned()
                            .ok_or(BackendError::Unavailable)?;
                        (*id, name, components)
                    };
                if components.iter().any(|part| !valid_windows_component(part)) {
                    return Err(BackendError::Unavailable);
                }
                Ok((
                    PlaceholderChild {
                        name,
                        identity: identity.as_bytes().to_vec(),
                        metadata: PlaceholderMetadata {
                            is_directory: true,
                            length: 0,
                        },
                        last_write_time: 0,
                    },
                    components,
                ))
            })
            .map_err(|error| self.reject_cached_cloud_error(error))?
    }

    /// Admit a verified vault beneath this exact retained native root. This
    /// does not register a second root or enable an agent vault capability.
    #[cfg(windows)]
    pub fn install_vault_route(
        &self,
        backend: Arc<crate::vault_placeholder::WindowsVaultPlaceholderBackend>,
        expected_root: crate::ConfiguredRootIdentity,
    ) -> Result<Arc<crate::vault_routes::VerifiedVaultRoute>, BackendError> {
        // Drain every pre-admission ordinary session/prepared object (including
        // edit recovery leases) before classifying a location as encrypted.
        let _drained = self
            .lease_gate
            .write()
            .map_err(|_| BackendError::Unavailable)?;
        let _publication = self
            .publish_gate
            .lock()
            .map_err(|_| BackendError::Unavailable)?;
        self.ensure_active()?;
        // No token lock is held here: route admission acquires its own exact
        // token/session publication leases after the ordinary publication gate.
        self.vault_routes
            .as_ref()
            .ok_or(BackendError::Unavailable)?
            .install(backend, expected_root)
    }

    #[cfg(windows)]
    pub fn remove_vault_route(&self, space: &str, root_id: &str) -> Result<bool, BackendError> {
        self.vault_routes
            .as_ref()
            .ok_or(BackendError::Unavailable)?
            .remove(space, root_id)
    }

    #[cfg(windows)]
    fn vault_for_identity(
        &self,
        identity: &[u8],
    ) -> Result<Option<Arc<crate::vault_routes::VerifiedVaultRoute>>, BackendError> {
        self.ensure_active()?;
        let Some(routes) = &self.vault_routes else {
            return Ok(None);
        };
        if let Some(route) = routes.resolve_identity(identity)? {
            return Ok(Some(route));
        }
        // Old ordinary identities must not bypass a newly admitted vault, even
        // when the server omits an encryption marker or the vault was locked.
        let location = {
            let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
            let id: [u8; 16] = match identity.try_into() {
                Ok(id) => id,
                Err(_) => return Ok(None),
            };
            state
                .files
                .get(&OpaqueIdentity(id))
                .map(|entry| (entry.space_id.clone(), entry.path.clone()))
                .or_else(|| {
                    state
                        .directories
                        .get(&OpaqueIdentity(id))
                        .map(|entry| (entry.space_id.clone(), entry.path.clone()))
                })
        };
        if let Some((space, path)) = location {
            if routes.covers_path(&space, &path)? {
                return Err(BackendError::Unavailable);
            }
        }
        Ok(None)
    }

    #[cfg(windows)]
    fn vault_root(
        &self,
        space: &str,
        entry: &raiun_core::backend::RemoteEntry,
    ) -> Result<Option<Arc<crate::vault_routes::VerifiedVaultRoute>>, BackendError> {
        if !entry.directory {
            return Ok(None);
        }
        self.ensure_active()?;
        match &self.vault_routes {
            Some(routes) => routes.exact_root(space, &entry.path, &entry.id),
            None => Ok(None),
        }
    }

    fn ensure_ordinary_location(&self, space: &str, path: &str) -> Result<(), BackendError> {
        #[cfg(windows)]
        if let Some(routes) = &self.vault_routes {
            if routes.covers_path(space, path)? {
                return Err(BackendError::Unavailable);
            }
        }
        #[cfg(not(windows))]
        let _ = (space, path);
        Ok(())
    }

    fn known_vault_root(&self, space: &str, path: &str) -> Result<bool, BackendError> {
        #[cfg(windows)]
        {
            match &self.vault_routes {
                Some(routes) => routes.is_known_root(space, path),
                None => Ok(false),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = (space, path);
            Ok(false)
        }
    }

    fn has_vault_space_root(&self, space: &str) -> Result<bool, BackendError> {
        #[cfg(windows)]
        {
            match &self.vault_routes {
                Some(routes) => routes.has_space_root(space),
                None => Ok(false),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = space;
            Ok(false)
        }
    }

    fn vault_root_identity(
        &self,
        space: &str,
        entry: &raiun_core::backend::RemoteEntry,
    ) -> Result<Option<Vec<u8>>, BackendError> {
        #[cfg(windows)]
        {
            Ok(self
                .vault_root(space, entry)?
                .map(|route| route.backend().root_identity().to_vec()))
        }
        #[cfg(not(windows))]
        {
            let _ = (space, entry);
            Ok(None)
        }
    }

    fn accepted_encrypted_root(
        &self,
        space: &str,
        entry: &raiun_core::backend::RemoteEntry,
    ) -> Result<bool, BackendError> {
        #[cfg(windows)]
        {
            Ok(self.vault_root(space, entry)?.is_some())
        }
        #[cfg(not(windows))]
        {
            let _ = (space, entry);
            Ok(false)
        }
    }

    fn vault_parent_uncached(&self, space: &str, path: &str) -> Result<bool, BackendError> {
        #[cfg(windows)]
        {
            match &self.vault_routes {
                Some(routes) => routes.has_direct_child(space, path),
                None => Ok(false),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = (space, path);
            Ok(false)
        }
    }

    /// Whether this backend has been revoked and must not accept new work.
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    /// Revoke all identities before the authenticated client token or account
    /// state is mutated. In-flight reads observe revocation and discard staged
    /// bytes before returning them to Cloud Files.
    pub fn revoke(&self) {
        {
            let _publication = self
                .publish_gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.revoked.store(true, Ordering::Release);
        }
        #[cfg(windows)]
        if let Some(routes) = &self.vault_routes {
            // Every later vault permit fails before auth owner changes keys.
            let _ = routes.revoke_all();
        }
        // Wait for current bounded reads to finish or observe revocation. This
        // makes return from revoke a barrier before the auth owner mutates the
        // shared token or publishes a replacement account session.
        let _drained = self
            .lease_gate
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }

    fn enumerate_scoped(
        &self,
        identity: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<Vec<PlaceholderChild>, BackendError> {
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled);
        }
        if cancellation.is_expired() {
            return Err(BackendError::Unavailable);
        }
        self.ensure_active()?;
        let identity: [u8; 16] = identity.try_into().map_err(|_| BackendError::NotFound)?;
        let namespace = {
            self.state
                .lock()
                .map_err(|_| BackendError::Unavailable)?
                .namespace_directories
                .get(&OpaqueIdentity(identity))
                .cloned()
        };
        if let Some(namespace) = namespace {
            return self.enumerate_namespace_scoped(namespace, cancellation);
        }
        let directory = self
            .state
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .directories
            .get(&OpaqueIdentity(identity))
            .cloned()
            .ok_or(BackendError::NotFound)?;
        let entries = self.cached_directory_entries(&directory, cancellation)?;
        self.admit_directory_entries(&directory, entries, cancellation)
    }

    fn admit_directory_entries(
        &self,
        directory: &DirectoryBinding,
        entries: Vec<(String, raiun_core::backend::RemoteEntry)>,
        cancellation: &CancellationToken,
    ) -> Result<Vec<PlaceholderChild>, BackendError> {
        check_cancel(cancellation)?;
        // Callers retain the ordinary read lease through catalogue admission.
        self.ensure_ordinary_location(&directory.space_id, &directory.path)?;
        #[cfg(windows)]
        let vault_children = {
            let mut children = HashMap::new();
            for (_, entry) in &entries {
                if entry.directory {
                    if let Some(route) = self.vault_root(&directory.space_id, entry)? {
                        children.insert(
                            (entry.path.clone(), entry.id.clone()),
                            route.backend().root_identity(),
                        );
                        continue;
                    }
                }
                if entry.encrypted
                    || self.vault_routes.as_ref().is_some_and(|routes| {
                        routes
                            .is_known_root(&directory.space_id, &entry.path)
                            .unwrap_or(true)
                    })
                {
                    return Err(BackendError::Unavailable);
                }
            }
            children
        };
        let catalog_scope = self.catalog_scope_snapshot()?;
        let mut state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
        self.client
            .with_token_generation(self.token_generation, || {
                if self.revoked.load(Ordering::Acquire) {
                    return Err(BackendError::Unavailable);
                }
                let mut children = Vec::with_capacity(entries.len());
                for (name, entry) in entries {
                    check_cancel(cancellation)?;
                    #[cfg(windows)]
                    if let Some(identity) =
                        vault_children.get(&(entry.path.clone(), entry.id.clone()))
                    {
                        children.push(PlaceholderChild {
                            name,
                            identity: identity.to_vec(),
                            metadata: PlaceholderMetadata {
                                is_directory: true,
                                length: 0,
                            },
                            last_write_time: 0,
                        });
                        continue; // never persist a vault route in the ordinary catalogue
                    }
                    let durable_binding = catalog_scope.as_ref().map(|scope| {
                        if entry.directory {
                            let identity = binding_identity(
                                scope,
                                "directory",
                                &[
                                    &directory.space_id,
                                    &directory.root_resource_id,
                                    &entry.path,
                                    &entry.id,
                                ],
                            );
                            ProviderIdentityBinding::Directory {
                                identity: *identity.as_bytes(),
                                space_id: directory.space_id.clone(),
                                root_resource_id: directory.root_resource_id.clone(),
                                path: entry.path.clone(),
                                remote_id: entry.id.clone(),
                            }
                        } else {
                            let identity = binding_identity(
                                scope,
                                "file",
                                &[
                                    &directory.space_id,
                                    &directory.root_resource_id,
                                    &entry.path,
                                    &entry.id,
                                ],
                            );
                            ProviderIdentityBinding::File {
                                identity: *identity.as_bytes(),
                                space_id: directory.space_id.clone(),
                                root_resource_id: directory.root_resource_id.clone(),
                                path: entry.path.clone(),
                                remote_id: entry.id.clone(),
                                etag: entry.etag.clone(),
                                size: entry.size,
                            }
                        }
                    });
                    let opaque = if let (Some(scope), Some(binding)) =
                        (catalog_scope.as_ref(), durable_binding.as_ref())
                    {
                        let identity = binding.identity();
                        self.upsert_identity_binding(scope, binding)?;
                        identity
                    } else {
                        let existing = if entry.directory {
                            state
                                .directories
                                .iter()
                                .find(|(_, item)| {
                                    item.space_id == directory.space_id
                                        && item.root_resource_id == directory.root_resource_id
                                        && item.path == entry.path
                                        && item.remote_id == entry.id
                                })
                                .map(|(identity, _)| *identity)
                        } else {
                            state
                                .files
                                .iter()
                                .find(|(_, item)| {
                                    item.space_id == directory.space_id
                                        && item.root_resource_id == directory.root_resource_id
                                        && item.path == entry.path
                                        && item.remote_id == entry.id
                                })
                                .map(|(identity, _)| *identity)
                        };
                        if let Some(existing) = existing {
                            existing
                        } else {
                            if binding_count(&state) >= MAX_IDENTITY_CATALOG_ENTRIES {
                                return Err(BackendError::Unavailable);
                            }
                            next_identity(self.backend_id, &mut state)?
                        }
                    };
                    if entry.directory {
                        state.directories.insert(
                            opaque,
                            DirectoryBinding {
                                space_id: directory.space_id.clone(),
                                root_resource_id: directory.root_resource_id.clone(),
                                path: entry.path.clone(),
                                remote_id: entry.id.clone(),
                            },
                        );
                    } else {
                        state.files.insert(
                            opaque,
                            FileBinding {
                                space_id: directory.space_id.clone(),
                                root_resource_id: directory.root_resource_id.clone(),
                                path: entry.path.clone(),
                                remote_id: entry.id.clone(),
                                etag: entry.etag.clone(),
                                size: entry.size,
                            },
                        );
                    }
                    let last_write_time = unix_to_filetime(entry.modified_unix);
                    children.push(PlaceholderChild {
                        name,
                        identity: opaque.0.to_vec(),
                        metadata: PlaceholderMetadata {
                            is_directory: entry.directory,
                            length: if entry.directory { 0 } else { entry.size },
                        },
                        last_write_time,
                    });
                }
                Ok(children)
            })
            .map_err(|error| self.reject_cached_cloud_error(error))?
    }

    fn enumerate_namespace_scoped(
        &self,
        namespace: NamespaceDirectory,
        cancellation: &CancellationToken,
    ) -> Result<Vec<PlaceholderChild>, BackendError> {
        check_cancel(cancellation)?;
        self.ensure_active()?;
        let deadline = cancellation.deadline();
        let (account_id, personal_space_id, personal_root_id) = match &namespace {
            NamespaceDirectory::Root {
                account_id,
                personal_space_id,
                personal_root_id,
            }
            | NamespaceDirectory::Spaces {
                account_id,
                personal_space_id,
                personal_root_id,
            } => (account_id, personal_space_id, personal_root_id),
        };
        let spaces = self.validate_namespace_scope(
            account_id,
            personal_space_id,
            personal_root_id,
            deadline,
        )?;
        let staged_space_roots = if matches!(&namespace, NamespaceDirectory::Spaces { .. }) {
            let mut names = std::collections::HashSet::new();
            let mut staged = Vec::new();
            for space in spaces.iter().filter(|space| !space.personal) {
                check_cancel(cancellation)?;
                if space.encrypted && !self.has_vault_space_root(&space.id)? {
                    continue;
                }
                let root = self
                    .client
                    .stat_discovered_space_root_with_context(
                        space,
                        RangeReadContext {
                            deadline,
                            token_generation: self.token_generation,
                        },
                    )
                    .map_err(|error| self.reject_cached_cloud_error(error))?;
                let vault_identity = self.vault_root_identity(&space.id, &root)?;
                let known_vault = self.known_vault_root(&space.id, "/")?;
                if known_vault && vault_identity.is_none() {
                    return Err(BackendError::Unavailable);
                }
                if (space.encrypted || root.encrypted) && vault_identity.is_none() {
                    continue;
                }
                if !root.directory || !valid_remote_id(&root.id) {
                    return Err(BackendError::Unavailable);
                }
                let name = checked_space_display_name(&space.name, &space.id, &mut names)?;
                staged.push((space.id.clone(), root.id, name, vault_identity));
                if staged.len() > MAX_DIRECTORY_CHILDREN {
                    return Err(BackendError::Unavailable);
                }
            }
            // Bind the complete set only if the account's Personal root and
            // namespace identity still match after root discovery.
            self.validate_namespace_scope(
                account_id,
                personal_space_id,
                personal_root_id,
                deadline,
            )?;
            for (space_id, root_id, _, vault_identity) in &staged {
                check_cancel(cancellation)?;
                let spaces_by_id = spaces
                    .iter()
                    .find(|space| space.id == *space_id)
                    .ok_or(BackendError::Unavailable)?;
                let root_after = self
                    .client
                    .stat_discovered_space_root_with_context(
                        spaces_by_id,
                        RangeReadContext {
                            deadline,
                            token_generation: self.token_generation,
                        },
                    )
                    .map_err(|error| self.reject_cached_cloud_error(error))?;
                if !root_after.directory
                    || root_after.id != *root_id
                    || (vault_identity.is_none()
                        && (spaces_by_id.encrypted
                            || root_after.encrypted
                            || self.known_vault_root(space_id, "/")?))
                {
                    return Err(BackendError::Unavailable);
                }
                if let Some(expected) = vault_identity {
                    if self.vault_root_identity(space_id, &root_after)?.as_ref() != Some(expected) {
                        return Err(BackendError::Unavailable);
                    }
                }
            }
            Some(staged)
        } else {
            None
        };
        let catalog_scope = self.catalog_scope_snapshot()?;
        let mut state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
        self.client
            .with_token_generation(self.token_generation, || {
                if self.revoked.load(Ordering::Acquire) {
                    return Err(BackendError::Unavailable);
                }
                match namespace {
                    NamespaceDirectory::Root {
                        account_id,
                        personal_space_id,
                        personal_root_id,
                    } => {
                        state.location_labels.insert(
                            (personal_space_id.clone(), personal_root_id.clone()),
                            "Personal".to_owned(),
                        );
                        let personal_identity = if let Some(scope) = catalog_scope.as_ref() {
                            let identity = binding_identity(
                                scope,
                                "directory",
                                &[
                                    &personal_space_id,
                                    &personal_root_id,
                                    "/",
                                    &personal_root_id,
                                ],
                            );
                            let binding = ProviderIdentityBinding::Directory {
                                identity: *identity.as_bytes(),
                                space_id: personal_space_id.clone(),
                                root_resource_id: personal_root_id.clone(),
                                path: "/".to_owned(),
                                remote_id: personal_root_id.clone(),
                            };
                            self.upsert_identity_binding(scope, &binding)?;
                            state.directories.insert(
                                identity,
                                DirectoryBinding {
                                    space_id: personal_space_id.clone(),
                                    root_resource_id: personal_root_id.clone(),
                                    path: "/".to_owned(),
                                    remote_id: personal_root_id.clone(),
                                },
                            );
                            identity
                        } else {
                            if let Some(identity) = find_directory_identity(
                                &state,
                                &personal_space_id,
                                &personal_root_id,
                                "/",
                                &personal_root_id,
                            ) {
                                identity
                            } else {
                                if binding_count(&state) >= MAX_IDENTITY_CATALOG_ENTRIES {
                                    return Err(BackendError::Unavailable);
                                }
                                let identity = next_identity(self.backend_id, &mut state)?;
                                state.directories.insert(
                                    identity,
                                    DirectoryBinding {
                                        space_id: personal_space_id.clone(),
                                        root_resource_id: personal_root_id.clone(),
                                        path: "/".to_owned(),
                                        remote_id: personal_root_id.clone(),
                                    },
                                );
                                identity
                            }
                        };
                        let spaces_identity = if let Some(scope) = catalog_scope.as_ref() {
                            let identity = binding_identity(
                                scope,
                                "spaces_namespace",
                                &[&personal_space_id, &personal_root_id],
                            );
                            let binding = ProviderIdentityBinding::SpacesNamespace {
                                identity: *identity.as_bytes(),
                                personal_space_id: personal_space_id.clone(),
                                personal_root_resource_id: personal_root_id.clone(),
                            };
                            self.upsert_identity_binding(scope, &binding)?;
                            state.namespace_directories.insert(
                                identity,
                                NamespaceDirectory::Spaces {
                                    account_id,
                                    personal_space_id,
                                    personal_root_id,
                                },
                            );
                            identity
                        } else if let Some(identity) = find_spaces_identity(&state, &account_id) {
                            identity
                        } else {
                            if binding_count(&state) >= MAX_IDENTITY_CATALOG_ENTRIES {
                                return Err(BackendError::Unavailable);
                            }
                            let identity = next_identity(self.backend_id, &mut state)?;
                            state.namespace_directories.insert(
                                identity,
                                NamespaceDirectory::Spaces {
                                    account_id,
                                    personal_space_id,
                                    personal_root_id,
                                },
                            );
                            identity
                        };
                        Ok(vec![
                            PlaceholderChild {
                                name: "Personal".to_owned(),
                                identity: personal_identity.0.to_vec(),
                                metadata: PlaceholderMetadata {
                                    is_directory: true,
                                    length: 0,
                                },
                                last_write_time: 0,
                            },
                            PlaceholderChild {
                                name: "Spaces".to_owned(),
                                identity: spaces_identity.0.to_vec(),
                                metadata: PlaceholderMetadata {
                                    is_directory: true,
                                    length: 0,
                                },
                                last_write_time: 0,
                            },
                        ])
                    }
                    NamespaceDirectory::Spaces {
                        account_id: _,
                        personal_space_id,
                        personal_root_id,
                    } => {
                        // Replace Space names only from the freshly validated
                        // complete set. Old roots must not keep a stale label.
                        state.location_labels.retain(|(space, root), _| {
                            space == &personal_space_id && root == &personal_root_id
                        });
                        let mut children = Vec::new();
                        for (space_id, root_id, name, vault_identity) in
                            staged_space_roots.unwrap_or_default()
                        {
                            check_cancel(cancellation)?;
                            if let Some(identity) = vault_identity {
                                children.push(PlaceholderChild {
                                    name,
                                    identity,
                                    metadata: PlaceholderMetadata {
                                        is_directory: true,
                                        length: 0,
                                    },
                                    last_write_time: 0,
                                });
                                continue; // verified vault route never enters ordinary persistence
                            }
                            state.location_labels.insert(
                                (space_id.clone(), root_id.clone()),
                                format!("Spaces / {name}"),
                            );
                            let identity = if let Some(scope) = catalog_scope.as_ref() {
                                let identity = binding_identity(
                                    scope,
                                    "directory",
                                    &[&space_id, &root_id, "/", &root_id],
                                );
                                let binding = ProviderIdentityBinding::Directory {
                                    identity: *identity.as_bytes(),
                                    space_id: space_id.clone(),
                                    root_resource_id: root_id.clone(),
                                    path: "/".to_owned(),
                                    remote_id: root_id.clone(),
                                };
                                self.upsert_identity_binding(scope, &binding)?;
                                state.directories.insert(
                                    identity,
                                    DirectoryBinding {
                                        space_id: space_id.clone(),
                                        root_resource_id: root_id.clone(),
                                        path: "/".to_owned(),
                                        remote_id: root_id.clone(),
                                    },
                                );
                                identity
                            } else {
                                if let Some(identity) = find_directory_identity(
                                    &state, &space_id, &root_id, "/", &root_id,
                                ) {
                                    identity
                                } else {
                                    if binding_count(&state) >= MAX_IDENTITY_CATALOG_ENTRIES {
                                        return Err(BackendError::Unavailable);
                                    }
                                    let identity = next_identity(self.backend_id, &mut state)?;
                                    state.directories.insert(
                                        identity,
                                        DirectoryBinding {
                                            space_id,
                                            root_resource_id: root_id.clone(),
                                            path: "/".to_owned(),
                                            remote_id: root_id,
                                        },
                                    );
                                    identity
                                }
                            };
                            children.push(PlaceholderChild {
                                name,
                                identity: identity.0.to_vec(),
                                metadata: PlaceholderMetadata {
                                    is_directory: true,
                                    length: 0,
                                },
                                last_write_time: 0,
                            });
                        }
                        if children.len() > MAX_DIRECTORY_CHILDREN {
                            return Err(BackendError::Unavailable);
                        }
                        Ok(children)
                    }
                }
            })
            .map_err(|error| self.reject_cached_cloud_error(error))?
    }

    fn validate_namespace_scope(
        &self,
        account_id: &str,
        expected_personal_space_id: &str,
        expected_personal_root_id: &str,
        deadline: std::time::Instant,
    ) -> Result<Vec<raiun_core::backend::CloudSpace>, BackendError> {
        let spaces = self.discover_spaces(deadline)?;
        let personal = verified_personal(&spaces)?;
        if personal.id != expected_personal_space_id
            || derive_account_id(&self.client.configured_server_url(), &personal.id) != account_id
            || account_id != self.scope.account_id
        {
            return Err(BackendError::Unavailable);
        }
        let personal = spaces
            .iter()
            .find(|space| space.id == expected_personal_space_id)
            .ok_or(BackendError::Unavailable)?;
        let root = self
            .client
            .stat_discovered_space_root_with_context(
                personal,
                RangeReadContext {
                    deadline,
                    token_generation: self.token_generation,
                },
            )
            .map_err(|error| self.reject_cached_cloud_error(error))?;
        if !root.directory || root.encrypted || root.id != expected_personal_root_id {
            return Err(BackendError::Unavailable);
        }
        Ok(spaces)
    }

    fn begin_scoped_publish<'a>(
        &'a self,
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn PublishPermit + 'a>, BackendError> {
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled);
        }
        if cancellation.is_expired() {
            return Err(BackendError::Unavailable);
        }
        let publication = loop {
            if cancellation.is_cancelled() {
                return Err(BackendError::Cancelled);
            }
            if cancellation.is_expired() {
                return Err(BackendError::Unavailable);
            }
            match self.publish_gate.try_lock() {
                Ok(guard) => break guard,
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(BackendError::Unavailable);
                }
            }
        };
        self.ensure_active()?;
        let token = loop {
            if cancellation.is_cancelled() {
                return Err(BackendError::Cancelled);
            }
            if cancellation.is_expired() {
                return Err(BackendError::Unavailable);
            }
            match self
                .client
                .try_lock_token_generation(self.token_generation)
                // Token mismatch permanently fences this backend through
                // ensure_active; publication is already locked here.
                .map_err(map_cloud_error)?
            {
                Some(guard) => break guard,
                None => std::thread::sleep(std::time::Duration::from_millis(1)),
            }
        };
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled);
        }
        if cancellation.is_expired() {
            return Err(BackendError::Unavailable);
        }
        self.ensure_active()?;
        Ok(Box::new(OpenCloudPublishPermit {
            _publication: publication,
            _token: token,
        }))
    }

    fn ensure_active(&self) -> Result<(), BackendError> {
        if self.revoked.load(Ordering::Acquire)
            || self.client.token_generation() != self.token_generation
        {
            Err(BackendError::Unavailable)
        } else {
            Ok(())
        }
    }
}

impl PlaceholderBackend for OpenCloudPlaceholderBackend {
    #[cfg(windows)]
    fn requires_hydration_inventory(&self, identity: &[u8]) -> Result<bool, BackendError> {
        Ok(self.vault_for_identity(identity)?.is_some())
    }

    fn prepare_edit_binding<'a>(
        &'a self,
        identity: &[u8],
    ) -> Result<Box<dyn PreparedEditBinding + 'a>, BackendError> {
        #[cfg(windows)]
        if self.vault_for_identity(identity)?.is_some() {
            return Err(BackendError::Unavailable);
        }
        let lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        self.ensure_active()?;
        let identity: [u8; 16] = identity.try_into().map_err(|_| BackendError::NotFound)?;
        let file = self
            .state
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .files
            .get(&OpaqueIdentity(identity))
            .cloned()
            .ok_or(BackendError::NotFound)?;
        let binding = PlaceholderEditBinding {
            profile_id: self.scope.profile_id.clone(),
            server_origin: self.scope.server_origin.clone(),
            account_subject: self.scope.account_id.clone(),
            account_generation: self.token_generation,
            space_id: file.space_id,
            root_resource_id: file.root_resource_id,
            remote_resource_id: file.remote_id,
            virtual_path: file.path,
            base_etag: file.etag,
            base_size: file.size,
        };
        self.client
            .with_token_generation(self.token_generation, || {
                if self.revoked.load(Ordering::Acquire) {
                    Err(BackendError::Unavailable)
                } else {
                    Ok(())
                }
            })
            .map_err(|error| self.reject_cached_cloud_error(error))??;
        Ok(Box::new(OpenCloudPreparedEdit {
            _lease: lease,
            binding,
        }))
    }

    fn lookup(&self, identity: &[u8]) -> Result<Option<PlaceholderMetadata>, BackendError> {
        #[cfg(windows)]
        if let Some(route) = self.vault_for_identity(identity)? {
            return route.backend().lookup(identity);
        }
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        self.ensure_active()?;
        let identity: [u8; 16] = match identity.try_into() {
            Ok(identity) => identity,
            Err(_) => return Ok(None),
        };
        let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
        let identity = OpaqueIdentity(identity);
        if let Some(binding) = state.files.get(&identity) {
            return Ok(Some(PlaceholderMetadata {
                is_directory: false,
                length: binding.size,
            }));
        }
        if state.namespace_directories.contains_key(&identity) {
            return Ok(Some(PlaceholderMetadata {
                is_directory: true,
                length: 0,
            }));
        }
        Ok(state
            .directories
            .get(&identity)
            .map(|_| PlaceholderMetadata {
                is_directory: true,
                length: 0,
            }))
    }

    fn enumerate(
        &self,
        identity: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<Vec<PlaceholderChild>, BackendError> {
        let prepared = self.prepare_enumeration(identity, cancellation)?;
        Ok(prepared.children().to_vec())
    }

    fn prepare_enumeration<'a>(
        &'a self,
        identity: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn PreparedEnumeration + 'a>, BackendError> {
        #[cfg(windows)]
        if let Some(route) = self.vault_for_identity(identity)? {
            return route
                .backend()
                .prepare_enumeration_owned(identity, cancellation);
        }
        let lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        let children = self.enumerate_scoped(identity, cancellation)?;
        Ok(Box::new(OpenCloudPreparedEnumeration {
            backend: self,
            _lease: lease,
            children,
        }))
    }

    fn read_range(
        &self,
        identity: &[u8],
        offset: u64,
        output: &mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<usize, BackendError> {
        #[cfg(windows)]
        if let Some(route) = self.vault_for_identity(identity)? {
            return route
                .backend()
                .read_range(identity, offset, output, cancellation);
        }
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled);
        }
        if cancellation.is_expired() {
            return Err(BackendError::Unavailable);
        }
        self.ensure_active()?;
        if output.len() > MAX_RANGE_BYTES {
            return Err(BackendError::InvalidRange);
        }
        let identity: [u8; 16] = identity.try_into().map_err(|_| BackendError::NotFound)?;
        let binding = self
            .state
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .files
            .get(&OpaqueIdentity(identity))
            .cloned()
            .ok_or(BackendError::NotFound)?;
        let mut staged = vec![0; output.len()];
        let result = self.client.read_range_cancellable_with_context(
            RemoteRangeRequest {
                space: &binding.space_id,
                expected_root_id: &binding.root_resource_id,
                path: &binding.path,
                expected_id: &binding.remote_id,
                expected_etag: &binding.etag,
                expected_size: binding.size,
                offset,
            },
            &mut staged,
            RangeReadContext {
                deadline: cancellation.deadline(),
                token_generation: self.token_generation,
            },
            || {
                cancellation.is_cancelled()
                    || cancellation.is_expired()
                    || self.revoked.load(Ordering::Acquire)
                    || self.client.token_generation() != self.token_generation
            },
        );
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled);
        }
        self.ensure_active()?;
        if cancellation.is_expired() {
            return Err(BackendError::Unavailable);
        }
        let read = match result {
            Ok(read) => {
                self.publish_complete_cached_content(
                    &binding,
                    offset,
                    &staged[..read],
                    cancellation,
                )?;
                read
            }
            Err(error) if error.kind == ErrorKind::Offline => {
                let bytes = self.read_cached_range(&binding, offset, output.len(), cancellation)?;
                staged[..bytes.len()].copy_from_slice(&bytes);
                bytes.len()
            }
            Err(error) => return Err(self.reject_cached_cloud_error(error)),
        };
        self.client
            .with_token_generation(self.token_generation, || {
                if self.revoked.load(Ordering::Acquire) {
                    return Err(BackendError::Unavailable);
                }
                output[..read].copy_from_slice(&staged[..read]);
                Ok(read)
            })
            .map_err(|error| self.reject_cached_cloud_error(error))?
    }

    fn prepare_fetch_session<'a>(
        &'a self,
        identity: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn PreparedFetchSession + 'a>, BackendError> {
        #[cfg(windows)]
        if let Some(route) = self.vault_for_identity(identity)? {
            return route
                .backend()
                .prepare_fetch_session_owned(identity, cancellation);
        }
        let lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled);
        }
        if cancellation.is_expired() {
            return Err(BackendError::Unavailable);
        }
        self.ensure_active()?;
        let identity: [u8; 16] = identity.try_into().map_err(|_| BackendError::NotFound)?;
        let binding = self
            .state
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .files
            .get(&OpaqueIdentity(identity))
            .cloned()
            .ok_or(BackendError::NotFound)?;
        Ok(Box::new(OpenCloudFetchSession {
            backend: self,
            _lease: lease,
            binding,
        }))
    }

    fn prepare_fetch<'a>(
        &'a self,
        identity: &[u8],
        range: FetchRange,
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn PreparedFetch + 'a>, BackendError> {
        #[cfg(windows)]
        if let Some(route) = self.vault_for_identity(identity)? {
            return route
                .backend()
                .prepare_fetch_owned(identity, range, cancellation);
        }
        let lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled);
        }
        if cancellation.is_expired() || range.len() > MAX_REQUEST_BYTES {
            return Err(BackendError::Unavailable);
        }
        self.ensure_active()?;
        let identity: [u8; 16] = identity.try_into().map_err(|_| BackendError::NotFound)?;
        let binding = self
            .state
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .files
            .get(&OpaqueIdentity(identity))
            .cloned()
            .ok_or(BackendError::NotFound)?;
        self.prepare_bound_fetch(&binding, range, cancellation, Some(lease))
    }
}

impl OpenCloudPlaceholderBackend {
    fn prepare_bound_fetch<'a>(
        &'a self,
        binding: &FileBinding,
        range: FetchRange,
        cancellation: &CancellationToken,
        lease: Option<RwLockReadGuard<'a, ()>>,
    ) -> Result<Box<dyn PreparedFetch + 'a>, BackendError> {
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled);
        }
        if cancellation.is_expired() {
            return Err(BackendError::Unavailable);
        }
        self.ensure_active()?;
        self.ensure_ordinary_location(&binding.space_id, &binding.path)?;
        if range.end < range.offset || range.len() > MAX_REQUEST_BYTES {
            return Err(BackendError::InvalidRange);
        }
        let metadata = PlaceholderMetadata {
            is_directory: false,
            length: binding.size,
        };
        if range.end > binding.size || range.len() as usize > MAX_CALLBACK_RANGE_BYTES {
            return Err(BackendError::InvalidRange);
        }
        let length = usize::try_from(range.len()).map_err(|_| BackendError::InvalidRange)?;
        // The caller reserves one of two global staging permits before calling
        // this method, so the client-owned buffer is bounded to 16 MiB / 32 MiB total.
        let bytes = self
            .client
            .read_callback_range_to_vec_cancellable_with_context(
                RemoteRangeRequest {
                    space: &binding.space_id,
                    expected_root_id: &binding.root_resource_id,
                    path: &binding.path,
                    expected_id: &binding.remote_id,
                    expected_etag: &binding.etag,
                    expected_size: binding.size,
                    offset: range.offset,
                },
                length,
                RangeReadContext {
                    deadline: cancellation.deadline(),
                    token_generation: self.token_generation,
                },
                || {
                    cancellation.is_cancelled()
                        || cancellation.is_expired()
                        || self.revoked.load(Ordering::Acquire)
                        || self.client.token_generation() != self.token_generation
                },
            );
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled);
        }
        self.ensure_active()?;
        if cancellation.is_expired() {
            return Err(BackendError::Unavailable);
        }
        let bytes = match bytes {
            Ok(bytes) => {
                self.publish_complete_cached_content(binding, range.offset, &bytes, cancellation)?;
                bytes
            }
            Err(error) if error.kind == ErrorKind::Offline => {
                self.read_cached_range(binding, range.offset, length, cancellation)?
            }
            Err(error) => return Err(self.reject_cached_cloud_error(error)),
        };
        if bytes.len() != length {
            return Err(BackendError::Unavailable);
        }
        self.client
            .with_token_generation(self.token_generation, || {
                if self.revoked.load(Ordering::Acquire) {
                    return Err(BackendError::Unavailable);
                }
                Ok(Box::new(OpenCloudPreparedFetch {
                    backend: self,
                    _lease: lease,
                    metadata,
                    bytes,
                }) as Box<dyn PreparedFetch>)
            })
            .map_err(|error| self.reject_cached_cloud_error(error))?
    }
}

fn valid_scope_part(value: &str) -> bool {
    !value.is_empty() && value.len() <= 2_048 && !value.chars().any(char::is_control)
}

fn valid_remote_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256 * 1024
        && !value.chars().any(char::is_control)
        && !value.starts_with("http://")
        && !value.starts_with("https://")
}

fn verified_personal(
    spaces: &[raiun_core::backend::CloudSpace],
) -> Result<&raiun_core::backend::CloudSpace, BackendError> {
    let mut matches = spaces.iter().filter(|space| space.personal);
    let Some(personal) = matches.next() else {
        return Err(BackendError::Unavailable);
    };
    if matches.next().is_some()
        || personal.id.is_empty()
        || personal.id.len() > 512
        || !valid_remote_id(&personal.id)
        || personal.encrypted
    {
        return Err(BackendError::Unavailable);
    }
    Ok(personal)
}

fn derive_account_id(server_url: &str, personal_space_id: &str) -> String {
    let bytes = format!("{server_url}\0{personal_space_id}");
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes.bytes() {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn binding_count(state: &State) -> usize {
    state
        .files
        .len()
        .saturating_add(state.directories.len())
        .saturating_add(state.namespace_directories.len())
}

fn binding_identity(
    scope: &ProviderIdentityCatalogScope,
    kind: &str,
    tuple: &[&str],
) -> OpaqueIdentity {
    let mut digest = Sha256::new();
    digest.update(b"raiun-cloud-files-descendant-identity-v1\0");
    digest.update(scope.root_volume_serial.to_le_bytes());
    digest.update(scope.root_file_index.to_le_bytes());
    for value in [
        scope.profile_id.as_str(),
        scope.account_id.as_str(),
        scope.server_origin.as_str(),
        scope.personal_space_id.as_str(),
        scope.personal_root_resource_id.as_str(),
        kind,
    ]
    .into_iter()
    .chain(tuple.iter().copied())
    {
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value.as_bytes());
    }
    let digest = digest.finalize();
    let mut identity = [0_u8; 16];
    let identity_len = identity.len();
    identity.copy_from_slice(&digest[..identity_len]);
    OpaqueIdentity(identity)
}

#[cfg(test)]
fn same_identity_tuple(left: &ProviderIdentityBinding, right: &ProviderIdentityBinding) -> bool {
    match (left, right) {
        (
            ProviderIdentityBinding::Directory {
                space_id: left_space,
                root_resource_id: left_root,
                path: left_path,
                remote_id: left_id,
                ..
            },
            ProviderIdentityBinding::Directory {
                space_id: right_space,
                root_resource_id: right_root,
                path: right_path,
                remote_id: right_id,
                ..
            },
        )
        | (
            ProviderIdentityBinding::File {
                space_id: left_space,
                root_resource_id: left_root,
                path: left_path,
                remote_id: left_id,
                ..
            },
            ProviderIdentityBinding::File {
                space_id: right_space,
                root_resource_id: right_root,
                path: right_path,
                remote_id: right_id,
                ..
            },
        ) => {
            left_space == right_space
                && left_root == right_root
                && left_path == right_path
                && left_id == right_id
        }
        (
            ProviderIdentityBinding::SpacesNamespace {
                personal_space_id: left_space,
                personal_root_resource_id: left_root,
                ..
            },
            ProviderIdentityBinding::SpacesNamespace {
                personal_space_id: right_space,
                personal_root_resource_id: right_root,
                ..
            },
        ) => left_space == right_space && left_root == right_root,
        _ => false,
    }
}

fn validate_catalog_binding(
    scope: &ProviderIdentityCatalogScope,
    binding: &ProviderIdentityBinding,
) -> Result<OpaqueIdentity, BackendError> {
    let (expected, identity) = match binding {
        ProviderIdentityBinding::Directory {
            identity,
            space_id,
            root_resource_id,
            path,
            remote_id,
        } => {
            if !valid_remote_path(space_id, root_resource_id, path, true)
                || !valid_remote_id(remote_id)
                || !valid_remote_id(root_resource_id)
            {
                return Err(BackendError::Unavailable);
            }
            (
                binding_identity(
                    scope,
                    "directory",
                    &[space_id, root_resource_id, path, remote_id],
                ),
                OpaqueIdentity(*identity),
            )
        }
        ProviderIdentityBinding::File {
            identity,
            space_id,
            root_resource_id,
            path,
            remote_id,
            etag,
            ..
        } => {
            if !valid_remote_path(space_id, root_resource_id, path, false)
                || !valid_remote_id(remote_id)
                || !valid_remote_id(root_resource_id)
                || etag.is_empty()
                || etag.len() > 4096
                || etag.chars().any(char::is_control)
            {
                return Err(BackendError::Unavailable);
            }
            (
                binding_identity(
                    scope,
                    "file",
                    &[space_id, root_resource_id, path, remote_id],
                ),
                OpaqueIdentity(*identity),
            )
        }
        ProviderIdentityBinding::SpacesNamespace {
            identity,
            personal_space_id,
            personal_root_resource_id,
        } => {
            if personal_space_id != &scope.personal_space_id
                || personal_root_resource_id != &scope.personal_root_resource_id
            {
                return Err(BackendError::Unavailable);
            }
            (
                binding_identity(
                    scope,
                    "spaces_namespace",
                    &[personal_space_id, personal_root_resource_id],
                ),
                OpaqueIdentity(*identity),
            )
        }
    };
    if expected != identity {
        return Err(BackendError::Unavailable);
    }
    Ok(identity)
}

fn composite_root_identity(
    scope: &ProviderScope,
    personal_space_id: &str,
    personal_root_id: &str,
) -> OpaqueIdentity {
    let mut digest = Sha256::new();
    digest.update(b"raiun-cloud-files-composite-root-v1\0");
    for value in [
        scope.profile_id.as_bytes(),
        scope.account_id.as_bytes(),
        scope.server_origin.as_bytes(),
        personal_space_id.as_bytes(),
        personal_root_id.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value);
    }
    let digest = digest.finalize();
    let mut identity = [0_u8; 16];
    let identity_len = identity.len();
    identity.copy_from_slice(&digest[..identity_len]);
    OpaqueIdentity(identity)
}

fn identity_in_use(state: &State, identity: OpaqueIdentity) -> bool {
    state.files.contains_key(&identity)
        || state.directories.contains_key(&identity)
        || state.namespace_directories.contains_key(&identity)
}

fn find_directory_identity(
    state: &State,
    space_id: &str,
    root_id: &str,
    path: &str,
    remote_id: &str,
) -> Option<OpaqueIdentity> {
    state
        .directories
        .iter()
        .find(|(_, binding)| {
            binding.space_id == space_id
                && binding.root_resource_id == root_id
                && binding.path == path
                && binding.remote_id == remote_id
        })
        .map(|(identity, _)| *identity)
}

fn find_spaces_identity(state: &State, account_id: &str) -> Option<OpaqueIdentity> {
    state
        .namespace_directories
        .iter()
        .find(|(_, binding)| {
            matches!(binding, NamespaceDirectory::Spaces { account_id: current, .. } if current == account_id)
        })
        .map(|(identity, _)| *identity)
}

fn checked_space_display_name(
    name: &str,
    space_id: &str,
    used: &mut std::collections::HashSet<String>,
) -> Result<String, BackendError> {
    let candidate = if valid_windows_component(name) {
        name.to_owned()
    } else {
        format!("Space-{}", opaque_suffix(space_id))
    };
    if candidate.len() > 255 || !valid_windows_component(&candidate) {
        return Err(BackendError::Unavailable);
    }
    let folded = candidate.to_lowercase();
    if used.insert(folded) {
        return Ok(candidate);
    }
    for ordinal in 2..=MAX_PROVIDER_SPACES + 1 {
        let suffix = format!(" ({ordinal})");
        let max_base = 255usize.saturating_sub(suffix.len());
        let mut base = candidate.clone();
        while base.len() > max_base {
            base.pop();
        }
        while base.ends_with(['.', ' ']) {
            base.pop();
        }
        if base.is_empty() {
            base.push_str("Space");
        }
        let unique = format!("{base}{suffix}");
        if valid_windows_component(&unique) && used.insert(unique.to_lowercase()) {
            return Ok(unique);
        }
    }
    Err(BackendError::Unavailable)
}

fn opaque_suffix(value: &str) -> String {
    let mut suffix = String::with_capacity(16);
    for byte in value.as_bytes().iter().take(8) {
        use std::fmt::Write as _;
        let _ = write!(suffix, "{byte:02x}");
    }
    suffix
}

fn check_cancel(cancellation: &CancellationToken) -> Result<(), BackendError> {
    if cancellation.is_cancelled() {
        Err(BackendError::Cancelled)
    } else if cancellation.is_expired() {
        Err(BackendError::Unavailable)
    } else {
        Ok(())
    }
}

fn valid_remote_path(space_id: &str, root_id: &str, path: &str, allow_root: bool) -> bool {
    !space_id.is_empty()
        && space_id.len() <= 512
        && !space_id.chars().any(char::is_control)
        && !root_id.is_empty()
        && root_id.len() <= 256 * 1024
        && !root_id.chars().any(char::is_control)
        && path.len() <= 16 * 1024
        && path.starts_with('/')
        && (path == "/" && allow_root
            || path != "/"
                && !path.ends_with('/')
                && !path.contains("//")
                && !path.contains('\\')
                && !path.chars().any(char::is_control)
                && !path.split('/').any(|part| matches!(part, "." | "..")))
}

pub(crate) fn direct_child_name<'a>(parent: &str, child: &'a str) -> Option<&'a str> {
    let parent = parent.trim_end_matches('/');
    let child = child.trim_end_matches('/');
    let remainder = if parent.is_empty() {
        child.strip_prefix('/')?
    } else {
        child.strip_prefix(parent)?.strip_prefix('/')?
    };
    if remainder.is_empty() || remainder.contains('/') {
        None
    } else {
        Some(remainder)
    }
}

pub(crate) fn valid_windows_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value != "."
        && value != ".."
        && !matches!(value.chars().last(), Some('.' | ' '))
        && !value.chars().any(|ch| {
            ch.is_control() || matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
        })
        && !matches!(
            value
                .split('.')
                .next()
                .unwrap_or("")
                .to_ascii_uppercase()
                .as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        )
}

fn unix_to_filetime(seconds: i64) -> i64 {
    const WINDOWS_EPOCH_OFFSET_SECS: i64 = 11_644_473_600;
    seconds
        .checked_add(WINDOWS_EPOCH_OFFSET_SECS)
        .and_then(|value| value.checked_mul(10_000_000))
        .filter(|value| *value >= 0)
        .unwrap_or(0)
}

fn next_identity(backend_id: u64, state: &mut State) -> Result<OpaqueIdentity, BackendError> {
    let sequence = state.next_identity;
    state.next_identity = sequence.checked_add(1).ok_or(BackendError::Unavailable)?;
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&backend_id.to_le_bytes());
    bytes[8..].copy_from_slice(&sequence.to_le_bytes());
    Ok(OpaqueIdentity(bytes))
}

fn map_cloud_error(error: raiun_core::backend::CloudError) -> BackendError {
    match error.kind {
        ErrorKind::NotFound => BackendError::NotFound,
        ErrorKind::Conflict => BackendError::Unavailable,
        _ => BackendError::Unavailable,
    }
}

#[cfg(test)]
mod namespace_tests {
    mod initial_save_route_tests {
        include!("opencloud/initial_save_route_tests.rs");
    }
    mod fetch_session_tests {
        include!("opencloud/fetch_session_tests.rs");
    }
    #[cfg(windows)]
    mod offline_folder_tests {
        include!("opencloud/offline_folder_tests.rs");
    }
    #[cfg(windows)]
    mod offline_download_http_tests {
        include!("opencloud/offline_download_http_tests.rs");
    }

    use super::*;
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::atomic::AtomicBool,
        thread,
        time::Duration,
    };

    #[derive(Default)]
    struct MemoryIdentityCatalog(
        Mutex<Option<(ProviderIdentityCatalogScope, Vec<ProviderIdentityBinding>)>>,
    );

    impl ProviderIdentityCatalog for MemoryIdentityCatalog {
        fn load(
            &self,
            scope: &ProviderIdentityCatalogScope,
        ) -> Result<Vec<ProviderIdentityBinding>, BackendError> {
            let stored = self.0.lock().map_err(|_| BackendError::Unavailable)?;
            match stored.as_ref() {
                Some((stored_scope, bindings)) if stored_scope == scope => Ok(bindings.clone()),
                Some(_) => Err(BackendError::Unavailable),
                None => Ok(Vec::new()),
            }
        }

        fn upsert(
            &self,
            scope: &ProviderIdentityCatalogScope,
            binding: &ProviderIdentityBinding,
        ) -> Result<(), BackendError> {
            validate_catalog_binding(scope, binding)?;
            let mut stored = self.0.lock().map_err(|_| BackendError::Unavailable)?;
            let (stored_scope, bindings) =
                stored.get_or_insert_with(|| (scope.clone(), Vec::new()));
            if stored_scope != scope {
                return Err(BackendError::Unavailable);
            }
            if let Some(existing) = bindings
                .iter_mut()
                .find(|existing| existing.identity() == binding.identity())
            {
                if !same_identity_tuple(existing, binding) {
                    return Err(BackendError::Unavailable);
                }
                *existing = binding.clone();
            } else {
                if bindings.len() >= MAX_IDENTITY_CATALOG_ENTRIES {
                    return Err(BackendError::Unavailable);
                }
                bindings.push(binding.clone());
            }
            Ok(())
        }

        fn remove(
            &self,
            scope: &ProviderIdentityCatalogScope,
            identity: OpaqueIdentity,
        ) -> Result<(), BackendError> {
            let mut stored = self.0.lock().map_err(|_| BackendError::Unavailable)?;
            if let Some((stored_scope, bindings)) = stored.as_mut() {
                if stored_scope != scope {
                    return Err(BackendError::Unavailable);
                }
                bindings.retain(|binding| binding.identity() != identity);
            }
            Ok(())
        }
    }

    #[test]
    fn composite_root_routes_personal_and_plain_spaces_without_encrypted_space() {
        let (server, worker, stop) = start_namespace_fixture();
        let client = Arc::new(OpenCloudClient::new(&server, "test-token".into()).unwrap());
        let account_id = derive_account_id(&server, "personal-drive");
        let scope = ProviderScope::new(
            client.as_ref(),
            "profile-test".into(),
            account_id.clone(),
            client.server_origin().unwrap(),
        )
        .unwrap();
        let backend = OpenCloudPlaceholderBackend::new(client.clone(), scope).unwrap();
        let root = backend
            .register_composite_root_for("personal-drive", "personal-root")
            .unwrap();
        assert!(backend.owns_composite_root_identity(root));
        assert!(!backend.owns_composite_root_identity(OpaqueIdentity([0; 16])));
        assert_eq!(
            root,
            composite_root_identity(&backend.scope, "personal-drive", "personal-root"),
            "the persisted root identity is deterministic for this exact scope"
        );
        assert_ne!(
            root,
            composite_root_identity(&backend.scope, "another-drive", "personal-root")
        );
        assert_ne!(
            root,
            composite_root_identity(&backend.scope, "personal-drive", "another-root")
        );
        let other_profile_scope = ProviderScope::new(
            client.as_ref(),
            "different-profile".into(),
            account_id.clone(),
            client.server_origin().unwrap(),
        )
        .unwrap();
        assert_ne!(
            root,
            composite_root_identity(&other_profile_scope, "personal-drive", "personal-root"),
            "the same server account under another local profile has a separate root identity"
        );
        let mismatch_backend =
            OpenCloudPlaceholderBackend::new(client.clone(), backend.scope.clone())
                .expect("same account scope for mismatch test");
        assert_eq!(
            mismatch_backend.register_composite_root_for("personal-drive", "changed-root"),
            Err(BackendError::Unavailable),
            "fresh root discovery must match the persisted root resource ID"
        );
        let root_children = backend
            .enumerate(root.as_bytes(), &CancellationToken::new())
            .unwrap();
        assert_eq!(
            root_children
                .iter()
                .map(|child| child.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Personal", "Spaces"]
        );
        assert!(root_children.iter().all(|child| child.identity.len() == 16));
        let personal = root_children
            .iter()
            .find(|child| child.name == "Personal")
            .unwrap();
        let spaces = root_children
            .iter()
            .find(|child| child.name == "Spaces")
            .unwrap();

        let personal_children = backend
            .enumerate(&personal.identity, &CancellationToken::new())
            .unwrap();
        assert!(personal_children.is_empty());
        let spaces_children = backend
            .enumerate(&spaces.identity, &CancellationToken::new())
            .unwrap();
        assert_eq!(spaces_children.len(), 1);
        assert_eq!(spaces_children[0].name, "Projects");
        assert!(spaces_children[0].metadata.is_directory);

        let project_entries = backend
            .enumerate(&spaces_children[0].identity, &CancellationToken::new())
            .unwrap();
        assert_eq!(project_entries.len(), 1);
        assert_eq!(project_entries[0].name, "readme.txt");
        assert_eq!(
            backend
                .lookup(&project_entries[0].identity)
                .unwrap()
                .unwrap()
                .length,
            7
        );
        assert_ne!(project_entries[0].identity, b"/dav/projects/readme.txt");

        // A token rotation invalidates the whole namespace before another
        // callback can publish previously captured route identities.
        client.set_bearer_token("rotated-token".into()).unwrap();
        assert!(!backend.owns_composite_root_identity(root));
        assert_eq!(
            backend.enumerate(&spaces.identity, &CancellationToken::new()),
            Err(BackendError::Unavailable)
        );
        stop.store(true, Ordering::Release);
        worker.join().unwrap();
    }

    #[test]
    fn composite_root_rejects_account_scope_mismatch() {
        let (server, worker, stop) = start_namespace_fixture();
        let client = Arc::new(OpenCloudClient::new(&server, "test-token".into()).unwrap());
        let scope = ProviderScope::new(
            client.as_ref(),
            "profile-test".into(),
            "wrong-account-scope".into(),
            client.server_origin().unwrap(),
        )
        .unwrap();
        let backend = OpenCloudPlaceholderBackend::new(client, scope).unwrap();
        assert_eq!(
            backend.register_composite_root(),
            Err(BackendError::Unavailable)
        );
        stop.store(true, Ordering::Release);
        worker.join().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn restored_vault_exclusions_skip_ordinary_catalog_without_unlocking() {
        let (server, worker, stop) = start_namespace_fixture();
        let client = Arc::new(OpenCloudClient::new(&server, "test-token".into()).unwrap());
        let provider = ProviderScope::new(
            &client,
            "profile-test".into(),
            derive_account_id(&server, "personal-drive"),
            client.server_origin().unwrap(),
        )
        .unwrap();
        let local_root = crate::ConfiguredRootIdentity {
            volume_serial: 7,
            file_index: 19,
        };
        let scope = ProviderIdentityCatalogScope::new(
            &provider,
            local_root,
            "personal-drive",
            "personal-root",
        )
        .unwrap();
        let binding = |path: &str, resource: &str| {
            let identity = binding_identity(
                &scope,
                "file",
                &["personal-drive", "personal-root", path, resource],
            );
            ProviderIdentityBinding::File {
                identity: *identity.as_bytes(),
                space_id: "personal-drive".into(),
                root_resource_id: "personal-root".into(),
                path: path.into(),
                remote_id: resource.into(),
                etag: "\"v1\"".into(),
                size: 3,
            }
        };
        let covered = binding("/Vault/secret.txt", "covered-resource");
        let sibling = binding("/ordinary.txt", "ordinary-resource");
        let covered_id = validate_catalog_binding(&scope, &covered).unwrap();
        let sibling_id = validate_catalog_binding(&scope, &sibling).unwrap();
        let catalogue = Arc::new(MemoryIdentityCatalog::default());
        catalogue.upsert(&scope, &covered).unwrap();
        catalogue.upsert(&scope, &sibling).unwrap();
        let backend = OpenCloudPlaceholderBackend::new_with_identity_catalog(
            client,
            provider,
            local_root,
            catalogue.clone(),
        )
        .unwrap();
        backend
            .restore_vault_exclusions(local_root, &[("personal-drive".into(), "/Vault".into())])
            .unwrap();
        backend.register_composite_root().unwrap();
        assert!(backend.lookup(covered_id.as_bytes()).unwrap().is_none());
        assert!(
            backend
                .prepare_fetch_session(covered_id.as_bytes(), &CancellationToken::new())
                .is_err()
        );
        assert_eq!(
            backend
                .lookup(sibling_id.as_bytes())
                .unwrap()
                .unwrap()
                .length,
            3
        );
        let routes = backend.vault_routes.as_ref().unwrap();
        assert!(
            routes
                .covers_path("personal-drive", "/Vault/secret.txt")
                .unwrap()
        );
        assert!(
            routes
                .resolve_identity(covered_id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert!(
            routes
                .exact_root("personal-drive", "/Vault", "covered-resource")
                .unwrap()
                .is_none()
        );
        let durable = catalogue.load(&scope).unwrap();
        for original in [&covered, &sibling] {
            let actual = durable
                .iter()
                .find(|row| row.identity() == original.identity())
                .unwrap();
            assert_eq!(
                serde_json::to_vec(actual).unwrap(),
                serde_json::to_vec(original).unwrap()
            );
        }
        stop.store(true, Ordering::Release);
        worker.join().unwrap();
    }

    #[test]
    fn catalog_identity_is_stable_for_object_versions_and_bound_to_exact_local_root() {
        let client =
            Arc::new(OpenCloudClient::new("https://cloud.example", "test-token".into()).unwrap());
        let provider = ProviderScope::new(
            client.as_ref(),
            "profile-one".into(),
            "account-one".into(),
            client.server_origin().unwrap(),
        )
        .unwrap();
        let local_root = crate::ConfiguredRootIdentity {
            volume_serial: 0x1234,
            file_index: 0x9876,
        };
        let scope = ProviderIdentityCatalogScope::new(
            &provider,
            local_root,
            "personal-space",
            "personal-root",
        )
        .unwrap();
        let identity = binding_identity(
            &scope,
            "file",
            &[
                "projects",
                "projects-root",
                "/docs/readme.txt",
                "resource-17",
            ],
        );
        let first_version = ProviderIdentityBinding::File {
            identity: *identity.as_bytes(),
            space_id: "projects".into(),
            root_resource_id: "projects-root".into(),
            path: "/docs/readme.txt".into(),
            remote_id: "resource-17".into(),
            etag: "\"v1\"".into(),
            size: 10,
        };
        assert_eq!(
            validate_catalog_binding(&scope, &first_version),
            Ok(identity)
        );
        let second_version = match first_version.clone() {
            ProviderIdentityBinding::File {
                identity,
                space_id,
                root_resource_id,
                path,
                remote_id,
                ..
            } => ProviderIdentityBinding::File {
                identity,
                space_id,
                root_resource_id,
                path,
                remote_id,
                etag: "\"v2\"".into(),
                size: 11,
            },
            _ => unreachable!(),
        };
        assert_eq!(
            validate_catalog_binding(&scope, &second_version),
            Ok(identity)
        );

        let other_local_root = ProviderIdentityCatalogScope::new(
            &provider,
            crate::ConfiguredRootIdentity {
                volume_serial: local_root.volume_serial,
                file_index: local_root.file_index + 1,
            },
            "personal-space",
            "personal-root",
        )
        .unwrap();
        assert_ne!(
            binding_identity(
                &other_local_root,
                "file",
                &[
                    "projects",
                    "projects-root",
                    "/docs/readme.txt",
                    "resource-17"
                ],
            ),
            identity,
        );

        let moved_binding = match first_version {
            ProviderIdentityBinding::File {
                identity,
                space_id,
                root_resource_id,
                remote_id,
                etag,
                size,
                ..
            } => ProviderIdentityBinding::File {
                identity,
                space_id,
                root_resource_id,
                path: "/docs/renamed.txt".into(),
                remote_id,
                etag,
                size,
            },
            _ => unreachable!(),
        };
        assert_eq!(
            validate_catalog_binding(&scope, &moved_binding),
            Err(BackendError::Unavailable),
            "a stable callback identity cannot be retargeted to another path"
        );
    }

    #[test]
    fn catalog_rehydrates_nested_namespace_and_file_for_fresh_backend() {
        let (server, worker, stop) = start_namespace_fixture();
        let catalog = Arc::new(MemoryIdentityCatalog::default());
        let local_root = crate::ConfiguredRootIdentity {
            volume_serial: 0x45,
            file_index: 0x6789,
        };

        let client = Arc::new(OpenCloudClient::new(&server, "test-token".into()).unwrap());
        let scope = ProviderScope::new(
            client.as_ref(),
            "profile-catalog-test".into(),
            derive_account_id(&server, "personal-drive"),
            client.server_origin().unwrap(),
        )
        .unwrap();
        let first = OpenCloudPlaceholderBackend::new_with_identity_catalog(
            client,
            scope,
            local_root,
            catalog.clone(),
        )
        .unwrap();
        let root = first
            .register_composite_root_for("personal-drive", "personal-root")
            .unwrap();
        assert_eq!(
            first
                .register_composite_root_for("personal-drive", "personal-root")
                .unwrap(),
            root,
            "revalidating the same namespace root on one backend is idempotent"
        );
        let root_children = first
            .enumerate(root.as_bytes(), &CancellationToken::new())
            .unwrap();
        let personal_identity = root_children
            .iter()
            .find(|child| child.name == "Personal")
            .unwrap()
            .identity
            .clone();
        let spaces_identity = root_children
            .iter()
            .find(|child| child.name == "Spaces")
            .unwrap()
            .identity
            .clone();
        let personal_children = first
            .enumerate(&personal_identity, &CancellationToken::new())
            .unwrap();
        assert!(personal_children.is_empty());
        let spaces_children = first
            .enumerate(&spaces_identity, &CancellationToken::new())
            .unwrap();
        let projects_identity = spaces_children[0].identity.clone();
        let project_children = first
            .enumerate(&projects_identity, &CancellationToken::new())
            .unwrap();
        let file_identity = project_children[0].identity.clone();
        drop(first);

        // A new client and backend model a fresh process. Callback resolution
        // must come only from the protected identity catalog, never a guessed
        // path or an in-memory counter from the earlier instance.
        let client = Arc::new(OpenCloudClient::new(&server, "test-token".into()).unwrap());
        let scope = ProviderScope::new(
            client.as_ref(),
            "profile-catalog-test".into(),
            derive_account_id(&server, "personal-drive"),
            client.server_origin().unwrap(),
        )
        .unwrap();
        let second = OpenCloudPlaceholderBackend::new_with_identity_catalog(
            client, scope, local_root, catalog,
        )
        .unwrap();
        let reconnected_root = second
            .register_composite_root_for("personal-drive", "personal-root")
            .unwrap();
        assert_eq!(reconnected_root, root);
        let reconnected_root_children = second
            .enumerate(reconnected_root.as_bytes(), &CancellationToken::new())
            .unwrap();
        assert_eq!(reconnected_root_children[0].identity, personal_identity);
        assert_eq!(reconnected_root_children[1].identity, spaces_identity);
        let reconnected_spaces = second
            .enumerate(&spaces_identity, &CancellationToken::new())
            .unwrap();
        assert_eq!(reconnected_spaces[0].identity, projects_identity);
        let reconnected_project = second
            .enumerate(&projects_identity, &CancellationToken::new())
            .unwrap();
        assert_eq!(reconnected_project[0].identity, file_identity);
        let prepared = second
            .prepare_fetch(
                &file_identity,
                FetchRange { offset: 0, end: 7 },
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(prepared.bytes(), b"content");

        stop.store(true, Ordering::Release);
        worker.join().unwrap();
    }

    #[test]
    fn encrypted_direct_child_rejects_the_entire_spaces_listing() {
        let (server, worker, stop) = start_namespace_fixture_with(true);
        let client = Arc::new(OpenCloudClient::new(&server, "test-token".into()).unwrap());
        let scope = ProviderScope::new(
            client.as_ref(),
            "profile-test".into(),
            derive_account_id(&server, "personal-drive"),
            client.server_origin().unwrap(),
        )
        .unwrap();
        let backend = OpenCloudPlaceholderBackend::new(client, scope).unwrap();
        let root = backend.register_composite_root().unwrap();
        let root_children = backend
            .enumerate(root.as_bytes(), &CancellationToken::new())
            .unwrap();
        let spaces = root_children
            .iter()
            .find(|child| child.name == "Spaces")
            .unwrap();
        let spaces_children = backend
            .enumerate(&spaces.identity, &CancellationToken::new())
            .unwrap();
        assert_eq!(spaces_children.len(), 1);
        assert_eq!(
            backend.enumerate(&spaces_children[0].identity, &CancellationToken::new()),
            Err(BackendError::Unavailable),
            "an encrypted direct child prevents partial ordinary publication"
        );
        stop.store(true, Ordering::Release);
        worker.join().unwrap();
    }

    #[test]
    fn unsafe_or_duplicate_space_names_get_bounded_unique_components() {
        let mut names = std::collections::HashSet::new();
        let first = checked_space_display_name("Projects", "space-one", &mut names).unwrap();
        let second = checked_space_display_name("projects", "space-two", &mut names).unwrap();
        let reserved = checked_space_display_name("CON", "space-three", &mut names).unwrap();
        assert_eq!(first, "Projects");
        assert_ne!(first.to_lowercase(), second.to_lowercase());
        assert!(valid_windows_component(&reserved));
        assert!(reserved.starts_with("Space-"));
    }

    fn start_namespace_fixture() -> (String, thread::JoinHandle<()>, Arc<AtomicBool>) {
        start_namespace_fixture_with(false)
    }

    fn start_namespace_fixture_with(
        encrypted_child: bool,
    ) -> (String, thread::JoinHandle<()>, Arc<AtomicBool>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = thread::spawn(move || {
            let mut idle = 0;
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        idle = 0;
                        respond_namespace(&mut stream, address, encrypted_child);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        idle += 1;
                        if idle > 400 {
                            break;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("namespace fixture accept failed: {error}"),
                }
            }
        });
        (format!("http://{address}"), worker, stop)
    }

    fn respond_namespace(
        stream: &mut TcpStream,
        address: std::net::SocketAddr,
        encrypted_child: bool,
    ) {
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0_u8; 2048];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut chunk).unwrap();
            assert_ne!(count, 0);
            request.extend_from_slice(&chunk[..count]);
            assert!(request.len() <= 32 * 1024);
        }
        let request = String::from_utf8(request).unwrap();
        let target = request.split_whitespace().nth(1).unwrap_or_default();
        if request.starts_with("GET /dav/") {
            assert_eq!(target, "/dav/projects/readme.txt");
            assert!(
                request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("if-match: \"project-file-etag\""))
            );
            let range = request
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("range: bytes=")
                        .map(str::to_owned)
                })
                .expect("conditional range request");
            let (start, end) = range.split_once('-').unwrap();
            let start: usize = start.parse().unwrap();
            let end: usize = end.parse().unwrap();
            let content = b"content";
            assert!(start <= end && end < content.len());
            let body = &content[start..=end];
            let response = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{end}/{}\r\nETag: \"project-file-etag\"\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                body.len(),
                content.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
            return;
        }
        let (status, content_type, body) = if request.starts_with("GET /graph/") {
            let graph = format!(
                r#"{{"value":[{{"id":"personal-drive","name":"Personal","driveType":"personal","root":{{"id":"personal-root","webDavUrl":"http://{address}/dav/personal/"}}}},{{"id":"projects-drive","name":"Projects","driveType":"project","root":{{"id":"projects-root","webDavUrl":"http://{address}/dav/projects/"}}}},{{"id":"secret-drive","name":"Secret","driveType":"project","root":{{"id":"secret-root","webDavUrl":"http://{address}/dav/secret/","@libre.graph.contentType":"application/vnd.opencloud.vault"}}}}]}}"#
            );
            ("200 OK", "application/json", graph)
        } else if request.starts_with("PROPFIND ") {
            let path = target.split('?').next().unwrap_or(target);
            let (file_id, child) = if path.starts_with("/dav/personal/") {
                ("personal-root", None)
            } else if path.starts_with("/dav/projects/") {
                ("projects-root", Some(("readme.txt", "project-file", 7)))
            } else if path.starts_with("/dav/secret/") {
                ("secret-root", None)
            } else {
                panic!("unexpected namespace DAV path: {path}");
            };
            if path == "/dav/projects/readme.txt" {
                let xml = "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\"><d:response><d:href>/dav/projects/readme.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>7</d:getcontentlength><d:getetag>\"project-file-etag\"</d:getetag><oc:fileid>project-file</oc:fileid></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>".to_owned();
                let response = format!(
                    "HTTP/1.1 207 Multi-Status\r\nContent-Length: {}\r\nContent-Type: application/xml\r\nConnection: close\r\n\r\n{xml}",
                    xml.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
                return;
            }
            let collection = format!(
                r#"<d:response><d:href>{path}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>"{file_id}"</d:getetag><oc:fileid>{file_id}</oc:fileid></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"#
            );
            let listing = if request.to_ascii_lowercase().contains("depth: 1") {
                child.map(|(name, id, size)| {
                    let base = path.trim_end_matches('/');
                    let file = format!("<d:response><d:href>{base}/{name}</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>{size}</d:getcontentlength><d:getetag>\"{id}-etag\"</d:getetag><oc:fileid>{id}</oc:fileid></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>");
                    let encrypted = if encrypted_child {
                        format!("<d:response><d:href>{base}/Secret.vault/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype><d:getetag>secret-etag</d:getetag><oc:fileid>secret-folder-id</oc:fileid></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>")
                    } else {
                        String::new()
                    };
                    format!("{file}{encrypted}")
                }).unwrap_or_default()
            } else {
                String::new()
            };
            let xml = format!(
                "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">{collection}{listing}</d:multistatus>"
            );
            ("207 Multi-Status", "application/xml", xml)
        } else {
            panic!(
                "unexpected namespace fixture request: {}",
                request.lines().next().unwrap_or("")
            );
        };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
    }
}

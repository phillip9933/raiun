//! Narrow Windows Cloud Files API boundary.
//!
//! This crate probes Cloud Files, safely inspects explicitly selected empty
//! local directories, and provides a narrowly scoped synthetic provider
//! fixture for disposable Windows tests. Root inspection does not register or
//! mount a provider; this is not yet a production sync provider.

use std::{error::Error as StdError, fmt};

mod backend;
mod edit_journal;
mod initial_edit_queue;
mod opencloud;
mod recovery_provider;
mod recovery_reconcile;
#[cfg(windows)]
pub(crate) use backend::placeholder_population_completed;
pub use backend::{
    BackendError, BoundedPermit, BoundedPermitPool, CancellationToken, DEFAULT_FETCH_TIMEOUT,
    EditRecoveryProvider, FetchRange, MAX_CONCURRENT_DIRECTORY_ENUMERATIONS,
    MAX_CONCURRENT_FETCHES, MAX_DIRECTORY_CHILDREN, MAX_FILE_BYTES, MAX_RANGE_BYTES,
    MAX_REQUEST_BYTES, MAX_STAGED_CALLBACKS, PlaceholderBackend, PlaceholderChild,
    PlaceholderEditBinding, PlaceholderMetadata, PreparedEditBinding, PreparedEditRecovery,
    PreparedEnumeration, PreparedFetch, PreparedFetchSession, PublishPermit,
    RequestPublicationGate, RequestPublicationPermit, checked_fetch_range, next_chunk_len,
};
#[cfg(windows)]
pub use edit_journal::DpapiEditRecordProtector;
pub use edit_journal::{
    EditJournal, EditJournalScope, EditRecordProtector, ExplicitRecoveryApproval, JournalError,
    LocalEditMetadata, LocalEditRecord, LocalEditState, LocalFileIdentity, RecoveryAttemptOutcome,
    RecoveryAttemptState, RecoverySnapshot, RemoteEditBaseline,
};
pub use initial_edit_queue::{MAX_PENDING_INITIAL_EDITS, PendingInitialEdit};
pub use opencloud::{
    FileCacheBindingExpectation, FileCacheStatus, ListedFilePage, ListedFileRow, OpaqueIdentity,
    OpenCloudPlaceholderBackend, ProviderIdentityBinding, ProviderIdentityCatalog,
    ProviderIdentityCatalogScope, ProviderScope,
};
#[cfg(windows)]
pub use opencloud::{
    FolderCacheBindingExpectation, ListedFolderPage, ListedFolderRow, OfflineDownloadError,
};
pub use recovery_provider::{DurableEditRecoveryProvider, InitialEditReceipt};
pub use recovery_reconcile::{
    MAX_RECOVERY_UPLOAD_ATTEMPTS, MAX_RECOVERY_UPLOAD_BYTES, OpenCloudRecoveryRemote,
    ReconciliationIssue, ReconciliationOutcome, RecoveryRemote, RecoveryRemoteBody,
    RecoveryRemoteVersion,
};

#[cfg(windows)]
#[allow(unsafe_code)]
mod native;

/// Cloud Files API platform version. This reports API capability only; it is
/// not evidence that Raiun has connected a provider or mounted a drive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformVersion {
    pub build: u32,
    pub revision: u32,
    pub integration: u32,
}

/// Safe, non-path-bearing error from the Cloud Files adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// This target does not provide the Windows Cloud Files API.
    UnsupportedPlatform,
    /// A native Cloud Files operation failed. The code is an HRESULT.
    Native {
        operation: &'static str,
        hresult: i32,
    },
    /// The synthetic test directory could not be created or removed.
    Io {
        operation: &'static str,
        kind: std::io::ErrorKind,
    },
    /// The test directory was unexpectedly not empty before registration.
    SyntheticRootNotEmpty,
    /// The path could not be represented as a bounded Windows path.
    InvalidSyntheticPath,
    /// A callback or native operation found unexpected content in the test root.
    SyntheticRootChanged,
    /// The requested synthetic callback fixture did not complete correctly.
    SyntheticCallbackFailed,
    /// A protected edit-recovery capability could not be prepared for this
    /// account/root, so the native provider connection was not started.
    EditRecoveryUnavailable,
    /// A configured sync root is not a safe ordinary local directory.
    InvalidConfiguredRoot,
    /// A configured sync root must be empty before Raiun adopts it.
    ConfiguredRootNotEmpty,
    /// The selected root's path or stable file identity changed.
    ConfiguredRootChanged,
    /// Native connection ownership state did not match its lease.
    ConnectionStateInvalid,
    /// The exact authenticated account namespace could not be enumerated.
    ProviderUnavailable,
    /// At least one closed placeholder has modified or unverifiable data.
    /// The registration is deliberately retained for recovery.
    UnresolvedPlaceholderEdits,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("Windows Cloud Files is unavailable on this platform")
            }
            Self::Native { operation, hresult } => {
                write!(formatter, "{operation} failed (HRESULT {hresult:#010x})")
            }
            Self::Io { operation, kind } => write!(formatter, "{operation} failed ({kind})"),
            Self::SyntheticRootNotEmpty => {
                formatter.write_str("synthetic registration directory was not empty")
            }
            Self::InvalidSyntheticPath => {
                formatter.write_str("synthetic registration path is invalid")
            }
            Self::SyntheticRootChanged => {
                formatter.write_str("synthetic registration root ownership changed")
            }
            Self::SyntheticCallbackFailed => {
                formatter.write_str("synthetic provider callback failed")
            }
            Self::EditRecoveryUnavailable => formatter
                .write_str("durable edit recovery is unavailable for this account and root"),
            Self::InvalidConfiguredRoot => {
                formatter.write_str("configured root is not a safe local directory")
            }
            Self::ConfiguredRootNotEmpty => {
                formatter.write_str("configured root must be empty before setup")
            }
            Self::ConfiguredRootChanged => formatter.write_str("configured root identity changed"),
            Self::ConnectionStateInvalid => {
                formatter.write_str("Cloud Files connection state is invalid")
            }
            Self::ProviderUnavailable => {
                formatter.write_str("the authenticated provider namespace is unavailable")
            }
            Self::UnresolvedPlaceholderEdits => formatter.write_str(
                "modified or unverifiable placeholder data must be recovered before unregistering",
            ),
        }
    }
}

impl StdError for Error {}

/// Stable Windows filesystem identity captured for an explicitly selected
/// ordinary directory. This does not imply Cloud Files registration/mounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfiguredRootIdentity {
    pub volume_serial: u32,
    pub file_index: u64,
}

/// A validated empty root whose component handles remain open during the
/// configuration transaction. Callers must revalidate the path identity
/// immediately before and after persistence; an open handle alone is not a
/// guarantee that every filesystem operation will block renames.
#[allow(dead_code)]
pub struct ConfiguredRootLease {
    identity: ConfiguredRootIdentity,
    registered: bool,
    #[cfg(windows)]
    path: std::path::PathBuf,
    #[cfg(windows)]
    _native: native::RootInspectionLease,
}

impl ConfiguredRootLease {
    pub fn identity(&self) -> ConfiguredRootIdentity {
        self.identity
    }
}

/// Validate an empty local directory and retain its no-follow component
/// handles for a config transaction. It does not create a Cloud Files
/// registration; callers must revalidate the path before using the identity.
pub fn pin_configured_root(path: &std::path::Path) -> Result<ConfiguredRootLease, Error> {
    #[cfg(windows)]
    {
        let inner = native::pin_configured_root(path)?;
        Ok(ConfiguredRootLease {
            identity: inner.identity,
            registered: false,
            #[cfg(windows)]
            path: path.to_path_buf(),
            _native: inner,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(Error::UnsupportedPlatform)
    }
}

/// Re-pin an already registered root from persisted configuration. The path
/// must still resolve to the exact stored directory identity, and the Cloud
/// Files registration's provider name/version and opaque root identity must
/// match Raiun's registration. Existing namespace contents are allowed here;
/// the empty-root adoption rule remains exclusive to `pin_configured_root`.
pub fn pin_registered_configured_root(
    path: &std::path::Path,
    expected: ConfiguredRootIdentity,
) -> Result<ConfiguredRootLease, Error> {
    #[cfg(windows)]
    {
        let inner = native::pin_registered_configured_root(path, expected)?;
        Ok(ConfiguredRootLease {
            identity: inner.identity,
            registered: true,
            path: path.to_path_buf(),
            _native: inner,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = (path, expected);
        Err(Error::UnsupportedPlatform)
    }
}

/// Complete, preflighted input for a configured-root connection. The root,
/// authenticated backend scope, and durable recovery lease are acquired as a
/// unit before Cloud Files callbacks can start.
#[cfg(windows)]
#[allow(dead_code)]
pub struct PreparedConfiguredRootRuntime {
    root: ConfiguredRootLease,
    backend: std::sync::Arc<OpenCloudPlaceholderBackend>,
    composite_root_identity: OpaqueIdentity,
    recovery: std::sync::Arc<dyn PreparedEditRecovery>,
}

/// Prepare all required identity and recovery capabilities before native root
/// registration or connection. A recovery-preflight failure leaves the root
/// unregistered and no callback route active.
#[cfg(windows)]
#[allow(dead_code)]
pub fn prepare_configured_root_runtime(
    lease: ConfiguredRootLease,
    backend: std::sync::Arc<OpenCloudPlaceholderBackend>,
    composite_root_identity: OpaqueIdentity,
    recovery_provider: std::sync::Arc<dyn EditRecoveryProvider>,
) -> Result<PreparedConfiguredRootRuntime, Error> {
    if !backend.owns_composite_root_identity(composite_root_identity) {
        return Err(Error::ConfiguredRootChanged);
    }
    let recovery = prepare_root_recovery(&backend, lease.identity(), recovery_provider.as_ref())?;
    Ok(PreparedConfiguredRootRuntime {
        root: lease,
        backend,
        composite_root_identity,
        recovery,
    })
}

#[cfg(any(windows, test))]
fn prepare_root_recovery(
    backend: &OpenCloudPlaceholderBackend,
    root_identity: ConfiguredRootIdentity,
    provider: &dyn EditRecoveryProvider,
) -> Result<std::sync::Arc<dyn PreparedEditRecovery>, Error> {
    let scope = backend.scope();
    if backend.is_revoked() || scope.token_generation() == 0 {
        return Err(Error::EditRecoveryUnavailable);
    }
    let recovery = provider
        .prepare(scope, root_identity)
        .map_err(|_| Error::EditRecoveryUnavailable)?;
    if backend.is_revoked()
        || recovery.provider_scope() != scope
        || recovery.root_identity() != root_identity
    {
        return Err(Error::EditRecoveryUnavailable);
    }
    Ok(recovery)
}

/// Connect only from the full preflighted runtime bundle. Ordinary shutdown
/// disconnects without unregistering the persisted placeholder namespace.
#[cfg(windows)]
#[allow(dead_code)]
pub fn connect_configured_root(
    runtime: PreparedConfiguredRootRuntime,
) -> Result<ConfiguredRootConnection, Error> {
    Ok(ConfiguredRootConnection {
        inner: native::ConfiguredRootConnection::connect(runtime)?,
    })
}

/// Internal connection lease for one fully prepared configured root.
#[cfg(windows)]
#[allow(dead_code)]
pub struct ConfiguredRootConnection {
    inner: native::ConfiguredRootConnection,
}

#[cfg(windows)]
#[allow(dead_code)]
impl ConfiguredRootConnection {
    /// Take one newly captured close receipt from this exact live connection.
    /// This never scans recovered edits or authorizes a remote mutation.
    pub fn take_initial_edit(&self) -> Result<Option<PendingInitialEdit>, Error> {
        self.inner.take_initial_edit()
    }

    /// Bounded callback telemetry for the synthetic agent integration test.
    /// No path, account identity, or file data is exposed.
    #[cfg(feature = "synthetic-agent-integration")]
    pub fn directory_observation(&self) -> (usize, usize, usize, usize, usize) {
        self.inner.directory_observation()
    }

    /// Bounded hydration callback telemetry for the synthetic agent test.
    #[cfg(feature = "synthetic-agent-integration")]
    pub fn fetch_observation(&self) -> (usize, usize, usize, i32) {
        self.inner.fetch_observation()
    }

    /// Fixed, value-free close callback counters for the synthetic agent
    /// integration test. The production crate surface does not expose this.
    #[cfg(feature = "synthetic-agent-integration")]
    pub fn close_observation_for_integration(
        &self,
    ) -> (usize, usize, usize, usize, usize, i32, usize, usize) {
        self.inner.close_observation_for_integration()
    }

    /// Exact test-fixture placeholder metadata, with no path returned.
    #[cfg(feature = "synthetic-agent-integration")]
    pub fn placeholder_observation(
        &self,
        relative_components: &[&str],
    ) -> Result<(u32, u32, u32, u64), Error> {
        self.inner.placeholder_observation(relative_components)
    }

    /// Explicitly request hydration for a bounded synthetic fixture path.
    #[cfg(feature = "synthetic-agent-integration")]
    pub fn hydrate_test_placeholder(&self, relative_components: &[&str]) -> Result<i32, Error> {
        self.inner.hydrate_test_placeholder(relative_components)
    }

    /// Retry a disconnect without discarding the lease if the OS rejects the
    /// operation. The caller retains the connection object on error and must
    /// keep its authenticated scope revoked until a later disconnect succeeds.
    pub fn disconnect_in_place(&mut self) -> Result<(), Error> {
        self.inner.disconnect()
    }

    /// Drain callbacks and disconnect for ordinary shutdown while preserving
    /// the Cloud Files registration and namespace for the next process run.
    pub fn disconnect(mut self) -> Result<(), Error> {
        self.disconnect_in_place()
    }

    /// Explicitly unregister this exact, identity-verified root. Ordinary app
    /// shutdown must use `disconnect` so placeholders remain available.
    pub fn unregister(self) -> Result<(), Error> {
        self.inner.unregister()
    }
}

/// Test-only bridge for exercising the complete agent-to-Cloud-Files
/// lifecycle in a disposable Windows VM. The default production build does
/// not expose this entry point, and the application has no call site for it.
#[cfg(all(windows, debug_assertions, feature = "synthetic-agent-integration"))]
pub mod synthetic_agent_integration {
    use std::sync::Arc;

    use super::{
        ConfiguredRootConnection, ConfiguredRootLease, EditRecoveryProvider, Error,
        OpenCloudPlaceholderBackend, PreparedConfiguredRootRuntime, connect_configured_root,
        prepare_configured_root_runtime,
    };

    /// Opaque connection handle whose operations are intentionally limited to
    /// disconnect-preserving-registration and explicit unregister.
    pub struct Connection(ConfiguredRootConnection);

    /// Preflight the authenticated backend scope and durable recovery
    /// capability, then connect only the supplied pinned synthetic root.
    pub fn connect(
        lease: ConfiguredRootLease,
        backend: Arc<OpenCloudPlaceholderBackend>,
        personal_space_id: &str,
        personal_root_resource_id: &str,
        recovery: Arc<dyn EditRecoveryProvider>,
    ) -> Result<Connection, Error> {
        let composite_root_identity = backend
            .register_composite_root_for(personal_space_id, personal_root_resource_id)
            .map_err(|_| Error::ConfiguredRootChanged)?;
        let runtime: PreparedConfiguredRootRuntime =
            prepare_configured_root_runtime(lease, backend, composite_root_identity, recovery)?;
        connect_configured_root(runtime).map(Connection)
    }

    impl Connection {
        /// Drain callbacks and disconnect while retaining registration.
        pub fn disconnect(self) -> Result<(), Error> {
            self.0.disconnect()
        }

        /// Explicitly remove the exact validated registration.
        pub fn unregister(self) -> Result<(), Error> {
            self.0.unregister()
        }
    }
}

/// Validate a user-selected Windows root without registering it as a sync
/// root. The directory and every ancestor must be ordinary non-reparse
/// directories, and the final directory must be empty at inspection time.
pub fn inspect_configured_root(path: &std::path::Path) -> Result<ConfiguredRootIdentity, Error> {
    #[cfg(windows)]
    {
        native::inspect_configured_root(path, true)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(Error::UnsupportedPlatform)
    }
}

/// Revalidate a previously selected root's current ordinary-directory
/// identity and empty-state while no provider owns its contents. No
/// registration occurs.
pub fn verify_configured_root_identity(
    path: &std::path::Path,
) -> Result<ConfiguredRootIdentity, Error> {
    #[cfg(windows)]
    {
        native::inspect_configured_root(path, true)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(Error::UnsupportedPlatform)
    }
}

/// Check whether two already-existing local roots overlap by directory
/// identity, including case/alias paths. Every component is pinned and
/// checked without following reparse points; no registration occurs.
pub fn configured_roots_overlap(
    left: &std::path::Path,
    right: &std::path::Path,
) -> Result<bool, Error> {
    #[cfg(windows)]
    {
        native::configured_roots_overlap(left, right)
    }
    #[cfg(not(windows))]
    {
        let _ = (left, right);
        Err(Error::UnsupportedPlatform)
    }
}

/// Compare an exactly identified, OS-registered Cloud Files root with a plain
/// private directory. Only the registered root's final component may be a
/// reparse point; all ancestors and the private directory remain plain.
pub fn registered_configured_root_overlaps(
    registered: &std::path::Path,
    expected: ConfiguredRootIdentity,
    plain: &std::path::Path,
) -> Result<bool, Error> {
    #[cfg(windows)]
    {
        native::registered_configured_root_overlaps(registered, expected, plain)
    }
    #[cfg(not(windows))]
    {
        let _ = (registered, expected, plain);
        Err(Error::UnsupportedPlatform)
    }
}

/// Query the Windows Cloud Files API version.
///
/// Success indicates only that the platform API answered the query.
pub fn platform_version() -> Result<PlatformVersion, Error> {
    #[cfg(windows)]
    {
        native::platform_version()
    }
    #[cfg(not(windows))]
    {
        Err(Error::UnsupportedPlatform)
    }
}

/// A registration lease for an internally created synthetic test root.
///
/// The root path is intentionally not exposed. This prevents callers from
/// registering arbitrary user directories through this test-only boundary.
/// Dropping the lease attempts to unregister the root. If ownership checks or
/// unregistration fail, cleanup leaves the path untouched. Connecting it is
/// possible only through the bounded deterministic test-provider API below.
pub struct SyntheticRegistration {
    #[cfg(windows)]
    root: native::OwnedSyntheticRoot,
}

/// Connected, deterministic provider used only by ignored Windows VM tests.
/// It creates a small multi-entry synthetic namespace and hydrates files from
/// deterministic in-memory ranges; it has no account, network, or user path.
#[cfg(windows)]
pub struct SyntheticConnection {
    inner: native::SyntheticConnection,
}

impl SyntheticRegistration {
    /// Create and register a unique empty root with a current-user-only ACL in
    /// the user's temporary directory. Intended for disposable Windows VM
    /// tests only.
    pub fn create() -> Result<Self, Error> {
        #[cfg(windows)]
        {
            platform_version()?;
            Ok(Self {
                root: native::OwnedSyntheticRoot::create_and_register()?,
            })
        }
        #[cfg(not(windows))]
        {
            Err(Error::UnsupportedPlatform)
        }
    }

    /// Explicitly unregister this synthetic root and remove its empty folder.
    pub fn unregister(self) -> Result<(), Error> {
        #[cfg(windows)]
        {
            self.root.unregister()
        }
        #[cfg(not(windows))]
        {
            let _ = self;
            Err(Error::UnsupportedPlatform)
        }
    }

    /// Connect deterministic callbacks to this crate's private test root.
    ///
    /// This method creates a bounded fixture with two directories and two
    /// files at the synthetic root. The returned connection can enumerate the
    /// fixture and read deterministic payloads. This is a Cloud Files API
    /// integration test, not production provider support.
    #[cfg(windows)]
    pub fn connect(self) -> Result<SyntheticConnection, Error> {
        Ok(SyntheticConnection {
            inner: native::SyntheticConnection::connect(self.root)?,
        })
    }

    /// Reopen only a uniquely named private test registration created by this
    /// crate. This is used to simulate process restart and is absent from
    /// production builds.
    #[cfg(all(windows, test))]
    fn reconnect_for_test(path: std::path::PathBuf) -> Result<SyntheticConnection, Error> {
        let root = native::OwnedSyntheticRoot::reopen_registered_for_test(path)?;
        Ok(SyntheticConnection {
            inner: native::SyntheticConnection::reconnect_existing_for_test(root)?,
        })
    }
}

#[cfg(windows)]
impl SyntheticConnection {
    /// Enumerate the one test placeholder without exposing the private root.
    pub fn enumerate(&self) -> Result<Vec<SyntheticEntry>, Error> {
        self.inner.enumerate()
    }

    /// Read the fixed nested fixture directory through the operating system.
    /// This forces a real FETCH_PLACEHOLDERS callback; the returned contents
    /// are deterministic local test metadata only.
    pub fn enumerate_directory(
        &mut self,
        directory_name: &str,
    ) -> Result<Vec<SyntheticEntry>, Error> {
        self.inner.enumerate_directory(directory_name)
    }

    /// Return the already-validated private fixture folder for a test-only
    /// external directory query. This accessor is absent from non-test builds.
    #[cfg(test)]
    pub fn owned_fixture_directory_path_for_test(
        &self,
        directory_name: &str,
    ) -> Result<std::path::PathBuf, Error> {
        self.inner
            .owned_fixture_directory_path_for_test(directory_name)
    }

    /// Read the Cloud Files placeholder state for the fixed nested fixture
    /// directory. This is synthetic-test telemetry only; it accepts no path.
    #[cfg(test)]
    pub fn registered_population_policy(&self) -> Result<u32, Error> {
        self.inner.registered_population_policy()
    }

    #[cfg(test)]
    pub fn enable_directory_population(&self, directory_name: &str) -> Result<i32, Error> {
        self.inner.enable_directory_population(directory_name)
    }

    pub fn directory_placeholder_state(&self, directory_name: &str) -> Result<u32, Error> {
        self.inner.directory_placeholder_state(directory_name)
    }

    /// Read and hydrate the deterministic test file through the registered
    /// FETCH_DATA callback.
    pub fn read_payload(&self) -> Result<Vec<u8>, Error> {
        self.inner.read_payload()
    }

    /// Hydrate the fixed nested file by opening it through the local test root.
    pub fn read_nested_payload(&self) -> Result<Vec<u8>, Error> {
        self.inner.read_nested_payload()
    }

    /// Hydrate the fixed child in the second directory after its real
    /// population callback has completed.
    #[cfg(test)]
    pub fn read_second_folder_child_payload(&self) -> Result<Vec<u8>, Error> {
        self.inner.read_second_folder_child_payload()
    }

    /// Hydrate one named fixture file. Names are matched against the private
    /// fixed fixture; this does not accept a path or identity from the caller.
    pub fn read_file(&self, name: &str) -> Result<Vec<u8>, Error> {
        self.inner.read_file(name)
    }

    #[cfg(test)]
    pub fn disconnect_for_test(&mut self) -> Result<(), Error> {
        self.inner.disconnect_for_test()
    }

    #[cfg(test)]
    fn release_registration_for_restart_test(&mut self) -> Result<std::path::PathBuf, Error> {
        self.inner.release_registration_for_restart_test()
    }

    #[cfg(test)]
    pub fn owned_fixture_file_path_for_test(
        &self,
        name: &str,
    ) -> Result<std::path::PathBuf, Error> {
        self.inner.owned_fixture_file_path_for_test(name)
    }

    #[cfg(test)]
    pub fn close_observation_for_test(&self) -> (usize, usize, usize, usize, usize, i32, usize) {
        let observation = self.inner.callback_observation();
        (
            observation.modified_placeholder_closes,
            observation.unverifiable_placeholder_closes,
            observation.close_completion_callbacks,
            observation.last_close_param_size,
            observation.last_close_validation_stage,
            observation.last_close_validation_hresult,
            observation.last_close_path_common_prefix_bytes,
        )
    }

    #[cfg(test)]
    pub fn journaled_close_count_for_test(&self) -> usize {
        self.inner.journaled_close_count_for_test()
    }

    /// Return bounded test telemetry proving native fetch callback invocation
    /// and successful transfer, without exposing any path or account data.
    #[cfg(windows)]
    pub fn callback_observation(&self) -> (usize, usize, usize) {
        let observation = self.inner.callback_observation();
        (
            observation.fetch_callbacks,
            observation.last_fetch_param_size,
            observation.transferred_bytes,
        )
    }

    /// Return bounded directory-callback telemetry: callbacks observed, last
    /// ABI ParamSize, and entries submitted to CfExecute.
    pub fn directory_observation(&self) -> (usize, usize, usize, usize, usize) {
        let observation = self.inner.callback_observation();
        (
            observation.directory_callback_entries,
            observation.directory_callback_guard_rejections,
            observation.directory_callbacks,
            observation.last_directory_param_size,
            observation.placeholder_entries_submitted,
        )
    }

    #[cfg(test)]
    pub fn fixture_presence_for_test(&self) -> [bool; 5] {
        self.inner.fixture_presence_for_test()
    }

    /// Disconnect callbacks, unregister the synthetic root, and remove only
    /// the exact owned test file/root.
    pub fn shutdown(self) -> Result<(), Error> {
        self.inner.shutdown()
    }
}

/// Metadata returned by the synthetic placeholder enumeration test.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticEntry {
    pub name: String,
    pub is_file: bool,
    pub len: u64,
}

#[cfg(test)]
mod tests {
    use super::{
        BackendError, ConfiguredRootIdentity, EditRecoveryProvider, Error, LocalFileIdentity,
        OpenCloudPlaceholderBackend, PlaceholderEditBinding, PreparedEditRecovery, ProviderScope,
        prepare_root_recovery,
    };
    use raiun_core::backend::CloudBackend;
    use raiun_opencloud::OpenCloudClient;
    use std::sync::Arc;

    struct TestRecovery {
        scope: ProviderScope,
        root: ConfiguredRootIdentity,
    }

    impl PreparedEditRecovery for TestRecovery {
        fn provider_scope(&self) -> &ProviderScope {
            &self.scope
        }

        fn root_identity(&self) -> ConfiguredRootIdentity {
            self.root
        }

        fn append_edit(
            &self,
            _binding: &PlaceholderEditBinding,
            _root_identity: ConfiguredRootIdentity,
            _local_file: LocalFileIdentity,
            _relative_path: &str,
            _content: &[u8],
        ) -> Result<(), BackendError> {
            Ok(())
        }

        fn has_unresolved(&self) -> Result<bool, BackendError> {
            Ok(false)
        }
    }

    struct TestRecoveryProvider {
        scope: ProviderScope,
        root: ConfiguredRootIdentity,
        fail: bool,
    }

    impl EditRecoveryProvider for TestRecoveryProvider {
        fn prepare(
            &self,
            _provider_scope: &ProviderScope,
            _root_identity: ConfiguredRootIdentity,
        ) -> Result<Arc<dyn PreparedEditRecovery>, BackendError> {
            if self.fail {
                return Err(BackendError::Unavailable);
            }
            Ok(Arc::new(TestRecovery {
                scope: self.scope.clone(),
                root: self.root,
            }))
        }
    }

    fn test_backend() -> (OpenCloudPlaceholderBackend, ProviderScope) {
        let client =
            Arc::new(OpenCloudClient::new("https://example.test", "synthetic".into()).unwrap());
        let origin = client.server_origin().expect("normalized test origin");
        let scope = ProviderScope::new(
            &client,
            "synthetic-profile".into(),
            "synthetic-account".into(),
            origin,
        )
        .expect("valid synthetic account scope");
        let backend = OpenCloudPlaceholderBackend::new(client, scope.clone())
            .expect("backend matches synthetic client scope");
        (backend, scope)
    }

    #[test]
    fn configured_root_requires_preflighted_recovery_for_exact_scope_and_identity() {
        let (backend, scope) = test_backend();
        let root = ConfiguredRootIdentity {
            volume_serial: 7,
            file_index: 19,
        };
        let provider = TestRecoveryProvider {
            scope: scope.clone(),
            root,
            fail: false,
        };
        assert!(prepare_root_recovery(&backend, root, &provider).is_ok());

        let mismatched_root = TestRecoveryProvider {
            scope: scope.clone(),
            root: ConfiguredRootIdentity {
                file_index: root.file_index + 1,
                ..root
            },
            fail: false,
        };
        assert!(matches!(
            prepare_root_recovery(&backend, root, &mismatched_root),
            Err(Error::EditRecoveryUnavailable)
        ));

        let other_client = Arc::new(
            OpenCloudClient::new("https://example.test", "synthetic-other".into()).unwrap(),
        );
        let other_scope = ProviderScope::new(
            &other_client,
            "synthetic-profile".into(),
            "different-account".into(),
            other_client.server_origin().unwrap(),
        )
        .unwrap();
        let mismatched_scope = TestRecoveryProvider {
            scope: other_scope,
            root,
            fail: false,
        };
        assert!(matches!(
            prepare_root_recovery(&backend, root, &mismatched_scope),
            Err(Error::EditRecoveryUnavailable)
        ));

        let unavailable = TestRecoveryProvider {
            scope,
            root,
            fail: true,
        };
        assert!(matches!(
            prepare_root_recovery(&backend, root, &unavailable),
            Err(Error::EditRecoveryUnavailable)
        ));

        backend.revoke();
        assert!(matches!(
            prepare_root_recovery(
                &backend,
                root,
                &TestRecoveryProvider {
                    scope: ProviderScope::new(
                        &OpenCloudClient::new("https://example.test", "synthetic".into()).unwrap(),
                        "synthetic-profile".into(),
                        "synthetic-account".into(),
                        "https://example.test".into(),
                    )
                    .unwrap(),
                    root,
                    fail: false,
                }
            ),
            Err(Error::EditRecoveryUnavailable)
        ));
    }

    use super::{SyntheticRegistration, platform_version};
    #[cfg(not(windows))]
    use super::{configured_roots_overlap, inspect_configured_root};
    #[cfg(windows)]
    const OPEN_CLOUD_PAYLOAD_LEN: usize = 16 * 1024 * 1024;
    #[cfg(windows)]
    const LARGE_OPEN_CLOUD_PAYLOAD_LEN: usize = 17 * 1024 * 1024 + 7;
    #[cfg(windows)]
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread,
        time::{Duration, Instant},
    };

    #[cfg(not(windows))]
    #[test]
    fn windows_only_operations_fail_closed_on_other_targets() {
        assert_eq!(platform_version(), Err(Error::UnsupportedPlatform));
        assert_eq!(
            inspect_configured_root(std::path::Path::new("C:\\synthetic")),
            Err(Error::UnsupportedPlatform)
        );
        assert_eq!(
            configured_roots_overlap(
                std::path::Path::new("C:\\first"),
                std::path::Path::new("C:\\second")
            ),
            Err(Error::UnsupportedPlatform)
        );
        assert!(matches!(
            SyntheticRegistration::create(),
            Err(Error::UnsupportedPlatform)
        ));
    }

    /// Run only in the isolated Windows test VM. It registers an internally
    /// created empty temp directory and immediately unregisters it.
    #[cfg(windows)]
    fn query_owned_fixture_directory_in_child(path: &std::path::Path) -> bool {
        use std::{
            process::{Command, Stdio},
            thread,
            time::{Duration, Instant},
        };

        assert!(path.is_absolute(), "fixture path must be absolute");
        let mut child = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$ErrorActionPreference='Stop'; $items=[System.IO.Directory]::GetFileSystemEntries($env:RAIUN_SYNTHETIC_DIRECTORY); if ($items.Count -ne 1) { exit 23 }",
            ])
            .env("RAIUN_SYNTHETIC_DIRECTORY", path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start bounded synthetic directory-query process");
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match child
                .try_wait()
                .expect("poll synthetic directory-query process")
            {
                Some(status) => break status.success(),
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                None => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires disposable Windows VM with Cloud Files enabled"]
    fn synthetic_root_registration_can_be_unregistered() {
        let platform = platform_version().expect("query Cloud Files platform");
        assert!(platform.build > 0);
        let registration = SyntheticRegistration::create().expect("register empty synthetic root");
        registration
            .unregister()
            .expect("unregister synthetic root");
    }

    /// Exercises the identity-pinned configured-root connection lease in a
    /// disposable Windows VM. The test disconnects and reconnects the exact
    /// registration, then confirms unresolved namespace entries block removal.
    #[cfg(all(windows, feature = "synthetic-agent-integration"))]
    #[test]
    #[ignore = "requires disposable Windows VM with Cloud Files enabled"]
    fn configured_root_reconnect_refuses_unregister_with_unresolved_namespace() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let (server, worker) = start_opencloud_fixture();
        let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
        let server_origin = client.server_origin().expect("fixture origin");
        let account_id = canonical_test_account_id(&server_origin, "drive-personal");
        let scope = ProviderScope::new(
            client.as_ref(),
            "synthetic-profile".into(),
            account_id,
            server_origin,
        )
        .expect("valid synthetic account scope");

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "Raiun-Configured-Root-Lease-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create empty synthetic user root");
        let lease = super::pin_configured_root(&path).expect("pin empty root identity");
        let identity = lease.identity();
        let recovery = Arc::new(
            super::DurableEditRecoveryProvider::current_user(scope.clone(), identity)
                .expect("prepare exact current-user recovery scope"),
        );
        let backend = Arc::new(
            OpenCloudPlaceholderBackend::new_with_identity_catalog(
                client,
                scope.clone(),
                identity,
                recovery.identity_catalog(),
            )
            .expect("backend binds the exact local root and durable identity catalog"),
        );
        let connection = super::synthetic_agent_integration::connect(
            lease,
            backend.clone(),
            "drive-personal",
            "root-id",
            recovery.clone(),
        )
        .expect("register and connect through the trusted synthetic integration seam");
        connection
            .disconnect()
            .expect("disconnect and preserve registration");
        assert!(matches!(
            super::pin_registered_configured_root(
                &path,
                super::ConfiguredRootIdentity {
                    volume_serial: identity.volume_serial,
                    file_index: identity.file_index.wrapping_add(1),
                }
            ),
            Err(super::Error::ConfiguredRootChanged)
        ));
        let reconnect_lease = super::pin_registered_configured_root(&path, identity)
            .expect("recover exact persisted registration after disconnect");
        let reconnected = super::synthetic_agent_integration::connect(
            reconnect_lease,
            backend.clone(),
            "drive-personal",
            "root-id",
            recovery.clone(),
        )
        .expect("reconnect without replacing registration");
        assert!(matches!(
            reconnected.unregister(),
            Err(super::Error::UnresolvedPlaceholderEdits)
        ));
        let retained_registration = super::pin_registered_configured_root(&path, identity)
            .expect("exact registration remains recoverable after refusal");
        assert_eq!(retained_registration.identity(), identity);
        drop(retained_registration);
        let mut retained_entries = std::fs::read_dir(&path)
            .expect("inspect the retained namespace")
            .map(|entry| entry.expect("read retained entry").file_name())
            .collect::<Vec<_>>();
        retained_entries.sort();
        assert_eq!(
            retained_entries,
            vec![
                std::ffi::OsString::from("Personal"),
                std::ffi::OsString::from("Spaces")
            ],
            "only the exact composite Personal/Spaces namespace should remain"
        );

        let unexpected_root_file = path.join("synthetic-unregistered-entry.bin");
        let unexpected_root_bytes = b"raiun configured root unknown immediate entry r43\0\x01\xff";
        let mut unexpected_root_handle = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&unexpected_root_file)
            .expect("create only the deterministic unknown immediate root entry");
        std::io::Write::write_all(&mut unexpected_root_handle, unexpected_root_bytes)
            .expect("write deterministic unknown root entry");
        drop(unexpected_root_handle);

        let changed_root_lease = super::pin_registered_configured_root(&path, identity)
            .expect("unknown entry must not replace or invalidate the registered root identity");
        assert_eq!(changed_root_lease.identity(), identity);
        assert!(matches!(
            super::synthetic_agent_integration::connect(
                changed_root_lease,
                backend,
                "drive-personal",
                "root-id",
                recovery,
            ),
            Err(super::Error::ConfiguredRootChanged)
        ));
        assert_eq!(
            std::fs::read(&unexpected_root_file)
                .expect("unknown root entry remains untouched after refusal"),
            unexpected_root_bytes
        );
        let unchanged_registration = super::pin_registered_configured_root(&path, identity)
            .expect("registration remains recoverable after fail-closed reconnect refusal");
        assert_eq!(unchanged_registration.identity(), identity);
        drop(unchanged_registration);
        worker.join().expect("fixture worker remains healthy");
    }

    /// A successfully created first child is preserved when initialization
    /// fails before readiness. Reconnect must not fill in or erase the partial
    /// namespace because its original outcome needs explicit recovery.
    #[cfg(all(windows, feature = "synthetic-agent-integration"))]
    #[test]
    #[ignore = "requires disposable Windows VM with Cloud Files enabled"]
    fn configured_root_partial_initialization_preserves_registration_and_refuses_reconnect() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let (server, worker) = start_opencloud_fixture();
        let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
        let server_origin = client.server_origin().expect("fixture origin");
        let account_id = canonical_test_account_id(&server_origin, "drive-personal");
        let scope = ProviderScope::new(
            client.as_ref(),
            "synthetic-profile".into(),
            account_id,
            server_origin,
        )
        .expect("valid synthetic account scope");

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "Raiun-Partial-Initial-Root-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create empty synthetic user root");
        let lease = super::pin_configured_root(&path).expect("pin empty root identity");
        let identity = lease.identity();
        let recovery = Arc::new(
            super::DurableEditRecoveryProvider::current_user(scope.clone(), identity)
                .expect("prepare exact current-user recovery scope"),
        );
        let backend = Arc::new(
            OpenCloudPlaceholderBackend::new_with_identity_catalog(
                client,
                scope.clone(),
                identity,
                recovery.identity_catalog(),
            )
            .expect("backend binds the exact local root and durable identity catalog"),
        );
        super::native::stop_initial_population_after_first_for_test();
        assert!(matches!(
            super::synthetic_agent_integration::connect(
                lease,
                backend.clone(),
                "drive-personal",
                "root-id",
                recovery.clone(),
            ),
            Err(super::Error::ProviderUnavailable)
        ));
        let retained = super::pin_registered_configured_root(&path, identity)
            .expect("partial initialization must retain the exact registration");
        assert_eq!(retained.identity(), identity);
        drop(retained);
        let names = || {
            let mut entries = std::fs::read_dir(&path)
                .expect("inspect preserved partial namespace")
                .map(|entry| entry.expect("read preserved child").file_name())
                .collect::<Vec<_>>();
            entries.sort();
            entries
        };
        let before = names();
        assert_eq!(before, vec![std::ffi::OsString::from("Personal")]);
        let reconnect = super::pin_registered_configured_root(&path, identity)
            .expect("repin partial registered root");
        assert!(matches!(
            super::synthetic_agent_integration::connect(
                reconnect,
                backend,
                "drive-personal",
                "root-id",
                recovery,
            ),
            Err(super::Error::ConfiguredRootChanged)
        ));
        assert_eq!(
            names(),
            before,
            "reconnect must not mutate the partial namespace"
        );
        let retained = super::pin_registered_configured_root(&path, identity)
            .expect("refused reconnect must preserve registration for recovery");
        assert_eq!(retained.identity(), identity);
        drop(retained);
        worker.join().expect("fixture worker remains healthy");
    }

    /// Two independently pinned empty-root leases must never let a losing
    /// initialization unregister or replace the successful connection's root.
    #[cfg(all(windows, feature = "synthetic-agent-integration"))]
    #[test]
    #[ignore = "requires disposable Windows VM with Cloud Files enabled"]
    fn configured_root_concurrent_initialization_preserves_winning_namespace() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let (server, worker) = start_opencloud_fixture();
        let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
        let server_origin = client.server_origin().expect("fixture origin");
        let account_id = canonical_test_account_id(&server_origin, "drive-personal");
        let scope = ProviderScope::new(
            client.as_ref(),
            "synthetic-profile".into(),
            account_id,
            server_origin,
        )
        .expect("valid synthetic account scope");

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "Raiun-Concurrent-Initial-Root-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create empty synthetic user root");
        let lease = super::pin_configured_root(&path).expect("pin empty root identity");
        let identity = lease.identity();
        let recovery = Arc::new(
            super::DurableEditRecoveryProvider::current_user(scope.clone(), identity)
                .expect("prepare exact current-user recovery scope"),
        );
        let backend = Arc::new(
            OpenCloudPlaceholderBackend::new_with_identity_catalog(
                client,
                scope.clone(),
                identity,
                recovery.identity_catalog(),
            )
            .expect("backend binds the exact local root and durable identity catalog"),
        );
        drop(lease);
        let start = Arc::new(std::sync::Barrier::new(2));
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let mut workers = Vec::new();
        let mut releases = Vec::new();
        for index in 0..2 {
            let path = path.clone();
            let backend = backend.clone();
            let recovery = recovery.clone();
            let start = start.clone();
            let result_tx = result_tx.clone();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            releases.push(release_tx);
            workers.push(std::thread::spawn(move || {
                // Both attempts pin before either is allowed to register.
                let lease = super::pin_configured_root(&path);
                let pinned = lease.is_ok();
                start.wait();
                let connection = lease.and_then(|lease| {
                    super::synthetic_agent_integration::connect(
                        lease,
                        backend,
                        "drive-personal",
                        "root-id",
                        recovery,
                    )
                });
                result_tx
                    .send((index, pinned, connection.is_ok()))
                    .expect("report bounded connect result");
                if let Ok(connection) = connection {
                    let _ = release_rx.recv_timeout(Duration::from_secs(30));
                    connection
                        .disconnect()
                        .expect("winner disconnect preserves registration");
                }
            }));
        }
        drop(result_tx);
        let results = (0..2)
            .map(|_| {
                result_rx
                    .recv_timeout(Duration::from_secs(30))
                    .expect("both initialization attempts finish")
            })
            .collect::<Vec<_>>();
        // Release/join every worker before asserting, including on a failed
        // invariant. Synthetic registrations and namespace remain for recovery.
        for release in releases {
            let _ = release.send(());
        }
        for worker in workers {
            worker
                .join()
                .expect("bounded connect worker remains healthy");
        }
        assert!(
            results.iter().all(|(_, pinned, _)| *pinned),
            "both leases must pin the original empty root"
        );
        assert_eq!(
            results
                .iter()
                .filter(|(_, _, connected)| *connected)
                .count(),
            1,
            "exactly one attempt owns the native connection: {results:?}"
        );
        let retained = super::pin_registered_configured_root(&path, identity)
            .expect("losing initialization must not unregister the winning root");
        assert_eq!(retained.identity(), identity);
        drop(retained);
        let mut names = std::fs::read_dir(&path)
            .expect("inspect winning namespace")
            .map(|entry| entry.expect("read preserved child").file_name())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            vec![
                std::ffi::OsString::from("Personal"),
                std::ffi::OsString::from("Spaces")
            ]
        );
        let reconnect = super::pin_registered_configured_root(&path, identity)
            .expect("repin exact winning registration");
        super::synthetic_agent_integration::connect(
            reconnect,
            backend,
            "drive-personal",
            "root-id",
            recovery,
        )
        .expect("winning namespace remains reconnectable")
        .disconnect()
        .expect("preserve after reconnect");
        worker.join().expect("fixture worker remains healthy");
    }

    /// Exercises connect, callback-backed placeholder metadata, hydration,
    /// and ordered teardown only in the disposable Windows VM.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires disposable Windows VM with Cloud Files enabled"]
    fn synthetic_provider_enumerates_and_hydrates_then_disconnects() {
        let registration = SyntheticRegistration::create().expect("create synthetic root");
        let mut provider = registration.connect().expect("connect synthetic callbacks");
        eprintln!(
            "synthetic fixture presence stage=connected {:?}",
            provider.fixture_presence_for_test()
        );
        assert_eq!(
            provider.enumerate().expect("enumerate synthetic entries"),
            vec![
                super::SyntheticEntry {
                    name: "first-folder".to_owned(),
                    is_file: false,
                    len: 0,
                },
                super::SyntheticEntry {
                    name: "second-folder".to_owned(),
                    is_file: false,
                    len: 0,
                },
                super::SyntheticEntry {
                    name: "synthetic.bin".to_owned(),
                    is_file: true,
                    len: 4096,
                },
                super::SyntheticEntry {
                    name: "second.bin".to_owned(),
                    is_file: true,
                    len: 8192,
                },
            ]
        );
        let folder_state = provider
            .directory_placeholder_state("first-folder")
            .expect("inspect nested fixture placeholder state");
        let population_policy = provider
            .registered_population_policy()
            .expect("read back registered population policy");
        eprintln!(
            "synthetic root population_policy={population_policy:#x} nested directory placeholder_state={folder_state:#x}"
        );
        let update_result = provider
            .enable_directory_population("first-folder")
            .expect("explicitly enable on-demand population for owned fixture directory");
        let updated_folder_state = provider
            .directory_placeholder_state("first-folder")
            .expect("inspect explicitly enabled folder placeholder");
        eprintln!(
            "synthetic explicit directory population update={update_result:#x} state={updated_folder_state:#x}"
        );
        let fixture_directory = provider
            .owned_fixture_directory_path_for_test("first-folder")
            .expect("resolve exact owned synthetic fixture directory");
        let before_directory = provider.directory_observation();
        let child_query_completed = query_owned_fixture_directory_in_child(&fixture_directory);
        let after_child_query = provider.directory_observation();
        eprintln!(
            "synthetic fixture presence stage=child_query {:?}",
            provider.fixture_presence_for_test()
        );
        eprintln!(
            "synthetic child directory query completed={} entries={} guard_rejections={} accepted_callbacks={} param_size={} entries_submitted={}",
            child_query_completed,
            after_child_query.0.saturating_sub(before_directory.0),
            after_child_query.1.saturating_sub(before_directory.1),
            after_child_query.2.saturating_sub(before_directory.2),
            after_child_query.3,
            after_child_query.4.saturating_sub(before_directory.4),
        );
        let nested_result = provider.enumerate_directory("first-folder");
        let after_directory = provider.directory_observation();
        let entries = after_directory.0.saturating_sub(before_directory.0);
        let guard_rejections = after_directory.1.saturating_sub(before_directory.1);
        let directory_callbacks = after_directory.2.saturating_sub(before_directory.2);
        let directory_param_size = after_directory.3;
        let submitted = after_directory.4.saturating_sub(before_directory.4);
        eprintln!(
            "synthetic Cloud Files directory entries={entries} guard_rejections={guard_rejections} accepted_callbacks={directory_callbacks} param_size={directory_param_size} entries_submitted={submitted} child_query_completed={child_query_completed} result_ok={}",
            nested_result.is_ok()
        );
        assert!(
            child_query_completed,
            "bounded external directory query failed; see callback telemetry above"
        );
        let nested_entries =
            nested_result.expect("enumerate nested directory through FETCH_PLACEHOLDERS");
        eprintln!(
            "synthetic fixture presence stage=nested_enumerated {:?}",
            provider.fixture_presence_for_test()
        );
        assert_eq!(
            nested_entries,
            vec![super::SyntheticEntry {
                name: "nested.bin".to_owned(),
                is_file: true,
                len: 4096,
            }]
        );
        let nested = provider
            .read_nested_payload()
            .expect("hydrate nested synthetic content");
        assert_eq!(nested.len(), 4096);
        assert_eq!(nested[0], 19);
        assert_eq!(nested[4095], ((4095_u32 * 17 + 19) % 256) as u8);
        eprintln!(
            "synthetic fixture presence stage=nested_hydrated {:?}",
            provider.fixture_presence_for_test()
        );
        // CfUnregisterSyncRoot deletes an unpopulated placeholder directory.
        // Populate this second directory through the real callback and
        // hydrate its child so teardown verifies the normal-directory path;
        // the prior r20 empty-directory failure remains separate evidence.
        let second_folder_update = provider
            .enable_directory_population("second-folder")
            .expect("explicitly enable population for the second owned directory");
        let second_folder_state = provider
            .directory_placeholder_state("second-folder")
            .expect("inspect populated second-directory placeholder");
        let second_folder_path = provider
            .owned_fixture_directory_path_for_test("second-folder")
            .expect("resolve exact second synthetic directory");
        let before_second_query = provider.directory_observation();
        let second_query_completed = query_owned_fixture_directory_in_child(&second_folder_path);
        let second_child_entries = provider
            .enumerate_directory("second-folder")
            .expect("enumerate the second directory through FETCH_PLACEHOLDERS");
        let after_second_query = provider.directory_observation();
        eprintln!(
            "synthetic second directory population update={second_folder_update:#x} state={second_folder_state:#x} child_query_completed={second_query_completed} entries={} submitted={} fixture_presence={:?}",
            after_second_query.0.saturating_sub(before_second_query.0),
            after_second_query.4.saturating_sub(before_second_query.4),
            provider.fixture_presence_for_test()
        );
        assert!(
            second_query_completed,
            "second directory must complete its bounded Cloud Files population callback"
        );
        assert_eq!(
            second_child_entries,
            vec![super::SyntheticEntry {
                name: "retained-child.bin".to_owned(),
                is_file: true,
                len: 1024,
            }]
        );
        let retained_child = provider
            .read_second_folder_child_payload()
            .expect("hydrate the second directory's known synthetic child");
        assert_eq!(retained_child.len(), 1024);
        assert_eq!(retained_child[0], 19);
        assert_eq!(retained_child[1023], ((1023_u32 * 17 + 19) % 256) as u8);
        eprintln!(
            "synthetic fixture presence stage=second_directory_hydrated {:?}",
            provider.fixture_presence_for_test()
        );
        let bytes = provider.read_payload().expect("hydrate synthetic bytes");
        assert_eq!(bytes.len(), 4096);
        assert_eq!(bytes[0], 7);
        assert_eq!(bytes[1], 38);
        assert_eq!(bytes[4095], ((4095_u32 * 31 + 7) % 256) as u8);
        eprintln!(
            "synthetic fixture presence stage=synthetic_hydrated {:?}",
            provider.fixture_presence_for_test()
        );
        let second = provider
            .read_file("second.bin")
            .expect("hydrate second file");
        assert_eq!(second.len(), 8192);
        assert_eq!(second[0], 19);
        assert_eq!(second[4096], ((4096_u32 * 17 + 19) % 256) as u8);
        eprintln!(
            "synthetic fixture presence stage=second_hydrated {:?}",
            provider.fixture_presence_for_test()
        );
        let (callbacks, param_size, transferred_bytes) = provider.callback_observation();
        eprintln!(
            "synthetic Cloud Files fetch callbacks={callbacks} param_size={param_size} transferred_bytes={transferred_bytes}"
        );
        assert!(
            callbacks >= 2,
            "both synthetic files must invoke FETCH_DATA"
        );
        assert!(matches!(param_size, 60 | 64));
        assert!(transferred_bytes >= 4096 + 8192);
        assert!(directory_callbacks > 0, "FETCH_PLACEHOLDERS must run");
        assert!(matches!(directory_param_size, 20 | 24));
        assert!(submitted >= 1);
        provider
            .shutdown()
            .expect("disconnect and clean synthetic root");
    }

    /// Exercise real Cloud Files callbacks backed by a synthetic local
    /// OpenCloud DAV server. This still uses only the internally-created test
    /// root and never connects provider support to a user account.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires disposable Windows VM with Cloud Files enabled"]
    fn synthetic_cloudfiles_callbacks_hydrate_from_scoped_opencloud_ranges() {
        use super::{OpenCloudPlaceholderBackend, ProviderScope};
        use raiun_core::backend::CloudBackend;
        use raiun_opencloud::OpenCloudClient;

        let payload_len = LARGE_OPEN_CLOUD_PAYLOAD_LEN;
        let (server, worker) = start_opencloud_fixture_with_payload_len(payload_len);
        let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
        let scope = ProviderScope::new(
            client.as_ref(),
            "synthetic-profile".into(),
            "synthetic-account".into(),
            client.server_origin().unwrap(),
        )
        .unwrap();
        let backend = Arc::new(OpenCloudPlaceholderBackend::new(client, scope).unwrap());
        let identity = backend
            .register_file("drive-personal", "root-id", "/cloud.bin")
            .expect("register one ordinary localhost file");

        let registration = SyntheticRegistration::create().expect("create synthetic root");
        let expected_payload = opencloud_payload_for_len(payload_len);
        assert_eq!(expected_payload.len(), payload_len);
        let mut provider = super::native::SyntheticConnection::connect_with_opencloud_backend(
            registration.root,
            backend,
            identity.as_bytes().to_vec(),
            expected_payload.clone(),
            None,
        )
        .expect("connect test callbacks to scoped OpenCloud backend");

        // Keep every expected directory populated across unregister. Cloud
        // Files removes empty directory placeholders during unregister; that
        // separate behavior is covered by the empty-placeholder regression.
        // Here we verify populated directories and their children survive,
        // without relaxing the owned-root cleanup predicate.
        for (directory, expected_name, expected_len) in [
            ("first-folder", "nested.bin", 4096_u64),
            ("second-folder", "retained-child.bin", 1024_u64),
        ] {
            provider
                .enable_directory_population(directory)
                .expect("enable population on the exact synthetic fixture directory");
            let path = provider
                .owned_fixture_directory_path_for_test(directory)
                .expect("resolve an identity-checked synthetic directory");
            assert!(
                query_owned_fixture_directory_in_child(&path),
                "complete the bounded child-directory population callback"
            );
            let entries = provider
                .enumerate_directory(directory)
                .expect("enumerate the populated synthetic directory");
            assert_eq!(
                entries,
                vec![super::SyntheticEntry {
                    name: expected_name.to_owned(),
                    is_file: true,
                    len: expected_len,
                }]
            );
        }
        let nested = provider
            .read_nested_payload()
            .expect("hydrate the populated first-directory child");
        assert_eq!(nested.len(), 4096);
        let retained = provider
            .read_second_folder_child_payload()
            .expect("hydrate the populated second-directory child");
        assert_eq!(retained.len(), 1024);

        let read_result = provider.read_opencloud_fixture();
        let observation = provider.callback_observation();
        eprintln!(
            "synthetic OpenCloud callback result: callbacks={} param_size={} requested_offset={} requested_length={} staged_fetch_ms={} published_bytes={} first_failed_hresult={:#x}",
            observation.fetch_callbacks,
            observation.last_fetch_param_size,
            observation.last_requested_offset,
            observation.last_requested_length,
            observation.last_staged_fetch_millis,
            observation.transferred_bytes,
            observation.first_failed_hresult,
        );
        assert_eq!(
            provider.fixture_presence_for_test(),
            [true; 5],
            "all expected fixtures must be present before unregister"
        );
        provider
            .shutdown()
            .expect("clean synthetic root and callbacks");

        let observations = worker.join().expect("local HTTP fixture remains healthy");
        assert!(
            read_result.is_ok(),
            "hydrate the 17 MiB + 7 byte placeholder: result={read_result:?}; observation={observation:?}; fixture={observations:?}"
        );
        let bytes = read_result.expect("checked successful hydration above");
        assert_eq!(bytes, expected_payload);
        assert_eq!(bytes.len(), payload_len);
        assert!(
            observation.fetch_callbacks > 0,
            "the Cloud Files callback must run"
        );
        assert!(matches!(observation.last_fetch_param_size, 60 | 64));
        assert!(
            observation.transferred_bytes >= payload_len,
            "the OS callbacks must publish the full 17 MiB + 7 byte file; observed {} bytes",
            observation.transferred_bytes
        );
        assert!(
            observations.0 > 0,
            "at least one DAV range request is required"
        );
        assert!(observations.1 > 0, "a DAV range request is required");
        assert!(
            observations.2 >= payload_len as u64,
            "the conditional DAV range path must transfer the full fixture; observed {} bytes",
            observations.2
        );
    }

    /// The isolated Windows VM writes to a hydrated OpenCloud-backed
    /// placeholder and verifies that the exact account-bound DPAPI record
    /// survives disconnect/reopen. This preserves the unique synthetic root.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires disposable Windows VM with Cloud Files and current-user DPAPI"]
    fn modified_opencloud_close_is_dpapi_journaled_and_unregister_stays_blocked() {
        use super::{
            DpapiEditRecordProtector, EditJournal, EditJournalScope, EditRecordProtector,
            LocalFileIdentity, OpenCloudPlaceholderBackend, ProviderScope, RemoteEditBaseline,
        };
        use raiun_core::backend::CloudBackend;
        use raiun_opencloud::OpenCloudClient;
        use std::{
            fs::OpenOptions,
            io::Write,
            process::Command,
            thread,
            time::{Duration, Instant},
        };

        const EDIT_PATH_ENV: &str = "RAIUN_CLOUDFILES_JOURNAL_EDIT_PATH";
        const RECOVER_SCOPE_ENV: &str = "RAIUN_CLOUDFILES_JOURNAL_RECOVER_SCOPE";
        const CROSSUSER_INPUT_ENV: &str = "RAIUN_CLOUDFILES_JOURNAL_CROSSUSER_INPUT";
        const CROSSUSER_EXPORT_DIR_ENV: &str = "RAIUN_CLOUDFILES_JOURNAL_CROSSUSER_EXPORT_DIR";
        if let Some(path) = std::env::var_os(CROSSUSER_INPUT_ENV) {
            let manifest: serde_json::Value = serde_json::from_slice(
                &std::fs::read(path).expect("read only the synthetic sealed-record manifest"),
            )
            .expect("parse the test-only sealed-record manifest");
            let decode_hex = |value: &str| -> Vec<u8> {
                assert_eq!(value.len() % 2, 0, "synthetic hex data must be complete");
                value
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| {
                        let digit = |byte: u8| match byte {
                            b'0'..=b'9' => byte - b'0',
                            b'a'..=b'f' => byte - b'a' + 10,
                            _ => panic!("invalid synthetic hex data"),
                        };
                        (digit(pair[0]) << 4) | digit(pair[1])
                    })
                    .collect()
            };
            let associated_data = decode_hex(
                manifest["associated_data_hex"]
                    .as_str()
                    .expect("manifest includes associated data"),
            );
            let sealed = decode_hex(
                manifest["sealed_hex"]
                    .as_str()
                    .expect("manifest includes sealed record bytes"),
            );
            let protector = DpapiEditRecordProtector::current_user()
                .expect("second standard test user can create its own DPAPI protector");
            match protector.open(&associated_data, &sealed) {
                Err(super::JournalError::ProtectionFailed) => {}
                Ok(plaintext) => {
                    drop(zeroize::Zeroizing::new(plaintext));
                    panic!("a different Windows user decrypted a synthetic journal record");
                }
                Err(_) => panic!("cross-user rejection returned an unexpected safe error"),
            }
            return;
        }
        if let Ok(scope_json) = std::env::var(RECOVER_SCOPE_ENV) {
            let scope: EditJournalScope = serde_json::from_str(&scope_json)
                .expect("child receives only the parent-created synthetic scope");
            let protector = DpapiEditRecordProtector::current_user()
                .expect("same Windows user can reopen the DPAPI protector in a child process");
            let state_directory = protector.local_state_directory().to_path_buf();
            let journal = EditJournal::open(&state_directory, scope.clone(), protector)
                .expect("reopen exact synthetic account/root journal in a new process");
            let recovered = journal
                .recover_all()
                .expect("authenticate the DPAPI-protected record in a new process");
            assert_eq!(recovered.records.len(), 1);
            let record = &recovered.records[0];
            assert_eq!(record.metadata.scope, scope);
            assert_eq!(record.metadata.relative_path, "cloud.bin");
            assert_eq!(record.recovered_state(), super::LocalEditState::Uncertain);
            assert!(record.has_strong_baseline());
            let mut expected = opencloud_payload();
            expected[0] = 0xa5;
            assert_eq!(record.content, expected);
            return;
        }
        if let Some(path) = std::env::var_os(EDIT_PATH_ENV) {
            let mut file = OpenOptions::new()
                .write(true)
                .open(path)
                .expect("open only the parent-selected synthetic placeholder");
            file.write_all(&[0xa5]).expect("write one synthetic byte");
            file.sync_all().expect("flush the synthetic edit");
            return;
        }

        let (server, worker) = start_opencloud_fixture();
        let client = Arc::new(OpenCloudClient::new(&server, "synthetic-token".into()).unwrap());
        let server_origin = client.server_origin().expect("fixture origin");
        let account_id = canonical_test_account_id(&server_origin, "drive-personal");
        let scope = ProviderScope::new(
            client.as_ref(),
            "synthetic-profile".into(),
            account_id.clone(),
            server_origin.clone(),
        )
        .unwrap();
        let registration = SyntheticRegistration::create().expect("create synthetic root");
        let root_identity = registration
            .root
            .identity_for_test()
            .expect("read the exact owned synthetic root identity");
        let recovery_provider = Arc::new(
            super::DurableEditRecoveryProvider::current_user(scope.clone(), root_identity)
                .expect("prepare durable recovery for the exact account and root"),
        );
        let backend = Arc::new(
            OpenCloudPlaceholderBackend::new_with_identity_catalog(
                client,
                scope.clone(),
                root_identity,
                recovery_provider.identity_catalog(),
            )
            .expect("bind the backend to the exact synthetic root identity"),
        );
        backend
            .register_composite_root_for("drive-personal", "root-id")
            .expect("register the exact discovered Personal/Spaces root");
        let identity = backend
            .register_file("drive-personal", "root-id", "/cloud.bin")
            .expect("register the synthetic ordinary file");
        let recovery =
            super::prepare_root_recovery(&backend, root_identity, recovery_provider.as_ref())
                .expect("prepare exact scoped recovery before Cloud Files callbacks start");
        let original = opencloud_payload();
        let mut provider = super::native::SyntheticConnection::connect_with_opencloud_backend(
            registration.root,
            backend,
            identity.as_bytes().to_vec(),
            original.clone(),
            Some(recovery),
        )
        .expect("connect the identity-scoped synthetic backend");
        assert_eq!(provider.read_opencloud_fixture().unwrap(), original);
        let path = provider
            .owned_fixture_file_path_for_test("synthetic.bin")
            .expect("resolve the owned synthetic placeholder");
        let (root_volume, root_file_index) = provider
            .root_identity_for_test()
            .expect("read the pinned synthetic root identity");
        let (file_volume, file_index) = provider
            .fixture_file_identity_for_test("synthetic.bin")
            .expect("read the pinned synthetic file identity");
        let before = provider.close_observation_for_test();
        let child = Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("tests::modified_opencloud_close_is_dpapi_journaled_and_unregister_stays_blocked")
            .arg("--ignored")
            .arg("--nocapture")
            .env(EDIT_PATH_ENV, &path)
            .status()
            .expect("launch a synthetic user-mode editor process");
        assert!(child.success(), "synthetic editor failed: {child}");

        let deadline = Instant::now() + Duration::from_secs(20);
        while provider.close_observation_for_test().2 == before.2 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        let mut close = provider.close_observation_for_test();
        while close.0 == 0
            && close.1 == 0
            && provider.journaled_close_count_for_test() == 0
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(50));
            close = provider.close_observation_for_test();
        }
        assert!(
            close.0 > 0,
            "the edited placeholder must remain dirty or unresolved; expected_file_id={file_index:#x} last_close_file_id={:#x} observation={close:?}",
            provider.last_close_file_id_for_test()
        );
        assert_eq!(close.1, 0, "the exact placeholder identity must verify");
        assert!(
            provider.journaled_close_count_for_test() > 0,
            "the close callback must durably append the protected record"
        );

        let preserved_root = provider
            .release_registration_for_restart_test()
            .expect("disconnect without unregistering the edited root");
        let protector = DpapiEditRecordProtector::current_user().unwrap();
        let journal_directory = protector.local_state_directory().to_path_buf();
        let journal_scope = EditJournalScope {
            profile_id: "synthetic-profile".into(),
            server_origin,
            account_subject: account_id,
            space_id: "drive-personal".into(),
            root_resource_id: "root-id".into(),
            root_volume_serial: root_volume,
            root_file_index,
        };
        let recovery_child = Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("tests::modified_opencloud_close_is_dpapi_journaled_and_unregister_stays_blocked")
            .arg("--ignored")
            .arg("--nocapture")
            .env(
                RECOVER_SCOPE_ENV,
                serde_json::to_string(&journal_scope).expect("serialize synthetic scope"),
            )
            .status()
            .expect("launch a fresh process for DPAPI journal recovery");
        assert!(
            recovery_child.success(),
            "cross-process DPAPI recovery failed: {recovery_child}"
        );
        let journal = EditJournal::open(&journal_directory, journal_scope, protector)
            .expect("reopen only the exact account/root journal");
        let recovered = journal.recover_all().expect("authenticate local records");
        assert_eq!(recovered.records.len(), 1);
        let record = &recovered.records[0];
        if let Some(export_dir) = std::env::var_os(CROSSUSER_EXPORT_DIR_ENV) {
            let (sealed, associated_data) = journal
                .sealed_record_for_test(&record.metadata.record_id)
                .expect("read only the exact synthetic sealed record");
            let to_hex = |bytes: &[u8]| {
                let mut output = String::with_capacity(bytes.len() * 2);
                for byte in bytes {
                    use std::fmt::Write as _;
                    write!(&mut output, "{byte:02x}").expect("write into String");
                }
                output
            };
            let manifest = serde_json::json!({
                "associated_data_hex": to_hex(&associated_data),
                "sealed_hex": to_hex(&sealed),
            });
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            let path = std::path::PathBuf::from(export_dir).join("sealed-record.json");
            let mut file = options
                .open(path)
                .expect("publish a new synthetic-only ciphertext fixture");
            use std::io::Write as _;
            file.write_all(&serde_json::to_vec(&manifest).unwrap())
                .expect("write the synthetic sealed fixture");
            file.sync_all().expect("flush the synthetic fixture");
        }
        assert_eq!(record.metadata.relative_path, "cloud.bin");
        assert_eq!(
            record.metadata.local_file,
            LocalFileIdentity {
                volume_serial: file_volume,
                file_index,
            }
        );
        assert_eq!(record.recovered_state(), super::LocalEditState::Uncertain);
        assert!(record.has_strong_baseline());
        assert_eq!(
            record.metadata.remote,
            Some(RemoteEditBaseline {
                resource_id: "cloud-file-id".into(),
                etag: "\"cloud-v1\"".into(),
                byte_len: OPEN_CLOUD_PAYLOAD_LEN as u64,
            })
        );
        let mut expected = original;
        expected[0] = 0xa5;
        assert_eq!(record.content, expected);
        assert_eq!(std::fs::read(path).unwrap(), record.content);
        assert!(!preserved_root.as_os_str().is_empty());

        let observations = worker.join().expect("fixture worker remains healthy");
        assert!(
            observations.1 > 0,
            "the synthetic file must be fetched by range"
        );
    }

    /// The isolated Windows VM writes to a hydrated synthetic placeholder,
    /// waits for the native close notification, and proves unregister refuses
    /// to discard the user's bytes. This intentionally preserves that unique
    /// synthetic root as recovery evidence.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires disposable Windows VM with Cloud Files enabled"]
    fn modified_placeholder_close_blocks_unregister_and_retains_bytes() {
        use std::{
            ffi::OsStr,
            fs::OpenOptions,
            process::Command,
            thread,
            time::{Duration, Instant},
        };

        const EDIT_PATH_ENV: &str = "RAIUN_CLOUDFILES_SYNTHETIC_EDIT_PATH";
        const REOPEN_ROOT_ENV: &str = "RAIUN_CLOUDFILES_SYNTHETIC_REOPEN_ROOT";
        if let Some(path) = std::env::var_os(REOPEN_ROOT_ENV) {
            let path = std::path::PathBuf::from(path);
            let reopened = SyntheticRegistration::reconnect_for_test(path.clone())
                .expect("reopen the exact private synthetic registration after process restart");
            let observation = reopened.close_observation_for_test();
            assert!(
                observation.0 + observation.1 > 0,
                "reconnect scan must rediscover modified or unclassifiable filesystem state"
            );
            assert_eq!(
                reopened.inner.shutdown(),
                Err(Error::UnresolvedPlaceholderEdits),
                "reconnected provider must refuse unregister without process-local close history"
            );
            let path = path.join("synthetic.bin");
            assert_eq!(
                std::fs::read(path)
                    .expect("edited file must remain available after refused unregister"),
                b"synthetic user edit that must survive provider disconnect"
            );
            return;
        }
        if let Some(path) = std::env::var_os(EDIT_PATH_ENV) {
            let path = std::path::PathBuf::from(path);
            let parent = path.parent().and_then(std::path::Path::file_name);
            assert_eq!(path.file_name(), Some(OsStr::new("synthetic.bin")));
            assert!(
                parent.is_some_and(|name| name
                    .to_string_lossy()
                    .starts_with("Raiun-CfApi-Synthetic-"))
            );
            let edited = b"synthetic user edit that must survive provider disconnect";
            let mut file = OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open the exact private synthetic placeholder as a separate user process");
            file.write_all(edited).expect("write synthetic user edit");
            file.set_len(edited.len() as u64)
                .expect("set edited length");
            file.sync_all().expect("flush synthetic user edit");
            return;
        }

        let registration = SyntheticRegistration::create().expect("create owned test root");
        let mut provider = registration.connect().expect("connect test callbacks");
        let initial = provider
            .read_payload()
            .expect("hydrate synthetic placeholder");
        assert_eq!(initial.len(), 4096);
        let path = provider
            .owned_fixture_file_path_for_test("synthetic.bin")
            .expect("resolve only the known owned fixture path");
        let before = provider.close_observation_for_test();
        let edited = b"synthetic user edit that must survive provider disconnect";
        let child = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("tests::modified_placeholder_close_blocks_unregister_and_retains_bytes")
            .arg("--ignored")
            .arg("--nocapture")
            .env(EDIT_PATH_ENV, &path)
            .status()
            .expect("launch separate synthetic user process");
        assert!(
            child.success(),
            "synthetic user edit process failed: {child}"
        );

        let deadline = Instant::now() + Duration::from_secs(15);
        let mut observation = provider.close_observation_for_test();
        while observation.2 == before.2 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
            observation = provider.close_observation_for_test();
        }
        assert!(
            observation.2 > before.2,
            "Cloud Files close callback was not observed: before={before:?} after={observation:?}"
        );
        assert!(matches!(observation.3, 8 | 12));
        // This legacy fixture uses a synthetic backend with no authenticated
        // account binding, so journaling is intentionally unavailable. The
        // close callback must still retain an unresolved blocker rather than
        // treating the edit as clean; the OpenCloud-backed test below covers
        // durable account-scoped journal creation.
        assert!(
            observation.0 + observation.1 > 0,
            "modified or unverifiable data must remain a destructive-operation blocker: {observation:?}"
        );
        let root = provider
            .release_registration_for_restart_test()
            .expect("release process-owned handles but preserve the OS registration");
        assert_eq!(
            std::fs::read(&path).expect("edited file survives ordinary disconnect"),
            edited
        );
        let restarted = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("tests::modified_placeholder_close_blocks_unregister_and_retains_bytes")
            .arg("--ignored")
            .arg("--nocapture")
            .env(REOPEN_ROOT_ENV, &root)
            .status()
            .expect("launch a new provider process to simulate app restart");
        assert!(
            restarted.success(),
            "restart scan failed to preserve dirty bytes and refuse unregister: {restarted}"
        );
        assert_eq!(
            provider.shutdown(),
            Err(Error::UnresolvedPlaceholderEdits),
            "unregister must fail closed while edited bytes have no recovery path"
        );
        assert_eq!(
            std::fs::read(&path).expect("edited file remains available for recovery"),
            edited
        );
    }

    #[cfg(windows)]
    fn opencloud_payload() -> Vec<u8> {
        opencloud_payload_for_len(OPEN_CLOUD_PAYLOAD_LEN)
    }

    #[cfg(windows)]
    fn opencloud_payload_for_len(length: usize) -> Vec<u8> {
        (0..length).map(|index| (index % 251) as u8).collect()
    }

    #[cfg(windows)]
    fn canonical_test_account_id(server_origin: &str, personal_space_id: &str) -> String {
        format!("{server_origin}\0{personal_space_id}")
            .bytes()
            .fold(String::new(), |mut encoded, byte| {
                use std::fmt::Write;
                write!(encoded, "{byte:02x}").expect("append account-id byte");
                encoded
            })
    }

    #[cfg(windows)]
    fn start_opencloud_fixture() -> (String, thread::JoinHandle<(usize, usize, u64)>) {
        start_opencloud_fixture_with_payload_len(OPEN_CLOUD_PAYLOAD_LEN)
    }

    #[cfg(windows)]
    fn start_opencloud_fixture_with_payload_len(
        payload_len: usize,
    ) -> (String, thread::JoinHandle<(usize, usize, u64)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut requests = 0;
            let mut ranges = 0;
            let mut range_bytes = 0;
            let mut idle = 0;
            let mut request_number = 0;
            while idle < 600 {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => {
                        idle = 0;
                        value
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        idle += 1;
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(error) => panic!("local DAV fixture accept failed: {error}"),
                };
                request_number += 1;
                let accepted_at = Instant::now();
                // Windows accepted sockets inherit nonblocking mode from the
                // listener, but this bounded fixture reads full requests.
                stream
                    .set_nonblocking(false)
                    .expect("fixture stream should be blocking");
                let request = read_http_request(&mut stream);
                let request_line = request.lines().next().unwrap_or("<empty>");
                eprintln!(
                    "synthetic DAV request #{request_number} headers_read_ms={} line={request_line}",
                    accepted_at.elapsed().as_millis()
                );
                let (status, headers, body, content_type) = opencloud_response(
                    &request,
                    address,
                    payload_len,
                    &mut ranges,
                    &mut range_bytes,
                );
                if let Err(error) = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\n{headers}Connection: close\r\n\r\n",
                    body.len()
                ) {
                    eprintln!(
                        "synthetic DAV response header failed request=#{request_number} after_ms={} error={error:?}",
                        accepted_at.elapsed().as_millis()
                    );
                    break;
                }
                if let Err(error) = stream.write_all(&body) {
                    eprintln!(
                        "synthetic DAV response body failed request=#{request_number} bytes={} after_ms={} error={error:?}",
                        body.len(),
                        accepted_at.elapsed().as_millis()
                    );
                    break;
                }
                eprintln!(
                    "synthetic DAV response sent request=#{request_number} status={status} bytes={} elapsed_ms={}",
                    body.len(),
                    accepted_at.elapsed().as_millis()
                );
                requests += 1;
            }
            (requests, ranges, range_bytes)
        });
        (format!("http://{address}"), worker)
    }

    #[cfg(windows)]
    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut chunk = [0; 4096];
        let header_end = loop {
            if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                let end = position + 4;
                assert!(end <= 32 * 1024);
                break end;
            }
            assert!(bytes.len() <= 32 * 1024);
            let count = stream.read(&mut chunk).unwrap();
            assert_ne!(count, 0, "fixture request ended before its headers");
            bytes.extend_from_slice(&chunk[..count]);
            assert!(bytes.len() <= 32 * 1024 + chunk.len());
        };
        let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
        let body_len = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        assert!(body_len <= 32 * 1024);
        let request_len = header_end + body_len;
        while bytes.len() < request_len {
            let count = stream.read(&mut chunk).unwrap();
            assert_ne!(count, 0, "fixture request body ended early");
            bytes.extend_from_slice(&chunk[..count]);
            assert!(bytes.len() <= request_len + chunk.len());
        }
        headers
    }

    #[cfg(windows)]
    fn opencloud_response(
        request: &str,
        address: std::net::SocketAddr,
        payload_len: usize,
        ranges: &mut usize,
        range_bytes: &mut u64,
    ) -> (&'static str, String, Vec<u8>, &'static str) {
        let target = request.split_whitespace().nth(1).unwrap_or_default();
        if request.starts_with("GET /graph/") {
            let body = format!(
                r#"{{"value":[{{"id":"drive-personal","name":"Personal","driveType":"personal","root":{{"id":"root-id","webDavUrl":"http://{address}/dav/personal/"}}}}]}}"#
            );
            return (
                "200 OK",
                String::new(),
                body.into_bytes(),
                "application/json",
            );
        }
        if request.starts_with("PROPFIND ") {
            let (href, xml) = if target == "/dav/personal/" {
                (
                    "/dav/personal/",
                    r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>root-v1</d:getetag><oc:fileid>root-id</oc:fileid></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_string(),
                )
            } else {
                (
                    "/dav/personal/cloud.bin",
                    format!(
                        r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/cloud.bin</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>{payload_len}</d:getcontentlength><d:getetag>"cloud-v1"</d:getetag><oc:fileid>cloud-file-id</oc:fileid></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#
                    ),
                )
            };
            let _ = href;
            return (
                "207 Multi-Status",
                String::new(),
                xml.into_bytes(),
                "application/xml",
            );
        }
        if request.starts_with("GET /dav/personal/cloud.bin") {
            let lower = request.to_ascii_lowercase();
            assert!(lower.contains("if-match: \"cloud-v1\""));
            let range = lower
                .lines()
                .find_map(|line| line.strip_prefix("range: bytes="))
                .expect("range header");
            let (start, end) = range.split_once('-').expect("range bounds");
            let start = start.parse::<usize>().unwrap();
            let end = end.parse::<usize>().unwrap();
            assert!(start <= end && end < payload_len);
            let body = (start..=end)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            *ranges += 1;
            *range_bytes += body.len() as u64;
            return (
                "206 Partial Content",
                format!(
                    "ETag: \"cloud-v1\"\r\nContent-Range: bytes {start}-{end}/{payload_len}\r\nAccept-Ranges: bytes\r\n"
                ),
                body,
                "application/octet-stream",
            );
        }
        panic!("unexpected request to synthetic DAV fixture: {request}");
    }
}

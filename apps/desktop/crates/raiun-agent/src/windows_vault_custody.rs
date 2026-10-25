//! Protected write-ahead metadata service, not native recovery authority.
//! Root membership precedes child creation and every publication precedes its
//! protected CAS. Missing legacy manifests/children are never adopted or healed.
use super::{
    SessionStore,
    root_manifest::{RootBinding, RootManifest},
    vault_custody::{self, Custody, Entry, Scope},
    vault_edit_capture as capture, vault_edit_retention, vault_edit_upload as upload,
    windows_vault_close_worker::{FreshVaultCloseJob, VaultClosePublisher},
};
use raiun_cloudfiles_windows::vault_custody::{
    ExistingVaultEditBaseline, ExistingVaultEditPayload, VaultCatalogueEntry, VaultHydrationIntent,
    VaultPublicationCustody, VaultPublishedHistorySource,
};
use raiun_cloudfiles_windows::{
    BackendError, ConfiguredRootIdentity, DeferredVaultCaptureNotification,
    FreshVaultCaptureDispatch, ProviderScope, VaultCustodyRootContext,
};
use raiun_core::backend::RemoteEntry;
use raiun_vault::session::VaultSessionScope;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, Weak},
};
use zeroize::Zeroizing;

const REFUSED: &str = "Protected vault custody is unavailable or changed";
type Result<T> = std::result::Result<T, String>;
fn refused() -> String {
    REFUSED.into()
}
fn unavailable<T>(_: T) -> BackendError {
    BackendError::Unavailable
}

trait Storage: Send + Sync {
    fn load(&self, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn cas(&self, key: &[u8], old: Option<&[u8]>, next: &[u8]) -> Result<()>;
    fn load_capture(&self, _key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Err(refused())
    }
    fn put_new_capture(&self, _key: &[u8], _record: &[u8]) -> Result<()> {
        Err(refused())
    }
}
struct SessionStorage(Arc<dyn SessionStore>);
impl Storage for SessionStorage {
    fn load_capture(&self, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.0.load_vault_existing_edit_capture(key)
    }
    fn put_new_capture(&self, key: &[u8], record: &[u8]) -> Result<()> {
        self.0.put_new_vault_existing_edit_capture(key, record)
    }
    fn load(&self, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.0.load_vault_custody(key)
    }
    fn cas(&self, key: &[u8], old: Option<&[u8]>, next: &[u8]) -> Result<()> {
        self.0.compare_exchange_vault_custody(key, old, next)
    }
}
struct ProtectedStore(Arc<dyn Storage>);
struct CaptureStore(Arc<dyn Storage>);
impl capture::Store for CaptureStore {
    fn load(
        &self,
        domain: &[u8],
        binding: &[u8],
    ) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, capture::Error> {
        if domain != capture::DOMAIN {
            return Err(capture::Error::Foreign);
        }
        self.0
            .load_capture(binding)
            .map_err(|_| capture::Error::Persistence)
    }
    fn put_new(
        &self,
        domain: &[u8],
        binding: &[u8],
        record: &[u8],
    ) -> std::result::Result<capture::PutNew, capture::Error> {
        if domain != capture::DOMAIN {
            return Err(capture::Error::Foreign);
        }
        if self
            .0
            .load_capture(binding)
            .map_err(|_| capture::Error::Persistence)?
            .is_some()
        {
            return Ok(capture::PutNew::AlreadyExists);
        }
        // A race or post-publication failure remains uncertain, never success.
        self.0
            .put_new_capture(binding, record)
            .map_err(|_| capture::Error::Persistence)?;
        Ok(capture::PutNew::Created)
    }
}

impl super::root_manifest::Store for ProtectedStore {
    fn load(
        &self,
        key: &[u8],
    ) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, vault_custody::Error> {
        self.0
            .load(key)
            .map_err(|_| vault_custody::Error::Persistence)
    }
    fn compare_exchange(
        &self,
        key: &[u8],
        old: Option<&[u8]>,
        next: &[u8],
    ) -> std::result::Result<(), vault_custody::Error> {
        self.0
            .cas(key, old, next)
            .map_err(|_| vault_custody::Error::Persistence)
    }
}
fn child_key(scope: &Scope) -> std::result::Result<Vec<u8>, vault_custody::Error> {
    let full = scope.authenticated_store_binding()?;
    let mut key = b"raiun-vault-custody-child-v1\0".to_vec();
    key.extend_from_slice(&Sha256::digest(full.as_slice()));
    Ok(key)
}
impl vault_custody::Store for ProtectedStore {
    fn load(
        &self,
        scope: &Scope,
    ) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, vault_custody::Error> {
        self.0
            .load(&child_key(scope)?)
            .map_err(|_| vault_custody::Error::Persistence)
    }
    fn compare_exchange(
        &self,
        scope: &Scope,
        old: Option<&[u8]>,
        next: &[u8],
    ) -> std::result::Result<(), vault_custody::Error> {
        self.0
            .cas(&child_key(scope)?, old, next)
            .map_err(|_| vault_custody::Error::Persistence)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountFields {
    profile: String,
    server: String,
    client: String,
    issuer: Option<String>,
    subject: String,
}

struct Child {
    custody: Mutex<Custody>,
    failed: std::sync::atomic::AtomicBool,
}
struct State {
    manifest: RootManifest,
    children: BTreeMap<Vec<u8>, Arc<Child>>,
    failed: bool,
}
/// Local source-instance locator, not upload authority. The marker is the
/// broker's existing failure flag, not an independently minted identity.
pub(super) struct FreshCaptureOrigin {
    owner: ProviderScope,
    root: ConfiguredRootIdentity,
    broker: Weak<std::sync::atomic::AtomicBool>,
}
impl FreshCaptureOrigin {
    pub(super) fn owner(&self) -> &ProviderScope {
        &self.owner
    }
    pub(super) fn root(&self) -> ConfiguredRootIdentity {
        self.root
    }
}

struct FreshCloseNotification {
    publisher: VaultClosePublisher,
    job: FreshVaultCloseJob,
}
impl DeferredVaultCaptureNotification for FreshCloseNotification {
    fn try_publish(self: Box<Self>) -> std::result::Result<(), BackendError> {
        // Called only after the native callback and every publication/storage
        // guard has ended. No lookup, persistence, auth or HTTP is permitted.
        let Self { publisher, job } = *self;
        publisher
            .try_send(job)
            .map_err(|_| BackendError::Unavailable)
    }
}

/// This service is scoped to one exact provider generation and native root.
/// It owns no native handles and cannot clear incomplete history. The broker
/// must retain/revalidate its root and publication/session fences independently.
pub(super) struct WindowsVaultCustody {
    account: Zeroizing<Vec<u8>>,
    owner: ProviderScope,
    root: ConfiguredRootIdentity,
    registration: String,
    store: ProtectedStore,
    state: Mutex<State>,
    failed: Arc<std::sync::atomic::AtomicBool>,
    fresh_close_publisher: Option<VaultClosePublisher>,
}
impl WindowsVaultCustody {
    pub(super) fn prepare(
        store: Arc<dyn SessionStore>,
        account: &[u8],
        context: &VaultCustodyRootContext<'_>,
    ) -> Result<Arc<Self>> {
        Self::prepare_with_fresh_close_publisher(store, account, context, None)
    }
    pub(super) fn prepare_with_fresh_close_publisher(
        store: Arc<dyn SessionStore>,
        account: &[u8],
        context: &VaultCustodyRootContext<'_>,
        publisher: Option<VaultClosePublisher>,
    ) -> Result<Arc<Self>> {
        if publisher
            .as_ref()
            .is_some_and(|source| source.generation() == 0)
        {
            return Err(refused());
        }
        context.revalidate().map_err(|_| refused())?;
        let root = context.root_identity();
        let binding = RootBinding::new(
            account,
            root.volume_serial,
            root.file_index,
            context.registration_binding(),
        )
        .map_err(|_| refused())?;
        let fields: AccountFields = serde_json::from_slice(account).map_err(|_| refused())?;
        let owner = context.provider_scope();
        if store.bound_profile() != Some(owner.profile_id())
            || fields.profile != owner.profile_id()
            || fields.subject != owner.account_id()
            || url::Url::parse(&fields.server)
                .map_err(|_| refused())?
                .origin()
                .ascii_serialization()
                != owner.server_origin()
            || owner.token_generation() == 0
        {
            return Err(refused());
        }
        // RootBinding validated all canonical account fields, including client/issuer.
        let _ = (&fields.client, &fields.issuer);
        let store = ProtectedStore(Arc::new(SessionStorage(store)));
        let manifest = if context.is_new_registration() {
            RootManifest::initialize_new_registration(&store, &binding)
        } else {
            RootManifest::reopen(&store, &binding)
        }
        .map_err(|_| refused())?;
        // Every indexed child is mandatory. A crash between membership and
        // child CAS remains blocked; no valid snapshot is treated as coverage.
        let mut children = BTreeMap::new();
        for scope in manifest
            .scopes_for_reconciliation()
            .map_err(|_| refused())?
        {
            let child = Custody::reopen(&store, scope).map_err(|_| refused())?;
            children.insert(
                scope
                    .authenticated_store_binding()
                    .map_err(|_| refused())?
                    .to_vec(),
                Arc::new(Child {
                    custody: Mutex::new(child),
                    failed: std::sync::atomic::AtomicBool::new(false),
                }),
            );
        }
        context.revalidate().map_err(|_| refused())?;
        Ok(Arc::new(Self {
            account: Zeroizing::new(account.to_vec()),
            owner: owner.clone(),
            root,
            registration: context.registration_binding().into(),
            store,
            failed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            fresh_close_publisher: publisher,
            state: Mutex::new(State {
                manifest,
                children,
                failed: false,
            }),
        }))
    }
    pub(super) fn matches_fresh_origin(&self, origin: &FreshCaptureOrigin) -> bool {
        origin.owner() == &self.owner
            && origin.root() == self.root
            && Weak::ptr_eq(&origin.broker, &Arc::downgrade(&self.failed))
            && origin
                .broker
                .upgrade()
                .is_some_and(|failed| !failed.load(std::sync::atomic::Ordering::Acquire))
    }
    /// Bounded historical IDs only, with no body or live authority creation.
    #[cfg(test)]
    pub(super) fn retained_capture_ids(
        &self,
        owner: &ProviderScope,
        vault: &VaultSessionScope,
        remote_root: &str,
    ) -> Result<Vec<String>> {
        if *owner != self.owner || self.failed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(refused());
        }
        let scope = Scope::new(
            &self.account,
            vault,
            remote_root,
            self.root.volume_serial,
            self.root.file_index,
            &self.registration,
        )
        .map_err(|_| refused())?;
        let key = scope.authenticated_store_binding().map_err(|_| refused())?;
        let child = {
            let state = self.state.lock().map_err(|_| refused())?;
            if state.failed {
                return Err(refused());
            }
            Arc::clone(state.children.get(key.as_slice()).ok_or_else(refused)?)
        };
        let _guard = child.custody.lock().map_err(|_| refused())?;
        if child.failed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(refused());
        }
        let binding = RootBinding::new(
            &self.account,
            self.root.volume_serial,
            self.root.file_index,
            &self.registration,
        )
        .map_err(|_| refused())?;
        let references = upload::load_capture_references(&self.store, &binding, &scope)
            .map_err(|_| refused())?;
        if self.failed.load(std::sync::atomic::Ordering::Acquire)
            || child.failed.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(refused());
        }
        Ok(references
            .iter()
            .map(|reference| reference.id().to_owned())
            .collect())
    }
    /// Discover only an existing protected capture under this admitted exact
    /// account/provider/root. No root membership or child is created here.
    /// Returned object owns no mutex guard; future HTTP must run outside it.
    pub(super) fn upload_ledger(
        &self,
        owner: &ProviderScope,
        vault: &VaultSessionScope,
        remote_root: &str,
        capture_id: &str,
    ) -> Result<UploadLedger> {
        if *owner != self.owner || self.failed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(refused());
        }
        let scope = Scope::new(
            &self.account,
            vault,
            remote_root,
            self.root.volume_serial,
            self.root.file_index,
            &self.registration,
        )
        .map_err(|_| refused())?;
        let key = scope.authenticated_store_binding().map_err(|_| refused())?;
        let child = {
            let state = self.state.lock().map_err(|_| {
                self.failed
                    .store(true, std::sync::atomic::Ordering::Release);
                refused()
            })?;
            if state.failed {
                return Err(refused());
            }
            Arc::clone(state.children.get(key.as_slice()).ok_or_else(refused)?)
        };
        if child.failed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(refused());
        }
        let root_binding = RootBinding::new(
            &self.account,
            self.root.volume_serial,
            self.root.file_index,
            &self.registration,
        )
        .map_err(|_| refused())?;
        let reference =
            upload::load_capture_reference(&self.store, &root_binding, &scope, capture_id)
                .map_err(|_| refused())?;
        Ok(UploadLedger {
            root_binding,
            scope,
            reference,
            store: ProtectedStore(Arc::clone(&self.store.0)),
            root_failed: Arc::clone(&self.failed),
            child,
        })
    }
    pub(super) fn view(
        &self,
        owner: &ProviderScope,
        vault: &VaultSessionScope,
        remote_root: &str,
    ) -> Result<Arc<dyn VaultPublicationCustody>> {
        if *owner != self.owner {
            return Err(refused());
        }
        let scope = Scope::new(
            &self.account,
            vault,
            remote_root,
            self.root.volume_serial,
            self.root.file_index,
            &self.registration,
        )
        .map_err(|_| refused())?;
        let key = scope
            .authenticated_store_binding()
            .map_err(|_| refused())?
            .to_vec();
        let mut state = self.state.lock().map_err(|_| {
            self.failed
                .store(true, std::sync::atomic::Ordering::Release);
            refused()
        })?;
        if state.failed || self.failed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(refused());
        }
        let added = match state.manifest.register(&self.store, &scope) {
            Ok(added) => added,
            Err(_) => {
                state.failed = true;
                self.failed
                    .store(true, std::sync::atomic::Ordering::Release);
                return Err(refused());
            }
        };
        let child = if let Some(child) = state.children.get(&key) {
            if added {
                state.failed = true;
                self.failed
                    .store(true, std::sync::atomic::Ordering::Release);
                return Err(refused());
            }
            Arc::clone(child)
        } else {
            let child = if added {
                Custody::initialize_new_scope(&self.store, scope.clone())
            } else {
                Custody::reopen(&self.store, &scope)
            };
            let child = match child {
                Ok(child) => child,
                Err(_) => {
                    state.failed = true;
                    self.failed
                        .store(true, std::sync::atomic::Ordering::Release);
                    return Err(refused());
                }
            };
            let child = Arc::new(Child {
                custody: Mutex::new(child),
                failed: std::sync::atomic::AtomicBool::new(false),
            });
            state.children.insert(key, Arc::clone(&child));
            child
        };
        Ok(Arc::new(View {
            root_failed: Arc::clone(&self.failed),
            account: Zeroizing::new(self.account.to_vec()),
            registration: self.registration.clone(),
            scope,
            owner: self.owner.clone(),
            root: self.root,
            store: ProtectedStore(Arc::clone(&self.store.0)),
            child,
            fresh_close_publisher: self.fresh_close_publisher.clone(),
        }))
    }
}
/// Read-only synthetic acceptance view. No registration, adoption or writes.
#[cfg(test)]
pub(super) struct CaptureInspection {
    pub entries: Vec<Entry>,
    pub hydrations: Vec<vault_custody::Hydration>,
    pub captures: Vec<(capture::RetainedEdit, Entry)>,
}
#[cfg(test)]
impl WindowsVaultCustody {
    pub(super) fn inspect_capture_for_test(
        &self,
        vault: &VaultSessionScope,
        remote_root: &str,
    ) -> Result<CaptureInspection> {
        let binding = RootBinding::new(
            &self.account,
            self.root.volume_serial,
            self.root.file_index,
            &self.registration,
        )
        .map_err(|_| refused())?;
        let scope = Scope::new(
            &self.account,
            vault,
            remote_root,
            self.root.volume_serial,
            self.root.file_index,
            &self.registration,
        )
        .map_err(|_| refused())?;
        let mut manifest = RootManifest::reopen(&self.store, &binding).map_err(|_| refused())?;
        if !manifest
            .scopes_for_reconciliation()
            .map_err(|_| refused())?
            .contains(&scope)
        {
            return Err(refused());
        }
        let child = Custody::reopen(&self.store, &scope).map_err(|_| refused())?;
        let mut captures = Vec::new();
        for reference in child.captures_for_reconciliation() {
            let id = capture::CaptureId::new(reference.id()).map_err(|_| refused())?;
            let retained =
                capture::reopen_for_recovery(&CaptureStore(Arc::clone(&self.store.0)), &scope, &id)
                    .map_err(|_| refused())?;
            if retained.encoded_frame_ref() != reference.frame() {
                return Err(refused());
            }
            captures.push((retained, reference.entry().clone()));
        }
        manifest
            .verify_current(&self.store)
            .map_err(|_| refused())?;
        Ok(CaptureInspection {
            entries: child.entries_for_reconciliation().to_vec(),
            hydrations: child.hydrations_for_reconciliation().to_vec(),
            captures,
        })
    }
}
/// Called only after exclusive CfConnect and before Ready or fresh view exposure.
/// Reopening every document closes the previous-provider snapshot race. The
/// resulting retained intents are evidence, not native identity/range authority.
impl VaultPublishedHistorySource for WindowsVaultCustody {
    fn snapshot(
        &self,
        owner: &ProviderScope,
        root: ConfiguredRootIdentity,
        registration: &str,
    ) -> std::result::Result<Vec<VaultHydrationIntent>, BackendError> {
        if *owner != self.owner || root != self.root || registration != self.registration {
            return Err(BackendError::Unavailable);
        }
        let mut state = self.state.lock().map_err(|_| {
            self.failed
                .store(true, std::sync::atomic::Ordering::Release);
            BackendError::Unavailable
        })?;
        if state.failed || self.failed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(BackendError::Unavailable);
        }
        let result = (|| -> Result<_> {
            if state
                .children
                .values()
                .any(|child| child.failed.load(std::sync::atomic::Ordering::Acquire))
            {
                return Err(refused());
            }
            let binding = RootBinding::new(
                &self.account,
                root.volume_serial,
                root.file_index,
                registration,
            )
            .map_err(|_| refused())?;
            let mut manifest =
                RootManifest::reopen(&self.store, &binding).map_err(|_| refused())?;
            let mut children = BTreeMap::new();
            let mut intents: Vec<VaultHydrationIntent> = Vec::new();
            let mut identities = std::collections::BTreeSet::new();
            let mut files = std::collections::BTreeSet::new();
            let mut paths = std::collections::BTreeSet::new();
            for scope in manifest
                .scopes_for_reconciliation()
                .map_err(|_| refused())?
            {
                let child = Custody::reopen(&self.store, scope).map_err(|_| refused())?;
                for row in child.publication_history().map_err(|_| refused())? {
                    if intents.len() == 100_000
                        || !identities.insert(row.opaque())
                        || !files.insert(row.file_index())
                        || !paths.insert(
                            row.components()
                                .iter()
                                .map(|c| c.to_lowercase())
                                .collect::<Vec<_>>(),
                        )
                    {
                        return Err(refused());
                    }
                    intents.push(VaultHydrationIntent {
                        root,
                        identity: row.opaque(),
                        file_index: row.file_index(),
                        length: row.length(),
                        components: row.components().to_vec(),
                    });
                }
                children.insert(
                    scope
                        .authenticated_store_binding()
                        .map_err(|_| refused())?
                        .to_vec(),
                    Arc::new(Child {
                        custody: Mutex::new(child),
                        failed: std::sync::atomic::AtomicBool::new(false),
                    }),
                );
            }
            manifest
                .verify_current(&self.store)
                .map_err(|_| refused())?;
            Ok((manifest, children, intents))
        })();
        match result {
            Ok((manifest, children, intents)) => {
                state.manifest = manifest;
                state.children = children;
                Ok(intents)
            }
            Err(_) => {
                state.failed = true;
                self.failed
                    .store(true, std::sync::atomic::Ordering::Release);
                Err(BackendError::Unavailable)
            }
        }
    }
}

/// Trusted local ledger/body seam for a future separately fenced broker worker.
/// No current-user/profile lookup, session/network callback or lock guard escapes.
pub(super) struct UploadLedger {
    root_binding: RootBinding,
    scope: Scope,
    reference: vault_custody::CaptureRef,
    store: ProtectedStore,
    root_failed: Arc<std::sync::atomic::AtomicBool>,
    child: Arc<Child>,
}
impl UploadLedger {
    fn check(&self) -> std::result::Result<(), upload::Error> {
        if self.root_failed.load(std::sync::atomic::Ordering::Acquire)
            || self.child.failed.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(upload::Error::Persistence);
        }
        Ok(())
    }
    fn with_ledger<T>(
        &self,
        operation: impl FnOnce(
            &upload::CustodyLedger<'_, ProtectedStore>,
        ) -> std::result::Result<T, upload::Error>,
    ) -> std::result::Result<T, upload::Error> {
        let result = (|| {
            self.check()?;
            let mut cached = self
                .child
                .custody
                .lock()
                .map_err(|_| upload::Error::Persistence)?;
            self.check()?;
            let ledger = upload::CustodyLedger::admit(
                &self.store,
                &self.root_binding,
                &self.scope,
                &self.reference,
            )?;
            let result = operation(&ledger)?;
            let fresh = Custody::reopen(&self.store, &self.scope)
                .map_err(|_| upload::Error::Persistence)?;
            fresh
                .load_upload_attempt(&self.reference)
                .map_err(|_| upload::Error::Persistence)?;
            self.check()?;
            *cached = fresh;
            Ok(result)
        })();
        if result.is_err() {
            self.child
                .failed
                .store(true, std::sync::atomic::Ordering::Release);
        }
        result
    }
    /// Fresh local protected-context check only; all mutexes are released
    /// before return. Physical root/account/session leases belong to the worker.
    pub(super) fn verify_current(&self) -> std::result::Result<(), upload::Error> {
        self.with_ledger(|_| Ok(()))
    }
    pub(super) fn scope(&self) -> &Scope {
        &self.scope
    }
    pub(super) fn reference(&self) -> &vault_custody::CaptureRef {
        &self.reference
    }
    pub(super) fn initialize_attempt(
        &self,
    ) -> std::result::Result<upload::UploadAttempt, upload::Error> {
        upload::UploadAttempt::initialize(
            self,
            &CaptureStore(Arc::clone(&self.store.0)),
            &self.scope,
            &self.reference,
            self.reference.entry(),
        )
    }
    pub(super) fn reopen_attempt(
        &self,
    ) -> std::result::Result<upload::UploadAttempt, upload::Error> {
        upload::UploadAttempt::reopen(
            self,
            &CaptureStore(Arc::clone(&self.store.0)),
            &self.scope,
            &self.reference,
            self.reference.entry(),
        )
    }
    pub(super) fn read_body(&self) -> std::result::Result<capture::RetainedEdit, upload::Error> {
        self.with_ledger(|ledger| {
            let key = upload::locator(&self.scope, &self.reference)?;
            upload::Store::load(ledger, &key)?;
            let id =
                capture::CaptureId::new(self.reference.id()).map_err(|_| upload::Error::Invalid)?;
            let retained = capture::reopen_for_recovery(
                &CaptureStore(Arc::clone(&self.store.0)),
                &self.scope,
                &id,
            )
            .map_err(|_| upload::Error::Persistence)?;
            if retained.encoded_frame_ref() != self.reference.frame() {
                return Err(upload::Error::Foreign);
            }
            upload::Store::load(ledger, &key)?;
            Ok(retained)
        })
    }
}
impl upload::Store for UploadLedger {
    fn load(&self, key: &[u8]) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, upload::Error> {
        self.with_ledger(|ledger| upload::Store::load(ledger, key))
    }
    fn compare_exchange(
        &self,
        key: &[u8],
        old: Option<&[u8]>,
        next: &[u8],
    ) -> std::result::Result<(), upload::Error> {
        self.with_ledger(|ledger| upload::Store::compare_exchange(ledger, key, old, next))
    }
}

struct View {
    root_failed: Arc<std::sync::atomic::AtomicBool>,
    account: Zeroizing<Vec<u8>>,
    registration: String,
    scope: Scope,
    owner: ProviderScope,
    root: ConfiguredRootIdentity,
    store: ProtectedStore,
    child: Arc<Child>,
    fresh_close_publisher: Option<VaultClosePublisher>,
}
// Deterministic locator only, never authority. Length framing binds each
// trusted field and the edited body digest without retaining plaintext copies.
fn deterministic_capture_id(
    scope: &Scope,
    entry: &Entry,
    baseline: &ExistingVaultEditBaseline,
    payload: &ExistingVaultEditPayload,
) -> std::result::Result<capture::CaptureId, BackendError> {
    let scope = scope.authenticated_store_binding().map_err(unavailable)?;
    let entry = Zeroizing::new(serde_json::to_vec(entry).map_err(unavailable)?);
    let mut hash = Sha256::new();
    let mut field = |bytes: &[u8]| {
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    };
    field(b"raiun-vault-native-existing-edit-capture-id-v1");
    field(&scope);
    field(&entry);
    field(&baseline.unlock_epoch().to_le_bytes());
    field(&baseline.token_generation().to_le_bytes());
    field(&payload.file.volume_serial.to_le_bytes());
    field(&payload.file.file_index.to_le_bytes());
    field(&(payload.bytes.len() as u64).to_le_bytes());
    field(&Sha256::digest(payload.bytes.as_slice()));
    capture::CaptureId::new(&format!("{:x}", hash.finalize())).map_err(unavailable)
}

impl VaultPublicationCustody for View {
    fn retain_existing_edit(
        &self,
        baseline: &ExistingVaultEditBaseline,
        payload: ExistingVaultEditPayload,
        dispatch: FreshVaultCaptureDispatch,
    ) -> std::result::Result<Option<Box<dyn DeferredVaultCaptureNotification>>, BackendError> {
        let result = (|| {
            self.verify_context(baseline.owner(), baseline.vault(), baseline.remote_root())?;
            if baseline.root() != self.root
                || payload.root != self.root
                || payload.file.volume_serial != self.root.volume_serial
                || payload.file.file_index == 0
                || payload.bytes.len() > capture::MAX_BODY_BYTES
                || payload.components.len() > 256
                || payload.components.iter().map(String::len).sum::<usize>() > 32000
                || baseline.metadata().writable
            {
                return Err(BackendError::Unavailable);
            }
            let binding = RootBinding::new(
                &self.account,
                self.root.volume_serial,
                self.root.file_index,
                &self.registration,
            )
            .map_err(unavailable)?;
            // Existing membership only: never call view/register or initialize
            // a child from a native callback, even when storage is missing.
            let mut manifest = RootManifest::reopen(&self.store, &binding).map_err(unavailable)?;
            if !manifest
                .scopes_for_reconciliation()
                .map_err(unavailable)?
                .contains(&self.scope)
            {
                return Err(BackendError::Unavailable);
            }
            manifest.verify_current(&self.store).map_err(unavailable)?;
            let mut cached = self.child.custody.lock().map_err(unavailable)?;
            self.verify_context(baseline.owner(), baseline.vault(), baseline.remote_root())?;
            let mut child = Custody::reopen(&self.store, &self.scope).map_err(unavailable)?;
            let metadata = baseline.metadata();
            let expected = Entry::new(
                baseline.identity(),
                &metadata.id,
                &metadata.path,
                &metadata.etag,
                metadata.directory,
                metadata.size,
            )
            .map_err(unavailable)?;
            if !child.entries_for_reconciliation().contains(&expected) {
                return Err(BackendError::Unavailable);
            }
            let id = deterministic_capture_id(&self.scope, &expected, baseline, &payload)?;
            let original = capture::Baseline::new(
                baseline.identity(),
                &metadata.etag,
                baseline.unlock_epoch(),
                baseline.token_generation(),
                payload.file.volume_serial,
                payload.file.file_index,
            )
            .map_err(unavailable)?;
            let prepared = capture::PreparedCapture::new(&self.scope, &id, original, payload.bytes)
                .map_err(unavailable)?;
            let capture_id = prepared.id().to_owned();
            // Service matches the exact persisted hydration file/components and
            // enrolls the full immutable frame before any protected body put.
            let outcome = vault_edit_retention::retain_indexed(
                &self.store,
                &mut child,
                &CaptureStore(Arc::clone(&self.store.0)),
                prepared,
                &payload.components,
            )
            .map_err(unavailable)?;
            manifest.verify_current(&self.store).map_err(unavailable)?;
            self.verify_context(baseline.owner(), baseline.vault(), baseline.remote_root())?;
            *cached = child;
            // No guard or body escapes. Only a genuinely new acknowledged
            // publication can supply a live-close locator to the deferred sink.
            drop(cached);
            if outcome != vault_edit_retention::RetentionOutcome::New {
                return Ok(None);
            }
            let Some(publisher) = self.fresh_close_publisher.as_ref() else {
                return Ok(None);
            };
            let job = FreshVaultCloseJob {
                origin: FreshCaptureOrigin {
                    owner: self.owner.clone(),
                    root: self.root,
                    broker: Arc::downgrade(&self.root_failed),
                },
                vault: baseline.vault().clone(),
                remote_root: baseline.remote_root().to_owned(),
                capture_id,
                dispatch,
                expected_generation: publisher.generation(),
            };
            Ok(Some(Box::new(FreshCloseNotification {
                publisher: publisher.clone(),
                job,
            })
                as Box<dyn DeferredVaultCaptureNotification>))
        })();
        if result.is_err() {
            // Includes uncertainty after publication. Retain every protected
            // row/body and native dirty file; never acknowledge or roll back.
            self.child
                .failed
                .store(true, std::sync::atomic::Ordering::Release);
        }
        result
    }
    fn root_identity(&self) -> ConfiguredRootIdentity {
        self.root
    }
    fn verify_context(
        &self,
        owner: &ProviderScope,
        vault: &VaultSessionScope,
        remote_root: &str,
    ) -> std::result::Result<(), BackendError> {
        if *owner != self.owner
            || self.root_failed.load(std::sync::atomic::Ordering::Acquire)
            || self.child.failed.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(BackendError::Unavailable);
        }
        // Reconstruct from the captured full scope, never from callback-supplied account bytes.
        let actual = Scope::new(
            &self.account,
            vault,
            remote_root,
            self.root.volume_serial,
            self.root.file_index,
            &self.registration,
        )
        .map_err(unavailable)?;
        if actual != self.scope {
            return Err(BackendError::Unavailable);
        }
        Ok(())
    }
    fn catalogue_snapshot(&self) -> std::result::Result<Vec<VaultCatalogueEntry>, BackendError> {
        if self.root_failed.load(std::sync::atomic::Ordering::Acquire)
            || self.child.failed.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(BackendError::Unavailable);
        }
        let child = self.child.custody.lock().map_err(unavailable)?;
        if self.root_failed.load(std::sync::atomic::Ordering::Acquire)
            || self.child.failed.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(BackendError::Unavailable);
        }
        Ok(child
            .entries_for_reconciliation()
            .iter()
            .map(|entry| VaultCatalogueEntry {
                identity: entry.opaque(),
                metadata: RemoteEntry {
                    id: entry.remote_id().into(),
                    path: entry.root_relative_path().into(),
                    directory: entry.is_directory(),
                    size: entry.length(),
                    etag: entry.etag().into(),
                    modified_unix: 0,
                    writable: false,
                    encrypted: true,
                },
            })
            .collect())
    }
    fn persist_catalogue(
        &self,
        entries: &[VaultCatalogueEntry],
    ) -> std::result::Result<(), BackendError> {
        if self.root_failed.load(std::sync::atomic::Ordering::Acquire)
            || self.child.failed.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(BackendError::Unavailable);
        }
        if entries.len() > vault_custody::MAX_CATALOGUE {
            self.child
                .failed
                .store(true, std::sync::atomic::Ordering::Release);
            return Err(BackendError::Unavailable);
        }
        let entries = entries
            .iter()
            .map(|entry| {
                Entry::new(
                    entry.identity,
                    &entry.metadata.id,
                    &entry.metadata.path,
                    &entry.metadata.etag,
                    entry.metadata.directory,
                    entry.metadata.size,
                )
            })
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| {
                self.child
                    .failed
                    .store(true, std::sync::atomic::Ordering::Release);
                BackendError::Unavailable
            })?;
        let mut child = self.child.custody.lock().map_err(unavailable)?;
        if self.root_failed.load(std::sync::atomic::Ordering::Acquire)
            || self.child.failed.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(BackendError::Unavailable);
        }
        let result = child
            .record_entries(&self.store, &entries)
            .map_err(unavailable);
        if result.is_err() {
            self.child
                .failed
                .store(true, std::sync::atomic::Ordering::Release);
        }
        result
    }
    fn persist_hydration(
        &self,
        intent: &VaultHydrationIntent,
    ) -> std::result::Result<(), BackendError> {
        if self.root_failed.load(std::sync::atomic::Ordering::Acquire)
            || self.child.failed.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(BackendError::Unavailable);
        }
        if intent.root != self.root
            || intent.components.len() > 256
            || intent.components.iter().map(String::len).sum::<usize>() > 32000
        {
            self.child
                .failed
                .store(true, std::sync::atomic::Ordering::Release);
            return Err(BackendError::Unavailable);
        }
        let mut child = self.child.custody.lock().map_err(unavailable)?;
        if self.root_failed.load(std::sync::atomic::Ordering::Acquire)
            || self.child.failed.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(BackendError::Unavailable);
        }
        let result = child
            .persist_hydration_intent(
                &self.store,
                intent.identity,
                intent.file_index,
                intent.length,
                intent.components.clone(),
            )
            .map_err(unavailable);
        if result.is_err() {
            self.child
                .failed
                .store(true, std::sync::atomic::Ordering::Release);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    type Records = BTreeMap<Vec<u8>, Vec<u8>>;
    #[derive(Default)]
    struct Memory {
        bytes: Mutex<Records>,
        writes: AtomicUsize,
        fail: AtomicBool,
    }
    impl Storage for Memory {
        fn load(&self, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(self
                .bytes
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .map(Zeroizing::new))
        }
        fn cas(&self, key: &[u8], old: Option<&[u8]>, next: &[u8]) -> Result<()> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(refused());
            }
            let mut bytes = self.bytes.lock().unwrap();
            if bytes.get(key).map(Vec::as_slice) != old {
                return Err(refused());
            }
            bytes.insert(key.to_vec(), next.to_vec());
            self.writes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    fn fixture() -> (
        Arc<Memory>,
        WindowsVaultCustody,
        ProviderScope,
        VaultSessionScope,
    ) {
        let store = Arc::new(Memory::default());
        let protected = ProtectedStore(store.clone());
        let account = raiun_engine::folder_pairs::AccountScope::new(
            "default".into(),
            "https://example.test/".into(),
            "client".into(),
            Some("https://issuer.test/".into()),
            "subject".into(),
        )
        .unwrap();
        let account = serde_json::to_vec(&account).unwrap();
        let client =
            raiun_opencloud::OpenCloudClient::new("https://example.test/", "synthetic".into())
                .unwrap();
        let owner = ProviderScope::new(
            &client,
            "default".into(),
            "subject".into(),
            "https://example.test".into(),
        )
        .unwrap();
        let root = ConfiguredRootIdentity {
            volume_serial: 7,
            file_index: 42,
        };
        let binding = RootBinding::new(&account, 7, 42, "registration").unwrap();
        let manifest = RootManifest::initialize_new_registration(&protected, &binding).unwrap();
        let service = WindowsVaultCustody {
            account: Zeroizing::new(account),
            owner: owner.clone(),
            root,
            registration: "registration".into(),
            store: protected,
            failed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            fresh_close_publisher: None,
            state: Mutex::new(State {
                manifest,
                children: BTreeMap::new(),
                failed: false,
            }),
        };
        let vault =
            VaultSessionScope::new("default", "https://example.test", "space", "vault-root")
                .unwrap();
        (store, service, owner, vault)
    }
    #[test]
    fn fresh_origin_is_exact_broker_instance_owner_root_and_never_revives_failure() {
        let (_, service, _, _) = fixture();
        let origin = FreshCaptureOrigin {
            owner: service.owner.clone(),
            root: service.root,
            broker: Arc::downgrade(&service.failed),
        };
        assert!(service.matches_fresh_origin(&origin));
        let (_, other, _, _) = fixture();
        assert!(!other.matches_fresh_origin(&origin));
        let foreign_root = FreshCaptureOrigin {
            owner: service.owner.clone(),
            root: ConfiguredRootIdentity {
                file_index: service.root.file_index + 1,
                ..service.root
            },
            broker: Arc::downgrade(&service.failed),
        };
        assert!(!service.matches_fresh_origin(&foreign_root));
        let client =
            raiun_opencloud::OpenCloudClient::new("https://example.test/", "synthetic".into())
                .unwrap();
        let foreign_owner = FreshCaptureOrigin {
            owner: ProviderScope::new(
                &client,
                "default".into(),
                "foreign".into(),
                "https://example.test".into(),
            )
            .unwrap(),
            root: service.root,
            broker: Arc::downgrade(&service.failed),
        };
        assert!(!service.matches_fresh_origin(&foreign_owner));
        service.failed.store(true, Ordering::Release);
        assert!(!service.matches_fresh_origin(&origin));
        drop(service);
        assert!(origin.broker.upgrade().is_none());
        assert!(!other.matches_fresh_origin(&origin));
    }
    fn entry(id: u8) -> VaultCatalogueEntry {
        VaultCatalogueEntry {
            identity: [id; 16],
            metadata: RemoteEntry {
                id: "file".into(),
                path: "/1".into(),
                directory: false,
                size: 65537,
                etag: "v1".into(),
                modified_unix: 0,
                writable: false,
                encrypted: true,
            },
        }
    }
    fn intent(service: &WindowsVaultCustody) -> VaultHydrationIntent {
        VaultHydrationIntent {
            root: service.root,
            identity: [1; 16],
            file_index: 99,
            length: 65537,
            components: vec!["Personal".into(), "Travel.vault".into(), "1".into()],
        }
    }
    #[test]
    fn publication_batch_and_intent_survive_reopen_as_evidence() {
        let (store, service, owner, vault) = fixture();
        let view = service.view(&owner, &vault, "/Travel.vault").unwrap();
        view.verify_context(&owner, &vault, "/Travel.vault")
            .unwrap();
        view.persist_catalogue(&[entry(1)]).unwrap();
        view.persist_hydration(&intent(&service)).unwrap();
        let scope = Scope::new(
            &service.account,
            &vault,
            "/Travel.vault",
            7,
            42,
            "registration",
        )
        .unwrap();
        let reopened = Custody::reopen(&ProtectedStore(store), &scope).unwrap();
        assert_eq!(reopened.entries_for_reconciliation().len(), 1);
        assert_eq!(
            reopened.hydrations_for_reconciliation()[0].components(),
            &["Personal", "Travel.vault", "1"]
        );
        let row = &reopened.hydrations_for_reconciliation()[0];
        assert_eq!(row.opaque(), [1; 16]);
        assert_eq!(row.file_index(), 99);
        assert_eq!(row.length(), 65537);
        assert!(reopened.needs_reconciliation());
    }
    #[test]
    fn cached_view_revalidates_manifest_cas_and_missing_child_is_not_healed() {
        let (store, service, owner, vault) = fixture();
        service.view(&owner, &vault, "/Travel.vault").unwrap();
        let retained = service.view(&owner, &vault, "/Travel.vault").unwrap();
        let count = store.writes.load(Ordering::SeqCst);
        service.view(&owner, &vault, "/Travel.vault").unwrap();
        assert_eq!(store.writes.load(Ordering::SeqCst), count + 1);
        store.bytes.lock().unwrap().clear();
        assert!(service.view(&owner, &vault, "/Travel.vault").is_err());
        assert!(retained.persist_catalogue(&[entry(1)]).is_err());
        assert!(service.view(&owner, &vault, "/Travel.vault").is_err());
        let (store, service, owner, vault) = fixture();
        let scope = Scope::new(
            &service.account,
            &vault,
            "/Travel.vault",
            7,
            42,
            "registration",
        )
        .unwrap();
        service
            .state
            .lock()
            .unwrap()
            .manifest
            .register(&service.store, &scope)
            .unwrap();
        let count = store.writes.load(Ordering::SeqCst);
        assert!(service.view(&owner, &vault, "/Travel.vault").is_err());
        assert_eq!(store.writes.load(Ordering::SeqCst), count + 1); // membership CAS only, no child initialization
    }
    #[test]
    fn store_failure_prevents_acknowledgement_and_poisoned_child_snapshot() {
        let (store, service, owner, vault) = fixture();
        let view = service.view(&owner, &vault, "/Travel.vault").unwrap();
        store.fail.store(true, Ordering::SeqCst);
        assert!(view.persist_catalogue(&[entry(1)]).is_err());
        store.fail.store(false, Ordering::SeqCst);
        assert!(view.catalogue_snapshot().is_err());
        assert!(view.persist_catalogue(&[entry(1)]).is_err());
    }
    #[test]
    fn invalid_last_entry_and_foreign_native_root_are_sticky_without_partial_write() {
        let (store, service, owner, vault) = fixture();
        let view = service.view(&owner, &vault, "/Travel.vault").unwrap();
        let count = store.writes.load(Ordering::SeqCst);
        let mut bad = entry(2);
        bad.metadata.path = "/../escape".into();
        assert!(view.persist_catalogue(&[entry(1), bad]).is_err());
        assert_eq!(store.writes.load(Ordering::SeqCst), count);
        assert!(view.catalogue_snapshot().is_err());
        let (_, service, owner, vault) = fixture();
        let view = service.view(&owner, &vault, "/Travel.vault").unwrap();
        view.persist_catalogue(&[entry(1)]).unwrap();
        let mut bad = intent(&service);
        bad.root.file_index += 1;
        assert!(view.persist_hydration(&bad).is_err());
        assert!(view.persist_hydration(&intent(&service)).is_err());
    }
    #[test]
    fn poisoned_manifest_controller_blocks_retained_views() {
        let (_, service, owner, vault) = fixture();
        let retained = service.view(&owner, &vault, "/Travel.vault").unwrap();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = service.state.lock().unwrap();
            panic!("synthetic state poison");
        }));
        assert!(caught.is_err());
        assert!(service.view(&owner, &vault, "/Travel.vault").is_err());
        assert!(retained.persist_catalogue(&[entry(1)]).is_err());
        assert!(
            retained
                .verify_context(&owner, &vault, "/Travel.vault")
                .is_err()
        );
    }
    #[test]
    fn owner_generation_foreign_vault_and_location_cannot_rebind_view() {
        let (_, service, owner, vault) = fixture();
        let view = service.view(&owner, &vault, "/Travel.vault").unwrap();
        let foreign =
            VaultSessionScope::new("default", "https://example.test", "space", "other-root")
                .unwrap();
        assert!(
            view.verify_context(&owner, &foreign, "/Travel.vault")
                .is_err()
        );
        assert!(view.verify_context(&owner, &vault, "/other").is_err());
        let client =
            raiun_opencloud::OpenCloudClient::new("https://example.test/", "synthetic".into())
                .unwrap();
        client.set_bearer_token("rotated-synthetic".into()).unwrap();
        let rotated = ProviderScope::new(
            &client,
            "default".into(),
            "subject".into(),
            "https://example.test".into(),
        )
        .unwrap();
        assert!(service.view(&rotated, &vault, "/Travel.vault").is_err());
        let other = ProviderScope::new(
            &client,
            "default".into(),
            "foreign".into(),
            "https://example.test".into(),
        )
        .unwrap();
        assert!(service.view(&other, &vault, "/Travel.vault").is_err());
    }
    #[test]
    fn history_reopens_post_connect_bytes_and_refuses_missing_or_failed_proof() {
        let (store, service, owner, vault) = fixture();
        let view = service.view(&owner, &vault, "/Travel.vault").unwrap();
        view.persist_catalogue(&[entry(1)]).unwrap();
        // A fresh protected reader must see a publication made after preparation.
        view.persist_hydration(&intent(&service)).unwrap();
        let rows = service
            .snapshot(&owner, service.root, "registration")
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].identity, [1; 16]);
        assert_eq!(rows[0].file_index, 99);
        assert_eq!(rows[0].length, 65537);
        assert_eq!(rows[0].components, intent(&service).components);
        assert!(service.snapshot(&owner, service.root, "foreign").is_err());
        assert_eq!(
            service
                .snapshot(&owner, service.root, "registration")
                .unwrap()
                .len(),
            1
        );
        let scope = Scope::new(
            &service.account,
            &vault,
            "/Travel.vault",
            7,
            42,
            "registration",
        )
        .unwrap();
        store
            .bytes
            .lock()
            .unwrap()
            .remove(&child_key(&scope).unwrap());
        assert!(
            service
                .snapshot(&owner, service.root, "registration")
                .is_err()
        );
        assert!(
            view.verify_context(&owner, &vault, "/Travel.vault")
                .is_err()
        );
        assert!(service.view(&owner, &vault, "/Travel.vault").is_err());
    }

    #[test]
    fn history_global_conflict_and_final_cas_failure_never_replace_cache() {
        let (store, service, owner, vault) = fixture();
        let view = service.view(&owner, &vault, "/Travel.vault").unwrap();
        view.persist_catalogue(&[entry(1)]).unwrap();
        view.persist_hydration(&intent(&service)).unwrap();
        let other =
            VaultSessionScope::new("default", "https://example.test", "space", "other-root")
                .unwrap();
        let second = service.view(&owner, &other, "/Other.vault").unwrap();
        second.persist_catalogue(&[entry(1)]).unwrap();
        second.persist_hydration(&intent(&service)).unwrap();
        assert!(
            service
                .snapshot(&owner, service.root, "registration")
                .is_err()
        );
        assert!(
            view.verify_context(&owner, &vault, "/Travel.vault")
                .is_err()
        );
        assert!(!store.bytes.lock().unwrap().is_empty());
        let (store, service, owner, _) = fixture();
        store.fail.store(true, Ordering::SeqCst);
        assert!(
            service
                .snapshot(&owner, service.root, "registration")
                .is_err()
        );
        store.fail.store(false, Ordering::SeqCst);
        assert!(
            service
                .snapshot(&owner, service.root, "registration")
                .is_err()
        );
    }
}

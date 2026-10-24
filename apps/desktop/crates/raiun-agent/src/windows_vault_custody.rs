//! Protected write-ahead metadata service, not native recovery authority.
//! Root membership precedes child creation and every publication precedes its
//! protected CAS. Missing legacy manifests/children are never adopted or healed.
use super::{
    SessionStore,
    root_manifest::{RootBinding, RootManifest},
    vault_custody::{self, Custody, Entry, Scope},
};
use raiun_cloudfiles_windows::vault_custody::{
    VaultCatalogueEntry, VaultHydrationIntent, VaultPublicationCustody,
};
use raiun_cloudfiles_windows::{
    BackendError, ConfiguredRootIdentity, ProviderScope, VaultCustodyRootContext,
};
use raiun_core::backend::RemoteEntry;
use raiun_vault::session::VaultSessionScope;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
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
}
struct SessionStorage(Arc<dyn SessionStore>);
impl Storage for SessionStorage {
    fn load(&self, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.0.load_vault_custody(key)
    }
    fn cas(&self, key: &[u8], old: Option<&[u8]>, next: &[u8]) -> Result<()> {
        self.0.compare_exchange_vault_custody(key, old, next)
    }
}
struct ProtectedStore(Arc<dyn Storage>);
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
}
impl WindowsVaultCustody {
    pub(super) fn prepare(
        store: Arc<dyn SessionStore>,
        account: &[u8],
        context: &VaultCustodyRootContext<'_>,
    ) -> Result<Arc<Self>> {
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
            state: Mutex::new(State {
                manifest,
                children,
                failed: false,
            }),
        }))
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
        }))
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
}
impl VaultPublicationCustody for View {
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
}

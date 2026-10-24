//! Inert protected root-wide write-ahead manifest. No filesystem, session,
//! registration or history-completeness authority is created by this model.
use super::vault_custody::{Error, Scope};
use raiun_engine::folder_pairs::AccountScope;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use zeroize::Zeroizing;

pub const MAX_SCOPES: usize = 128;
pub const MAX_BYTES: usize = 1024 * 1024;
const VERSION: u32 = 1;
const KEY_DOMAIN: &[u8] = b"raiun-vault-root-manifest-v1\0";
type Result<T> = std::result::Result<T, Error>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountFields {
    profile: String,
    server: String,
    client: String,
    issuer: Option<String>,
    subject: String,
}
/// Validated exact account/physical-root/registration scope, available before
/// any vault exists. Opaque bytes do NOT prove a fresh registration, clean
/// history, filesystem identity, session authority or permission to initialize.
pub struct RootBinding {
    bytes: Zeroizing<Vec<u8>>,
}
impl RootBinding {
    pub fn new(account: &[u8], volume: u32, file_id: u64, registration: &str) -> Result<Self> {
        if account.is_empty()
            || account.len() > 16384
            || volume == 0
            || file_id == 0
            || registration.is_empty()
            || registration.len() > 4096
            || registration.trim() != registration
            || registration.chars().any(char::is_control)
        {
            return Err(Error::Invalid);
        }
        let fields: AccountFields = serde_json::from_slice(account).map_err(|_| Error::Invalid)?;
        if fields.profile != "default"
            && !(fields.profile.len() == 40
                && fields.profile.starts_with("profile-")
                && fields.profile[8..]
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
        {
            return Err(Error::Invalid);
        }
        let canonical = AccountScope::new(
            fields.profile,
            fields.server,
            fields.client,
            fields.issuer,
            fields.subject,
        )
        .map_err(|_| Error::Invalid)?;
        if serde_json::to_vec(&canonical).map_err(|_| Error::Invalid)? != account {
            return Err(Error::Invalid);
        }
        let bytes = serde_json::to_vec(&(
            "raiun-vault-custody-root-v1",
            account,
            volume,
            file_id,
            registration,
        ))
        .map_err(|_| Error::Invalid)?;
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }
    #[cfg(test)]
    pub fn from_scope(scope: &Scope) -> Result<Self> {
        Ok(Self {
            bytes: scope.root_binding()?,
        })
    }
}

/// Fixed protected custody domain/private path, bound to these key bytes. The
/// implementation authenticates the WHOLE payload, serializes cross-process
/// full-byte CAS, and returns Ok only after durable publication/exact readback.
/// Missing load creates no storage. Err may be post-publication uncertainty.
/// The key is a locator/AAD binding, never root or account authority.
pub trait Store {
    fn load(&self, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn compare_exchange(&self, key: &[u8], expected: Option<&[u8]>, next: &[u8]) -> Result<()>;
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    root_binding: Vec<u8>,
    scopes: Vec<Scope>,
}

/// Retains all historical rows. There is deliberately no remove/reset/clean API.
/// Returned scopes are only input to reconciliation; an empty manifest cannot
/// clear native reconnect/incomplete history or prove that no plaintext exists.
pub struct RootManifest {
    document: Document,
    key: Zeroizing<Vec<u8>>,
    raw: Zeroizing<Vec<u8>>,
    uncertain: bool,
}
impl RootManifest {
    /// Caller must independently prove a genuinely NEW empty registration/root.
    /// This is explicit initialization, never a fallback for a missing read.
    /// RootBinding is only scope, NOT proof of a new root or clean history.
    /// CAS None refuses existing history. No vault is implicitly registered.
    pub fn initialize_new_registration(store: &impl Store, trusted: &RootBinding) -> Result<Self> {
        let binding = trusted.bytes.as_slice();
        let key = store_key(binding);
        let document = Document {
            version: VERSION,
            root_binding: binding.to_vec(),
            scopes: Vec::new(),
        };
        let raw = encode(&document)?;
        store
            .compare_exchange(&key, None, &raw)
            .map_err(|_| Error::Persistence)?;
        Ok(Self {
            document,
            key,
            raw,
            uncertain: false,
        })
    }

    /// Caller supplies the currently trusted full-account/physical-root/
    /// registration binding. No authority is inferred from any stored row.
    pub fn reopen(store: &impl Store, trusted: &RootBinding) -> Result<Self> {
        let binding = trusted.bytes.as_slice();
        let key = store_key(binding);
        let raw = store
            .load(&key)
            .map_err(|_| Error::Persistence)?
            .ok_or(Error::Missing)?;
        let document = decode(&raw, binding)?;
        Ok(Self {
            document,
            key,
            raw,
            uncertain: false,
        })
    }

    /// Must succeed BEFORE any child custody document or plaintext publication.
    /// Only an exact row repeats idempotently; old rows are never replaced.
    /// Even repeats CAS the current full bytes, refusing stale controllers.
    /// Returns true only for a NEW row after durable CAS; false for an exact
    /// historical repeat. True is bookkeeping, never native/freshness authority.
    /// Child initialization additionally requires a trusted never-published
    /// new-scope proof. False + missing child MUST reopen/refuse, never initialize.
    /// A crash after append but before child creation stays missing/fail-closed.
    pub fn register(&mut self, store: &impl Store, scope: &Scope) -> Result<bool> {
        if self.uncertain {
            return Err(Error::Incomplete);
        }
        if scope.root_binding()?.as_slice() != self.document.root_binding {
            return Err(Error::Foreign);
        }
        // Explicit validated canonical helper; derived Deserialize is not proof.
        let canonical = scope.authenticated_store_binding()?;
        let validated = Scope::from_authenticated_store_binding(&canonical)?;
        let already = self.document.scopes.contains(&validated);
        if !already && self.document.scopes.len() == MAX_SCOPES {
            return Err(Error::Capacity);
        }
        let mut scopes = self.document.scopes.clone();
        if !already {
            scopes.push(validated);
        }
        let candidate = Document {
            version: VERSION,
            root_binding: self.document.root_binding.clone(),
            scopes,
        };
        let next = encode(&candidate)?;
        if store
            .compare_exchange(&self.key, Some(&self.raw), &next)
            .is_err()
        {
            // Publication may have completed. Keep all old bytes/rows, but
            // require reopen rather than claiming that they remain current.
            self.uncertain = true;
            return Err(Error::Persistence);
        }
        self.document = candidate;
        self.raw = next;
        Ok(!already)
    }

    pub fn scopes_for_reconciliation(&self) -> Result<&[Scope]> {
        if self.uncertain {
            return Err(Error::Incomplete);
        }
        Ok(&self.document.scopes)
    }
}

fn store_key(binding: &[u8]) -> Zeroizing<Vec<u8>> {
    // Root/account JSON byte arrays can exceed the Control scope byte limit.
    // Keep this key fixed-size; the protected document retains/compares the
    // exact full canonical binding, so a hash is never the scope authority.
    let mut bytes = Zeroizing::new(Vec::with_capacity(KEY_DOMAIN.len() + 32));
    bytes.extend_from_slice(KEY_DOMAIN);
    bytes.extend_from_slice(&Sha256::digest(binding));
    bytes
}
struct BoundedWriter(Zeroizing<Vec<u8>>);
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_BYTES - self.0.len() {
            return Err(io::Error::other("Protected root manifest exceeds limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode(document: &Document) -> Result<Zeroizing<Vec<u8>>> {
    let mut writer = BoundedWriter(Zeroizing::new(Vec::with_capacity(MAX_BYTES)));
    serde_json::to_writer(&mut writer, document).map_err(|_| Error::Capacity)?;
    Ok(writer.0)
}
fn decode(bytes: &[u8], binding: &[u8]) -> Result<Document> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(Error::Invalid);
    }
    let document: Document = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    if document.version != VERSION || document.scopes.len() > MAX_SCOPES {
        return Err(Error::Invalid);
    }
    if document.root_binding != binding {
        return Err(Error::Foreign);
    }
    for (index, scope) in document.scopes.iter().enumerate() {
        let canonical = scope.authenticated_store_binding()?;
        let validated = Scope::from_authenticated_store_binding(&canonical)?;
        if scope != &validated || scope.root_binding()?.as_slice() != binding {
            return Err(Error::Foreign);
        }
        if document.scopes[..index].contains(scope) {
            return Err(Error::Invalid);
        }
    }
    if encode(&document)?.as_slice() != bytes {
        return Err(Error::Invalid);
    }
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;
    use raiun_engine::folder_pairs::AccountScope;
    use raiun_vault::session::VaultSessionScope;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Memory(Mutex<BTreeMap<Vec<u8>, Vec<u8>>>);
    impl Store for Memory {
        fn load(&self, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(self.0.lock().unwrap().get(key).cloned().map(Zeroizing::new))
        }
        fn compare_exchange(&self, key: &[u8], expected: Option<&[u8]>, next: &[u8]) -> Result<()> {
            let mut rows = self.0.lock().unwrap();
            if rows.get(key).map(Vec::as_slice) != expected {
                return Err(Error::Conflict);
            }
            rows.insert(key.to_vec(), next.to_vec());
            Ok(())
        }
    }
    fn scope(vault: usize, root: u64) -> Scope {
        let account = AccountScope::new(
            "default".into(),
            "https://cloud.example/".into(),
            "synthetic-client".into(),
            Some("https://issuer.example/".into()),
            "synthetic-subject".into(),
        )
        .unwrap();
        let vault_scope = VaultSessionScope::new(
            "default",
            "https://cloud.example/",
            "synthetic-space",
            &format!("vault-{vault}"),
        )
        .unwrap();
        Scope::new(
            &serde_json::to_vec(&account).unwrap(),
            &vault_scope,
            &format!("/vault-{vault}"),
            9,
            root,
            "synthetic-registration",
        )
        .unwrap()
    }

    #[test]
    fn writeahead_register_reopen_and_stale_cas_preserve_history() {
        let store = Memory::default();
        let a = scope(0, 42);
        assert!(matches!(
            RootManifest::reopen(&store, &RootBinding::from_scope(&a).unwrap()),
            Err(Error::Missing)
        ));
        assert!(store.0.lock().unwrap().is_empty());
        let mut manifest = RootManifest::initialize_new_registration(
            &store,
            &RootBinding::from_scope(&a).unwrap(),
        )
        .unwrap();
        assert!(manifest.scopes_for_reconciliation().unwrap().is_empty());
        assert!(
            RootManifest::initialize_new_registration(
                &store,
                &RootBinding::from_scope(&a).unwrap()
            )
            .is_err()
        );
        assert!(manifest.register(&store, &a).unwrap());
        assert!(!manifest.register(&store, &a).unwrap());
        assert_eq!(
            manifest.scopes_for_reconciliation().unwrap(),
            std::slice::from_ref(&a)
        );
        let mut stale =
            RootManifest::reopen(&store, &RootBinding::from_scope(&a).unwrap()).unwrap();
        let b = scope(1, 42);
        assert!(manifest.register(&store, &b).unwrap());
        assert!(matches!(
            stale.register(&store, &a),
            Err(Error::Persistence)
        ));
        assert!(matches!(
            stale.scopes_for_reconciliation(),
            Err(Error::Incomplete)
        ));
        assert!(matches!(stale.register(&store, &b), Err(Error::Incomplete)));
        let mut reopened =
            RootManifest::reopen(&store, &RootBinding::from_scope(&b).unwrap()).unwrap();
        assert!(!reopened.register(&store, &a).unwrap());
        assert_eq!(
            reopened.scopes_for_reconciliation().unwrap(),
            &[a.clone(), b]
        );
        let before = store.0.lock().unwrap().clone();
        assert!(matches!(
            manifest.register(&store, &scope(2, 43)),
            Err(Error::Foreign)
        ));
        assert!(matches!(
            RootManifest::reopen(&store, &RootBinding::from_scope(&scope(0, 43)).unwrap()),
            Err(Error::Missing)
        ));
        assert_eq!(*store.0.lock().unwrap(), before);
    }

    #[test]
    fn capacity_retains_all_128_rows_and_refuses_extra_scope() {
        let store = Memory::default();
        let a = scope(0, 42);
        let mut manifest = RootManifest::initialize_new_registration(
            &store,
            &RootBinding::from_scope(&a).unwrap(),
        )
        .unwrap();
        for i in 0..MAX_SCOPES {
            manifest.register(&store, &scope(i, 42)).unwrap();
        }
        let before = store.0.lock().unwrap().clone();
        assert!(matches!(
            manifest.register(&store, &scope(MAX_SCOPES, 42)),
            Err(Error::Capacity)
        ));
        manifest.register(&store, &a).unwrap();
        assert_eq!(*store.0.lock().unwrap(), before);
        assert_eq!(
            RootManifest::reopen(&store, &RootBinding::from_scope(&a).unwrap())
                .unwrap()
                .scopes_for_reconciliation()
                .unwrap()
                .len(),
            MAX_SCOPES
        );
    }

    #[test]
    fn malformed_foreign_noncanonical_and_duplicate_documents_refuse_without_reset() {
        let store = Memory::default();
        let a = scope(0, 42);
        let mut manifest = RootManifest::initialize_new_registration(
            &store,
            &RootBinding::from_scope(&a).unwrap(),
        )
        .unwrap();
        manifest.register(&store, &a).unwrap();
        let key = store_key(&a.root_binding().unwrap());
        let original = store.0.lock().unwrap()[key.as_slice()].clone();
        let base: serde_json::Value = serde_json::from_slice(&original).unwrap();
        let mut variants = vec![b"{".to_vec(), vec![0; MAX_BYTES + 1]];
        let mut unknown = base.clone();
        unknown["unknown"] = true.into();
        variants.push(serde_json::to_vec(&unknown).unwrap());
        let mut foreign = base.clone();
        foreign["root_binding"] = serde_json::json!([1]);
        variants.push(serde_json::to_vec(&foreign).unwrap());
        let mut invalid = base.clone();
        invalid["scopes"][0]["root_file"] = 0.into();
        variants.push(serde_json::to_vec(&invalid).unwrap());
        let mut duplicate = base.clone();
        let row = duplicate["scopes"][0].clone();
        duplicate["scopes"].as_array_mut().unwrap().push(row);
        variants.push(serde_json::to_vec(&duplicate).unwrap());
        let mut noncanonical = original.clone();
        noncanonical.push(b' ');
        variants.push(noncanonical);
        for bytes in variants {
            store.0.lock().unwrap().insert(key.to_vec(), bytes.clone());
            assert!(RootManifest::reopen(&store, &RootBinding::from_scope(&a).unwrap()).is_err());
            assert_eq!(store.0.lock().unwrap()[key.as_slice()], bytes);
        }
    }
}

#[cfg(test)]
mod root_binding_tests {
    use super::super::vault_custody::{Custody, Store as ChildStore};
    use super::*;
    use raiun_vault::session::VaultSessionScope;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    fn account() -> Vec<u8> {
        serde_json::to_vec(
            &AccountScope::new(
                "default".into(),
                "https://cloud.example/".into(),
                "synthetic-client".into(),
                Some("https://issuer.example/".into()),
                "synthetic-subject".into(),
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn vault(account: &[u8], id: &str) -> Scope {
        Scope::new(
            account,
            &VaultSessionScope::new("default", "https://cloud.example/", "synthetic-space", id)
                .unwrap(),
            &format!("/{id}"),
            9,
            42,
            "synthetic-registration",
        )
        .unwrap()
    }
    #[derive(Default)]
    struct Memory(Mutex<BTreeMap<Vec<u8>, Vec<u8>>>);
    impl Store for Memory {
        fn load(&self, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(self.0.lock().unwrap().get(key).cloned().map(Zeroizing::new))
        }
        fn compare_exchange(&self, key: &[u8], expected: Option<&[u8]>, next: &[u8]) -> Result<()> {
            let mut rows = self.0.lock().unwrap();
            if rows.get(key).map(Vec::as_slice) != expected {
                return Err(Error::Conflict);
            }
            rows.insert(key.to_vec(), next.to_vec());
            Ok(())
        }
    }
    impl ChildStore for Memory {
        fn load(&self, scope: &Scope) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Store::load(self, &scope.authenticated_store_binding()?)
        }
        fn compare_exchange(
            &self,
            scope: &Scope,
            expected: Option<&[u8]>,
            next: &[u8],
        ) -> Result<()> {
            Store::compare_exchange(self, &scope.authenticated_store_binding()?, expected, next)
        }
    }
    #[test]
    fn direct_root_binding_precedes_vault_and_rejects_noncanonical_or_invalid_inputs() {
        let bytes = account();
        // No dummy vault exists or is required at root admission.
        let direct = RootBinding::new(&bytes, 9, 42, "synthetic-registration").unwrap();
        let store = Memory::default();
        let manifest = RootManifest::initialize_new_registration(&store, &direct).unwrap();
        assert!(manifest.scopes_for_reconciliation().unwrap().is_empty());
        let real = vault(&bytes, "real-vault");
        assert_eq!(
            direct.bytes.as_slice(),
            real.root_binding().unwrap().as_slice()
        );
        assert_eq!(
            direct.bytes.as_slice(),
            RootBinding::from_scope(&real).unwrap().bytes.as_slice()
        );
        let mut noncanonical = bytes.clone();
        noncanonical.push(b' ');
        assert!(RootBinding::new(&noncanonical, 9, 42, "synthetic-registration").is_err());
        assert!(RootBinding::new(b"{}", 9, 42, "synthetic-registration").is_err());
        assert!(RootBinding::new(&bytes, 0, 42, "synthetic-registration").is_err());
        assert!(RootBinding::new(&bytes, 9, 0, "synthetic-registration").is_err());
        assert!(RootBinding::new(&bytes, 9, 42, " registration").is_err());
        assert!(RootBinding::new(&bytes, 9, 42, "").is_err());
    }
    #[test]
    fn new_row_boolean_does_not_heal_historical_missing_child() {
        let bytes = account();
        let root = RootBinding::new(&bytes, 9, 42, "synthetic-registration").unwrap();
        let store = Memory::default();
        let mut manifest = RootManifest::initialize_new_registration(&store, &root).unwrap();
        let first = vault(&bytes, "first");
        let second = vault(&bytes, "second");
        assert!(manifest.register(&store, &first).unwrap());
        Custody::initialize_new_scope(&store, first.clone()).unwrap();
        // Independently verified never-published new scope may initialize only
        // in the fresh true branch. This boolean alone never proves that fact.
        assert!(manifest.register(&store, &second).unwrap());
        // Simulate crash after durable manifest append, before child creation.
        let mut reopened = RootManifest::reopen(&store, &root).unwrap();
        let newly_added = reopened.register(&store, &second).unwrap();
        assert!(!newly_added);
        let before = store.0.lock().unwrap().clone();
        let child = if newly_added {
            Custody::initialize_new_scope(&store, second.clone())
        } else {
            Custody::reopen(&store, &second)
        };
        assert!(matches!(child, Err(Error::Missing)));
        assert_eq!(
            *store.0.lock().unwrap(),
            before,
            "missing historical child must not be created"
        );
        assert!(!reopened.register(&store, &first).unwrap());
        assert!(Custody::reopen(&store, &first).is_ok());
        assert_eq!(reopened.scopes_for_reconciliation().unwrap().len(), 2);
    }
}

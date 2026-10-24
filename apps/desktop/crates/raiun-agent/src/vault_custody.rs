//! Inert protected-store payload and write-ahead custody model only.
//! The Store MUST authenticate the whole payload/domain and bind its trusted
//! scope independently. JSON alone has no integrity. No file/route/session or
//! restore authority is conferred by decoding rows or a persistence acknowledgement.
use raiun_engine::folder_pairs::AccountScope;
use raiun_vault::session::VaultSessionScope;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{self, Write};
use zeroize::Zeroizing;

pub const MAX_BYTES: usize = 1024 * 1024;
pub const MAX_CATALOGUE: usize = 1024;
pub const MAX_HYDRATIONS: usize = 4096;
const VERSION: u32 = 1;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Missing,
    Foreign,
    Incomplete,
    Conflict,
    Capacity,
    Persistence,
}
type Result<T> = std::result::Result<T, Error>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountFields {
    profile: String,
    server: String,
    client: String,
    issuer: Option<String>,
    subject: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    account: Vec<u8>,
    profile: String,
    origin: String,
    space: String,
    resource: String,
    remote_root: String,
    volume: u32,
    root_file: u64,
    registration: String,
}
impl std::fmt::Debug for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultCustodyScope([redacted])")
    }
}
impl Scope {
    /// Account bytes must be serialized ONCE from the authenticated canonical
    /// AccountScope, not rebuilt from raw session issuer spelling or request JSON.
    /// Root/registration arguments must come from retained native root proofs.
    pub fn new(
        account: &[u8],
        vault: &VaultSessionScope,
        remote_root: &str,
        volume: u32,
        root_file: u64,
        registration: &str,
    ) -> Result<Self> {
        if account.is_empty() || account.len() > 16384 {
            return Err(Error::Invalid);
        }
        let a: AccountFields = serde_json::from_slice(account).map_err(|_| Error::Invalid)?;
        let model = AccountScope::new(
            a.profile.clone(),
            a.server.clone(),
            a.client,
            a.issuer,
            a.subject,
        )
        .map_err(|_| Error::Invalid)?;
        if serde_json::to_vec(&model).map_err(|_| Error::Invalid)? != account
            || !valid_profile(&a.profile)
            || a.profile != vault.account_id()
            || url::Url::parse(&a.server)
                .map_err(|_| Error::Invalid)?
                .origin()
                .ascii_serialization()
                != vault.server_origin()
            || !remote_path(remote_root)
            || volume == 0
            || root_file == 0
            || !bounded(registration, 4096)
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            account: account.to_vec(),
            profile: a.profile,
            origin: vault.server_origin().into(),
            space: vault.space_id().into(),
            resource: vault.resource_id().into(),
            remote_root: remote_root.into(),
            volume,
            root_file,
            registration: registration.into(),
        })
    }
    /// Canonical full-scope bytes for the parent's separate custody DPAPI AAD.
    /// Caller must pass the same bytes to load and CAS; not a credential key.
    pub fn authenticated_store_binding(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        serde_json::to_vec(self)
            .map(Zeroizing::new)
            .map_err(|_| Error::Invalid)
    }
    /// Parse only authenticated parent/store bytes; validation is structural,
    /// never proof of a live account, registration or completeness.
    pub fn from_authenticated_store_binding(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 128 * 1024 {
            return Err(Error::Invalid);
        }
        let scope: Self = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        if scope.authenticated_store_binding()?.as_slice() != bytes {
            return Err(Error::Invalid);
        }
        Ok(scope)
    }
    /// Canonical parent-manifest root binding. Excludes only the vault-specific
    /// Space/resource/remote locator; this value is not a completeness proof.
    pub fn root_binding(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        serde_json::to_vec(&(
            "raiun-vault-custody-root-v1",
            &self.account,
            self.volume,
            self.root_file,
            &self.registration,
        ))
        .map(Zeroizing::new)
        .map_err(|_| Error::Invalid)
    }
    fn validate(&self) -> Result<()> {
        let v = VaultSessionScope::new(&self.profile, &self.origin, &self.space, &self.resource)
            .map_err(|_| Error::Invalid)?;
        if Self::new(
            &self.account,
            &v,
            &self.remote_root,
            self.volume,
            self.root_file,
            &self.registration,
        )? != *self
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
fn valid_profile(s: &str) -> bool {
    s == "default"
        || (s.len() == 40
            && s.starts_with("profile-")
            && s[8..]
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
}
fn bounded(s: &str, n: usize) -> bool {
    !s.trim().is_empty() && s.trim() == s && s.len() <= n && !s.chars().any(char::is_control)
}
fn remote_path(s: &str) -> bool {
    s == "/"
        || (s.len() <= 32000
            && s.starts_with('/')
            && !s.ends_with('/')
            && !s.contains('\\')
            && !s.chars().any(char::is_control)
            && s[1..]
                .split('/')
                .all(|p| !p.is_empty() && p != "." && p != ".."))
}
fn components(v: &[String]) -> bool {
    !v.is_empty()
        && v.len() <= 256
        && v.iter().map(String::len).sum::<usize>() <= 32000
        && v.iter().all(|s| {
            let base = s.split('.').next().unwrap_or("").to_ascii_uppercase();
            !s.is_empty()
                && s.len() <= 255
                && s != "."
                && s != ".."
                && !s.ends_with(['.', ' '])
                && !s
                    .chars()
                    .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
                && !matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                && !(base.len() == 4
                    && (base.starts_with("COM") || base.starts_with("LPT"))
                    && matches!(base.as_bytes()[3], b'1'..=b'9'))
        })
}

/// Sensitive metadata: deliberately no Debug, only protected payload serialization.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    opaque: [u8; 16],
    remote_id: String,
    remote_path: String,
    etag: String,
    directory: bool,
    length: u64,
}
impl Entry {
    /// Remote verified metadata only; local paths do not exist at enumeration.
    pub fn new(
        opaque: [u8; 16],
        remote_id: &str,
        root_relative_path: &str,
        etag: &str,
        directory: bool,
        length: u64,
    ) -> Result<Self> {
        let e = Self {
            opaque,
            remote_id: remote_id.into(),
            remote_path: root_relative_path.into(),
            etag: etag.into(),
            directory,
            length,
        };
        e.validate()?;
        Ok(e)
    }
    pub fn opaque(&self) -> [u8; 16] {
        self.opaque
    }
    pub fn remote_id(&self) -> &str {
        &self.remote_id
    }
    pub fn root_relative_path(&self) -> &str {
        &self.remote_path
    }
    pub fn etag(&self) -> &str {
        &self.etag
    }
    pub fn is_directory(&self) -> bool {
        self.directory
    }
    pub fn length(&self) -> u64 {
        self.length
    }
    fn validate(&self) -> Result<()> {
        if self.opaque == [0; 16]
            || !bounded(&self.remote_id, 4096)
            || !remote_path(&self.remote_path)
            || (!self.directory && !bounded(&self.etag, 4096))
            || self.etag.len() > 4096
            || self.etag.chars().any(char::is_control)
            || (self.directory && self.length != 0)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn validate_in_scope(&self, scope: &Scope) -> Result<()> {
        self.validate()?;
        if self.remote_path == "/" && (!self.directory || self.remote_id != scope.resource) {
            return Err(Error::Foreign);
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hydration {
    opaque: [u8; 16],
    file_index: u64,
    length: u64,
    components: Vec<String>,
}
impl Hydration {
    #[cfg(test)]
    pub fn opaque(&self) -> [u8; 16] {
        self.opaque
    }
    #[cfg(test)]
    pub fn file_index(&self) -> u64 {
        self.file_index
    }
    #[cfg(test)]
    pub fn length(&self) -> u64 {
        self.length
    }
    #[cfg(test)]
    pub fn components(&self) -> &[String] {
        &self.components
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    scope: Scope,
    revision: u64,
    incomplete: bool,
    catalogue: Vec<Entry>,
    pending: Vec<Hydration>,
}
impl Document {
    fn validate(&self, scope: &Scope) -> Result<()> {
        self.scope.validate()?;
        if &self.scope != scope {
            return Err(Error::Foreign);
        }
        if self.version != VERSION || self.revision == 0 {
            return Err(Error::Invalid);
        }
        if self.catalogue.len() > MAX_CATALOGUE || self.pending.len() > MAX_HYDRATIONS {
            return Err(Error::Capacity);
        }
        let mut ids = BTreeSet::new();
        let mut versions = BTreeSet::new();
        for e in &self.catalogue {
            e.validate_in_scope(scope)?;
            if !ids.insert(e.opaque)
                || !versions.insert((&e.remote_path, &e.remote_id, &e.etag, e.directory, e.length))
            {
                return Err(Error::Conflict);
            }
            // VaultBackend entries are canonical DECRYPTED root-relative paths
            // ("/", "/1"), independent of the encrypted remote root locator.
        }
        let mut files = BTreeSet::new();
        let mut hydrated_ids = BTreeSet::new();
        for h in &self.pending {
            let e = self
                .catalogue
                .iter()
                .find(|e| e.opaque == h.opaque)
                .ok_or(Error::Invalid)?;
            if e.directory
                || h.file_index == 0
                || h.length != e.length
                || !components(&h.components)
                || !files.insert(h.file_index)
                || !hydrated_ids.insert(h.opaque)
            {
                return Err(Error::Conflict);
            }
        }
        Ok(())
    }
}
struct BoundedBytes(Zeroizing<Vec<u8>>);
impl Write for BoundedBytes {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(b.len())
            .is_none_or(|n| n > MAX_BYTES)
        {
            return Err(io::Error::other("custody bounds"));
        }
        self.0.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode(d: &Document) -> Result<Zeroizing<Vec<u8>>> {
    let mut b = BoundedBytes(Zeroizing::new(Vec::new()));
    serde_json::to_writer(&mut b, d).map_err(|_| Error::Capacity)?;
    Ok(b.0)
}
fn decode(bytes: &[u8], scope: &Scope) -> Result<Document> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(Error::Invalid);
    }
    let d: Document = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    d.validate(scope)?;
    Ok(d)
}
/// Implementations must use a dedicated protected domain/private fixed path,
/// authenticate the complete scope and bytes, serialize cross-process CAS, and
/// return Ok ONLY after write-through publication + exact readback. Err can be
/// post-publication uncertainty; no caller may infer previous bytes survived.
/// load(None) must not create storage. Expected is full plaintext byte equality.
/// This trait performs no DPAPI or filesystem work itself.
pub trait Store {
    fn load(&self, scope: &Scope) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn compare_exchange(&self, scope: &Scope, expected: Option<&[u8]>, next: &[u8]) -> Result<()>;
}
/// Per-vault evidence only. A separate root-wide durable manifest must cover
/// every vault scope before any publication. This document cannot establish
/// global connection completeness or clear legacy/reconnect unknown history.
pub struct Custody {
    document: Document,
    raw: Zeroizing<Vec<u8>>,
    failed: bool,
}
impl Custody {
    /// Caller must independently authenticate a COMPLETE root manifest and
    /// durably append this exact NEW scope row before calling (register=true).
    /// The vault scope must never have published before. The native root itself
    /// need not be new/empty; other scopes may already exist under that root.
    /// CAS None alone is NOT that proof. Existing manifest row (register=false)
    /// MUST use reopen; missing child then refuses, including append-before-child
    /// crash. Never repair/reinitialize a missing legacy/existing child.
    pub fn initialize_new_scope(store: &impl Store, scope: Scope) -> Result<Self> {
        scope.validate()?;
        let document = Document {
            version: VERSION,
            scope,
            revision: 1,
            incomplete: false,
            catalogue: vec![],
            pending: vec![],
        };
        let raw = encode(&document)?;
        store
            .compare_exchange(&document.scope, None, &raw)
            .map_err(|_| Error::Persistence)?;
        Ok(Self {
            document,
            raw,
            failed: false,
        })
    }
    pub fn reopen(store: &impl Store, scope: &Scope) -> Result<Self> {
        scope.validate()?;
        let raw = store
            .load(scope)
            .map_err(|_| Error::Persistence)?
            .ok_or(Error::Missing)?;
        let document = decode(&raw, scope)?;
        Ok(Self {
            document,
            raw,
            failed: false,
        })
    }
    /// Restored rows are only reconciliation evidence. Even an empty complete
    /// document is NOT filesystem coverage or permission to clear native unknown history.
    #[cfg(test)]
    pub fn needs_reconciliation(&self) -> bool {
        self.failed || self.document.incomplete || !self.document.pending.is_empty()
    }
    #[cfg(test)]
    pub fn pending_count(&self) -> usize {
        self.document.pending.len()
    }
    fn commit(&mut self, store: &impl Store, mut next: Document) -> Result<()> {
        if self.failed || self.document.incomplete {
            return Err(Error::Incomplete);
        }
        next.revision = next.revision.checked_add(1).ok_or(Error::Capacity)?;
        next.validate(&self.document.scope)?;
        let raw = match encode(&next) {
            Ok(raw) => raw,
            Err(error) => {
                // The rejected oversized proposal must not replace old rows.
                // Persist a bounded sticky marker using only the previous rows.
                let mut blocked = self.document.clone();
                blocked.revision = next.revision;
                blocked.incomplete = true;
                let raw = encode(&blocked)?;
                self.failed = true;
                store
                    .compare_exchange(&blocked.scope, Some(&self.raw), &raw)
                    .map_err(|_| Error::Persistence)?;
                self.document = blocked;
                self.raw = raw;
                return Err(error);
            }
        };
        if store
            .compare_exchange(&next.scope, Some(&self.raw), &raw)
            .is_err()
        {
            self.failed = true;
            return Err(Error::Persistence);
        }
        self.raw = raw;
        self.document = next;
        Ok(())
    }
    fn refuse_conflict(&mut self, store: &impl Store, error: Error) -> Result<()> {
        let mut next = self.document.clone();
        next.incomplete = true;
        let persisted = self.commit(store, next);
        self.failed = true;
        persisted.and(Err(error))
    }
    /// Atomic remote catalogue batch before any opaque IDs/names are published.
    /// Validate every proposed entry first; one full-document CAS, not one fsync
    /// per child. Exact duplicates are idempotent but still CAS current bytes.
    pub fn record_entries(&mut self, store: &impl Store, entries: &[Entry]) -> Result<()> {
        if self.failed || self.document.incomplete {
            return Err(Error::Incomplete);
        }
        if entries.len() > MAX_CATALOGUE {
            return self.refuse_conflict(store, Error::Capacity);
        }
        for e in entries {
            e.validate_in_scope(&self.document.scope)?;
        }
        let mut next = self.document.clone();
        for entry in entries {
            if let Some(old) = next.catalogue.iter().find(|e| {
                e.opaque == entry.opaque
                    || (e.remote_id == entry.remote_id
                        && e.remote_path == entry.remote_path
                        && e.etag == entry.etag
                        && e.directory == entry.directory
                        && e.length == entry.length)
            }) {
                if old != entry {
                    return self.refuse_conflict(store, Error::Conflict);
                }
                continue;
            }
            if next.catalogue.len() == MAX_CATALOGUE {
                return self.refuse_conflict(store, Error::Capacity);
            }
            next.catalogue.push(entry.clone());
        }
        self.commit(store, next)
    }
    #[cfg(test)]
    pub fn record_entry(&mut self, store: &impl Store, entry: Entry) -> Result<()> {
        self.record_entries(store, &[entry])
    }
    /// Authenticated historical metadata ONLY, not a restore/cleanup permit.
    pub fn entries_for_reconciliation(&self) -> &[Entry] {
        &self.document.catalogue
    }
    #[cfg(test)]
    pub fn hydrations_for_reconciliation(&self) -> &[Hydration] {
        &self.document.pending
    }
    /// Write-ahead intent retained whether CfExecute succeeds, fails or crashes.
    /// Ok is only a persistence acknowledgement, never a publication ticket.
    /// Caller still needs all current root/route/request/session fences AND a
    /// separately committed root-wide manifest covering this scope.
    /// No API removes rows, marks them clean, resets incomplete, or infers restore
    /// authority. A later reconciler must independently prove native custody.
    pub fn persist_hydration_intent(
        &mut self,
        store: &impl Store,
        opaque: [u8; 16],
        file_index: u64,
        native_length: u64,
        native_components: Vec<String>,
    ) -> Result<()> {
        if self.failed || self.document.incomplete {
            return Err(Error::Incomplete);
        }
        let e = self
            .document
            .catalogue
            .iter()
            .find(|e| e.opaque == opaque && !e.directory)
            .cloned()
            .ok_or(Error::Invalid)?;
        if file_index == 0 || native_length != e.length || !components(&native_components) {
            return Err(Error::Invalid);
        }
        if let Some(old) = self
            .document
            .pending
            .iter()
            .find(|h| h.file_index == file_index || h.opaque == opaque)
        {
            if old.file_index != file_index
                || old.opaque != opaque
                || old.length != e.length
                || old.components != native_components
            {
                self.refuse_conflict(store, Error::Conflict)?;
            }
            // Idempotent return still verifies current durable CAS; an old local
            // snapshot never authorizes publication after a competing change.
            self.commit(store, self.document.clone())?;
        } else {
            if self.document.pending.len() == MAX_HYDRATIONS {
                self.refuse_conflict(store, Error::Capacity)?;
            }
            let mut next = self.document.clone();
            next.pending.push(Hydration {
                opaque,
                file_index,
                length: e.length,
                components: native_components,
            });
            self.commit(store, next)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    #[derive(Default)]
    struct Memory {
        bytes: RefCell<Option<Zeroizing<Vec<u8>>>>,
        fail: RefCell<bool>,
        uncertain: RefCell<bool>,
        calls: Cell<usize>,
    }
    impl Store for Memory {
        fn load(&self, _: &Scope) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(self
                .bytes
                .borrow()
                .as_ref()
                .map(|b| Zeroizing::new(b.to_vec())))
        }
        fn compare_exchange(&self, _: &Scope, expected: Option<&[u8]>, next: &[u8]) -> Result<()> {
            self.calls.set(self.calls.get() + 1);
            if self.bytes.borrow().as_ref().map(|b| b.as_slice()) != expected {
                return Err(Error::Conflict);
            }
            if *self.fail.borrow() {
                return Err(Error::Persistence);
            }
            *self.bytes.borrow_mut() = Some(Zeroizing::new(next.to_vec()));
            if *self.uncertain.borrow() {
                return Err(Error::Persistence);
            }
            Ok(())
        }
    }
    fn scope(subject: &str) -> Scope {
        let a = AccountScope::new(
            "default".into(),
            "https://example.test/".into(),
            "client".into(),
            Some("https://issuer.test/".into()),
            subject.into(),
        )
        .unwrap();
        let v = VaultSessionScope::new("default", "https://example.test", "space", "vault-root")
            .unwrap();
        Scope::new(
            &serde_json::to_vec(&a).unwrap(),
            &v,
            "/Travel.vault",
            7,
            42,
            "registered-root-id",
        )
        .unwrap()
    }
    fn native_components() -> Vec<String> {
        vec!["Personal".into(), "Travel.vault".into(), "1".into()]
    }
    fn entry(id: u8) -> Entry {
        Entry::new([id; 16], "remote-file", "/1", "etag", false, 65537).unwrap()
    }
    #[test]
    fn writeahead_survives_crash_reopen_without_granting_restore_authority() {
        let s = Memory::default();
        let scope = scope("subject");
        assert!(matches!(Custody::reopen(&s, &scope), Err(Error::Missing)));
        assert!(s.bytes.borrow().is_none());
        let binding = scope.authenticated_store_binding().unwrap();
        assert_eq!(
            Scope::from_authenticated_store_binding(&binding).unwrap(),
            scope
        );
        let mut noncanonical_binding = binding.to_vec();
        noncanonical_binding.push(b' ');
        assert!(Scope::from_authenticated_store_binding(&noncanonical_binding).is_err());
        let mut c = Custody::initialize_new_scope(&s, scope.clone()).unwrap();
        assert!(Custody::initialize_new_scope(&s, scope.clone()).is_err());
        c.record_entry(&s, entry(1)).unwrap();
        c.record_entry(
            &s,
            Entry::new([9; 16], "vault-root", "/", "", true, 0).unwrap(),
        )
        .unwrap();
        assert!(Entry::new([8; 16], "bad", "/../outside", "etag", false, 1).is_err());
        c.persist_hydration_intent(&s, [1; 16], 90, 65537, native_components())
            .unwrap();
        // Simulated crash before CfExecute or any success acknowledgement.
        drop(c);
        let restored = Custody::reopen(&s, &scope).unwrap();
        assert_eq!(restored.pending_count(), 1);
        assert!(restored.needs_reconciliation());
        assert_eq!(restored.document.pending[0].components, native_components());
        let raw = s.bytes.borrow();
        assert_eq!(
            encode(&restored.document).unwrap().as_slice(),
            raw.as_ref().unwrap().as_slice()
        );
        assert!(matches!(
            Custody::reopen(&s, &self::scope("foreign")),
            Err(Error::Foreign)
        ));
        let mut foreign_root = scope.clone();
        foreign_root.root_file += 1;
        assert!(matches!(
            Custody::reopen(&s, &foreign_root),
            Err(Error::Foreign)
        ));
        let mut foreign_vault = scope.clone();
        foreign_vault.resource = "other-vault".into();
        assert_eq!(
            scope.root_binding().unwrap().as_slice(),
            foreign_vault.root_binding().unwrap().as_slice()
        );
        assert_ne!(
            scope.root_binding().unwrap().as_slice(),
            foreign_root.root_binding().unwrap().as_slice()
        );
        assert_ne!(
            scope.root_binding().unwrap().as_slice(),
            self::scope("foreign").root_binding().unwrap().as_slice()
        );
        assert!(matches!(
            Custody::reopen(&s, &foreign_vault),
            Err(Error::Foreign)
        ));
        let mut foreign_registration = scope;
        foreign_registration.registration = "other-registration".into();
        assert!(matches!(
            Custody::reopen(&s, &foreign_registration),
            Err(Error::Foreign)
        ));
    }
    #[test]
    fn failed_or_uncertain_persistence_never_returns_publication_receipt() {
        let s = Memory::default();
        let scope = scope("subject");
        let mut c = Custody::initialize_new_scope(&s, scope.clone()).unwrap();
        c.record_entry(&s, entry(1)).unwrap();
        *s.fail.borrow_mut() = true;
        assert!(matches!(
            c.persist_hydration_intent(&s, [1; 16], 90, 65537, native_components()),
            Err(Error::Persistence)
        ));
        assert!(matches!(
            c.persist_hydration_intent(&s, [1; 16], 90, 65537, native_components()),
            Err(Error::Incomplete)
        ));
        assert_eq!(Custody::reopen(&s, &scope).unwrap().pending_count(), 0);
        *s.fail.borrow_mut() = false;
        let mut c = Custody::reopen(&s, &scope).unwrap();
        *s.uncertain.borrow_mut() = true;
        assert!(matches!(
            c.persist_hydration_intent(&s, [1; 16], 90, 65537, native_components()),
            Err(Error::Persistence)
        ));
        // Err does NOT mean rollback. The durable pending intent survived.
        assert!(Custody::reopen(&s, &scope).unwrap().needs_reconciliation());
        assert!(matches!(
            c.record_entry(&s, entry(2)),
            Err(Error::Incomplete)
        ));
    }
    #[test]
    fn stale_snapshot_conflicting_identity_and_overflow_preserve_sticky_evidence() {
        let s = Memory::default();
        let scope = scope("subject");
        let mut first = Custody::initialize_new_scope(&s, scope.clone()).unwrap();
        let mut stale = Custody::reopen(&s, &scope).unwrap();
        first.record_entry(&s, entry(1)).unwrap();
        assert!(matches!(
            stale.record_entry(&s, entry(2)),
            Err(Error::Persistence)
        ));
        let mut conflict = entry(1);
        conflict.remote_id = "replacement".into();
        assert!(matches!(
            first.record_entry(&s, conflict),
            Err(Error::Conflict)
        ));
        let restored = Custody::reopen(&s, &scope).unwrap();
        assert!(restored.document.incomplete);
        assert_eq!(restored.document.catalogue[0].remote_id, "remote-file");
        let s = Memory::default();
        let mut c = Custody::initialize_new_scope(&s, scope.clone()).unwrap();
        for i in 0..MAX_CATALOGUE {
            let mut e = entry(1);
            e.opaque = (i as u128 + 1).to_le_bytes();
            e.remote_id = format!("id-{i}");
            e.remote_path = format!("/Travel.vault/{i}");
            c.document.catalogue.push(e);
        }
        // Persist a validated full document in this bounded test setup.
        let full = encode(&c.document).unwrap();
        *s.bytes.borrow_mut() = Some(Zeroizing::new(full.to_vec()));
        c.raw = full;
        let mut extra = entry(255);
        extra.remote_id = "extra".into();
        extra.remote_path = "/Travel.vault/extra".into();
        extra.opaque = [255; 16];
        assert!(matches!(c.record_entry(&s, extra), Err(Error::Capacity)));
        let restored = Custody::reopen(&s, &scope).unwrap();
        assert!(restored.document.incomplete);
        assert_eq!(restored.document.catalogue.len(), MAX_CATALOGUE);
    }
    #[test]
    fn idempotent_stale_catalogue_and_replaced_physical_file_refuse() {
        let s = Memory::default();
        let scope = scope("subject");
        let mut c = Custody::initialize_new_scope(&s, scope.clone()).unwrap();
        c.record_entry(&s, entry(1)).unwrap();
        let mut stale = Custody::reopen(&s, &scope).unwrap();
        c.persist_hydration_intent(&s, [1; 16], 90, 65537, native_components())
            .unwrap();
        assert!(matches!(
            stale.record_entry(&s, entry(1)),
            Err(Error::Persistence)
        ));
        assert!(matches!(
            c.persist_hydration_intent(&s, [1; 16], 91, 65537, native_components()),
            Err(Error::Conflict)
        ));
        let restored = Custody::reopen(&s, &scope).unwrap();
        assert!(restored.document.incomplete);
        assert_eq!(restored.document.pending.len(), 1);
        assert_eq!(restored.document.pending[0].file_index, 90);
        assert_eq!(
            scope.authenticated_store_binding().unwrap().as_slice(),
            serde_json::to_vec(&scope).unwrap()
        );
    }
    #[test]
    fn new_scope_under_existing_root_and_repeat_missing_child_refuses() {
        // Minimal caller ordering with the separately owned root manifest's
        // register -> newly_added result. This boolean is NOT native authority.
        fn after_manifest_register(
            store: &Memory,
            scope: Scope,
            newly_added: bool,
        ) -> Result<Custody> {
            if newly_added {
                Custody::initialize_new_scope(store, scope)
            } else {
                Custody::reopen(store, &scope)
            }
        }
        let first_scope = scope("subject");
        let mut second_scope = first_scope.clone();
        second_scope.resource = "second-vault".into();
        second_scope.remote_root = "/Second.vault".into();
        assert_eq!(
            first_scope.root_binding().unwrap().as_slice(),
            second_scope.root_binding().unwrap().as_slice()
        );
        let first_store = Memory::default();
        let mut first = after_manifest_register(&first_store, first_scope.clone(), true).unwrap();
        first.record_entry(&first_store, entry(1)).unwrap();
        first
            .persist_hydration_intent(&first_store, [1; 16], 90, 65537, native_components())
            .unwrap();
        let second_store = Memory::default();
        // Same physical root, new durably appended scope: no new-root condition.
        let second = after_manifest_register(&second_store, second_scope.clone(), true).unwrap();
        assert_eq!(second.pending_count(), 0);
        assert_eq!(
            Custody::reopen(&first_store, &first_scope)
                .unwrap()
                .pending_count(),
            1
        );
        // Manifest append succeeded, process crashed BEFORE child creation.
        // Repeat register=false must never turn missing bytes into a clean doc.
        let interrupted_store = Memory::default();
        assert!(matches!(
            after_manifest_register(&interrupted_store, second_scope, false),
            Err(Error::Missing)
        ));
        assert!(interrupted_store.bytes.borrow().is_none());
    }
    #[test]
    fn catalogue_batch_is_one_cas_and_invalid_tail_never_partially_commits() {
        let s = Memory::default();
        let scope = scope("subject");
        let mut c = Custody::initialize_new_scope(&s, scope.clone()).unwrap();
        let root = Entry::new([9; 16], "vault-root", "/", "", true, 0).unwrap();
        let child = entry(1);
        let calls = s.calls.get();
        c.record_entries(&s, &[root.clone(), child.clone(), child.clone()])
            .unwrap();
        assert_eq!(s.calls.get(), calls + 1);
        assert_eq!(c.entries_for_reconciliation().len(), 2);
        let before = s.bytes.borrow().as_ref().unwrap().to_vec();
        let calls = s.calls.get();
        let mut invalid = entry(2);
        invalid.remote_path = "/../outside".into();
        assert!(matches!(
            c.record_entries(&s, &[entry(3), invalid]),
            Err(Error::Invalid)
        ));
        assert_eq!(s.calls.get(), calls);
        assert!(s.bytes.borrow().as_ref().unwrap().as_slice() == before);
        let badroot = Entry::new([8; 16], "foreign-root", "/", "", true, 0).unwrap();
        assert!(matches!(
            c.record_entries(&s, &[badroot]),
            Err(Error::Foreign)
        ));
        assert!(s.bytes.borrow().as_ref().unwrap().as_slice() == before);
        let file_root = Entry::new([8; 16], "vault-root", "/", "etag", false, 1).unwrap();
        assert!(matches!(
            c.record_entries(&s, &[file_root]),
            Err(Error::Foreign)
        ));
        assert!(s.bytes.borrow().as_ref().unwrap().as_slice() == before);
        let calls = s.calls.get();
        c.record_entries(&s, &[root, child]).unwrap();
        assert_eq!(s.calls.get(), calls + 1);
        let mut conflict = entry(1);
        conflict.remote_id = "replacement".into();
        assert!(matches!(
            c.record_entries(&s, &[entry(3), conflict]),
            Err(Error::Conflict)
        ));
        let reopened = Custody::reopen(&s, &scope).unwrap();
        assert!(reopened.needs_reconciliation());
        assert_eq!(reopened.entries_for_reconciliation().len(), 2);
    }
    #[test]
    fn catalogue_has_no_local_path_and_native_intent_path_conflict_blocks() {
        let s = Memory::default();
        let scope = scope("subject");
        let mut c = Custody::initialize_new_scope(&s, scope.clone()).unwrap();
        c.record_entries(
            &s,
            &[
                Entry::new([9; 16], "vault-root", "/", "", true, 0).unwrap(),
                entry(1),
            ],
        )
        .unwrap();
        assert!(c.hydrations_for_reconciliation().is_empty());
        c.persist_hydration_intent(&s, [1; 16], 90, 65537, native_components())
            .unwrap();
        let mut changed = native_components();
        changed[2] = "renamed".into();
        assert!(matches!(
            c.persist_hydration_intent(&s, [1; 16], 90, 65537, changed),
            Err(Error::Conflict)
        ));
        let reopened = Custody::reopen(&s, &scope).unwrap();
        assert!(reopened.needs_reconciliation());
        let row = &reopened.hydrations_for_reconciliation()[0];
        assert_eq!(row.components(), native_components());
        assert_eq!(row.file_index(), 90);
        assert_eq!(row.length(), 65537);
        assert_eq!(row.opaque(), [1; 16]);
        let e = &reopened.entries_for_reconciliation()[1];
        assert_eq!(e.root_relative_path(), "/1");
        assert_eq!(e.remote_id(), "remote-file");
        assert_eq!(e.etag(), "etag");
        assert_eq!(e.length(), 65537);
        assert!(!e.is_directory());
        assert_eq!(e.opaque(), [1; 16]);
    }
    #[test]
    fn malformed_tampered_schema_and_noncanonical_scope_refuse_without_reset() {
        let s = Memory::default();
        let scope = scope("subject");
        let mut c = Custody::initialize_new_scope(&s, scope.clone()).unwrap();
        c.record_entry(&s, entry(1)).unwrap();
        let original = s.bytes.borrow().as_ref().unwrap().to_vec();
        for mutation in 0..5 {
            let mut v: serde_json::Value = serde_json::from_slice(&original).unwrap();
            match mutation {
                0 => v["unknown"] = true.into(),
                1 => v["version"] = 2.into(),
                2 => {
                    v["catalogue"][0]["unknown"] = true.into();
                }
                3 => {
                    let duplicate = v["catalogue"][0].clone();
                    v["catalogue"].as_array_mut().unwrap().push(duplicate);
                }
                _ => {
                    v["scope"]["root_file"] = 99.into();
                }
            }
            let bad = serde_json::to_vec(&v).unwrap();
            *s.bytes.borrow_mut() = Some(Zeroizing::new(bad.clone()));
            assert!(Custody::reopen(&s, &scope).is_err());
            assert!(s.bytes.borrow().as_ref().unwrap().as_slice() == bad);
        }
        *s.bytes.borrow_mut() = Some(Zeroizing::new(vec![b'x'; MAX_BYTES + 1]));
        assert!(Custody::reopen(&s, &scope).is_err());
        let mut noncanonical = scope.clone();
        noncanonical.account.push(b' ');
        assert_eq!(noncanonical.validate(), Err(Error::Invalid));
        let v = VaultSessionScope::new(
            "other-profile",
            "https://example.test",
            "space",
            "vault-root",
        )
        .unwrap();
        assert!(Scope::new(&scope.account, &v, "/Travel.vault", 7, 42, "registration").is_err());
        assert!(Entry::new([1; 16], "id", "/../outside", "etag", false, 1).is_err());
        assert!(!format!("{scope:?}").contains("subject"));
    }
}
